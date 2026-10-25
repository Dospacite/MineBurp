//! Decides which captured flows belong to a Minecraft client JVM.
//!
//! Attribution compares a frame's full 4-tuple against the socket table of
//! the processes that look like Minecraft clients. Three things keep it from
//! losing the frames that matter most — a connection's handshake and login,
//! which arrive within one round trip of the socket being created:
//!
//! - The socket table is rebuilt on a background thread, so a scan of `/proc`
//!   never stalls the thread reading dumpcap's output.
//! - A frame whose flow is not in the table yet is reported as *unknown*
//!   rather than unrelated, and the caller holds it until a scan that started
//!   after the frame was seen has finished. Only then is the flow declared
//!   unrelated.
//! - Once attributed, a flow stays attributed until it closes (plus a short
//!   grace period for the final segments), even after the socket has left the
//!   table — a closing socket's inode is zero, so the table cannot see it.

use std::{net::SocketAddr, time::Instant};

use crate::packet::Transport;

/// What the filter knows about one flow right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Attribution {
    /// The flow belongs to this Minecraft process. `outgoing` is whether the
    /// frame was sent by the Minecraft side.
    Minecraft { pid: u32, outgoing: bool },
    /// A scan that started after the flow was first seen did not find it.
    Unrelated,
    /// Not decided yet; hold the frame and ask again.
    Unknown,
}

/// A flow with its endpoints in a canonical order, so both directions share
/// one cache entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct FlowKey {
    pub transport: Transport,
    pub low: SocketAddr,
    pub high: SocketAddr,
}

impl FlowKey {
    pub(crate) fn new(transport: Transport, a: SocketAddr, b: SocketAddr) -> Self {
        if a <= b {
            Self {
                transport,
                low: a,
                high: b,
            }
        } else {
            Self {
                transport,
                low: b,
                high: a,
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::{
        collections::HashMap,
        fs,
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        path::Path,
        sync::Arc,
        thread::JoinHandle,
        time::{Duration, Instant},
    };

    use indexmap::IndexMap;
    use parking_lot::{Condvar, Mutex};

    use super::{Attribution, FlowKey};
    use crate::packet::{Transport, normalize};

    /// The least time between two scans, however many misses ask for one.
    const MIN_SCAN_INTERVAL: Duration = Duration::from_millis(40);
    /// Scans happen at least this often, so a closed socket's entry is
    /// replaced even without a miss to prompt it.
    const IDLE_SCAN_INTERVAL: Duration = Duration::from_secs(2);
    /// How long an attributed flow is kept after its FIN or RST.
    const CLOSE_GRACE: Duration = Duration::from_secs(5);
    /// How long an attributed flow is kept with no traffic at all.
    const IDLE_EXPIRY: Duration = Duration::from_mins(10);
    /// How long an unrelated verdict is trusted before the flow is re-checked.
    const UNRELATED_EXPIRY: Duration = Duration::from_secs(30);
    const CACHE_CAPACITY: usize = 16_384;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    struct SocketKey {
        transport: Transport,
        local: SocketAddr,
        remote: SocketAddr,
    }

    /// Minecraft-owned sockets as of one scan.
    #[derive(Debug, Default)]
    struct SocketTable {
        connected: HashMap<SocketKey, u32>,
        /// Sockets with no remote (unconnected UDP), matched by local port
        /// and, when the socket is bound to one, local address.
        unconnected: HashMap<(Transport, u16), (u32, IpAddr)>,
    }

    impl SocketTable {
        /// Which endpoint is the Minecraft side, if either is.
        fn find(
            &self,
            transport: Transport,
            source: SocketAddr,
            destination: SocketAddr,
        ) -> Option<(u32, SocketAddr)> {
            let exact = |local: SocketAddr, remote: SocketAddr| {
                self.connected.get(&SocketKey {
                    transport,
                    local,
                    remote,
                })
            };
            if let Some(pid) = exact(source, destination) {
                return Some((*pid, source));
            }
            if let Some(pid) = exact(destination, source) {
                return Some((*pid, destination));
            }
            let unconnected = |endpoint: SocketAddr| {
                self.unconnected
                    .get(&(transport, endpoint.port()))
                    .filter(|(_, bound)| bound.is_unspecified() || *bound == endpoint.ip())
                    .map(|(pid, _)| (*pid, endpoint))
            };
            unconnected(source).or_else(|| unconnected(destination))
        }
    }

    #[derive(Debug, Default)]
    struct ScanState {
        table: Arc<SocketTable>,
        /// Incremented every time a scan finishes.
        generation: u64,
        requested: bool,
        stop: bool,
    }

    #[derive(Debug, Default)]
    struct Shared {
        state: Mutex<ScanState>,
        wake: Condvar,
    }

    #[derive(Debug, Clone, Copy)]
    struct Known {
        pid: u32,
        local: SocketAddr,
        last_seen: Instant,
        closed_at: Option<Instant>,
    }

    /// Resolves captured endpoints to Minecraft client JVMs through Linux
    /// `procfs`, without a user-selected PID.
    #[derive(Debug)]
    pub(crate) struct MinecraftFlowFilter {
        shared: Arc<Shared>,
        scanner: Option<JoinHandle<()>>,
        known: IndexMap<FlowKey, Known>,
        unrelated: IndexMap<FlowKey, Instant>,
        /// For undecided flows: the scan generation when first seen.
        pending: IndexMap<FlowKey, u64>,
    }

    impl MinecraftFlowFilter {
        pub(crate) fn new() -> Self {
            let shared = Arc::new(Shared::default());
            let worker = shared.clone();
            let scanner = std::thread::Builder::new()
                .name("mineburp-socket-scan".into())
                .spawn(move || scan_loop(&worker))
                .ok();
            Self {
                shared,
                scanner,
                known: IndexMap::new(),
                unrelated: IndexMap::new(),
                pending: IndexMap::new(),
            }
        }

        pub(crate) const fn supported() -> bool {
            true
        }

        pub(crate) fn attribute(
            &mut self,
            transport: Transport,
            source: SocketAddr,
            destination: SocketAddr,
        ) -> Attribution {
            let now = Instant::now();
            let key = FlowKey::new(transport, source, destination);
            if let Some(known) = self.known.get_mut(&key) {
                let expired = known
                    .closed_at
                    .is_some_and(|closed| now.duration_since(closed) > CLOSE_GRACE)
                    || now.duration_since(known.last_seen) > IDLE_EXPIRY;
                if !expired {
                    known.last_seen = now;
                    return Attribution::Minecraft {
                        pid: known.pid,
                        outgoing: known.local == source,
                    };
                }
                // A reused 4-tuple after the grace period is a new connection
                // and has to be attributed afresh.
                self.known.shift_remove(&key);
            }
            if let Some(until) = self.unrelated.get(&key) {
                if now < *until {
                    return Attribution::Unrelated;
                }
                self.unrelated.shift_remove(&key);
            }
            let (table, generation) = {
                let state = self.shared.state.lock();
                (state.table.clone(), state.generation)
            };
            if let Some((pid, local)) = table.find(transport, source, destination) {
                self.pending.shift_remove(&key);
                bounded_insert(
                    &mut self.known,
                    key,
                    Known {
                        pid,
                        local,
                        last_seen: now,
                        closed_at: None,
                    },
                );
                return Attribution::Minecraft {
                    pid,
                    outgoing: local == source,
                };
            }
            // A scan running when the flow was first seen may have read the
            // socket table before the socket existed. The one after it cannot
            // have, so two generations later the miss is a verdict.
            let first_seen = *self.pending.entry(key).or_insert(generation);
            if generation >= first_seen + 2 {
                self.pending.shift_remove(&key);
                bounded_insert(&mut self.unrelated, key, now + UNRELATED_EXPIRY);
                return Attribution::Unrelated;
            }
            if self.pending.len() > CACHE_CAPACITY {
                self.pending.shift_remove_index(0);
            }
            self.request_scan();
            Attribution::Unknown
        }

        /// Records a FIN or RST, so the flow's entry ages out after the grace
        /// period instead of lingering until the idle expiry.
        pub(crate) fn observe_close(
            &mut self,
            transport: Transport,
            source: SocketAddr,
            destination: SocketAddr,
        ) {
            let key = FlowKey::new(transport, source, destination);
            if let Some(known) = self.known.get_mut(&key) {
                known.closed_at.get_or_insert_with(Instant::now);
            }
        }

        fn request_scan(&self) {
            let mut state = self.shared.state.lock();
            if !state.requested {
                state.requested = true;
                self.shared.wake.notify_one();
            }
        }
    }

    impl Drop for MinecraftFlowFilter {
        fn drop(&mut self) {
            self.shared.state.lock().stop = true;
            self.shared.wake.notify_one();
            if let Some(scanner) = self.scanner.take() {
                let _ = scanner.join();
            }
        }
    }

    fn bounded_insert<V>(map: &mut IndexMap<FlowKey, V>, key: FlowKey, value: V) {
        if map.len() >= CACHE_CAPACITY && !map.contains_key(&key) {
            map.shift_remove_index(0);
        }
        map.insert(key, value);
    }

    fn scan_loop(shared: &Shared) {
        loop {
            {
                let mut state = shared.state.lock();
                if !state.requested && !state.stop {
                    shared.wake.wait_for(&mut state, IDLE_SCAN_INTERVAL);
                }
                if state.stop {
                    return;
                }
                state.requested = false;
            }
            let table = Arc::new(discover_minecraft_sockets());
            {
                let mut state = shared.state.lock();
                state.table = table;
                state.generation += 1;
            }
            std::thread::sleep(MIN_SCAN_INTERVAL);
        }
    }

    fn discover_minecraft_sockets() -> SocketTable {
        let owners = discover_minecraft_socket_inodes();
        let mut table = SocketTable::default();
        if owners.is_empty() {
            return table;
        }
        for (path, transport) in [
            ("/proc/net/tcp", Transport::Tcp),
            ("/proc/net/tcp6", Transport::Tcp),
            ("/proc/net/udp", Transport::Udp),
            ("/proc/net/udp6", Transport::Udp),
        ] {
            if let Ok(text) = fs::read_to_string(path) {
                parse_socket_table(&text, transport, &owners, &mut table);
            }
        }
        table
    }

    fn discover_minecraft_socket_inodes() -> HashMap<u64, u32> {
        let mut owners = HashMap::new();
        let Ok(processes) = fs::read_dir("/proc") else {
            return owners;
        };
        for process in processes.flatten() {
            let Some(pid) = process
                .file_name()
                .to_str()
                .and_then(|value| value.parse::<u32>().ok())
            else {
                continue;
            };
            let root = process.path();
            let Ok(command_line) = fs::read(root.join("cmdline")) else {
                continue;
            };
            let Ok(executable) = fs::read_link(root.join("exe")) else {
                continue;
            };
            if !looks_like_minecraft_client(&command_line, &executable) {
                continue;
            }
            let Ok(descriptors) = fs::read_dir(root.join("fd")) else {
                continue;
            };
            for descriptor in descriptors.flatten() {
                let Ok(target) = fs::read_link(descriptor.path()) else {
                    continue;
                };
                if let Some(inode) = socket_inode(&target.to_string_lossy()) {
                    owners.insert(inode, pid);
                }
            }
        }
        owners
    }

    pub(super) fn looks_like_minecraft_client(command_line: &[u8], executable: &Path) -> bool {
        let executable = executable
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if executable != "java" && executable != "javaw" && executable != "java.exe" {
            return false;
        }
        let command = String::from_utf8_lossy(command_line).to_ascii_lowercase();
        [
            "net.minecraft.client.main.main",
            "net.fabricmc.loader.impl.launch.knot.knotclient",
            "net.fabricmc.loader.launch.knot.knotclient",
            "org.quiltmc.loader.impl.launch.knot.knotclient",
            "net.minecraft.launchwrapper.launch",
            "net.minecraftforge.bootstrap.forgebootstrap",
        ]
        .iter()
        .any(|marker| command.contains(marker))
            || ((command.contains("cpw.mods.modlauncher.launcher")
                || command.contains("cpw.mods.bootstraplauncher.bootstraplauncher"))
                && [
                    "forgeclient",
                    "forge_client",
                    "fmlclient",
                    "neoforgeclient",
                    "neoforge_client",
                ]
                .iter()
                .any(|marker| command.contains(marker)))
            || (command.contains("-dminecraft.launcher.brand=") && command.contains("--gamedir"))
    }

    fn socket_inode(target: &str) -> Option<u64> {
        target
            .strip_prefix("socket:[")?
            .strip_suffix(']')?
            .parse()
            .ok()
    }

    fn parse_socket_table(
        text: &str,
        transport: Transport,
        owners: &HashMap<u64, u32>,
        table: &mut SocketTable,
    ) {
        for line in text.lines().skip(1) {
            let fields: Vec<_> = line.split_whitespace().collect();
            let Some(inode) = fields.get(9).and_then(|value| value.parse::<u64>().ok()) else {
                continue;
            };
            let Some(pid) = owners.get(&inode) else {
                continue;
            };
            let Some(local) = fields.get(1).and_then(|value| parse_endpoint(value)) else {
                continue;
            };
            let Some(remote) = fields.get(2).and_then(|value| parse_endpoint(value)) else {
                continue;
            };
            if remote.port() == 0 && remote.ip().is_unspecified() {
                table
                    .unconnected
                    .insert((transport, local.port()), (*pid, local.ip()));
            } else {
                table.connected.insert(
                    SocketKey {
                        transport,
                        local,
                        remote,
                    },
                    *pid,
                );
            }
        }
    }

    /// Reads `ADDRESS:PORT` from `/proc/net/*`: the address is the in-memory
    /// representation, one 32-bit word at a time in host byte order.
    fn parse_endpoint(endpoint: &str) -> Option<SocketAddr> {
        let (address, port) = endpoint.split_once(':')?;
        let port = u16::from_str_radix(port, 16).ok()?;
        let word = |index: usize| -> Option<[u8; 4]> {
            let digits = address.get(index * 8..index * 8 + 8)?;
            Some(u32::from_str_radix(digits, 16).ok()?.to_ne_bytes())
        };
        let ip = match address.len() {
            8 => IpAddr::V4(Ipv4Addr::from(word(0)?)),
            32 => {
                let mut bytes = [0_u8; 16];
                for index in 0..4 {
                    bytes[index * 4..index * 4 + 4].copy_from_slice(&word(index)?);
                }
                IpAddr::V6(Ipv6Addr::from(bytes))
            }
            _ => return None,
        };
        Some(SocketAddr::new(normalize(ip), port))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn recognizes_vanilla_fabric_and_forge_clients_only() {
            let java = Path::new("/usr/lib/jvm/java-21/bin/java");
            assert!(looks_like_minecraft_client(
                b"java\0net.minecraft.client.main.Main\0",
                java
            ));
            assert!(looks_like_minecraft_client(
                b"java\0net.fabricmc.loader.impl.launch.knot.KnotClient\0",
                java
            ));
            assert!(looks_like_minecraft_client(
                b"java\0cpw.mods.modlauncher.Launcher\0--launchTarget\0neoforgeclient\0",
                java
            ));
            assert!(looks_like_minecraft_client(
                b"java\0-Dminecraft.launcher.brand=CurseForge\0net.minecraftforge.bootstrap.ForgeBootstrap\0--gameDir\0/tmp/game\0--launchTarget\0forge_client\0",
                java
            ));
            assert!(!looks_like_minecraft_client(
                b"java\0com.example.UnrelatedService\0",
                java
            ));
            assert!(!looks_like_minecraft_client(
                b"minecraft\0net.minecraft.client.main.Main\0",
                Path::new("/usr/bin/python")
            ));
        }

        #[cfg(target_endian = "little")]
        #[test]
        fn parses_proc_socket_rows_with_addresses() {
            let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:C350 04030201:63DD 01 00000000:00000000 00:00000000 00000000  1000        0 4242 1 0000000000000000 100 0 0 10 0\n   1: 00000000:A000 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 4343 1 0000000000000000 100 0 0 10 0\n";
            let owners = HashMap::from([(4_242, 123_u32), (4_343, 124_u32)]);
            let mut table = SocketTable::default();
            parse_socket_table(text, Transport::Tcp, &owners, &mut table);
            let local: SocketAddr = "127.0.0.1:50000".parse().unwrap();
            let remote: SocketAddr = "1.2.3.4:25565".parse().unwrap();
            assert_eq!(
                table.find(Transport::Tcp, local, remote),
                Some((123, local))
            );
            // Either direction resolves, with the Minecraft side identified.
            assert_eq!(
                table.find(Transport::Tcp, remote, local),
                Some((123, local))
            );
            // Same ports, different host: not the same socket.
            let elsewhere: SocketAddr = "10.9.9.9:25565".parse().unwrap();
            assert_eq!(table.find(Transport::Tcp, local, elsewhere), None);
            // An unconnected socket matches by local port.
            let any: SocketAddr = "192.168.0.5:40960".parse().unwrap();
            let peer: SocketAddr = "8.8.8.8:53".parse().unwrap();
            assert_eq!(table.find(Transport::Tcp, any, peer), Some((124, any)));
        }

        #[cfg(target_endian = "little")]
        #[test]
        fn parses_ipv6_and_mapped_endpoints() {
            assert_eq!(
                parse_endpoint("00000000000000000000000001000000:0050"),
                Some("[::1]:80".parse().unwrap())
            );
            assert_eq!(
                parse_endpoint("0000000000000000FFFF00000100007F:0050"),
                Some("127.0.0.1:80".parse().unwrap())
            );
            assert_eq!(parse_endpoint("zz:0050"), None);
        }

        #[test]
        fn extracts_only_socket_inode_links() {
            assert_eq!(socket_inode("socket:[12345]"), Some(12_345));
            assert_eq!(socket_inode("pipe:[12345]"), None);
        }

        #[test]
        fn an_unseen_flow_is_unknown_until_a_later_scan_rules_it_out() {
            let mut filter = MinecraftFlowFilter::new();
            let a: SocketAddr = "10.255.0.1:1".parse().unwrap();
            let b: SocketAddr = "10.255.0.2:2".parse().unwrap();
            assert_eq!(filter.attribute(Transport::Tcp, a, b), Attribution::Unknown);
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                match filter.attribute(Transport::Tcp, a, b) {
                    Attribution::Unrelated => break,
                    Attribution::Unknown if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    other => panic!("unexpected attribution {other:?}"),
                }
            }
            // The verdict is cached for the reverse direction too.
            assert_eq!(
                filter.attribute(Transport::Tcp, b, a),
                Attribution::Unrelated
            );
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use std::net::SocketAddr;

    use super::Attribution;
    use crate::packet::Transport;

    #[derive(Debug)]
    pub(crate) struct MinecraftFlowFilter;

    impl MinecraftFlowFilter {
        pub(crate) const fn new() -> Self {
            Self
        }

        pub(crate) const fn supported() -> bool {
            false
        }

        pub(crate) fn attribute(
            &mut self,
            _transport: Transport,
            _source: SocketAddr,
            _destination: SocketAddr,
        ) -> Attribution {
            Attribution::Unrelated
        }

        pub(crate) fn observe_close(
            &mut self,
            _transport: Transport,
            _source: SocketAddr,
            _destination: SocketAddr,
        ) {
        }
    }
}

pub(crate) use platform::MinecraftFlowFilter;

/// Frames held while their flow is undecided.
///
/// Bounded by count and by bytes, and by age: a frame still undecided after
/// [`HOLD_LIMIT`] is dropped rather than kept, because a flow the scanner
/// cannot place after several scans is not going to become placeable.
#[derive(Debug)]
pub(crate) struct HoldQueue<T> {
    items: std::collections::VecDeque<(Instant, FlowKey, usize, T)>,
    bytes: usize,
}

pub(crate) const HOLD_LIMIT: std::time::Duration = std::time::Duration::from_millis(1_500);
const HOLD_MAX_ITEMS: usize = 16_384;
const HOLD_MAX_BYTES: usize = 32 * 1024 * 1024;

impl<T> Default for HoldQueue<T> {
    fn default() -> Self {
        Self {
            items: std::collections::VecDeque::new(),
            bytes: 0,
        }
    }
}

impl<T> HoldQueue<T> {
    /// Holds an item; returns `false` (and drops it) when the queue is full.
    pub(crate) fn push(&mut self, key: FlowKey, size: usize, item: T) -> bool {
        if self.items.len() >= HOLD_MAX_ITEMS || self.bytes + size > HOLD_MAX_BYTES {
            return false;
        }
        self.bytes += size;
        self.items.push_back((Instant::now(), key, size, item));
        true
    }

    pub(crate) fn len(&self) -> usize {
        self.items.len()
    }

    pub(crate) fn holds(&self, key: &FlowKey) -> bool {
        self.items.iter().any(|(_, held, _, _)| held == key)
    }

    /// Removes every held item, oldest first, for the caller to re-decide.
    pub(crate) fn take_all(&mut self) -> Vec<(Instant, FlowKey, T)> {
        self.bytes = 0;
        self.items
            .drain(..)
            .map(|(at, key, _, item)| (at, key, item))
            .collect()
    }

    /// Puts an item back, keeping its original hold time.
    pub(crate) fn restore(&mut self, at: Instant, key: FlowKey, size: usize, item: T) {
        self.bytes += size;
        self.items.push_back((at, key, size, item));
    }
}
