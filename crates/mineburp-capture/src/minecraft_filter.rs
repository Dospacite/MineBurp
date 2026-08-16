#[cfg(target_os = "linux")]
mod platform {
    use std::{
        collections::HashMap,
        fs,
        path::Path,
        time::{Duration, Instant},
    };

    const REFRESH_INTERVAL: Duration = Duration::from_millis(100);

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    enum Transport {
        Tcp,
        Udp,
    }

    impl Transport {
        fn from_name(value: &str) -> Option<Self> {
            match value {
                "tcp" => Some(Self::Tcp),
                "udp" => Some(Self::Udp),
                _ => None,
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    struct SocketKey {
        transport: Transport,
        local_port: u16,
        remote_port: u16,
    }

    /// Resolves captured endpoints to Minecraft client JVMs through Linux
    /// `procfs`. The short refresh interval avoids requiring a user-selected PID
    /// while keeping unrelated system frames outside the application boundary.
    #[derive(Debug)]
    pub(crate) struct MinecraftFlowFilter {
        sockets: HashMap<SocketKey, u32>,
        next_refresh: Instant,
    }

    impl MinecraftFlowFilter {
        pub(crate) fn new() -> Self {
            Self {
                sockets: HashMap::new(),
                next_refresh: Instant::now(),
            }
        }

        pub(crate) const fn supported() -> bool {
            true
        }

        pub(crate) fn owner(
            &mut self,
            transport: &str,
            local_port: u16,
            remote_port: u16,
        ) -> Option<u32> {
            let now = Instant::now();
            if now >= self.next_refresh {
                self.sockets = discover_minecraft_sockets();
                self.next_refresh = now + REFRESH_INTERVAL;
            }
            let transport = Transport::from_name(transport)?;
            self.sockets
                .get(&SocketKey {
                    transport,
                    local_port,
                    remote_port,
                })
                .or_else(|| {
                    self.sockets.get(&SocketKey {
                        transport,
                        local_port,
                        remote_port: 0,
                    })
                })
                .copied()
        }
    }

    fn discover_minecraft_sockets() -> HashMap<SocketKey, u32> {
        let owners = discover_minecraft_socket_inodes();
        let mut sockets = HashMap::new();
        for (path, transport) in [
            ("/proc/net/tcp", Transport::Tcp),
            ("/proc/net/tcp6", Transport::Tcp),
            ("/proc/net/udp", Transport::Udp),
            ("/proc/net/udp6", Transport::Udp),
        ] {
            if let Ok(table) = fs::read_to_string(path) {
                parse_socket_table(&table, transport, &owners, &mut sockets);
            }
        }
        sockets
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

    fn looks_like_minecraft_client(command_line: &[u8], executable: &Path) -> bool {
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
        table: &str,
        transport: Transport,
        owners: &HashMap<u64, u32>,
        sockets: &mut HashMap<SocketKey, u32>,
    ) {
        for line in table.lines().skip(1) {
            let fields: Vec<_> = line.split_whitespace().collect();
            let Some(inode) = fields.get(9).and_then(|value| value.parse::<u64>().ok()) else {
                continue;
            };
            let Some(pid) = owners.get(&inode) else {
                continue;
            };
            let Some(local_port) = fields.get(1).and_then(|value| parse_port(value)) else {
                continue;
            };
            let Some(remote_port) = fields.get(2).and_then(|value| parse_port(value)) else {
                continue;
            };
            sockets.insert(
                SocketKey {
                    transport,
                    local_port,
                    remote_port,
                },
                *pid,
            );
        }
    }

    fn parse_port(endpoint: &str) -> Option<u16> {
        u16::from_str_radix(endpoint.rsplit_once(':')?.1, 16).ok()
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

        #[test]
        fn parses_proc_socket_rows_for_owned_inodes() {
            let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:C350 04030201:63DD 01 00000000:00000000 00:00000000 00000000  1000        0 4242 1 0000000000000000 100 0 0 10 0\n";
            let owners = HashMap::from([(4_242, 123_u32)]);
            let mut sockets = HashMap::new();
            parse_socket_table(table, Transport::Tcp, &owners, &mut sockets);
            assert_eq!(
                sockets.get(&SocketKey {
                    transport: Transport::Tcp,
                    local_port: 50_000,
                    remote_port: 25_565,
                }),
                Some(&123)
            );
        }

        #[test]
        fn extracts_only_socket_inode_links() {
            assert_eq!(socket_inode("socket:[12345]"), Some(12_345));
            assert_eq!(socket_inode("pipe:[12345]"), None);
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    #[derive(Debug)]
    pub(crate) struct MinecraftFlowFilter;

    impl MinecraftFlowFilter {
        pub(crate) const fn new() -> Self {
            Self
        }

        pub(crate) const fn supported() -> bool {
            false
        }

        pub(crate) fn owner(
            &mut self,
            _transport: &str,
            _local_port: u16,
            _remote_port: u16,
        ) -> Option<u32> {
            None
        }
    }
}

pub(crate) use platform::MinecraftFlowFilter;
