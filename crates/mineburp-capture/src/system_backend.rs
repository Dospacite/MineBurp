use std::{
    io::{self, Read},
    process::{Child, ChildStderr, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use parking_lot::{Mutex, RwLock};
use tokio::sync::broadcast;

use crate::{
    CaptureCapabilities, CaptureError, CaptureStats, SideCapture, SideChannelFrame,
    minecraft_filter::MinecraftFlowFilter,
    pcap::{CaptureReader, CaptureRecord},
    pipeline::{FrameContext, Pipeline, now_micros},
};

/// How long a `dumpcap -D` probe result is trusted.
const PROBE_TTL: Duration = Duration::from_secs(30);
/// How often the dispatcher wakes to retry held frames when traffic is idle.
const DISPATCH_TICK: Duration = Duration::from_millis(25);
/// Records queued between the reader and the dispatcher.
const RECORD_QUEUE: usize = 8_192;
/// How much of dumpcap's stderr is kept for error reports.
const STDERR_TAIL: usize = 2_048;

/// Minecraft-client TCP/UDP capture through Wireshark's privilege-separated
/// `dumpcap` helper and automatic process/socket attribution.
#[derive(Debug)]
pub struct SystemCapture {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    stats: RwLock<CaptureStats>,
    sender: broadcast::Sender<SideChannelFrame>,
    /// The running capture, if any. Held for the whole of `start` and `stop`
    /// so two concurrent starts cannot both launch dumpcap.
    running: Mutex<Option<Running>>,
    probe: Mutex<Option<(Instant, crate::setup::DumpcapCheck)>>,
}

#[derive(Debug)]
struct Running {
    stop: Arc<AtomicBool>,
    child: Arc<Mutex<Option<Child>>>,
    reader: JoinHandle<()>,
    dispatcher: JoinHandle<()>,
}

impl Running {
    fn finished(&self) -> bool {
        self.dispatcher.is_finished()
    }

    fn shut_down(self) {
        self.stop.store(true, Ordering::Release);
        if let Some(child) = self.child.lock().as_mut() {
            let _ = child.kill();
        }
        let _ = self.reader.join();
        let _ = self.dispatcher.join();
        if let Some(mut child) = self.child.lock().take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Default for SystemCapture {
    fn default() -> Self {
        let (sender, _) = broadcast::channel(8_192);
        Self {
            inner: Arc::new(Inner {
                stats: RwLock::new(CaptureStats::default()),
                sender,
                running: Mutex::new(None),
                probe: Mutex::new(None),
            }),
        }
    }
}

#[async_trait]
impl SideCapture for SystemCapture {
    fn capabilities(&self) -> CaptureCapabilities {
        let probe = self.inner.dumpcap_probe();
        let dumpcap = probe == crate::setup::DumpcapCheck::Ready;
        let attribution = MinecraftFlowFilter::supported();
        let available = dumpcap && attribution;
        CaptureCapabilities {
            available,
            requires_elevation: false,
            process_attribution: attribution,
            backend: "dumpcap-minecraft".into(),
            reason: if !attribution {
                Some(
                    "automatic Minecraft process attribution is currently available on Linux"
                        .into(),
                )
            } else if !dumpcap {
                probe.reason().map(str::to_owned)
            } else {
                None
            },
        }
    }

    fn subscribe(&self) -> broadcast::Receiver<SideChannelFrame> {
        self.inner.sender.subscribe()
    }

    async fn start(&self) -> Result<(), CaptureError> {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || inner.start())
            .await
            .map_err(|error| CaptureError::Backend(error.to_string()))?
    }

    async fn stop(&self) -> Result<(), CaptureError> {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || inner.stop())
            .await
            .map_err(|error| CaptureError::Backend(error.to_string()))
    }

    async fn stats(&self) -> CaptureStats {
        let mut stats = self.inner.stats.read().clone();
        stats.running = self
            .inner
            .running
            .lock()
            .as_ref()
            .is_some_and(|running| !running.finished());
        stats
    }
}

impl Inner {
    fn dumpcap_available(&self) -> bool {
        self.dumpcap_probe() == crate::setup::DumpcapCheck::Ready
    }

    fn dumpcap_probe(&self) -> crate::setup::DumpcapCheck {
        let mut probe = self.probe.lock();
        if let Some((at, result)) = *probe
            && at.elapsed() < PROBE_TTL
        {
            return result;
        }
        let result = crate::setup::probe_dumpcap();
        *probe = Some((Instant::now(), result));
        result
    }

    fn start(self: &Arc<Self>) -> Result<(), CaptureError> {
        let mut running = self.running.lock();
        if let Some(current) = running.as_ref() {
            if !current.finished() {
                return Ok(());
            }
            // The previous capture died on its own (dumpcap exited, the pipe
            // broke); clear it so this start launches a fresh one.
            if let Some(stale) = running.take() {
                stale.shut_down();
            }
        }
        if !MinecraftFlowFilter::supported() {
            return Err(self.fail(CaptureError::Unavailable(
                "automatic Minecraft process attribution is not supported on this platform".into(),
            )));
        }
        // A start is an explicit request; re-probe rather than trust a cached
        // "unavailable" from before the operator fixed permissions.
        *self.probe.lock() = None;
        if !self.dumpcap_available() {
            return Err(self.fail(CaptureError::Unavailable(
                "dumpcap could not access a capture interface".into(),
            )));
        }
        let mut child = Command::new("dumpcap")
            .args([
                "-i",
                "any",
                "-F",
                "pcap",
                "-q",
                "-f",
                "tcp or udp",
                "-w",
                "-",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| self.fail(CaptureError::Backend(error.to_string())))?;
        let stdout = child.stdout.take().ok_or_else(|| {
            self.fail(CaptureError::Backend(
                "dumpcap did not provide its capture stream".into(),
            ))
        })?;
        let stderr_tail = Arc::new(Mutex::new(String::new()));
        if let Some(stderr) = child.stderr.take() {
            spawn_stderr_reader(stderr, stderr_tail.clone());
        }
        {
            let mut stats = self.stats.write();
            *stats = CaptureStats::default();
        }
        let stop = Arc::new(AtomicBool::new(false));
        let child = Arc::new(Mutex::new(Some(child)));
        let (records, queue) = mpsc::sync_channel::<CaptureRecord>(RECORD_QUEUE);

        let reader = self.spawn_reader(stdout, records, &stop, &child, stderr_tail);
        let reader = match reader {
            Ok(reader) => reader,
            Err(error) => {
                kill(&child);
                return Err(self.fail(CaptureError::Backend(error.to_string())));
            }
        };
        let dispatcher = {
            let inner = self.clone();
            let stop = stop.clone();
            spawn_thread("mineburp-capture-dispatch", move || {
                dispatch(&queue, &inner, &stop);
            })
        };
        let dispatcher = match dispatcher {
            Ok(dispatcher) => dispatcher,
            Err(error) => {
                stop.store(true, Ordering::Release);
                kill(&child);
                let _ = reader.join();
                return Err(self.fail(CaptureError::Backend(error.to_string())));
            }
        };
        *running = Some(Running {
            stop,
            child,
            reader,
            dispatcher,
        });
        Ok(())
    }

    /// Starts the thread that reads dumpcap's stream. When dumpcap ends
    /// without being asked to, it records why — exit status and the tail of
    /// stderr — so the UI can say more than "capture stopped".
    fn spawn_reader(
        self: &Arc<Self>,
        stdout: impl Read + Send + 'static,
        records: mpsc::SyncSender<CaptureRecord>,
        stop: &Arc<AtomicBool>,
        child: &Arc<Mutex<Option<Child>>>,
        stderr_tail: Arc<Mutex<String>>,
    ) -> io::Result<JoinHandle<()>> {
        let inner = self.clone();
        let stop = stop.clone();
        let child = child.clone();
        spawn_thread("mineburp-capture-reader", move || {
            let result = read_stream(stdout, &records, &stop);
            drop(records);
            if !stop.load(Ordering::Acquire) {
                let status = child
                    .lock()
                    .as_mut()
                    .and_then(|process| process.wait().ok())
                    .map(|status| status.to_string());
                let detail = stderr_tail.lock().trim().to_owned();
                let message = match (result, status) {
                    (Err(error), _) => format!("capture stream failed: {error}"),
                    (Ok(()), Some(status)) => format!("dumpcap exited ({status})"),
                    (Ok(()), None) => "dumpcap exited".to_owned(),
                };
                inner.record_error(if detail.is_empty() {
                    message
                } else {
                    format!("{message}: {detail}")
                });
            }
        })
    }

    fn stop(&self) {
        let current = self.running.lock().take();
        if let Some(current) = current {
            current.shut_down();
        }
    }

    fn record_error(&self, message: String) {
        let mut stats = self.stats.write();
        stats.errors += 1;
        stats.last_error = Some(message);
    }

    fn fail(&self, error: CaptureError) -> CaptureError {
        self.record_error(error.to_string());
        error
    }
}

impl Drop for SystemCapture {
    fn drop(&mut self) {
        // The worker threads hold their own references to `inner`, so the
        // capture would outlive its owner unless it is stopped here.
        self.inner.stop();
    }
}

fn spawn_thread(name: &str, work: impl FnOnce() + Send + 'static) -> io::Result<JoinHandle<()>> {
    std::thread::Builder::new().name(name.into()).spawn(work)
}

fn kill(child: &Mutex<Option<Child>>) {
    if let Some(mut process) = child.lock().take() {
        let _ = process.kill();
        let _ = process.wait();
    }
}

fn spawn_stderr_reader(mut stderr: ChildStderr, tail: Arc<Mutex<String>>) {
    let _ = spawn_thread("mineburp-dumpcap-stderr", move || {
        let mut buffer = [0_u8; 512];
        while let Ok(read) = stderr.read(&mut buffer) {
            if read == 0 {
                break;
            }
            let mut text = tail.lock();
            text.push_str(&String::from_utf8_lossy(&buffer[..read]));
            if text.len() > STDERR_TAIL {
                let cut = text.len() - STDERR_TAIL;
                let cut = (cut..text.len())
                    .find(|index| text.is_char_boundary(*index))
                    .unwrap_or(text.len());
                text.drain(..cut);
            }
        }
    });
}

/// Reads dumpcap's stream and queues its records for the dispatcher.
fn read_stream(
    input: impl Read,
    records: &mpsc::SyncSender<CaptureRecord>,
    stop: &AtomicBool,
) -> io::Result<()> {
    let mut reader = CaptureReader::new(input)?;
    while !stop.load(Ordering::Acquire) {
        let Some(record) = reader.next_record()? else {
            return Ok(());
        };
        if records.send(record).is_err() {
            return Ok(());
        }
    }
    Ok(())
}

/// Attributes, reassembles, and publishes records off the reading thread, so
/// neither `/proc` scans nor a burst of held frames slow the pipe from dumpcap.
fn dispatch(queue: &mpsc::Receiver<CaptureRecord>, inner: &Inner, stop: &AtomicBool) {
    let mut pipeline = Pipeline::new(MinecraftFlowFilter::new());
    let mut emit = |frame: SideChannelFrame, _: FrameContext| {
        let _ = inner.sender.send(frame);
    };
    let mut last_stats = Instant::now();
    loop {
        match queue.recv_timeout(DISPATCH_TICK) {
            Ok(record) => {
                inner.stats.write().bytes_seen += record.data.len() as u64;
                pipeline.push(&record, &mut emit);
                // Drain a burst before doing periodic work.
                while let Ok(record) = queue.try_recv() {
                    inner.stats.write().bytes_seen += record.data.len() as u64;
                    pipeline.push(&record, &mut emit);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                pipeline.finish(&mut emit);
                publish_stats(inner, &pipeline);
                return;
            }
        }
        if stop.load(Ordering::Acquire) {
            return;
        }
        pipeline.retry_held(&mut emit);
        pipeline.expire(now_micros(), &mut emit);
        if last_stats.elapsed() >= Duration::from_millis(250) {
            publish_stats(inner, &pipeline);
            last_stats = Instant::now();
        }
    }
}

fn publish_stats(inner: &Inner, pipeline: &Pipeline<MinecraftFlowFilter>) {
    let current = pipeline.stats();
    let mut stats = inner.stats.write();
    stats.frames_seen = current.frames_seen;
    stats.frames_emitted = current.frames_emitted;
    stats.bytes_emitted = current.bytes_emitted;
    stats.frames_dropped = current.frames_dropped;
    stats.frames_held = current.frames_held;
    stats.retransmissions = current.reassembly.duplicates;
    stats.reordered = current.reassembly.reordered;
    stats.gaps = current.reassembly.gaps;
}
