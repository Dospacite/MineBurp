#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let options = mineburp_capture::ImportOptions { max_frames: 8192, server_ports: Vec::new(), ..Default::default() };
    let _ = mineburp_capture::import_capture(std::io::Cursor::new(data), &options, |_| Ok(()));
});
