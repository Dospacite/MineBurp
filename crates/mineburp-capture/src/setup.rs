//! Bounded, read-only capture prerequisite probe.
use std::{
    io,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DumpcapCheck {
    Ready,
    Missing,
    PermissionDenied,
    Failed,
    TimedOut,
}
impl DumpcapCheck {
    #[must_use]
    pub fn reason(self) -> Option<&'static str> {
        match self {
            Self::Ready => None,
            Self::Missing => Some("dumpcap is not installed or is not on PATH"),
            Self::PermissionDenied => {
                Some("dumpcap permission denied; grant your user capture permission")
            }
            Self::Failed => Some("dumpcap could not enumerate capture interfaces"),
            Self::TimedOut => Some("dumpcap interface enumeration timed out"),
        }
    }
}
/// Classifies runner output separately so callers can test without a helper installed.
#[must_use]
pub fn classify_dumpcap(result: Result<(bool, String), io::ErrorKind>) -> DumpcapCheck {
    match result {
        Ok((true, _)) => DumpcapCheck::Ready,
        Err(io::ErrorKind::NotFound) => DumpcapCheck::Missing,
        Err(io::ErrorKind::PermissionDenied) => DumpcapCheck::PermissionDenied,
        Ok((false, text))
            if ["permission", "permitted", "access denied"]
                .iter()
                .any(|s| text.to_lowercase().contains(s)) =>
        {
            DumpcapCheck::PermissionDenied
        }
        _ => DumpcapCheck::Failed,
    }
}
#[must_use]
pub fn probe_dumpcap() -> DumpcapCheck {
    // No capture is started; -D only enumerates interfaces. A helper blocked
    // on its stderr pipe is killed at the same deadline.
    let mut child = match Command::new("dumpcap")
        .arg("-D")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => return classify_dumpcap(Err(error.kind())),
    };
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                use std::io::Read;
                let mut stderr = String::new();
                if let Some(pipe) = child.stderr.take() {
                    let _ = pipe.take(8192).read_to_string(&mut stderr);
                }
                return classify_dumpcap(Ok((status.success(), stderr)));
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return DumpcapCheck::TimedOut;
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn maps_runner_results() {
        assert_eq!(
            classify_dumpcap(Err(io::ErrorKind::NotFound)),
            DumpcapCheck::Missing
        );
        assert_eq!(
            classify_dumpcap(Err(io::ErrorKind::PermissionDenied)),
            DumpcapCheck::PermissionDenied
        );
        assert_eq!(
            classify_dumpcap(Ok((false, "Operation not permitted".into()))),
            DumpcapCheck::PermissionDenied
        );
        assert_eq!(
            classify_dumpcap(Ok((false, "bad interface".into()))),
            DumpcapCheck::Failed
        );
        assert_eq!(
            classify_dumpcap(Ok((true, String::new()))),
            DumpcapCheck::Ready
        );
    }
}
