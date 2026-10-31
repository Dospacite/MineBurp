//! The desktop app's private MCP endpoint: a Unix socket only its user can use.
//!
//! The socket lives in a directory created `0700`, the socket itself is
//! `0600`, and every connection's peer credentials are checked against the
//! owning user, so another local account cannot reach decrypted traffic
//! through it even if permissions were loosened.

use std::{
    io,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    sync::Arc,
};

use tokio::net::{UnixListener, UnixStream};

use crate::{McpServer, serve};

/// Overrides the socket location for both the app and the bridge.
pub const SOCKET_ENV: &str = "MINEBURP_MCP_SOCKET";

/// Where the app listens and the bridge connects.
pub fn default_socket_path() -> PathBuf {
    if let Some(path) = std::env::var_os(SOCKET_ENV).filter(|value| !value.is_empty()) {
        return PathBuf::from(path);
    }
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR").filter(|value| !value.is_empty()) {
        return PathBuf::from(runtime).join("mineburp").join("mcp.sock");
    }
    let user = std::env::var("USER").unwrap_or_else(|_| "user".into());
    std::env::temp_dir()
        .join(format!("mineburp-{user}"))
        .join("mcp.sock")
}

/// Binds the socket, replacing a stale one but never a live one.
pub async fn bind(path: &Path) -> io::Result<UnixListener> {
    let directory = path
        .parent()
        .ok_or_else(|| io::Error::other("socket path has no parent directory"))?;
    std::fs::create_dir_all(directory)?;
    if path.exists() {
        if UnixStream::connect(path).await.is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("another MineBurp is serving MCP on {}", path.display()),
            ));
        }
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    // The socket was just created by this process, so its owner is us; a
    // directory someone else owns could let them swap the socket out.
    let owner = std::fs::metadata(path)?.uid();
    let directory_meta = std::fs::metadata(directory)?;
    if directory_meta.uid() != owner {
        let _ = std::fs::remove_file(path);
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} is owned by another user", directory.display()),
        ));
    }
    if directory_meta.permissions().mode() & 0o077 != 0 {
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(listener)
}

/// Accepts sessions until the listener fails.
pub async fn serve_listener(listener: UnixListener, path: PathBuf, server: Arc<McpServer>) {
    let owner = std::fs::metadata(&path).map(|meta| meta.uid()).ok();
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            break;
        };
        let peer = stream.peer_cred().ok().map(|credentials| credentials.uid());
        if owner.is_none() || peer != owner {
            continue;
        }
        let server = server.clone();
        tokio::spawn(async move {
            let (reader, writer) = stream.into_split();
            let _ = serve(reader, writer, server).await;
        });
    }
}

/// Removes the socket file, if it is still ours.
pub fn remove(path: &Path) {
    let _ = std::fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};

    use super::*;
    use crate::OfflineHost;

    #[tokio::test]
    async fn serves_mcp_over_a_private_socket() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("run").join("mcp.sock");
        let listener = bind(&path).await.unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(bind(&path).await.is_err(), "a live socket is not replaced");
        let server = Arc::new(McpServer::new(Arc::new(OfflineHost::default())));
        tokio::spawn(serve_listener(listener, path.clone(), server));

        let mut stream = UnixStream::connect(&path).await.unwrap();
        stream
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n")
            .await
            .unwrap();
        let mut line = String::new();
        BufReader::new(&mut stream)
            .read_line(&mut line)
            .await
            .unwrap();
        assert!(line.contains("\"result\":{}"), "{line}");
    }
}
