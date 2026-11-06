use std::sync::Arc;

use async_trait::async_trait;
use mineburp_mcp::{Host, McpServer, OfflineHost};
use mineburp_project::ProjectStore;
use mineburp_proxy::ProxyService;
use serde_json::{Value, json};
use tokio::net::TcpStream;

struct LiveHost(ProxyService);

#[async_trait]
impl Host for LiveHost {
    fn mode(&self) -> &'static str {
        "desktop"
    }
    fn project(&self) -> Option<ProjectStore> {
        None
    }
    async fn install_project(&self, _: ProjectStore) -> Result<(), String> {
        Ok(())
    }
    fn proxy(&self) -> Option<ProxyService> {
        Some(self.0.clone())
    }
}

#[tokio::test]
async fn route_requires_live_host_and_valid_target() {
    let offline = McpServer::new(Arc::new(OfflineHost::default()));
    assert_eq!(
        offline.call("route", json!({"host":"127.0.0.1"})).await["isError"],
        true
    );
    let proxy = ProxyService::new();
    let server = McpServer::new(Arc::new(LiveHost(proxy.clone())));
    for args in [
        json!({}),
        json!({"host":" "}),
        json!({"host":"127.0.0.1","port":0}),
        json!({"host":"127.0.0.1","port":65536}),
        json!({"host":"127.0.0.1","port":-1}),
        json!({"host":"127.0.0.1","port":"25565"}),
    ] {
        assert_eq!(server.call("route", args).await["isError"], true);
    }
    assert!(proxy.sessions().is_empty());
}

#[tokio::test]
async fn route_creates_connectable_loopback_listener_and_limits_pending_routes() {
    let proxy = ProxyService::new();
    let server = McpServer::new(Arc::new(LiveHost(proxy.clone())));
    for _ in 0..16 {
        let result = server
            .call("route", json!({"host":"127.0.0.1","port":25565}))
            .await;
        assert_eq!(result["isError"], false, "{result}");
    }
    let denied: Value = server.call("route", json!({"host":"127.0.0.1"})).await;
    assert_eq!(denied["isError"], true);
    let sessions = proxy.sessions();
    let address = sessions[0]
        .listener_address
        .parse::<std::net::SocketAddr>()
        .unwrap();
    assert!(address.ip().is_loopback());
    let _stream = TcpStream::connect(address).await.unwrap();
    for session in sessions {
        let _ = proxy.stop_session(session.id);
    }
}

#[cfg(unix)]
#[tokio::test]
async fn bridge_switches_offline_online_and_back() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("mcp.sock");
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_mineburp-mcp"))
        .args(["--socket", path.to_str().unwrap()])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap()).lines();
    let request = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"status\",\"arguments\":{\"format\":\"json\"}}}\n";
    input.write_all(request).await.unwrap();
    let offline = output.next_line().await.unwrap().unwrap();
    assert!(offline.contains("offline"));
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (reader, writer) = stream.into_split();
        let proxy = ProxyService::new();
        mineburp_mcp::serve(
            reader,
            writer,
            Arc::new(McpServer::new(Arc::new(LiveHost(proxy)))),
        )
        .await
        .unwrap();
    });
    input.write_all(request).await.unwrap();
    let online = output.next_line().await.unwrap().unwrap();
    assert!(online.contains("desktop"));
    task.await.unwrap();
    std::fs::remove_file(&path).unwrap();
    input.write_all(request).await.unwrap();
    let offline = output.next_line().await.unwrap().unwrap();
    assert!(offline.contains("offline"));
    drop(input);
    assert!(child.wait().await.unwrap().success());
}

#[tokio::test]
async fn concurrent_rule_adds_preserve_both_updates() {
    let temp = tempfile::tempdir().unwrap();
    let store = ProjectStore::create(
        temp.path().join("rules.mineburp"),
        "rules",
        mineburp_project::ProjectOptions::default(),
    )
    .unwrap();
    let server = McpServer::new(Arc::new(OfflineHost::new(Some(store.clone()))));
    let (first, second) = tokio::join!(
        server.call("rules", json!({"action":"add","name":"first","expr":"state == handshake","set":{"server_address":"a"}})),
        server.call("rules", json!({"action":"add","name":"second","expr":"state == handshake","set":{"server_address":"b"}}))
    );
    assert_eq!(first["isError"], false, "{first}");
    assert_eq!(second["isError"], false, "{second}");
    assert_eq!(store.load_replacement_rules().unwrap().len(), 2);
}
