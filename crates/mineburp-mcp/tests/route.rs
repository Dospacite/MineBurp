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
