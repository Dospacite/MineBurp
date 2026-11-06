//! MCP's JSON-RPC framing: one JSON message per line, as on stdio.

use std::sync::Arc;

use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    sync::mpsc,
};

use crate::server::McpServer;

/// Protocol revisions this server speaks, newest first.
const PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

/// The longest line accepted from a client. Tool arguments carry at most a
/// frame of hex or a schema pack, far below this.
const MAX_LINE: usize = 16 * 1024 * 1024;

/// Serves one MCP session until the reader closes.
///
/// Tool calls run concurrently so a call that waits for traffic does not
/// hold up a quick one behind it; responses are written as they finish.
pub async fn serve<R, W>(reader: R, writer: W, server: Arc<McpServer>) -> std::io::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (sender, mut receiver) = mpsc::channel::<Value>(64);
    let writer_task = tokio::spawn(async move {
        let mut writer = writer;
        while let Some(message) = receiver.recv().await {
            let mut line = serde_json::to_vec(&message).unwrap_or_default();
            line.push(b'\n');
            if writer.write_all(&line).await.is_err() || writer.flush().await.is_err() {
                break;
            }
        }
    });

    let mut lines = BufReader::new(reader);
    let mut buffer = String::new();
    loop {
        buffer.clear();
        let read = (&mut lines)
            .take((MAX_LINE + 1) as u64)
            .read_line(&mut buffer)
            .await?;
        if read == 0 {
            break;
        }
        if buffer.len() > MAX_LINE {
            let _ = sender
                .send(error_response(&Value::Null, -32600, "message too large"))
                .await;
            break;
        }
        let text = buffer.trim();
        if text.is_empty() {
            continue;
        }
        let message: Value = match serde_json::from_str(text) {
            Ok(message) => message,
            Err(error) => {
                let _ = sender
                    .send(error_response(&Value::Null, -32700, &error.to_string()))
                    .await;
                continue;
            }
        };
        let messages = match message {
            Value::Array(batch) => batch,
            single => vec![single],
        };
        for message in messages {
            let server = server.clone();
            let sender = sender.clone();
            tokio::spawn(async move {
                if let Some(response) = handle(&server, message).await {
                    let _ = sender.send(response).await;
                }
            });
        }
    }
    drop(sender);
    let _ = writer_task.await;
    Ok(())
}

/// Answers one message; notifications and responses get no reply.
async fn handle(server: &McpServer, message: Value) -> Option<Value> {
    let method = message.get("method")?.as_str()?.to_owned();
    let id = message.get("id").cloned();
    let params = message.get("params").cloned().unwrap_or(Value::Null);
    let id = id?;
    let result = match method.as_str() {
        "initialize" => Ok(initialize(server, &params)),
        "ping" | "logging/setLevel" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": server.tool_list() })),
        "tools/call" => {
            let Some(name) = params.get("name").and_then(Value::as_str) else {
                return Some(error_response(&id, -32602, "tools/call needs a `name`"));
            };
            let arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            Ok(server.call(name, arguments).await)
        }
        "resources/list" => Ok(json!({ "resources": [] })),
        "resources/templates/list" => Ok(json!({ "resourceTemplates": [] })),
        "prompts/list" => Ok(json!({ "prompts": [] })),
        _ => Err((-32601, format!("method `{method}` is not supported"))),
    };
    Some(match result {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err((code, message)) => error_response(&id, code, &message),
    })
}

fn initialize(server: &McpServer, params: &Value) -> Value {
    let requested = params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .unwrap_or(PROTOCOL_VERSIONS[0]);
    let version = PROTOCOL_VERSIONS
        .iter()
        .find(|version| **version == requested)
        .copied()
        .unwrap_or(PROTOCOL_VERSIONS[0]);
    json!({
        "protocolVersion": version,
        "capabilities": { "tools": { "listChanged": false } },
        "serverInfo": { "name": "mineburp", "version": env!("CARGO_PKG_VERSION") },
        "instructions": server.instructions(),
    })
}

fn error_response(id: &Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OfflineHost;

    async fn exchange(input: &str) -> Vec<Value> {
        let server = Arc::new(McpServer::new(Arc::new(OfflineHost::default())));
        let (client, server_end) = tokio::io::duplex(1 << 20);
        let (server_read, server_write) = tokio::io::split(server_end);
        let task = tokio::spawn(serve(server_read, server_write, server));
        let (client_read, mut client_write) = tokio::io::split(client);
        client_write.write_all(input.as_bytes()).await.unwrap();
        client_write.shutdown().await.unwrap();
        drop(client_write);
        let mut lines = BufReader::new(client_read).lines();
        let mut out = Vec::new();
        while let Ok(Some(line)) = lines.next_line().await {
            out.push(serde_json::from_str(&line).unwrap());
        }
        task.await.unwrap().unwrap();
        out
    }

    #[tokio::test]
    async fn initializes_lists_and_calls() {
        let replies = exchange(concat!(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"decode","arguments":{"hex":"00","state":"handshake","dir":"c2s"}}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":4,"method":"nope"}"#,
            "\n",
        ))
        .await;
        assert_eq!(replies.len(), 4, "the notification gets no reply");
        let by_id = |id: i64| {
            replies
                .iter()
                .find(|reply| reply["id"] == id)
                .unwrap()
                .clone()
        };
        assert_eq!(by_id(1)["result"]["protocolVersion"], "2025-03-26");
        assert!(by_id(2)["result"]["tools"].as_array().unwrap().len() > 10);
        assert!(by_id(3)["result"]["content"][0]["text"].is_string());
        assert_eq!(by_id(4)["error"]["code"], -32601);
    }
}
