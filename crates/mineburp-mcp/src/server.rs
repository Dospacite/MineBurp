//! The tool catalog and dispatcher behind one MCP session.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::{Host, tools};

const INSTRUCTIONS: &str = "\
MineBurp is a Minecraft Java protocol workbench for authorized testing. \
Start with `status`. Packets are rows `#id` in the open project; connections \
are 8-hex-char ids (`c=1a2b3c4d`) that every tool accepts back, as a prefix. \
Frames are hex of the logical frame: packet-id VarInt then body (no length, \
no compression). Typical flow: `packets` (filter with `expr`, e.g. \
`state == play && name ~ chat`) → `packet` id=… for the decode → `rewrite` \
to try edits offline → `repeater` send or `rules` add. `intercept` holds \
live frames for forward/edit/drop. Paging: pass the printed `before=`/`after=` \
cursors; `after` with `wait_ms` waits for new traffic.";

/// One MCP server bound to one host.
pub struct McpServer {
    host: Arc<dyn Host>,
}

impl std::fmt::Debug for McpServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("McpServer")
            .field("mode", &self.host.mode())
            .finish()
    }
}

impl McpServer {
    pub fn new(host: Arc<dyn Host>) -> Self {
        Self { host }
    }

    pub fn instructions(&self) -> String {
        if self.host.mode() == "offline" {
            format!(
                "{INSTRUCTIONS} OFFLINE: no desktop app is attached, so live tools \
                 (intercept, network, repeater send, capture, launcher) are unavailable."
            )
        } else {
            INSTRUCTIONS.to_owned()
        }
    }

    pub fn tool_list(&self) -> Value {
        Value::Array(
            tools::catalog()
                .into_iter()
                .map(|tool| {
                    // Only hints that differ from the spec's defaults
                    // (read-only false, destructive true) are sent.
                    let annotations = if tool.read_only {
                        json!({ "readOnlyHint": true })
                    } else if tool.destructive {
                        json!({})
                    } else {
                        json!({ "destructiveHint": false })
                    };
                    json!({
                        "name": tool.name,
                        "description": tool.description,
                        "inputSchema": tool.schema,
                        "annotations": annotations,
                    })
                })
                .collect(),
        )
    }

    /// Runs one tool and wraps its text as an MCP tool result.
    pub async fn call(&self, name: &str, arguments: Value) -> Value {
        let result = tools::dispatch(self.host.as_ref(), name, arguments).await;
        let (text, is_error) = match result {
            Ok(text) => (text, false),
            Err(error) => (error, true),
        };
        json!({
            "content": [{ "type": "text", "text": text }],
            "isError": is_error,
        })
    }
}
