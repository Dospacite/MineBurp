//! `mineburp-mcp`: the MCP server an MCP client launches over stdio.
//!
//! With the desktop app running, stdio is bridged to the app's private socket
//! so every tool — live intercept and Repeater included — acts on the app.
//! Otherwise (or with `--project`/`--offline`) the tools run here against a
//! project file and the live ones report that they need the app.

use std::{path::PathBuf, process::ExitCode, sync::Arc};

use mineburp_mcp::{McpServer, OfflineHost, serve};
use mineburp_project::{ProjectOptions, ProjectStore};

const USAGE: &str = "\
usage: mineburp-mcp [--project FILE.mineburp] [--passphrase-env VAR] [--read-only]
                    [--offline] [--socket PATH]

Speaks MCP on stdin/stdout. Connects to the running MineBurp app when it is
available; otherwise serves offline against --project (or no project, which
the `project` tool can open later).

  --project FILE       open this project and serve offline
  --passphrase-env VAR read the project passphrase from environment variable VAR
  --read-only          open the project read-only
  --offline            never connect to the app
  --socket PATH        app socket (default: $MINEBURP_MCP_SOCKET, then
                       $XDG_RUNTIME_DIR/mineburp/mcp.sock)";

#[derive(Debug, Default)]
struct Options {
    project: Option<PathBuf>,
    passphrase_env: Option<String>,
    read_only: bool,
    offline: bool,
    socket: Option<PathBuf>,
}

fn parse() -> Result<Options, String> {
    let mut options = Options::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = |name: &str| args.next().ok_or_else(|| format!("{name} needs a value"));
        match arg.as_str() {
            "--project" => options.project = Some(PathBuf::from(value("--project")?)),
            "--passphrase-env" => options.passphrase_env = Some(value("--passphrase-env")?),
            "--read-only" => options.read_only = true,
            "--offline" => options.offline = true,
            "--socket" => options.socket = Some(PathBuf::from(value("--socket")?)),
            "-h" | "--help" => return Err(String::new()),
            "-V" | "--version" => {
                println!("mineburp-mcp {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument `{other}`")),
        }
    }
    Ok(options)
}

#[tokio::main]
async fn main() -> ExitCode {
    let options = match parse() {
        Ok(options) => options,
        Err(error) => {
            if !error.is_empty() {
                eprintln!("mineburp-mcp: {error}");
            }
            eprintln!("{USAGE}");
            return if error.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            };
        }
    };

    #[cfg(unix)]
    if !options.offline && options.project.is_none() {
        let path = options
            .socket
            .clone()
            .unwrap_or_else(mineburp_mcp::socket::default_socket_path);
        if let Ok(stream) = tokio::net::UnixStream::connect(&path).await {
            eprintln!(
                "mineburp-mcp: connected to the MineBurp app at {}",
                path.display()
            );
            return bridge(stream).await;
        }
        eprintln!("mineburp-mcp: the MineBurp app is not running; serving offline");
    }

    let project = match &options.project {
        Some(path) => {
            let passphrase = if let Some(variable) = &options.passphrase_env {
                let Ok(value) = std::env::var(variable) else {
                    eprintln!("mineburp-mcp: environment variable `{variable}` is not set");
                    return ExitCode::from(2);
                };
                Some(value)
            } else {
                None
            };
            match ProjectStore::open(
                path,
                ProjectOptions {
                    passphrase,
                    read_only: options.read_only,
                },
            ) {
                Ok(store) => Some(store),
                Err(error) => {
                    eprintln!("mineburp-mcp: cannot open {}: {error}", path.display());
                    return ExitCode::FAILURE;
                }
            }
        }
        None => None,
    };
    let server = Arc::new(McpServer::new(Arc::new(OfflineHost::new(project))));
    match serve(tokio::io::stdin(), tokio::io::stdout(), server).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("mineburp-mcp: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Copies stdio to the app's socket and back.
///
/// Ends when the app side closes: after stdin's EOF is passed on, the app
/// finishes the calls in flight and closes, and if the app quits first there
/// is nothing left to talk to.
#[cfg(unix)]
async fn bridge(stream: tokio::net::UnixStream) -> ExitCode {
    let (mut socket_read, mut socket_write) = stream.into_split();
    tokio::spawn(async move {
        let _ = tokio::io::copy(&mut tokio::io::stdin(), &mut socket_write).await;
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut socket_write).await;
    });
    let _ = tokio::io::copy(&mut socket_read, &mut tokio::io::stdout()).await;
    ExitCode::SUCCESS
}
