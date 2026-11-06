use crate::state::DesktopState;
use serde::Serialize;
use tauri::State;

#[derive(Debug, Serialize)]
pub struct SetupCheck {
    id: &'static str,
    status: &'static str,
    required: bool,
    detail: String,
    hint: &'static str,
}
fn check(
    id: &'static str,
    pass: bool,
    required: bool,
    detail: impl Into<String>,
    hint: &'static str,
) -> SetupCheck {
    SetupCheck {
        id,
        status: if pass {
            "pass"
        } else if required {
            "fail"
        } else {
            "warn"
        },
        required,
        detail: detail.into(),
        hint,
    }
}
fn prerequisite_checks(
    state: &DesktopState,
    probe: mineburp_capture::setup::DumpcapCheck,
) -> Vec<SetupCheck> {
    use mineburp_capture::setup::DumpcapCheck;
    vec![
        check(
            "dumpcap",
            probe != DumpcapCheck::Missing,
            true,
            if probe == DumpcapCheck::Missing {
                "dumpcap is not installed or is not on PATH"
            } else {
                "dumpcap executable found"
            },
            "Debian/Ubuntu: install wireshark-common. Arch/Fedora: install wireshark-cli.",
        ),
        check(
            "capture_permission",
            probe == DumpcapCheck::Ready,
            true,
            probe.reason().unwrap_or("Capture interfaces available"),
            "Debian/Ubuntu: sudo dpkg-reconfigure wireshark-common and enable non-root capture. All distributions: sudo usermod -aG wireshark \"$USER\", then log out and back in. Check dumpcap -D as your normal user. See CONTRIBUTING.md.",
        ),
        check(
            "procfs",
            cfg!(target_os = "linux") && std::path::Path::new("/proc/self/net/tcp").is_file(),
            true,
            "Linux process/socket attribution",
            "Run on Linux with procfs mounted and access to the Minecraft process.",
        ),
        check(
            "agent_jar",
            state.agent_path.is_file(),
            true,
            state.agent_path.display().to_string(),
            "Reinstall MineBurp or run npm run build:agent in a development checkout, then restart.",
        ),
    ]
}
pub async fn setup_check(state: State<'_, DesktopState>) -> Result<Vec<SetupCheck>, String> {
    use mineburp_capture::setup::probe_dumpcap;
    let probe = tokio::task::spawn_blocking(probe_dumpcap)
        .await
        .map_err(|e| e.to_string())?;
    let mut checks = prerequisite_checks(&state, probe);
    let listening = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        tokio::net::TcpStream::connect(state.client_assist.endpoint()),
    )
    .await
    .is_ok_and(|r| r.is_ok());
    checks.push(check(
        "broker",
        listening,
        true,
        "Client-assistance loopback broker",
        "Restart MineBurp and check that local security software permits loopback connections.",
    ));
    let status = state.client_assist.status().await;
    checks.push(check(
        "connected_agents",
        status.connected_agents > 0,
        false,
        format!("{} agents connected", status.connected_agents),
        "Configure assistance, launch that instance, and connect to your authorized server.",
    ));
    match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        state
            .launchers
            .discover_with_argument(&state.client_assist_jvm_argument()),
    )
    .await
    {
        Ok(results) => {
            let instances: Vec<_> = results.into_iter().filter_map(Result::ok).collect();
            checks.push(check(
                "launchers",
                !instances.is_empty(),
                false,
                format!("{} instances discovered", instances.len()),
                "Install a supported launcher or use the manual JVM argument in Instances.",
            ));
            checks.push(check(
                "assistance",
                instances
                    .iter()
                    .any(|i| i.client_assist_configured && !i.client_assist_stale),
                false,
                "Instance assistance configuration",
                "Configure assistance in Instances and restart Minecraft.",
            ));
            checks.push(check(
                "stale_assistance",
                !instances.iter().any(|i| i.client_assist_stale),
                false,
                "Check for outdated assistance arguments",
                "Choose Reconfigure on each stale instance, then restart Minecraft.",
            ));
        }
        Err(_) => checks.push(check(
            "launchers",
            false,
            false,
            "Launcher discovery timed out",
            "Refresh Setup or use the manual JVM argument in Instances.",
        )),
    }
    Ok(checks)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn required_failures_and_optional_warnings_are_distinct() {
        assert_eq!(
            check("required", false, true, "missing", "fix").status,
            "fail"
        );
        assert_eq!(
            check("optional", false, false, "missing", "fix").status,
            "warn"
        );
        assert_eq!(check("ready", true, true, "ready", "fix").status, "pass");
    }
}
