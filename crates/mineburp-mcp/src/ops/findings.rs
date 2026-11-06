//! Portable assessment reports. All captured text is escaped before HTML output.
use super::{PathPurpose, validate_path};
use mineburp_core::{Evidence, Severity};
use mineburp_project::ProjectStore;
use std::{fmt::Write as _, io::Write as _, path::Path};

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
#[allow(
    clippy::too_many_lines,
    reason = "report sections share a single escaped output buffer"
)]
pub fn render_findings(store: &ProjectStore, html: bool) -> Result<String, String> {
    let findings = store.list_findings(None, None).map_err(|e| e.to_string())?;
    let mut table =
        String::from("<table><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>");
    for severity in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        let count = findings.iter().filter(|f| f.severity == severity).count();
        let _ = write!(table, "<tr><td>{severity:?}</td><td>{count}</td></tr>");
    }
    table.push_str("</tbody></table>");
    let mut out = String::from("# Findings\n\n| Severity | Count |\n| --- | --- |\n");
    for severity in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        let count = findings.iter().filter(|f| f.severity == severity).count();
        let _ = writeln!(out, "| {severity:?} | {count} |");
    }
    for f in findings {
        let _ = write!(
            out,
            "\n## {}\n\n{:?} · {:?}\n\n{}\n\n### Reproduction steps\n\n{}\n\n### Evidence\n",
            escape(&f.title),
            f.severity,
            f.status,
            escape(&f.description),
            escape(&f.reproduction_steps)
        );
        let _ = writeln!(
            out,
            "Created: {} · Updated: {}\nTags: {}",
            f.created_at_micros,
            f.updated_at_micros,
            escape(&f.tags.join(", "))
        );
        for evidence in f.evidence {
            if let Evidence::Packet(id) = evidence {
                if let Some(packet) = store.packet_detail(id).map_err(|e| e.to_string())? {
                    let s = &packet.summary;
                    let _ = writeln!(
                        out,
                        "\nPacket #{id} time={} {:?} {:?} {} connection={}\n",
                        s.timestamp_micros,
                        s.direction,
                        s.state,
                        escape(s.name.as_deref().unwrap_or("unknown")),
                        s.connection_id
                    );
                    let insight = mineburp_protocol::inspect_logical(
                        s.state,
                        s.direction,
                        &packet.logical_bytes,
                        s.protocol_version,
                    );
                    if let Some(connection) = store
                        .connection(s.connection_id)
                        .map_err(|e| e.to_string())?
                    {
                        let _ = writeln!(
                            out,
                            "Endpoints: {} → {}:{}",
                            escape(&connection.listener_address),
                            escape(&connection.target.host),
                            connection.target.port
                        );
                    }
                    let decoded = format!("{insight:?}");
                    let bounded: String = decoded.chars().take(65536).collect();
                    let _ = writeln!(out, "{}\n\nHex (first 512 bytes):", escape(&bounded));
                    for byte in packet.logical_bytes.iter().take(512) {
                        let _ = write!(out, "{byte:02x}");
                    }
                    out.push('\n');
                } else {
                    let _ = writeln!(out, "Packet #{id}: missing");
                }
            } else {
                let missing = match &evidence {
                    Evidence::Connection(id) => {
                        store.connection(*id).map_err(|e| e.to_string())?.is_none()
                    }
                    Evidence::Repeater(id) => !store
                        .load_repeater_tabs()
                        .map_err(|e| e.to_string())?
                        .iter()
                        .any(|t| t.id == *id),
                    Evidence::Rule(id) => !store
                        .load_replacement_rules()
                        .map_err(|e| e.to_string())?
                        .iter()
                        .any(|r| r.id == *id),
                    Evidence::Packet(_) => false,
                };
                let _ = writeln!(
                    out,
                    "{evidence:?}{}",
                    if missing { ": missing" } else { "" }
                );
            }
        }
    }
    if html {
        Ok(format!(
            "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Findings</title><body>{table}<pre>{out}</pre></body></html>"
        ))
    } else {
        Ok(out)
    }
}
pub fn export_findings_with_overwrite(
    store: &ProjectStore,
    path: &Path,
    html: bool,
    overwrite: bool,
) -> Result<(), String> {
    let purpose = if html {
        PathPurpose::ExportHtml
    } else {
        PathPurpose::ExportMarkdown
    };
    let info = store.info();
    validate_path(path, purpose, &[&info.path])?;
    super::check_export_target(path, overwrite)?;
    let mut temporary = tempfile::NamedTempFile::new_in(path.parent().ok_or("missing parent")?)
        .map_err(|e| e.to_string())?;
    temporary
        .write_all(render_findings(store, html)?.as_bytes())
        .map_err(|e| e.to_string())?;
    super::publish_export(temporary, path, overwrite)
}
#[cfg(test)]
mod tests {
    #[test]
    fn escapes_hostile_capture_text() {
        assert_eq!(super::escape("<script>\"&"), "&lt;script&gt;&quot;&amp;");
    }
}
