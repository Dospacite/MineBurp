//! Generates the desktop app's permission manifest.
//!
//! Every command the webview may call is listed here, so Tauri generates an
//! `allow-<command>` permission for it, and the main window's capability in
//! `capabilities/default.json` grants exactly these. A command registered in
//! `generate_handler!` but missing from both is refused at runtime; a unit test
//! in `src/lib.rs` keeps the three lists identical.

const COMMANDS: &[&str] = &[
    "app_capabilities",
    "decrypt_mode_status",
    "decrypt_mode_set",
    "capture_start",
    "capture_stop",
    "capture_stats",
    "project_create",
    "project_open",
    "project_save_as",
    "project_current",
    "project_checkpoint",
    "connections_query",
    "packets_query",
    "packets_export",
    "packets_export_pcapng",
    "packets_delete",
    "packets_query_cancel",
    "capture_import",
    "project_compact",
    "traffic_stats",
    "packet_annotations_get",
    "packet_annotations_list",
    "packet_annotation_set",
    "saved_filters_list",
    "saved_filter_save",
    "saved_filter_delete",
    "filter_vocabulary",
    "filter_validate",
    "packet_detail",
    "packet_bytes",
    "inspect_bytes",
    "packet_layout",
    "field_edit",
    "proxy_sessions",
    "intercept_settings_get",
    "intercept_settings_set",
    "intercept_pending",
    "intercept_resolve",
    "intercept_forward_all",
    "network_conditions_get",
    "network_conditions_set",
    "replacement_rules_set",
    "replacement_rules_get",
    "replacement_preview",
    "repeater_send",
    "repeater_tabs",
    "repeater_tab_save",
    "repeater_tab_delete",
    "protocol_versions",
    "schema_validate",
    "launcher_instances",
    "launcher_launch",
    "client_assist_status",
    "launcher_client_assist_configure",
    "auth_begin",
    "auth_complete",
    "auth_session",
    "auth_refresh",
    "auth_sign_out",
];

fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("failed to generate the desktop permission manifest");
}
