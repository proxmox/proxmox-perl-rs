//! Rust library for the Proxmox VE code base.

#![deny(missing_docs)]

use std::sync::OnceLock;

use anyhow::Error;
use serde_json::json;

use proxmox_apt_api_types::APTUpdateInfo;
use proxmox_notify::{Config, Notification, Severity};

#[path = "../common/src/mod.rs"]
mod common;

mod sdn;

pub mod bindings;

fn send_notification(notification: &Notification) -> Result<(), Error> {
    let config = proxmox_sys::fs::file_read_optional_string("/etc/pve/notifications.cfg")?
        .unwrap_or_default();
    let private_config =
        proxmox_sys::fs::file_read_optional_string("/etc/pve/priv/notifications.cfg")?
            .unwrap_or_default();

    let context = crate::notify_context();

    let config =
        Config::parse_section_config(&config, &private_config, Some(context.default_config()))?;

    proxmox_notify::send(context, &config, notification)?;

    Ok(())
}

/// This is the produce specific code to send available upadte information via the notification
/// system. It is called from `common` code.
pub fn send_updates_available(updates: &[&APTUpdateInfo]) -> Result<(), Error> {
    let hostname = proxmox_sys::nodename().to_string();

    // The template uses the `table` handlebars helper, so
    // we need to form the approriate data structure first.
    let update_table = json!({
        "schema": {
            "columns": [
                {
                    "label": "Package",
                    "id": "Package",
                },
                {
                    "label": "Old Version",
                    "id": "OldVersion",
                },
                {
                    "label": "New Version",
                    "id": "Version",
                }
            ],
        },
        "data": updates,
    });

    let template_data = json!({
        "hostname": hostname,
        "updates": update_table,
    });

    let notification = Notification::template_builder("package-updates", template_data)
        .severity(Severity::Info)
        .field("hostname", hostname)
        .field("type", "package-updates")
        .build()?;

    send_notification(&notification)?;
    Ok(())
}

static NOTIFY_CONTEXT: OnceLock<proxmox_notify::Context> = OnceLock::new();

/// Get a reference to the static notification context for PVE.
pub fn notify_context() -> &'static proxmox_notify::Context {
    NOTIFY_CONTEXT
        .get_or_init(|| proxmox_notify::Context::new(proxmox_notify::context::pve::PVEContext))
}
