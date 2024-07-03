//! Rust library for the Proxmox VE code base.

#[path = "../common/src/mod.rs"]
pub mod common;

pub mod apt;
pub mod openid;
pub mod resource_scheduling;
pub mod tfa;

use std::collections::HashMap;

use anyhow::Error;

use proxmox_apt_api_types::APTUpdateInfo;
use proxmox_notify::{Config, Notification, Severity};
use serde_json::json;

#[perlmod::package(name = "Proxmox::Lib::PVE", lib = "pve_rs")]
mod export {
    use proxmox_notify::context::pve::PVE_CONTEXT;

    use crate::common;

    #[export]
    pub fn init() {
        common::logger::init("PVE_LOG", "info");
        proxmox_notify::context::set_context(&PVE_CONTEXT);
    }
}

fn send_notification(notification: &Notification) -> Result<(), Error> {
    let config = proxmox_sys::fs::file_read_optional_string("/etc/pve/notifications.cfg")?
        .unwrap_or_default();
    let private_config =
        proxmox_sys::fs::file_read_optional_string("/etc/pve/priv/notifications.cfg")?
            .unwrap_or_default();

    let config = Config::new(&config, &private_config)?;

    proxmox_notify::api::common::send(&config, notification)?;

    Ok(())
}

pub fn send_updates_available(updates: &[&APTUpdateInfo]) -> Result<(), Error> {
    let hostname = proxmox_sys::nodename().to_string();

    let metadata = HashMap::from([
        ("hostname".into(), hostname.clone()),
        ("type".into(), "package-updates".into()),
    ]);

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

    let notification =
        Notification::from_template(Severity::Info, "package-updates", template_data, metadata);

    send_notification(&notification)?;
    Ok(())
}
