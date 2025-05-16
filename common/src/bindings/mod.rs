//! This contains all the perl bindings.

#![deny(missing_docs)]

mod apt_repositories;
pub use apt_repositories::proxmox_rs_apt_repositories;

mod calendar_event;
pub use calendar_event::proxmox_rs_calendar_event;

mod notify;
pub use notify::proxmox_rs_notify;

mod oidc;
pub use oidc::proxmox_rs_oidc;

mod subscription;
pub use subscription::proxmox_rs_subscription;

mod shared_cache;
pub use shared_cache::proxmox_rs_shared_cache;
