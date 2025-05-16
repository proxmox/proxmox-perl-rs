//! This contains all the perl bindings.

#![deny(missing_docs)]

mod notify;
pub use notify::proxmox_rs_notify;

mod subscription;
pub use subscription::proxmox_rs_subscription;
