//! Resource scheduling related bindings.

mod resource;
mod usage;

mod pve_static;
pub use pve_static::pve_rs_resource_scheduling_static;

mod pve_dynamic;
pub use pve_dynamic::pve_rs_resource_scheduling_dynamic;
