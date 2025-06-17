//! This contains all the perl bindings.

mod resource_scheduling_static;
pub use resource_scheduling_static::pve_rs_resource_scheduling_static;

mod tfa;
pub use tfa::pve_rs_tfa;

mod openid;
pub use openid::pve_rs_open_id;

pub mod firewall;

#[allow(unused_imports)]
pub use crate::common::bindings::*;

#[perlmod::package(name = "Proxmox::Lib::PVE", lib = "pve_rs")]
pub mod proxmox_lib_pve {
    //! The `Proxmox::Lib::PVE` package.
    //!
    //! This contains the `init` function executed by the module on startup.

    use proxmox_notify::context::pve::PVE_CONTEXT;

    use crate::common;

    #[export]
    fn init() {
        common::logger::init("PVE_LOG", "info");
        proxmox_notify::context::set_context(&PVE_CONTEXT);
    }
}
