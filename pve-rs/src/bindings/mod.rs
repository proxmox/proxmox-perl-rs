//! This contains all the perl bindings.

#![deny(missing_docs)]

mod tfa;
pub use tfa::pve_rs_tfa;

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
