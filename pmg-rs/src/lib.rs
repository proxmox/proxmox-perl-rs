#[path = "../common/src/mod.rs"]
pub mod common;

pub mod acme;
pub mod apt;
pub mod csr;
pub mod tfa;

#[perlmod::package(name = "Proxmox::Lib::PMG", lib = "pmg_rs")]
mod export {
    use crate::common;

    #[export]
    pub fn init() {
        common::logger::init("PMG_LOG", "info");
    }
}
