use anyhow::Error;

use proxmox_apt_api_types::APTUpdateInfo;

#[path = "../common/src/mod.rs"]
pub mod common;

pub mod acme;
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

pub fn send_updates_available(_updates: &[&APTUpdateInfo]) -> Result<(), Error> {
    tracing::warn!("update notifications are not implemented for PMG yet");

    Ok(())
}
