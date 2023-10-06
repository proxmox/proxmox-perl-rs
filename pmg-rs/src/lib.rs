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

    /// CLI tools should call this very early. This is a workaround causing environment variable
    /// manipulation to leak instead of crash. Required when calling into rust code that causes
    /// `setenv` calls, particularly code using the openssl crate.
    #[export]
    pub fn use_safe_putenv() {
        perlmod::ffi::use_safe_putenv(true);
    }
}
