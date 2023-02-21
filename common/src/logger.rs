/// Initialize logging. Should only be called once
pub fn init() {
    if let Err(e) = env_logger::try_init() {
        eprintln!("could not set up env_logger: {e}");
    }
}
