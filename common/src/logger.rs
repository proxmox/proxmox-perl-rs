use anyhow::Error;

/// Initialize logging. Should only be called once
pub fn init(env_var_name: &str, default_log_level: &str) {
    if let Err(e) = default_log_level
        .parse()
        .map_err(Error::from)
        .and_then(|default_log_level| proxmox_log::init_logger(env_var_name, default_log_level))
    {
        eprintln!("could not set up env_logger: {e:?}");
    }
}
