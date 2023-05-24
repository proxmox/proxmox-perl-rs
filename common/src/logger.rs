use env_logger::{Builder, Env};
use std::io::Write;

/// Initialize logging. Should only be called once
pub fn init(env_var_name: &str, default_log_level: &str) {
    if let Err(e) = Builder::from_env(Env::new().filter_or(env_var_name, default_log_level))
        .format(|buf, record| writeln!(buf, "{}: {}", record.level(), record.args()))
        .write_style(env_logger::WriteStyle::Never)
        .format_timestamp(None)
        .try_init()
    {
        eprintln!("could not set up env_logger: {e}");
    }
}
