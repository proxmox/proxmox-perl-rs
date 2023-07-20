use std::path::Path;

use log;

use proxmox_notify::context::Context;

// Some helpers borrowed and slightly adapted from `proxmox-mail-forward`

fn normalize_for_return(s: Option<&str>) -> Option<String> {
    match s?.trim() {
        "" => None,
        s => Some(s.to_string()),
    }
}

fn attempt_file_read<P: AsRef<Path>>(path: P) -> Option<String> {
    match proxmox_sys::fs::file_read_optional_string(path) {
        Ok(contents) => contents,
        Err(err) => {
            log::error!("{err}");
            None
        }
    }
}

fn lookup_mail_address(content: &str, user: &str) -> Option<String> {
    normalize_for_return(content.lines().find_map(|line| {
        let fields: Vec<&str> = line.split(':').collect();
        #[allow(clippy::get_first)] // to keep expression style consistent
        match fields.get(0)?.trim() == "user" && fields.get(1)?.trim() == user {
            true => fields.get(6).copied(),
            false => None,
        }
    }))
}

fn lookup_datacenter_config_key(content: &str, key: &str) -> Option<String> {
    let key_prefix = format!("{key}:");
    normalize_for_return(
        content
            .lines()
            .find_map(|line| line.strip_prefix(&key_prefix)),
    )
}

#[derive(Debug)]
struct PVEContext;

impl Context for PVEContext {
    fn lookup_email_for_user(&self, user: &str) -> Option<String> {
        let content = attempt_file_read("/etc/pve/user.cfg");
        content.and_then(|content| lookup_mail_address(&content, user))
    }

    fn default_sendmail_author(&self) -> String {
        "Proxmox VE".into()
    }

    fn default_sendmail_from(&self) -> String {
        let content = attempt_file_read("/etc/pve/datacenter.cfg");
        content
            .and_then(|content| lookup_datacenter_config_key(&content, "mail_from"))
            .unwrap_or_else(|| String::from("root"))
    }
}

#[cfg(test)]
mod tests {
    use crate::notify::{lookup_datacenter_config_key, lookup_mail_address};

    const USER_CONFIG: &str = "
user:root@pam:1:0:::root@example.com:::
user:test@pve:1:0:::test@example.com:::
user:no-mail@pve:1:0::::::
    ";

    #[test]
    fn test_parse_mail() {
        assert_eq!(
            lookup_mail_address(USER_CONFIG, "root@pam"),
            Some("root@example.com".to_string())
        );
        assert_eq!(
            lookup_mail_address(USER_CONFIG, "test@pve"),
            Some("test@example.com".to_string())
        );
        assert_eq!(lookup_mail_address(USER_CONFIG, "no-mail@pve"), None);
    }

    const DC_CONFIG: &str = "
email_from: user@example.com
keyboard: en-us
";
    #[test]
    fn test_parse_dc_config() {
        assert_eq!(
            lookup_datacenter_config_key(DC_CONFIG, "email_from"),
            Some("user@example.com".to_string())
        );
    }
}

static CONTEXT: PVEContext = PVEContext;

pub fn init() {
    proxmox_notify::context::set_context(&CONTEXT)
}

#[perlmod::package(name = "PVE::RS::Notify")]
mod export {
    use anyhow::{bail, Error};
    use perlmod::Value;
    use serde_json::Value as JSONValue;
    use std::sync::Mutex;

    use proxmox_notify::endpoints::gotify::{
        DeleteableGotifyProperty, GotifyConfig, GotifyConfigUpdater, GotifyPrivateConfig,
        GotifyPrivateConfigUpdater,
    };
    use proxmox_notify::endpoints::sendmail::{
        DeleteableSendmailProperty, SendmailConfig, SendmailConfigUpdater,
    };
    use proxmox_notify::filter::{
        DeleteableFilterProperty, FilterConfig, FilterConfigUpdater, FilterModeOperator,
    };
    use proxmox_notify::group::{DeleteableGroupProperty, GroupConfig, GroupConfigUpdater};
    use proxmox_notify::{api, api::ApiError, Config, Notification, Severity};

    pub struct NotificationConfig {
        config: Mutex<Config>,
    }

    perlmod::declare_magic!(Box<NotificationConfig> : &NotificationConfig as "PVE::RS::Notify");

    /// Support `dclone` so this can be put into the `ccache` of `PVE::Cluster`.
    #[export(name = "STORABLE_freeze", raw_return)]
    fn storable_freeze(
        #[try_from_ref] this: &NotificationConfig,
        cloning: bool,
    ) -> Result<Value, Error> {
        if !cloning {
            bail!("freezing Notification config not supported!");
        }

        let mut cloned = Box::new(NotificationConfig {
            config: Mutex::new(this.config.lock().unwrap().clone()),
        });
        let value = Value::new_pointer::<NotificationConfig>(&mut *cloned);
        let _perl = Box::leak(cloned);
        Ok(value)
    }

    /// Instead of `thaw` we implement `attach` for `dclone`.
    #[export(name = "STORABLE_attach", raw_return)]
    fn storable_attach(
        #[raw] class: Value,
        cloning: bool,
        #[raw] serialized: Value,
    ) -> Result<Value, Error> {
        if !cloning {
            bail!("STORABLE_attach called with cloning=false");
        }
        let data = unsafe { Box::from_raw(serialized.pv_raw::<NotificationConfig>()?) };
        Ok(perlmod::instantiate_magic!(&class, MAGIC => data))
    }

    #[export(raw_return)]
    fn parse_config(
        #[raw] class: Value,
        raw_config: &[u8],
        raw_private_config: &[u8],
    ) -> Result<Value, Error> {
        let raw_config = std::str::from_utf8(raw_config)?;
        let raw_private_config = std::str::from_utf8(raw_private_config)?;

        Ok(perlmod::instantiate_magic!(&class, MAGIC => Box::new(
            NotificationConfig {
                config: Mutex::new(Config::new(raw_config, raw_private_config)?)
            }
        )))
    }

    #[export]
    fn write_config(#[try_from_ref] this: &NotificationConfig) -> Result<(String, String), Error> {
        Ok(this.config.lock().unwrap().write()?)
    }

    #[export]
    fn digest(#[try_from_ref] this: &NotificationConfig) -> String {
        let config = this.config.lock().unwrap();
        hex::encode(config.digest())
    }

    #[export(serialize_error)]
    fn send(
        #[try_from_ref] this: &NotificationConfig,
        channel: &str,
        severity: Severity,
        title: String,
        body: String,
        properties: Option<JSONValue>,
    ) -> Result<(), ApiError> {
        let config = this.config.lock().unwrap();

        let notification = Notification {
            severity,
            title,
            body,
            properties,
        };

        api::common::send(&config, channel, &notification)
    }

    #[export(serialize_error)]
    fn test_target(
        #[try_from_ref] this: &NotificationConfig,
        target: &str,
    ) -> Result<(), ApiError> {
        let config = this.config.lock().unwrap();
        api::common::test_target(&config, target)
    }

    #[export(serialize_error)]
    fn get_groups(#[try_from_ref] this: &NotificationConfig) -> Result<Vec<GroupConfig>, ApiError> {
        let config = this.config.lock().unwrap();
        api::group::get_groups(&config)
    }

    #[export(serialize_error)]
    fn get_group(
        #[try_from_ref] this: &NotificationConfig,
        id: &str,
    ) -> Result<GroupConfig, ApiError> {
        let config = this.config.lock().unwrap();
        api::group::get_group(&config, id)
    }

    #[export(serialize_error)]
    fn add_group(
        #[try_from_ref] this: &NotificationConfig,
        name: String,
        endpoints: Vec<String>,
        comment: Option<String>,
        filter: Option<String>,
    ) -> Result<(), ApiError> {
        let mut config = this.config.lock().unwrap();
        api::group::add_group(
            &mut config,
            &GroupConfig {
                name,
                endpoint: endpoints,
                comment,
                filter,
            },
        )
    }

    #[export(serialize_error)]
    fn update_group(
        #[try_from_ref] this: &NotificationConfig,
        name: &str,
        endpoints: Option<Vec<String>>,
        comment: Option<String>,
        filter: Option<String>,
        delete: Option<Vec<DeleteableGroupProperty>>,
        digest: Option<&str>,
    ) -> Result<(), ApiError> {
        let mut config = this.config.lock().unwrap();
        let digest = digest.map(hex::decode).transpose().map_err(|e| {
            ApiError::internal_server_error(format!("invalid digest: {e}"), Some(Box::new(e)))
        })?;

        api::group::update_group(
            &mut config,
            name,
            &GroupConfigUpdater {
                endpoint: endpoints,
                comment,
                filter,
            },
            delete.as_deref(),
            digest.as_deref(),
        )
    }

    #[export(serialize_error)]
    fn delete_group(#[try_from_ref] this: &NotificationConfig, name: &str) -> Result<(), ApiError> {
        let mut config = this.config.lock().unwrap();
        api::group::delete_group(&mut config, name)
    }

    #[export(serialize_error)]
    fn get_sendmail_endpoints(
        #[try_from_ref] this: &NotificationConfig,
    ) -> Result<Vec<SendmailConfig>, ApiError> {
        let config = this.config.lock().unwrap();
        api::sendmail::get_endpoints(&config)
    }

    #[export(serialize_error)]
    fn get_sendmail_endpoint(
        #[try_from_ref] this: &NotificationConfig,
        id: &str,
    ) -> Result<SendmailConfig, ApiError> {
        let config = this.config.lock().unwrap();
        api::sendmail::get_endpoint(&config, id)
    }

    #[export(serialize_error)]
    #[allow(clippy::too_many_arguments)]
    fn add_sendmail_endpoint(
        #[try_from_ref] this: &NotificationConfig,
        name: String,
        mailto: Option<Vec<String>>,
        mailto_user: Option<Vec<String>>,
        from_address: Option<String>,
        author: Option<String>,
        comment: Option<String>,
        filter: Option<String>,
    ) -> Result<(), ApiError> {
        let mut config = this.config.lock().unwrap();

        api::sendmail::add_endpoint(
            &mut config,
            &SendmailConfig {
                name,
                mailto,
                mailto_user,
                from_address,
                author,
                comment,
                filter,
            },
        )
    }

    #[export(serialize_error)]
    #[allow(clippy::too_many_arguments)]
    fn update_sendmail_endpoint(
        #[try_from_ref] this: &NotificationConfig,
        name: &str,
        mailto: Option<Vec<String>>,
        mailto_user: Option<Vec<String>>,
        from_address: Option<String>,
        author: Option<String>,
        comment: Option<String>,
        filter: Option<String>,
        delete: Option<Vec<DeleteableSendmailProperty>>,
        digest: Option<&str>,
    ) -> Result<(), ApiError> {
        let mut config = this.config.lock().unwrap();
        let digest = digest.map(hex::decode).transpose().map_err(|e| {
            ApiError::internal_server_error(format!("invalid digest: {e}"), Some(Box::new(e)))
        })?;

        api::sendmail::update_endpoint(
            &mut config,
            name,
            &SendmailConfigUpdater {
                mailto,
                mailto_user,
                from_address,
                author,
                comment,
                filter,
            },
            delete.as_deref(),
            digest.as_deref(),
        )
    }

    #[export(serialize_error)]
    fn delete_sendmail_endpoint(
        #[try_from_ref] this: &NotificationConfig,
        name: &str,
    ) -> Result<(), ApiError> {
        let mut config = this.config.lock().unwrap();
        api::sendmail::delete_endpoint(&mut config, name)
    }

    #[export(serialize_error)]
    fn get_gotify_endpoints(
        #[try_from_ref] this: &NotificationConfig,
    ) -> Result<Vec<GotifyConfig>, ApiError> {
        let config = this.config.lock().unwrap();
        api::gotify::get_endpoints(&config)
    }

    #[export(serialize_error)]
    fn get_gotify_endpoint(
        #[try_from_ref] this: &NotificationConfig,
        id: &str,
    ) -> Result<GotifyConfig, ApiError> {
        let config = this.config.lock().unwrap();
        api::gotify::get_endpoint(&config, id)
    }

    #[export(serialize_error)]
    fn add_gotify_endpoint(
        #[try_from_ref] this: &NotificationConfig,
        name: String,
        server: String,
        token: String,
        comment: Option<String>,
        filter: Option<String>,
    ) -> Result<(), ApiError> {
        let mut config = this.config.lock().unwrap();
        api::gotify::add_endpoint(
            &mut config,
            &GotifyConfig {
                name: name.clone(),
                server,
                comment,
                filter,
            },
            &GotifyPrivateConfig { name, token },
        )
    }

    #[export(serialize_error)]
    #[allow(clippy::too_many_arguments)]
    fn update_gotify_endpoint(
        #[try_from_ref] this: &NotificationConfig,
        name: &str,
        server: Option<String>,
        token: Option<String>,
        comment: Option<String>,
        filter: Option<String>,
        delete: Option<Vec<DeleteableGotifyProperty>>,
        digest: Option<&str>,
    ) -> Result<(), ApiError> {
        let mut config = this.config.lock().unwrap();
        let digest = digest.map(hex::decode).transpose().map_err(|e| {
            ApiError::internal_server_error(format!("invalid digest: {e}"), Some(Box::new(e)))
        })?;

        api::gotify::update_endpoint(
            &mut config,
            name,
            &GotifyConfigUpdater {
                server,
                comment,
                filter,
            },
            &GotifyPrivateConfigUpdater { token },
            delete.as_deref(),
            digest.as_deref(),
        )
    }

    #[export(serialize_error)]
    fn delete_gotify_endpoint(
        #[try_from_ref] this: &NotificationConfig,
        name: &str,
    ) -> Result<(), ApiError> {
        let mut config = this.config.lock().unwrap();
        api::gotify::delete_gotify_endpoint(&mut config, name)
    }

    #[export(serialize_error)]
    fn get_filters(
        #[try_from_ref] this: &NotificationConfig,
    ) -> Result<Vec<FilterConfig>, ApiError> {
        let config = this.config.lock().unwrap();
        api::filter::get_filters(&config)
    }

    #[export(serialize_error)]
    fn get_filter(
        #[try_from_ref] this: &NotificationConfig,
        id: &str,
    ) -> Result<FilterConfig, ApiError> {
        let config = this.config.lock().unwrap();
        api::filter::get_filter(&config, id)
    }

    #[export(serialize_error)]
    #[allow(clippy::too_many_arguments)]
    fn add_filter(
        #[try_from_ref] this: &NotificationConfig,
        name: String,
        min_severity: Option<Severity>,
        mode: Option<FilterModeOperator>,
        invert_match: Option<bool>,
        comment: Option<String>,
    ) -> Result<(), ApiError> {
        let mut config = this.config.lock().unwrap();
        api::filter::add_filter(
            &mut config,
            &FilterConfig {
                name,
                min_severity,
                mode,
                invert_match,
                comment,
            },
        )
    }

    #[export(serialize_error)]
    #[allow(clippy::too_many_arguments)]
    fn update_filter(
        #[try_from_ref] this: &NotificationConfig,
        name: &str,
        min_severity: Option<Severity>,
        mode: Option<FilterModeOperator>,
        invert_match: Option<bool>,
        comment: Option<String>,
        delete: Option<Vec<DeleteableFilterProperty>>,
        digest: Option<&str>,
    ) -> Result<(), ApiError> {
        let mut config = this.config.lock().unwrap();
        let digest = digest.map(hex::decode).transpose().map_err(|e| {
            ApiError::internal_server_error(format!("invalid digest: {e}"), Some(Box::new(e)))
        })?;

        api::filter::update_filter(
            &mut config,
            name,
            &FilterConfigUpdater {
                min_severity,
                mode,
                invert_match,
                comment,
            },
            delete.as_deref(),
            digest.as_deref(),
        )
    }

    #[export(serialize_error)]
    fn delete_filter(
        #[try_from_ref] this: &NotificationConfig,
        name: &str,
    ) -> Result<(), ApiError> {
        let mut config = this.config.lock().unwrap();
        api::filter::delete_filter(&mut config, name)
    }
}