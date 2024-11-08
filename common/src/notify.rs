#[perlmod::package(name = "Proxmox::RS::Notify")]
mod export {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use anyhow::{bail, Error};
    use serde_json::Value as JSONValue;

    use perlmod::Value;
    use proxmox_http_error::HttpError;
    use proxmox_notify::endpoints::gotify::{
        DeleteableGotifyProperty, GotifyConfig, GotifyConfigUpdater, GotifyPrivateConfig,
        GotifyPrivateConfigUpdater,
    };
    use proxmox_notify::endpoints::sendmail::{
        DeleteableSendmailProperty, SendmailConfig, SendmailConfigUpdater,
    };
    use proxmox_notify::endpoints::smtp::{
        DeleteableSmtpProperty, SmtpConfig, SmtpConfigUpdater, SmtpMode, SmtpPrivateConfig,
        SmtpPrivateConfigUpdater,
    };
    use proxmox_notify::endpoints::webhook::{
        DeleteableWebhookProperty, WebhookConfig, WebhookConfigUpdater,
    };
    use proxmox_notify::matcher::{
        CalendarMatcher, DeleteableMatcherProperty, FieldMatcher, MatchModeOperator, MatcherConfig,
        MatcherConfigUpdater, SeverityMatcher,
    };
    use proxmox_notify::{api, Config, Notification, Severity};

    pub struct NotificationConfig {
        config: Mutex<Config>,
    }

    perlmod::declare_magic!(Box<NotificationConfig> : &NotificationConfig as "Proxmox::RS::Notify");

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
        severity: Severity,
        template_name: String,
        template_data: Option<JSONValue>,
        fields: Option<HashMap<String, String>>,
    ) -> Result<(), HttpError> {
        let config = this.config.lock().unwrap();
        let notification = Notification::from_template(
            severity,
            template_name,
            template_data.unwrap_or_default(),
            fields.unwrap_or_default(),
        );

        api::common::send(&config, &notification)
    }

    #[export(serialize_error)]
    fn test_target(
        #[try_from_ref] this: &NotificationConfig,
        target: &str,
    ) -> Result<(), HttpError> {
        let config = this.config.lock().unwrap();
        api::common::test_target(&config, target)
    }

    #[export(serialize_error)]
    fn get_sendmail_endpoints(
        #[try_from_ref] this: &NotificationConfig,
    ) -> Result<Vec<SendmailConfig>, HttpError> {
        let config = this.config.lock().unwrap();
        api::sendmail::get_endpoints(&config)
    }

    #[export(serialize_error)]
    fn get_sendmail_endpoint(
        #[try_from_ref] this: &NotificationConfig,
        id: &str,
    ) -> Result<SendmailConfig, HttpError> {
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
        disable: Option<bool>,
    ) -> Result<(), HttpError> {
        let mut config = this.config.lock().unwrap();

        api::sendmail::add_endpoint(
            &mut config,
            SendmailConfig {
                name,
                mailto: mailto.unwrap_or_default(),
                mailto_user: mailto_user.unwrap_or_default(),
                from_address,
                author,
                comment,
                disable,
                filter: None,
                origin: None,
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
        disable: Option<bool>,
        delete: Option<Vec<DeleteableSendmailProperty>>,
        digest: Option<&str>,
    ) -> Result<(), HttpError> {
        let mut config = this.config.lock().unwrap();
        let digest = decode_digest(digest)?;

        api::sendmail::update_endpoint(
            &mut config,
            name,
            SendmailConfigUpdater {
                mailto,
                mailto_user,
                from_address,
                author,
                comment,
                disable,
            },
            delete.as_deref(),
            digest.as_deref(),
        )
    }

    #[export(serialize_error)]
    fn delete_sendmail_endpoint(
        #[try_from_ref] this: &NotificationConfig,
        name: &str,
    ) -> Result<(), HttpError> {
        let mut config = this.config.lock().unwrap();
        api::sendmail::delete_endpoint(&mut config, name)
    }

    #[export(serialize_error)]
    fn get_gotify_endpoints(
        #[try_from_ref] this: &NotificationConfig,
    ) -> Result<Vec<GotifyConfig>, HttpError> {
        let config = this.config.lock().unwrap();
        api::gotify::get_endpoints(&config)
    }

    #[export(serialize_error)]
    fn get_gotify_endpoint(
        #[try_from_ref] this: &NotificationConfig,
        id: &str,
    ) -> Result<GotifyConfig, HttpError> {
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
        disable: Option<bool>,
    ) -> Result<(), HttpError> {
        let mut config = this.config.lock().unwrap();
        api::gotify::add_endpoint(
            &mut config,
            GotifyConfig {
                name: name.clone(),
                server,
                comment,
                disable,
                filter: None,
                origin: None,
            },
            GotifyPrivateConfig { name, token },
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
        disable: Option<bool>,
        delete: Option<Vec<DeleteableGotifyProperty>>,
        digest: Option<&str>,
    ) -> Result<(), HttpError> {
        let mut config = this.config.lock().unwrap();
        let digest = decode_digest(digest)?;

        api::gotify::update_endpoint(
            &mut config,
            name,
            GotifyConfigUpdater {
                server,
                comment,
                disable,
            },
            GotifyPrivateConfigUpdater { token },
            delete.as_deref(),
            digest.as_deref(),
        )
    }

    #[export(serialize_error)]
    fn delete_gotify_endpoint(
        #[try_from_ref] this: &NotificationConfig,
        name: &str,
    ) -> Result<(), HttpError> {
        let mut config = this.config.lock().unwrap();
        api::gotify::delete_gotify_endpoint(&mut config, name)
    }

    #[export(serialize_error)]
    fn get_smtp_endpoints(
        #[try_from_ref] this: &NotificationConfig,
    ) -> Result<Vec<SmtpConfig>, HttpError> {
        let config = this.config.lock().unwrap();
        api::smtp::get_endpoints(&config)
    }

    #[export(serialize_error)]
    fn get_smtp_endpoint(
        #[try_from_ref] this: &NotificationConfig,
        id: &str,
    ) -> Result<SmtpConfig, HttpError> {
        let config = this.config.lock().unwrap();
        api::smtp::get_endpoint(&config, id)
    }

    #[export(serialize_error)]
    #[allow(clippy::too_many_arguments)]
    fn add_smtp_endpoint(
        #[try_from_ref] this: &NotificationConfig,
        name: String,
        server: String,
        port: Option<u16>,
        mode: Option<SmtpMode>,
        username: Option<String>,
        password: Option<String>,
        mailto: Option<Vec<String>>,
        mailto_user: Option<Vec<String>>,
        from_address: String,
        author: Option<String>,
        comment: Option<String>,
        disable: Option<bool>,
    ) -> Result<(), HttpError> {
        let mut config = this.config.lock().unwrap();
        api::smtp::add_endpoint(
            &mut config,
            SmtpConfig {
                name: name.clone(),
                server,
                port,
                mode,
                username,
                mailto: mailto.unwrap_or_default(),
                mailto_user: mailto_user.unwrap_or_default(),
                from_address,
                author,
                comment,
                disable,
                origin: None,
            },
            SmtpPrivateConfig { name, password },
        )
    }

    #[export(serialize_error)]
    #[allow(clippy::too_many_arguments)]
    fn update_smtp_endpoint(
        #[try_from_ref] this: &NotificationConfig,
        name: &str,
        server: Option<String>,
        port: Option<u16>,
        mode: Option<SmtpMode>,
        username: Option<String>,
        password: Option<String>,
        mailto: Option<Vec<String>>,
        mailto_user: Option<Vec<String>>,
        from_address: Option<String>,
        author: Option<String>,
        comment: Option<String>,
        disable: Option<bool>,
        delete: Option<Vec<DeleteableSmtpProperty>>,
        digest: Option<&str>,
    ) -> Result<(), HttpError> {
        let mut config = this.config.lock().unwrap();
        let digest = decode_digest(digest)?;

        api::smtp::update_endpoint(
            &mut config,
            name,
            SmtpConfigUpdater {
                server,
                port,
                mode,
                username,
                mailto,
                mailto_user,
                from_address,
                author,
                comment,
                disable,
            },
            SmtpPrivateConfigUpdater { password },
            delete.as_deref(),
            digest.as_deref(),
        )
    }

    #[export(serialize_error)]
    fn delete_smtp_endpoint(
        #[try_from_ref] this: &NotificationConfig,
        name: &str,
    ) -> Result<(), HttpError> {
        let mut config = this.config.lock().unwrap();
        api::smtp::delete_endpoint(&mut config, name)
    }

    #[export(serialize_error)]
    fn get_webhook_endpoints(
        #[try_from_ref] this: &NotificationConfig,
    ) -> Result<Vec<WebhookConfig>, HttpError> {
        let config = this.config.lock().unwrap();
        api::webhook::get_endpoints(&config)
    }

    #[export(serialize_error)]
    fn get_webhook_endpoint(
        #[try_from_ref] this: &NotificationConfig,
        id: &str,
    ) -> Result<WebhookConfig, HttpError> {
        let config = this.config.lock().unwrap();
        api::webhook::get_endpoint(&config, id)
    }

    #[export(serialize_error)]
    #[allow(clippy::too_many_arguments)]
    fn add_webhook_endpoint(
        #[try_from_ref] this: &NotificationConfig,
        endpoint_config: WebhookConfig,
    ) -> Result<(), HttpError> {
        let mut config = this.config.lock().unwrap();
        api::webhook::add_endpoint(
            &mut config,
            endpoint_config,
        )
    }

    #[export(serialize_error)]
    #[allow(clippy::too_many_arguments)]
    fn update_webhook_endpoint(
        #[try_from_ref] this: &NotificationConfig,
        name: &str,
        config_updater: WebhookConfigUpdater,
        delete: Option<Vec<DeleteableWebhookProperty>>,
        digest: Option<&str>,
    ) -> Result<(), HttpError> {
        let mut config = this.config.lock().unwrap();
        let digest = decode_digest(digest)?;

        api::webhook::update_endpoint(
            &mut config,
            name,
            config_updater,
            delete.as_deref(),
            digest.as_deref(),
        )
    }

    #[export(serialize_error)]
    fn delete_webhook_endpoint(
        #[try_from_ref] this: &NotificationConfig,
        name: &str,
    ) -> Result<(), HttpError> {
        let mut config = this.config.lock().unwrap();
        api::webhook::delete_endpoint(&mut config, name)
    }

    #[export(serialize_error)]
    fn get_matchers(
        #[try_from_ref] this: &NotificationConfig,
    ) -> Result<Vec<MatcherConfig>, HttpError> {
        let config = this.config.lock().unwrap();
        api::matcher::get_matchers(&config)
    }

    #[export(serialize_error)]
    fn get_matcher(
        #[try_from_ref] this: &NotificationConfig,
        id: &str,
    ) -> Result<MatcherConfig, HttpError> {
        let config = this.config.lock().unwrap();
        api::matcher::get_matcher(&config, id)
    }

    #[export(serialize_error)]
    #[allow(clippy::too_many_arguments)]
    fn add_matcher(
        #[try_from_ref] this: &NotificationConfig,
        name: String,
        target: Option<Vec<String>>,
        match_severity: Option<Vec<SeverityMatcher>>,
        match_field: Option<Vec<FieldMatcher>>,
        match_calendar: Option<Vec<CalendarMatcher>>,
        mode: Option<MatchModeOperator>,
        invert_match: Option<bool>,
        comment: Option<String>,
        disable: Option<bool>,
    ) -> Result<(), HttpError> {
        let mut config = this.config.lock().unwrap();
        api::matcher::add_matcher(
            &mut config,
            MatcherConfig {
                name,
                match_severity: match_severity.unwrap_or_default(),
                match_field: match_field.unwrap_or_default(),
                match_calendar: match_calendar.unwrap_or_default(),
                target: target.unwrap_or_default(),
                mode,
                invert_match,
                comment,
                disable,
                origin: None,
            },
        )
    }

    #[export(serialize_error)]
    #[allow(clippy::too_many_arguments)]
    fn update_matcher(
        #[try_from_ref] this: &NotificationConfig,
        name: &str,
        target: Option<Vec<String>>,
        match_severity: Option<Vec<SeverityMatcher>>,
        match_field: Option<Vec<FieldMatcher>>,
        match_calendar: Option<Vec<CalendarMatcher>>,
        mode: Option<MatchModeOperator>,
        invert_match: Option<bool>,
        comment: Option<String>,
        disable: Option<bool>,
        delete: Option<Vec<DeleteableMatcherProperty>>,
        digest: Option<&str>,
    ) -> Result<(), HttpError> {
        let mut config = this.config.lock().unwrap();
        let digest = decode_digest(digest)?;

        api::matcher::update_matcher(
            &mut config,
            name,
            MatcherConfigUpdater {
                match_severity,
                match_field,
                match_calendar,
                target,
                mode,
                invert_match,
                comment,
                disable,
            },
            delete.as_deref(),
            digest.as_deref(),
        )
    }

    #[export(serialize_error)]
    fn delete_matcher(
        #[try_from_ref] this: &NotificationConfig,
        name: &str,
    ) -> Result<(), HttpError> {
        let mut config = this.config.lock().unwrap();
        api::matcher::delete_matcher(&mut config, name)
    }

    #[export]
    fn get_referenced_entities(
        #[try_from_ref] this: &NotificationConfig,
        name: &str,
    ) -> Result<Vec<String>, HttpError> {
        let config = this.config.lock().unwrap();
        api::common::get_referenced_entities(&config, name)
    }

    fn decode_digest(digest: Option<&str>) -> Result<Option<Vec<u8>>, HttpError> {
        digest
            .map(hex::decode)
            .transpose()
            .map_err(|e| api::http_err!(BAD_REQUEST, "invalid digest: {e}"))
    }
}
