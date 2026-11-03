#[perlmod::package(name = "PVE::RS::Notify")]
pub mod pve_rs_notify {
    //! The `PVE::RS::Notify` package.
    //!
    //! This implements the new notification API and support code.
    //!
    //! # Note
    //!
    //! This package provides `STORABLE_freeze` and `STORABLE_attach` subs for `dclone` support,
    //! since this object will be put into `PVE::Cluster`'s `ccache`!

    use std::collections::HashMap;
    use std::sync::Mutex;

    use anyhow::{bail, Error};
    use serde_json::Value as JSONValue;

    use perlmod::Value;
    use proxmox_http_error::HttpError;
    use proxmox_notify::api::Target;
    use proxmox_notify::endpoints::gotify::{
        DeleteableGotifyProperty, GotifyConfig, GotifyConfigUpdater, GotifyPrivateConfig,
        GotifyPrivateConfigUpdater,
    };
    use proxmox_notify::endpoints::sendmail::{
        DeleteableSendmailProperty, SendmailConfig, SendmailConfigUpdater,
    };
    use proxmox_notify::endpoints::smtp::{
        DeleteableSmtpProperty, SmtpConfig, SmtpConfigUpdater, SmtpPrivateConfig,
        SmtpPrivateConfigUpdater,
    };
    use proxmox_notify::endpoints::webhook::{
        DeleteableWebhookProperty, WebhookConfig, WebhookConfigUpdater,
    };
    use proxmox_notify::matcher::{DeleteableMatcherProperty, MatcherConfig, MatcherConfigUpdater};
    use proxmox_notify::{api, Config, Notification, Severity};

    /// A notification catalog instance.
    ///
    /// See [`Config`].
    pub struct NotificationConfig {
        config: Mutex<Config>,
    }

    perlmod::declare_magic!(Box<NotificationConfig> : &NotificationConfig as "PVE::RS::Notify");

    /// Method: Support `dclone` so this can be put into the `ccache` of `PVE::Cluster`.
    #[export(name = "STORABLE_freeze", raw_return)]
    pub fn storable_freeze(
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

    /// Class method: Instead of `thaw` we implement `attach` for `dclone`.
    #[export(name = "STORABLE_attach", raw_return)]
    pub fn storable_attach(
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

    type NotificationConfigInstance = Value;

    /// Class method: Parse the notification configurations to produce a [`NotificationConfig`]
    /// instance.
    #[export(raw_return)]
    pub fn parse_config(
        #[raw] class: Value,
        raw_config: &[u8],
        raw_private_config: &[u8],
    ) -> Result<NotificationConfigInstance, Error> {
        let raw_config = std::str::from_utf8(raw_config)?;
        let raw_private_config = std::str::from_utf8(raw_private_config)?;

        Ok(perlmod::instantiate_magic!(&class, MAGIC => Box::new(
            NotificationConfig {
                config: Mutex::new(Config::new(raw_config, raw_private_config)?)
            }
        )))
    }

    /// Method: Write the notification config out as a string.
    #[export]
    pub fn write_config(
        #[try_from_ref] this: &NotificationConfig,
    ) -> Result<(String, String), Error> {
        Ok(this.config.lock().unwrap().write()?)
    }

    /// Method: Returns the SHA256 digest of the configuration.
    ///
    /// The digest is only computed once when the configuration deserialized.
    #[export]
    pub fn digest(#[try_from_ref] this: &NotificationConfig) -> String {
        let config = this.config.lock().unwrap();
        hex::encode(config.digest())
    }

    /// Method: Send a notification from a template.
    ///
    /// This instantiates a [`Notification`] via [`from_template`](Notification::from_template())
    /// and sends it according to the configuration.
    ///
    /// See [`api::common::send`].
    #[export(serialize_error)]
    pub fn send(
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

    /// Method: Get a list of all notification targets.
    ///
    /// See [`api::get_targets`].
    #[export(serialize_error)]
    pub fn get_targets(
        #[try_from_ref] this: &NotificationConfig,
    ) -> Result<Vec<Target>, HttpError> {
        let config = this.config.lock().unwrap();
        api::get_targets(&config)
    }

    /// Method: Test a target, see [`api::common::test_target`].
    #[export(serialize_error)]
    pub fn test_target(
        #[try_from_ref] this: &NotificationConfig,
        target: &str,
    ) -> Result<(), HttpError> {
        let config = this.config.lock().unwrap();
        api::common::test_target(&config, target)
    }

    /// Method: Get sendmail endpoints.
    ///
    /// See [`api::sendmail::get_endpoints`].
    #[export(serialize_error)]
    pub fn get_sendmail_endpoints(
        #[try_from_ref] this: &NotificationConfig,
    ) -> Result<Vec<SendmailConfig>, HttpError> {
        let config = this.config.lock().unwrap();
        api::sendmail::get_endpoints(&config)
    }

    /// Method: Get a single sendmail endpoint by id.
    ///
    /// See [`api::sendmail::get_endpoint`].
    #[export(serialize_error)]
    pub fn get_sendmail_endpoint(
        #[try_from_ref] this: &NotificationConfig,
        id: &str,
    ) -> Result<SendmailConfig, HttpError> {
        let config = this.config.lock().unwrap();
        api::sendmail::get_endpoint(&config, id)
    }

    /// Method: Add a sendmail endpoint.
    ///
    /// See [`api::sendmail::add_endpoint`].
    #[export(serialize_error)]
    pub fn add_sendmail_endpoint(
        #[try_from_ref] this: &NotificationConfig,
        sendmail_config: SendmailConfig,
    ) -> Result<(), HttpError> {
        let mut config = this.config.lock().unwrap();

        api::sendmail::add_endpoint(&mut config, sendmail_config)
    }

    /// Method: Update a sendmail endpoint.
    ///
    /// See [`api::sendmail::update_endpoint`].
    #[export(serialize_error)]
    pub fn update_sendmail_endpoint(
        #[try_from_ref] this: &NotificationConfig,
        name: &str,
        updater: SendmailConfigUpdater,
        delete: Option<Vec<DeleteableSendmailProperty>>,
        digest: Option<&str>,
    ) -> Result<(), HttpError> {
        let mut config = this.config.lock().unwrap();
        let digest = decode_digest(digest)?;

        api::sendmail::update_endpoint(
            &mut config,
            name,
            updater,
            delete.as_deref(),
            digest.as_deref(),
        )
    }

    /// Method: Delete a sendmail endpoint.
    ///
    /// See [`api::sendmail::delete_endpoint`].
    #[export(serialize_error)]
    pub fn delete_sendmail_endpoint(
        #[try_from_ref] this: &NotificationConfig,
        name: &str,
    ) -> Result<(), HttpError> {
        let mut config = this.config.lock().unwrap();
        api::sendmail::delete_endpoint(&mut config, name)
    }

    /// Method: Get 'gotify' endpoints.
    ///
    /// See [`api::gotify::get_endpoints`].
    #[export(serialize_error)]
    pub fn get_gotify_endpoints(
        #[try_from_ref] this: &NotificationConfig,
    ) -> Result<Vec<GotifyConfig>, HttpError> {
        let config = this.config.lock().unwrap();
        api::gotify::get_endpoints(&config)
    }

    /// Method: Get a single 'gotify' endpoint by id.
    ///
    /// See [`api::gotify::get_endpoint`].
    #[export(serialize_error)]
    pub fn get_gotify_endpoint(
        #[try_from_ref] this: &NotificationConfig,
        id: &str,
    ) -> Result<GotifyConfig, HttpError> {
        let config = this.config.lock().unwrap();
        api::gotify::get_endpoint(&config, id)
    }

    /// Method: Add a 'gotify' endpoint.
    ///
    /// See [`api::gotify::add_endpoint`].
    #[export(serialize_error)]
    pub fn add_gotify_endpoint(
        #[try_from_ref] this: &NotificationConfig,
        gotify_config: GotifyConfig,
        gotify_private_config: GotifyPrivateConfig,
    ) -> Result<(), HttpError> {
        let mut config = this.config.lock().unwrap();
        api::gotify::add_endpoint(&mut config, gotify_config, gotify_private_config)
    }

    /// Method: Update a 'gotify' endpoint.
    ///
    /// See [`api::gotify::update_endpoint`].
    #[export(serialize_error)]
    pub fn update_gotify_endpoint(
        #[try_from_ref] this: &NotificationConfig,
        name: &str,
        updater: GotifyConfigUpdater,
        private_updater: GotifyPrivateConfigUpdater,
        delete: Option<Vec<DeleteableGotifyProperty>>,
        digest: Option<&str>,
    ) -> Result<(), HttpError> {
        let mut config = this.config.lock().unwrap();
        let digest = decode_digest(digest)?;

        api::gotify::update_endpoint(
            &mut config,
            name,
            updater,
            private_updater,
            delete.as_deref(),
            digest.as_deref(),
        )
    }

    /// Method: Delete a 'gotify' endpoint.
    ///
    /// See [`api::gotify::delete_gotify_endpoint`].
    #[export(serialize_error)]
    pub fn delete_gotify_endpoint(
        #[try_from_ref] this: &NotificationConfig,
        name: &str,
    ) -> Result<(), HttpError> {
        let mut config = this.config.lock().unwrap();
        api::gotify::delete_gotify_endpoint(&mut config, name)
    }

    /// Method: Get SMTP endpoints.
    ///
    /// See [`api::smtp::get_endpoints`].
    #[export(serialize_error)]
    pub fn get_smtp_endpoints(
        #[try_from_ref] this: &NotificationConfig,
    ) -> Result<Vec<SmtpConfig>, HttpError> {
        let config = this.config.lock().unwrap();
        api::smtp::get_endpoints(&config)
    }

    /// Method: Get a single SMTP endpoint by id.
    ///
    /// See [`api::smtp::get_endpoint`].
    #[export(serialize_error)]
    pub fn get_smtp_endpoint(
        #[try_from_ref] this: &NotificationConfig,
        id: &str,
    ) -> Result<SmtpConfig, HttpError> {
        let config = this.config.lock().unwrap();
        api::smtp::get_endpoint(&config, id)
    }

    /// Method: Add an SMTP endpoint.
    ///
    /// See [`api::smtp::add_endpoint`].
    #[export(serialize_error)]
    pub fn add_smtp_endpoint(
        #[try_from_ref] this: &NotificationConfig,
        smtp_config: SmtpConfig,
        smtp_private_config: SmtpPrivateConfig,
    ) -> Result<(), HttpError> {
        let mut config = this.config.lock().unwrap();
        api::smtp::add_endpoint(&mut config, smtp_config, smtp_private_config)
    }

    /// Method: Update an SMTP endpoint.
    ///
    /// See [`api::smtp::update_endpoint`].
    #[export(serialize_error)]
    pub fn update_smtp_endpoint(
        #[try_from_ref] this: &NotificationConfig,
        name: &str,
        updater: SmtpConfigUpdater,
        private_updater: SmtpPrivateConfigUpdater,
        delete: Option<Vec<DeleteableSmtpProperty>>,
        digest: Option<&str>,
    ) -> Result<(), HttpError> {
        let mut config = this.config.lock().unwrap();
        let digest = decode_digest(digest)?;

        api::smtp::update_endpoint(
            &mut config,
            name,
            updater,
            private_updater,
            delete.as_deref(),
            digest.as_deref(),
        )
    }

    /// Method: Delete an SMTP endpoint.
    ///
    /// See [`api::smtp::delete_endpoint`].
    #[export(serialize_error)]
    pub fn delete_smtp_endpoint(
        #[try_from_ref] this: &NotificationConfig,
        name: &str,
    ) -> Result<(), HttpError> {
        let mut config = this.config.lock().unwrap();
        api::smtp::delete_endpoint(&mut config, name)
    }

    /// Method: Get webhook endpoints.
    ///
    /// See [`api::webhook::get_endpoints`].
    #[export(serialize_error)]
    pub fn get_webhook_endpoints(
        #[try_from_ref] this: &NotificationConfig,
    ) -> Result<Vec<WebhookConfig>, HttpError> {
        let config = this.config.lock().unwrap();
        api::webhook::get_endpoints(&config)
    }

    /// Method: Get a single webhook endpoint by id.
    ///
    /// See [`api::webhook::get_endpoint`].
    #[export(serialize_error)]
    pub fn get_webhook_endpoint(
        #[try_from_ref] this: &NotificationConfig,
        id: &str,
    ) -> Result<WebhookConfig, HttpError> {
        let config = this.config.lock().unwrap();
        api::webhook::get_endpoint(&config, id)
    }

    /// Method: Add a webhook endpoint.
    ///
    /// See [`api::webhook::add_endpoint`].
    #[export(serialize_error)]
    pub fn add_webhook_endpoint(
        #[try_from_ref] this: &NotificationConfig,
        endpoint_config: WebhookConfig,
    ) -> Result<(), HttpError> {
        let mut config = this.config.lock().unwrap();
        api::webhook::add_endpoint(&mut config, endpoint_config)
    }

    /// Method: Update a webhook endpoint.
    ///
    /// See [`api::webhook::update_endpoint`].
    #[export(serialize_error)]
    pub fn update_webhook_endpoint(
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

    /// Method: Delete a webhook endpoint.
    ///
    /// See [`api::webhook::delete_endpoint`].
    #[export(serialize_error)]
    pub fn delete_webhook_endpoint(
        #[try_from_ref] this: &NotificationConfig,
        name: &str,
    ) -> Result<(), HttpError> {
        let mut config = this.config.lock().unwrap();
        api::webhook::delete_endpoint(&mut config, name)
    }

    /// Method: Get a list of all matchers.
    ///
    /// See [`api::matcher::get_matchers`].
    #[export(serialize_error)]
    pub fn get_matchers(
        #[try_from_ref] this: &NotificationConfig,
    ) -> Result<Vec<MatcherConfig>, HttpError> {
        let config = this.config.lock().unwrap();
        api::matcher::get_matchers(&config)
    }

    /// Method: Get a single matchers by id.
    ///
    /// See [`api::matcher::get_matcher`].
    #[export(serialize_error)]
    pub fn get_matcher(
        #[try_from_ref] this: &NotificationConfig,
        id: &str,
    ) -> Result<MatcherConfig, HttpError> {
        let config = this.config.lock().unwrap();
        api::matcher::get_matcher(&config, id)
    }

    /// Method: Add a matcher.
    ///
    /// See [`api::matcher::add_matcher`].
    #[export(serialize_error)]
    pub fn add_matcher(
        #[try_from_ref] this: &NotificationConfig,
        matcher_config: MatcherConfig,
    ) -> Result<(), HttpError> {
        let mut config = this.config.lock().unwrap();
        api::matcher::add_matcher(&mut config, matcher_config)
    }

    /// Method: Update a matcher.
    ///
    /// See [`api::matcher::update_matcher`].
    #[export(serialize_error)]
    pub fn update_matcher(
        #[try_from_ref] this: &NotificationConfig,
        name: &str,
        updater: MatcherConfigUpdater,
        delete: Option<Vec<DeleteableMatcherProperty>>,
        digest: Option<&str>,
    ) -> Result<(), HttpError> {
        let mut config = this.config.lock().unwrap();
        let digest = decode_digest(digest)?;

        api::matcher::update_matcher(
            &mut config,
            name,
            updater,
            delete.as_deref(),
            digest.as_deref(),
        )
    }

    /// Method: Delete a matcher.
    ///
    /// See [`api::matcher::delete_matcher`].
    #[export(serialize_error)]
    pub fn delete_matcher(
        #[try_from_ref] this: &NotificationConfig,
        name: &str,
    ) -> Result<(), HttpError> {
        let mut config = this.config.lock().unwrap();
        api::matcher::delete_matcher(&mut config, name)
    }

    /// Method: Get a list of referenced entities for an entity.
    ///
    /// See [`api::common::get_referenced_entities`].
    #[export]
    pub fn get_referenced_entities(
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
