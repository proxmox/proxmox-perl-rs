#[perlmod::package(name = "Proxmox::RS::Subscription")]
pub mod proxmox_rs_subscription {
    //! The `Proxmox::RS::Subscription` package.
    //!
    //! Implements the functions to check/update/delete the subscription status.

    use anyhow::{Error, bail, format_err};

    use proxmox_subscription::SubscriptionInfo;
    use proxmox_sys::fs::CreateOptions;

    use proxmox_http::HttpOptions;
    use proxmox_http::ProxyConfig;
    use proxmox_http::client::sync::Client;

    /// Read the subscription status.
    ///
    /// See [`proxmox_subscription::files::read_subscription`].
    #[export]
    pub fn read_subscription(path: String) -> Result<Option<SubscriptionInfo>, Error> {
        proxmox_subscription::files::read_subscription(
            path.as_str(),
            &[proxmox_subscription::files::DEFAULT_SIGNING_KEY],
        )
    }

    /// Write the subscription status.
    ///
    /// See [`proxmox_subscription::files::write_subscription`].
    #[export]
    pub fn write_subscription(
        path: String,
        apt_path: String,
        url: &str,
        info: SubscriptionInfo,
    ) -> Result<(), Error> {
        let mode = nix::sys::stat::Mode::from_bits_truncate(0o0640);
        let www_data = nix::unistd::Group::from_name("www-data")?
            .ok_or(format_err!("no 'www-data' group found!"))?
            .gid;
        let opts = CreateOptions::new()
            .perm(mode)
            .owner(nix::unistd::ROOT)
            .group(www_data);

        let mode = nix::sys::stat::Mode::from_bits_truncate(0o0600);
        let apt_opts = CreateOptions::new().perm(mode).owner(nix::unistd::ROOT);

        proxmox_subscription::files::write_subscription(path, opts, &info).and_then(|_| {
            proxmox_subscription::files::update_apt_auth(
                apt_path,
                apt_opts,
                url,
                info.key,
                info.serverid,
            )
        })
    }

    /// Delete the subscription status.
    ///
    /// See [`proxmox_subscription::files::delete_subscription`].
    #[export]
    pub fn delete_subscription(path: String, apt_path: String, url: &str) -> Result<(), Error> {
        let mode = nix::sys::stat::Mode::from_bits_truncate(0o0600);
        let apt_opts = CreateOptions::new().perm(mode).owner(nix::unistd::ROOT);

        proxmox_subscription::files::delete_subscription(path).and_then(|_| {
            proxmox_subscription::files::update_apt_auth(apt_path, apt_opts, url, None, None)
        })
    }

    /// Check the subscription status.
    ///
    /// See [`proxmox_subscription::check::check_subscription`].
    #[export]
    pub fn check_subscription(
        key: String,
        server_id: String,
        product_url: String,
        user_agent: String,
        proxy: Option<String>,
    ) -> Result<SubscriptionInfo, Error> {
        let proxy_config = match proxy {
            Some(url) => Some(ProxyConfig::parse_proxy_url(&url)?),
            None => None,
        };
        let options = HttpOptions {
            proxy_config,
            user_agent: Some(user_agent),
            ..Default::default()
        };
        let client = Client::new(options);

        proxmox_subscription::check::check_subscription(key, server_id, product_url, client)
    }

    /// Check that server ID contained in [`SubscriptionInfo`] matches that of current system.
    ///
    /// See [`proxmox_subscription::SubscriptionInfo::check_server_id`].
    #[export]
    pub fn check_server_id(mut info: SubscriptionInfo) -> SubscriptionInfo {
        info.check_server_id();
        info
    }

    /// Checks whether a [`SubscriptionInfo`]'s `checktime` matches the age criteria:
    ///
    /// See [`proxmox_subscription::SubscriptionInfo::check_age`].
    #[export]
    pub fn check_age(mut info: SubscriptionInfo, re_check: bool) -> SubscriptionInfo {
        info.check_age(re_check);
        info
    }

    /// Check a [`SubscriptionInfo`]'s signature, if one is available.
    ///
    /// See [`proxmox_subscription::SubscriptionInfo::check_signature`].
    #[export]
    pub fn check_signature(mut info: SubscriptionInfo) -> Result<SubscriptionInfo, Error> {
        if !info.is_signed() {
            bail!("SubscriptionInfo is not signed!");
        }

        info.check_signature(&[proxmox_subscription::files::DEFAULT_SIGNING_KEY]);

        Ok(info)
    }
}
