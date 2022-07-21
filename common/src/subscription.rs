mod client {
    use anyhow::{format_err, Error};
    use http::Response;

    pub(crate) struct UreqClient {
        pub user_agent: String,
        pub proxy: Option<String>,
    }

    impl UreqClient {
        fn agent(&self) -> Result<ureq::Agent, Error> {
            let mut builder = ureq::AgentBuilder::new();
            if let Some(proxy) = &self.proxy {
                builder = builder.proxy(ureq::Proxy::new(proxy)?);
            }

            Ok(builder.build())
        }

        fn exec_request(
            &self,
            req: ureq::Request,
            body: Option<&str>,
        ) -> Result<Response<String>, Error> {
            let req = req.set("User-Agent", &self.user_agent);
            let res = match body {
                Some(body) => req.send_string(body),
                None => req.call(),
            }?;

            let mut builder = http::response::Builder::new()
                .status(http::status::StatusCode::from_u16(res.status())?);

            for header in res.headers_names() {
                if let Some(value) = res.header(&header) {
                    builder = builder.header(header, value);
                }
            }
            builder
                .body(res.into_string()?)
                .map_err(|err| format_err!("Failed to convert HTTP response - {err}"))
        }
    }

    impl proxmox_http::HttpClient<String> for UreqClient {
        fn get(&self, uri: &str) -> Result<Response<String>, Error> {
            let req = self.agent()?.get(uri);

            self.exec_request(req, None)
        }

        fn post(
            &self,
            uri: &str,
            body: Option<&str>,
            content_type: Option<&str>,
        ) -> Result<Response<String>, Error> {
            let mut req = self.agent()?.post(uri);
            if let Some(content_type) = content_type {
                req = req.set("Content-Type", content_type);
            }

            self.exec_request(req, body)
        }
    }
}

#[perlmod::package(name = "Proxmox::RS::Subscription")]
mod export {
    use anyhow::{bail, format_err, Error};

    use proxmox_subscription::SubscriptionInfo;
    use proxmox_sys::fs::CreateOptions;

    use super::client::UreqClient;

    #[export]
    fn read_subscription(path: String) -> Result<Option<SubscriptionInfo>, Error> {
        proxmox_subscription::files::read_subscription(
            path.as_str(),
            &[proxmox_subscription::files::DEFAULT_SIGNING_KEY],
        )
    }

    #[export]
    fn write_subscription(
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

    #[export]
    fn delete_subscription(path: String, apt_path: String, url: &str) -> Result<(), Error> {
        let mode = nix::sys::stat::Mode::from_bits_truncate(0o0600);
        let apt_opts = CreateOptions::new().perm(mode).owner(nix::unistd::ROOT);

        proxmox_subscription::files::delete_subscription(path).and_then(|_| {
            proxmox_subscription::files::update_apt_auth(apt_path, apt_opts, url, None, None)
        })
    }

    #[export]
    fn check_subscription(
        key: String,
        server_id: String,
        product_url: String,
        user_agent: String,
        proxy: Option<String>,
    ) -> Result<SubscriptionInfo, Error> {
        let client = UreqClient { user_agent, proxy };

        proxmox_subscription::check::check_subscription(key, server_id, product_url, client)
    }

    #[export]
    fn check_server_id(mut info: SubscriptionInfo) -> SubscriptionInfo {
        info.check_server_id();
        info
    }

    #[export]
    fn check_age(mut info: SubscriptionInfo, re_check: bool) -> SubscriptionInfo {
        info.check_age(re_check);
        info
    }

    #[export]
    fn check_signature(mut info: SubscriptionInfo) -> Result<SubscriptionInfo, Error> {
        if !info.is_signed() {
            bail!("SubscriptionInfo is not signed!");
        }

        info.check_signature(&[proxmox_subscription::files::DEFAULT_SIGNING_KEY]);

        Ok(info)
    }
}
