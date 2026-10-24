#[perlmod::package(name = "Proxmox::RS::AccessLog")]
pub mod proxmox_rs_access_log {
    //! The `Proxmox::RS::AccessLog` package.
    //!
    //! Reads the API access log written by pve-http-server, the HTTP server of the Perl based
    //! products.
    //!
    //! See [`proxmox_access_log`].

    use std::path::Path;

    use anyhow::Error;

    use proxmox_access_log::{
        AccessLogFilter, AccessLogStats, InvalidRequest, LogFormat, QueryResult, StatsOptions,
    };
    use proxmox_http_error::{HttpError, StatusCode};

    /// Reads a page of the entries of the access log at `path` and its rotated copies that match
    /// `filter`, newest first, continuing at `cursor` if given. With `redact`, the values of query
    /// parameters get replaced, as clients can pass any parameter there, passwords included.
    ///
    /// See [`proxmox_access_log::query`] and [`proxmox_access_log::AccessLogEntry::redact`].
    #[export(serialize_error)]
    pub fn query(
        path: &str,
        filter: AccessLogFilter,
        limit: Option<u64>,
        cursor: Option<&str>,
        redact: bool,
    ) -> Result<QueryResult, HttpError> {
        let result = proxmox_access_log::query(Path::new(path), FORMAT, &filter, limit, cursor)
            .map_err(api_error)?;
        Ok(redacted(result, redact))
    }

    /// Reads the entries of the access log at `path` and its rotated copies that match `filter`
    /// and got logged after the position of the `head` cursor of an earlier page, newest first,
    /// redacted like for [`query`].
    ///
    /// See [`proxmox_access_log::query_newer`].
    #[export(serialize_error)]
    pub fn query_newer(
        path: &str,
        filter: AccessLogFilter,
        limit: Option<u64>,
        head: &str,
        redact: bool,
    ) -> Result<QueryResult, HttpError> {
        let result = proxmox_access_log::query_newer(Path::new(path), FORMAT, &filter, limit, head)
            .map_err(api_error)?;
        Ok(redacted(result, redact))
    }

    /// Counts the requests of the access log at `path` and its rotated copies that match `filter`
    /// in its time range, listing the `top` values with the most requests and a histogram with
    /// buckets of `bucket` seconds. The lists hold no query of the request targets, only what
    /// redacted entries show too, so they need no redacting.
    ///
    /// See [`proxmox_access_log::stats`].
    #[export(serialize_error)]
    pub fn stats(
        path: &str,
        filter: AccessLogFilter,
        top: Option<u64>,
        bucket: Option<u64>,
    ) -> Result<AccessLogStats, HttpError> {
        proxmox_access_log::stats(
            Path::new(path),
            FORMAT,
            &filter,
            StatsOptions { top, bucket },
        )
        .map_err(api_error)
    }

    fn api_error(err: Error) -> HttpError {
        let code = if err.is::<InvalidRequest>() {
            StatusCode::BAD_REQUEST
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };
        HttpError::new(code, err.to_string())
    }

    const FORMAT: LogFormat = LogFormat::PveHttpServer;

    fn redacted(mut result: QueryResult, redact: bool) -> QueryResult {
        if redact {
            for entry in &mut result.entries {
                entry.redact(FORMAT);
            }
        }
        result
    }
}
