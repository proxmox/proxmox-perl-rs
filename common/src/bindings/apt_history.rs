#[perlmod::package(name = "Proxmox::RS::APT::History")]
pub mod proxmox_rs_apt_history {
    //! The `Proxmox::RS::APT::History` package.
    //!
    //! Access to the APT history of the system, i.e. the package changes of past APT transactions,
    //! their terminal output and the changelog entries for their package changes.

    use anyhow::Error;

    use proxmox_apt_history::{
        HistoryEntry, HistoryListOptions, TermLogFormat, TransactionChangelog,
    };

    /// List the entries of the APT history log, including the rotated ones, newest first.
    ///
    /// See [`proxmox_apt_history::list_history`].
    #[export]
    pub fn list_history(options: HistoryListOptions) -> Result<Vec<HistoryEntry>, Error> {
        Ok(proxmox_apt_history::list_history(&options)?)
    }

    /// Get the terminal output of the APT transaction with the given start time and start index,
    /// which defaults to 0, in the given format, which defaults to plain text.
    ///
    /// See [`proxmox_apt_history::get_term_log`].
    #[export]
    pub fn get_term_log(
        start_time: i64,
        start_index: Option<u32>,
        format: Option<TermLogFormat>,
    ) -> Result<Option<String>, Error> {
        Ok(proxmox_apt_history::get_term_log(
            start_time,
            start_index.unwrap_or_default(),
            format.unwrap_or_default(),
        )?)
    }

    /// Get the changelog entries for the package changes of the APT transaction with the given
    /// start time and start index, which defaults to 0, grouped by source package, or undef if the
    /// history has no such transaction.
    ///
    /// See [`proxmox_apt_history::get_transaction_changelogs`].
    #[export]
    pub fn transaction_changelogs(
        start_time: i64,
        start_index: Option<u32>,
    ) -> Result<Option<Vec<TransactionChangelog>>, Error> {
        Ok(proxmox_apt_history::get_transaction_changelogs(
            start_time,
            start_index.unwrap_or_default(),
        )?)
    }
}
