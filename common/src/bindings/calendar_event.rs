#[perlmod::package(name = "Proxmox::RS::CalendarEvent")]
pub mod proxmox_rs_calendar_event {
    //! The `Proxmox::RS::CalendarEvent` package.
    //!
    //! Implements systemd-like calender events.
    //!
    //! See [`proxmox_time::CalendarEvent`].

    use anyhow::Error;
    use perlmod::Value;

    perlmod::declare_magic!(Box<CalendarEvent> : &CalendarEvent as "Proxmox::RS::CalendarEvent");

    /// Wrapper for [`proxmox_time::CalendarEvent`].
    #[repr(transparent)]
    pub struct CalendarEvent(proxmox_time::CalendarEvent);

    /// Class method: Create a new [`CalendarEvent`] instance.
    ///
    /// See [`proxmox_time::CalendarEvent`].
    #[export(raw_return)]
    pub fn new(#[raw] class: Value, event: String) -> Result<Value, Error> {
        Ok(perlmod::instantiate_magic!(&class, MAGIC => Box::new(CalendarEvent(event.parse()?))))
    }

    /// Method: Computes the next timestamp after `last`.
    ///
    /// See [`proxmox_time::CalendarEvent::compute_next_event`].
    #[export]
    pub fn compute_next_event(
        #[try_from_ref] this: &CalendarEvent,
        last: i64,
    ) -> Result<Option<i64>, Error> {
        this.0.compute_next_event(last)
    }
}
