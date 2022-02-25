#[perlmod::package(name = "Proxmox::RS::CalendarEvent")]
mod export {
    use anyhow::Error;
    use perlmod::Value;

    perlmod::declare_magic!(Box<CalendarEvent> : &CalendarEvent as "Proxmox::RS::CalendarEvent");

    #[repr(transparent)]
    struct CalendarEvent(proxmox_time::CalendarEvent);

    #[export(raw_return)]
    fn new(#[raw] class: Value, event: String) -> Result<Value, Error> {
        Ok(perlmod::instantiate_magic!(&class, MAGIC => Box::new(CalendarEvent(event.parse()?))))
    }

    #[export]
    fn compute_next_event(
        #[try_from_ref] this: &CalendarEvent,
        last: i64,
    ) -> Result<Option<i64>, Error> {
        this.0.compute_next_event(last)
    }
}
