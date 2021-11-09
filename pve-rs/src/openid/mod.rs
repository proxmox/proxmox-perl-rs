#[perlmod::package(name = "PVE::RS::OpenId", lib = "pve_rs")]
mod export {
    use std::sync::Mutex;
    use std::convert::TryFrom;

    use anyhow::Error;

    use perlmod::{to_value, Value};

    use proxmox_openid::{OpenIdConfig, OpenIdAuthenticator, PrivateAuthState};

    const CLASSNAME: &str = "PVE::RS::OpenId";

    /// An OpenIdAuthenticator client instance.
    pub struct OpenId {
        inner: Mutex<OpenIdAuthenticator>,
    }

    impl<'a> TryFrom<&'a Value> for &'a OpenId {
        type Error = Error;

        fn try_from(value: &'a Value) -> Result<&'a OpenId, Error> {
            Ok(unsafe { value.from_blessed_box(CLASSNAME)? })
        }
    }

    fn bless(class: Value, mut ptr: Box<OpenId>) -> Result<Value, Error> {
        let value = Value::new_pointer::<OpenId>(&mut *ptr);
        let value = Value::new_ref(&value);
        let this = value.bless_sv(&class)?;
        let _perl = Box::leak(ptr);
        Ok(this)
    }

    #[export(name = "DESTROY")]
    fn destroy(#[raw] this: Value) {
        perlmod::destructor!(this, OpenId: CLASSNAME);
    }

    /// Create a new OpenId client instance
    #[export(raw_return)]
    pub fn discover(
        #[raw] class: Value,
        config: OpenIdConfig,
        redirect_url: &str,
    ) -> Result<Value, Error> {

        let open_id = OpenIdAuthenticator::discover(&config, redirect_url)?;
        bless(
            class,
            Box::new(OpenId {
                inner: Mutex::new(open_id),
            }),
        )
    }

    #[export]
    pub fn authorize_url(
        #[try_from_ref] this: &OpenId,
        state_dir: &str,
        realm: &str,
    ) -> Result<String, Error> {

        let open_id = this.inner.lock().unwrap();
        open_id.authorize_url(state_dir, realm)
    }

    #[export]
    pub fn verify_public_auth_state(
        state_dir: &str,
        state: &str,
    )  -> Result<(String, PrivateAuthState), Error> {
        OpenIdAuthenticator::verify_public_auth_state(state_dir, state)
    }

    #[export(raw_return)]
    pub fn verify_authorization_code(
       #[try_from_ref] this: &OpenId,
        code: &str,
        private_auth_state: PrivateAuthState,
    ) -> Result<Value, Error> {

        let open_id = this.inner.lock().unwrap();
        let claims = open_id.verify_authorization_code(code, &private_auth_state)?;

        Ok(to_value(&claims)?)
    }
}
