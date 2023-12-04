#[perlmod::package(name = "PMG::RS::CSR")]
pub mod export {
    use std::collections::HashMap;

    use anyhow::Error;
    use serde_bytes::ByteBuf;

    use proxmox_acme::util::Csr;

    /// Generates a CSR and its accompanying private key.
    ///
    /// The CSR is DER formatted, the private key is a PEM formatted pkcs8 private key.
    #[export]
    pub fn generate_csr(
        identifiers: Vec<&str>,
        attributes: HashMap<String, &str>,
    ) -> Result<(ByteBuf, ByteBuf), Error> {
        let csr = Csr::generate(&identifiers, &attributes)?;
        Ok((ByteBuf::from(csr.data), ByteBuf::from(csr.private_key_pem)))
    }
}
