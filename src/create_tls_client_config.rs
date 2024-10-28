use std::sync::Arc;

use tokio_rustls::rustls::{client::ResolvesClientCert, ClientConfig};

use crate::ClientCertificate;

pub fn create_tls_client_config(
    client_certificate: &Option<ClientCertificate>,
) -> Result<ClientConfig, crate::tokio_rustls::rustls::Error> {
    crate::install_default_crypto_providers();

    let config_builder = crate::tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(crate::ROOT_CERT_STORE.clone());

    let client_config = if let Some(client_cert) = client_certificate {
        let certified_key = client_cert.get_certified_key();

        let mut config = config_builder.with_client_auth_cert(
            client_cert.cert_chain.clone(),
            client_cert.private_key.clone_key(),
        )?;

        config.client_auth_cert_resolver = Arc::new(MyClientCertResolver(Arc::new(certified_key)));
        config
    } else {
        config_builder.with_no_client_auth()
    };

    Ok(client_config)
}

#[derive(Debug)]
pub struct MyClientCertResolver(Arc<crate::tokio_rustls::rustls::sign::CertifiedKey>);

impl ResolvesClientCert for MyClientCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[crate::tokio_rustls::rustls::SignatureScheme],
    ) -> Option<Arc<crate::tokio_rustls::rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}
