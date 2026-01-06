mod client_certificate;

pub use client_certificate::*;
mod cert_content;
pub use cert_content::*;
mod certs_iterator;
pub use certs_iterator::*;
#[cfg(feature = "self-signed-certificate")]
pub mod ssl;

#[cfg(feature = "self-signed-certificate")]
pub mod self_signed_cert;

#[cfg(feature = "crl")]
pub mod crl;

pub extern crate tokio_rustls;

mod create_tls_client_config;
pub use create_tls_client_config::*;

mod install_default_crypto_providers;
pub use install_default_crypto_providers::*;
mod cert_info;
pub use cert_info::*;

pub fn get_trusted_certs(other_certs: Option<&[u8]>) -> tokio_rustls::rustls::RootCertStore {
    let mut root_cert_store = tokio_rustls::rustls::RootCertStore::empty();

    let certificates_iterator = CertificatesIterator::new(ALL_CERTIFICATES);

    root_cert_store.add_parsable_certificates(
        certificates_iterator
            .into_iter()
            .map(|itm| pem_to_der(&ALL_CERTIFICATES[itm.0..itm.1])),
    );

    if let Some(other_certs) = other_certs {
        let certificates_iterator = CertificatesIterator::new(other_certs);
        root_cert_store.add_parsable_certificates(
            certificates_iterator
                .into_iter()
                .map(|itm| pem_to_der(&other_certs[itm.0..itm.1])),
        );
    }

    root_cert_store
}
