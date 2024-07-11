mod client_certificate;
use std::sync::Arc;

pub use client_certificate::*;
mod cert_content;
pub use cert_content::*;
mod certs_iterator;
pub use certs_iterator::*;

pub fn get_trusted_certs(other_certs: &[u8]) -> Arc<tokio_rustls::rustls::RootCertStore> {
    let mut root_cert_store = tokio_rustls::rustls::RootCertStore::empty();

    let certificates_iterator = CertificatesIterator::new(ALL_CERTIFICATES);

    root_cert_store.add_parsable_certificates(
        certificates_iterator
            .into_iter()
            .map(|itm| pem_to_der(&ALL_CERTIFICATES[itm.0..itm.1])),
    );

    let certificates_iterator = CertificatesIterator::new(other_certs);
    root_cert_store.add_parsable_certificates(
        certificates_iterator
            .into_iter()
            .map(|itm| pem_to_der(&other_certs[itm.0..itm.1])),
    );

    Arc::new(root_cert_store)
}
