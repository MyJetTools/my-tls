use std::sync::Arc;

use tokio_rustls::rustls::pki_types::CertificateDer;

use crate::{CertificatesIterator, ALL_CERTIFICATES};

lazy_static::lazy_static! {
    pub static ref ROOT_CERT_STORE: Arc<tokio_rustls::rustls::RootCertStore> = {

        let mut root_cert_store = tokio_rustls::rustls::RootCertStore::empty();

        let certificates_iterator = CertificatesIterator::new(ALL_CERTIFICATES);


        root_cert_store.add_parsable_certificates(certificates_iterator.into_iter().map(|itm| pem_to_der(itm)));

        Arc::new(root_cert_store)

    };
}

pub fn pem_to_der<'s>(pem_data: Vec<u8>) -> CertificateDer<'s> {
    pem_data.into()
    //use pem::parse;
    // Parse the PEM file
    //let pem = parse(pem_data).unwrap();

    // The pem::Pem struct contains the decoded data
    // pem.contents().to_vec()
}

/*
fn split_certificates() -> Vec<&'static [u8]> {
    let iterator = SliceIterator::new(ALL_CERTIFICATES);


    let mut iterator = std::str::from_utf8(ALL_CERTIFICATES)
        .unwrap()
        .split("\n")
        .into_iter();


    while let Some(itm) = iterator.next() {
        if itm == "-----BEGIN CERTIFICATE-----" {
            cert = Some(Vec::new());
            cert.as_mut().unwrap().extend_from_slice(itm.as_bytes());
            cert.as_mut().unwrap().push(b'\n');
            continue;
        } else if itm == "-----END CERTIFICATE-----" {
            cert.as_mut().unwrap().extend_from_slice(itm.as_bytes());
            cert.as_mut().unwrap().push(b'\n');

            if let Some(cert_to_add) = cert.take() {
                result.push(cert_to_add);
            }
            continue;
        }

        if let Some(cert) = cert.as_mut() {
            cert.extend_from_slice(itm.as_bytes());
            cert.push(b'\n');
        }
    }

    result

}


     */
