use rustls_pki_types::{CertificateDer, PrivateKeyDer};

pub fn calc_cert_key(
    private_key: &PrivateKeyDer<'static>,
    certificates: Vec<CertificateDer<'static>>,
) -> tokio_rustls::rustls::sign::CertifiedKey {
    let private_key =
        tokio_rustls::rustls::crypto::aws_lc_rs::sign::any_supported_type(private_key).unwrap();
    tokio_rustls::rustls::sign::CertifiedKey::new(certificates.clone(), private_key)
}
