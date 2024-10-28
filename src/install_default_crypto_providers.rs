pub fn install_default_crypto_providers() {
    let _ = crate::tokio_rustls::rustls::crypto::ring::default_provider().install_default();
}
