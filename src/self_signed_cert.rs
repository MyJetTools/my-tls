use rustls_pki_types::CertificateDer;
pub fn generate(
    cn_name: String,
) -> Result<tokio_rustls::rustls::sign::CertifiedKey, SelfSignedCertError> {
    let (cert, key_pair) = generate_pk(cn_name);

    let mut reader = std::io::BufReader::new(key_pair.as_bytes());

    let private_key = rustls_pemfile::private_key(&mut reader)?;

    if private_key.is_none() {
        return Err(SelfSignedCertError::ErrorParsingPrivateKey);
    }

    let private_key = private_key.unwrap();

    Ok(crate::ssl::calc_cert_key(&private_key, vec![cert]))
}

fn generate_pk(cn_name: String) -> (CertificateDer<'static>, String) {
    use rcgen::*;

    let subject_alt_names = vec![cn_name];

    let certified_key = generate_simple_self_signed(subject_alt_names).unwrap();

    let cert = certified_key.cert.der().clone();

    let key_pair = certified_key.key_pair.serialize_pem();

    (cert, key_pair)
}

pub enum SelfSignedCertError {
    IoError(std::io::Error),
    ErrorParsingPrivateKey,
}

impl From<std::io::Error> for SelfSignedCertError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn generate_private_key() {
        let _ = super::generate("localhost".to_string());
    }
}
