use rust_extensions::StrOrString;
use rustls_pki_types::CertificateDer;
pub fn generate<'s>(
    cn_name: impl Into<StrOrString<'s>>,
) -> Result<tokio_rustls::rustls::sign::CertifiedKey, SelfSignedCertError> {
    let cn_name = cn_name.into().to_string();
    let (cert, key_pair) = generate_pk(cn_name)?;

    let mut reader = std::io::BufReader::new(key_pair.as_bytes());

    let private_key = rustls_pemfile::private_key(&mut reader)?;

    if private_key.is_none() {
        return Err(SelfSignedCertError::ErrorParsingPrivateKey);
    }

    let private_key = private_key.unwrap();

    Ok(crate::ssl::calc_cert_key(&private_key, vec![cert]))
}

fn generate_pk(cn_name: String) -> Result<(CertificateDer<'static>, String), rcgen::Error> {
    use rcgen::*;

    let subject_alt_names = vec![cn_name];

    let certified_key = generate_simple_self_signed(subject_alt_names)?;

    let cert = certified_key.cert.der().clone();

    let key_pair = certified_key.key_pair.serialize_pem();

    Ok((cert, key_pair))
}

#[derive(Debug)]
pub enum SelfSignedCertError {
    IoError(std::io::Error),
    RcGenError(rcgen::Error),
    ErrorParsingPrivateKey,
}

impl From<std::io::Error> for SelfSignedCertError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}

impl From<rcgen::Error> for SelfSignedCertError {
    fn from(err: rcgen::Error) -> Self {
        Self::RcGenError(err)
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn generate_private_key() {
        let _ = super::generate("localhost".to_string());
    }
}
