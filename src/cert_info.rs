use rust_extensions::date_time::DateTimeAsMicroseconds;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub cn: String,
    pub expires: DateTimeAsMicroseconds,
}

#[derive(Clone, Debug)]
pub struct SslCertificate(tokio_rustls::rustls::sign::CertifiedKey);

impl SslCertificate {
    pub fn new(private_key: Vec<u8>, certificates_content: Vec<u8>) -> Result<Self, String> {
        let private_key = load_private_key(private_key)?;

        let certs = load_certs(certificates_content);
        let cert_key = calc_cert_key(&private_key, certs);

        let result = SslCertificate(cert_key);

        Ok(result)
    }

    pub fn get_cert_info(&self) -> CertificateInfo {
        use x509_parser::prelude::FromDer;
        use x509_parser::prelude::X509Certificate;

        let mut found_cn = None;
        let mut expires = None;

        for cert_der in self.0.cert.iter() {
            let (_, cert) = X509Certificate::from_der(cert_der).unwrap();

            let expires_from_cer = cert.validity().not_after.to_datetime().unix_timestamp();
            match expires {
                Some(expires_value) => {
                    if expires_from_cer < expires_value {
                        expires = Some(expires_from_cer);
                    }
                }
                None => {
                    expires = Some(expires_from_cer);
                }
            }

            for attr in cert.subject().iter_attributes() {
                // OID for Common Name
                if let Ok(cn) = attr.as_str() {
                    let value = match &found_cn {
                        Some(found_cn) => {
                            format!("{};{}", found_cn, cn)
                        }
                        None => cn.to_string(),
                    };

                    found_cn = Some(value);
                }
            }
        }

        let result = CertificateInfo {
            cn: found_cn.unwrap_or_else(|| "Unknown".to_string()),
            expires: DateTimeAsMicroseconds::from(expires.unwrap()),
        };

        result
    }

    pub fn get_certified_key(&self) -> &tokio_rustls::rustls::sign::CertifiedKey {
        &self.0
    }
}

pub fn calc_cert_key(
    private_key: &PrivateKeyDer<'static>,
    certificates: Vec<CertificateDer<'static>>,
) -> tokio_rustls::rustls::sign::CertifiedKey {
    let private_key =
        tokio_rustls::rustls::crypto::aws_lc_rs::sign::any_supported_type(private_key).unwrap();
    tokio_rustls::rustls::sign::CertifiedKey::new(certificates.clone(), private_key)
}

// Load private key from file.
pub fn load_private_key(src: Vec<u8>) -> Result<PrivateKeyDer<'static>, String> {
    let mut reader = std::io::BufReader::new(src.as_slice());

    let private_key = rustls_pemfile::private_key(&mut reader);

    if let Err(err) = &private_key {
        return Err(format!("Error loading private key: {:?}", err));
    }

    let private_key = private_key.unwrap();

    if private_key.is_none() {
        return Err(format!("No private key found in file"));
    }

    Ok(private_key.unwrap())

    //  Ok(private_key.into())
}

pub fn load_certs(src: Vec<u8>) -> Vec<CertificateDer<'static>> {
    // Open certificate file.

    let mut reader = std::io::BufReader::new(src.as_slice());

    let certs = rustls_pemfile::certs(&mut reader);

    // Load and return certificate.
    let mut result = Vec::new();

    for cert in certs {
        let cert: rustls_pki_types::CertificateDer<'_> = cert.unwrap();
        result.push(cert);
    }

    result
}
