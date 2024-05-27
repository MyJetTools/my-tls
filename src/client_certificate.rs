use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

pub struct ClientCertificate {
    pub private_key: PrivateKeyDer<'static>,
    pub cert_chain: Vec<CertificateDer<'static>>,
}

impl ClientCertificate {
    pub async fn from_pks12_file(filename: &str, password: &str) -> Self {
        let filename = rust_extensions::file_utils::format_path(filename);
        let content = tokio::fs::read(filename.as_str()).await.unwrap();
        Self::from_pkcs12(&content, password)
    }

    pub fn from_pkcs12(src: &[u8], password: &str) -> Self {
        let pkcs12 = openssl::pkcs12::Pkcs12::from_der(src)
            .unwrap()
            .parse2(password)
            .unwrap();

        let private_key = pkcs12.pkey.unwrap();

        let private_key = private_key.private_key_to_pkcs8().unwrap();

        let cert_chain = if let Some(x509) = &pkcs12.cert {
            let der = x509.to_der().unwrap();
            vec![der.into()]
        } else {
            vec![]
        };

        Self {
            private_key: PrivateKeyDer::Pkcs8(private_key.into()),
            cert_chain,
        }
    }

    pub async fn load_pks12_from_file(file_name: &str, password: &str) -> Result<Self, String> {
        let file_name = rust_extensions::file_utils::format_path(file_name);
        let content = tokio::fs::read(file_name.as_str())
            .await
            .map_err(|itm| format!("Can not load file {}: Err:{:?}", file_name.as_str(), itm))?;
        let cert = Self::from_pkcs12(&content, password);
        Ok(cert)
    }

    pub fn clone(&self) -> Self {
        Self {
            private_key: self.private_key.clone_key(),
            cert_chain: self.cert_chain.clone(),
        }
    }

    pub fn get_certified_key(&self) -> tokio_rustls::rustls::sign::CertifiedKey {
        let private_key =
            tokio_rustls::rustls::crypto::aws_lc_rs::sign::any_supported_type(&self.private_key)
                .unwrap();
        tokio_rustls::rustls::sign::CertifiedKey::new(self.cert_chain.clone(), private_key)
    }
}
