use rust_extensions::array_of_bytes_iterator::{ArrayOfBytesIterator, SliceIterator};

pub static ALL_CERTIFICATES: &'static [u8] = std::include_bytes!("cacert-2023-08-22.pem");

const BEGIN_CERTIFICATE_MARKER: &'static [u8] = b"-----BEGIN CERTIFICATE-----";
const END_CERTIFICATE_MARKER: &'static [u8] = b"-----END CERTIFICATE-----";

pub struct CertificatesIterator<'s> {
    iterator: SliceIterator<'s>,
}

impl<'s> CertificatesIterator<'s> {
    pub fn new(src: &'s [u8]) -> Self {
        Self {
            iterator: SliceIterator::new(src),
        }
    }

    fn find_pos(&mut self, marker: &[u8]) -> Option<usize> {
        loop {
            if self
                .iterator
                .peek_sequence(marker.len(), |current_sequence| current_sequence == marker)
            {
                return Some(self.iterator.get_pos());
            }

            self.iterator.get_next()?;
        }
    }

    fn locate_cert(&mut self) -> Option<usize> {
        let from_pos = self.find_pos(BEGIN_CERTIFICATE_MARKER)?;
        self.find_pos(END_CERTIFICATE_MARKER)?;

        self.iterator.advance(END_CERTIFICATE_MARKER.len())?;

        Some(from_pos)
    }
}

impl<'s> Iterator for CertificatesIterator<'s> {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        let from_pos = self.locate_cert()?;

        let result = self.iterator.get_slice_to_current_pos(from_pos).to_vec();
        Some(result)
    }
}

/*
impl<'s> Iterator for CertificatesIterator<'s> {
    type Item = &'s [u8];

    fn next<'d: 's>(&'d mut self) -> Option<&'s [u8]> {
        let from_pos = self.find_pos(BEGIN_CERTIFICATE_MARKER)?;
        self.find_pos(END_CERTIFICATE_MARKER)?;

        self.iterator.advance(END_CERTIFICATE_MARKER.len())?;

        let result = self.iterator.get_slice_to_current_pos(from_pos);
        Some(result)
    }
}
 */
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_certs() {
        let certs = r#"
GlobalSign Root CA
==================
-----BEGIN CERTIFICATE-----
MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkGA1UEBhMCQkUx
-----END CERTIFICATE-----

Entrust.net Premium 2048 Secure Server CA
=========================================
-----BEGIN CERTIFICATE-----
MIIEKjCCAxKgAwIBAgIEOGPe+DANBgkqhkiG9w0BAQUFADCBtDEUMBIGA1UEChMLRW50cnVzdC5u
-----END CERTIFICATE-----
"#;

        let mut result = Vec::new();

        let mut iterator = CertificatesIterator::new(certs.as_bytes());

        while let Some(cert) = iterator.next() {
            result.push(cert);
        }

        assert_eq!(2, result.len());

        assert_eq!(
            r#"-----BEGIN CERTIFICATE-----
MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkGA1UEBhMCQkUx
-----END CERTIFICATE-----"#
                .as_bytes(),
            result[0]
        );

        assert_eq!(
            r#"-----BEGIN CERTIFICATE-----
MIIEKjCCAxKgAwIBAgIEOGPe+DANBgkqhkiG9w0BAQUFADCBtDEUMBIGA1UEChMLRW50cnVzdC5u
-----END CERTIFICATE-----"#
                .as_bytes(),
            result[1]
        );
    }
}
