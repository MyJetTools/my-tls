use rust_extensions::date_time::DateTimeAsMicroseconds;
use x509_parser::{num_bigint::BigUint, prelude::FromDer};

#[derive(Debug, Clone)]
pub struct CrlRecord {
    pub serial: BigUint,
    pub revoked: DateTimeAsMicroseconds,
}

pub fn read(src: &[u8]) -> Result<Vec<CrlRecord>, String> {
    let pem = pem::parse(src).unwrap();

    if pem.tag() != "X509 CRL" {
        return Err("The provided file is not an X509 CRL".into());
    }

    let (_, list) =
        x509_parser::revocation_list::CertificateRevocationList::from_der(pem.contents()).unwrap();

    let mut result = Vec::new();
    for revoked_certificate in list.iter_revoked_certificates() {
        result.push(CrlRecord {
            serial: revoked_certificate.serial().clone(),
            revoked: DateTimeAsMicroseconds::from(revoked_certificate.revocation_date.timestamp()),
        });

        //println!("Itm: {:?}",  );
    }

    Ok(result)
}

/*
#[cfg(test)]
mod tests {

    #[test]
    fn test_crl_reading() {
        let records = super::read(super::TEST_CLR).unwrap();

        println!("Records: {:#?}", records);
    }
}
 */
