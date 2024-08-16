use rust_extensions::date_time::DateTimeAsMicroseconds;
use x509_parser::prelude::FromDer;

#[derive(Debug, Clone, Copy)]
pub struct CrlRecord {
    pub serial: u64,
    pub revoked: DateTimeAsMicroseconds,
}

pub fn read(src: &str) -> Result<Vec<CrlRecord>, String> {
    let pem = pem::parse(src.as_bytes()).unwrap();

    if pem.tag() != "X509 CRL" {
        return Err("The provided file is not an X509 CRL".into());
    }

    let (_, list) =
        x509_parser::revocation_list::CertificateRevocationList::from_der(pem.contents()).unwrap();

    let mut result = Vec::new();
    for revoked_certificate in list.iter_revoked_certificates() {
        result.push(CrlRecord {
            serial: revoked_certificate.serial().bits(),
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
