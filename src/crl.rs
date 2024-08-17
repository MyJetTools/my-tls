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

pub const EMPTY_CRL: &str = r#"
-----BEGIN X509 CRL-----
MIICdzBhAgEBMA0GCSqGSIb3DQEBBQUAMB8xHTAbBgNVBAMMFFB1cHBldCBDQTog
bG9jYWxob3N0Fw0xMzA3MTYyMDQ4NDJaFw0xODA3MTUyMDQ4NDNaoA4wDDAKBgNV
HRQEAwIBADANBgkqhkiG9w0BAQUFAAOCAgEAqyBJOy3dtCOcrb0Fu7ZOOiDQnarg
IzXUV/ug1dauPEVyURLNNr+CJrr89QZnU/71lqgpWTN/J47mO/lffMSPjmINE+ng
XzOffm0qCG2+gNyaOBOdEmQTLdHPIXvcm7T+wEqc7XFW2tjEdpEubZgweruU/+DB
RX6/PhFbalQ0bKcMeFLzLAD4mmtBaQCJISmUUFWx1pyCS6pgBtQ1bNy3PJPN2PNW
YpDf3DNZ16vrAJ4a4SzXLXCoONw0MGxZcS6/hctJ75Vz+dTMrArKwckytWgQS/5e
c/1/wlMZn4xlho+EcIPMPfCB5hW1qzGU2WjUakTVxzF4goamnfFuKbHKEoXVOo9C
3dEQ9un4Uyd1xHxj8WvQck79In5/S2l9hdqp4eud4BaYB6tNRKxlUntSCvCNriR2
wrDNsMuQ5+KJReG51vM0OzzKmlScgIHaqbVeNFZI9X6TpsO2bLEZX2xyqKw4xrre
OIEZRoJrmX3VQ/4u9hj14Qbt72/khYo6z/Fckc5zVD+dW4fjP2ztVTSPzBqIK3+H
zAgewYW6cJ6Aan8GSl3IfRqj6WlOubWj8Gr1U0dOE7SkBX6w/X61uqsHrOyg/E/Z
0Wcz/V+W5iZxa4Spm0x4sfpNzf/bNmjTe4M2MXyn/hXx5MdHf/HZdhOs/lzwKUGL
kEwcy38d6hYtUjs=
-----END X509 CRL-----
"#;

#[cfg(test)]
mod tests {

    #[test]
    fn test_crl_reading() {
        let records = super::read(super::EMPTY_CRL.as_bytes()).unwrap();

        println!("Records: {:#?}", records);
    }
}
