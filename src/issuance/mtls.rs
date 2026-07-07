use x509_parser::prelude::*;

/// Return the first `spiffe://` URI SAN in a client leaf certificate (DER).
pub fn extract_spiffe(cert_der: &[u8]) -> Option<String> {
    let (_rem, cert) = X509Certificate::from_der(cert_der).ok()?;
    let san = cert.subject_alternative_name().ok()??;
    for gn in &san.value.general_names {
        if let GeneralName::URI(uri) = gn {
            if uri.starts_with("spiffe://") {
                return Some((*uri).to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_cert_der_with_uri(uri: &str) -> Vec<u8> {
        let mut params = rcgen::CertificateParams::new(vec!["client".to_string()]).unwrap();
        params
            .subject_alt_names
            .push(rcgen::SanType::URI(rcgen::string::Ia5String::try_from(uri).unwrap()));
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        cert.der().to_vec()
    }

    #[test]
    fn extracts_spiffe_uri() {
        let der = client_cert_der_with_uri("spiffe://pit/ci/pit-ts");
        assert_eq!(extract_spiffe(&der).as_deref(), Some("spiffe://pit/ci/pit-ts"));
    }

    #[test]
    fn none_when_no_spiffe_san() {
        let der = client_cert_der_with_uri("https://example.com/not-spiffe");
        assert_eq!(extract_spiffe(&der), None);
    }
}
