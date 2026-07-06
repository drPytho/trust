use base64::Engine;
use pingora::http::RequestHeader;

use crate::config::{Injection, InjectionScheme};

#[derive(Debug, thiserror::Error)]
pub enum InjectError {
    #[error("invalid header value for injection")]
    InvalidValue,
}

pub fn inject(
    req: &mut RequestHeader,
    injection: &Injection,
    secret: &str,
) -> Result<(), InjectError> {
    let value = match injection.scheme {
        InjectionScheme::Bearer => format!("Bearer {secret}"),
        InjectionScheme::Basic => {
            format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(secret.as_bytes()))
        }
        InjectionScheme::Raw => secret.to_string(),
    };
    req.insert_header(injection.header.clone(), value)
        .map_err(|_| InjectError::InvalidValue)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Injection, InjectionScheme};
    use pingora::http::RequestHeader;

    fn req() -> RequestHeader {
        RequestHeader::build("GET", b"/", None).unwrap()
    }

    #[test]
    fn raw_injects_verbatim() {
        let mut r = req();
        let inj = Injection { header: "x-api-key".into(), scheme: InjectionScheme::Raw };
        inject(&mut r, &inj, "sekret").unwrap();
        assert_eq!(r.headers.get("x-api-key").unwrap().as_bytes(), b"sekret");
    }

    #[test]
    fn bearer_prefixes() {
        let mut r = req();
        let inj = Injection { header: "authorization".into(), scheme: InjectionScheme::Bearer };
        inject(&mut r, &inj, "sekret").unwrap();
        assert_eq!(r.headers.get("authorization").unwrap().as_bytes(), b"Bearer sekret");
    }

    #[test]
    fn basic_base64_encodes() {
        let mut r = req();
        let inj = Injection { header: "authorization".into(), scheme: InjectionScheme::Basic };
        inject(&mut r, &inj, "user:pass").unwrap();
        // base64("user:pass") == "dXNlcjpwYXNz"
        assert_eq!(r.headers.get("authorization").unwrap().as_bytes(), b"Basic dXNlcjpwYXNz");
    }
}
