use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{Algorithm, Header, Validation, decode, decode_header, encode};
use serde::{Deserialize, Serialize};

use crate::keystore::KeyMaterial;
use crate::scope::ScopeSet;

#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("failed to sign token: {0}")]
    Sign(String),
    #[error("unknown signing key id")]
    UnknownKid,
    #[error("invalid token: {0}")]
    Invalid(String),
    #[error("token expired")]
    Expired,
    #[error("invalid scope claim: {0}")]
    BadScope(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub iat: u64,
    pub exp: u64,
    pub scope: String,
}

pub struct Issuer {
    issuer: String,
    audience: String,
    ttl_secs: u64,
}

impl Issuer {
    pub fn new(issuer: String, audience: String, ttl: std::time::Duration) -> Issuer {
        Issuer {
            issuer,
            audience,
            ttl_secs: ttl.as_secs(),
        }
    }

    pub fn ttl_secs(&self) -> u64 {
        self.ttl_secs
    }

    pub fn mint(
        &self,
        km: &KeyMaterial,
        sub: &str,
        scopes: &ScopeSet,
        now: u64,
    ) -> Result<String, JwtError> {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(km.signing_kid.clone());
        let claims = Claims {
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            sub: sub.to_string(),
            iat: now,
            exp: now + self.ttl_secs,
            scope: scopes.to_scope_string(),
        };
        encode(&header, &claims, &km.encoding).map_err(|e| JwtError::Sign(e.to_string()))
    }
}

pub struct Verifier {
    issuer: String,
    audience: String,
}

#[derive(Debug)]
pub struct VerifiedToken {
    pub subject: String,
    pub scopes: ScopeSet,
    pub expires_at: u64,
}

impl Verifier {
    pub fn new(issuer: String, audience: String) -> Verifier {
        Verifier { issuer, audience }
    }

    pub fn verify_token(&self, km: &KeyMaterial, token: &str) -> Result<VerifiedToken, JwtError> {
        let header = decode_header(token).map_err(|e| JwtError::Invalid(e.to_string()))?;
        let kid = header.kid.ok_or(JwtError::UnknownKid)?;
        let key = km.decoding.get(&kid).ok_or(JwtError::UnknownKid)?;

        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);

        let data = decode::<Claims>(token, key, &validation).map_err(|e| match e.kind() {
            ErrorKind::ExpiredSignature => JwtError::Expired,
            _ => JwtError::Invalid(e.to_string()),
        })?;

        let scopes =
            ScopeSet::parse(&data.claims.scope).map_err(|e| JwtError::BadScope(e.to_string()))?;
        Ok(VerifiedToken {
            subject: data.claims.sub,
            scopes,
            expires_at: data.claims.exp,
        })
    }

    pub fn verify(&self, km: &KeyMaterial, token: &str) -> Result<ScopeSet, JwtError> {
        self.verify_token(km, token).map(|token| token.scopes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::build_key_material;
    use crate::scope::ScopeSet;

    fn km() -> crate::keystore::KeyMaterial {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        build_key_material(&key.serialize_pem(), None).unwrap()
    }

    fn now() -> u64 {
        jsonwebtoken::get_current_timestamp()
    }

    #[test]
    fn mint_then_verify_roundtrip() {
        let km = km();
        let issuer = Issuer::new(
            "iss".into(),
            "aud".into(),
            std::time::Duration::from_secs(3600),
        );
        let verifier = Verifier::new("iss".into(), "aud".into());
        let scopes = ScopeSet::parse("anthropic github:pitorg/pit-ts").unwrap();
        let token = issuer.mint(&km, "user:filip", &scopes, now()).unwrap();
        let got = verifier.verify(&km, &token).unwrap();
        assert_eq!(got.to_scope_string(), "anthropic github:pitorg/pit-ts");
        let verified = verifier.verify_token(&km, &token).unwrap();
        assert_eq!(verified.subject, "user:filip");
        assert!(verified.expires_at > now());
    }

    #[test]
    fn rejects_expired() {
        let km = km();
        let issuer = Issuer::new(
            "iss".into(),
            "aud".into(),
            std::time::Duration::from_secs(3600),
        );
        let verifier = Verifier::new("iss".into(), "aud".into());
        let scopes = ScopeSet::parse("anthropic").unwrap();
        // iat far in the past → exp already elapsed.
        let token = issuer.mint(&km, "s", &scopes, now() - 100_000).unwrap();
        assert!(matches!(
            verifier.verify(&km, &token),
            Err(JwtError::Expired)
        ));
    }

    #[test]
    fn rejects_wrong_audience() {
        let km = km();
        let issuer = Issuer::new(
            "iss".into(),
            "other-aud".into(),
            std::time::Duration::from_secs(3600),
        );
        let verifier = Verifier::new("iss".into(), "aud".into());
        let token = issuer
            .mint(&km, "s", &ScopeSet::parse("anthropic").unwrap(), now())
            .unwrap();
        assert!(matches!(
            verifier.verify(&km, &token),
            Err(JwtError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_unknown_kid() {
        // Token signed by a DIFFERENT key material → its kid isn't in `km`.
        let signer_km = km();
        let verifier_km = km();
        let issuer = Issuer::new(
            "iss".into(),
            "aud".into(),
            std::time::Duration::from_secs(3600),
        );
        let verifier = Verifier::new("iss".into(), "aud".into());
        let token = issuer
            .mint(
                &signer_km,
                "s",
                &ScopeSet::parse("anthropic").unwrap(),
                now(),
            )
            .unwrap();
        assert!(matches!(
            verifier.verify(&verifier_km, &token),
            Err(JwtError::UnknownKid)
        ));
    }
}
