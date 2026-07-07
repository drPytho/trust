use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, EllipticCurve, EllipticCurveKeyParameters,
    EllipticCurveKeyType, Jwk, JwkSet, KeyAlgorithm, PublicKeyUse, ThumbprintHash,
};
use jsonwebtoken::{DecodingKey, EncodingKey};
use p256::SecretKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::{DecodePrivateKey, EncodePublicKey};

use crate::config::SigningConfig;
use crate::secrets::SecretProvider;

#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("invalid signing key: {0}")]
    BadKey(String),
    #[error("secret backend error: {0}")]
    Secret(String),
}

pub struct KeyMaterial {
    pub signing_kid: String,
    pub encoding: EncodingKey,
    pub decoding: HashMap<String, DecodingKey>,
    pub jwks_json: String,
}

fn jwk_for(secret: &SecretKey) -> (String, Jwk, DecodingKey) {
    let public = secret.public_key();
    let point = public.to_encoded_point(false); // 0x04 || X(32) || Y(32)
    let x = URL_SAFE_NO_PAD.encode(point.x().expect("P-256 has X"));
    let y = URL_SAFE_NO_PAD.encode(point.y().expect("P-256 has Y"));

    let mut jwk = Jwk {
        common: CommonParameters {
            public_key_use: Some(PublicKeyUse::Signature),
            key_algorithm: Some(KeyAlgorithm::ES256),
            key_id: None,
            ..Default::default()
        },
        algorithm: AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
            key_type: EllipticCurveKeyType::EC,
            curve: EllipticCurve::P256,
            x,
            y,
        }),
    };
    let kid = jwk.thumbprint(ThumbprintHash::SHA256);
    jwk.common.key_id = Some(kid.clone());

    let spki_pem = public
        .to_public_key_pem(p256::pkcs8::LineEnding::LF)
        .expect("public key to SPKI PEM");
    let decoding = DecodingKey::from_ec_pem(spki_pem.as_bytes()).expect("valid SPKI");
    (kid, jwk, decoding)
}

pub fn build_key_material(
    current_pkcs8_pem: &str,
    previous_pkcs8_pem: Option<&str>,
) -> Result<KeyMaterial, KeystoreError> {
    let current = SecretKey::from_pkcs8_pem(current_pkcs8_pem)
        .map_err(|e| KeystoreError::BadKey(e.to_string()))?;
    let encoding = EncodingKey::from_ec_pem(current_pkcs8_pem.as_bytes())
        .map_err(|e| KeystoreError::BadKey(e.to_string()))?;

    let (signing_kid, cur_jwk, cur_decoding) = jwk_for(&current);
    let mut decoding = HashMap::new();
    decoding.insert(signing_kid.clone(), cur_decoding);
    let mut jwks = vec![cur_jwk];

    if let Some(prev_pem) = previous_pkcs8_pem {
        let prev = SecretKey::from_pkcs8_pem(prev_pem)
            .map_err(|e| KeystoreError::BadKey(e.to_string()))?;
        let (prev_kid, prev_jwk, prev_decoding) = jwk_for(&prev);
        if prev_kid != signing_kid {
            decoding.insert(prev_kid, prev_decoding);
            jwks.push(prev_jwk);
        }
    }

    let jwks_json = serde_json::to_string(&JwkSet { keys: jwks })
        .map_err(|e| KeystoreError::BadKey(e.to_string()))?;

    Ok(KeyMaterial {
        signing_kid,
        encoding,
        decoding,
        jwks_json,
    })
}

pub async fn fetch(
    provider: &dyn SecretProvider,
    cfg: &SigningConfig,
) -> Result<KeyMaterial, KeystoreError> {
    let current = provider
        .get(&cfg.key_secret_ref)
        .await
        .map_err(|e| KeystoreError::Secret(e.to_string()))?;
    let previous = match &cfg.previous_key_secret_ref {
        Some(r) => Some(
            provider
                .get(r)
                .await
                .map_err(|e| KeystoreError::Secret(e.to_string()))?,
        ),
        None => None,
    };
    build_key_material(current.expose(), previous.as_ref().map(|s| s.expose()))
}

pub struct Keystore {
    current: ArcSwapOption<KeyMaterial>,
}

impl Keystore {
    pub fn new() -> Keystore {
        Keystore {
            current: ArcSwapOption::empty(),
        }
    }

    pub fn load(&self) -> Option<Arc<KeyMaterial>> {
        self.current.load_full()
    }

    pub fn store(&self, km: KeyMaterial) {
        self.current.store(Some(Arc::new(km)));
    }
}

impl Default for Keystore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Generate an EC P-256 PKCS8 private key PEM for tests.
    fn gen_pkcs8_pem() -> String {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        key.serialize_pem()
    }

    #[test]
    fn builds_material_with_one_key() {
        let pem = gen_pkcs8_pem();
        let km = build_key_material(&pem, None).unwrap();
        assert!(!km.signing_kid.is_empty());
        assert!(km.decoding.contains_key(&km.signing_kid));
        assert!(km.jwks_json.contains("\"kty\":\"EC\""));
        assert!(km.jwks_json.contains("\"crv\":\"P-256\""));
        assert!(km.jwks_json.contains(&km.signing_kid));
    }

    #[test]
    fn previous_key_is_verify_only_and_in_jwks() {
        let cur = gen_pkcs8_pem();
        let prev = gen_pkcs8_pem();
        let km = build_key_material(&cur, Some(&prev)).unwrap();
        // Two distinct kids in the decoding map + JWKS; signing kid is the current one.
        assert_eq!(km.decoding.len(), 2);
        assert!(km.decoding.contains_key(&km.signing_kid));
        let key_count = km.jwks_json.matches("\"kid\"").count();
        assert_eq!(key_count, 2);
    }

    #[test]
    fn keystore_swaps() {
        let ks = Keystore::new();
        assert!(ks.load().is_none());
        ks.store(build_key_material(&gen_pkcs8_pem(), None).unwrap());
        assert!(ks.load().is_some());
    }
}
