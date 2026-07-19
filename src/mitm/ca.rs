use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use pingora::tls::pkey::{PKey, Private};
use pingora::tls::x509::X509;
use rand::RngCore;
use rcgen::{
    CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    SerialNumber,
};
use time::{Duration as TimeDuration, OffsetDateTime};
use x509_parser::parse_x509_certificate;

use crate::config::{ForwardProxyMitmConfig, canonical_intercept_dns_host};

#[derive(Debug, thiserror::Error)]
pub enum MitmCaError {
    #[error("failed to read egress signer material at {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid egress signer: {0}")]
    InvalidIssuer(String),
    #[error("invalid interception DNS hostname: {0}")]
    InvalidHostname(String),
    #[error("failed to issue egress leaf certificate: {0}")]
    Issue(String),
    #[error("leaf cache capacity {capacity} is smaller than configured host count {hosts}")]
    CacheCapacity { capacity: usize, hosts: usize },
}

/// In-memory certificate/key material for one exact intercepted hostname.
///
/// The leaf key is intentionally never serialized to disk. This type does not
/// implement `Debug` so accidental logging cannot expose key material.
pub struct LeafCertificate {
    pub(crate) hostname: String,
    pub(crate) certificate: X509,
    pub(crate) private_key: PKey<Private>,
    pub(crate) intermediates: Vec<X509>,
    expires_at: OffsetDateTime,
}

impl LeafCertificate {
    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }
}

/// An online, scoped intermediate signer. The root never enters this type.
pub struct EgressSigner {
    issuer: Issuer<'static, KeyPair>,
    intermediates: Vec<X509>,
    leaf_ttl: Duration,
    issuer_not_after: OffsetDateTime,
}

impl EgressSigner {
    pub fn load(config: &ForwardProxyMitmConfig) -> Result<Self, MitmCaError> {
        let certificate_chain =
            std::fs::read(&config.issuer_cert_chain_path).map_err(|source| MitmCaError::Read {
                path: config.issuer_cert_chain_path.clone(),
                source,
            })?;
        let key = std::fs::read(&config.issuer_key_path).map_err(|source| MitmCaError::Read {
            path: config.issuer_key_path.clone(),
            source,
        })?;
        Self::from_pem(&certificate_chain, &key, config.leaf_ttl)
    }

    pub fn from_pem(
        certificate_chain_pem: &[u8],
        private_key_pem: &[u8],
        leaf_ttl: Duration,
    ) -> Result<Self, MitmCaError> {
        let intermediates = X509::stack_from_pem(certificate_chain_pem).map_err(|error| {
            MitmCaError::InvalidIssuer(format!("invalid certificate chain: {error}"))
        })?;
        let issuer_certificate = intermediates.first().ok_or_else(|| {
            MitmCaError::InvalidIssuer("issuer certificate chain is empty".to_string())
        })?;

        if issuer_certificate
            .subject_name()
            .try_cmp(issuer_certificate.issuer_name())
            .map_err(|error| MitmCaError::InvalidIssuer(format!("compare issuer name: {error}")))?
            == Ordering::Equal
        {
            return Err(MitmCaError::InvalidIssuer(
                "a self-signed root must not be mounted as the online signer".to_string(),
            ));
        }
        for certificate in intermediates.iter().skip(1) {
            if certificate
                .subject_name()
                .try_cmp(certificate.issuer_name())
                .map_err(|error| {
                    MitmCaError::InvalidIssuer(format!("compare certificate chain name: {error}"))
                })?
                == Ordering::Equal
            {
                return Err(MitmCaError::InvalidIssuer(
                    "the mounted signer chain must omit its self-signed root".to_string(),
                ));
            }
        }

        let issuer_der = issuer_certificate
            .to_der()
            .map_err(|error| MitmCaError::InvalidIssuer(format!("serialize issuer: {error}")))?;
        let (_, parsed_issuer) = parse_x509_certificate(&issuer_der).map_err(|error| {
            MitmCaError::InvalidIssuer(format!("parse issuer certificate: {error}"))
        })?;
        if !parsed_issuer.is_ca() {
            return Err(MitmCaError::InvalidIssuer(
                "signing certificate must have CA:TRUE".to_string(),
            ));
        }
        let key_usage = parsed_issuer
            .key_usage()
            .map_err(|error| {
                MitmCaError::InvalidIssuer(format!("parse issuer key usage: {error}"))
            })?
            .ok_or_else(|| {
                MitmCaError::InvalidIssuer(
                    "signing certificate must include keyCertSign usage".to_string(),
                )
            })?;
        if !key_usage.value.key_cert_sign() {
            return Err(MitmCaError::InvalidIssuer(
                "signing certificate must include keyCertSign usage".to_string(),
            ));
        }
        if !parsed_issuer.validity().is_valid() {
            return Err(MitmCaError::InvalidIssuer(
                "signing certificate is not currently valid".to_string(),
            ));
        }

        let private_key = PKey::private_key_from_pem(private_key_pem)
            .map_err(|error| MitmCaError::InvalidIssuer(format!("parse issuer key: {error}")))?;
        let issuer_public_key = issuer_certificate.public_key().map_err(|error| {
            MitmCaError::InvalidIssuer(format!("read issuer public key: {error}"))
        })?;
        if !issuer_public_key.public_eq(&private_key) {
            return Err(MitmCaError::InvalidIssuer(
                "issuer private key does not match signing certificate".to_string(),
            ));
        }

        let issuer_pem = issuer_certificate.to_pem().map_err(|error| {
            MitmCaError::InvalidIssuer(format!("serialize issuer PEM: {error}"))
        })?;
        let key_pem = private_key.private_key_to_pem_pkcs8().map_err(|error| {
            MitmCaError::InvalidIssuer(format!("serialize issuer key: {error}"))
        })?;
        let key_pem = std::str::from_utf8(&key_pem).map_err(|error| {
            MitmCaError::InvalidIssuer(format!("issuer key is not PEM: {error}"))
        })?;
        let issuer_key = KeyPair::from_pem(key_pem).map_err(|error| {
            MitmCaError::InvalidIssuer(format!("unsupported issuer key: {error}"))
        })?;
        let issuer_pem = std::str::from_utf8(&issuer_pem).map_err(|error| {
            MitmCaError::InvalidIssuer(format!("issuer certificate is not PEM: {error}"))
        })?;
        let issuer = Issuer::from_ca_cert_pem(issuer_pem, issuer_key).map_err(|error| {
            MitmCaError::InvalidIssuer(format!("parse issuer for signing: {error}"))
        })?;

        Ok(EgressSigner {
            issuer,
            intermediates,
            leaf_ttl,
            issuer_not_after: parsed_issuer.validity().not_after.to_datetime(),
        })
    }

    pub fn issue_leaf(&self, hostname: &str) -> Result<LeafCertificate, MitmCaError> {
        let hostname = canonical_intercept_dns_host(hostname)
            .ok_or_else(|| MitmCaError::InvalidHostname(hostname.to_string()))?;
        let now = OffsetDateTime::now_utc();
        let ttl_seconds = i64::try_from(self.leaf_ttl.as_secs())
            .map_err(|_| MitmCaError::Issue("leaf TTL is too large".to_string()))?;
        let requested_not_after = now + TimeDuration::seconds(ttl_seconds);
        let not_after = requested_not_after.min(self.issuer_not_after);
        if not_after <= now {
            return Err(MitmCaError::Issue(
                "signing intermediate has no remaining validity".to_string(),
            ));
        }

        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|error| MitmCaError::Issue(format!("generate leaf key: {error}")))?;
        let mut params = CertificateParams::new(vec![hostname.clone()])
            .map_err(|error| MitmCaError::Issue(format!("build leaf parameters: {error}")))?;
        params.not_before = now - TimeDuration::minutes(1);
        params.not_after = not_after;
        params.is_ca = IsCa::ExplicitNoCa;
        params
            .distinguished_name
            .push(DnType::CommonName, hostname.clone());
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.serial_number = Some(random_positive_serial());

        let certificate = params
            .signed_by(&leaf_key, &self.issuer)
            .map_err(|error| MitmCaError::Issue(format!("sign leaf certificate: {error}")))?;
        let certificate = X509::from_der(certificate.der().as_ref())
            .map_err(|error| MitmCaError::Issue(format!("parse issued leaf: {error}")))?;
        let private_key = PKey::private_key_from_pem(leaf_key.serialize_pem().as_bytes())
            .map_err(|error| MitmCaError::Issue(format!("parse issued leaf key: {error}")))?;

        Ok(LeafCertificate {
            hostname,
            certificate,
            private_key,
            intermediates: self.intermediates.clone(),
            expires_at: not_after,
        })
    }
}

/// A bounded cache containing only configuration-approved exact hostnames.
/// Certificate issuance happens during startup or background refresh, never in
/// the TLS handshake callback.
pub struct LeafCertificateCache {
    signer: Arc<EgressSigner>,
    entries: RwLock<HashMap<String, Arc<LeafCertificate>>>,
    hosts: Vec<String>,
    refresh_before: Duration,
}

impl LeafCertificateCache {
    pub fn new(
        signer: Arc<EgressSigner>,
        hosts: impl IntoIterator<Item = String>,
        refresh_before: Duration,
        capacity: usize,
    ) -> Result<Self, MitmCaError> {
        let mut unique = HashSet::new();
        for host in hosts {
            let host = canonical_intercept_dns_host(&host)
                .ok_or_else(|| MitmCaError::InvalidHostname(host.clone()))?;
            unique.insert(host);
        }
        let mut hosts: Vec<_> = unique.into_iter().collect();
        hosts.sort();
        if hosts.len() > capacity {
            return Err(MitmCaError::CacheCapacity {
                capacity,
                hosts: hosts.len(),
            });
        }

        let mut entries = HashMap::with_capacity(hosts.len());
        for host in &hosts {
            entries.insert(host.clone(), Arc::new(signer.issue_leaf(host)?));
        }
        Ok(LeafCertificateCache {
            signer,
            entries: RwLock::new(entries),
            hosts,
            refresh_before,
        })
    }

    /// Return only an already-issued, non-expired leaf. This is safe to call
    /// from a TLS callback because it cannot issue or perform I/O.
    pub fn get(&self, hostname: &str) -> Option<Arc<LeafCertificate>> {
        self.get_at(hostname, OffsetDateTime::now_utc())
    }

    fn get_at(&self, hostname: &str, now: OffsetDateTime) -> Option<Arc<LeafCertificate>> {
        let hostname = canonical_intercept_dns_host(hostname)?;
        let leaf = self.entries.read().ok()?.get(&hostname)?.clone();
        (leaf.expires_at > now).then_some(leaf)
    }

    pub fn len(&self) -> usize {
        self.entries.read().map_or(0, |entries| entries.len())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Refresh all leaves that are nearing expiry. Call from a background task;
    /// this method intentionally performs local signing outside a TLS handshake.
    pub fn refresh_due(&self) -> Result<usize, MitmCaError> {
        self.refresh_due_at(OffsetDateTime::now_utc())
    }

    fn refresh_due_at(&self, now: OffsetDateTime) -> Result<usize, MitmCaError> {
        let refresh_seconds = i64::try_from(self.refresh_before.as_secs())
            .map_err(|_| MitmCaError::Issue("refresh window is too large".to_string()))?;
        let deadline = now + TimeDuration::seconds(refresh_seconds);
        let due_hosts: Vec<_> = {
            let entries = self
                .entries
                .read()
                .map_err(|_| MitmCaError::Issue("leaf cache lock poisoned".to_string()))?;
            self.hosts
                .iter()
                .filter(|host| {
                    entries
                        .get(*host)
                        .is_none_or(|leaf| leaf.expires_at <= deadline)
                })
                .cloned()
                .collect()
        };

        if due_hosts.is_empty() {
            return Ok(0);
        }
        let mut refreshed = Vec::with_capacity(due_hosts.len());
        for host in due_hosts {
            refreshed.push((host.clone(), Arc::new(self.signer.issue_leaf(&host)?)));
        }
        let mut entries = self
            .entries
            .write()
            .map_err(|_| MitmCaError::Issue("leaf cache lock poisoned".to_string()))?;
        let count = refreshed.len();
        entries.extend(refreshed);
        Ok(count)
    }

    pub fn spawn_refresher(self: Arc<Self>) {
        let period = self.refresh_before.div_f64(2.0).max(Duration::from_secs(1));
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(period).await;
                if let Err(error) = self.refresh_due() {
                    log::error!("egress leaf certificate refresh failed: {error}");
                }
            }
        });
    }
}

fn random_positive_serial() -> SerialNumber {
    let mut serial = [0_u8; 16];
    rand::rng().fill_bytes(&mut serial);
    serial[0] &= 0x7f;
    if serial.iter().all(|byte| *byte == 0) {
        serial[15] = 1;
    }
    SerialNumber::from(serial.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, KeyUsagePurpose};

    fn intermediate_material() -> (String, String) {
        let mut root_params = CertificateParams::default();
        root_params
            .distinguished_name
            .push(DnType::CommonName, "Trust test root");
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let root_key = KeyPair::generate().unwrap();
        let _root_certificate = root_params.self_signed(&root_key).unwrap();
        let root_issuer = Issuer::new(root_params, root_key);

        let mut intermediate_params = CertificateParams::default();
        intermediate_params
            .distinguished_name
            .push(DnType::CommonName, "Trust test intermediate");
        intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        intermediate_params.key_usages =
            vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let intermediate_key = KeyPair::generate().unwrap();
        let intermediate = intermediate_params
            .signed_by(&intermediate_key, &root_issuer)
            .unwrap();
        (intermediate.pem(), intermediate_key.serialize_pem())
    }

    #[test]
    fn issues_exact_dns_leaf_from_intermediate() {
        let (chain, key) = intermediate_material();
        let signer =
            EgressSigner::from_pem(chain.as_bytes(), key.as_bytes(), Duration::from_secs(3600))
                .unwrap();

        let leaf = signer.issue_leaf("Api.Example.Com.").unwrap();
        assert_eq!(leaf.hostname(), "api.example.com");
        assert_eq!(leaf.intermediates.len(), 1);
        let sans = leaf.certificate.subject_alt_names().unwrap();
        assert_eq!(sans.len(), 1);
        assert_eq!(sans[0].dnsname(), Some("api.example.com"));
        assert!(
            leaf.certificate
                .public_key()
                .unwrap()
                .public_eq(&leaf.private_key)
        );
    }

    #[test]
    fn rejects_root_or_mismatched_signer_key() {
        let mut root_params = CertificateParams::default();
        root_params
            .distinguished_name
            .push(DnType::CommonName, "Trust test root");
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let root_key = KeyPair::generate().unwrap();
        let root = root_params.self_signed(&root_key).unwrap();
        assert!(matches!(
            EgressSigner::from_pem(
                root.pem().as_bytes(),
                root_key.serialize_pem().as_bytes(),
                Duration::from_secs(60)
            ),
            Err(MitmCaError::InvalidIssuer(_))
        ));

        let (chain, _key) = intermediate_material();
        let wrong_key = KeyPair::generate().unwrap();
        assert!(matches!(
            EgressSigner::from_pem(
                chain.as_bytes(),
                wrong_key.serialize_pem().as_bytes(),
                Duration::from_secs(60)
            ),
            Err(MitmCaError::InvalidIssuer(_))
        ));
    }

    #[test]
    fn rejects_malformed_non_ca_and_expired_signers() {
        assert!(matches!(
            EgressSigner::from_pem(b"not a certificate", b"not a key", Duration::from_secs(60)),
            Err(MitmCaError::InvalidIssuer(_))
        ));

        let mut root_params = CertificateParams::default();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let root_key = KeyPair::generate().unwrap();
        let root_issuer = Issuer::new(root_params, root_key);

        let mut non_ca_params = CertificateParams::default();
        non_ca_params
            .distinguished_name
            .push(DnType::CommonName, "Trust test non-CA");
        non_ca_params.is_ca = IsCa::ExplicitNoCa;
        let non_ca_key = KeyPair::generate().unwrap();
        let non_ca = non_ca_params.signed_by(&non_ca_key, &root_issuer).unwrap();
        assert!(matches!(
            EgressSigner::from_pem(
                non_ca.pem().as_bytes(),
                non_ca_key.serialize_pem().as_bytes(),
                Duration::from_secs(60)
            ),
            Err(MitmCaError::InvalidIssuer(_))
        ));

        let mut expired_params = CertificateParams::default();
        expired_params
            .distinguished_name
            .push(DnType::CommonName, "Trust expired intermediate");
        expired_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        expired_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        expired_params.not_before = OffsetDateTime::now_utc() - TimeDuration::days(2);
        expired_params.not_after = OffsetDateTime::now_utc() - TimeDuration::days(1);
        let expired_key = KeyPair::generate().unwrap();
        let expired = expired_params
            .signed_by(&expired_key, &root_issuer)
            .unwrap();
        assert!(matches!(
            EgressSigner::from_pem(
                expired.pem().as_bytes(),
                expired_key.serialize_pem().as_bytes(),
                Duration::from_secs(60)
            ),
            Err(MitmCaError::InvalidIssuer(_))
        ));
    }

    #[test]
    fn caps_leaf_validity_at_the_signing_intermediate_expiry() {
        let mut root_params = CertificateParams::default();
        root_params
            .distinguished_name
            .push(DnType::CommonName, "Trust test root");
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let root_key = KeyPair::generate().unwrap();
        let root_issuer = Issuer::new(root_params, root_key);

        let issuer_expiry = OffsetDateTime::now_utc() + TimeDuration::minutes(10);
        let mut intermediate_params = CertificateParams::default();
        intermediate_params
            .distinguished_name
            .push(DnType::CommonName, "Trust short-lived intermediate");
        intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        intermediate_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        intermediate_params.not_after = issuer_expiry;
        let intermediate_key = KeyPair::generate().unwrap();
        let intermediate = intermediate_params
            .signed_by(&intermediate_key, &root_issuer)
            .unwrap();
        let signer = EgressSigner::from_pem(
            intermediate.pem().as_bytes(),
            intermediate_key.serialize_pem().as_bytes(),
            Duration::from_secs(24 * 60 * 60),
        )
        .unwrap();

        let leaf = signer.issue_leaf("api.example.com").unwrap();
        assert!(leaf.expires_at() <= issuer_expiry);
        assert!(leaf.expires_at() > OffsetDateTime::now_utc());
    }

    #[test]
    fn prewarms_only_configured_hosts() {
        let (chain, key) = intermediate_material();
        let signer = Arc::new(
            EgressSigner::from_pem(chain.as_bytes(), key.as_bytes(), Duration::from_secs(3600))
                .unwrap(),
        );
        let cache = LeafCertificateCache::new(
            signer,
            [
                "api.example.com".to_string(),
                "other.example.com".to_string(),
            ],
            Duration::from_secs(60),
            2,
        )
        .unwrap();

        assert_eq!(cache.len(), 2);
        assert!(cache.get("API.EXAMPLE.COM.").is_some());
        assert!(cache.get("not-configured.example.com").is_none());
        assert!(
            LeafCertificateCache::new(
                Arc::new(
                    EgressSigner::from_pem(
                        chain.as_bytes(),
                        key.as_bytes(),
                        Duration::from_secs(3600)
                    )
                    .unwrap(),
                ),
                [
                    "api.example.com".to_string(),
                    "other.example.com".to_string()
                ],
                Duration::from_secs(60),
                1,
            )
            .is_err()
        );
    }

    #[test]
    fn cache_fails_closed_when_expired_and_refreshes_only_known_hosts() {
        let (chain, key) = intermediate_material();
        let signer = Arc::new(
            EgressSigner::from_pem(chain.as_bytes(), key.as_bytes(), Duration::from_secs(3600))
                .unwrap(),
        );
        let cache = LeafCertificateCache::new(
            signer,
            ["api.example.com".to_string()],
            Duration::from_secs(60),
            1,
        )
        .unwrap();
        let original = cache.get("api.example.com").unwrap();
        assert!(
            cache
                .get_at(
                    "api.example.com",
                    original.expires_at() + TimeDuration::seconds(1)
                )
                .is_none()
        );

        assert_eq!(
            cache
                .refresh_due_at(original.expires_at() - TimeDuration::seconds(30))
                .unwrap(),
            1
        );
        let refreshed = cache.get("api.example.com").unwrap();
        assert!(!Arc::ptr_eq(&original, &refreshed));
        assert!(cache.get("other.example.com").is_none());
    }
}
