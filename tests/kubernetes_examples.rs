use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Deserialize;
use serde_yaml_ng::Value;
use trust::config::{Config, CredentialSource, InjectionScheme, UpstreamKind, UpstreamMode};
use trust::resource::ResourceKind;

fn example_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples/kubernetes")
        .join(name)
}

fn yaml_documents(name: &str) -> Vec<Value> {
    let path = example_path(name);
    let source = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("failed to read {}: {error}", path.display());
    });
    serde_yaml_ng::Deserializer::from_str(&source)
        .map(|document| {
            Value::deserialize(document).unwrap_or_else(|error| {
                panic!("invalid YAML in {}: {error}", path.display());
            })
        })
        .collect()
}

fn document<'a>(documents: &'a [Value], kind: &str, name: &str) -> &'a Value {
    documents
        .iter()
        .find(|document| {
            document["kind"].as_str() == Some(kind)
                && document["metadata"]["name"].as_str() == Some(name)
        })
        .unwrap_or_else(|| panic!("missing {kind}/{name}"))
}

#[test]
fn all_kubernetes_examples_are_valid_yaml() {
    let directory = example_path("");
    for entry in fs::read_dir(&directory).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("yaml") {
            continue;
        }
        let name = path.file_name().unwrap().to_str().unwrap();
        let documents = yaml_documents(name);
        assert!(!documents.is_empty(), "{} contains no YAML", path.display());
        assert!(
            documents
                .iter()
                .all(|document| document.as_mapping().is_some()),
            "{} contains a non-object document",
            path.display()
        );
    }
}

#[test]
fn deployment_config_enables_audit_egress_and_allowlists_google_api_connect_endpoints() {
    let documents = yaml_documents("deployment.yaml");
    let config_map = document(&documents, "ConfigMap", "trust-config");
    let config_source = config_map["data"]["config.toml"]
        .as_str()
        .expect("ConfigMap must contain data.config.toml");
    let config = Config::from_str(config_source).expect("embedded trust config must be valid");

    let forward_proxy = config
        .forward_proxy
        .expect("example must enable the forward-proxy listener");
    assert!(
        !forward_proxy.tls,
        "example confines the plaintext proxy listener with NetworkPolicy"
    );
    assert_eq!(
        forward_proxy
            .audit_unmatched
            .as_ref()
            .map(|audit| audit.scope.as_str()),
        Some("outbound-audit"),
        "the sandbox egress example must audit-allow unmatched public destinations"
    );
    let mitm = forward_proxy
        .mitm
        .expect("example must configure its dedicated egress signer");
    assert_eq!(
        mitm.issuer_cert_chain_path,
        "/etc/trust/egress-mitm/intermediate-chain.pem"
    );
    assert_eq!(
        mitm.issuer_key_path,
        "/etc/trust/egress-mitm/intermediate.key"
    );

    for (name, host) in [
        ("gcp-pubsub", "pubsub.googleapis.com"),
        ("gcp-storage", "storage.googleapis.com"),
    ] {
        let upstream = config
            .upstreams
            .iter()
            .find(|upstream| upstream.name == name)
            .unwrap_or_else(|| panic!("missing {name} upstream"));
        assert_eq!(upstream.mode, UpstreamMode::Passthrough);
        assert!(upstream.allow_connect);
        assert_eq!(upstream.origin.host, host);
        assert_eq!(upstream.origin.port, 443);
        assert!(upstream.credential.is_none());
        assert!(upstream.injection.is_none());
    }

    let allowed_scopes = &config.issuance.clients[0].allowed_scopes;
    assert!(allowed_scopes.iter().any(|scope| scope == "gcp-pubsub"));
    assert!(allowed_scopes.iter().any(|scope| scope == "gcp-storage"));
    assert!(allowed_scopes.iter().any(|scope| scope == "outbound-audit"));

    let linear = config
        .upstreams
        .iter()
        .find(|upstream| upstream.name == "linear")
        .expect("example must include the Linear GraphQL upstream");
    assert_eq!(linear.origin.host, "api.linear.app");
    assert_eq!(linear.allowed_methods, ["POST"]);
    assert!(matches!(
        linear.credential,
        Some(CredentialSource::StaticSecret { .. })
    ));
    assert!(matches!(
        linear.injection,
        Some(ref injection)
            if injection.header.eq_ignore_ascii_case("authorization")
                && injection.scheme == InjectionScheme::Raw
    ));
    assert!(allowed_scopes.iter().any(|scope| scope == "linear"));

    let anthropic = config
        .upstreams
        .iter()
        .find(|upstream| upstream.name == "anthropic")
        .expect("example must include the opt-in Anthropic interception route");
    assert!(anthropic.intercept_connect);
    assert!(!anthropic.allow_connect);
    assert!(allowed_scopes.iter().any(|scope| scope == "anthropic"));

    let github = config
        .upstreams
        .iter()
        .find(|upstream| upstream.name == "github")
        .expect("example must include the GitHub CLI API upstream");
    assert_eq!(github.resource, Some(ResourceKind::GithubCliRepo));
    assert_eq!(github.origin.host, "api.github.com");

    let github_git = config
        .upstreams
        .iter()
        .find(|upstream| upstream.name == "github-git")
        .expect("example must include the gh git subprocess upstream");
    assert_eq!(github_git.kind, UpstreamKind::GitCache);
    assert_eq!(github_git.resource, Some(ResourceKind::GitRepo));
    assert!(
        allowed_scopes
            .iter()
            .any(|scope| scope == "github:ORG/REPOSITORY")
    );
    assert!(
        allowed_scopes
            .iter()
            .any(|scope| scope == "github-git:ORG/REPOSITORY")
    );
}

#[test]
fn kubernetes_examples_keep_mitm_signer_and_workload_ca_separate() {
    let trust_documents = yaml_documents("deployment.yaml");
    let trust = document(&trust_documents, "Deployment", "trust");
    let trust_pod = &trust["spec"]["template"]["spec"];
    let trust_container = &trust_pod["containers"]
        .as_sequence()
        .expect("trust deployment must have a container")[0];
    let signer_mount = trust_container["volumeMounts"]
        .as_sequence()
        .expect("trust container must have volume mounts")
        .iter()
        .find(|mount| mount["name"].as_str() == Some("egress-mitm-intermediate"))
        .expect("trust must mount the egress signer");
    assert_eq!(
        signer_mount["mountPath"].as_str(),
        Some("/etc/trust/egress-mitm")
    );
    assert_eq!(signer_mount["readOnly"].as_bool(), Some(true));
    let signer_volume = trust_pod["volumes"]
        .as_sequence()
        .expect("trust pod must have volumes")
        .iter()
        .find(|volume| volume["name"].as_str() == Some("egress-mitm-intermediate"))
        .expect("trust must define the egress signer volume");
    assert_eq!(
        signer_volume["secret"]["secretName"].as_str(),
        Some("trust-egress-mitm-intermediate")
    );

    let workload_documents = yaml_documents("client-workload.yaml");
    let workload_ca = document(&workload_documents, "ConfigMap", "trust-egress-mitm-ca");
    let ca_data = workload_ca["data"]
        .as_mapping()
        .expect("egress CA ConfigMap must have data");
    assert_eq!(ca_data.len(), 1, "workload receives only the public CA");
    let ca = workload_ca["data"]["ca-bundle.crt"]
        .as_str()
        .expect("egress CA ConfigMap must provide ca-bundle.crt");
    assert!(ca.contains("BEGIN CERTIFICATE"));
    assert!(!ca.contains("PRIVATE KEY"));

    let workload = document(&workload_documents, "Deployment", "my-service");
    let workload_pod = &workload["spec"]["template"]["spec"];
    let workload_container = &workload_pod["containers"]
        .as_sequence()
        .expect("workload deployment must have a container")[0];
    let ca_mount = workload_container["volumeMounts"]
        .as_sequence()
        .expect("workload container must have volume mounts")
        .iter()
        .find(|mount| mount["name"].as_str() == Some("trust-egress-mitm-ca"))
        .expect("workload must mount the opt-in public CA");
    assert_eq!(
        ca_mount["mountPath"].as_str(),
        Some("/var/run/trust/egress-mitm")
    );
    assert_eq!(ca_mount["readOnly"].as_bool(), Some(true));
    let ca_volume = workload_pod["volumes"]
        .as_sequence()
        .expect("workload pod must have volumes")
        .iter()
        .find(|volume| volume["name"].as_str() == Some("trust-egress-mitm-ca"))
        .expect("workload must define the egress CA volume");
    assert_eq!(
        ca_volume["configMap"]["name"].as_str(),
        Some("trust-egress-mitm-ca")
    );
}

#[test]
fn restricted_sandbox_can_reach_only_trust_dns_and_gke_metadata() {
    let documents = yaml_documents("sandbox-egress-network-policy.yaml");
    let policy = document(&documents, "NetworkPolicy", "sandbox-egress-through-trust");
    let rules = policy["spec"]["egress"]
        .as_sequence()
        .expect("NetworkPolicy must define egress rules");

    let metadata_rule = rules
        .iter()
        .find(|rule| {
            rule["to"].as_sequence().is_some_and(|destinations| {
                destinations.iter().any(|destination| {
                    destination["ipBlock"]["cidr"].as_str() == Some("169.254.169.254/32")
                })
            })
        })
        .expect("Dataplane V2 GKE metadata server must be allowlisted");
    let metadata_ports = metadata_rule["ports"]
        .as_sequence()
        .expect("metadata rule must restrict ports")
        .iter()
        .map(|port| {
            port["port"]
                .as_u64()
                .expect("metadata port must be numeric")
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(metadata_ports, BTreeSet::from([80, 8080]));

    let cidrs = rules
        .iter()
        .flat_map(|rule| rule["to"].as_sequence().into_iter().flatten())
        .filter_map(|destination| destination["ipBlock"]["cidr"].as_str())
        .collect::<Vec<_>>();
    assert_eq!(cidrs, ["169.254.169.254/32"]);

    let direct_api_port = rules.iter().any(|rule| {
        rule["ports"]
            .as_sequence()
            .is_some_and(|ports| ports.iter().any(|port| port["port"].as_u64() == Some(443)))
    });
    assert!(
        !direct_api_port,
        "sandbox must not have direct HTTPS egress"
    );
}

#[test]
fn workload_uses_the_internal_proxy_without_a_relay_sidecar() {
    let documents = yaml_documents("client-workload.yaml");
    let deployment = document(&documents, "Deployment", "my-service");
    let containers = deployment["spec"]["template"]["spec"]["containers"]
        .as_sequence()
        .expect("workload must define containers");
    let env = containers[0]["env"]
        .as_sequence()
        .expect("client container must define env");
    let no_proxy = env
        .iter()
        .find(|entry| entry["name"].as_str() == Some("NO_PROXY"))
        .and_then(|entry| entry["value"].as_str())
        .expect("client must define NO_PROXY");
    let entries = no_proxy.split(',').map(str::trim).collect::<BTreeSet<_>>();

    for required in [
        "metadata.google.internal",
        "169.254.169.254",
        "169.254.169.252",
        "trust.trust-system.svc",
        ".proxy.internal",
    ] {
        assert!(entries.contains(required), "NO_PROXY is missing {required}");
    }
    assert!(!entries.contains(".googleapis.com"));
    assert_eq!(containers.len(), 1, "workload must not run a relay sidecar");
    assert!(env.iter().any(
        |entry| entry["name"].as_str() == Some("TRUST_FORWARD_PROXY")
            && entry["value"].as_str() == Some("http://trust.trust-system.svc:6180")
    ));
    for proxy_variable in ["HTTP_PROXY", "HTTPS_PROXY"] {
        assert!(
            env.iter()
                .any(|entry| entry["name"].as_str() == Some(proxy_variable)
                    && entry["value"].as_str()
                        == Some(
                            "http://jwt:REPLACE_WITH_SHORT_LIVED_TRUST_JWT@trust.trust-system.svc:6180"
                        ))
        );
    }
    assert!(
        env.iter()
            .any(|entry| entry["name"].as_str() == Some("SSL_CERT_FILE")
                && entry["value"].as_str() == Some("/var/run/trust/egress-mitm/ca-bundle.crt"))
    );
}

#[test]
fn live_gke_smoke_job_exercises_metadata_pubsub_and_storage() {
    let documents = yaml_documents("gcp-wif-smoke-test.yaml");
    let job = document(&documents, "Job", "trust-gcp-wif-smoke-test");
    let pod_spec = &job["spec"]["template"]["spec"];
    assert_eq!(pod_spec["serviceAccountName"].as_str(), Some("my-service"));
    assert_eq!(
        pod_spec["automountServiceAccountToken"].as_bool(),
        Some(false)
    );

    let labels = &job["spec"]["template"]["metadata"]["labels"];
    for label in [
        "trust.example.com/token-client",
        "trust.example.com/proxy-client",
        "trust.example.com/restricted-egress",
    ] {
        assert_eq!(labels[label].as_str(), Some("true"));
    }

    let command = pod_spec["containers"][0]["command"]
        .as_sequence()
        .expect("smoke container must define a command");
    assert_eq!(command[0].as_str(), Some("/bin/sh"));
    assert_eq!(command[1].as_str(), Some("-ceu"));
    let script = command[2]
        .as_str()
        .expect("smoke command must contain a script");
    for required in [
        "metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://trust.trust-system.svc:6180",
        "Proxy-Authorization: Bearer ${TRUST_TOKEN}",
        "https://pubsub.googleapis.com/",
        "https://storage.googleapis.com/",
        "Authorization: Bearer ${GOOGLE_TOKEN}",
    ] {
        assert!(
            script.contains(required),
            "smoke script is missing {required}"
        );
    }

    let mut shell = Command::new("/bin/sh")
        .arg("-n")
        .stdin(Stdio::piped())
        .spawn()
        .expect("/bin/sh must be available to validate the smoke script");
    shell
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    assert!(
        shell.wait().unwrap().success(),
        "smoke script has invalid shell syntax"
    );
}
