use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Deserialize;
use serde_yaml_ng::Value;
use trust::config::{Config, UpstreamKind, UpstreamMode};
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
fn deployment_config_allowlists_google_api_connect_endpoints() {
    let documents = yaml_documents("deployment.yaml");
    let config_map = document(&documents, "ConfigMap", "trust-config");
    let config_source = config_map["data"]["config.toml"]
        .as_str()
        .expect("ConfigMap must contain data.config.toml");
    let config = Config::from_str(config_source).expect("embedded trust config must be valid");

    let forward_proxy = config
        .forward_proxy
        .expect("example must enable the CONNECT listener");
    assert!(
        forward_proxy.tls,
        "example must protect proxy JWTs with TLS"
    );
    assert!(
        forward_proxy.audit_unmatched.is_none(),
        "the production-oriented example must remain deny-by-default"
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
fn workload_bypasses_proxy_only_for_metadata_and_internal_trust_hosts() {
    let documents = yaml_documents("client-workload.yaml");
    let deployment = document(&documents, "Deployment", "my-service");
    let env = deployment["spec"]["template"]["spec"]["containers"][0]["env"]
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
        "https://trust.trust-system.svc:6180",
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
