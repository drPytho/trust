use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
};

/// Prometheus metrics emitted by the proxy request lifecycle.
pub struct ProxyMetrics {
    registry: Registry,
    requests: IntCounterVec,
    rejections: IntCounterVec,
    request_duration: HistogramVec,
    in_flight: IntGauge,
    credential_resolutions: IntCounterVec,
    credential_resolution_duration: HistogramVec,
    connect_attempts: IntCounterVec,
    connect_active: IntGaugeVec,
    connect_duration: HistogramVec,
    connect_bytes: IntCounterVec,
    forward_proxy_requests: IntCounterVec,
    mitm_handshakes: IntCounterVec,
    mitm_certificate_cache: IntCounterVec,
    mitm_active_connections: IntGaugeVec,
    mitm_connection_duration: HistogramVec,
}

impl ProxyMetrics {
    pub fn new() -> ProxyMetrics {
        let registry = Registry::new();
        let requests = IntCounterVec::new(
            Opts::new(
                "trust_proxy_requests_total",
                "Completed proxy requests by routed upstream and HTTP status.",
            ),
            &["upstream", "status"],
        )
        .expect("valid requests metric");
        let rejections = IntCounterVec::new(
            Opts::new(
                "trust_proxy_rejections_total",
                "Proxy requests rejected locally by reason, routed upstream, and HTTP status.",
            ),
            &["upstream", "reason", "status"],
        )
        .expect("valid rejections metric");
        let request_duration = HistogramVec::new(
            HistogramOpts::new(
                "trust_proxy_request_duration_seconds",
                "Proxy request duration in seconds by routed upstream.",
            ),
            &["upstream"],
        )
        .expect("valid request duration metric");
        let in_flight = IntGauge::new(
            "trust_proxy_in_flight_requests",
            "Number of proxy requests currently being processed.",
        )
        .expect("valid in-flight metric");
        let credential_resolutions = IntCounterVec::new(
            Opts::new(
                "trust_credential_resolutions_total",
                "Credential resolutions by upstream, provider, and result.",
            ),
            &["upstream", "provider", "result"],
        )
        .expect("valid credential resolutions metric");
        let credential_resolution_duration = HistogramVec::new(
            HistogramOpts::new(
                "trust_credential_resolution_duration_seconds",
                "Credential resolution duration by provider.",
            ),
            &["provider"],
        )
        .expect("valid credential resolution duration metric");
        let connect_attempts = IntCounterVec::new(
            Opts::new(
                "trust_connect_attempts_total",
                "CONNECT attempts by configured upstream or audit fallback and bounded result.",
            ),
            &["upstream", "result"],
        )
        .expect("valid CONNECT attempts metric");
        let connect_active = IntGaugeVec::new(
            Opts::new(
                "trust_connect_active_tunnels",
                "Active CONNECT tunnels by configured upstream.",
            ),
            &["upstream"],
        )
        .expect("valid CONNECT active metric");
        let connect_duration = HistogramVec::new(
            HistogramOpts::new(
                "trust_connect_duration_seconds",
                "CONNECT tunnel duration in seconds by configured upstream.",
            ),
            &["upstream"],
        )
        .expect("valid CONNECT duration metric");
        let connect_bytes = IntCounterVec::new(
            Opts::new(
                "trust_connect_bytes_total",
                "Bytes transferred through CONNECT tunnels by upstream and direction.",
            ),
            &["upstream", "direction"],
        )
        .expect("valid CONNECT bytes metric");
        let forward_proxy_requests = IntCounterVec::new(
            Opts::new(
                "trust_forward_proxy_requests_total",
                "HTTP forward-proxy requests by configured upstream or audit fallback and bounded result.",
            ),
            &["upstream", "result"],
        )
        .expect("valid HTTP forward-proxy requests metric");
        let mitm_handshakes = IntCounterVec::new(
            Opts::new(
                "trust_mitm_handshakes_total",
                "TLS interception handshakes by configured upstream and bounded result.",
            ),
            &["upstream", "result"],
        )
        .expect("valid MITM handshake metric");
        let mitm_certificate_cache = IntCounterVec::new(
            Opts::new(
                "trust_mitm_certificate_cache_total",
                "TLS interception leaf certificate cache outcomes.",
            ),
            &["result"],
        )
        .expect("valid MITM cache metric");
        let mitm_active_connections = IntGaugeVec::new(
            Opts::new(
                "trust_mitm_active_connections",
                "Active TLS-intercepted connections by configured upstream.",
            ),
            &["upstream"],
        )
        .expect("valid MITM active metric");
        let mitm_connection_duration = HistogramVec::new(
            HistogramOpts::new(
                "trust_mitm_connection_duration_seconds",
                "TLS-intercepted connection duration by configured upstream.",
            ),
            &["upstream"],
        )
        .expect("valid MITM connection duration metric");

        registry
            .register(Box::new(requests.clone()))
            .expect("register requests metric");
        registry
            .register(Box::new(request_duration.clone()))
            .expect("register request duration metric");
        registry
            .register(Box::new(rejections.clone()))
            .expect("register rejections metric");
        registry
            .register(Box::new(in_flight.clone()))
            .expect("register in-flight metric");
        registry
            .register(Box::new(credential_resolutions.clone()))
            .expect("register credential resolutions metric");
        registry
            .register(Box::new(credential_resolution_duration.clone()))
            .expect("register credential resolution duration metric");
        registry
            .register(Box::new(connect_attempts.clone()))
            .expect("register CONNECT attempts metric");
        registry
            .register(Box::new(connect_active.clone()))
            .expect("register CONNECT active metric");
        registry
            .register(Box::new(connect_duration.clone()))
            .expect("register CONNECT duration metric");
        registry
            .register(Box::new(connect_bytes.clone()))
            .expect("register CONNECT bytes metric");
        registry
            .register(Box::new(forward_proxy_requests.clone()))
            .expect("register HTTP forward-proxy requests metric");
        registry
            .register(Box::new(mitm_handshakes.clone()))
            .expect("register MITM handshake metric");
        registry
            .register(Box::new(mitm_certificate_cache.clone()))
            .expect("register MITM cache metric");
        registry
            .register(Box::new(mitm_active_connections.clone()))
            .expect("register MITM active metric");
        registry
            .register(Box::new(mitm_connection_duration.clone()))
            .expect("register MITM connection duration metric");

        ProxyMetrics {
            registry,
            requests,
            rejections,
            request_duration,
            in_flight,
            credential_resolutions,
            credential_resolution_duration,
            connect_attempts,
            connect_active,
            connect_duration,
            connect_bytes,
            forward_proxy_requests,
            mitm_handshakes,
            mitm_certificate_cache,
            mitm_active_connections,
            mitm_connection_duration,
        }
    }

    pub fn request_started(&self) {
        self.in_flight.inc();
    }

    pub fn request_finished(&self, upstream: &str, status: u16, elapsed_seconds: f64) {
        let status = status.to_string();
        self.requests.with_label_values(&[upstream, &status]).inc();
        self.request_duration
            .with_label_values(&[upstream])
            .observe(elapsed_seconds);
        self.in_flight.dec();
    }

    pub fn rejection(&self, upstream: &str, reason: &str, status: u16) {
        let status = status.to_string();
        self.rejections
            .with_label_values(&[upstream, reason, &status])
            .inc();
    }

    pub fn request_abandoned(&self) {
        self.in_flight.dec();
    }

    pub fn credential_resolution(
        &self,
        upstream: &str,
        provider: &str,
        result: &str,
        elapsed_seconds: f64,
    ) {
        self.credential_resolutions
            .with_label_values(&[upstream, provider, result])
            .inc();
        self.credential_resolution_duration
            .with_label_values(&[provider])
            .observe(elapsed_seconds);
    }

    pub fn connect_attempt(&self, upstream: &str, result: &str) {
        self.connect_attempts
            .with_label_values(&[upstream, result])
            .inc();
    }

    pub fn connect_started(&self, upstream: &str) {
        self.connect_attempt(upstream, "established");
        self.connect_active.with_label_values(&[upstream]).inc();
    }

    pub fn connect_finished(
        &self,
        upstream: &str,
        elapsed_seconds: f64,
        bytes_to_upstream: u64,
        bytes_to_client: u64,
    ) {
        self.connect_active.with_label_values(&[upstream]).dec();
        self.connect_duration
            .with_label_values(&[upstream])
            .observe(elapsed_seconds);
        self.connect_bytes
            .with_label_values(&[upstream, "to_upstream"])
            .inc_by(bytes_to_upstream);
        self.connect_bytes
            .with_label_values(&[upstream, "to_client"])
            .inc_by(bytes_to_client);
    }

    pub fn forward_proxy_request(&self, upstream: &str, result: &str) {
        self.forward_proxy_requests
            .with_label_values(&[upstream, result])
            .inc();
    }

    pub fn mitm_handshake(&self, upstream: &str, result: &str) {
        self.mitm_handshakes
            .with_label_values(&[upstream, result])
            .inc();
    }

    pub fn mitm_certificate_cache(&self, result: &str) {
        self.mitm_certificate_cache
            .with_label_values(&[result])
            .inc();
    }

    pub fn mitm_connection_started(&self, upstream: &str) {
        self.mitm_active_connections
            .with_label_values(&[upstream])
            .inc();
    }

    pub fn mitm_connection_finished(&self, upstream: &str, elapsed_seconds: f64) {
        self.mitm_active_connections
            .with_label_values(&[upstream])
            .dec();
        self.mitm_connection_duration
            .with_label_values(&[upstream])
            .observe(elapsed_seconds);
    }

    pub fn encode(&self) -> Result<Vec<u8>, prometheus::Error> {
        let encoder = prometheus::TextEncoder::new();
        let families = self.registry.gather();
        let mut output = Vec::new();
        encoder.encode(&families, &mut output)?;
        Ok(output)
    }
}

impl Default for ProxyMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_request_metrics() {
        let metrics = ProxyMetrics::new();
        metrics.request_started();
        metrics.rejection("anthropic", "invalid_token", 401);
        metrics.credential_resolution("anthropic", "static-secret", "static", 0.01);
        metrics.connect_started("docs");
        metrics.connect_finished("docs", 0.5, 12, 34);
        metrics.mitm_handshake("anthropic", "established");
        metrics.mitm_certificate_cache("hit");
        metrics.mitm_connection_started("anthropic");
        metrics.mitm_connection_finished("anthropic", 0.1);
        metrics.request_finished("anthropic", 200, 0.25);

        let output = String::from_utf8(metrics.encode().unwrap()).unwrap();
        assert!(
            output.contains("trust_proxy_requests_total{status=\"200\",upstream=\"anthropic\"} 1")
        );
        assert!(
            output.contains("trust_proxy_request_duration_seconds_count{upstream=\"anthropic\"} 1")
        );
        assert!(output.contains(
            "trust_proxy_rejections_total{reason=\"invalid_token\",status=\"401\",upstream=\"anthropic\"} 1"
        ));
        assert!(output.contains("trust_proxy_in_flight_requests 0"));
        assert!(output.contains(
            "trust_credential_resolutions_total{provider=\"static-secret\",result=\"static\",upstream=\"anthropic\"} 1"
        ));
        assert!(
            output.contains(
                "trust_connect_attempts_total{result=\"established\",upstream=\"docs\"} 1"
            )
        );
        assert!(output.contains("trust_connect_active_tunnels{upstream=\"docs\"} 0"));
        assert!(
            output.contains(
                "trust_connect_bytes_total{direction=\"to_upstream\",upstream=\"docs\"} 12"
            )
        );
        assert!(output.contains(
            "trust_mitm_handshakes_total{result=\"established\",upstream=\"anthropic\"} 1"
        ));
        assert!(output.contains("trust_mitm_certificate_cache_total{result=\"hit\"} 1"));
        assert!(output.contains("trust_mitm_active_connections{upstream=\"anthropic\"} 0"));
        assert!(
            output
                .contains("trust_mitm_connection_duration_seconds_count{upstream=\"anthropic\"} 1")
        );
    }
}
