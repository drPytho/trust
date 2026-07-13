use prometheus::{Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, Opts, Registry};

/// Prometheus metrics emitted by the proxy request lifecycle.
pub struct ProxyMetrics {
    registry: Registry,
    requests: IntCounterVec,
    rejections: IntCounterVec,
    request_duration: HistogramVec,
    in_flight: IntGauge,
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

        ProxyMetrics {
            registry,
            requests,
            rejections,
            request_duration,
            in_flight,
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
    }
}
