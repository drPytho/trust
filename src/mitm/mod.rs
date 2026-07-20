use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::Upstream;
use crate::scope::ScopeSet;

pub mod ca;
pub mod io;
pub mod proxy;
pub mod runtime;

/// Authentication and routing information frozen at the successful CONNECT
/// boundary. Decrypted requests must use this context instead of choosing an
/// upstream from their own Host header.
#[derive(Debug, Clone)]
pub struct MitmConnectionContext {
    pub upstream: Arc<Upstream>,
    pub authority_host: String,
    pub authority_port: u16,
    /// Origin addresses resolved and policy-checked at CONNECT time. The
    /// decrypted proxy tries only this frozen set, so it cannot bypass egress
    /// policy or observe a later DNS rebinding result.
    pub upstream_addresses: Vec<SocketAddr>,
    pub subject: String,
    pub scopes: ScopeSet,
    pub expires_at: u64,
}
