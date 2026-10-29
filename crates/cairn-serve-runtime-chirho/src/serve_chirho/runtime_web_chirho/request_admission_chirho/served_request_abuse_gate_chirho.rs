// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Bounds served execution with process-local source, origin, principal and global admission.
//!
//! Workflow: `spec-chirho/workflows-chirho/served-request-admission-chirho/served-request-admission-workflow-chirho.md`.

use super::served_request_limits_chirho::ServedRequestAbuseLimitsChirho;
use anyhow::{bail, Context, Result};
use axum::http::HeaderMap;
use cairn_write_relay_chirho::{RelayIngressAdmissionChirho, RelayIngressScopeChirho};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const ACTOR_KEY_CONTEXT_CHIRHO: &str = "cairn-served-request-actor-key-v1-chirho";
const NETWORK_ACTOR_DOMAIN_CHIRHO: &[u8] = b"network-actor-chirho";
const PRINCIPAL_ACTOR_DOMAIN_CHIRHO: &[u8] = b"principal-actor-chirho";
const UNKNOWN_NETWORK_CHIRHO: &[u8] = b"unknown-network-chirho";
const X_FORWARDED_FOR_CHIRHO: &str = "x-forwarded-for";

#[path = "served_request_abuse_gate_chirho/ingress_chirho.rs"]
mod ingress_chirho;
pub(super) use ingress_chirho::ServedIngressAdmissionChirho;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct ServedRequestActorKeyChirho([u8; 32]);

#[derive(Clone, Copy)]
struct ServedRequestChargeChirho {
    at_ms_chirho: u64,
    body_bytes_chirho: u64,
}

#[derive(Default)]
struct ServedRequestBucketChirho {
    charges_chirho: VecDeque<ServedRequestChargeChirho>,
}

#[derive(Default)]
struct ServedRequestAbuseStateChirho {
    actor_buckets_chirho: HashMap<ServedRequestActorKeyChirho, ServedRequestBucketChirho>,
    global_bucket_chirho: ServedRequestBucketChirho,
    last_now_ms_chirho: u64,
}

pub(super) struct ServedDagAdmissionChirho {
    inflight_permit_chirho: Arc<OwnedSemaphorePermit>,
    gate_identity_chirho: Arc<()>,
    ingress_assertion_chirho: RelayIngressAdmissionChirho,
}

pub(super) struct ServedRequestAbuseGateChirho {
    limits_chirho: ServedRequestAbuseLimitsChirho,
    started_chirho: Instant,
    state_chirho: Mutex<ServedRequestAbuseStateChirho>,
    identity_chirho: Arc<()>,
    relay_scope_chirho: Option<RelayIngressScopeChirho>,
}

impl ServedRequestAbuseGateChirho {
    /// The refusal's ONE Retry-After (R13 Part 8, PFE #26153, #26154): the rolling window's whole seconds, rounded up.
    /// Every refusal clears within one window, the caps sooner, so it is an honest upper bound and the same for every
    /// reason; it says nothing about which limit fired.
    pub(super) fn retry_after_secs_chirho(&self) -> u64 {
        self.limits_chirho.window_ms_chirho.div_ceil(1000)
    }

    pub(super) fn new_chirho(limits_chirho: ServedRequestAbuseLimitsChirho) -> Result<Self> {
        limits_chirho.validate_chirho()?;
        Ok(Self {
            limits_chirho,
            started_chirho: Instant::now(),
            state_chirho: Mutex::new(ServedRequestAbuseStateChirho::default()),
            identity_chirho: Arc::new(()),
            relay_scope_chirho: None,
        })
    }

    pub(super) fn admit_chirho(
        &self,
        inflight_chirho: Arc<Semaphore>,
        peer_chirho: Option<SocketAddr>,
        headers_chirho: &HeaderMap,
        principal_chirho: Option<&str>,
        body_bytes_chirho: usize,
    ) -> Result<ServedDagAdmissionChirho> {
        let ingress_chirho = self.admit_ingress_chirho(
            inflight_chirho,
            peer_chirho,
            headers_chirho,
            body_bytes_chirho,
        )?;
        self.promote_ingress_chirho(ingress_chirho, principal_chirho)
    }

    #[cfg(test)]
    fn admit_at_chirho(
        &self,
        inflight_chirho: Arc<Semaphore>,
        peer_chirho: Option<SocketAddr>,
        headers_chirho: &HeaderMap,
        principal_chirho: Option<&str>,
        body_bytes_chirho: usize,
        now_ms_chirho: u64,
    ) -> Result<ServedDagAdmissionChirho> {
        let ingress_chirho = self.admit_ingress_at_chirho(
            inflight_chirho,
            peer_chirho,
            headers_chirho,
            body_bytes_chirho,
            now_ms_chirho,
        )?;
        self.promote_ingress_at_chirho(ingress_chirho, principal_chirho, now_ms_chirho)
    }

    #[cfg(test)]
    pub(super) fn admit_for_test_chirho(
        &self,
        inflight_chirho: Arc<Semaphore>,
        peer_chirho: Option<SocketAddr>,
        headers_chirho: &HeaderMap,
        principal_chirho: Option<&str>,
        body_bytes_chirho: usize,
        now_ms_chirho: u64,
    ) -> Result<ServedDagAdmissionChirho> {
        self.admit_at_chirho(
            inflight_chirho,
            peer_chirho,
            headers_chirho,
            principal_chirho,
            body_bytes_chirho,
            now_ms_chirho,
        )
    }

    #[cfg(test)]
    pub(super) fn actor_bucket_count_for_test_chirho(&self) -> usize {
        self.state_chirho
            .lock()
            .map(|state_chirho| state_chirho.actor_buckets_chirho.len())
            .unwrap_or(usize::MAX)
    }
}

fn ensure_new_bucket_can_admit_chirho(
    max_requests_chirho: u64,
    max_body_bytes_chirho: u64,
    next_body_bytes_chirho: u64,
) -> Result<()> {
    if max_requests_chirho < 1 || next_body_bytes_chirho > max_body_bytes_chirho {
        bail!("served request actor quota exceeded");
    }
    Ok(())
}

fn ensure_bucket_can_admit_chirho(
    bucket_chirho: &ServedRequestBucketChirho,
    max_requests_chirho: u64,
    max_body_bytes_chirho: u64,
    next_body_bytes_chirho: u64,
) -> Result<()> {
    let requests_chirho = u64::try_from(bucket_chirho.charges_chirho.len()).unwrap_or(u64::MAX);
    let body_bytes_chirho = bucket_chirho
        .charges_chirho
        .iter()
        .fold(0_u64, |sum_chirho, charge_chirho| {
            sum_chirho.saturating_add(charge_chirho.body_bytes_chirho)
        });
    if requests_chirho >= max_requests_chirho
        || body_bytes_chirho.saturating_add(next_body_bytes_chirho) > max_body_bytes_chirho
    {
        bail!("served request quota exceeded");
    }
    Ok(())
}

fn prune_state_chirho(
    state_chirho: &mut ServedRequestAbuseStateChirho,
    limits_chirho: &ServedRequestAbuseLimitsChirho,
    now_ms_chirho: u64,
) {
    prune_bucket_chirho(
        &mut state_chirho.global_bucket_chirho,
        limits_chirho.window_ms_chirho,
        now_ms_chirho,
    );
    state_chirho
        .actor_buckets_chirho
        .retain(|_actor_key_chirho, bucket_chirho| {
            prune_bucket_chirho(bucket_chirho, limits_chirho.window_ms_chirho, now_ms_chirho);
            !bucket_chirho.charges_chirho.is_empty()
        });
}

fn prune_bucket_chirho(
    bucket_chirho: &mut ServedRequestBucketChirho,
    window_ms_chirho: u64,
    now_ms_chirho: u64,
) {
    while bucket_chirho
        .charges_chirho
        .front()
        .is_some_and(|charge_chirho| {
            now_ms_chirho.saturating_sub(charge_chirho.at_ms_chirho) >= window_ms_chirho
        })
    {
        bucket_chirho.charges_chirho.pop_front();
    }
}

/// The normalized client network a request comes from, as a keyed hash: the peer address, with X-Forwarded-For
/// trusted only behind a loopback proxy. Shared with the sign-in gate, so both agree on what a source is.
pub(super) fn served_network_actor_key_chirho(
    peer_chirho: Option<SocketAddr>,
    headers_chirho: &HeaderMap,
) -> ServedRequestActorKeyChirho {
    let normalized_chirho = match peer_chirho {
        Some(peer_chirho) if !peer_chirho.ip().is_loopback() => {
            normalized_ip_bytes_chirho(peer_chirho.ip())
        }
        Some(_loopback_chirho) => forwarded_client_ip_chirho(headers_chirho)
            .map(normalized_ip_bytes_chirho)
            .unwrap_or_else(|| UNKNOWN_NETWORK_CHIRHO.to_vec()),
        None => UNKNOWN_NETWORK_CHIRHO.to_vec(),
    };
    domain_actor_key_chirho(NETWORK_ACTOR_DOMAIN_CHIRHO, &normalized_chirho)
}

fn served_principal_actor_key_chirho(principal_chirho: &str) -> ServedRequestActorKeyChirho {
    domain_actor_key_chirho(PRINCIPAL_ACTOR_DOMAIN_CHIRHO, principal_chirho.as_bytes())
}

fn domain_actor_key_chirho(
    domain_chirho: &[u8],
    value_chirho: &[u8],
) -> ServedRequestActorKeyChirho {
    let mut hasher_chirho = blake3::Hasher::new_derive_key(ACTOR_KEY_CONTEXT_CHIRHO);
    hasher_chirho.update(domain_chirho);
    hasher_chirho.update(&[0]);
    hasher_chirho.update(value_chirho);
    ServedRequestActorKeyChirho(*hasher_chirho.finalize().as_bytes())
}

fn forwarded_client_ip_chirho(headers_chirho: &HeaderMap) -> Option<IpAddr> {
    headers_chirho
        .get(X_FORWARDED_FOR_CHIRHO)
        .and_then(|value_chirho| value_chirho.to_str().ok())
        .and_then(|value_chirho| value_chirho.split(',').next())
        .map(str::trim)
        .filter(|value_chirho| !value_chirho.is_empty())
        .and_then(|value_chirho| value_chirho.parse::<IpAddr>().ok())
}

fn normalized_ip_bytes_chirho(ip_chirho: IpAddr) -> Vec<u8> {
    match ip_chirho {
        IpAddr::V4(ipv4_chirho) => {
            let mut bytes_chirho = b"ipv4-chirho".to_vec();
            bytes_chirho.extend_from_slice(&ipv4_chirho.octets());
            bytes_chirho
        }
        IpAddr::V6(ipv6_chirho) => match ipv6_chirho.to_ipv4_mapped() {
            Some(ipv4_chirho) => normalized_ip_bytes_chirho(IpAddr::V4(ipv4_chirho)),
            None => {
                let mut network_chirho = ipv6_chirho.octets();
                network_chirho[8..].fill(0);
                let normalized_chirho = Ipv6Addr::from(network_chirho);
                let mut bytes_chirho = b"ipv6-64-chirho".to_vec();
                bytes_chirho.extend_from_slice(&normalized_chirho.octets());
                bytes_chirho
            }
        },
    }
}

#[cfg(test)]
pub(super) fn served_network_keys_match_for_test_chirho(
    first_peer_chirho: Option<SocketAddr>,
    first_headers_chirho: &HeaderMap,
    second_peer_chirho: Option<SocketAddr>,
    second_headers_chirho: &HeaderMap,
) -> bool {
    served_network_actor_key_chirho(first_peer_chirho, first_headers_chirho)
        == served_network_actor_key_chirho(second_peer_chirho, second_headers_chirho)
}

#[cfg(test)]
#[path = "served_request_abuse_gate_tests_chirho.rs"]
mod served_request_abuse_gate_tests_chirho;

#[cfg(test)]
#[path = "served_request_abuse_gate_chirho/ingress_tests_chirho.rs"]
mod ingress_tests_chirho;
