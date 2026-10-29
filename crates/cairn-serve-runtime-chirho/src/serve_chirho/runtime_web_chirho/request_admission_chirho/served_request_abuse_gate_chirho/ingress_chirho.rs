// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Keeps ingress rate charges and affine permit custody through forwarding and principal admission.
//!
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/write-forwarding-chirho/relay-admission-chirho/f1-ingress-design-chirho.md`.

use super::*;
use cairn_write_relay_chirho::VerifiedServedWriteRelayRequestChirho;

const ORIGIN_ACTOR_DOMAIN_CHIRHO: &[u8] = b"verified-relay-origin-chirho";

pub(in crate::serve_chirho) struct ServedIngressAdmissionChirho {
    admission_chirho: ServedDagAdmissionChirho,
    body_bytes_chirho: u64,
}

impl ServedDagAdmissionChirho {
    pub(in crate::serve_chirho) fn ingress_assertion_chirho(&self) -> RelayIngressAdmissionChirho {
        self.ingress_assertion_chirho
    }

    pub(in crate::serve_chirho) fn retain_for_dispatch_chirho(&self) -> Arc<OwnedSemaphorePermit> {
        Arc::clone(&self.inflight_permit_chirho)
    }
}

impl ServedIngressAdmissionChirho {
    pub(in crate::serve_chirho) fn ingress_assertion_chirho(&self) -> RelayIngressAdmissionChirho {
        self.admission_chirho.ingress_assertion_chirho()
    }

    pub(in crate::serve_chirho) fn retain_for_dispatch_chirho(&self) -> Arc<OwnedSemaphorePermit> {
        self.admission_chirho.retain_for_dispatch_chirho()
    }
}

impl ServedRequestAbuseGateChirho {
    pub(in crate::serve_chirho) fn with_relay_scope_chirho(
        limits_chirho: ServedRequestAbuseLimitsChirho,
        relay_scope_chirho: Option<RelayIngressScopeChirho>,
    ) -> Result<Self> {
        let mut gate_chirho = Self::new_chirho(limits_chirho)?;
        gate_chirho.relay_scope_chirho = relay_scope_chirho;
        gate_chirho.ingress_assertion_chirho()?;
        Ok(gate_chirho)
    }

    fn now_ms_chirho(&self) -> u64 {
        u64::try_from(self.started_chirho.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn ingress_assertion_chirho(&self) -> Result<RelayIngressAdmissionChirho> {
        let origins_chirho = self
            .relay_scope_chirho
            .as_ref()
            .map_or(1, RelayIngressScopeChirho::origin_count_chirho);
        RelayIngressAdmissionChirho::new_chirho(
            self.limits_chirho.window_ms_chirho,
            self.limits_chirho.actor_max_requests_chirho,
            self.limits_chirho.actor_max_body_bytes_chirho,
            self.limits_chirho.global_max_requests_chirho / origins_chirho,
            self.limits_chirho.global_max_body_bytes_chirho / origins_chirho,
        )
        .map_err(anyhow::Error::from)
    }

    pub(in crate::serve_chirho) fn admit_ingress_chirho(
        &self,
        inflight_chirho: Arc<Semaphore>,
        peer_chirho: Option<SocketAddr>,
        headers_chirho: &HeaderMap,
        body_bytes_chirho: usize,
    ) -> Result<ServedIngressAdmissionChirho> {
        self.admit_ingress_at_chirho(
            inflight_chirho,
            peer_chirho,
            headers_chirho,
            body_bytes_chirho,
            self.now_ms_chirho(),
        )
    }

    pub(super) fn admit_ingress_at_chirho(
        &self,
        inflight_chirho: Arc<Semaphore>,
        peer_chirho: Option<SocketAddr>,
        headers_chirho: &HeaderMap,
        body_bytes_chirho: usize,
        now_ms_chirho: u64,
    ) -> Result<ServedIngressAdmissionChirho> {
        let permit_chirho = inflight_chirho
            .try_acquire_owned()
            .context("served DAG in-flight limit reached")?;
        let body_bytes_chirho =
            u64::try_from(body_bytes_chirho).context("served body length exceeds u64")?;
        let assertion_chirho = self.ingress_assertion_chirho()?;
        let mut keys_chirho = vec![(
            served_network_actor_key_chirho(peer_chirho, headers_chirho),
            self.limits_chirho.actor_max_requests_chirho,
            self.limits_chirho.actor_max_body_bytes_chirho,
        )];
        if let Some(scope_chirho) = &self.relay_scope_chirho {
            keys_chirho.push((
                origin_key_chirho(scope_chirho.local_node_id_chirho()),
                assertion_chirho.ingress_max_requests_chirho(),
                assertion_chirho.ingress_max_body_bytes_chirho(),
            ));
        }
        self.charge_at_chirho(&keys_chirho, true, body_bytes_chirho, now_ms_chirho)?;
        Ok(self.ingress_custody_chirho(permit_chirho, assertion_chirho, body_bytes_chirho))
    }

    pub(in crate::serve_chirho) fn accepts_relay_ingress_chirho(
        &self,
        request_chirho: &VerifiedServedWriteRelayRequestChirho,
    ) -> bool {
        let (Some(scope_chirho), Some(assertion_chirho)) = (
            self.relay_scope_chirho.as_ref(),
            request_chirho.ingress_admission_chirho(),
        ) else {
            return false;
        };
        scope_chirho.accepts_request_chirho(request_chirho)
            && self.ingress_assertion_chirho().is_ok_and(|owner_chirho| {
                assertion_chirho.permits_source_policy_chirho(&owner_chirho)
            })
    }

    pub(in crate::serve_chirho) fn admit_relay_ingress_chirho(
        &self,
        inflight_chirho: Arc<Semaphore>,
        request_chirho: &VerifiedServedWriteRelayRequestChirho,
    ) -> Result<ServedIngressAdmissionChirho> {
        if !self.accepts_relay_ingress_chirho(request_chirho) {
            bail!("relay ingress scope or policy mismatch");
        }
        let permit_chirho = inflight_chirho
            .try_acquire_owned()
            .context("served DAG in-flight limit reached")?;
        let body_bytes_chirho = u64::try_from(request_chirho.body_chirho().len())
            .context("served body length exceeds u64")?;
        let assertion_chirho = self.ingress_assertion_chirho()?;
        let remote_chirho = request_chirho
            .ingress_admission_chirho()
            .expect("checked signed assertion");
        let keys_chirho = [(
            origin_key_chirho(request_chirho.origin_node_id_chirho()),
            assertion_chirho
                .ingress_max_requests_chirho()
                .min(remote_chirho.ingress_max_requests_chirho()),
            assertion_chirho
                .ingress_max_body_bytes_chirho()
                .min(remote_chirho.ingress_max_body_bytes_chirho()),
        )];
        self.charge_at_chirho(&keys_chirho, true, body_bytes_chirho, self.now_ms_chirho())?;
        Ok(self.ingress_custody_chirho(permit_chirho, assertion_chirho, body_bytes_chirho))
    }

    fn ingress_custody_chirho(
        &self,
        permit_chirho: OwnedSemaphorePermit,
        assertion_chirho: RelayIngressAdmissionChirho,
        body_bytes_chirho: u64,
    ) -> ServedIngressAdmissionChirho {
        ServedIngressAdmissionChirho {
            admission_chirho: ServedDagAdmissionChirho {
                inflight_permit_chirho: Arc::new(permit_chirho),
                gate_identity_chirho: Arc::clone(&self.identity_chirho),
                ingress_assertion_chirho: assertion_chirho,
            },
            body_bytes_chirho,
        }
    }

    pub(in crate::serve_chirho) fn promote_ingress_chirho(
        &self,
        ingress_chirho: ServedIngressAdmissionChirho,
        principal_chirho: Option<&str>,
    ) -> Result<ServedDagAdmissionChirho> {
        self.promote_ingress_at_chirho(ingress_chirho, principal_chirho, self.now_ms_chirho())
    }

    pub(super) fn promote_ingress_at_chirho(
        &self,
        ingress_chirho: ServedIngressAdmissionChirho,
        principal_chirho: Option<&str>,
        now_ms_chirho: u64,
    ) -> Result<ServedDagAdmissionChirho> {
        if !Arc::ptr_eq(
            &self.identity_chirho,
            &ingress_chirho.admission_chirho.gate_identity_chirho,
        ) {
            bail!("ingress admission belongs to another abuse gate");
        }
        let keys_chirho = principal_chirho.map(|principal_chirho| {
            (
                served_principal_actor_key_chirho(principal_chirho),
                self.limits_chirho.actor_max_requests_chirho,
                self.limits_chirho.actor_max_body_bytes_chirho,
            )
        });
        self.charge_at_chirho(
            &keys_chirho.into_iter().collect::<Vec<_>>(),
            false,
            ingress_chirho.body_bytes_chirho,
            now_ms_chirho,
        )?;
        Ok(ingress_chirho.admission_chirho)
    }

    fn charge_at_chirho(
        &self,
        keys_chirho: &[(ServedRequestActorKeyChirho, u64, u64)],
        global_chirho: bool,
        body_bytes_chirho: u64,
        now_ms_chirho: u64,
    ) -> Result<()> {
        let mut state_chirho = self
            .state_chirho
            .lock()
            .map_err(|_| anyhow::anyhow!("served request abuse gate lock poisoned"))?;
        if now_ms_chirho < state_chirho.last_now_ms_chirho {
            bail!("served request monotonic clock moved backwards");
        }
        state_chirho.last_now_ms_chirho = now_ms_chirho;
        prune_state_chirho(&mut state_chirho, &self.limits_chirho, now_ms_chirho);
        let new_keys_chirho = keys_chirho
            .iter()
            .filter(|(key_chirho, _, _)| {
                !state_chirho.actor_buckets_chirho.contains_key(key_chirho)
            })
            .count();
        if state_chirho
            .actor_buckets_chirho
            .len()
            .saturating_add(new_keys_chirho)
            > self.limits_chirho.actor_bucket_cap_chirho
        {
            bail!("served request actor bucket capacity reached");
        }
        if global_chirho {
            ensure_bucket_can_admit_chirho(
                &state_chirho.global_bucket_chirho,
                self.limits_chirho.global_max_requests_chirho,
                self.limits_chirho.global_max_body_bytes_chirho,
                body_bytes_chirho,
            )?;
        }
        for (key_chirho, requests_chirho, bytes_chirho) in keys_chirho {
            if let Some(bucket_chirho) = state_chirho.actor_buckets_chirho.get(key_chirho) {
                ensure_bucket_can_admit_chirho(
                    bucket_chirho,
                    *requests_chirho,
                    *bytes_chirho,
                    body_bytes_chirho,
                )?;
            } else {
                ensure_new_bucket_can_admit_chirho(
                    *requests_chirho,
                    *bytes_chirho,
                    body_bytes_chirho,
                )?;
            }
        }
        let charge_chirho = ServedRequestChargeChirho {
            at_ms_chirho: now_ms_chirho,
            body_bytes_chirho,
        };
        if global_chirho {
            state_chirho
                .global_bucket_chirho
                .charges_chirho
                .push_back(charge_chirho);
        }
        for (key_chirho, _, _) in keys_chirho {
            state_chirho
                .actor_buckets_chirho
                .entry(*key_chirho)
                .or_default()
                .charges_chirho
                .push_back(charge_chirho);
        }
        Ok(())
    }
}

fn origin_key_chirho(node_id_chirho: &str) -> ServedRequestActorKeyChirho {
    let mut material_chirho =
        Vec::with_capacity(ORIGIN_ACTOR_DOMAIN_CHIRHO.len() + node_id_chirho.len());
    material_chirho.extend_from_slice(ORIGIN_ACTOR_DOMAIN_CHIRHO);
    material_chirho.extend_from_slice(node_id_chirho.as_bytes());
    ServedRequestActorKeyChirho(blake3::derive_key(
        ACTOR_KEY_CONTEXT_CHIRHO,
        &material_chirho,
    ))
}
