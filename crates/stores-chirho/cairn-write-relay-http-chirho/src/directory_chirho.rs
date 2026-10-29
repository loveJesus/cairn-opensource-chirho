// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use anyhow::{bail, Result};
use cairn_roster_config_chirho::{VerifiedActiveRelayMeshChirho, ELECTOR_PORT_CHIRHO};
use cairn_write_relay_chirho::{
    PreparedServedWriteRelayAttemptChirho, RelayContractErrorChirho, RelayRosterChirho,
    RelayTransportFailureChirho, ServedWriteRelayFailureChirho,
};
use cairn_writer_elector_chirho::elector_port_chirho::LeadershipChirho;
use cairn_writer_elector_chirho::monotonic_clock_chirho::{
    lease_deadline_from_remaining_chirho, lease_deadline_is_live_chirho, MonotonicClockChirho,
};
use cairn_writer_elector_http_chirho::discover_leader_chirho;
use std::collections::BTreeMap;
#[cfg(test)]
use std::net::IpAddr;
use std::num::NonZeroU64;
use std::sync::Arc;
#[cfg(test)]
use url::Url;

#[cfg(test)]
const RELAY_DIRECTORY_MAX_ENDPOINTS_CHIRHO: usize = 64;

pub trait FixedGroupLeadershipViewChirho: Send + Sync {
    fn current_leadership_chirho(&self) -> LeadershipChirho;
}

#[derive(Clone)]
struct FixedRelayEndpointChirho {
    base_url_chirho: String,
}

impl FixedRelayEndpointChirho {
    #[cfg(test)]
    fn try_new_chirho(base_url_chirho: String) -> Result<Self> {
        let parsed_chirho = Url::parse(&base_url_chirho)?;
        if parsed_chirho.scheme() != "http"
            || !parsed_chirho.username().is_empty()
            || parsed_chirho.password().is_some()
            || parsed_chirho.port().is_none()
            || parsed_chirho.query().is_some()
            || parsed_chirho.fragment().is_some()
            || !matches!(parsed_chirho.path(), "" | "/")
        {
            bail!(
                "relay endpoint must be a credential-free fixed http origin with an explicit port"
            );
        }
        let address_chirho: IpAddr = parsed_chirho
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("relay endpoint is missing a host"))?
            .parse()
            .map_err(|_| anyhow::anyhow!("relay endpoint host must be a literal IP address"))?;
        if !private_mesh_address_chirho(address_chirho) {
            bail!("relay endpoint IP must be loopback or private-mesh scoped");
        }
        Ok(Self {
            base_url_chirho: parsed_chirho.as_str().trim_end_matches('/').to_string(),
        })
    }
}

#[cfg(test)]
fn private_mesh_address_chirho(address_chirho: IpAddr) -> bool {
    match address_chirho {
        IpAddr::V4(address_chirho) => address_chirho.is_loopback() || address_chirho.is_private(),
        IpAddr::V6(address_chirho) => {
            address_chirho.is_loopback() || (address_chirho.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

pub(crate) fn valid_group_digest_chirho(group_digest_chirho: &str) -> bool {
    group_digest_chirho.len() == 64
        && group_digest_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
}

pub struct ResolvedRelayOwnerChirho {
    node_id_chirho: String,
    base_url_chirho: String,
    term_chirho: u64,
    lease_deadline_millis_chirho: u64,
}

impl ResolvedRelayOwnerChirho {
    pub fn node_id_chirho(&self) -> &str {
        &self.node_id_chirho
    }

    pub fn base_url_chirho(&self) -> &str {
        &self.base_url_chirho
    }

    pub fn term_chirho(&self) -> u64 {
        self.term_chirho
    }
}

pub struct FixedRelayDirectoryChirho {
    group_digest_chirho: String,
    leadership_chirho: Arc<dyn FixedGroupLeadershipViewChirho>,
    endpoints_chirho: BTreeMap<String, FixedRelayEndpointChirho>,
    clock_chirho: Arc<dyn MonotonicClockChirho>,
    transit_budget_millis_chirho: NonZeroU64,
}

impl FixedRelayDirectoryChirho {
    /// R2-2 deliberately has no production constructor. A literal private IP does not prove that
    /// request secrets cross an authenticated encrypted peer link. R2-3 must add a constructor that
    /// consumes opaque operator-signed roster/WireGuard evidence before this directory can enter a
    /// served composition.
    #[cfg(test)]
    pub(crate) fn new_for_test_chirho(
        group_digest_chirho: String,
        leadership_chirho: Arc<dyn FixedGroupLeadershipViewChirho>,
        endpoint_urls_chirho: BTreeMap<String, String>,
        roster_chirho: &RelayRosterChirho,
        clock_chirho: Arc<dyn MonotonicClockChirho>,
        transit_budget_millis_chirho: NonZeroU64,
    ) -> Result<Self> {
        if !valid_group_digest_chirho(&group_digest_chirho) {
            bail!("relay consistency-group digest must be canonical lowercase BLAKE3 hex");
        }
        if endpoint_urls_chirho.is_empty()
            || endpoint_urls_chirho.len() > RELAY_DIRECTORY_MAX_ENDPOINTS_CHIRHO
        {
            bail!("relay endpoint directory is empty or exceeds its fixed bound");
        }
        let mut endpoints_chirho = BTreeMap::new();
        for (node_id_chirho, endpoint_chirho) in endpoint_urls_chirho {
            if !roster_chirho.contains_chirho(&node_id_chirho) {
                bail!("relay endpoint directory contains a node outside the exact roster");
            }
            endpoints_chirho.insert(
                node_id_chirho,
                FixedRelayEndpointChirho::try_new_chirho(endpoint_chirho)?,
            );
        }
        Ok(Self {
            group_digest_chirho,
            leadership_chirho,
            endpoints_chirho,
            clock_chirho,
            transit_budget_millis_chirho,
        })
    }

    /// Build the production directory only from the complete operator-signed roster joined to an
    /// active local WireGuard interface. Literal-IP parsing remains test-only.
    pub fn new_from_verified_active_mesh_chirho(
        group_digest_chirho: String,
        leadership_chirho: Arc<dyn FixedGroupLeadershipViewChirho>,
        verified_mesh_chirho: &VerifiedActiveRelayMeshChirho,
        clock_chirho: Arc<dyn MonotonicClockChirho>,
        transit_budget_millis_chirho: NonZeroU64,
    ) -> Result<(Self, RelayRosterChirho)> {
        if !valid_group_digest_chirho(&group_digest_chirho) {
            bail!("relay consistency-group digest must be canonical lowercase BLAKE3 hex");
        }
        let roster_chirho = RelayRosterChirho::new_chirho(
            verified_mesh_chirho
                .members_chirho()
                .iter()
                .map(|member_chirho| member_chirho.node_id_chirho().to_string()),
        )
        .map_err(anyhow::Error::from)?;
        let endpoints_chirho = verified_mesh_chirho
            .members_chirho()
            .iter()
            .map(|member_chirho| {
                let address_chirho = member_chirho.mesh_ip_chirho();
                let host_chirho = match address_chirho {
                    std::net::IpAddr::V4(address_chirho) => address_chirho.to_string(),
                    std::net::IpAddr::V6(address_chirho) => format!("[{address_chirho}]"),
                };
                (
                    member_chirho.node_id_chirho().to_string(),
                    FixedRelayEndpointChirho {
                        base_url_chirho: format!("http://{host_chirho}:{ELECTOR_PORT_CHIRHO}"),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        if endpoints_chirho.len() != verified_mesh_chirho.members_chirho().len() {
            bail!("verified relay mesh contains duplicate node identities");
        }
        Ok((
            Self {
                group_digest_chirho,
                leadership_chirho,
                endpoints_chirho,
                clock_chirho,
                transit_budget_millis_chirho,
            },
            roster_chirho,
        ))
    }

    pub(crate) fn resolve_chirho(
        &self,
        attempt_chirho: &PreparedServedWriteRelayAttemptChirho,
        agent_chirho: &ureq::Agent,
    ) -> Result<ResolvedRelayOwnerChirho, ServedWriteRelayFailureChirho> {
        let first_view_chirho = self.leadership_chirho.current_leadership_chirho();
        let owner_chirho = first_view_chirho
            .leader_id_chirho
            .ok_or_else(RelayContractErrorChirho::owner_unknown_chirho)?;
        attempt_chirho.require_resolution_chirho(
            &self.group_digest_chirho,
            &owner_chirho.0,
            first_view_chirho.term_chirho,
        )?;
        let endpoint_chirho = self
            .endpoints_chirho
            .get(&owner_chirho.0)
            .ok_or_else(RelayContractErrorChirho::owner_unroutable_chirho)?;
        let leader_info_chirho =
            discover_leader_chirho(agent_chirho, &endpoint_chirho.base_url_chirho)
                .map_err(|_| RelayTransportFailureChirho::owner_unavailable_before_send_chirho())?;
        if !leader_info_chirho.is_local_leader_chirho
            || leader_info_chirho.leader_node_id_chirho.as_deref() != Some(owner_chirho.0.as_str())
            || leader_info_chirho.term_chirho != attempt_chirho.expected_term_chirho()
        {
            return Err(RelayContractErrorChirho::owner_term_changed_chirho().into());
        }
        let lease_deadline_millis_chirho = lease_deadline_from_remaining_chirho(
            self.clock_chirho.as_ref(),
            leader_info_chirho.lease_remaining_millis_chirho,
            self.transit_budget_millis_chirho,
        )
        .ok_or_else(RelayContractErrorChirho::lease_expired_chirho)?;
        if !lease_deadline_is_live_chirho(
            self.clock_chirho.as_ref(),
            Some(lease_deadline_millis_chirho),
        ) {
            return Err(RelayContractErrorChirho::lease_expired_chirho().into());
        }
        let second_view_chirho = self.leadership_chirho.current_leadership_chirho();
        if second_view_chirho.leader_id_chirho.as_ref() != Some(&owner_chirho)
            || second_view_chirho.term_chirho != attempt_chirho.expected_term_chirho()
        {
            return Err(RelayContractErrorChirho::owner_term_changed_chirho().into());
        }
        Ok(ResolvedRelayOwnerChirho {
            node_id_chirho: owner_chirho.0,
            base_url_chirho: endpoint_chirho.base_url_chirho.clone(),
            term_chirho: attempt_chirho.expected_term_chirho(),
            lease_deadline_millis_chirho,
        })
    }

    pub(crate) fn resolution_is_live_chirho(
        &self,
        resolution_chirho: &ResolvedRelayOwnerChirho,
    ) -> bool {
        lease_deadline_is_live_chirho(
            self.clock_chirho.as_ref(),
            Some(resolution_chirho.lease_deadline_millis_chirho),
        )
    }
}
