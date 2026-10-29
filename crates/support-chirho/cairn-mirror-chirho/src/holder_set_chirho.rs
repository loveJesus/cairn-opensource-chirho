// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Exact three-region holder selection over verified placement. The elected leader stores locally and
//! both other placement-assigned serving voters must durably mirror. Placement chooses candidates;
//! residency retains an independent veto over every selected failure domain.

use crate::membership_chirho::{MirrorHolderChirho, MirrorMembershipViewChirho};
use crate::refusal_chirho::MirrorContractErrorChirho;
use cairn_placement_chirho::failure_domain_chirho::FailureDomainChirho;
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MirrorResidencyPolicyChirho {
    AnyDomainChirho,
    AllowedDomainsChirho(BTreeSet<FailureDomainChirho>),
}

impl MirrorResidencyPolicyChirho {
    pub fn allowed_domains_chirho(
        domains_chirho: impl IntoIterator<Item = FailureDomainChirho>,
    ) -> Self {
        Self::AllowedDomainsChirho(domains_chirho.into_iter().collect())
    }

    fn allows_chirho(&self, domain_chirho: &FailureDomainChirho) -> bool {
        match self {
            Self::AnyDomainChirho => true,
            Self::AllowedDomainsChirho(allowed_chirho) => allowed_chirho.contains(domain_chirho),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MirrorHolderSetChirho {
    leader_chirho: MirrorHolderChirho,
    peer_holders_chirho: [MirrorHolderChirho; 2],
}

impl MirrorHolderSetChirho {
    pub fn select_chirho(
        view_chirho: &MirrorMembershipViewChirho,
        leader_node_id_chirho: &str,
        residency_chirho: &MirrorResidencyPolicyChirho,
    ) -> Result<Self, MirrorContractErrorChirho> {
        if view_chirho.holders_chirho().len() != 3 {
            return Err(MirrorContractErrorChirho::holder_set_unsatisfiable_chirho());
        }
        let leader_chirho = view_chirho
            .holder_chirho(leader_node_id_chirho)
            .ok_or_else(MirrorContractErrorChirho::holder_set_unsatisfiable_chirho)?
            .clone();
        if view_chirho.holders_chirho().iter().any(|holder_chirho| {
            !residency_chirho.allows_chirho(holder_chirho.failure_domain_chirho())
        }) {
            return Err(MirrorContractErrorChirho::residency_veto_chirho());
        }
        let distinct_domains_chirho = view_chirho
            .holders_chirho()
            .iter()
            .map(|holder_chirho| holder_chirho.failure_domain_chirho().clone())
            .collect::<BTreeSet<_>>();
        if distinct_domains_chirho.len() != 3 {
            return Err(MirrorContractErrorChirho::region_spread_unsatisfied_chirho());
        }
        let peer_holders_chirho: [MirrorHolderChirho; 2] = view_chirho
            .holders_chirho()
            .iter()
            .filter(|holder_chirho| holder_chirho.node_id_chirho() != leader_node_id_chirho)
            .cloned()
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| MirrorContractErrorChirho::holder_set_unsatisfiable_chirho())?;
        Ok(Self {
            leader_chirho,
            peer_holders_chirho,
        })
    }

    pub fn leader_chirho(&self) -> &MirrorHolderChirho {
        &self.leader_chirho
    }

    pub fn mirror_holders_chirho(&self) -> [&MirrorHolderChirho; 2] {
        [&self.peer_holders_chirho[0], &self.peer_holders_chirho[1]]
    }
}
