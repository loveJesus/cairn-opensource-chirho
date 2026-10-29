// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Provider and region are separate failure-domain axes, and spread is counted in DISTINCT domains.
//!
//! CF8 acceptance, verbatim: *"provider and region are typed failure-domain coordinates with a
//! minimum-domain spread constraint."*
//!
//! **Why provider and region are counted separately, and not blended.** Three regions at one provider
//! looks like spread three and is spread one against a provider-wide failure — a billing
//! suspension, a control-plane outage, an account action. Cairn learned this concretely: a two-zone
//! topology did not survive the loss of a single provider's region, which is why a third zone was
//! placed on a *different* box rather than a second region of the same provider. So the two axes are
//! checked independently and a shortfall in either refuses; there is no combined "diversity score"
//! that a provider-correlated layout could satisfy.
//!
//! **Spread counts DOMAINS, not replicas.** Five copies in one region is spread one. Counting
//! replicas would let a layout satisfy a spread requirement by growing inside a single failure
//! domain, which is precisely the arrangement the requirement exists to prevent.
//!
//! Pure: no I/O, no provider APIs, no network probing. A coordinate is whatever the caller declares —
//! CF8 explicitly does not claim live provider APIs, so nothing here tries to discover topology.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Where one placement physically sits. Typed rather than a bare string pair so the two axes cannot
/// be swapped at a call site.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FailureDomainChirho {
    /// The hosting provider — the coarser blast radius.
    pub provider_chirho: String,
    /// The region within that provider.
    pub region_chirho: String,
}

/// The minimum distinct-domain counts a placement set must satisfy on each axis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinimumSpreadChirho {
    pub distinct_providers_chirho: usize,
    pub distinct_regions_chirho: usize,
}

/// The axis a layout fell short on. Named per-axis so an operator knows whether to add a region or a
/// whole provider — a distinction a single number would erase.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpreadAxisChirho {
    ProviderChirho,
    RegionChirho,
}

/// One reason a layout does not meet its spread requirement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpreadRefusalChirho {
    TooFewDistinctDomainsChirho {
        axis_chirho: SpreadAxisChirho,
        required_chirho: usize,
        actual_chirho: usize,
    },
}

/// Distinct providers in a layout.
pub fn distinct_providers_chirho(placements_chirho: &[FailureDomainChirho]) -> usize {
    placements_chirho
        .iter()
        .map(|domain_chirho| domain_chirho.provider_chirho.as_str())
        .collect::<BTreeSet<_>>()
        .len()
}

/// Distinct regions in a layout, qualified by provider — two providers may both call a region
/// `"eu-west"`, and treating those as one region would understate the real spread.
pub fn distinct_regions_chirho(placements_chirho: &[FailureDomainChirho]) -> usize {
    placements_chirho
        .iter()
        .map(|domain_chirho| {
            (
                domain_chirho.provider_chirho.as_str(),
                domain_chirho.region_chirho.as_str(),
            )
        })
        .collect::<BTreeSet<_>>()
        .len()
}

/// Every way this layout falls short of the minimum spread; empty means it satisfies it.
pub fn spread_refusals_chirho(
    placements_chirho: &[FailureDomainChirho],
    minimum_chirho: MinimumSpreadChirho,
) -> Vec<SpreadRefusalChirho> {
    let mut refusals_chirho = Vec::new();
    let providers_chirho = distinct_providers_chirho(placements_chirho);
    if providers_chirho < minimum_chirho.distinct_providers_chirho {
        refusals_chirho.push(SpreadRefusalChirho::TooFewDistinctDomainsChirho {
            axis_chirho: SpreadAxisChirho::ProviderChirho,
            required_chirho: minimum_chirho.distinct_providers_chirho,
            actual_chirho: providers_chirho,
        });
    }
    let regions_chirho = distinct_regions_chirho(placements_chirho);
    if regions_chirho < minimum_chirho.distinct_regions_chirho {
        refusals_chirho.push(SpreadRefusalChirho::TooFewDistinctDomainsChirho {
            axis_chirho: SpreadAxisChirho::RegionChirho,
            required_chirho: minimum_chirho.distinct_regions_chirho,
            actual_chirho: regions_chirho,
        });
    }
    refusals_chirho
}

#[cfg(test)]
#[path = "failure_domain_tests_chirho.rs"]
mod failure_domain_tests_chirho;
