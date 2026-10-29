// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Spread counts distinct domains, and the two axes never substitute for one another.

use super::*;

fn domain_chirho(provider_chirho: &str, region_chirho: &str) -> FailureDomainChirho {
    FailureDomainChirho {
        provider_chirho: provider_chirho.to_string(),
        region_chirho: region_chirho.to_string(),
    }
}

fn minimum_chirho(
    distinct_providers_chirho: usize,
    distinct_regions_chirho: usize,
) -> MinimumSpreadChirho {
    MinimumSpreadChirho {
        distinct_providers_chirho,
        distinct_regions_chirho,
    }
}

#[test]
fn many_replicas_in_one_domain_are_spread_one_chirho() {
    // Counting replicas instead of domains would let a layout satisfy a spread requirement by
    // growing inside a single failure domain — the exact arrangement the requirement prevents.
    let layout_chirho = vec![
        domain_chirho("hetzner-chirho", "fsn1-chirho"),
        domain_chirho("hetzner-chirho", "fsn1-chirho"),
        domain_chirho("hetzner-chirho", "fsn1-chirho"),
        domain_chirho("hetzner-chirho", "fsn1-chirho"),
        domain_chirho("hetzner-chirho", "fsn1-chirho"),
    ];
    assert_eq!(distinct_providers_chirho(&layout_chirho), 1);
    assert_eq!(distinct_regions_chirho(&layout_chirho), 1);
    assert_eq!(
        spread_refusals_chirho(&layout_chirho, minimum_chirho(1, 2)),
        vec![SpreadRefusalChirho::TooFewDistinctDomainsChirho {
            axis_chirho: SpreadAxisChirho::RegionChirho,
            required_chirho: 2,
            actual_chirho: 1,
        }]
    );
}

#[test]
fn three_regions_at_one_provider_do_not_satisfy_provider_spread_chirho() {
    // THE LESSON THAT COST US A TOPOLOGY. This layout looks like spread three and is spread ONE
    // against a provider-wide failure: a billing suspension, a control-plane outage, an account
    // action. A blended diversity score would accept it; separate axes refuse it.
    let layout_chirho = vec![
        domain_chirho("ovh-chirho", "fr-chirho"),
        domain_chirho("ovh-chirho", "de-chirho"),
        domain_chirho("ovh-chirho", "uk-chirho"),
    ];
    assert_eq!(distinct_regions_chirho(&layout_chirho), 3);
    assert_eq!(distinct_providers_chirho(&layout_chirho), 1);
    assert_eq!(
        spread_refusals_chirho(&layout_chirho, minimum_chirho(2, 3)),
        vec![SpreadRefusalChirho::TooFewDistinctDomainsChirho {
            axis_chirho: SpreadAxisChirho::ProviderChirho,
            required_chirho: 2,
            actual_chirho: 1,
        }],
        "abundant region spread must not pay for absent provider spread"
    );
}

#[test]
fn a_second_provider_satisfies_what_more_regions_could_not_chirho() {
    let layout_chirho = vec![
        domain_chirho("ovh-chirho", "fr-chirho"),
        domain_chirho("ovh-chirho", "de-chirho"),
        domain_chirho("hetzner-chirho", "fsn1-chirho"),
    ];
    assert!(spread_refusals_chirho(&layout_chirho, minimum_chirho(2, 3)).is_empty());
}

#[test]
fn like_named_regions_at_different_providers_are_distinct_domains_chirho() {
    // Two providers may both call a region "eu-west"; collapsing them would understate real spread
    // and reject a layout that is genuinely diverse.
    let layout_chirho = vec![
        domain_chirho("ovh-chirho", "eu-west-chirho"),
        domain_chirho("hetzner-chirho", "eu-west-chirho"),
    ];
    assert_eq!(distinct_regions_chirho(&layout_chirho), 2);
    assert!(spread_refusals_chirho(&layout_chirho, minimum_chirho(2, 2)).is_empty());
}

#[test]
fn an_empty_layout_has_no_spread_and_refuses_on_both_axes_chirho() {
    let refusals_chirho = spread_refusals_chirho(&[], minimum_chirho(2, 3));
    assert_eq!(refusals_chirho.len(), 2, "{refusals_chirho:?}");
    assert!(refusals_chirho.iter().all(|refusal_chirho| matches!(
        refusal_chirho,
        SpreadRefusalChirho::TooFewDistinctDomainsChirho {
            actual_chirho: 0,
            ..
        }
    )));
}

#[test]
fn a_zero_minimum_accepts_anything_including_nothing_chirho() {
    // A requirement of zero is not a hidden floor of one; the caller asked for no constraint.
    assert!(spread_refusals_chirho(&[], minimum_chirho(0, 0)).is_empty());
}

#[test]
fn both_axes_report_together_so_an_operator_sees_the_whole_bill_chirho() {
    let layout_chirho = vec![domain_chirho("hetzner-chirho", "fsn1-chirho")];
    let refusals_chirho = spread_refusals_chirho(&layout_chirho, minimum_chirho(3, 3));
    assert_eq!(refusals_chirho.len(), 2);
    let axes_chirho = refusals_chirho
        .iter()
        .map(|refusal_chirho| match refusal_chirho {
            SpreadRefusalChirho::TooFewDistinctDomainsChirho { axis_chirho, .. } => *axis_chirho,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        axes_chirho,
        vec![
            SpreadAxisChirho::ProviderChirho,
            SpreadAxisChirho::RegionChirho
        ],
        "deterministic axis order keeps refusal text stable"
    );
}
