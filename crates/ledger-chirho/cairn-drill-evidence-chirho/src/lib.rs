// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The item-6 healing-drill's read-only OBSERVER channel and its evidence-PACKAGING harness: observe
//! leader/term/writer-era/obligation from a survivor plus the partition cut status (proven
//! observational — no key, no mutation), wire that observation into the EXISTING shareable evidence
//! packet, and package a redaction-safe bundle with a self-tested SHA-256 manifest and a reused
//! no-leak scan.
//!
//! This is brick 6.5-d (ruling (d) + §2.e). It runs NO host and executes NO drill: the observer is
//! driven from fixtures, and the packaging harness is proven locally. Two modules carry it:
//!
//! * [`observer_chirho`] — the D1 (survivor leader/term/writer-era/obligation projection) + D3
//!   (partition cut status) read-only observer. D2 (an on-the-wire deposition-belief endpoint) is a
//!   NON-GOAL; the former owner's own step-down belief is host-private.
//! * [`packaging_chirho`] — the b5-style bundle: recursive relative SHA-256 manifest, self-tested
//!   verifier, the reused forbidden-marker/no-leak scan, a fixed nonclaims block, and host-private
//!   captures excluded by type.
//!
//! It REUSES `cairn-ledger-regenesis-chirho`'s [`ShareableEvidencePacketChirho`] (its F4 typing is the
//! primary privacy control) rather than redesigning it: [`shareable_packet_from_observation_chirho`]
//! is the "producer wiring" that emits the packet from an observation, through the packet's own
//! validated builder.

mod observer_chirho;
mod packaging_chirho;

pub use observer_chirho::{
    observe_from_survivor_chirho, CutModeChirho, CutRefusalLabelChirho, CutStatusChirho,
    ObligationPhaseChirho, ObservationRecordChirho, ObserverAuthorityChirho, ObserverRefusalChirho,
    SurvivorLeaderProjectionChirho, WriterEraPhaseChirho,
};
pub use packaging_chirho::{
    bundle_verifier_selftest_chirho, nonclaims_member_chirho, package_shareable_bundle_chirho,
    verify_shareable_bundle_chirho, BundleManifestChirho, BundleRefusalChirho,
    BundleSelftestReportChirho, ForbiddenMarkerReasonChirho, HostPrivateCaptureChirho,
    HostPrivateCaptureKindChirho, ShareableBundleMemberChirho, ShareableEvidenceBundleChirho,
    BUNDLE_SELFTEST_CONTROL_COUNT_CHIRHO, ITEM6_DRILL_NONCLAIMS_CHIRHO,
};

use cairn_ledger_regenesis_chirho::{
    build_shareable_evidence_packet_chirho, canonical_shareable_evidence_packet_chirho,
    shareable_manifest_node_chirho, LedgerRegenesisRefusalChirho,
    ShareableEvidenceBarrierEventChirho, ShareableEvidenceFileClassChirho,
    ShareableEvidenceInputsChirho, ShareableEvidencePacketChirho, ShareableEvidenceStatusChirho,
    ShareableEvidenceTermChirho,
};

/// The relative member name the shareable evidence packet takes inside a bundle.
pub const SHAREABLE_PACKET_MEMBER_NAME_CHIRHO: &str = "shareable-evidence-packet-chirho.json";

/// The drill-derived typed scalars the shareable packet needs beyond the observation itself: the
/// evidence status, the three counts, and the barrier lifecycle. All bounded — no free text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrillEvidenceInputsChirho {
    pub status_chirho: ShareableEvidenceStatusChirho,
    pub event_count_chirho: u64,
    pub provider_execution_count_chirho: u64,
    pub journal_receipt_count_chirho: u64,
    pub barrier_events_chirho: Vec<ShareableEvidenceBarrierEventChirho>,
}

/// Wire a read-only OBSERVATION (D1 + D3) plus the drill's typed scalars into a valid, redaction-safe
/// [`ShareableEvidencePacketChirho`] (§2.e producer wiring). The observation's three terms become the
/// packet's `CurrentTerm`/`WinnerTerm`/`ObserverTerm`, and the packet's own validated builder
/// guarantees the result verifies and carries no forbidden marker. The observation's richer read-only
/// detail (leader id, writer-era/obligation phase) stays in the observation record; the packet is the
/// bounded shareable SUBSET.
pub fn shareable_packet_from_observation_chirho(
    observation_chirho: &ObservationRecordChirho,
    drill_chirho: DrillEvidenceInputsChirho,
) -> Result<ShareableEvidencePacketChirho, LedgerRegenesisRefusalChirho> {
    let manifest_chirho = shareable_manifest_node_chirho(
        ShareableEvidenceFileClassChirho::VerificationSummaryChirho,
        vec![
            shareable_manifest_node_chirho(
                ShareableEvidenceFileClassChirho::BarrierEventChirho,
                Vec::new(),
            ),
            shareable_manifest_node_chirho(
                ShareableEvidenceFileClassChirho::DurableStateDigestChirho,
                Vec::new(),
            ),
        ],
    );
    let inputs_chirho = ShareableEvidenceInputsChirho {
        status_chirho: drill_chirho.status_chirho,
        terms_chirho: vec![
            (
                ShareableEvidenceTermChirho::CurrentTermChirho,
                observation_chirho.former_owner_term_chirho,
            ),
            (
                ShareableEvidenceTermChirho::WinnerTermChirho,
                observation_chirho.winner_term_chirho,
            ),
            (
                ShareableEvidenceTermChirho::ObserverTermChirho,
                observation_chirho.observer_term_chirho,
            ),
        ],
        event_count_chirho: drill_chirho.event_count_chirho,
        provider_execution_count_chirho: drill_chirho.provider_execution_count_chirho,
        journal_receipt_count_chirho: drill_chirho.journal_receipt_count_chirho,
        observed_at_ms_chirho: observation_chirho.observed_at_ms_chirho,
        barrier_events_chirho: drill_chirho.barrier_events_chirho,
        manifest_chirho,
    };
    build_shareable_evidence_packet_chirho(inputs_chirho)
}

/// Canonicalize a shareable packet into a bundle member (a valid packet's bytes under the fixed member
/// name). The canonical form runs the packet's own validation + forbidden-marker scan, so a member
/// built here is already redaction-safe before it even reaches the bundle no-leak scan.
pub fn shareable_packet_member_chirho(
    packet_chirho: &ShareableEvidencePacketChirho,
) -> Result<ShareableBundleMemberChirho, LedgerRegenesisRefusalChirho> {
    let bytes_chirho = canonical_shareable_evidence_packet_chirho(packet_chirho)?;
    Ok(ShareableBundleMemberChirho::new_chirho(
        SHAREABLE_PACKET_MEMBER_NAME_CHIRHO,
        bytes_chirho,
    ))
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use cairn_drill_partition_nft_chirho::{
        plan_partition_chirho, DrillTargetKindChirho, HostedPartitionModeSpecChirho,
        HostedPartitionRequestChirho, OverlayPlaneChirho, OverlayPlanePortChirho,
        PartitionSubjectChirho,
    };
    use cairn_ledger_regenesis_chirho::verify_shareable_evidence_packet_chirho;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn observation_after_heal_chirho() -> ObservationRecordChirho {
        // A survivor OUTSIDE the partition sees the winner elected at a higher term; the drilled
        // obligation reached the compensated terminal; the cut is armed as a NetworkPartition.
        let request_chirho = HostedPartitionRequestChirho::new_chirho(
            PartitionSubjectChirho {
                former_owner_label_chirho: "boaz3".to_owned(),
                former_owner_overlay_addr_chirho: Ipv4Addr::new(10, 100, 0, 7),
            },
            vec![
                OverlayPlanePortChirho {
                    plane_chirho: OverlayPlaneChirho::ElectorChirho,
                    port_chirho: 8300,
                },
                OverlayPlanePortChirho {
                    plane_chirho: OverlayPlaneChirho::WriteRelayChirho,
                    port_chirho: 8400,
                },
                OverlayPlanePortChirho {
                    plane_chirho: OverlayPlaneChirho::ObservationChirho,
                    port_chirho: 8500,
                },
            ],
            HostedPartitionModeSpecChirho::NetworkPartitionChirho,
            DrillTargetKindChirho::DrillRootSyntheticChirho,
            Duration::from_secs(600),
        );
        let plan_chirho = plan_partition_chirho(&request_chirho).unwrap();
        let projection_chirho = SurvivorLeaderProjectionChirho {
            leader_id_hex_chirho: "ab".repeat(32),
            observer_term_chirho: 28,
            winner_term_chirho: 28,
            former_owner_term_chirho: 27,
            writer_era_phase_chirho: WriterEraPhaseChirho::ElectedChirho,
            obligation_phase_chirho: ObligationPhaseChirho::CompletedChirho,
        };
        observe_from_survivor_chirho(
            &projection_chirho,
            CutStatusChirho::observed_from_plan_chirho(&plan_chirho),
            1_725_000_000_000,
        )
        .unwrap()
    }

    fn drill_scalars_chirho() -> DrillEvidenceInputsChirho {
        DrillEvidenceInputsChirho {
            status_chirho: ShareableEvidenceStatusChirho::VerifiedChirho,
            event_count_chirho: 4,
            provider_execution_count_chirho: 1,
            journal_receipt_count_chirho: 1,
            barrier_events_chirho: vec![
                ShareableEvidenceBarrierEventChirho::ArmedChirho,
                ShareableEvidenceBarrierEventChirho::DisconnectedChirho,
                ShareableEvidenceBarrierEventChirho::HealedChirho,
                ShareableEvidenceBarrierEventChirho::CleanedChirho,
            ],
        }
    }

    #[test]
    fn observation_wires_into_a_verifiable_packet_chirho() {
        // End-to-end: OBSERVER -> shareable PACKET. The packet the wiring emits verifies through
        // regenesis's own verifier, and the observer's three terms are carried through.
        let observation_chirho = observation_after_heal_chirho();
        let packet_chirho =
            shareable_packet_from_observation_chirho(&observation_chirho, drill_scalars_chirho())
                .expect("observation wires into a valid packet");
        let bytes_chirho = canonical_shareable_evidence_packet_chirho(&packet_chirho).unwrap();
        let verified_chirho = verify_shareable_evidence_packet_chirho(&bytes_chirho)
            .expect("the emitted packet verifies");
        assert!(verified_chirho
            .terms_chirho
            .contains(&(ShareableEvidenceTermChirho::WinnerTermChirho, 28)));
        assert!(verified_chirho
            .terms_chirho
            .contains(&(ShareableEvidenceTermChirho::CurrentTermChirho, 27)));
        assert!(verified_chirho
            .terms_chirho
            .contains(&(ShareableEvidenceTermChirho::ObserverTermChirho, 28)));
    }

    #[test]
    fn end_to_end_observer_to_packaged_bundle_is_redaction_safe_chirho() {
        // The full 6.5-d flow with no host: observe -> packet -> member -> bundle -> verify.
        let observation_chirho = observation_after_heal_chirho();
        let packet_chirho =
            shareable_packet_from_observation_chirho(&observation_chirho, drill_scalars_chirho())
                .unwrap();
        let packet_member_chirho = shareable_packet_member_chirho(&packet_chirho).unwrap();
        let bundle_chirho = package_shareable_bundle_chirho(vec![packet_member_chirho])
            .expect("a redaction-safe packet packages");
        verify_shareable_bundle_chirho(&bundle_chirho).expect("the bundle verifies");
        // The bundle carries the packet member + the auto-appended nonclaims block.
        assert!(bundle_chirho.has_nonclaims_chirho());
        assert_eq!(bundle_chirho.members_chirho().len(), 2);
        // No member's bytes carry a host path (defense in depth over the packet's own typing).
        for member_chirho in bundle_chirho.members_chirho() {
            let text_chirho = String::from_utf8_lossy(member_chirho.bytes_chirho());
            assert!(!text_chirho.contains("/var/lib/"));
            assert!(!text_chirho.contains("/Users/"));
        }
    }

    #[test]
    fn the_leader_id_stays_in_the_observation_not_the_shareable_packet_chirho() {
        // The observation carries the (public) leader id; the shareable packet is the bounded subset
        // and does not. This pins that the packet surface is not silently widened by the wiring.
        let observation_chirho = observation_after_heal_chirho();
        assert_eq!(observation_chirho.leader_id_hex_chirho, "ab".repeat(32));
        let packet_chirho =
            shareable_packet_from_observation_chirho(&observation_chirho, drill_scalars_chirho())
                .unwrap();
        let bytes_chirho = canonical_shareable_evidence_packet_chirho(&packet_chirho).unwrap();
        let text_chirho = String::from_utf8_lossy(&bytes_chirho);
        assert!(!text_chirho.contains(&"ab".repeat(32)));
    }
}
