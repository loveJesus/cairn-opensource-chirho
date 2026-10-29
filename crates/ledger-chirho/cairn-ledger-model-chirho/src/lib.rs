// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Pure ledger DTOs — account-log identity and record shapes, with zero I/O.
//!
//! Brick 2.0 (this) carries only the TOY record the proof harness needs (a sequence, its writing
//! shard-epoch, an opaque payload digest) — just enough for Model A (epoch fence) and Model B
//! (rotation recovery). The real signed record — the FROZEN §11 two-leg per-cluster-journal shape,
//! with per-leg `(C, D, held)` post-state (Pr1: balance authority IS the last signed leg), HLC,
//! asset-kind, op, idempotency key, provenance, attribution, cross-zone anchor, and the F3
//! cross-cluster consume-once claim — lands in Brick 2.1 (`record_chirho`, `counterpart_chirho`,
//! `ids_chirho`). Nothing here touches fs, clock, or tokio.

// Our identifiers carry the `Chirho` suffix by convention, so every enum's variants share it.
#![allow(clippy::enum_variant_names)]

pub mod account_state_chirho;
pub mod asset_op_chirho;
pub mod counterpart_chirho;
pub mod finality_chirho;
pub(crate) mod framing_chirho;
pub mod ids_chirho;
pub mod projection_json_chirho;
pub mod record_chirho;
pub mod wire_chirho;

use serde::{Deserialize, Serialize};

/// Domain separator so a log-identity digest can never collide with another blake3 use.
const LOG_IDENTITY_DOMAIN_CHIRHO: &str = "cairn-ledger-log-identity-v1-chirho";

/// A path-free logical identity for ONE account-log: `(owner, stable asset-kind id)` — the
/// conflict-domain unit (one log per `(owner, kind)`, the CF0-locked packing). The kind component is
/// the STABLE [`ids_chirho::AssetKindIdChirho`] (R5b), never a policy-revision digest — so revising a
/// kind's policy can never move or strand an account. The digest binds records to their log so the
/// same bytes can never be replayed under a different account-log.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LogIdChirho {
    pub owner_chirho: String,
    pub kind_id_chirho: ids_chirho::AssetKindIdChirho,
}

impl LogIdChirho {
    /// Build an account-log id from an owner principal and a STABLE asset-kind id.
    pub fn new_chirho(
        owner_chirho: impl Into<String>,
        kind_id_chirho: impl Into<ids_chirho::AssetKindIdChirho>,
    ) -> Self {
        Self {
            owner_chirho: owner_chirho.into(),
            kind_id_chirho: kind_id_chirho.into(),
        }
    }

    /// Domain-separated blake3 digest of the (owner, kind-id) pair. Fields are LENGTH-PREFIX framed
    /// (`crate::framing_chirho`), not `0x00`-delimited — so an owner/kind containing `0x00` cannot
    /// collide with a different split (the A1 money-audit finding, claude2 #4418).
    pub fn digest_chirho(&self) -> String {
        let mut hasher_chirho = blake3::Hasher::new();
        crate::framing_chirho::frame_field_chirho(
            &mut hasher_chirho,
            LOG_IDENTITY_DOMAIN_CHIRHO.as_bytes(),
        );
        crate::framing_chirho::frame_field_chirho(&mut hasher_chirho, self.owner_chirho.as_bytes());
        crate::framing_chirho::frame_field_chirho(
            &mut hasher_chirho,
            self.kind_id_chirho.0.as_bytes(),
        );
        hasher_chirho.finalize().to_hex().to_string()
    }
}

/// The shard-lease epoch (P1, CF0-locked): a monotone fence granted per SHARD (not per log) and
/// DENORMALIZED into each record so a record self-proves which lease wrote it. Model A grants shard
/// epochs and proves the fence holds across sibling logs of one shard.
pub type ShardEpochChirho = u64;

/// The TOY record for Brick 2.0's proof harness. Deliberately minimal — the real signed record is 2.1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerToyRecordChirho {
    pub seq_chirho: u64,
    pub epoch_chirho: ShardEpochChirho,
    pub payload_digest_chirho: String,
}

impl LedgerToyRecordChirho {
    /// A toy record at `seq`/`epoch` carrying the digest of `payload`.
    pub fn new_chirho(
        seq_chirho: u64,
        epoch_chirho: ShardEpochChirho,
        payload_chirho: &[u8],
    ) -> Self {
        Self {
            seq_chirho,
            epoch_chirho,
            payload_digest_chirho: blake3::hash(payload_chirho).to_hex().to_string(),
        }
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn log_id_digest_is_stable_and_separated_chirho() {
        let a_chirho = LogIdChirho::new_chirho("owner-a-chirho", "money-chirho");
        let a2_chirho = LogIdChirho::new_chirho("owner-a-chirho", "money-chirho");
        let b_chirho = LogIdChirho::new_chirho("owner-a-chirho", "points-chirho");
        assert_eq!(a_chirho.digest_chirho(), a2_chirho.digest_chirho());
        assert_ne!(a_chirho.digest_chirho(), b_chirho.digest_chirho());
        // Field-boundary separated: (a, bc) must not collide with (ab, c).
        let split1_chirho = LogIdChirho::new_chirho("x", "yz");
        let split2_chirho = LogIdChirho::new_chirho("xy", "z");
        assert_ne!(split1_chirho.digest_chirho(), split2_chirho.digest_chirho());
    }

    #[test]
    fn toy_record_roundtrips_chirho() {
        let record_chirho = LedgerToyRecordChirho::new_chirho(3, 7, b"payload-chirho");
        let bytes_chirho = serde_json::to_vec(&record_chirho).unwrap();
        let back_chirho: LedgerToyRecordChirho = serde_json::from_slice(&bytes_chirho).unwrap();
        assert_eq!(record_chirho, back_chirho);
        assert_eq!(record_chirho.seq_chirho, 3);
        assert_eq!(record_chirho.epoch_chirho, 7);
    }

    #[test]
    fn real_record_roundtrips_and_omits_none_options_chirho() {
        use crate::ids_chirho::*;
        use crate::record_chirho::*;
        let leg_chirho = |owner_chirho: &str, delta_chirho, c_chirho, d_chirho| LedgerLegChirho {
            account_chirho: LogIdChirho::new_chirho(owner_chirho, "money-chirho"),
            kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho("money-kind-v1-chirho".into())),
            delta_chirho,
            amount_chirho: 10,
            post_chirho: LegPostStateChirho {
                credits_total_chirho: c_chirho,
                debits_total_chirho: d_chirho,
                held_chirho: 0,
            },
            counterpart_chirho: None,
        };
        let record_chirho = LedgerRecordChirho {
            schema_chirho: crate::wire_chirho::LEDGER_RECORD_SCHEMA_V1_CHIRHO.into(),
            format_version_chirho: 1,
            seq_chirho: 5,
            prev_chirho: DigestChirho("prevdigest-chirho".into()),
            epoch_chirho: 3,
            hlc_chirho: HlcChirho {
                physical_ms_chirho: 1000,
                logical_chirho: 2,
            },
            legs_chirho: vec![
                leg_chirho("alice-chirho", LegDeltaChirho::DebitChirho, 100, 10),
                leg_chirho("bob-chirho", LegDeltaChirho::CreditChirho, 10, 0),
            ],
            op_chirho: LedgerOpChirho::TransferChirho,
            idempotency_key_chirho: "idem-chirho".into(),
            provenance_chirho: None,
            attribution_chirho: AttributionChirho::PlatformChirho,
            anchor_chirho: None,
            sig_chirho: "sig-chirho".into(),
            key_id_chirho: "key-chirho".into(),
        };
        let bytes_chirho = serde_json::to_vec(&record_chirho).unwrap();
        let back_chirho: LedgerRecordChirho = serde_json::from_slice(&bytes_chirho).unwrap();
        assert_eq!(record_chirho, back_chirho);
        // Option policy (F5): None serializes ABSENT, never `null`.
        let text_chirho = String::from_utf8(bytes_chirho).unwrap();
        assert!(
            !text_chirho.contains("null"),
            "None must be absent: {text_chirho}"
        );
        assert!(!text_chirho.contains("provenance_chirho"));
        assert!(!text_chirho.contains("anchor_chirho"));
        assert!(!text_chirho.contains("counterpart_chirho"));
    }

    #[test]
    fn counterpart_nullifier_binds_and_excludes_the_finality_proof_chirho() {
        use crate::counterpart_chirho::*;
        use crate::ids_chirho::*;
        let make_claim_chirho = |proof_chirho: &str| CounterpartClaimChirho {
            transfer_id_chirho: TransferIdChirho("t1-chirho".into()),
            burn_chirho: FinalBurnRefChirho {
                source_money_group_chirho: MoneyGroupIdChirho("mg-src-chirho".into()),
                source_cluster_chirho: ClusterIdChirho("cl-src-chirho".into()),
                source_epoch_chirho: 2,
                source_seq_chirho: 9,
                source_record_digest_chirho: DigestChirho("burn-digest-chirho".into()),
                finality_proof_ref_chirho: DigestChirho(proof_chirho.into()),
            },
            amount_chirho: 50,
            kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho("money-kind-v1-chirho".into())),
            src_chirho: LogIdChirho::new_chirho("alice-chirho", "money-chirho"),
            dst_money_group_chirho: MoneyGroupIdChirho("mg-dst-chirho".into()),
            dst_cluster_chirho: ClusterIdChirho("cl-dst-chirho".into()),
            dst_chirho: LogIdChirho::new_chirho("bob-chirho", "money-chirho"),
            channel_chirho: SettlementChannelIdChirho("chan-1-chirho".into()),
            nullifier_chirho: CounterpartNullifierChirho(DigestChirho("placeholder".into())),
        };
        let mut claim_a_chirho = make_claim_chirho("proof-A-chirho");
        claim_a_chirho.nullifier_chirho = claim_a_chirho.expected_nullifier_chirho();
        assert!(claim_a_chirho.nullifier_is_bound_chirho());
        // A DIFFERENT finality proof for the SAME burn→dst→channel yields the SAME nullifier
        // (it EXCLUDES the proof) — so a newer proof cannot mint a second consume-once coordinate.
        let mut claim_b_chirho = make_claim_chirho("proof-B-DIFFERENT-chirho");
        claim_b_chirho.nullifier_chirho = claim_b_chirho.expected_nullifier_chirho();
        assert_eq!(
            claim_a_chirho.nullifier_chirho,
            claim_b_chirho.nullifier_chirho
        );
        // A different destination yields a DIFFERENT nullifier (the binding holds).
        let mut claim_c_chirho = make_claim_chirho("proof-A-chirho");
        claim_c_chirho.dst_chirho = LogIdChirho::new_chirho("carol-chirho", "money-chirho");
        claim_c_chirho.nullifier_chirho = claim_c_chirho.expected_nullifier_chirho();
        assert_ne!(
            claim_a_chirho.nullifier_chirho,
            claim_c_chirho.nullifier_chirho
        );
        // A caller-chosen nullifier that does not match its derivation is REJECTED.
        let mut forged_chirho = make_claim_chirho("proof-A-chirho");
        forged_chirho.nullifier_chirho =
            CounterpartNullifierChirho(DigestChirho("forged-chirho".into()));
        assert!(!forged_chirho.nullifier_is_bound_chirho());
    }

    #[test]
    fn policy_revision_never_strands_the_account_chirho() {
        // R5b two-concept law: the account is keyed by its STABLE kind id, the leg by its policy
        // REVISION ref. Two legs admitted under DIFFERENT policy revisions of the same kind address
        // the SAME account — a policy revision can never move or strand a balance.
        use crate::ids_chirho::*;
        let account_chirho = LogIdChirho::new_chirho("alice-chirho", "money-chirho");
        let v1_chirho = AssetKindRefChirho(DigestChirho("policy-v1-chirho".into()));
        let v2_chirho = AssetKindRefChirho(DigestChirho("policy-v2-chirho".into()));
        assert_ne!(
            v1_chirho, v2_chirho,
            "distinct revisions have distinct refs"
        );
        assert_eq!(
            LogIdChirho::new_chirho("alice-chirho", "money-chirho").digest_chirho(),
            account_chirho.digest_chirho(),
            "the account digest is a function of (owner, stable kind id) ONLY"
        );
        // And the stable id is typed distinctly from the revision ref: an AssetKindIdChirho can
        // never be passed where an AssetKindRefChirho is required (compile-level; witnessed here by
        // constructing both from the same seed string yet remaining unrelated values).
        let id_chirho: AssetKindIdChirho = "money-chirho".into();
        assert_eq!(account_chirho.kind_id_chirho, id_chirho);
    }

    #[test]
    fn logid_framing_resists_delimiter_collision_chirho() {
        // The adversarial pair a 0x00-delimiter scheme collapses: ("a","b\0c") and ("a\0b","c") both
        // delimit to "…a\0b\0c\0". A LEGACY delimiter helper COLLIDES on it (that IS the bug)…
        fn legacy_digest_chirho(owner_chirho: &str, kind_chirho: &str) -> String {
            let mut h_chirho = blake3::Hasher::new();
            h_chirho.update(LOG_IDENTITY_DOMAIN_CHIRHO.as_bytes());
            h_chirho.update(&[0u8]);
            h_chirho.update(owner_chirho.as_bytes());
            h_chirho.update(&[0u8]);
            h_chirho.update(kind_chirho.as_bytes());
            h_chirho.finalize().to_hex().to_string()
        }
        assert_eq!(
            legacy_digest_chirho("a", "b\0c"),
            legacy_digest_chirho("a\0b", "c"),
            "legacy 0x00-delimiter MUST collide on this pair (the bug being fixed)"
        );
        // …but the production LENGTH-PREFIXED digest keeps them DISTINCT.
        assert_ne!(
            LogIdChirho::new_chirho("a", "b\0c").digest_chirho(),
            LogIdChirho::new_chirho("a\0b", "c").digest_chirho(),
        );
    }

    #[test]
    fn nullifier_framing_resists_delimiter_collision_chirho() {
        use crate::counterpart_chirho::CounterpartNullifierChirho;
        use crate::ids_chirho::*;
        let derive_chirho = |mg_chirho: &str, cluster_chirho: &str| {
            CounterpartNullifierChirho::derive_chirho(
                &MoneyGroupIdChirho(mg_chirho.into()),
                &ClusterIdChirho(cluster_chirho.into()),
                1,
                2,
                &DigestChirho("rec-chirho".into()),
                &MoneyGroupIdChirho("mgd-chirho".into()),
                &ClusterIdChirho("cld-chirho".into()),
                &LogIdChirho::new_chirho("o-chirho", "k-chirho"),
                &SettlementChannelIdChirho("ch-chirho".into()),
            )
        };
        // A LEGACY 0x00-delimiter derivation over the SAME full field list COLLIDES the two DIFFERENT
        // burns ("a","b\0c") and ("a\0b","c") onto ONE nullifier — proven DIRECTLY here (gpt #4431),
        // not by analogy to the LogId test.
        fn legacy_nullifier_chirho(mg_chirho: &str, cluster_chirho: &str) -> String {
            fn f_chirho(h_chirho: &mut blake3::Hasher, b_chirho: &[u8]) {
                h_chirho.update(b_chirho);
                h_chirho.update(&[0u8]);
            }
            let mut h_chirho = blake3::Hasher::new();
            f_chirho(&mut h_chirho, b"ledger-counterpart-nullifier-v1-chirho");
            f_chirho(&mut h_chirho, mg_chirho.as_bytes());
            f_chirho(&mut h_chirho, cluster_chirho.as_bytes());
            f_chirho(&mut h_chirho, &1u64.to_le_bytes());
            f_chirho(&mut h_chirho, &2u64.to_le_bytes());
            f_chirho(&mut h_chirho, b"rec-chirho");
            f_chirho(&mut h_chirho, b"mgd-chirho");
            f_chirho(&mut h_chirho, b"cld-chirho");
            f_chirho(&mut h_chirho, b"o-chirho");
            f_chirho(&mut h_chirho, b"k-chirho");
            f_chirho(&mut h_chirho, b"ch-chirho");
            h_chirho.finalize().to_hex().to_string()
        }
        assert_eq!(
            legacy_nullifier_chirho("a", "b\0c"),
            legacy_nullifier_chirho("a\0b", "c"),
            "legacy 0x00-delimiter nullifier MUST collide on this pair (the bug being fixed)"
        );
        // ...but the production LENGTH-PREFIX framed nullifier keeps the two DIFFERENT burns DISTINCT
        // (adjacent source_money_group/source_cluster), so a legitimate mint is no longer falsely
        // refused.
        assert_ne!(derive_chirho("a", "b\0c"), derive_chirho("a\0b", "c"));
    }
}
