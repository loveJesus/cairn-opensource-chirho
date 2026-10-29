// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The cross-cluster consume-once claim (frozen §11.8, F3): a boundary credit leg proves it matches a
//! real, FINAL, not-yet-consumed source burn, so cross-cluster conservation is provable from the
//! records rather than from saga trust. gpt's typed shape-pin (#4395), ratified both seats; the shape
//! is frozen — CF2 needs no record re-freeze.

use crate::framing_chirho::frame_field_chirho;
use crate::ids_chirho::{
    AccountIdChirho, AssetKindRefChirho, ClusterIdChirho, DigestChirho, MoneyGroupIdChirho,
    SettlementChannelIdChirho, TransferIdChirho,
};
use crate::ShardEpochChirho;
use serde::{Deserialize, Serialize};

/// Domain separator so a counterpart-nullifier digest can never collide with another BLAKE3 use.
const COUNTERPART_NULLIFIER_DOMAIN_CHIRHO: &str = "ledger-counterpart-nullifier-v1-chirho";

/// The SINGLE typed source locator + self-verifying finality (frozen §11.8, F3). `finality_proof_ref`
/// content-addresses a root-signed proof that (a) binds the exact source record/cut, (b) proves
/// ancestry into an independently-retained high-water at/after the burn, (c) verifies under the source
/// money-group trust root — a saga assertion cannot satisfy it. The verifier PROTOCOL is a CF2
/// obligation; the SHAPE freezes now.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalBurnRefChirho {
    pub source_money_group_chirho: MoneyGroupIdChirho,
    pub source_cluster_chirho: ClusterIdChirho,
    pub source_epoch_chirho: ShardEpochChirho,
    pub source_seq_chirho: u64,
    pub source_record_digest_chirho: DigestChirho,
    pub finality_proof_ref_chirho: DigestChirho,
}

/// The domain-separated consume-once nullifier (frozen §11.8, F3). It binds
/// `source(money-group/cluster/epoch/seq/record-digest) → dst(money-group/cluster/account) → channel`
/// and DELIBERATELY EXCLUDES the finality-proof ref, so a NEWER proof for the same burn cannot mint a
/// second coordinate. Content-addressed ⇒ the CF2 consumed-set is an efficient, collision-resistant
/// indexed set (`Ord` for a `BTreeSet` consumed-set).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CounterpartNullifierChirho(pub DigestChirho);

impl CounterpartNullifierChirho {
    /// Derive the canonical nullifier. Fields are LENGTH-PREFIX framed (`crate::framing_chirho`), not
    /// `0x00`-delimited — so an id field containing `0x00` cannot collide with a different field split
    /// (the A1 money-audit finding, claude2 #4418). The source `finality_proof_ref` is NOT an input —
    /// the whole point, so one `burn → dst → channel` collapses to ONE key regardless of which
    /// (possibly newer) finality proof accompanies it.
    #[allow(clippy::too_many_arguments)]
    pub fn derive_chirho(
        source_money_group_chirho: &MoneyGroupIdChirho,
        source_cluster_chirho: &ClusterIdChirho,
        source_epoch_chirho: ShardEpochChirho,
        source_seq_chirho: u64,
        source_record_digest_chirho: &DigestChirho,
        dst_money_group_chirho: &MoneyGroupIdChirho,
        dst_cluster_chirho: &ClusterIdChirho,
        dst_account_chirho: &AccountIdChirho,
        channel_chirho: &SettlementChannelIdChirho,
    ) -> Self {
        let mut hasher_chirho = blake3::Hasher::new();
        frame_field_chirho(
            &mut hasher_chirho,
            COUNTERPART_NULLIFIER_DOMAIN_CHIRHO.as_bytes(),
        );
        frame_field_chirho(&mut hasher_chirho, source_money_group_chirho.0.as_bytes());
        frame_field_chirho(&mut hasher_chirho, source_cluster_chirho.0.as_bytes());
        frame_field_chirho(&mut hasher_chirho, &source_epoch_chirho.to_le_bytes());
        frame_field_chirho(&mut hasher_chirho, &source_seq_chirho.to_le_bytes());
        frame_field_chirho(&mut hasher_chirho, source_record_digest_chirho.0.as_bytes());
        frame_field_chirho(&mut hasher_chirho, dst_money_group_chirho.0.as_bytes());
        frame_field_chirho(&mut hasher_chirho, dst_cluster_chirho.0.as_bytes());
        frame_field_chirho(
            &mut hasher_chirho,
            dst_account_chirho.owner_chirho.as_bytes(),
        );
        frame_field_chirho(
            &mut hasher_chirho,
            dst_account_chirho.kind_id_chirho.0.as_bytes(),
        );
        frame_field_chirho(&mut hasher_chirho, channel_chirho.0.as_bytes());
        Self(DigestChirho(hasher_chirho.finalize().to_hex().to_string()))
    }
}

/// The consume-once cross-cluster claim carried by a boundary credit leg (frozen §11.8, F3). The
/// append verifier proves, before crediting `dst`: (i) the source burn exists and every duplicated
/// field EQUALS the burn evidence; (ii) `nullifier` is unconsumed (first claim authoritative); (iii)
/// `burn.finality_proof_ref` proves the burn is FINAL / non-rollbackable.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CounterpartClaimChirho {
    pub transfer_id_chirho: TransferIdChirho,
    pub burn_chirho: FinalBurnRefChirho,
    pub amount_chirho: u64,
    /// The policy REVISION the source burn was admitted under — equality-checked against the burn
    /// evidence (R5b). The STABLE kind identity rides in `src`/`dst` (`account.kind_id`); admission
    /// additionally requires `src.kind_id == dst.kind_id` (a transfer never changes kind).
    pub kind_policy_ref_chirho: AssetKindRefChirho,
    pub src_chirho: AccountIdChirho,
    pub dst_money_group_chirho: MoneyGroupIdChirho,
    pub dst_cluster_chirho: ClusterIdChirho,
    pub dst_chirho: AccountIdChirho,
    pub channel_chirho: SettlementChannelIdChirho,
    pub nullifier_chirho: CounterpartNullifierChirho,
}

impl CounterpartClaimChirho {
    /// The nullifier this claim MUST carry, recomputed from its own binding fields (excluding the
    /// finality proof). A verifier compares this to the stored `nullifier` and rejects a mismatch.
    pub fn expected_nullifier_chirho(&self) -> CounterpartNullifierChirho {
        CounterpartNullifierChirho::derive_chirho(
            &self.burn_chirho.source_money_group_chirho,
            &self.burn_chirho.source_cluster_chirho,
            self.burn_chirho.source_epoch_chirho,
            self.burn_chirho.source_seq_chirho,
            &self.burn_chirho.source_record_digest_chirho,
            &self.dst_money_group_chirho,
            &self.dst_cluster_chirho,
            &self.dst_chirho,
            &self.channel_chirho,
        )
    }

    /// Whether the carried nullifier matches its derivation — a BOUND claim. A mismatch is a forged or
    /// malformed nullifier that the append verifier rejects (the nullifier cannot be caller-chosen).
    pub fn nullifier_is_bound_chirho(&self) -> bool {
        self.nullifier_chirho == self.expected_nullifier_chirho()
    }
}
