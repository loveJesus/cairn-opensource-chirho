// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The fixed content-binding vocabulary: one distinct `[u8; 32]` newtype per evidence, digest, and
//! safe-projection class. There is no shared `from_bytes` constructor, so one class can never be
//! passed where another is expected — a digest of the roster cannot masquerade as a PRD digest.

use crate::codec_chirho::geo_hex_newtype_chirho;
use crate::error_chirho::{GeoGenesisRefusalChirho, GeoGenesisResultChirho};

geo_hex_newtype_chirho!(
    /// Blake3 digest of the canonical `LedgerRegenesisPlanV1Chirho`; the original plan is reloaded and
    /// re-verified through the ledger crate at authoring/verify time (8.2b).
    GeoLedgerRegenesisPlanDigestChirho,
    32
);

impl GeoLedgerRegenesisPlanDigestChirho {
    /// Bind the digest of an in-memory canonical ledger regenesis plan. Pure type-level binding
    /// (canonical bytes -> blake3); reloading under custody and matching the review digest is 8.2b.
    /// This is the one constructor that consumes the named verified canonical type, and it is what
    /// makes the crate's inward edge on `cairn-ledger-regenesis-chirho` load-bearing already.
    pub fn from_canonical_ledger_regenesis_plan_chirho(
        plan_chirho: &cairn_ledger_regenesis_chirho::LedgerRegenesisPlanV1Chirho,
    ) -> GeoGenesisResultChirho<Self> {
        let bytes_chirho = cairn_ledger_regenesis_chirho::canonical_plan_bytes_chirho(plan_chirho)
            .map_err(|_error_chirho| GeoGenesisRefusalChirho::MalformedChirho)?;
        let hex_chirho = cairn_ledger_regenesis_chirho::plan_digest_chirho(&bytes_chirho);
        Self::from_hex_chirho(&hex_chirho)
    }
}

geo_hex_newtype_chirho!(
    /// Blake3 digest of the full reviewed PRD content; guards against an extracted set masking an
    /// unrelated PRD change.
    GeoPrdContentDigestChirho,
    32
);

geo_hex_newtype_chirho!(
    /// Blake3 digest of the canonicalized GG1-GG8 definition set parsed from the fixed PRD location.
    GeoGgDefinitionSetDigestChirho,
    32
);

geo_hex_newtype_chirho!(
    /// Blake3 digest of the canonicalized CF8 acceptance set parsed from the fixed PRD location.
    GeoCf8AcceptanceSetDigestChirho,
    32
);

geo_hex_newtype_chirho!(
    /// Blake3 digest of the signed roster projection this plan is paired with.
    GeoRosterProjectionDigestChirho,
    32
);

geo_hex_newtype_chirho!(
    /// Blake3 digest of the verified consistency-group canonical bytes; no raw group string appears.
    GeoConsistencyGroupDigestChirho,
    32
);

geo_hex_newtype_chirho!(
    /// Blake3 digest of the ledger plan's final-namespace relation (a safe projection, not the path).
    GeoLedgerFinalNamespaceDigestChirho,
    32
);

geo_hex_newtype_chirho!(
    /// Blake3 digest of a member's safe config projection (identities, keys, roles, endpoints).
    GeoNodeConfigProjectionDigestChirho,
    32
);

geo_hex_newtype_chirho!(
    /// Ref to a signed safe projection proving a member's exact cluster/ledger config plus custody
    /// checks; raw config and its path are absent.
    GeoNodeConfigEvidenceRefChirho,
    32
);

geo_hex_newtype_chirho!(
    /// Ref to a member's fresh build evidence (binary hash, target, config projection).
    GeoNodeBuildEvidenceRefChirho,
    32
);

geo_hex_newtype_chirho!(
    /// Redacted ref to a member custody verifier; never a secret name or key bytes.
    GeoCustodyVerifierRefChirho,
    32
);

geo_hex_newtype_chirho!(
    /// Ref to a verified safe GG projection accepted for one GG disposition.
    GeoGgEvidenceRefChirho,
    32
);

geo_hex_newtype_chirho!(
    /// SHA-256 of installed binary bytes; preserves the current binary-evidence algorithm.
    GeoBinarySha256Chirho,
    32
);

geo_hex_newtype_chirho!(
    /// Ref privately derived from the reviewed synthetic test-kind registry; not an arbitrary label.
    GeoSyntheticKindRefChirho,
    32
);

geo_hex_newtype_chirho!(
    /// Digest of the exact selected item-5 cell-advance terminal implementation/arm contract.
    GeoItem5TerminalContractDigestChirho,
    32
);

geo_hex_newtype_chirho!(
    /// Digest of the exact item-5 durable custody-verified certificate contract.
    GeoItem5CertificateContractDigestChirho,
    32
);

geo_hex_newtype_chirho!(
    /// Digest of the exact item-6 typed packet schema, verifier build, and ruled capture posture.
    GeoItem6PacketContractDigestChirho,
    32
);

geo_hex_newtype_chirho!(
    /// Digest of the exact production-wired synthetic canary schema and observation-window rule.
    GeoCanaryContractDigestChirho,
    32
);

geo_hex_newtype_chirho!(
    /// Digest of the exact CF7 mint-spend-project-reverse-conserve packet schema.
    GeoCf7PacketContractDigestChirho,
    32
);

geo_hex_newtype_chirho!(
    /// Actual item-5 terminal evidence ref (one `CompletedChirho` row plus receipt).
    GeoItem5TerminalEvidenceRefChirho,
    32
);

geo_hex_newtype_chirho!(
    /// Actual item-5 durable certificate evidence ref consumed by D3.
    GeoItem5CertificateEvidenceRefChirho,
    32
);

geo_hex_newtype_chirho!(
    /// Actual item-6 shareable manifest ref.
    GeoItem6ManifestRefChirho,
    32
);

geo_hex_newtype_chirho!(
    /// Ref to the exact ruled item-7 six-token contract plus its implementation/evidence schema.
    GeoItem7ContractRefChirho,
    32
);

geo_hex_newtype_chirho!(
    /// Actual finalized item-7 mirror receipt-set ref.
    GeoItem7ReceiptSetRefChirho,
    32
);

geo_hex_newtype_chirho!(
    /// Actual item-7 read-serving evidence ref, credited only under the ruled serving mode.
    GeoItem7ReadServingEvidenceRefChirho,
    32
);

geo_hex_newtype_chirho!(
    /// Actual canary observation evidence ref.
    GeoCanaryEvidenceRefChirho,
    32
);

geo_hex_newtype_chirho!(
    /// Actual loss-drill evidence ref (leader, node, or whole-region loss).
    GeoLossDrillEvidenceRefChirho,
    32
);

geo_hex_newtype_chirho!(
    /// Actual heal/failback evidence ref.
    GeoHealFailbackEvidenceRefChirho,
    32
);

geo_hex_newtype_chirho!(
    /// Actual CF7 packet evidence ref that survived the loss matrix.
    GeoCf7PacketEvidenceRefChirho,
    32
);

geo_hex_newtype_chirho!(
    /// Blake3 digest of the verified canonical geo-genesis plan bytes.
    GeoGenesisPlanDigestChirho,
    32
);

geo_hex_newtype_chirho!(
    /// Blake3 digest of the verified canonical authoritative-intent marker bytes.
    GeoGenesisIntentDigestChirho,
    32
);

geo_hex_newtype_chirho!(
    /// Ref to the complete verified intent marker set (operator guard plus every member marker).
    GeoIntentMarkerSetRefChirho,
    32
);

geo_hex_newtype_chirho!(
    /// Digest of the verified ledger publication manifest; no raw roots/paths copied into a receipt.
    GeoLedgerPublicationManifestDigestChirho,
    32
);

geo_hex_newtype_chirho!(
    /// Identity of the separately custody-verified operator guard root holding the intent marker.
    GeoOperatorGuardIdentityChirho,
    32
);

geo_hex_newtype_chirho!(
    /// Safe projection ref of the observed final member set.
    GeoObservedMemberSetRefChirho,
    32
);
