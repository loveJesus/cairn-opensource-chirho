// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Typed, path-redacted item-6 evidence. Raw diagnostic captures never enter this schema.

use crate::error_chirho::{LedgerRegenesisRefusalChirho, LedgerRegenesisResultChirho};
use cairn_operator_evidence_chirho::operator_evidence_chirho::LOCAL_ROOT_REDACTED_CHIRHO;
use serde::{Deserialize, Serialize};
use std::fmt;

pub const SHAREABLE_EVIDENCE_SCHEMA_V1_CHIRHO: &str = "shareable-item6-evidence-v1-chirho";
const SHAREABLE_EVIDENCE_DIGEST_DOMAIN_CHIRHO: &str =
    "cairn-shareable-item6-evidence-manifest-v1-chirho";

const HOST_PATH_MARKERS_CHIRHO: &[&str] = &[
    "/Users/",
    "/private/tmp/",
    "/var/lib/",
    "/etc/",
    "/usr/local/bin/",
    "/tmp/",
    "/home/",
    "/root/",
    "/usr/",
    "/opt/",
    "/srv/",
];
const BEARER_MARKERS_CHIRHO: &[&str] =
    &["bearer ", "authorization:", "access_token", "refresh_token"];
const PRINCIPAL_MARKERS_CHIRHO: &[&str] =
    &["principal_name", "email_address", "free_text_principal"];
const PROVIDER_MARKERS_CHIRHO: &[&str] =
    &["raw_provider_bytes", "provider_payload", "stripe_secret"];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ShareableEvidenceFileClassChirho {
    BarrierEventChirho,
    DurableStateDigestChirho,
    VerificationSummaryChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ShareableEvidenceTermChirho {
    CurrentTermChirho,
    WinnerTermChirho,
    ObserverTermChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ShareableEvidenceBarrierEventChirho {
    ArmedChirho,
    DisconnectedChirho,
    HealedChirho,
    CleanedChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ShareableEvidenceStatusChirho {
    VerifiedChirho,
    BlockedChirho,
    IncompleteChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareableEvidenceManifestNodeChirho {
    pub file_class_chirho: ShareableEvidenceFileClassChirho,
    pub digest_chirho: String,
    pub children_chirho: Vec<ShareableEvidenceManifestNodeChirho>,
}

/// INVARIANT (F4 disposition, reviewed 2026-08-08): every field here is typed or
/// bounded — an enum, an equality-pinned label, or a validated hex/count/timestamp —
/// so the packet has NO free-text surface. That typing is the PRIMARY privacy control
/// (safety by typing, not scanning). Any new datum that would be free text is PRIVATE
/// per the recon §4 rule and CANNOT enter this shareable packet; keep it host-private.
/// The producer's forbidden-marker scan in `canonical_shareable_evidence_packet_chirho`
/// is defense-in-depth only, and is unfirable-by-construction while this invariant holds
/// — never rely on it in place of keeping every field typed/bounded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareableEvidencePacketChirho {
    pub schema_chirho: String,
    pub evidence_digest_chirho: String,
    pub status_chirho: ShareableEvidenceStatusChirho,
    pub terms_chirho: Vec<(ShareableEvidenceTermChirho, u64)>,
    pub event_count_chirho: u64,
    pub provider_execution_count_chirho: u64,
    pub journal_receipt_count_chirho: u64,
    pub observed_at_ms_chirho: u64,
    pub barrier_events_chirho: Vec<ShareableEvidenceBarrierEventChirho>,
    pub manifest_chirho: ShareableEvidenceManifestNodeChirho,
    pub root_scope_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShareableEvidenceRefusalReasonChirho {
    NonCanonicalChirho,
    SchemaChirho,
    EmptyDigestChirho,
    RootScopeChirho,
    UnallowlistedManifestChirho,
    ManifestDigestChirho,
    ForbiddenHostPathChirho,
    ForbiddenBearerMarkerChirho,
    ForbiddenPrincipalMarkerChirho,
    ForbiddenProviderBytesChirho,
}

impl fmt::Display for ShareableEvidenceRefusalReasonChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text_chirho = match self {
            Self::NonCanonicalChirho => "packet is not canonical",
            Self::SchemaChirho => "packet schema is unsupported",
            Self::EmptyDigestChirho => "packet contains an empty digest",
            Self::RootScopeChirho => "packet root scope is not the fixed redacted label",
            Self::UnallowlistedManifestChirho => "manifest contains an unallowlisted file class",
            Self::ManifestDigestChirho => "manifest digest is invalid",
            Self::ForbiddenHostPathChirho => "packet contains a host path marker",
            Self::ForbiddenBearerMarkerChirho => "packet contains a bearer marker",
            Self::ForbiddenPrincipalMarkerChirho => "packet contains free-text principal data",
            Self::ForbiddenProviderBytesChirho => "packet contains raw provider data",
        };
        formatter_chirho.write_str(text_chirho)
    }
}

fn refuse_shareable_evidence_chirho(
    reason_chirho: ShareableEvidenceRefusalReasonChirho,
) -> LedgerRegenesisRefusalChirho {
    LedgerRegenesisRefusalChirho::ShareableEvidenceRefusedChirho { reason_chirho }
}

pub fn canonical_shareable_evidence_packet_chirho(
    packet_chirho: &ShareableEvidencePacketChirho,
) -> LedgerRegenesisResultChirho<Vec<u8>> {
    validate_shareable_evidence_packet_chirho(packet_chirho)?;
    let bytes_chirho = serde_json::to_vec(packet_chirho).map_err(|_| {
        refuse_shareable_evidence_chirho(ShareableEvidenceRefusalReasonChirho::SchemaChirho)
    })?;
    scan_forbidden_markers_chirho(&bytes_chirho)?;
    Ok(bytes_chirho)
}

pub fn verify_shareable_evidence_packet_chirho(
    bytes_chirho: &[u8],
) -> LedgerRegenesisResultChirho<ShareableEvidencePacketChirho> {
    let packet_chirho: ShareableEvidencePacketChirho = serde_json::from_slice(bytes_chirho)
        .map_err(|_| {
            refuse_shareable_evidence_chirho(ShareableEvidenceRefusalReasonChirho::SchemaChirho)
        })?;
    let canonical_bytes_chirho = canonical_shareable_evidence_packet_chirho(&packet_chirho)?;
    if canonical_bytes_chirho != bytes_chirho {
        return Err(refuse_shareable_evidence_chirho(
            ShareableEvidenceRefusalReasonChirho::NonCanonicalChirho,
        ));
    }
    scan_forbidden_markers_chirho(bytes_chirho)?;
    Ok(packet_chirho)
}

/// The typed inputs a drill producer hands in to emit a shareable packet. Every field is ALREADY
/// typed/bounded (the F4 invariant on [`ShareableEvidencePacketChirho`]); this input carries no new
/// free-text surface. The builder fills in only the fixed schema, the redacted root scope, and the
/// domain-separated digests, so nothing here can widen what the packet can express.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareableEvidenceInputsChirho {
    pub status_chirho: ShareableEvidenceStatusChirho,
    pub terms_chirho: Vec<(ShareableEvidenceTermChirho, u64)>,
    pub event_count_chirho: u64,
    pub provider_execution_count_chirho: u64,
    pub journal_receipt_count_chirho: u64,
    pub observed_at_ms_chirho: u64,
    pub barrier_events_chirho: Vec<ShareableEvidenceBarrierEventChirho>,
    pub manifest_chirho: ShareableEvidenceManifestNodeChirho,
}

/// Public manifest-node constructor: compute a node's domain-separated digest from its file class and
/// its children's digests. Callers build the manifest bottom-up with this; the packet builder ALSO
/// recomputes every digest, so a hand-built node carrying a stale digest is corrected, never trusted.
pub fn shareable_manifest_node_chirho(
    file_class_chirho: ShareableEvidenceFileClassChirho,
    children_chirho: Vec<ShareableEvidenceManifestNodeChirho>,
) -> ShareableEvidenceManifestNodeChirho {
    let mut node_chirho = ShareableEvidenceManifestNodeChirho {
        file_class_chirho,
        digest_chirho: String::new(),
        children_chirho,
    };
    node_chirho.digest_chirho = manifest_node_digest_chirho(&node_chirho);
    node_chirho
}

fn recompute_manifest_digests_chirho(
    node_chirho: &ShareableEvidenceManifestNodeChirho,
) -> ShareableEvidenceManifestNodeChirho {
    let children_chirho = node_chirho
        .children_chirho
        .iter()
        .map(recompute_manifest_digests_chirho)
        .collect();
    shareable_manifest_node_chirho(node_chirho.file_class_chirho.clone(), children_chirho)
}

/// Emit a valid, canonical shareable packet from typed producer inputs — the 6.5 "producer wiring".
/// It sets the fixed schema and the fixed redacted root scope, recomputes every manifest digest and
/// the packet integrity digest with the SAME domain-separated hashing `verify_...` uses, then
/// validates and forbidden-marker-scans before returning. A producer therefore cannot emit a packet
/// that would fail [`verify_shareable_evidence_packet_chirho`], and cannot re-implement (and drift
/// from) the canonical hashing. It redesigns nothing: only the existing typed fields go in.
pub fn build_shareable_evidence_packet_chirho(
    inputs_chirho: ShareableEvidenceInputsChirho,
) -> LedgerRegenesisResultChirho<ShareableEvidencePacketChirho> {
    let mut packet_chirho = ShareableEvidencePacketChirho {
        schema_chirho: SHAREABLE_EVIDENCE_SCHEMA_V1_CHIRHO.to_owned(),
        evidence_digest_chirho: String::new(),
        status_chirho: inputs_chirho.status_chirho,
        terms_chirho: inputs_chirho.terms_chirho,
        event_count_chirho: inputs_chirho.event_count_chirho,
        provider_execution_count_chirho: inputs_chirho.provider_execution_count_chirho,
        journal_receipt_count_chirho: inputs_chirho.journal_receipt_count_chirho,
        observed_at_ms_chirho: inputs_chirho.observed_at_ms_chirho,
        barrier_events_chirho: inputs_chirho.barrier_events_chirho,
        manifest_chirho: recompute_manifest_digests_chirho(&inputs_chirho.manifest_chirho),
        root_scope_chirho: LOCAL_ROOT_REDACTED_CHIRHO.to_owned(),
    };
    packet_chirho.evidence_digest_chirho = packet_integrity_digest_chirho(&packet_chirho);
    // Fail closed: the producer's output MUST validate and MUST carry no forbidden marker. This runs
    // the exact validation + scan the verifier runs, so a producer never emits an unverifiable packet.
    canonical_shareable_evidence_packet_chirho(&packet_chirho)?;
    Ok(packet_chirho)
}

fn validate_shareable_evidence_packet_chirho(
    packet_chirho: &ShareableEvidencePacketChirho,
) -> LedgerRegenesisResultChirho<()> {
    if packet_chirho.schema_chirho != SHAREABLE_EVIDENCE_SCHEMA_V1_CHIRHO {
        return Err(refuse_shareable_evidence_chirho(
            ShareableEvidenceRefusalReasonChirho::SchemaChirho,
        ));
    }
    if !is_digest_chirho(&packet_chirho.evidence_digest_chirho) {
        return Err(refuse_shareable_evidence_chirho(
            ShareableEvidenceRefusalReasonChirho::EmptyDigestChirho,
        ));
    }
    if packet_chirho.root_scope_chirho != LOCAL_ROOT_REDACTED_CHIRHO {
        return Err(refuse_shareable_evidence_chirho(
            ShareableEvidenceRefusalReasonChirho::RootScopeChirho,
        ));
    }
    if packet_chirho.evidence_digest_chirho != packet_integrity_digest_chirho(packet_chirho) {
        return Err(refuse_shareable_evidence_chirho(
            ShareableEvidenceRefusalReasonChirho::ManifestDigestChirho,
        ));
    }
    validate_manifest_node_chirho(&packet_chirho.manifest_chirho)?;
    Ok(())
}

fn validate_manifest_node_chirho(
    node_chirho: &ShareableEvidenceManifestNodeChirho,
) -> LedgerRegenesisResultChirho<()> {
    if !is_digest_chirho(&node_chirho.digest_chirho)
        || node_chirho.digest_chirho != manifest_node_digest_chirho(node_chirho)
    {
        return Err(refuse_shareable_evidence_chirho(
            ShareableEvidenceRefusalReasonChirho::EmptyDigestChirho,
        ));
    }
    for child_chirho in &node_chirho.children_chirho {
        validate_manifest_node_chirho(child_chirho)?;
    }
    Ok(())
}

fn is_digest_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_hexdigit())
}

fn manifest_node_digest_chirho(node_chirho: &ShareableEvidenceManifestNodeChirho) -> String {
    let child_digests_chirho: Vec<&str> = node_chirho
        .children_chirho
        .iter()
        .map(|child_chirho| child_chirho.digest_chirho.as_str())
        .collect();
    let payload_chirho =
        serde_json::to_vec(&(&node_chirho.file_class_chirho, child_digests_chirho))
            .expect("manifest node payload is serializable");
    blake3::hash(
        &[
            SHAREABLE_EVIDENCE_DIGEST_DOMAIN_CHIRHO.as_bytes(),
            &payload_chirho,
        ]
        .concat(),
    )
    .to_hex()
    .to_string()
}

fn packet_integrity_digest_chirho(packet_chirho: &ShareableEvidencePacketChirho) -> String {
    let mut packet_copy_chirho = packet_chirho.clone();
    packet_copy_chirho.evidence_digest_chirho.clear();
    let bytes_chirho = serde_json::to_vec(&packet_copy_chirho).expect("packet is serializable");
    blake3::hash(
        &[
            SHAREABLE_EVIDENCE_DIGEST_DOMAIN_CHIRHO.as_bytes(),
            &bytes_chirho,
        ]
        .concat(),
    )
    .to_hex()
    .to_string()
}

/// Defense-in-depth forbidden-marker scan (host paths, bearer tokens, free-text principals, raw
/// provider bytes). Public so a drill's evidence-PACKAGING harness scans every shareable member with
/// the SAME marker lists this crate uses on the packet — one scan, never a duplicated list. Per the
/// F4 invariant above this is defense-in-depth, never a substitute for keeping every field typed.
pub fn scan_forbidden_markers_chirho(bytes_chirho: &[u8]) -> LedgerRegenesisResultChirho<()> {
    let text_chirho = String::from_utf8_lossy(bytes_chirho).to_ascii_lowercase();
    if HOST_PATH_MARKERS_CHIRHO
        .iter()
        .any(|marker_chirho| text_chirho.contains(&marker_chirho.to_ascii_lowercase()))
    {
        return Err(refuse_shareable_evidence_chirho(
            ShareableEvidenceRefusalReasonChirho::ForbiddenHostPathChirho,
        ));
    }
    if BEARER_MARKERS_CHIRHO
        .iter()
        .any(|marker_chirho| text_chirho.contains(&marker_chirho.to_ascii_lowercase()))
    {
        return Err(refuse_shareable_evidence_chirho(
            ShareableEvidenceRefusalReasonChirho::ForbiddenBearerMarkerChirho,
        ));
    }
    if PRINCIPAL_MARKERS_CHIRHO
        .iter()
        .any(|marker_chirho| text_chirho.contains(&marker_chirho.to_ascii_lowercase()))
    {
        return Err(refuse_shareable_evidence_chirho(
            ShareableEvidenceRefusalReasonChirho::ForbiddenPrincipalMarkerChirho,
        ));
    }
    if PROVIDER_MARKERS_CHIRHO
        .iter()
        .any(|marker_chirho| text_chirho.contains(&marker_chirho.to_ascii_lowercase()))
    {
        return Err(refuse_shareable_evidence_chirho(
            ShareableEvidenceRefusalReasonChirho::ForbiddenProviderBytesChirho,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    fn valid_packet_chirho() -> ShareableEvidencePacketChirho {
        let mut packet_chirho = ShareableEvidencePacketChirho {
            schema_chirho: SHAREABLE_EVIDENCE_SCHEMA_V1_CHIRHO.to_owned(),
            evidence_digest_chirho: String::new(),
            status_chirho: ShareableEvidenceStatusChirho::VerifiedChirho,
            terms_chirho: vec![(ShareableEvidenceTermChirho::CurrentTermChirho, 7)],
            event_count_chirho: 3,
            provider_execution_count_chirho: 1,
            journal_receipt_count_chirho: 1,
            observed_at_ms_chirho: 1_725_000_000_000,
            barrier_events_chirho: vec![ShareableEvidenceBarrierEventChirho::CleanedChirho],
            manifest_chirho: ShareableEvidenceManifestNodeChirho {
                file_class_chirho: ShareableEvidenceFileClassChirho::VerificationSummaryChirho,
                digest_chirho: String::new(),
                children_chirho: vec![ShareableEvidenceManifestNodeChirho {
                    file_class_chirho: ShareableEvidenceFileClassChirho::DurableStateDigestChirho,
                    digest_chirho: String::new(),
                    children_chirho: Vec::new(),
                }],
            },
            root_scope_chirho: LOCAL_ROOT_REDACTED_CHIRHO.to_owned(),
        };
        let child_chirho = &mut packet_chirho.manifest_chirho.children_chirho[0];
        child_chirho.digest_chirho = manifest_node_digest_chirho(child_chirho);
        packet_chirho.manifest_chirho.digest_chirho =
            manifest_node_digest_chirho(&packet_chirho.manifest_chirho);
        packet_chirho.evidence_digest_chirho = packet_integrity_digest_chirho(&packet_chirho);
        packet_chirho
    }

    fn packet_bytes_chirho(packet_chirho: &ShareableEvidencePacketChirho) -> Vec<u8> {
        canonical_shareable_evidence_packet_chirho(packet_chirho).unwrap()
    }

    #[test]
    fn valid_packet_and_safe_status_survive_verification_chirho() {
        let packet_chirho = valid_packet_chirho();
        let bytes_chirho = packet_bytes_chirho(&packet_chirho);
        let verified_chirho = verify_shareable_evidence_packet_chirho(&bytes_chirho).unwrap();
        assert_eq!(
            verified_chirho.status_chirho,
            ShareableEvidenceStatusChirho::VerifiedChirho
        );
        assert!(verified_chirho.evidence_digest_chirho.len() == 64);
    }

    #[test]
    fn tampered_manifest_member_has_named_failure_chirho() {
        let mut packet_chirho = valid_packet_chirho();
        packet_chirho.manifest_chirho.children_chirho[0]
            .digest_chirho
            .replace_range(0..1, "f");
        let tampered_bytes_chirho = serde_json::to_vec(&packet_chirho).unwrap();
        let refusal_chirho =
            verify_shareable_evidence_packet_chirho(&tampered_bytes_chirho).unwrap_err();
        assert!(matches!(
            refusal_chirho,
            LedgerRegenesisRefusalChirho::ShareableEvidenceRefusedChirho {
                reason_chirho: ShareableEvidenceRefusalReasonChirho::ManifestDigestChirho
            }
        ));
    }

    #[test]
    fn tampered_term_and_count_have_named_failure_chirho() {
        for tamper_chirho in ["term", "count"] {
            let mut packet_chirho = valid_packet_chirho();
            if tamper_chirho == "term" {
                packet_chirho.terms_chirho[0].1 += 1;
            } else {
                packet_chirho.event_count_chirho += 1;
            }
            let tampered_bytes_chirho = serde_json::to_vec(&packet_chirho).unwrap();
            let refusal_chirho =
                verify_shareable_evidence_packet_chirho(&tampered_bytes_chirho).unwrap_err();
            assert!(matches!(
                refusal_chirho,
                LedgerRegenesisRefusalChirho::ShareableEvidenceRefusedChirho {
                    reason_chirho: ShareableEvidenceRefusalReasonChirho::ManifestDigestChirho
                }
            ));
        }
    }

    #[test]
    fn each_forbidden_marker_blocks_publication_with_its_reason_chirho() {
        let marker_cases_chirho = [
            (
                "/etc/cairn-chirho/x",
                ShareableEvidenceRefusalReasonChirho::ForbiddenHostPathChirho,
            ),
            (
                "bearer secret-token",
                ShareableEvidenceRefusalReasonChirho::ForbiddenBearerMarkerChirho,
            ),
            (
                "free_text_principal=owner",
                ShareableEvidenceRefusalReasonChirho::ForbiddenPrincipalMarkerChirho,
            ),
            (
                "raw_provider_bytes=payload",
                ShareableEvidenceRefusalReasonChirho::ForbiddenProviderBytesChirho,
            ),
        ];
        for (marker_chirho, expected_reason_chirho) in marker_cases_chirho {
            let refusal_chirho =
                scan_forbidden_markers_chirho(marker_chirho.as_bytes()).unwrap_err();
            assert!(matches!(
                refusal_chirho,
                LedgerRegenesisRefusalChirho::ShareableEvidenceRefusedChirho { reason_chirho }
                    if reason_chirho == expected_reason_chirho
            ));
        }
        for marker_chirho in HOST_PATH_MARKERS_CHIRHO {
            let refusal_chirho =
                scan_forbidden_markers_chirho(marker_chirho.as_bytes()).unwrap_err();
            assert!(matches!(
                refusal_chirho,
                LedgerRegenesisRefusalChirho::ShareableEvidenceRefusedChirho {
                    reason_chirho: ShareableEvidenceRefusalReasonChirho::ForbiddenHostPathChirho
                }
            ));
        }
    }
}
