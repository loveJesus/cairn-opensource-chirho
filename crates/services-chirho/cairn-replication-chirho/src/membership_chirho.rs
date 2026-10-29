// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! D3 signed membership roster: the trust root that resolves which node public keys a replica may
//! pin as an authorized SOURCE. The roster is an append-only log of add/remove events, each signed by
//! the platform OPERATOR key L.J. controls; a node is a valid replication source only if the roster —
//! verified against the pinned operator key — currently lists it. A node id IS its verification key,
//! and a region is a declared label. This gates the P3 fold verifier's `source_pubkey_hex`: only an
//! active roster member's key is ever pinned.

use anyhow::{bail, Context, Result};
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_signer_chirho::signer_chirho::verify_with_pubkey_chirho;
use std::collections::BTreeMap;
use std::path::Path;

pub const MEMBERSHIP_ROSTER_RECORD_SCHEMA_CHIRHO: &str = "membership-roster-record-v1-chirho";
pub const MEMBERSHIP_ROSTER_HEAD_SCHEMA_CHIRHO: &str = "membership-roster-head-v1-chirho";

/// One signed roster event. Add or remove a node; the node id is its public key.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "action_chirho")]
pub enum MembershipActionChirho {
    AddNodeChirho,
    RemoveNodeChirho,
}

/// A signed membership-roster record. Signed by the operator key; the operator key id must match the
/// pinned operator public key at verify time.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MembershipRosterRecordChirho {
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub action_chirho: MembershipActionChirho,
    /// The node's ed25519 public key (hex) — the node's identity.
    pub node_pubkey_hex_chirho: String,
    /// A declared, non-identifying region label.
    pub region_label_chirho: String,
    pub at_ms_chirho: u64,
    /// The operator public key that signed this record; must equal the pinned operator key.
    pub operator_key_id_chirho: String,
    pub sig_chirho: String,
}

/// The canonical signed message = the record with its signature cleared.
pub fn unsigned_membership_roster_message_chirho(
    record_chirho: &MembershipRosterRecordChirho,
) -> Result<Vec<u8>> {
    let mut unsigned_chirho = record_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&unsigned_chirho)?)
}

/// The A2 node-network-record schema. Network records live in the SAME roster log as membership
/// records (one operator-signed append-only log, one `seq` space), so the log carries two operator-signed
/// fact kinds: WHO is a member (add/remove) and WHERE a member is on the mesh + its raft id. A2.1's
/// generator derives WireGuard + elector config from the join of the two; extending the existing
/// membership record was avoided so its live + test signatures stay byte-stable (a separate record is
/// additive and independently revocable).
pub const NODE_NETWORK_RECORD_SCHEMA_CHIRHO: &str = "node-network-record-v1-chirho";

/// A1.4: the operator's per-consistency-group PREFERRED-LEADER choice (a separate additive signed record,
/// like the network record — independently revocable, membership signatures stay byte-stable).
pub const PREFERRED_LEADER_RECORD_SCHEMA_CHIRHO: &str = "preferred-leader-record-v1-chirho";

/// A signed node-network-coordinate record: the operator's assignment of a node's raft id and mesh
/// coordinates. Carries the WG **public** key ONLY — the private key is generated and held locally and
/// never enters any record, log, or CAS. Operator-signed like the membership record.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NodeNetworkRecordChirho {
    pub schema_chirho: String,
    pub seq_chirho: u64,
    /// The node's ed25519 public key (hex) — joins to the membership record on identity.
    pub node_pubkey_hex_chirho: String,
    /// The operator-assigned raft numeric id (never 0; never-rebind bijection verified in A1.3).
    pub raft_id_chirho: u64,
    /// The node's WireGuard PUBLIC key (base64) — never the private key.
    pub wg_pubkey_chirho: String,
    /// The node's private-mesh IP, e.g. `10.100.0.7`.
    pub mesh_ip_chirho: String,
    /// The node's public WireGuard endpoint `host:port` (redacted in shareable evidence).
    pub endpoint_chirho: String,
    pub at_ms_chirho: u64,
    /// The operator public key that signed this record; must equal the pinned operator key.
    pub operator_key_id_chirho: String,
    pub sig_chirho: String,
}

/// The canonical signed message for a node-network record = the record with its signature cleared.
pub fn unsigned_node_network_record_message_chirho(
    record_chirho: &NodeNetworkRecordChirho,
) -> Result<Vec<u8>> {
    let mut unsigned_chirho = record_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&unsigned_chirho)?)
}

/// A verified node-network coordinate set (operator-signature-checked), keyed by node pubkey.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedNodeNetworkChirho {
    pub node_pubkey_hex_chirho: String,
    pub raft_id_chirho: u64,
    pub wg_pubkey_chirho: String,
    pub mesh_ip_chirho: String,
    pub endpoint_chirho: String,
}

/// A signed preferred-leader record: the operator's per-consistency-group choice of WHICH node should
/// hold write leadership when it is healthy (L.J.'s "the primary audience's home location"). The
/// re-home driver (A1.4) transfers leadership BACK to this node when it is a caught-up healthy voter —
/// election-only, mints nothing. Operator-signed like the other roster records.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PreferredLeaderRecordChirho {
    pub schema_chirho: String,
    pub seq_chirho: u64,
    /// The consistency group this preference is for (its canonical id string).
    pub group_id_chirho: String,
    /// The operator-assigned raft id that should hold leadership for this group when it is healthy.
    pub preferred_leader_raft_id_chirho: u64,
    pub at_ms_chirho: u64,
    /// The operator public key that signed this record; must equal the pinned operator key.
    pub operator_key_id_chirho: String,
    pub sig_chirho: String,
}

/// The canonical signed message for a preferred-leader record = the record with its signature cleared.
pub fn unsigned_preferred_leader_record_message_chirho(
    record_chirho: &PreferredLeaderRecordChirho,
) -> Result<Vec<u8>> {
    let mut unsigned_chirho = record_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&unsigned_chirho)?)
}

/// A verified preferred-leader choice (operator-signature-checked), keyed by consistency-group id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPreferredLeaderChirho {
    pub group_id_chirho: String,
    pub preferred_leader_raft_id_chirho: u64,
}

/// Peek a roster line's `schema_chirho` without committing to a record type (unknown fields ignored),
/// so a mixed log can route each line to the right verifier.
fn peek_schema_chirho(line_chirho: &[u8]) -> Result<String> {
    #[derive(serde::Deserialize)]
    struct SchemaPeekChirho {
        schema_chirho: String,
    }
    let peek_chirho: SchemaPeekChirho = serde_json::from_slice(line_chirho)?;
    Ok(peek_chirho.schema_chirho)
}

/// Every schema that may legitimately appear as a roster-LOG line (the head is delivered separately). A
/// per-line verifier processes its OWN schema, SKIPS the other known ones (another verifier's concern),
/// and FAILS CLOSED on an unknown schema — so each verifier is independently fail-closed over a mixed log.
/// Adding a fourth roster-line record = add it here + write its verifier; the routing stays symmetric.
const KNOWN_ROSTER_LINE_SCHEMAS_CHIRHO: &[&str] = &[
    MEMBERSHIP_ROSTER_RECORD_SCHEMA_CHIRHO,
    NODE_NETWORK_RECORD_SCHEMA_CHIRHO,
    PREFERRED_LEADER_RECORD_SCHEMA_CHIRHO,
];

/// True if `schema_chirho` is a KNOWN roster-line schema OTHER than `mine_chirho` — i.e. another
/// verifier's concern, to be SKIPPED (neither this verifier's to process, nor an unknown to fail closed
/// on). A verifier calls this to skip sibling records, then fails closed on anything left that is not its
/// own schema.
fn is_other_known_roster_schema_chirho(schema_chirho: &str, mine_chirho: &str) -> bool {
    schema_chirho != mine_chirho && KNOWN_ROSTER_LINE_SCHEMAS_CHIRHO.contains(&schema_chirho)
}

/// Verify the node-network records in the SAME roster log against the pinned operator key: each network
/// record's operator signature is checked, its `seq` must equal its line index (the shared length-witness
/// space), and — per A2-R4 — the LATEST operator-signed record per node pubkey (by log position) wins, so
/// a moved endpoint supersedes cleanly with no ambiguity. Non-network lines (membership records) are
/// skipped by schema. Returns the winning verified coordinates keyed by node pubkey.
pub fn verify_node_network_records_chirho(
    lines_chirho: &[Vec<u8>],
    operator_pubkey_hex_chirho: &str,
) -> Result<BTreeMap<String, VerifiedNodeNetworkChirho>> {
    let mut latest_chirho: BTreeMap<String, VerifiedNodeNetworkChirho> = BTreeMap::new();
    for (index_chirho, line_chirho) in lines_chirho.iter().enumerate() {
        // Route by schema (shared with every roster verifier): SKIP a sibling record (a membership or
        // preferred-leader line), VERIFY a network record here, and FAIL CLOSED on an unknown schema — so
        // this verifier is independently fail-closed on a garbage/trailing line even over a mixed log.
        let schema_chirho = peek_schema_chirho(line_chirho)?;
        if is_other_known_roster_schema_chirho(&schema_chirho, NODE_NETWORK_RECORD_SCHEMA_CHIRHO) {
            continue;
        }
        if schema_chirho != NODE_NETWORK_RECORD_SCHEMA_CHIRHO {
            bail!(
                "roster line {index_chirho} has unknown schema '{schema_chirho}'; the network verifier fails closed on it"
            );
        }
        let record_chirho: NodeNetworkRecordChirho = serde_json::from_slice(line_chirho)?;
        if record_chirho.seq_chirho != index_chirho as u64 {
            bail!(
                "node-network record seq {} is not contiguous (expected {})",
                record_chirho.seq_chirho,
                index_chirho
            );
        }
        if record_chirho.operator_key_id_chirho != operator_pubkey_hex_chirho {
            bail!("node-network record operator key id does not match the pinned operator key");
        }
        let message_chirho = unsigned_node_network_record_message_chirho(&record_chirho)?;
        if !verify_with_pubkey_chirho(
            operator_pubkey_hex_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!("node-network record {index_chirho} signature is invalid for the operator key");
        }
        // Latest-by-log-position wins (A2-R4): overwrite any earlier record for this pubkey.
        latest_chirho.insert(
            record_chirho.node_pubkey_hex_chirho.clone(),
            VerifiedNodeNetworkChirho {
                node_pubkey_hex_chirho: record_chirho.node_pubkey_hex_chirho,
                raft_id_chirho: record_chirho.raft_id_chirho,
                wg_pubkey_chirho: record_chirho.wg_pubkey_chirho,
                mesh_ip_chirho: record_chirho.mesh_ip_chirho,
                endpoint_chirho: record_chirho.endpoint_chirho,
            },
        );
    }
    Ok(latest_chirho)
}

/// Verify the preferred-leader records in the SAME roster log against the pinned operator key: each
/// record's operator signature is checked, its `seq` must equal its line index (the shared length-witness
/// space), and the LATEST operator-signed record per consistency group (by log position) wins — so an
/// operator re-homing the primary supersedes cleanly. Sibling records (membership / network) are skipped
/// by schema; an unknown schema fails closed. Returns the winning verified choice keyed by group id.
pub fn verify_preferred_leader_records_chirho(
    lines_chirho: &[Vec<u8>],
    operator_pubkey_hex_chirho: &str,
) -> Result<BTreeMap<String, VerifiedPreferredLeaderChirho>> {
    let mut latest_chirho: BTreeMap<String, VerifiedPreferredLeaderChirho> = BTreeMap::new();
    for (index_chirho, line_chirho) in lines_chirho.iter().enumerate() {
        let schema_chirho = peek_schema_chirho(line_chirho)?;
        if is_other_known_roster_schema_chirho(
            &schema_chirho,
            PREFERRED_LEADER_RECORD_SCHEMA_CHIRHO,
        ) {
            continue;
        }
        if schema_chirho != PREFERRED_LEADER_RECORD_SCHEMA_CHIRHO {
            bail!(
                "roster line {index_chirho} has unknown schema '{schema_chirho}'; the preferred-leader verifier fails closed on it"
            );
        }
        let record_chirho: PreferredLeaderRecordChirho = serde_json::from_slice(line_chirho)?;
        if record_chirho.seq_chirho != index_chirho as u64 {
            bail!(
                "preferred-leader record seq {} is not contiguous (expected {})",
                record_chirho.seq_chirho,
                index_chirho
            );
        }
        if record_chirho.operator_key_id_chirho != operator_pubkey_hex_chirho {
            bail!("preferred-leader record operator key id does not match the pinned operator key");
        }
        let message_chirho = unsigned_preferred_leader_record_message_chirho(&record_chirho)?;
        if !verify_with_pubkey_chirho(
            operator_pubkey_hex_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "preferred-leader record {index_chirho} signature is invalid for the operator key"
            );
        }
        // Latest-by-log-position wins per group: an operator's re-home supersedes the earlier choice.
        latest_chirho.insert(
            record_chirho.group_id_chirho.clone(),
            VerifiedPreferredLeaderChirho {
                group_id_chirho: record_chirho.group_id_chirho,
                preferred_leader_raft_id_chirho: record_chirho.preferred_leader_raft_id_chirho,
            },
        );
    }
    Ok(latest_chirho)
}

/// A signed roster HEAD — the length witness. It pins the roster's record COUNT and a prefix digest
/// (a blake3 hash-chain over the raw roster line bytes), signed by the operator key. Delivered with the
/// roster, it makes a dropped tail — which would silently re-add a removed (revoked) node — fail closed:
/// the count/digest no longer match. This is the roster's analog of the Gate 1 anchor head, and it is
/// the trust root required before the roster is ever carried over untrusted transport (e.g. seeding
/// distributed membership).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MembershipRosterHeadChirho {
    pub schema_chirho: String,
    pub roster_record_count_chirho: u64,
    pub roster_prefix_digest_chirho: HashChirho,
    pub at_ms_chirho: u64,
    /// The operator public key that signed this head; must equal the pinned operator key.
    pub operator_key_id_chirho: String,
    pub sig_chirho: String,
}

/// The canonical signed message for a roster head = the head with its signature cleared.
pub fn unsigned_membership_roster_head_message_chirho(
    head_chirho: &MembershipRosterHeadChirho,
) -> Result<Vec<u8>> {
    let mut unsigned_chirho = head_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&unsigned_chirho)?)
}

/// The running blake3 hash-chain over the raw roster JSONL line bytes (from a zero seed). Because it
/// chains every line, the final digest pins the whole prefix — a truncated or tampered roster cannot
/// reproduce it. Used to build and to verify a `MembershipRosterHeadChirho`.
pub fn roster_prefix_digest_chirho(lines_chirho: &[Vec<u8>]) -> HashChirho {
    let mut previous_chirho = [0u8; 32];
    for line_chirho in lines_chirho {
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(&previous_chirho);
        hasher_chirho.update(line_chirho);
        previous_chirho = *hasher_chirho.finalize().as_bytes();
    }
    HashChirho(
        previous_chirho
            .iter()
            .map(|b_chirho| format!("{b_chirho:02x}"))
            .collect(),
    )
}

/// The currently-active nodes after folding a verified roster: node public key -> region label.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct VerifiedMembershipChirho {
    active_chirho: BTreeMap<String, String>,
}

impl VerifiedMembershipChirho {
    /// Is this node public key an active, operator-authorized replication source?
    pub fn is_active_source_chirho(&self, node_pubkey_hex_chirho: &str) -> bool {
        self.active_chirho.contains_key(node_pubkey_hex_chirho)
    }

    /// The declared region of an active node, if present.
    pub fn region_of_chirho(&self, node_pubkey_hex_chirho: &str) -> Option<&str> {
        self.active_chirho
            .get(node_pubkey_hex_chirho)
            .map(|s_chirho| s_chirho.as_str())
    }

    /// Count of active nodes.
    pub fn active_count_chirho(&self) -> usize {
        self.active_chirho.len()
    }

    /// The active member pubkeys, sorted (the `BTreeMap` key order) — for a consumer that must iterate the
    /// membership (e.g. the roster-derived config generator joining membership to network records).
    pub fn active_pubkeys_chirho(&self) -> impl Iterator<Item = &String> {
        self.active_chirho.keys()
    }
}

/// Read an operator-supplied roster JSONL as raw non-empty lines. Signature and semantic
/// verification remain separate so every consumer must name its pinned operator key explicitly.
/// Centralizing this bounded parser prevents the HTTP, S3, and replica-serve composition roots
/// from developing subtly different empty-line or empty-roster behavior.
pub fn read_membership_roster_lines_chirho(path_chirho: &Path) -> Result<Vec<Vec<u8>>> {
    let text_chirho = std::fs::read_to_string(path_chirho)
        .with_context(|| format!("read membership roster {}", path_chirho.display()))?;
    let lines_chirho: Vec<Vec<u8>> = text_chirho
        .lines()
        .filter(|line_chirho| !line_chirho.trim().is_empty())
        .map(|line_chirho| line_chirho.as_bytes().to_vec())
        .collect();
    if lines_chirho.is_empty() {
        bail!("membership roster {} has no records", path_chirho.display());
    }
    Ok(lines_chirho)
}

/// Verify a roster (its JSONL lines) against the PINNED operator public key and fold it into the set
/// of currently-active nodes. Every record must be signed by the operator key, carry that operator
/// key id, and be sequenced contiguously from 0; any failure fails the whole roster closed (a replica
/// must not act on a partially-trusted membership view).
pub fn verify_membership_roster_lines_chirho(
    lines_chirho: &[Vec<u8>],
    operator_pubkey_hex_chirho: &str,
) -> Result<VerifiedMembershipChirho> {
    let mut active_chirho: BTreeMap<String, String> = BTreeMap::new();
    for (index_chirho, line_chirho) in lines_chirho.iter().enumerate() {
        // The roster log may also carry sibling records (node-network, preferred-leader); they share the
        // `seq`/line-index space (so `seq == index` still holds for membership records) but are other
        // verifiers' concern. Skip them by schema — a membership-only roster is unaffected; an unknown
        // schema is NOT skipped and fails closed at the schema check below.
        let schema_chirho = peek_schema_chirho(line_chirho)?;
        if is_other_known_roster_schema_chirho(
            &schema_chirho,
            MEMBERSHIP_ROSTER_RECORD_SCHEMA_CHIRHO,
        ) {
            continue;
        }
        let record_chirho: MembershipRosterRecordChirho = serde_json::from_slice(line_chirho)?;
        if record_chirho.schema_chirho != MEMBERSHIP_ROSTER_RECORD_SCHEMA_CHIRHO {
            bail!(
                "membership roster record {} has unexpected schema '{}'",
                index_chirho,
                record_chirho.schema_chirho
            );
        }
        if record_chirho.seq_chirho != index_chirho as u64 {
            bail!(
                "membership roster seq {} is not contiguous (expected {})",
                record_chirho.seq_chirho,
                index_chirho
            );
        }
        if record_chirho.operator_key_id_chirho != operator_pubkey_hex_chirho {
            bail!(
                "membership roster record operator key id does not match the pinned operator key"
            );
        }
        let message_chirho = unsigned_membership_roster_message_chirho(&record_chirho)?;
        if !verify_with_pubkey_chirho(
            operator_pubkey_hex_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "membership roster record {index_chirho} signature is invalid for the operator key"
            );
        }
        match record_chirho.action_chirho {
            MembershipActionChirho::AddNodeChirho => {
                active_chirho.insert(
                    record_chirho.node_pubkey_hex_chirho,
                    record_chirho.region_label_chirho,
                );
            }
            MembershipActionChirho::RemoveNodeChirho => {
                active_chirho.remove(&record_chirho.node_pubkey_hex_chirho);
            }
        }
    }
    Ok(VerifiedMembershipChirho { active_chirho })
}

/// Verify a roster against a SIGNED roster HEAD and the pinned operator key, THEN fold it. The head is
/// the length witness: it pins the exact record count and the prefix digest, so a truncated tail (which
/// would silently re-add a revoked node) or any line tamper fails closed here — before the per-record
/// verification and fold. The roster and its head are versioned together, so the delivered roster must
/// have exactly the signed count (an appended forged tail is rejected too). Use this whenever the roster
/// is not an operator-supplied trusted input — e.g. carried over untrusted transport.
pub fn verify_membership_roster_with_head_chirho(
    lines_chirho: &[Vec<u8>],
    head_bytes_chirho: &[u8],
    operator_pubkey_hex_chirho: &str,
) -> Result<VerifiedMembershipChirho> {
    let head_chirho: MembershipRosterHeadChirho = serde_json::from_slice(head_bytes_chirho)?;
    if head_chirho.schema_chirho != MEMBERSHIP_ROSTER_HEAD_SCHEMA_CHIRHO {
        bail!(
            "membership roster head has unexpected schema '{}'",
            head_chirho.schema_chirho
        );
    }
    if head_chirho.operator_key_id_chirho != operator_pubkey_hex_chirho {
        bail!("membership roster head operator key id does not match the pinned operator key");
    }
    let message_chirho = unsigned_membership_roster_head_message_chirho(&head_chirho)?;
    if !verify_with_pubkey_chirho(
        operator_pubkey_hex_chirho,
        &message_chirho,
        &head_chirho.sig_chirho,
    )? {
        bail!("membership roster head signature is invalid for the operator key");
    }
    // Length witness: exact count + prefix digest must match the operator-signed head. A dropped tail,
    // an appended forged record, or any line tamper fails here before the roster is trusted.
    if lines_chirho.len() as u64 != head_chirho.roster_record_count_chirho {
        bail!(
            "membership roster has {} records, not the operator-signed {} (truncation/tamper)",
            lines_chirho.len(),
            head_chirho.roster_record_count_chirho
        );
    }
    let digest_chirho = roster_prefix_digest_chirho(lines_chirho);
    if digest_chirho != head_chirho.roster_prefix_digest_chirho {
        bail!(
            "membership roster prefix digest does not match the operator-signed head (truncation/tamper)"
        );
    }
    verify_membership_roster_lines_chirho(lines_chirho, operator_pubkey_hex_chirho)
}
