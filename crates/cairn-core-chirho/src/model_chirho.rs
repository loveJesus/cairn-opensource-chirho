// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! The node contract — the data model of cairn-chirho.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A blake3 content hash (hex). The identity of every object in the store. NOT sha1.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct HashChirho(pub String);

/// The authority-independent identity of one consistency group.
///
/// This value lives below `cairn-writer-head-chirho` so read-only roster and placement verifiers can
/// bind group coordinates without acquiring the crate that can issue fences and mutate heads.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind_chirho")]
pub enum ConsistencyGroupIdChirho {
    TenantChirho { tenant_id_chirho: String },
    RootPathChirho { canonical_root_chirho: String },
}

impl ConsistencyGroupIdChirho {
    /// The one stable, variant-prefixed string form used by signed operator coordinates.
    pub fn canonical_id_chirho(&self) -> String {
        match self {
            Self::TenantChirho { tenant_id_chirho } => {
                format!("tenant-chirho:{tenant_id_chirho}")
            }
            Self::RootPathChirho {
                canonical_root_chirho,
            } => format!("root-path-chirho:{canonical_root_chirho}"),
        }
    }
}

/// The raw group digest used only as a storage-key component.
///
/// Signed coordinates use [`tagged_writer_fence_group_digest_chirho`] instead, so their domain is
/// explicit at the wire boundary.
pub fn consistency_group_storage_hash_chirho(
    group_chirho: &ConsistencyGroupIdChirho,
) -> Result<String> {
    Ok(blake3::hash(&serde_json::to_vec(group_chirho)?)
        .to_hex()
        .to_string())
}

/// Domain-shaped digest carried by writer-fence and canary coordinates.
///
/// This proves domain and shape, not a binding to any particular group. Consumers independently
/// derive the expected value from their [`ConsistencyGroupIdChirho`] and compare it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct TaggedWriterFenceGroupDigestChirho(String);

impl TaggedWriterFenceGroupDigestChirho {
    pub fn as_str_chirho(&self) -> &str {
        &self.0
    }

    pub fn into_string_chirho(self) -> String {
        self.0
    }
}

impl<'de_chirho> Deserialize<'de_chirho> for TaggedWriterFenceGroupDigestChirho {
    fn deserialize<DeserializerChirho>(
        deserializer_chirho: DeserializerChirho,
    ) -> std::result::Result<Self, DeserializerChirho::Error>
    where
        DeserializerChirho: serde::Deserializer<'de_chirho>,
    {
        let encoded_chirho = String::deserialize(deserializer_chirho)?;
        parse_tagged_writer_fence_group_digest_chirho(encoded_chirho)
            .map_err(serde::de::Error::custom)
    }
}

fn parse_tagged_writer_fence_group_digest_chirho(
    encoded_chirho: String,
) -> Result<TaggedWriterFenceGroupDigestChirho> {
    let Some(digest_chirho) = encoded_chirho.strip_prefix("writer-fence-group-blake3-chirho:")
    else {
        bail!("TaggedWriterFenceGroupDigestDomainRefusedChirho");
    };
    if digest_chirho.len() != 64
        || !digest_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
    {
        bail!("TaggedWriterFenceGroupDigestShapeRefusedChirho");
    }
    Ok(TaggedWriterFenceGroupDigestChirho(encoded_chirho))
}

pub fn tagged_writer_fence_group_digest_chirho(
    group_chirho: &ConsistencyGroupIdChirho,
) -> Result<TaggedWriterFenceGroupDigestChirho> {
    parse_tagged_writer_fence_group_digest_chirho(format!(
        "writer-fence-group-blake3-chirho:{}",
        consistency_group_storage_hash_chirho(group_chirho)?
    ))
}

pub fn consistency_group_digest_chirho(group_chirho: &ConsistencyGroupIdChirho) -> Result<String> {
    Ok(tagged_writer_fence_group_digest_chirho(group_chirho)?.into_string_chirho())
}

pub const SKIPPED_STONE_SCHEMA_CHIRHO: &str = "skipped-stone-v1-chirho";
pub const SKIPPED_STONE_BYTES_CHIRHO: &[u8] =
    br#"{"schema_chirho":"skipped-stone-v1-chirho","skipped_chirho":true}"#;
pub const BUILTIN_PHI_IMPL_CHIRHO: &str = "builtin-phi-v1-chirho";
pub const BUILTIN_PHI_ENTRY_CHIRHO: &str = "phi_chirho";
/// The `impl_wasm_chirho` sentinel prefix marking a Tier-2 NATIVE (native-program) node. Defined
/// here (not in the root native worker) so every consumer — the root executor AND the read-only
/// replica pure-executor, which must FAIL CLOSED on native nodes — classifies against ONE
/// definition and cannot drift across the authority boundary.
pub const NATIVE_NODE_IMPL_PREFIX_CHIRHO: &str = "native-program:";
pub const DEFAULT_NODE_MAX_OUTPUT_BYTES_CHIRHO: u64 = 10 * 1024 * 1024;
pub const DEFAULT_NODE_MAX_MEMORY_BYTES_CHIRHO: u64 = 256 * 1024 * 1024;

pub fn is_skipped_stone_bytes_chirho(bytes_chirho: &[u8]) -> bool {
    bytes_chirho == SKIPPED_STONE_BYTES_CHIRHO
}

pub fn builtin_phi_impl_hash_chirho() -> HashChirho {
    HashChirho(BUILTIN_PHI_IMPL_CHIRHO.to_string())
}

pub fn builtin_phi_node_def_chirho(
    name_chirho: &str,
    input_ports_chirho: &[String],
    output_port_chirho: &str,
    schema_chirho: HashChirho,
) -> NodeDefChirho {
    NodeDefChirho {
        name_chirho: name_chirho.to_string(),
        impl_wasm_chirho: builtin_phi_impl_hash_chirho(),
        entry_chirho: BUILTIN_PHI_ENTRY_CHIRHO.to_string(),
        inputs_chirho: input_ports_chirho
            .iter()
            .map(|port_chirho| PortChirho {
                name_chirho: port_chirho.clone(),
                schema_chirho: schema_chirho.clone(),
            })
            .collect(),
        outputs_chirho: vec![PortChirho {
            name_chirho: output_port_chirho.to_string(),
            schema_chirho,
        }],
        capabilities_chirho: vec![],
        effect_contract_set_chirho: None,
        fuel_limit_chirho: 0,
        max_output_bytes_chirho: DEFAULT_NODE_MAX_OUTPUT_BYTES_CHIRHO,
        max_memory_bytes_chirho: DEFAULT_NODE_MAX_MEMORY_BYTES_CHIRHO,
    }
}

pub fn default_node_max_output_bytes_chirho() -> u64 {
    DEFAULT_NODE_MAX_OUTPUT_BYTES_CHIRHO
}

pub fn default_node_max_memory_bytes_chirho() -> u64 {
    DEFAULT_NODE_MAX_MEMORY_BYTES_CHIRHO
}

/// What I/O a node may perform. An empty capability set ⇒ pure ⇒ cacheable.
/// The capability set — not a self-declared flag — is what makes purity *enforceable*.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapabilityChirho {
    ReadStoreChirho {
        prefix_chirho: String,
    },
    WriteStoreChirho {
        prefix_chirho: String,
    },
    PaidEffectChirho {
        effect_chirho: String,
        caller_chirho: String,
    },
    UserIdentityChirho {
        principal_chirho: String,
        client_id_chirho: String,
        token_hash_chirho: String,
    },
    AppContextChirho {
        app_chirho: String,
        owner_principal_chirho: String,
        price_book_chirho: Option<HashChirho>,
        billing_policy_chirho: Option<HashChirho>,
    },
    SecretRefChirho {
        name_chirho: String,
    },
    RealtimeSessionChirho {
        app_chirho: String,
        caller_chirho: String,
    },
    SupportIssueChirho {
        issue_chirho: String,
        actions_chirho: Vec<String>,
    },
    CausalReversionChirho {
        branch_chirho: String,
    },
    NetChirho {
        allowlist_chirho: Vec<String>,
    },
    QueryChirho {
        prefix_chirho: String,
        caller_chirho: String,
        max_rows_chirho: u64,
    },
    ClockChirho,
    RandomChirho,
    InvokeChirho {
        node_chirho: HashChirho,
    },
    TemplateAppDeployChirho {
        template_id_chirho: String,
    },
}

/// How a blessed effect says it can be compensated during causal reversion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompensationKindChirho {
    FullInverseChirho,
    CorrectiveForwardChirho,
    PartialChirho {
        unsupported_aspects_chirho: Vec<String>,
    },
    ManualRemediationChirho {
        template_chirho: String,
    },
    NotApplicableChirho {
        reason_chirho: String,
    },
}

/// Request-time attribution injected by serve for app DAG runs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestContextChirho {
    pub user_principal_chirho: String,
    pub app_chirho: String,
    pub owner_principal_chirho: String,
    pub client_id_chirho: String,
    pub token_hash_chirho: String,
    pub price_book_chirho: Option<HashChirho>,
    pub billing_policy_chirho: Option<HashChirho>,
    /// Present only for a request authenticated by a limited key: what its matched grant lets the request touch. The
    /// viewer-state door refuses any logical key outside it. Skipped when absent, so a cookie or legacy context
    /// serializes, and hashes, exactly as before limited keys existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_limit_chirho: Option<RequestKeyLimitChirho>,
}

/// The limit a limited key's request carries: the action its grant is for, and the logical resources that grant
/// consented to.
/// Workflow: limited-key authority (K1),
/// `spec-chirho/workflows-chirho/identity-auth-chirho/limited-key-authority-chirho.md`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestKeyLimitChirho {
    pub action_chirho: String,
    pub resources_chirho: Vec<String>,
}

/// A typed port on a node. The schema is itself content-addressed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortChirho {
    pub name_chirho: String,
    pub schema_chirho: HashChirho,
}

/// An immutable node definition. Identity = hash(NodeDefChirho), so editing = a new version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeDefChirho {
    pub name_chirho: String,
    /// The WASM module, content-addressed (`impl` is a Rust keyword, hence `impl_wasm_chirho`).
    pub impl_wasm_chirho: HashChirho,
    pub entry_chirho: String,
    pub inputs_chirho: Vec<PortChirho>,
    pub outputs_chirho: Vec<PortChirho>,
    /// The only I/O this node may do. Empty ⇒ pure.
    pub capabilities_chirho: Vec<CapabilityChirho>,
    /// The exact descriptor-v2 contract set governing every effect door on this node.
    ///
    /// `None` is the byte-stable pre-v2 identity. A new reviewed v2 node carries one set digest;
    /// each invoked capability then resolves its own door under that complete set. The node never
    /// duplicates per-door contract keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_contract_set_chirho: Option<HashChirho>,
    pub fuel_limit_chirho: u64,
    #[serde(default = "default_node_max_output_bytes_chirho")]
    pub max_output_bytes_chirho: u64,
    #[serde(default = "default_node_max_memory_bytes_chirho")]
    pub max_memory_bytes_chirho: u64,
}

impl Default for NodeDefChirho {
    fn default() -> Self {
        Self {
            name_chirho: String::new(),
            impl_wasm_chirho: HashChirho(String::new()),
            entry_chirho: String::new(),
            inputs_chirho: Vec::new(),
            outputs_chirho: Vec::new(),
            capabilities_chirho: Vec::new(),
            effect_contract_set_chirho: None,
            fuel_limit_chirho: 0,
            max_output_bytes_chirho: DEFAULT_NODE_MAX_OUTPUT_BYTES_CHIRHO,
            max_memory_bytes_chirho: DEFAULT_NODE_MAX_MEMORY_BYTES_CHIRHO,
        }
    }
}

impl NodeDefChirho {
    /// Pure ⇔ no capabilities ⇒ output is a function of inputs ⇒ memoizable.
    pub fn is_pure_chirho(&self) -> bool {
        self.capabilities_chirho.is_empty()
    }

    pub fn is_builtin_phi_chirho(&self) -> bool {
        self.impl_wasm_chirho.0 == BUILTIN_PHI_IMPL_CHIRHO
            && self.entry_chirho == BUILTIN_PHI_ENTRY_CHIRHO
            && self.capabilities_chirho.is_empty()
    }
}

#[cfg(test)]
mod model_tests_chirho {
    use super::*;
    use crate::store_chirho::hash_object_chirho;

    const LEGACY_NODE_BYTES_CHIRHO: &[u8] = br#"{"name_chirho":"legacy-node-chirho","impl_wasm_chirho":"legacy-impl-chirho","entry_chirho":"legacy-entry-chirho","inputs_chirho":[],"outputs_chirho":[],"capabilities_chirho":[],"fuel_limit_chirho":0,"max_output_bytes_chirho":10485760,"max_memory_bytes_chirho":268435456}"#;
    const LEGACY_NODE_HASH_CHIRHO: &str =
        "86af963144df4b72c003c0e1cd5f176bb8f5a81e0d0ddec40bbdb9b64a23adbd";

    fn legacy_node_chirho() -> NodeDefChirho {
        NodeDefChirho {
            name_chirho: "legacy-node-chirho".to_string(),
            impl_wasm_chirho: HashChirho("legacy-impl-chirho".to_string()),
            entry_chirho: "legacy-entry-chirho".to_string(),
            inputs_chirho: Vec::new(),
            outputs_chirho: Vec::new(),
            capabilities_chirho: Vec::new(),
            effect_contract_set_chirho: None,
            fuel_limit_chirho: 0,
            max_output_bytes_chirho: DEFAULT_NODE_MAX_OUTPUT_BYTES_CHIRHO,
            max_memory_bytes_chirho: DEFAULT_NODE_MAX_MEMORY_BYTES_CHIRHO,
        }
    }

    #[test]
    fn legacy_none_contract_set_is_byte_and_hash_stable_chirho() {
        let node_chirho = legacy_node_chirho();
        assert_eq!(
            serde_json::to_vec(&node_chirho).unwrap(),
            LEGACY_NODE_BYTES_CHIRHO
        );
        assert_eq!(
            hash_object_chirho(&node_chirho).unwrap().0,
            LEGACY_NODE_HASH_CHIRHO
        );
    }

    #[test]
    fn v2_contract_set_moves_node_identity_chirho() {
        let legacy_chirho = legacy_node_chirho();
        let mut v2_chirho = legacy_chirho.clone();
        v2_chirho.effect_contract_set_chirho = Some(HashChirho("11".repeat(32)));

        let v2_bytes_chirho = serde_json::to_vec(&v2_chirho).unwrap();
        assert!(String::from_utf8(v2_bytes_chirho)
            .unwrap()
            .contains("\"effect_contract_set_chirho\":\"1111111111111111111111111111111111111111111111111111111111111111\""));
        assert_ne!(
            hash_object_chirho(&legacy_chirho).unwrap(),
            hash_object_chirho(&v2_chirho).unwrap()
        );
    }
}

/// The wiring of nodes into a graph. Content-addressed, hence versioned.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DagChirho {
    pub nodes_chirho: Vec<HashChirho>,
    pub edges_chirho: Vec<EdgeChirho>,
}

/// One public module boundary port bound to a real port on a node inside the wrapped DAG.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DagModulePortChirho {
    pub public_port_chirho: PortChirho,
    pub node_chirho: HashChirho,
    pub node_port_chirho: String,
}

/// A content-addressed wrapper around a DagChirho, exposing typed external ports without changing
/// the wrapped DAG's identity or run-cache semantics.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DagModuleChirho {
    pub name_chirho: String,
    pub dag_chirho: HashChirho,
    pub version_chirho: String,
    pub previous_module_chirho: Option<HashChirho>,
    pub inputs_chirho: Vec<DagModulePortChirho>,
    pub outputs_chirho: Vec<DagModulePortChirho>,
    pub route_labels_chirho: Vec<String>,
    pub metadata_chirho: BTreeMap<String, String>,
}

/// One named instance of a DagModuleChirho inside a module composition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DagModuleInstanceChirho {
    pub instance_chirho: String,
    pub module_chirho: HashChirho,
}

/// A typed cross-module edge from one module output to another module input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DagModuleWireChirho {
    pub from_instance_chirho: String,
    pub from_port_chirho: String,
    pub to_instance_chirho: String,
    pub to_port_chirho: String,
}

/// One public composition boundary port bound to a module instance's public port.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DagModuleCompositionPortChirho {
    pub public_port_chirho: PortChirho,
    pub instance_chirho: String,
    pub module_port_chirho: String,
}

/// A content-addressed module composition that expands to an ordinary DagChirho for execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DagModuleCompositionChirho {
    pub name_chirho: String,
    pub version_chirho: String,
    pub instances_chirho: Vec<DagModuleInstanceChirho>,
    pub wires_chirho: Vec<DagModuleWireChirho>,
    pub inputs_chirho: Vec<DagModuleCompositionPortChirho>,
    pub outputs_chirho: Vec<DagModuleCompositionPortChirho>,
    pub composed_dag_chirho: HashChirho,
    pub metadata_chirho: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeChirho {
    pub from_node_chirho: HashChirho,
    pub from_port_chirho: String,
    pub to_node_chirho: HashChirho,
    pub to_port_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy_chirho: Option<EdgePrivacyChirho>,
}

/// Storage policy for values crossing a DAG edge. Plain edges keep legacy CAS behavior; private
/// edges keep the value hash as the provenance/cache anchor while storing bytes in a subject-bound
/// private blob.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind_chirho", rename_all = "kebab-case")]
pub enum EdgePrivacyChirho {
    PrivateBlobRefChirho {
        subject_source_chirho: EdgePrivacySubjectSourceChirho,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EdgePrivacySubjectSourceChirho {
    RequestUserChirho,
    AppSubjectChirho,
    StaticSubjectChirho { subject_chirho: String },
}

/// The cache key / version coordinate of one application of a node to inputs.
/// `hash(RunKeyChirho)` is the run id — same code + inputs ⇒ same id ⇒ cache hit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunKeyChirho {
    pub node_chirho: HashChirho,
    /// port -> content hash (BTreeMap ⇒ stable, order-independent hashing).
    pub inputs_chirho: BTreeMap<String, HashChirho>,
    pub caps_chirho: HashChirho,
}

/// One logged side effect (every "POST"). Append-only; never mutated.
/// Rollback of an effect is a *compensating* effect, never an erasure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectChirho {
    pub seq_chirho: u64,
    pub capability_chirho: CapabilityChirho,
    pub request_chirho: HashChirho,
    /// Idempotency key — makes at-least-once retries safe.
    pub idem_key_chirho: HashChirho,
    /// None ⇒ pending.
    pub response_chirho: Option<HashChirho>,
    /// Signature by the node's key — tamper-evidence + sender authentication.
    pub sig_chirho: String,
    /// RFC3339 (epoch-ms for now) timestamp.
    pub at_chirho: String,
}

/// The canonical bytes signed for an [`EffectChirho`].
///
/// Kept with the model so every read-only verifier uses the same signed field set as the runtime
/// that creates effects. The timestamp is deliberately excluded for compatibility with the
/// existing effect signature contract; changing this payload is a wire-format migration.
pub fn effect_signing_message_chirho(effect_chirho: &EffectChirho) -> serde_json::Result<Vec<u8>> {
    #[derive(Serialize)]
    struct EffectSigPayloadChirho<'a> {
        seq_chirho: u64,
        capability_chirho: &'a CapabilityChirho,
        request_chirho: &'a HashChirho,
        idem_key_chirho: &'a HashChirho,
        response_chirho: &'a Option<HashChirho>,
    }

    serde_json::to_vec(&EffectSigPayloadChirho {
        seq_chirho: effect_chirho.seq_chirho,
        capability_chirho: &effect_chirho.capability_chirho,
        request_chirho: &effect_chirho.request_chirho,
        idem_key_chirho: &effect_chirho.idem_key_chirho,
        response_chirho: &effect_chirho.response_chirho,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunStatusChirho {
    OkChirho,
    FailedChirho { reason_chirho: String },
    CachedChirho,
    SkippedChirho { reason_chirho: String },
}

/// The result of a run — simultaneously cache entry, provenance record, and audit node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunResultChirho {
    /// = hash(RunKeyChirho).
    pub run_chirho: HashChirho,
    pub outputs_chirho: BTreeMap<String, HashChirho>,
    pub effects_chirho: Vec<EffectChirho>,
    pub fuel_used_chirho: u64,
    /// LLM-legible span, content-addressed.
    pub trace_chirho: HashChirho,
    pub status_chirho: RunStatusChirho,
    /// Upstream runs — the Merkle DAG edges / provenance chain.
    pub parents_chirho: Vec<HashChirho>,
}

/// The ONLY mutable state in the system: git-like named pointers.
/// Rollback = move a ref back to an earlier hash.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefsChirho {
    /// name -> Dag/Run hash (movable).
    pub branches_chirho: BTreeMap<String, HashChirho>,
    /// name -> hash (immutable pins).
    pub tags_chirho: BTreeMap<String, HashChirho>,
    /// current branch name.
    pub head_chirho: String,
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn effect_signing_message_preserves_the_existing_wire_contract_chirho() {
        let effect_chirho = EffectChirho {
            seq_chirho: 3,
            capability_chirho: CapabilityChirho::ReadStoreChirho {
                prefix_chirho: "tenant/item-chirho".to_string(),
            },
            request_chirho: HashChirho("11".repeat(32)),
            idem_key_chirho: HashChirho("22".repeat(32)),
            response_chirho: None,
            sig_chirho: "not-signed-yet-chirho".to_string(),
            at_chirho: "timestamp-not-signed-chirho".to_string(),
        };

        assert_eq!(
            String::from_utf8(effect_signing_message_chirho(&effect_chirho).unwrap()).unwrap(),
            format!(
                "{{\"seq_chirho\":3,\"capability_chirho\":{{\"ReadStoreChirho\":{{\"prefix_chirho\":\"tenant/item-chirho\"}}}},\"request_chirho\":\"{}\",\"idem_key_chirho\":\"{}\",\"response_chirho\":null}}",
                "11".repeat(32),
                "22".repeat(32)
            ),
            "the effect signature payload is persisted protocol: field set and order must not drift"
        );
    }
}
