// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Public protocol constants the production credits-demo LocalPhaseB command uses (the checked-in
//! app name, the balance projection name, the F2 external-provider seed coordinates, the spend
//! contract, and the priced effect). These are public protocol values — NOT custody secrets; the
//! signer/issuer/adapter/DSN key bytes and the plan/config are operator-reviewed inputs resolved
//! from the config + secret store, and the keyed seed FINGERPRINT is recomputed from the ACTUAL
//! configured adapter key at preflight (#6046 — never a constant expectation in production).

/// The checked-in credits-demo app name (matches `examples-chirho/tree-credits-demo-chirho`).
pub const APP_CHIRHO: &str = "credits-demo-chirho";

/// The credits-demo balance projection name — the packet projection-evidence row and the config
/// serve route are both exact-selected by this name (never positionally).
pub const BALANCE_PROJECTION_NAME_CHIRHO: &str = "credits-balance-chirho";

/// The reviewed LocalPhaseB plan/config coordinates shared by the production input author and the
/// deterministic test fixture. The values are public protocol coordinates; only the secret-store
/// VALUES behind the bounded ref names are private and operator-generated.
pub const SETTLEMENT_OWNER_CHIRHO: &str = "credits-demo-settlement-chirho";
pub const FRESH_PARENT_CHIRHO: &str = "credits-demo-localphaseb-parent-chirho";
pub const STAGING_PARENT_CHIRHO: &str = "credits-demo-localphaseb-staging-chirho";
pub const STORAGE_NAMESPACE_CHIRHO: &str = "credits-demo-localphaseb-parent-chirho/ledger-chirho";
pub const REVIEWED_INPUTS_DIR_CHIRHO: &str = "reviewed-inputs-chirho";
pub const HOST_CONFIG_FILE_CHIRHO: &str = "host-config-chirho.toml";
pub const REVIEWED_CANDIDATE_POINTER_FILE_CHIRHO: &str =
    "credits-demo-reviewed-candidate-chirho.json";
pub const MONITOR_NAMESPACE_CHIRHO: &str = "credits-demo-localphaseb-parent-chirho/ops-chirho";
pub const MONITOR_EVIDENCE_PATH_CHIRHO: &str = "monitor/cycles-chirho.jsonl";
pub const MONEY_GROUP_ID_CHIRHO: &str = "money-group-credits-demo-localphaseb-chirho";
pub const CLUSTER_ID_CHIRHO: &str = "cluster-credits-demo-localphaseb-chirho";
pub const JOURNAL_PATH_CHIRHO: &str = "journals/main-chirho.jsonl";
pub const LOCAL_EPOCH_CHIRHO: u64 = 7;
pub const KIND_REGISTRY_PATH_CHIRHO: &str = "registries/kinds-chirho.jsonl";
pub const KIND_REGISTRY_ID_CHIRHO: &str = "kind-registry-credits-demo-localphaseb-chirho";
pub const PROJECTION_REGISTRY_PATH_CHIRHO: &str = "registries/projections-chirho.jsonl";
pub const PROJECTION_REGISTRY_ID_CHIRHO: &str =
    "projection-registry-credits-demo-localphaseb-chirho";
pub const SOURCE_REGISTRY_PATH_CHIRHO: &str = "registries/sources-chirho.jsonl";
pub const SOURCE_REGISTRY_ID_CHIRHO: &str = "source-registry-credits-demo-localphaseb-chirho";
pub const BALANCE_HEAD_PATH_CHIRHO: &str = "published/credits-balance-head-chirho.json";
pub const MIRROR_PROJECTION_NAME_CHIRHO: &str = "credits-mirror-chirho";
pub const MIRROR_HEAD_PATH_CHIRHO: &str = "published/credits-mirror-head-chirho.json";
pub const MONITOR_CADENCE_MS_CHIRHO: u64 = 60_000;
pub const ISSUER_PRINCIPAL_CHIRHO: &str = "credits-demo-kind-issuer-chirho";
pub const ACTIVATION_PRINCIPAL_CHIRHO: &str = "credits-demo-ledger-activation-chirho";
pub const BILLING_KIND_CHIRHO: &str = "prepaid-credits-chirho";
pub const INITIAL_MINT_AMOUNT_CHIRHO: u64 = 750;
pub const GENESIS_PHYSICAL_MS_CHIRHO: u64 = 5_000;
pub const MINT_PHYSICAL_MS_CHIRHO: u64 = 5_250;
pub const IDEMPOTENCY_HORIZON_MS_CHIRHO: u64 = 86_400_000;
pub const RETRY_FINALITY_HORIZON_MS_CHIRHO: u64 = 86_400_000;

pub const JOURNAL_SECRET_NAME_CHIRHO: &str = "credits-demo-journal-secret-chirho";
pub const CONFIG_SECRET_NAME_CHIRHO: &str = "credits-demo-config-secret-chirho";
pub const FEEDER_SECRET_NAME_CHIRHO: &str = "credits-demo-feeder-secret-chirho";
pub const KIND_ROOT_SECRET_NAME_CHIRHO: &str = "credits-demo-kind-root-secret-chirho";
pub const EFFECT_INTENT_SECRET_NAME_CHIRHO: &str = "credits-demo-effect-intent-secret-chirho";
pub const EFFECT_TERMINAL_SECRET_NAME_CHIRHO: &str = "credits-demo-effect-terminal-secret-chirho";
pub const DEFAULT_ISSUER_SECRET_NAME_CHIRHO: &str = "credits-demo-offline-issuer-chirho";
pub const DEFAULT_ACTIVATION_SECRET_NAME_CHIRHO: &str = "credits-demo-offline-activation-chirho";
pub const ACTIVATION_AUTHORIZATION_FILE_NAME_CHIRHO: &str =
    "credits-demo-activation-authorization-chirho.json";
pub const DSN_SECRET_NAME_CHIRHO: &str = "credits-demo-pg-dsn-chirho";
pub const DEFAULT_PAYER_CREDENTIAL_SECRET_NAME_CHIRHO: &str =
    "credits-demo-payer-credential-chirho";

/// F2 operator-established (never cairn-minted) external provider preconditions. The seed value is
/// keyed-fingerprinted with the CONFIGURED adapter evidence key at preflight; the L2 spend
/// concurrency token equals that recomputed fingerprint (the spend's expected before-state),
/// binding the token to the seed under the actual operator custody.
pub const FIXED_SUBJECT_CHIRHO: &str =
    "81b8078f2e6771d23a2f3ff001d4229370708ea97389ba5ba3372b300cbf8508";
pub const FIXED_ROW_KEY_CHIRHO: &str =
    "62c2bd5bd145a1a00e980f80e14f30cd61da58755a4ccb17b64dbe407a628ef4";
pub const SEED_VALUE_CHIRHO: &[u8] = b"render-run-ready-chirho";

/// The bounded spend form contract (the app supplies no amount, price, payer, or provider mode).
pub const SPEND_ITEM_CHIRHO: &str = "render-run-chirho";
/// The spend route label (the effect-bearing route whose dag carries the postgres effect).
pub const SPEND_ROUTE_CHIRHO: &str = "spend-chirho";
pub const POSTGRES_REVERSIBLE_EFFECT_CHIRHO: &str = "postgres_reversible_chirho";
pub const POSTGRES_REVERSIBLE_PRICE_CHIRHO: i64 = 10;

/// The 3 external reversible tables the operator-direct schema install creates; preflight requires
/// ALL of them present (never only the seed table).
pub const REVERSIBLE_TABLES_CHIRHO: [&str; 3] = [
    "cairn_reversible_values_chirho",
    "cairn_reversible_forward_decisions_chirho",
    "cairn_reversible_comp_receipts_chirho",
];

/// The FROZEN wave-1 money-spine delete-candidate marker names (#6058/#6060/#6065): EXACT
/// file/dir names sourced from the sealed wave-1 delete-candidate set — deliberately NOT imported
/// from the live legacy path helpers, because this census must OUTLIVE the deleted code (the
/// cfg(test) pre-delete superset test binds this list to the live names and dies with the
/// delete). `head-removals-chirho.jsonl` is deliberately ABSENT: it is a KEPT generic
/// head-removal surface (app/privacy/compliance), not legacy money spine.
pub const MONEY_SPINE_MARKER_NAMES_CHIRHO: [&str; 16] = [
    "billing-compensations-chirho.jsonl",
    "billing-policy-records-chirho.jsonl",
    "billing-usage-chirho.jsonl",
    "coupon-issues-chirho.jsonl",
    "coupon-redemptions-chirho.jsonl",
    "credit-holds-chirho.jsonl",
    "external-usage-chirho.jsonl",
    "gate1-authority-head-chirho",
    "gate1-authority-log-chirho.jsonl",
    "gate1-log-anchors-chirho.jsonl",
    "ledger-chirho.jsonl",
    "provider-price-records-chirho.jsonl",
    "resource-policy-records-chirho.jsonl",
    "resource-policy-unset-records-chirho.jsonl",
    "resource-usage-chirho.jsonl",
    "stripe-identity-verifications-chirho.jsonl",
];

/// The adapter-evidence secret name (a bounded ref name, resolved from the operator secret store).
pub const ADAPTER_EVIDENCE_SECRET_NAME_CHIRHO: &str =
    cairn_chirho::effect_chirho::postgres_reversible_chirho::ADAPTER_EVIDENCE_SECRET_NAME_CHIRHO;

/// Deterministic-fixture integration pin ONLY (#6046): under the cfg(test) fixture's public
/// `[0x33; 32]` adapter key, the recomputed keyed seed fingerprint must reproduce this exact
/// value. The production path NEVER compares against it.
#[cfg(test)]
pub const FIXTURE_SEED_FINGERPRINT_CHIRHO: &str =
    "43a6150b9bfe41bd8980ded6f7900d50021ae1ac4b1210570c663a96744ac6b8";
