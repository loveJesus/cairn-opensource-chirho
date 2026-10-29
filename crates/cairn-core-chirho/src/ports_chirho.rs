// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! The cairn **ports** — the wasm-safe storage and execution traits the runtime depends on, so
//! adapters (memory, fs, redb, browser storage, …) can be swapped without leaking backend details.

use crate::cas_chirho::hash_chirho;
use crate::model_chirho::{HashChirho, NodeDefChirho};
use anyhow::Result as AnyResult;
use core::future::{ready, Future};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Typed storage-port error categories. Keep these broad: adapters can expose enough shape for callers
/// to distinguish I/O/backend/conflict/encoding faults without leaking redb/fs/browser-specific types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum StoreErrorKindChirho {
    IoChirho,
    EncodeChirho,
    InvalidChirho,
    ConflictChirho,
    BackendChirho,
}

/// Typed error at the storage port boundary. Runtime code can still lift it into `anyhow`, but the
/// port itself no longer erases every adapter failure into an unstructured error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct StoreErrorChirho {
    pub kind_chirho: StoreErrorKindChirho,
    pub message_chirho: String,
}

impl StoreErrorChirho {
    pub fn new_chirho(
        kind_chirho: StoreErrorKindChirho,
        message_chirho: impl Into<String>,
    ) -> Self {
        Self {
            kind_chirho,
            message_chirho: message_chirho.into(),
        }
    }

    pub fn invalid_chirho(message_chirho: impl Into<String>) -> Self {
        Self::new_chirho(StoreErrorKindChirho::InvalidChirho, message_chirho)
    }

    pub fn conflict_chirho(message_chirho: impl Into<String>) -> Self {
        Self::new_chirho(StoreErrorKindChirho::ConflictChirho, message_chirho)
    }

    pub fn backend_chirho(message_chirho: impl Into<String>) -> Self {
        Self::new_chirho(StoreErrorKindChirho::BackendChirho, message_chirho)
    }

    pub fn context_chirho(self, context_chirho: impl Into<String>) -> Self {
        Self {
            kind_chirho: self.kind_chirho,
            message_chirho: format!("{}: {}", context_chirho.into(), self.message_chirho),
        }
    }
}

impl fmt::Display for StoreErrorChirho {
    fn fmt(&self, f_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f_chirho, "{:?}: {}", self.kind_chirho, self.message_chirho)
    }
}

impl std::error::Error for StoreErrorChirho {}

impl From<std::io::Error> for StoreErrorChirho {
    fn from(error_chirho: std::io::Error) -> Self {
        Self::new_chirho(StoreErrorKindChirho::IoChirho, error_chirho.to_string())
    }
}

impl From<serde_json::Error> for StoreErrorChirho {
    fn from(error_chirho: serde_json::Error) -> Self {
        Self::new_chirho(StoreErrorKindChirho::EncodeChirho, error_chirho.to_string())
    }
}

impl From<anyhow::Error> for StoreErrorChirho {
    fn from(error_chirho: anyhow::Error) -> Self {
        Self::backend_chirho(format!("{error_chirho:#}"))
    }
}

pub type StoreResultChirho<T> = std::result::Result<T, StoreErrorChirho>;

/// Read half of the content-addressed plane: fetch bytes by address, and nothing else.
///
/// This exists so a read-only chain can be typed as read-only. A component that holds only a
/// `ContentReadChirho` **cannot name `put_chirho` at all** — writing is not refused at runtime, it
/// is absent from the type, so the compiler computes the confinement instead of a guard sampling
/// for it. The replica serve -> read-DAG -> pure-executor chain is typed on this port for exactly
/// that reason.
pub trait ContentReadChirho {
    /// Fetch bytes by content address; `None` if absent.
    fn get_chirho(&self, addr_chirho: &HashChirho) -> StoreResultChirho<Option<Vec<u8>>>;
}

/// Content-addressed byte store (the verifiable plane): bytes in → blake3 address out. The same
/// bytes always yield the same address, so `put_chirho` is idempotent. Bytes-first on purpose —
/// typed/canonical object helpers can layer on top without widening this port.
///
/// The read half lives in [`ContentReadChirho`]; this trait adds only the write. Every store is
/// therefore usable wherever a read port is wanted, while a read port can never widen into this
/// one.
pub trait ContentStoreChirho: ContentReadChirho {
    /// Store bytes; return their content address. Idempotent.
    fn put_chirho(&self, bytes_chirho: &[u8]) -> StoreResultChirho<HashChirho>;
}

/// Schema tag baked into every hashed audit record, so a future format change yields different
/// hashes instead of silently colliding with old records. Bump it when the record shape changes.
pub const AUDIT_RECORD_SCHEMA_CHIRHO: &str = "audit-record-v1";

/// One appended audit record. Fork-tolerant per-writer hash chain: each writer keeps its own
/// monotonic `local_seq_chirho`, and `prev_hash_chirho` links to that writer's previous record.
/// Two records sharing a `prev_hash_chirho` are a valid provenance fork, never an error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive] // construct via `new_chirho` only, so the schema tag is never omitted/mistyped
pub struct AuditRecordChirho {
    /// Format tag — always `AUDIT_RECORD_SCHEMA_CHIRHO`; part of the hashed payload.
    pub schema_chirho: String,
    pub writer_chirho: String,
    pub local_seq_chirho: u64,
    pub prev_hash_chirho: Option<HashChirho>,
    /// Opaque to the log. A signed event body lives here in a later brick.
    pub payload_chirho: Vec<u8>,
}

impl AuditRecordChirho {
    /// Build a record stamped with the current schema tag.
    pub fn new_chirho(
        writer_chirho: &str,
        local_seq_chirho: u64,
        prev_hash_chirho: Option<HashChirho>,
        payload_chirho: Vec<u8>,
    ) -> Self {
        Self {
            schema_chirho: AUDIT_RECORD_SCHEMA_CHIRHO.to_string(),
            writer_chirho: writer_chirho.to_string(),
            local_seq_chirho,
            prev_hash_chirho,
            payload_chirho,
        }
    }
}

/// The content address of a record = blake3 of its canonical JSON encoding. Defined once here so
/// every adapter hashes identically — that identity across backends is exactly what brick 1 proves.
pub fn record_hash_chirho(record_chirho: &AuditRecordChirho) -> StoreResultChirho<HashChirho> {
    let canonical_chirho = serde_json::to_vec(record_chirho)?;
    Ok(hash_chirho(&canonical_chirho))
}

/// Verify that bytes read from a content-addressed backend still match the address requested.
/// Adapters call this on read so local store tampering is surfaced before runtime code trusts bytes.
pub fn verify_content_address_chirho(
    addr_chirho: &HashChirho,
    bytes_chirho: &[u8],
) -> StoreResultChirho<()> {
    let actual_chirho = hash_chirho(bytes_chirho);
    if actual_chirho != addr_chirho.clone() {
        return Err(StoreErrorChirho::invalid_chirho(format!(
            "content address mismatch: requested {}, actual {}",
            addr_chirho.0, actual_chirho.0
        )));
    }
    Ok(())
}

/// Verify that a decoded audit record still hashes to the key/hash used to read it.
pub fn verify_audit_record_hash_chirho(
    expected_chirho: &HashChirho,
    record_chirho: &AuditRecordChirho,
) -> StoreResultChirho<()> {
    let actual_chirho = record_hash_chirho(record_chirho)?;
    if actual_chirho != expected_chirho.clone() {
        return Err(StoreErrorChirho::invalid_chirho(format!(
            "audit record hash mismatch: requested {}, actual {}",
            expected_chirho.0, actual_chirho.0
        )));
    }
    Ok(())
}

/// Append-only, fork-tolerant audit log. `append_chirho` chains a record after the writer's
/// current head and returns the new record's content hash (the writer's new head). `heads_chirho`
/// returns observed tips, not one canonical head. Strong cross-writer global ordering is a
/// SEPARATE, optional, non-portable `Sequencer` port (not defined here) — the runtime must be
/// correct without it.
pub trait AuditLogChirho {
    /// Append `payload_chirho` as `writer_chirho`'s next record; return the new record's hash.
    fn append_chirho(
        &self,
        writer_chirho: &str,
        payload_chirho: &[u8],
    ) -> StoreResultChirho<HashChirho>;
    /// Fetch a record by its content hash; `None` if absent.
    fn get_chirho(
        &self,
        record_hash_chirho: &HashChirho,
    ) -> StoreResultChirho<Option<AuditRecordChirho>>;
    /// The current observed head hash per writer (the tips of each chain).
    fn heads_chirho(&self) -> StoreResultChirho<Vec<HashChirho>>;
}

/// Runs a node: given its definition and one input-bytes payload, produce one output-bytes payload.
/// The fuel-metered wasmtime runner is a *server* adapter; a fn-table adapter serves tests and the
/// portable proof. Deliberately tiny + synchronous for the first vertical slice — single input ->
/// single output; richer multi-port / fuel / async execution is a later brick.
pub trait NodeRunnerChirho {
    fn run_node_chirho(
        &self,
        node_chirho: &NodeDefChirho,
        input_chirho: &[u8],
    ) -> AnyResult<Vec<u8>>;
}

/// Mutable application-state plane — the *second* plane, distinct from the immutable content/audit
/// plane. Plain keyed get/set, PLUS an idempotency-keyed `apply_once_chirho`: the crux of
/// write-atomicity without cross-plane transactions. A read-modify-write (e.g. "counter + 1") is
/// NOT safe to replay naively — it would double-apply after a crash/retry. `apply_once_chirho` ties
/// each mutation to a `mutation_id_chirho` and applies it at most once, so a re-run is idempotent.
/// A tighter one-backend state+audit unit-of-work can layer beside this port when an adapter can
/// commit both planes transactionally.
pub trait StateStoreChirho {
    fn get_state_chirho(&self, key_chirho: &str) -> StoreResultChirho<Option<Vec<u8>>>;
    fn set_state_chirho(&self, key_chirho: &str, value_chirho: &[u8]) -> StoreResultChirho<()>;
    /// Apply `value_chirho` at `key_chirho` exactly once for `mutation_id_chirho`. If that mutation
    /// id was already applied, this is a no-op. Returns `true` iff it applied now (`false` ⇒ it had
    /// already been applied — the replay/crash-recovery case). Recording the id and writing the
    /// value MUST be one atomic step within the single backend.
    fn apply_once_chirho(
        &self,
        mutation_id_chirho: &str,
        key_chirho: &str,
        value_chirho: &[u8],
    ) -> StoreResultChirho<bool>;
    /// Whether `mutation_id_chirho` has already been applied (lets a resumable run skip completed work).
    fn is_applied_chirho(&self, mutation_id_chirho: &str) -> StoreResultChirho<bool>;
}

/// Result of an atomic state+audit unit-of-work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateAuditCommitChirho {
    pub state_applied_chirho: bool,
    pub audit_head_chirho: HashChirho,
}

/// One-backend transaction that commits an idempotency-keyed state mutation and an audit append
/// together. This is deliberately small and generic; redb can implement it as a real transaction,
/// while browser/fs adapters can decline or provide weaker composition-root wrappers.
pub trait StateAuditUnitOfWorkChirho {
    fn commit_state_and_audit_chirho(
        &self,
        mutation_id_chirho: &str,
        state_key_chirho: &str,
        state_value_chirho: &[u8],
        audit_writer_chirho: &str,
        audit_payload_chirho: &[u8],
    ) -> StoreResultChirho<StateAuditCommitChirho>;
}

// Blanket impls for shared references, so a *fresh* component (e.g. a performer after a simulated
// restart) can reopen the SAME durable store via `&store` — the store outlives the component.
impl<T: ContentReadChirho + ?Sized> ContentReadChirho for &T {
    fn get_chirho(&self, addr_chirho: &HashChirho) -> StoreResultChirho<Option<Vec<u8>>> {
        (**self).get_chirho(addr_chirho)
    }
}

impl<T: ContentStoreChirho + ?Sized> ContentStoreChirho for &T {
    fn put_chirho(&self, bytes_chirho: &[u8]) -> StoreResultChirho<HashChirho> {
        (**self).put_chirho(bytes_chirho)
    }
}

impl<T: AuditLogChirho + ?Sized> AuditLogChirho for &T {
    fn append_chirho(
        &self,
        writer_chirho: &str,
        payload_chirho: &[u8],
    ) -> StoreResultChirho<HashChirho> {
        (**self).append_chirho(writer_chirho, payload_chirho)
    }
    fn get_chirho(
        &self,
        record_hash_chirho: &HashChirho,
    ) -> StoreResultChirho<Option<AuditRecordChirho>> {
        (**self).get_chirho(record_hash_chirho)
    }
    fn heads_chirho(&self) -> StoreResultChirho<Vec<HashChirho>> {
        (**self).heads_chirho()
    }
}

impl<T: StateStoreChirho + ?Sized> StateStoreChirho for &T {
    fn get_state_chirho(&self, key_chirho: &str) -> StoreResultChirho<Option<Vec<u8>>> {
        (**self).get_state_chirho(key_chirho)
    }
    fn set_state_chirho(&self, key_chirho: &str, value_chirho: &[u8]) -> StoreResultChirho<()> {
        (**self).set_state_chirho(key_chirho, value_chirho)
    }
    fn apply_once_chirho(
        &self,
        mutation_id_chirho: &str,
        key_chirho: &str,
        value_chirho: &[u8],
    ) -> StoreResultChirho<bool> {
        (**self).apply_once_chirho(mutation_id_chirho, key_chirho, value_chirho)
    }
    fn is_applied_chirho(&self, mutation_id_chirho: &str) -> StoreResultChirho<bool> {
        (**self).is_applied_chirho(mutation_id_chirho)
    }
}

impl<T: StateAuditUnitOfWorkChirho + ?Sized> StateAuditUnitOfWorkChirho for &T {
    fn commit_state_and_audit_chirho(
        &self,
        mutation_id_chirho: &str,
        state_key_chirho: &str,
        state_value_chirho: &[u8],
        audit_writer_chirho: &str,
        audit_payload_chirho: &[u8],
    ) -> StoreResultChirho<StateAuditCommitChirho> {
        (**self).commit_state_and_audit_chirho(
            mutation_id_chirho,
            state_key_chirho,
            state_value_chirho,
            audit_writer_chirho,
            audit_payload_chirho,
        )
    }
}

// --- M35.6a: ASYNC sibling ports (additive; the sync ports above are untouched). ---------------
// IndexedDB and the Web Locks API are Promise-based and cannot block the browser main thread, so the
// browser tier needs ASYNC storage ports. These are exact async mirrors of `ContentStoreChirho` /
// `AuditLogChirho`. Return-position `impl Future` (NOT `async fn` in the trait) is deliberate: it
// sidesteps the `async_fn_in_trait` lint under `-D warnings` and imposes NO `Send` bound, which suits
// single-threaded wasm + current-thread executors. `NodeRunnerChirho` stays synchronous (CPU, not I/O).

/// Async sibling of [`ContentStoreChirho`] for backends whose I/O is inherently asynchronous.
pub trait ContentStoreAsyncChirho {
    fn put_chirho(
        &self,
        bytes_chirho: &[u8],
    ) -> impl Future<Output = StoreResultChirho<HashChirho>>;
    fn get_chirho(
        &self,
        addr_chirho: &HashChirho,
    ) -> impl Future<Output = StoreResultChirho<Option<Vec<u8>>>>;
}

/// Async sibling of [`AuditLogChirho`] (same fork-tolerant, observed-tips contract).
pub trait AuditLogAsyncChirho {
    fn append_chirho(
        &self,
        writer_chirho: &str,
        payload_chirho: &[u8],
    ) -> impl Future<Output = StoreResultChirho<HashChirho>>;
    fn get_chirho(
        &self,
        record_hash_chirho: &HashChirho,
    ) -> impl Future<Output = StoreResultChirho<Option<AuditRecordChirho>>>;
    fn heads_chirho(&self) -> impl Future<Output = StoreResultChirho<Vec<HashChirho>>>;
}

/// Bridges any synchronous store into its async sibling by returning already-ready futures. This is
/// what lets the async executor run over the existing memory/fs/localStorage adapters — so the async
/// path is proven NATIVELY, byte-identical to the sync path, before any real async backend exists.
pub struct SyncAsAsyncChirho<T>(pub T);

impl<T: ContentStoreChirho> ContentStoreAsyncChirho for SyncAsAsyncChirho<T> {
    fn put_chirho(
        &self,
        bytes_chirho: &[u8],
    ) -> impl Future<Output = StoreResultChirho<HashChirho>> {
        ready(self.0.put_chirho(bytes_chirho))
    }
    fn get_chirho(
        &self,
        addr_chirho: &HashChirho,
    ) -> impl Future<Output = StoreResultChirho<Option<Vec<u8>>>> {
        ready(self.0.get_chirho(addr_chirho))
    }
}

impl<T: AuditLogChirho> AuditLogAsyncChirho for SyncAsAsyncChirho<T> {
    fn append_chirho(
        &self,
        writer_chirho: &str,
        payload_chirho: &[u8],
    ) -> impl Future<Output = StoreResultChirho<HashChirho>> {
        ready(self.0.append_chirho(writer_chirho, payload_chirho))
    }
    fn get_chirho(
        &self,
        record_hash_chirho: &HashChirho,
    ) -> impl Future<Output = StoreResultChirho<Option<AuditRecordChirho>>> {
        ready(self.0.get_chirho(record_hash_chirho))
    }
    fn heads_chirho(&self) -> impl Future<Output = StoreResultChirho<Vec<HashChirho>>> {
        ready(self.0.heads_chirho())
    }
}

/// Schema tag for the portable effect record (hashed; distinct from the prototype's signed
/// `EffectChirho`, which adds signatures/PKI on the server side).
pub const EFFECT_RECORD_SCHEMA_CHIRHO: &str = "effect-record-v1";

/// One performed side effect, recorded for replay + provenance: which kind, under what idempotency
/// key, over what args, producing what result. Appended to the `AuditLogChirho`. Built via
/// `new_chirho` so the schema tag is always set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct EffectRecordChirho {
    pub schema_chirho: String,
    pub kind_chirho: String,
    pub idempotency_key_chirho: String,
    pub args_hash_chirho: HashChirho,
    pub result_hash_chirho: HashChirho,
}

impl EffectRecordChirho {
    pub fn new_chirho(
        kind_chirho: &str,
        idempotency_key_chirho: &str,
        args_hash_chirho: HashChirho,
        result_hash_chirho: HashChirho,
    ) -> Self {
        Self {
            schema_chirho: EFFECT_RECORD_SCHEMA_CHIRHO.to_string(),
            kind_chirho: kind_chirho.to_string(),
            idempotency_key_chirho: idempotency_key_chirho.to_string(),
            args_hash_chirho,
            result_hash_chirho,
        }
    }
}

/// The outcome of performing (or replaying) one effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectOutcomeChirho {
    pub result_chirho: Vec<u8>,
    pub record_chirho: EffectRecordChirho,
    /// `true` ⇒ the idempotency key was already performed; the recorded result was replayed and the
    /// effect was NOT re-performed (the core of cairn's "effects can't be un-sent" safety).
    pub replayed_chirho: bool,
}

/// Performs a blessed side effect under an idempotency key, recording it for replay. Re-performing
/// with the same key MUST replay the recorded result and NOT re-run the effect — so a re-run is
/// safe (idempotent + resumable), the contract cairn uses *instead of* cross-plane transactions.
pub trait EffectPerformerChirho {
    fn perform_chirho(
        &self,
        idempotency_key_chirho: &str,
        kind_chirho: &str,
        args_chirho: &[u8],
    ) -> AnyResult<EffectOutcomeChirho>;
}

#[cfg(test)]
mod verify_content_address_tests_chirho {
    //! `verify_content_address_chirho` is a security primitive this crate OWNS, and until now no test
    //! here exercised it — its only guard lived in another crate's suite, which makes the protection
    //! accidental rather than owned. Found by asking why a mutation survived: disabling the
    //! comparison left all 19 of this crate's tests green.

    use super::*;
    use crate::cas_chirho::hash_chirho;

    #[test]
    fn bytes_matching_their_address_verify_chirho() {
        let bytes_chirho = b"honest-object-chirho";
        assert!(verify_content_address_chirho(&hash_chirho(bytes_chirho), bytes_chirho).is_ok());
    }

    #[test]
    fn substituted_bytes_are_refused_chirho() {
        // THE PROPERTY. Content addressing means nothing if bytes may be served under an address they
        // do not hash to; this is the check every content-addressed read leans on.
        let claimed_chirho = hash_chirho(b"what-the-caller-asked-for-chirho");
        let substituted_chirho = b"different-payload-chirho";
        assert_ne!(
            claimed_chirho,
            hash_chirho(substituted_chirho),
            "fixture must actually lie"
        );
        let error_chirho = verify_content_address_chirho(&claimed_chirho, substituted_chirho)
            .expect_err("substituted bytes must not verify");
        let message_chirho = format!("{error_chirho}");
        assert!(
            message_chirho.contains(&claimed_chirho.0)
                && message_chirho.contains(&hash_chirho(substituted_chirho).0),
            "the refusal must name BOTH the requested and the actual address so a caller can \
             quarantine by true hash: {message_chirho}"
        );
    }

    #[test]
    fn empty_bytes_still_verify_against_their_own_address_chirho() {
        // An empty object is a legitimate object; refusing it would be a fail-closed bug, not safety.
        assert!(verify_content_address_chirho(&hash_chirho(b""), b"").is_ok());
    }

    #[test]
    fn a_one_byte_difference_is_refused_chirho() {
        // Nothing here should be tolerant: content addressing is exact equality, not similarity.
        let bytes_chirho = b"payload-chirho";
        let mut altered_chirho = bytes_chirho.to_vec();
        altered_chirho.push(b'!');
        assert!(
            verify_content_address_chirho(&hash_chirho(bytes_chirho), &altered_chirho).is_err()
        );
    }
}
