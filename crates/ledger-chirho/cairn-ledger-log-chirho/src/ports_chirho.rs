// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The three I/O ports the ledger defines at birth (Brick 2 spec §1) so the money core never touches
//! fs / clock / tokio directly.
//!
//! There are no low-level I/O ports anywhere in the workspace today (fs, clock, tokio are called
//! concretely across ~20 crates), so the ledger defines its own — in-scope, zero retrofit. The sim
//! adapter injects a fault at EVERY operation (torn write, crash, reorder, delay, clock skew); the
//! real adapter wraps seqlog/RC4 + `cairn-durable-chirho`. Trait injection with root-pinned trust is
//! the established house idiom (mirrors `SegmentContinuityPortChirho`).

use anyhow::Result;

/// An opaque storage path within the ledger's namespace. The adapter maps it to a real filesystem
/// path or an in-memory key; the core never constructs a host path, so residency/placement stays a
/// shard-level concern the adapter owns.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StoragePathChirho(pub String);

impl StoragePathChirho {
    /// Build a storage path from a logical key.
    pub fn new_chirho(key_chirho: impl Into<String>) -> Self {
        Self(key_chirho.into())
    }

    /// The logical key.
    pub fn key_chirho(&self) -> &str {
        &self.0
    }
}

/// Result of atomically claiming a previously absent durable object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreateDurableOutcomeChirho {
    CreatedChirho,
    AlreadyExistsChirho,
}

/// Durable create / append / read / atomic-write / rename / list storage — the only way the log
/// touches persistence. Every method is a fault-injection point in the sim adapter.
pub trait LedgerStoragePortChirho {
    /// Atomically create an absent object with `bytes` and make it durable. `AlreadyExistsChirho`
    /// is a successful observation that MUST leave the preexisting object byte-exact. There is no
    /// default `exists + append` implementation because that composition is racy.
    fn create_durable_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        bytes_chirho: &[u8],
    ) -> Result<CreateDurableOutcomeChirho>;

    /// Append `bytes` to the object at `path` and make it durable (fsync-equivalent) before returning.
    fn append_durable_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        bytes_chirho: &[u8],
    ) -> Result<()>;

    /// Read the full object at `path`, or `None` if it does not exist.
    fn read_all_chirho(&self, path_chirho: &StoragePathChirho) -> Result<Option<Vec<u8>>>;

    /// The current durable byte length of the object at `path`, or `None` if it does not exist. Cheap
    /// metadata the fence uses to know a record range is in-bounds BEFORE reading it — the O(1)
    /// runtime-cost invariant forbids reading a whole object just to learn its length.
    fn object_len_chirho(&self, path_chirho: &StoragePathChirho) -> Result<Option<u64>>;

    /// Read EXACTLY `len` bytes starting at byte `offset` of the object at `path`. FAIL-CLOSED: `Err`
    /// on a missing object, on `offset + len` overflowing `u64` or exceeding the object's current
    /// length (a range past EOF / a torn tail), or on any short read — it NEVER returns fewer than
    /// `len` bytes as success and NEVER falls back to a full read. This is the ONLY hot-path record
    /// read: the fence locates a record by (offset, len, digest) and reads just its bytes, so per-append
    /// read cost is O(record), never O(log length) (the O(1) runtime-cost invariant, §11.4).
    ///
    /// PRECONDITION: `object_len_chirho` and this call are TWO calls, not one snapshot — the caller must
    /// hold the single-writer journal lock across the stable cut it reads (an `object_len` result is not
    /// itself a durable cut). This method still revalidates CURRENT length and fails closed if the object
    /// shrank underneath, so a lock bug degrades to a rejected read, never a torn one.
    fn read_exact_range_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        offset_chirho: u64,
        len_chirho: u64,
    ) -> Result<Vec<u8>>;

    /// Atomically (temp + rename + fsync) write `bytes` as the whole object at `path`.
    fn atomic_write_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        bytes_chirho: &[u8],
    ) -> Result<()>;

    /// Durably truncate the object at `path` to EXACTLY `new_len` bytes. A RECOVERY-ONLY primitive
    /// (torn-tail repair after a crash mid-append): the engine calls it only after fully verifying
    /// the clean prefix it truncates to. Fail-closed on a missing object or `new_len` greater than
    /// the current length (a truncate can only shorten). The size change is atomic on a real fs
    /// (`ftruncate`), so the sim treats a torn truncate as crash-before.
    fn truncate_durable_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        new_len_chirho: u64,
    ) -> Result<()>;

    /// Atomically rename `from` to `to` (durable parent), for the seal cut of rotation.
    fn rename_chirho(
        &self,
        from_chirho: &StoragePathChirho,
        to_chirho: &StoragePathChirho,
    ) -> Result<()>;

    /// Remove the object at `path` (idempotent: absent is Ok).
    fn remove_chirho(&self, path_chirho: &StoragePathChirho) -> Result<()>;

    /// List existing objects whose key starts with `prefix`, in sorted order.
    fn list_chirho(&self, prefix_chirho: &StoragePathChirho) -> Result<Vec<StoragePathChirho>>;

    /// Does an object exist at `path`?
    fn exists_chirho(&self, path_chirho: &StoragePathChirho) -> Result<bool>;
}

/// The per-journal signing port (§11.1: sig/key_id are label-only, never trust-selection — the
/// SegmentContinuityPort idiom; the key is injected per journal/family by the composition root).
/// The message is ALWAYS the canonical signed-content line (record minus `sig`, §11.6
/// sign-then-attach); the sim adapter returns a deterministic label, the real adapter wraps the
/// house signer.
pub trait LedgerSignerPortChirho {
    /// Sign the canonical signed-content line; the return value becomes the record's `sig` field.
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> Result<String>;

    /// The key label recorded as `key_id` (label-only).
    fn key_id_chirho(&self) -> String;

    /// Verify a signature over the canonical signed-content line against the port's INJECTED trust
    /// root (never against the record's self-declared `key_id` — that stays label-only). Used to
    /// verify the successor-less TAIL line's signature on reopen (the one line neither chain-bound by
    /// a successor's `prev` nor covered by the balance fold) AND the head-checkpoint sidecar's
    /// signature. On the FULL-open path the tail-sig is O(1) whole-journal tamper-evidence (every
    /// tamper ripples through the `prev` chain to the tail); the FAST path additionally trusts the
    /// sidecar-signature-vouched covered aggregates, so an interior covered tamper is caught at the
    /// next full open, not the fast path (details in `journal_chirho::verify_tail_signature_chirho`).
    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool;
}

/// Physical wall-clock in integer milliseconds — the physical component of the HLC. The monotonic
/// guard (bump the per-log logical counter on a regression) lives in ledger code, NOT here; the port
/// only reports what the clock says, so a regression/skew fault is injected at this one boundary.
pub trait LedgerClockPortChirho {
    /// Current physical time in milliseconds since an arbitrary fixed epoch (need not be wall UTC).
    fn physical_now_ms_chirho(&self) -> u64;
}

/// Runtime hooks for the virtual-actor lifecycle and durable timers. The sim adapter is a
/// single-threaded deterministic scheduler over virtual time (seeded interleaving choice); the real
/// adapter is tokio-backed. Brick 2.0 defines it; heavy use (hydrate / passivate / bounded mailbox)
/// arrives with the actor core.
pub trait LedgerRuntimePortChirho {
    /// Block until at least `deadline_ms_chirho` (virtual time in sim, real time in prod). Used by the
    /// durable-timer sweep; a passivated log still wakes for its next deadline via the shard index.
    fn sleep_until_ms_chirho(&self, deadline_ms_chirho: u64);
}
