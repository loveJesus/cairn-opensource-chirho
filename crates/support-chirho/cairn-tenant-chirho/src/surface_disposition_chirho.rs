// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! What happens to each root surface when a tenant root moves — and a NAMED REFUSAL where we have
//! deliberately not built a mechanism.
//!
//! CF8 acceptance, verbatim: *"every remaining surface is explicitly exported, custody-transferred,
//! rebuilt, or proven disposable."* Completeness answers *were you shown everything*;
//! self-containment answers *does what you were shown resolve here*; this answers *and then what
//! happens to it*. A root can pass both other halves and still lose data on the move, because
//! "present and accounted for" is not "carried".
//!
//! **THE CUSTODY REFUSAL WAS THE POINT, AND IT HAS NOW BEEN ANSWERED RATHER THAN WAIVED.** The
//! original wording is kept here because it stated the constraint exactly right and the constraint
//! still binds: *"how a private signing key moves between hosts is a SECURITY DESIGN QUESTION, not a
//! table entry. A bookkeeping module that quietly acquired a key-movement mechanism would be an
//! authority change hidden inside a completeness change."* That remains true, and it is why this entry
//! did not change until a mechanism existed somewhere a reader can go and check.
//!
//! It exists now: `move_chirho::move_stages_chirho`. The ordering is what makes the move safe rather
//! than merely possible — custody placed at the target BEFORE the writer moves, the source key erased
//! ONLY after handoff, and the move reversible until retirement, so there is never a moment with no key
//! anywhere and never two writers. Those are armed exhaustively over every stage, not sampled.
//!
//! So `signing-key-chirho.bin` and `pubkey-chirho.hex` now declare
//! [`SurfaceDispositionChirho::CustodyTransferredThroughMoveStagesChirho`], and CF8 clause 4 is what
//! forced the question back open: it requires a move that carries privacy-key custody and erasure
//! obligations THROUGH handoff and source retirement, so a permanent refusal makes the clause
//! unsatisfiable rather than satisfying it.
//!
//! **The refusal variant stays, and stays the default.** Any custody-bearing surface not named in the
//! table below still fails the whole migration closed — a new key-bearing surface must refuse until
//! somebody decides how it moves, rather than inheriting a decision made for a different surface. The
//! change here is one ruling about two named surfaces, not a general permission.
//!
//! **THE DISPOSITIONS WERE CORRECTED BY MEASUREMENT, and the correction is the most useful thing in
//! this file.** The first grouping — mine — put `runs-chirho` and `runkeys-chirho` under
//! *rebuilt-at-target, derivable*, reasoning from their names. Reading the code says otherwise, and
//! says it twice:
//!
//! - `gc_chirho.rs`'s `RUNTIME_RECORD_DIRS_CHIRHO` lists `runs-chirho`, `effects-chirho`,
//!   `runkeys-chirho`, and `runseals-chirho` as **GC ROOTS**. A surface that is a GC root is what
//!   keeps objects alive; dropping it at the target does not merely lose a cache, it makes the
//!   objects it referenced unreachable and therefore collectible.
//! - `RunResultChirho` carries `effects_chirho: Vec<EffectChirho>` — the signed, append-only effect
//!   log — and `verify_chirho` re-hashes runkey sidecars and checks effect signatures across all
//!   three directories. They are the audit chain, not a cache in front of it.
//!
//! So marking them *rebuilt* would have authorised discarding the signed record of what happened,
//! from what, by what code, and authorised by whom — for every past run — inside a change that reads
//! like bookkeeping. **`RebuiltAtTargetChirho` therefore has no members today.** The variant stays
//! because the clause names *rebuilt* as a legitimate disposition and a future surface may earn it;
//! an empty row that says why is worth more than a row filled to look complete.
//!
//! **Scope, named honestly.** This is the "every remaining surface" half of the clause. The clause's
//! other half — *"P3 is only the immutable-object/allowlisted-log seed"* — is a replication-scope
//! property and is guarded separately, in
//! `cairn-source-scan-chirho`'s `p3_replication_guard_tests_chirho`, which pins that the replication
//! crates carry zero head-mutation dependency. This module does not restate that.
//!
//! **The 21-surface census, ruled 2026-10-26 (CF8 Step B, AICEO #29534).** The closure census found
//! 21 surfaces that production writes at a tenant root's top level and that this model did not know.
//! Eighteen are ruled below, each from the module that writes it, and so is C2.1's law marker,
//! registered before its first production write, as C5's erasure-propagation store later was. The
//! evidence is in
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/tenant-migration-chirho/missing-surface-dispositions-chirho.md`.
//! Three stay refused because no list names them. The customer store `versioned-chirho.redb` and
//! the attribution directory `privacy-account-attribution-chirho/` are refused because the privacy
//! owner selected erasure at source after handoff and no production code retires a migration source
//! yet. `seqlog-quarantine-chirho/` is refused because it holds torn bytes that no erasure flow
//! reaches, and they must be reviewed before any move.
//!
//! Pure: no I/O. The observed surface list comes from the caller, so this is testable without a root.

use crate::migration_completeness_chirho::declared_log_surfaces_chirho;
use crate::tenant_chirho::{CONTROL_PLANE_LAW_MARKER_FILE_CHIRHO, GEO_GENESIS_GUARD_DIR_CHIRHO};
use cairn_core_chirho::store_chirho::hash_object_chirho;
use cairn_seqlog_chirho::SEQLOG_HEAD_SUFFIX_CHIRHO;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// What a migration does with one surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SurfaceDispositionChirho {
    /// The bytes travel with the root. This is the clause's "exported" for a whole-root move.
    CarriedWithTheRootChirho,
    /// Reconstructible at the target from what was carried.
    ///
    /// **No surface holds this today** — see the module header. It is kept because the clause names
    /// it and because the honest reading of an empty row is "we checked and none qualified".
    RebuiltAtTargetChirho,
    /// Deliberately NOT moved, because moving it would be a bug rather than a loss.
    ProvenDisposableChirho,
    /// Custody-bearing, with NO mechanism to move it. The migration refuses rather than inventing one.
    ///
    /// **Still the default for any custody-bearing surface not named below**, and deliberately so: a
    /// new key-bearing surface must refuse until somebody decides how it moves, rather than inheriting
    /// a decision made for a different surface.
    CustodyTransferRefusedInThisSliceChirho,
    /// Custody-bearing, and the mechanism now exists: `move_chirho::move_stages_chirho`.
    ///
    /// **This is a RULING, and it is recorded here because the refusal above was correct until the
    /// mechanism existed.** The module header used to say custody transfer was "out of this slice", and
    /// that a permanent refusal would be "a defensible permanent answer rather than a gap". CF8 clause
    /// 4 is what forced it back open: the clause requires a tenant-root move that carries privacy-key
    /// custody and erasure obligations THROUGH handoff and source retirement, so a permanent refusal
    /// makes the clause unsatisfiable rather than satisfying it.
    ///
    /// What changed is not the appetite for risk but the existence of an ordering that makes the move
    /// safe: custody is placed at the target BEFORE the writer moves, the source key is erased ONLY
    /// after handoff, and the move stays reversible until retirement — so there is never a moment with
    /// no key anywhere, and never two writers. Those are exhaustively armed in `move_stages_chirho`.
    ///
    /// The honest limit: this says the surface moves through that mechanism. It does not say any
    /// particular move executed it correctly — that is what the move's own signed stage log is for.
    CustodyTransferredThroughMoveStagesChirho,
    /// A platform root is not a placement/authority/migration unit (G1), so it is not movable as one.
    NotAMigrationUnitChirho,
}

/// Whether a top-level surface participates in the carried PAYLOAD commitment.
///
/// Move-control evidence travels with the root but describes the payload commitment, so including
/// it in that commitment would create a content-hash cycle. Every other classified surface is
/// payload unless its policy row says otherwise.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SurfacePayloadDispositionChirho {
    CommittedPayloadChirho,
    MoveControlChirho,
}

/// What source retirement does with this surface after writer handoff.
///
/// This is independent of movement. `pubkey-chirho.hex` travels through the custody mechanism but
/// remains at the retired source for public verification; its private-key siblings travel and are
/// erased only after handoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceRetirementDispositionChirho {
    RetainAtSourceChirho,
    EraseAtSourceAfterHandoffChirho,
}

/// One central, three-axis policy row for a top-level tenant-root surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootSurfacePolicyChirho {
    pub movement_disposition_chirho: SurfaceDispositionChirho,
    pub payload_disposition_chirho: SurfacePayloadDispositionChirho,
    pub source_retirement_disposition_chirho: SourceRetirementDispositionChirho,
}

impl RootSurfacePolicyChirho {
    const fn payload_chirho(movement_disposition_chirho: SurfaceDispositionChirho) -> Self {
        Self {
            movement_disposition_chirho,
            payload_disposition_chirho: SurfacePayloadDispositionChirho::CommittedPayloadChirho,
            source_retirement_disposition_chirho:
                SourceRetirementDispositionChirho::RetainAtSourceChirho,
        }
    }

    const fn private_custody_chirho(movement_disposition_chirho: SurfaceDispositionChirho) -> Self {
        Self {
            movement_disposition_chirho,
            payload_disposition_chirho: SurfacePayloadDispositionChirho::CommittedPayloadChirho,
            source_retirement_disposition_chirho:
                SourceRetirementDispositionChirho::EraseAtSourceAfterHandoffChirho,
        }
    }

    const fn move_control_chirho(movement_disposition_chirho: SurfaceDispositionChirho) -> Self {
        Self {
            movement_disposition_chirho,
            payload_disposition_chirho: SurfacePayloadDispositionChirho::MoveControlChirho,
            source_retirement_disposition_chirho:
                SourceRetirementDispositionChirho::RetainAtSourceChirho,
        }
    }
}

/// Dedicated content-addressed evidence that describes, but is not inside, the payload commitment.
pub const TENANT_MOVE_CONTROL_SURFACE_CHIRHO: &str = "tenant-root-move-control-chirho";

/// Non-log root surfaces and what happens to each.
///
/// Existing entries here were OBSERVED on a real root by `tenant-migration-verify` before receiving
/// policy, except `effects-chirho`, which comes from production GC's runtime-record list. The move-
/// control namespace is the deliberate inverse case: registered before its first production write,
/// after controlled scans proved no retained move rows on the four drill hosts, so it cannot become
/// an unknown surface during the very move that introduces it.
pub const NON_LOG_SURFACE_POLICIES_CHIRHO: &[(&str, RootSurfacePolicyChirho)] = &[
    // DISPOSABLE: lifetime-exclusive resident ownership. The module's own sentence is "lifetime-
    // exclusive resident ownership for one bounded canonical identity under one root" — an
    // exclusivity claim bound to a canonical path. That is the `locks-chirho` argument exactly: a
    // claim arriving at the target is stale by construction and would block the new resident writer
    // for a holder that no longer exists. It is NOT admitted to the rebuilt set, because the rebuilt
    // set is authority state and an ownership claim is not authority.
    (
        "resident-writer-chirho",
        RootSurfacePolicyChirho::payload_chirho(SurfaceDispositionChirho::ProvenDisposableChirho),
    ),
    // CARRIED: GD7 reconciliation evidence — "fresh-challenge, O(1)-addressed evidence for one
    // elected winner's exact current view", stored content-addressed at
    // `{namespace}/{family}/…/{object_digest}.json`. It is the record of how a deposed fork was
    // reconciled, and dropping evidence while reporting success is the failure this table exists to
    // prevent. Carried for the same reason the audit chain is.
    (
        "gd7-reconciliation-chirho",
        RootSurfacePolicyChirho::payload_chirho(SurfaceDispositionChirho::CarriedWithTheRootChirho),
    ),
    // CARRIED: inert F1 mirror durability and recovery evidence. "Inert" means this namespace has
    // no canonical-journal mutation handle; it does NOT mean its bytes are reconstructible. The
    // follower side retains signed high-water/bootstrap heads plus the exact mirrored records that
    // production recovery selects, and the leader side retains a prepared closure until the next
    // append reconciles whether its local journal record committed. Opening a fresh store recreates
    // only empty directories. Dropping a populated store can therefore discard an ACK-survival
    // source or the only durable instruction to finalize a locally committed record.
    //
    // The records bind tenant/cluster, placement, membership, term, holder and journal coordinates,
    // but not a root descriptor. The migrated target keeps the same tenant, node identity and
    // canonical journal while the source is barred, so carrying preserves the evidence without
    // importing a second writer. See the zone-mirror-before-ack and F1 recovery-adoption workflows.
    (
        "ledger-mirror-f1-chirho",
        RootSurfacePolicyChirho::payload_chirho(SurfaceDispositionChirho::CarriedWithTheRootChirho),
    ),
    // ---- Ruled 2026-08-19 against a REAL root's surfaces, each from the module that owns it. ----
    //
    // DISPOSABLE: CAS lifecycle coordination. Its own header calls it "the shared/exclusive root
    // barrier and deletion generation" — one host's live coordination state, which is the same
    // argument `locks-chirho` already carries: state that arrives at the target is stale by
    // construction. It holds generation counters, not object references, so disposing it cannot
    // orphan anything even though GC scans the directory.
    (
        "cas-lifecycle-chirho",
        RootSurfacePolicyChirho::payload_chirho(SurfaceDispositionChirho::ProvenDisposableChirho),
    ),
    // DISPOSABLE: the operator-socket runtime directory. It holds a unix socket and live process
    // scratch — nothing content-addressed, and nothing that survives the process meaningfully. On
    // the real root measured it was EMPTY.
    (
        "runtime-chirho",
        RootSurfacePolicyChirho::payload_chirho(SurfaceDispositionChirho::ProvenDisposableChirho),
    ),
    // CARRIED: "bounded, content-addressed public intent and terminal evidence" in its own words.
    // Content-addressed evidence is the audit chain, and the same sentence that makes `effects`,
    // `runs`, `runkeys` and `runseals` carried applies here unchanged: a migration that dropped it
    // would lose signed effect history while reporting success.
    (
        "effect-commit-evidence-chirho",
        RootSurfacePolicyChirho::payload_chirho(SurfaceDispositionChirho::CarriedWithTheRootChirho),
    ),
    // CARRIED, corrected 2026-08-19 after MEASURING the cell rather than reasoning from its name.
    // It read REBUILT, on the argument that a winner-term fence is authority state and carrying it
    // "would place a live term cell at the target". The cell was then read on a real root:
    //
    //     {"schema_chirho":"sink-term-fence-v1-chirho",
    //      "group_digest_chirho":"writer-fence-group-blake3-chirho:<group>",
    //      "highest_accepted_winner_term_chirho":1}
    //
    // No root, no device, no inode — it is a TENANT-scoped monotonic high-water mark, and its key is
    // the group digest, which is derived from `ConsistencyGroupIdChirho::TenantChirho` and is
    // therefore IDENTICAL at source and target. Carrying it lands the same mark under the same key.
    //
    // And the safety argument runs the other way from the original reasoning. The recover path
    // already refuses the dangerous case BY NAME — `RecoveredCellAheadOfCurrentAuthorityChirho`
    // when a carried cell is ahead of the acting authority — keeps an equal one, and advances a
    // behind one monotonically. REBUILDING has no such refusal: with no cell present it simply
    // creates one at the current term, which silently discards a higher mark. So rebuilding is the
    // fail-OPEN direction and carrying is the fail-closed one; the original ruling had it inverted
    // because it read "term cell" as host-local state.
    //
    // IT DOES NOT INHERIT `writer-fences-chirho`'s ARGUMENT, and the old comment claiming it did is
    // the reason this sat wrong. That surface stays rebuilt for a reason specific to it: its epoch
    // is COMPOSITE, `(geo_term << 32) | local_grant_seq`, whose low half resets per root — so its
    // epochs genuinely must not be compared across roots. This cell stores a plain winner term with
    // no per-root component, so the hazard that rules that surface simply is not present here. Two
    // surfaces with similar names and opposite answers; the names are what merged them.
    (
        "sink-term-fences-chirho",
        RootSurfacePolicyChirho::payload_chirho(SurfaceDispositionChirho::CarriedWithTheRootChirho),
    ),
    // REBUILT, ruled 2026-08-19. `writer-fences-chirho` is a directory of writer fence/epoch state
    // (`WRITER_FENCES_DIR_CHIRHO`), not key material — authority state rather than custody, so the
    // custody refusal above does not govern it. It blocked every root that has ever taken an elected
    // fence, which is exactly the class a tenant migration applies to.
    //
    // Why REBUILT rather than the two obvious answers, both of which are hazardous:
    // `ProvenDisposableChirho` leaves the target fenceless, so a stale source token refuses with the
    // WRONG identity; `CarriedWithTheRootChirho` puts a live-epoch fence file at the target during
    // the carry window. Rebuilt is neither: the target establishes its own fence through its own
    // elected authority.
    //
    // CARRIED, corrected 2026-08-19 by MEASURING what its absence does. The reasoning above is kept
    // because it was careful and still wrong, and the way it was wrong is the useful part: it weighed
    // carrying against rebuilding on EPOCH grounds and never asked what a missing fence means.
    //
    // `writer_authority_era_chirho` reads exactly this surface. Absent, it returns
    // `WriterAuthorityEraChirho::LocalChirho`. So dropping the fence does not leave the target
    // "fenceless pending its own election" — it silently DOWNGRADES the root's writer-authority era
    // from Elected back to Local, and a geo-elected tenant comes up locally authorized. Measured on
    // a real migrated root: the source's fence reads epoch 8589934593 = `(2 << 32) | 1`, a latched
    // geo term, so the source is Elected; the target without it resolved Local and demanded a
    // writer-era activation authorization that a migrated root has no business holding.
    //
    // The epoch objection is real and does not reach this. The era decision consults ONLY the geo
    // half — `split_writer_epoch_chirho(..).geo_term_chirho` through `is_geo_term_latched_chirho` —
    // and a geo term is geo-scoped, not per-root. The per-root half is `local_grant_seq`, and the
    // standing rule that epochs must not be COMPARED across roots stays exactly as it was: what
    // travels here is the latch, not a comparison. A replayed source-era token must still fail on
    // identity rather than ordering, and nothing below changes that.
    (
        "writer-fences-chirho",
        RootSurfacePolicyChirho::payload_chirho(SurfaceDispositionChirho::CarriedWithTheRootChirho),
    ),
    // CARRIED CONTROL: content-addressed move records and evidence. It travels with the root and is
    // independently verified, but cannot sit inside the payload commitment it describes.
    (
        TENANT_MOVE_CONTROL_SURFACE_CHIRHO,
        RootSurfacePolicyChirho::move_control_chirho(
            SurfaceDispositionChirho::CarriedWithTheRootChirho,
        ),
    ),
    // Carried: the object store, the ref map, and the runtime-record/audit chain.
    (
        "objects-chirho",
        RootSurfacePolicyChirho::payload_chirho(SurfaceDispositionChirho::CarriedWithTheRootChirho),
    ),
    (
        "refs-chirho.json",
        RootSurfacePolicyChirho::payload_chirho(SurfaceDispositionChirho::CarriedWithTheRootChirho),
    ),
    (
        "runs-chirho",
        RootSurfacePolicyChirho::payload_chirho(SurfaceDispositionChirho::CarriedWithTheRootChirho),
    ),
    (
        "runkeys-chirho",
        RootSurfacePolicyChirho::payload_chirho(SurfaceDispositionChirho::CarriedWithTheRootChirho),
    ),
    (
        "runseals-chirho",
        RootSurfacePolicyChirho::payload_chirho(SurfaceDispositionChirho::CarriedWithTheRootChirho),
    ),
    (
        "effects-chirho",
        RootSurfacePolicyChirho::payload_chirho(SurfaceDispositionChirho::CarriedWithTheRootChirho),
    ),
    // CARRIED: bounded per-viewer application state and its signed mutation receipts. This is
    // customer payload, not a projection or host-local coordination surface; rebuilding it would
    // silently discard the exact versions that customer restore and audit depend on.
    //
    // RETIREMENT IS OWED, NOT DONE. The privacy owner selected erasure at source after handoff for
    // this row (AICEO #29534), because the redb's key column holds the app's raw store keys and
    // those are not assumed to be safe metadata. The row still reads RETAIN. No production code
    // retires a migration source yet: `retire_source_chirho` and the move-stage store have only
    // test callers. Changing the enum alone would claim an erasure that nothing performs. The change
    // lands with that retirement step, together with `versioned-chirho.redb` and the attribution
    // directory.
    (
        "viewer-state-chirho.redb",
        RootSurfacePolicyChirho::payload_chirho(SurfaceDispositionChirho::CarriedWithTheRootChirho),
    ),
    // The tenant marker IS the root's identity; it travels or the target is not the same tenant.
    (
        "tenant-chirho.json",
        RootSurfacePolicyChirho::payload_chirho(SurfaceDispositionChirho::CarriedWithTheRootChirho),
    ),
    // TRAVELS, and the reasoning this replaces is worth keeping visible because it is the exact
    // shape of the mistake. It read: "a lock describes one host's live process state; a lock that
    // arrives at the target is stale by construction and would only ever block the new writer for a
    // holder that no longer exists." Every clause is intuitive and the conclusion is wrong, because
    // it confuses the FILE with the LOCK.
    //
    // Measured on a real root: every file under `locks-chirho` is ZERO BYTES, and the storage layer
    // refuses a non-empty one (`ObjectExceedsBoundChirho`). The file is a rendezvous point carrying
    // no state and no authority; the exclusion is the flock held on an open descriptor, which does
    // not outlive the process — so an arriving lock file blocks nobody and is stale in no sense.
    //
    // And the half that matters: the only call that CREATES one runs on the root BIRTH path. (Its
    // name is deliberately not written here — that symbol is confined by a source guard to storage
    // and sealed birth, and a mention in a comment is enough to pull this file into the confined
    // set. Widening a real confinement to make a comment more convenient is the wrong trade.) A migrated root is adopted, never born, so nothing
    // provisions its writer-fence lock, while every consumer uses `open_existing_...` and refuses
    // when it is absent. Dropping this surface therefore does not discard stale state; it makes the
    // migrated root permanently unopenable. Found by executing: a hosted target refused startup with
    // `descriptor-owned writer fence was refused: ledger storage object is missing`, and strace
    // recorded exactly ONE ENOENT in the whole run — an unrelated cgroup read — which is what ruled
    // out "a file failed to open" and pointed at a lookup returning None instead.
    (
        "locks-chirho",
        RootSurfacePolicyChirho::payload_chirho(SurfaceDispositionChirho::CarriedWithTheRootChirho),
    ),
    // Custody-bearing — these travel, and each answer below was MEASURED on a real root after the
    // first migration activated into a target that could not start (2026-08-19).
    //
    // `private-secrets-chirho` holds the runtime signer secrets. Journal verification binds to the
    // port's INJECTED key and treats a record's `key_id` as a label only, so a migrated journal
    // cannot open under fresh signer material — which rules out rebuilding these at the target, by
    // measurement rather than by preference.
    //
    // `privacy-keys-chirho` holds per-key-id privacy keys. Leaving them behind is not an incomplete
    // migration, it is CRYPTO-SHREDDING — cairn's erasure mechanism — applied by accident.
    //
    // `identity-keys-chirho` holds per-subject identity credential records. Without them the
    // tenant's users cannot authenticate to the root that just moved.
    //
    // HONEST LIMIT, and it is the reason this is not simply "carried": the ladder this disposition
    // is named for is not the ladder the executed migration runs. So today the model REFUSES a
    // target that lacks these (via the required-surfaces half) and an operator places them
    // deliberately; the staged ceremony is owed, and a refusal until it is done is the correct
    // interim, because the alternative is a migration that silently copies private keys.
    //
    // The same is true of retirement. The private rows below read erasure at source after handoff,
    // and no production code retires a migration source yet (measured 2026-10-26:
    // `retire_source_chirho` and the move-stage store have only test callers). So the erasure is a
    // recorded obligation, not a performed one.
    (
        "private-secrets-chirho",
        RootSurfacePolicyChirho::private_custody_chirho(
            SurfaceDispositionChirho::CustodyTransferredThroughMoveStagesChirho,
        ),
    ),
    (
        "privacy-keys-chirho",
        RootSurfacePolicyChirho::private_custody_chirho(
            SurfaceDispositionChirho::CustodyTransferredThroughMoveStagesChirho,
        ),
    ),
    (
        "identity-keys-chirho",
        RootSurfacePolicyChirho::private_custody_chirho(
            SurfaceDispositionChirho::CustodyTransferredThroughMoveStagesChirho,
        ),
    ),
    (
        "signing-key-chirho.bin",
        RootSurfacePolicyChirho::private_custody_chirho(
            SurfaceDispositionChirho::CustodyTransferredThroughMoveStagesChirho,
        ),
    ),
    (
        "pubkey-chirho.hex",
        RootSurfacePolicyChirho::payload_chirho(
            SurfaceDispositionChirho::CustodyTransferredThroughMoveStagesChirho,
        ),
    ),
    // ---- CF8 Step B, ruled 2026-10-26 (AICEO #29534) from the 21-surface census. ----
    //
    // CARRIED: exactly-once state. Each of these three is a `RedbStateAuditStoreChirho` holding
    // state, audit records, writer heads and the APPLIED MUTATION IDS (`cairn-store-redb-chirho`), so
    // a target without one could apply a replayed mutation twice. None can be rebuilt from its log.
    // A carried redb is a consistent copy only behind the source fence with no writer running, as
    // `viewer-state-chirho.redb` above is.
    (
        "app-build-request-state-chirho.redb",
        RootSurfacePolicyChirho::payload_chirho(SurfaceDispositionChirho::CarriedWithTheRootChirho),
    ),
    (
        "template-app-deploy-state-chirho.redb",
        RootSurfacePolicyChirho::payload_chirho(SurfaceDispositionChirho::CarriedWithTheRootChirho),
    ),
    (
        "publication-intent-state-chirho.redb",
        RootSurfacePolicyChirho::payload_chirho(SurfaceDispositionChirho::CarriedWithTheRootChirho),
    ),
    // CARRIED, and retained at source on purpose. This is the fork-impossible guard against a second
    // genesis. Its bytes are deterministic from the verified plan and identical on every member root,
    // so the target lands the same marker and the retired source still refuses a second genesis. A
    // move outside the plan's member set is a placement question, not a table row.
    (
        GEO_GENESIS_GUARD_DIR_CHIRHO,
        RootSurfacePolicyChirho::payload_chirho(SurfaceDispositionChirho::CarriedWithTheRootChirho),
    ),
    // CARRIED, and registered before its first production write (claude2 #29545, Agy #29539). The
    // control-plane law marker is C2.1's evidence E3: a schema, the public control-plane key id, the
    // tenant id and the genesis instance id. It holds no root coordinate and no private data, and
    // all four fields are the same at source and target. At main 4f93f36c only tests publish it,
    // so no retained root holds one. Registering it now means the brick that first writes it
    // (C2.1 1b) cannot meet its own marker as an unknown surface. If 1b ever binds the marker to a
    // root, this row must be ruled again.
    (
        CONTROL_PLANE_LAW_MARKER_FILE_CHIRHO,
        RootSurfacePolicyChirho::payload_chirho(SurfaceDispositionChirho::CarriedWithTheRootChirho),
    ),
    // CARRIED, retained at source, and registered before its first production write (claude #29636,
    // C5 B3-a2-ii). This is the leader's erasure-propagation store, `cairn-key-custody-http-chirho`'s
    // `leader_chirho`. It holds signed propagation requirements and their bindings: which key ids an
    // erasure must reach, at which holders, keyed by erasure seq and subject digest. It holds no key
    // material and no raw subject. Dropping it at the target would forget erasures that holders still
    // owe, so it travels, as the erasure log it is bound to does. At main 262c70c4 nothing in
    // production opens the store, so no retained root holds one. A name that drifts from the store's
    // constant fails closed, as an unknown surface.
    (
        "privacy-erasure-propagation-chirho",
        RootSurfacePolicyChirho::payload_chirho(SurfaceDispositionChirho::CarriedWithTheRootChirho),
    ),
    // CARRIED with its chain. This is the head of `gate1-authority-log-chirho.jsonl`'s hash chain,
    // and a target holding the log without its head, or the head without its log, cannot continue
    // the chain. GC does not scan it as a reference source (`gc_skip_dir_chirho`).
    (
        "gate1-authority-head-chirho",
        RootSurfacePolicyChirho::payload_chirho(SurfaceDispositionChirho::CarriedWithTheRootChirho),
    ),
    // DISPOSABLE, with a real reconstruction boundary. `ensure_read_model_chirho` rebuilds a missing
    // read model, or one lacking its table, from the carried store with `project_chirho`. It is a
    // projection of carried state, never a source of it.
    (
        "readmodel-chirho.sqlite",
        RootSurfacePolicyChirho::payload_chirho(SurfaceDispositionChirho::ProvenDisposableChirho),
    ),
    // DISPOSABLE: Tier 2 executables are materialized on demand from a CAS spec into
    // `native-workers-chirho/<spec hash>/`. The CAS travels and the first run re-materializes them. An
    // executable built for one host must not arrive at another. GC does not scan this directory as
    // a reference source, so disposing it cannot orphan an object.
    (
        "native-workers-chirho",
        RootSurfacePolicyChirho::payload_chirho(SurfaceDispositionChirho::ProvenDisposableChirho),
    ),
    // Only a platform root has this, and a platform root is not the migration unit.
    (
        "tenants-chirho",
        RootSurfacePolicyChirho::payload_chirho(SurfaceDispositionChirho::NotAMigrationUnitChirho),
    ),
];

/// Tenant logs the migration carries and the projection must not read (CF8 rows 1-5, 10 and 11).
///
/// **This is a second list on purpose. It is the COMPLEMENT of the projection manifest, not a copy
/// of it.** The manifest is not a passive declaration: the projection reads every log it names, for
/// its byte baseline, its typed ingestion (which parses each line) and the seqlog recovery scan.
/// Declaring a credential log there, so that a migration carries it, would widen what the
/// projection reads. That is a privacy change hidden inside a migration one. A log may sit in only
/// one of the two lists, and a test refuses a log named in both.
///
/// Each of these is root-signed history verified against `existing_pubkey_hex_chirho`. It verifies at
/// the target because `signing-key-chirho.bin` moves through the custody stages, so it adds no custody
/// law of its own. [`declared_log_surfaces_chirho`] joins this list to the manifest. Its head
/// sidecars, its completeness declaration and its tenant-log reference scan follow from that.
pub const CARRIED_UNPROJECTED_LOG_SURFACES_CHIRHO: &[&str] = &[
    "gate1-authority-log-chirho.jsonl",
    "head-removals-chirho.jsonl",
    "identity-credential-change-attempts-chirho.jsonl",
    "identity-credential-resets-chirho.jsonl",
    "identity-recovery-code-events-chirho.jsonl",
    "publication-intents-chirho.jsonl",
    "ref-snapshot-log-chirho.jsonl",
];

/// Logs that only a platform root writes (CF8 rows 6-9). A platform root is not a migration unit.
///
/// The publication applier is the only writer of the platform root, and these four logs are its
/// state, so they never reach a tenant root. They are logs, so their head sidecars take the same
/// policy (Agy #29519): `publication-applied-chirho.jsonl` is written through seqlog, and its
/// sidecar must read as not a migration unit rather than as undisposed.
pub const PLATFORM_ONLY_LOG_SURFACES_CHIRHO: &[&str] = &[
    "publication-applied-chirho.jsonl",
    "publication-owners-chirho.jsonl",
    "publication-reserved-slugs-chirho.jsonl",
    "slug-claims-chirho.jsonl",
];

/// The one policy every platform-only log and its head sidecar takes.
const PLATFORM_ONLY_LOG_POLICY_CHIRHO: RootSurfacePolicyChirho =
    RootSurfacePolicyChirho::payload_chirho(SurfaceDispositionChirho::NotAMigrationUnitChirho);

/// Domain separator for the semantic identity of the root-surface classifier.
///
/// v2 (2026-10-26) added the platform-only log population to the canonical form. A v1 digest was
/// computed over a layout without that field, so the version changed with the layout.
pub const DISPOSITION_POPULATION_DIGEST_SCHEMA_V2_CHIRHO: &str =
    "cairn.root-surface-disposition-population.v2.chirho";

/// Content identity of the semantic root-surface classifier.
///
/// This covers classification: the non-log policy rows, the declared-log population (the projection
/// manifest plus the carried unprojected logs) and derived HEAD-sidecar rule, the platform-only log
/// population and its sidecar rule, the configured-namespace rule, and the computed
/// travel/payload/retirement outcomes. It deliberately does NOT cover the filesystem walker or a caller-supplied observed
/// surface list. It also does not claim how every caller handles the classifier's `None` result;
/// caller-level fail-closed tests and guards own that behavior. A matching digest therefore cannot
/// make an omitted observed surface visible or prove that an uninspected caller refuses unknowns.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DispositionPopulationDigestChirho(String);

impl DispositionPopulationDigestChirho {
    pub fn as_str_chirho(&self) -> &str {
        &self.0
    }
}

#[derive(Serialize)]
struct CanonicalSurfacePolicyChirho {
    surface_chirho: String,
    policy_chirho: RootSurfacePolicyChirho,
    travels_with_root_chirho: bool,
    committed_payload_chirho: bool,
    erase_at_source_after_handoff_chirho: bool,
}

#[derive(Serialize)]
struct CanonicalDispositionPopulationChirho {
    schema_chirho: &'static str,
    non_log_surface_policies_chirho: Vec<CanonicalSurfacePolicyChirho>,
    declared_log_surfaces_chirho: Vec<String>,
    declared_log_policy_chirho: CanonicalSurfacePolicyChirho,
    declared_log_head_suffix_chirho: &'static str,
    platform_only_log_surfaces_chirho: Vec<String>,
    platform_only_log_policy_chirho: CanonicalSurfacePolicyChirho,
    configured_namespace_policy_chirho: CanonicalSurfacePolicyChirho,
}

fn canonical_surface_policy_chirho(
    surface_chirho: impl Into<String>,
    policy_chirho: RootSurfacePolicyChirho,
    travel_predicate_chirho: fn(SurfaceDispositionChirho) -> bool,
) -> CanonicalSurfacePolicyChirho {
    CanonicalSurfacePolicyChirho {
        surface_chirho: surface_chirho.into(),
        policy_chirho,
        travels_with_root_chirho: travel_predicate_chirho(
            policy_chirho.movement_disposition_chirho,
        ),
        committed_payload_chirho: surface_is_committed_payload_chirho(policy_chirho),
        erase_at_source_after_handoff_chirho: source_erases_surface_after_handoff_chirho(
            policy_chirho,
        ),
    }
}

fn disposition_population_digest_for_inputs_chirho(
    non_log_surface_policies_chirho: &[(&str, RootSurfacePolicyChirho)],
    declared_log_surfaces_chirho: &BTreeSet<String>,
    platform_only_log_surfaces_chirho: &[&str],
    travel_predicate_chirho: fn(SurfaceDispositionChirho) -> bool,
) -> DispositionPopulationDigestChirho {
    let mut canonical_non_log_chirho = non_log_surface_policies_chirho
        .iter()
        .map(|(surface_chirho, policy_chirho)| {
            canonical_surface_policy_chirho(
                *surface_chirho,
                *policy_chirho,
                travel_predicate_chirho,
            )
        })
        .collect::<Vec<_>>();
    canonical_non_log_chirho.sort_by(|left_chirho, right_chirho| {
        left_chirho.surface_chirho.cmp(&right_chirho.surface_chirho)
    });

    let carried_payload_policy_chirho =
        RootSurfacePolicyChirho::payload_chirho(SurfaceDispositionChirho::CarriedWithTheRootChirho);
    let identity_chirho = CanonicalDispositionPopulationChirho {
        schema_chirho: DISPOSITION_POPULATION_DIGEST_SCHEMA_V2_CHIRHO,
        non_log_surface_policies_chirho: canonical_non_log_chirho,
        declared_log_surfaces_chirho: declared_log_surfaces_chirho.iter().cloned().collect(),
        declared_log_policy_chirho: canonical_surface_policy_chirho(
            "declared-log-surface-chirho",
            carried_payload_policy_chirho,
            travel_predicate_chirho,
        ),
        declared_log_head_suffix_chirho: SEQLOG_HEAD_SUFFIX_CHIRHO,
        platform_only_log_surfaces_chirho: platform_only_log_surfaces_chirho
            .iter()
            .map(|surface_chirho| (*surface_chirho).to_string())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        platform_only_log_policy_chirho: canonical_surface_policy_chirho(
            "platform-only-log-surface-chirho",
            PLATFORM_ONLY_LOG_POLICY_CHIRHO,
            travel_predicate_chirho,
        ),
        configured_namespace_policy_chirho: canonical_surface_policy_chirho(
            "configured-namespace-root-surface-chirho",
            carried_payload_policy_chirho,
            travel_predicate_chirho,
        ),
    };
    DispositionPopulationDigestChirho(
        hash_object_chirho(&identity_chirho)
            .expect("the fixed in-memory disposition classifier must serialize")
            .0,
    )
}

/// Derive the current classifier identity from its semantic inputs, never from source-file bytes.
///
/// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/tenant-migration-chirho/authority-contract-chirho.md`
/// under "Root Hygiene And Classifier Identity".
pub fn disposition_population_digest_chirho() -> DispositionPopulationDigestChirho {
    disposition_population_digest_for_inputs_chirho(
        NON_LOG_SURFACE_POLICIES_CHIRHO,
        &declared_log_surfaces_chirho(),
        PLATFORM_ONLY_LOG_SURFACES_CHIRHO,
        surface_travels_with_the_root_chirho,
    )
}

/// The complete policy of one surface, or `None` if any axis remains undeclared.
///
/// Declared LOG surfaces are carried — they are the tenant's signed history. Platform-only logs are
/// not a migration unit. Everything else must appear in [`NON_LOG_SURFACE_POLICIES_CHIRHO`] by name;
/// an unrecognised surface returns `None` so movement, payload, and retirement callers all refuse
/// rather than borrowing another axis's answer.
pub fn policy_for_surface_chirho(surface_chirho: &str) -> Option<RootSurfacePolicyChirho> {
    if let Some((_, policy_chirho)) = NON_LOG_SURFACE_POLICIES_CHIRHO
        .iter()
        .find(|(name_chirho, _)| *name_chirho == surface_chirho)
    {
        return Some(*policy_chirho);
    }
    if let Some(policy_chirho) = log_surface_policy_chirho(surface_chirho) {
        return Some(policy_chirho);
    }
    // A seqlog HEAD SIDECAR takes its log's disposition, DERIVED rather than enumerated.
    //
    // Every declared log carries an O(1) `<log>.head-chirho` checkpoint beside it. Measured against
    // a real root on 2026-08-19: fourteen of them, none disposed, so a target refused on the
    // companions of surfaces that were themselves carried. A row per sidecar would need a new row
    // every time a log is added — and the row would be missing exactly when someone forgot, which is
    // the failure this derivation removes.
    //
    // Only a LOG's sidecar is derived, from whichever list holds the log. A table row has no head
    // checkpoint, so `<row>.head-chirho` stays unknown and refuses.
    surface_chirho
        .strip_suffix(SEQLOG_HEAD_SUFFIX_CHIRHO)
        .and_then(log_surface_policy_chirho)
}

/// The policy of a LOG surface: carried when declared, not a migration unit when platform-only.
fn log_surface_policy_chirho(log_chirho: &str) -> Option<RootSurfacePolicyChirho> {
    if declared_log_surfaces_chirho().contains(log_chirho) {
        Some(RootSurfacePolicyChirho::payload_chirho(
            SurfaceDispositionChirho::CarriedWithTheRootChirho,
        ))
    } else if PLATFORM_ONLY_LOG_SURFACES_CHIRHO.contains(&log_chirho) {
        Some(PLATFORM_ONLY_LOG_POLICY_CHIRHO)
    } else {
        None
    }
}

/// The movement axis retained for callers that need only the existing migration ruling.
pub fn disposition_for_surface_chirho(surface_chirho: &str) -> Option<SurfaceDispositionChirho> {
    policy_for_surface_chirho(surface_chirho)
        .map(|policy_chirho| policy_chirho.movement_disposition_chirho)
}

/// Whether this classified surface is inside the payload commitment.
pub fn surface_is_committed_payload_chirho(policy_chirho: RootSurfacePolicyChirho) -> bool {
    policy_chirho.payload_disposition_chirho
        == SurfacePayloadDispositionChirho::CommittedPayloadChirho
}

/// Whether source retirement must erase this classified private-custody surface after handoff.
pub fn source_erases_surface_after_handoff_chirho(policy_chirho: RootSurfacePolicyChirho) -> bool {
    policy_chirho.source_retirement_disposition_chirho
        == SourceRetirementDispositionChirho::EraseAtSourceAfterHandoffChirho
}

/// Why a migration is refused on disposition grounds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DispositionRefusalChirho {
    /// Present in the root, and nothing says what a migration does with it.
    UndisposedSurfaceChirho { surface_chirho: String },
    /// Custody-bearing, and this slice deliberately has no transfer mechanism.
    CustodyTransferNotMechanisedChirho { surface_chirho: String },
    /// The root is a platform root, which is not the placement/authority/migration unit.
    NotAMigrationUnitChirho { surface_chirho: String },
}

/// The disposition result, carrying the count it was computed over.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispositionVerdictChirho {
    pub surfaces_considered_chirho: usize,
    pub refusals_chirho: Vec<DispositionRefusalChirho>,
    pub disposition_population_digest_chirho: DispositionPopulationDigestChirho,
}

impl DispositionVerdictChirho {
    /// Disposed AND computed over at least one surface — the same anti-vacuity rule the other two
    /// halves carry, for the same reason: a root nobody looked at has not been cleared.
    pub fn is_disposed_over_evidence_chirho(&self) -> bool {
        self.refusals_chirho.is_empty() && self.surfaces_considered_chirho > 0
    }
}

/// The root-level surface that holds a root's CONFIGURED ledger storage namespace.
///
/// `storage_namespace_chirho` is a configured relative path (e.g. `"my-parent-chirho/ledger-chirho"`),
/// so the surface it lands under is whatever the operator named. Returns the FIRST component, which
/// is the root-level directory a surface enumeration will actually see.
pub fn configured_namespace_root_surface_chirho(storage_namespace_chirho: &str) -> Option<String> {
    storage_namespace_chirho
        .split('/')
        .find(|component_chirho| !component_chirho.is_empty())
        .map(|component_chirho| component_chirho.to_string())
}

/// Give every observed surface a disposition, or refuse and say which one and why.
///
/// `configured_namespace_root_surface_chirho` is CARRIED, and it is an INPUT rather than a table row
/// on purpose. The ledger storage namespace is configured per root, so its directory name is the
/// operator's choice — a fixed table can never name it, and a row that happened to match one
/// deployment would look fixed while failing every other root. Measured 2026-08-19: with no such
/// input, a real drill root failed the disposition verdict on its own ledger namespace, which is the
/// one surface that is unambiguously load-bearing.
///
/// Carried, not rebuilt or disposable: it holds the tenant's journal.
/// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/tenant-migration-chirho/authority-contract-chirho.md`
/// under "Root Hygiene And Classifier Identity".
pub fn verify_surface_dispositions_chirho(
    observed_surfaces_chirho: &[String],
    configured_namespace_root_surface_chirho: Option<&str>,
) -> DispositionVerdictChirho {
    let refusals_chirho = observed_surfaces_chirho
        .iter()
        .filter(|surface_chirho| {
            // The configured namespace is carried. Compared to the SUPPLIED value, never to a
            // literal, so a root that names it differently is treated identically.
            configured_namespace_root_surface_chirho
                .is_none_or(|configured_chirho| configured_chirho != surface_chirho.as_str())
        })
        .filter_map(
            |surface_chirho| match disposition_for_surface_chirho(surface_chirho) {
                // Still refuses, and must: the variant means "no mechanism", and a custody surface
                // nobody has decided about should stop a migration rather than ride along.
                Some(SurfaceDispositionChirho::CustodyTransferRefusedInThisSliceChirho) => Some(
                    DispositionRefusalChirho::CustodyTransferNotMechanisedChirho {
                        surface_chirho: surface_chirho.clone(),
                    },
                ),
                Some(SurfaceDispositionChirho::NotAMigrationUnitChirho) => {
                    Some(DispositionRefusalChirho::NotAMigrationUnitChirho {
                        surface_chirho: surface_chirho.clone(),
                    })
                }
                Some(_) => None,
                None => Some(DispositionRefusalChirho::UndisposedSurfaceChirho {
                    surface_chirho: surface_chirho.clone(),
                }),
            },
        )
        .collect();
    DispositionVerdictChirho {
        surfaces_considered_chirho: observed_surfaces_chirho.len(),
        refusals_chirho,
        disposition_population_digest_chirho: disposition_population_digest_chirho(),
    }
}

#[cfg(test)]
#[path = "surface_disposition_tests_chirho.rs"]
mod surface_disposition_tests_chirho;

/// Does the model say this surface TRAVELS with the root — that a migrated root should still have it?
///
/// Derived from the disposition, never enumerated, so a new table row inherits the right answer.
/// `Rebuilt` and `ProvenDisposable` are deliberately false: the first is re-made at the target and
/// the second is not wanted there.
pub fn surface_travels_with_the_root_chirho(disposition_chirho: SurfaceDispositionChirho) -> bool {
    match disposition_chirho {
        SurfaceDispositionChirho::CarriedWithTheRootChirho
        | SurfaceDispositionChirho::CustodyTransferredThroughMoveStagesChirho => true,
        SurfaceDispositionChirho::RebuiltAtTargetChirho
        | SurfaceDispositionChirho::ProvenDisposableChirho
        | SurfaceDispositionChirho::CustodyTransferRefusedInThisSliceChirho
        | SurfaceDispositionChirho::NotAMigrationUnitChirho => false,
    }
}

/// A surface the source has, the model says travels, and the target does not have.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequiredSurfaceRefusalChirho {
    MissingAtTargetChirho { surface_chirho: String },
}

/// Every surface that should have travelled and did not.
///
/// **WHY THIS EXISTS, and it is the finding of the first real migration (2026-08-19).** The other
/// three halves all ask questions about what a root HAS: is everything here declared, does it
/// resolve here, does everything here have a ruling. None of them can ask whether something is
/// MISSING — the completeness half says so in its own words, that absence is informational because
/// "a root need not use every surface". True of an optional surface. Catastrophic for a required
/// one.
///
/// The consequence, measured rather than argued: a target passed all three halves and activated,
/// and then could not start, because the surfaces holding its signing identity were absent — and
/// they were absent from the CHECK too, so nothing refused. The source, which has them, refuses the
/// same check. **One model, opposite verdicts on the two sides of one migration, and the side that
/// passes is the side that cannot run.**
///
/// Note what this does NOT do: it does not carry anything. The executed migration fences a source
/// and activates a target whose bytes an operator placed; the move-stage ladder that the custody
/// disposition is named for is a different ladder in a different crate, which this path never
/// enters. So this half's whole job is to make an operator's incomplete staging FAIL CLOSED instead
/// of activating into a root that cannot serve.
pub fn verify_required_surfaces_chirho(
    source_surfaces_chirho: &[String],
    target_surfaces_chirho: &[String],
) -> RequiredSurfaceVerdictChirho {
    let target_set_chirho: BTreeSet<&str> =
        target_surfaces_chirho.iter().map(String::as_str).collect();
    let mut required_considered_chirho = 0usize;
    let mut refusals_chirho = Vec::new();
    for surface_chirho in source_surfaces_chirho {
        let Some(disposition_chirho) = disposition_for_surface_chirho(surface_chirho) else {
            // Undisposed at the SOURCE is the disposition half's finding to report, not this one.
            continue;
        };
        if !surface_travels_with_the_root_chirho(disposition_chirho) {
            continue;
        }
        required_considered_chirho += 1;
        if !target_set_chirho.contains(surface_chirho.as_str()) {
            refusals_chirho.push(RequiredSurfaceRefusalChirho::MissingAtTargetChirho {
                surface_chirho: surface_chirho.clone(),
            });
        }
    }
    RequiredSurfaceVerdictChirho {
        required_considered_chirho,
        refusals_chirho,
        disposition_population_digest_chirho: disposition_population_digest_chirho(),
    }
}

/// The required-surface result, with the same anti-vacuity rule the other three halves carry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequiredSurfaceVerdictChirho {
    pub required_considered_chirho: usize,
    pub refusals_chirho: Vec<RequiredSurfaceRefusalChirho>,
    pub disposition_population_digest_chirho: DispositionPopulationDigestChirho,
}

impl RequiredSurfaceVerdictChirho {
    /// Nothing missing AND at least one required surface actually considered. A source that offered
    /// no travelling surfaces has not been checked, which is the same reason the other three carry
    /// this guard.
    pub fn is_complete_over_evidence_chirho(&self) -> bool {
        self.refusals_chirho.is_empty() && self.required_considered_chirho > 0
    }
}
