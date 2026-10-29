// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The production side of the test-kind fence: refuse a host config that says it was authored for a
//! synthetic test kind, so no production resident actor takes money authority from one.
//!
//! Brick #5 of the generic ledger-host authoring program
//! (`spec-chirho/workstream-state-chirho/ledger-host-config-authoring-design-chirho.md` §5, ruling
//! (b)). The AUTHOR side is a typed mode in `cairn-ledger-regenesis-chirho`; this is the consumer,
//! and the design pairs them in one brick on purpose — a marker with no consumer invites a reader to
//! believe a check happens that does not.
//!
//! **What this fence IS and IS NOT, stated first because the honest limit is the point.** It is a
//! named refusal at the two production resident-actor doors. It is NOT what makes a test-kind issuer
//! unusable in production: that is CUSTODY (§3.f.3). A test-kind issuer secret that has never been in
//! a production root's secret store cannot sign that root's registry, because the config pin is
//! DERIVED from the secret rather than asserted — and no flag, mode, or marker changes that either
//! way. Read this module as defence in depth over a structural property, never as the property.
//!
//! **Why here and not one layer down.** The obvious alternative is to refuse where the config's
//! issuer pin becomes `PinnedKindIssuerVerifierChirho`. Measured, that is wrong: the test-kind geo
//! node reaches the same conversion (both the production and test-kind voter startups call
//! `LedgerHostProjectionReadPortChirho::open_existing_chirho`, which builds it), so a refusal there
//! would deny the drill it exists to permit. The production/test-kind fork in this codebase is the
//! resident-actor DOOR — two provider-less production openers versus two compensation-provider
//! openers whose callers `gd7_compensation_provider_door_has_no_shipping_binary_caller_chirho`
//! already confines to the distinct test-kind crate. Putting the fence at that same fork keeps ONE
//! production/test-kind boundary in the codebase rather than inventing a second one.
//!
//! **What this function's own PARAMETER can and cannot bind — brick #4's question, asked of brick
//! #5's type.** Brick #4 found that accepting an already-derived artifacts value would let a caller
//! supply an invented issuer pin, because that type's fields are `pub`. This fence accepts
//! `&LedgerHostConfigChirho`, whose fields are `pub` too, so an in-process caller can hand over a
//! value it built with `test_kind_chirho: None` and pass. That is NOT closable here and is not a
//! hole this brick opened: it is the same boundary the issuer pin itself sits behind. The config's
//! integrity comes from being PARSED out of a custody-checked file, and by the time a value exists
//! in memory the composition holding it is already the trusted one. The fence therefore binds what
//! a config FILE says; a caller that assembles a config in code is outside its scope, exactly as it
//! is outside `validate_chirho`'s.
//!
//! **Deliberately un-fenced, named so nobody reads silence as coverage.**
//! * The read port (`LedgerHostProjectionReadPortChirho::open_existing_chirho`) — shared by both
//!   voter startups, and it composes reads, never the elected write or mint authority.
//! * The held GD7 coordinator — measured: it builds no `PinnedKindIssuerVerifierChirho` at all, so a
//!   marked config cannot become mint authority through it, and there is no test-kind held binary,
//!   so fencing it would deny the held side of a drill for no fence.
//! * `cairn-ledger-regenesis-chirho` — the operator create-authority tool, which is what AUTHORS a
//!   test-kind pair; refusing markers there would make the mode unusable by its own author.

use anyhow::{bail, Result};
use cairn_config_chirho::config_chirho::LedgerHostConfigChirho;

/// The stable refusal token this fence emits. Callers and tests match on THIS rather than on prose,
/// so the refusal's identity survives a wording change and cannot be confused with a neighbouring
/// custody or schema refusal.
pub const TEST_KIND_MARKED_LEDGER_HOST_CONFIG_REFUSAL_CHIRHO: &str =
    "TestKindMarkedLedgerHostConfigRefusedChirho";

/// The stable refusal token the INVERSE fence emits. Distinct from the production-side token above so
/// a test-kind-required refusal is never confused with a production refusal, a custody refusal, or a
/// schema refusal. Callers and tests match on THIS rather than on prose.
pub const NON_TEST_KIND_LEDGER_HOST_CONFIG_REFUSAL_CHIRHO: &str =
    "NonTestKindLedgerHostConfigRefusedChirho";

/// Refuse a test-kind-marked host config on a production composition road.
///
/// Absence of the marker is the passing case, and that is the correct default direction: a config
/// with no marker is exactly what every reviewed production config has always been, and the fence
/// grants nothing it did not already have.
pub fn refuse_test_kind_marked_host_config_chirho(
    config_chirho: &LedgerHostConfigChirho,
) -> Result<()> {
    if config_chirho.test_kind_chirho.is_some() {
        bail!(
            "{TEST_KIND_MARKED_LEDGER_HOST_CONFIG_REFUSAL_CHIRHO}: a production ledger-host \
             composition will not open a config authored for a synthetic test kind"
        );
    }
    Ok(())
}

/// Require a test-kind-marked host config on a DEV-ONLY (test-kind) composition road — the exact
/// inverse of [`refuse_test_kind_marked_host_config_chirho`].
///
/// This is the fence for a door that exists ONLY to open a SYNTHETIC test-kind root (a1's dev
/// bootstrap root and the drill roots): PRESENCE of the marker is the passing case, and ABSENCE fails
/// closed, so a dev-context door can never take money authority over a production (unmarked) ledger.
/// The two fences together keep exactly one production/test-kind boundary at the resident-actor door:
/// a production door refuses a test-kind config, and a dev-context door refuses a production config.
///
/// The scope limit the production fence carries applies here unchanged (see this module's header):
/// this binds what a config FILE says, parsed out of a custody-checked file; an in-process caller
/// that assembles a `LedgerHostConfigChirho` with `pub` fields is outside its scope, exactly as it is
/// outside `validate_chirho`'s. The load-bearing production guarantee remains custody, not this flag.
pub fn require_test_kind_marked_host_config_chirho(
    config_chirho: &LedgerHostConfigChirho,
) -> Result<()> {
    if config_chirho.test_kind_chirho.is_none() {
        bail!(
            "{NON_TEST_KIND_LEDGER_HOST_CONFIG_REFUSAL_CHIRHO}: a dev-context (test-kind) \
             ledger-host composition requires a test-kind host config and will not open a \
             production ledger"
        );
    }
    Ok(())
}
