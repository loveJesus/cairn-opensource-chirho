// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The author's one typed choice — production or synthetic test kind — and the two naming laws plus
//! the artifact marker that choice implies.
//!
//! Brick #5 of the generic ledger-host authoring program
//! (`spec-chirho/workstream-state-chirho/ledger-host-config-authoring-design-chirho.md` §5,
//! ruling (b): ONE author with a typed test-kind mode, fenced at the CONSUMER).
//!
//! **THE MODE IS LEGIBILITY, NOT THE CONTROL. Said first because a reader who takes it for the
//! control stops looking for the one that is.** What actually makes a test-kind issuer unusable in
//! production is CUSTODY: the config pin is DERIVED from a pre-provisioned secret rather than
//! asserted, so a test-kind issuer secret that has never been written into a production root's
//! secret store cannot sign that root's registry — whatever this enum said at authoring time. An
//! operator who supplies the production issuer secret while selecting `TestKindChirho` gets a
//! production key wearing a test-kind marker, and nothing in this module can prevent that. What the
//! mode buys is that the resulting artifact SAYS which one it is, so the consumer fence
//! (`cairn_ledger_host_chirho::test_kind_fence_chirho`) has something to refuse and an operator has
//! something to read. Design §3.f states the same three-layer split; only layer 3 is structural.
//!
//! **The naming laws run in BOTH directions, and the second direction is the useful one.** Requiring
//! a test-kind run to use reserved names catches an operator who selected the wrong mode. Refusing a
//! PRODUCTION run that names a reserved secret or principal catches the opposite slip — reaching for
//! the drill's issuer while authoring a real host — which is the slip that costs money. Both are
//! tripwires for accident, never fences against intent (§3.f.1).
//!
//! **What a caller may hand this module, and why that shape was chosen.** The mode is a fieldless
//! `Copy` enum: a CHOICE, never a VALUE. Brick #4 found the same hazard one type over — an
//! already-derived artifacts value has `pub` fields, so accepting one would let an outside caller
//! supply an invented issuer pin — and the same question applies here. If `TestKindChirho` carried
//! the marker, a caller could hand over a marker with a schema this crate never wrote. It does not:
//! the marker is CONSTRUCTED here from this crate's own constant, so the only thing crossing the
//! boundary is which of two branches to take.
//!
//! No key is read, derived, or created anywhere in this module; it holds two string predicates and
//! one constructor.

use crate::error_chirho::{LedgerRegenesisRefusalChirho, LedgerRegenesisResultChirho};
use cairn_config_chirho::config_chirho::{
    LedgerHostTestKindMarkerConfigChirho, LEDGER_HOST_TEST_KIND_ISSUER_PRINCIPAL_PREFIX_CHIRHO,
    LEDGER_HOST_TEST_KIND_MARKER_SCHEMA_V1_CHIRHO,
};

/// Which authoring coordinate a mode/naming refusal is about. Both coordinates are checked by one
/// law, and a refusal that could not say WHICH one was wrong would send an operator to edit the
/// reviewed document when the defect is in the invocation, or the reverse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LedgerHostAuthoringModeCoordinateChirho {
    /// The `--issuer-secret` style argument: which pre-provisioned secret this run exercises.
    IssuerSecretNameChirho,
    /// `issuer_principal_chirho` in the reviewed document: the name the registry records are signed
    /// under, and therefore the one the emitted config pins.
    IssuerPrincipalChirho,
}

impl LedgerHostAuthoringModeCoordinateChirho {
    pub fn label_chirho(self) -> &'static str {
        match self {
            Self::IssuerSecretNameChirho => "kind issuer secret name",
            Self::IssuerPrincipalChirho => "kind issuer principal",
        }
    }
}

/// The one choice an authoring invocation makes about what it is producing.
///
/// There is no `Default`, and that is deliberate: every road that authors artifacts takes this by
/// value with no fallback, so no composition can drift into production by omission. (M140 removed
/// the implicit `PlainChirho` runtime-body default for the same reason; a defaulted authority mode
/// is the shape that lets a missing argument decide a money question.)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LedgerHostAuthoringModeChirho {
    /// Authoring a real host: reserved test-kind names are refused, and the emitted config carries
    /// no marker, exactly as every reviewed production config already does.
    ProductionChirho,
    /// Authoring for a synthetic test kind: reserved names are REQUIRED, and the emitted config
    /// carries the marker every production resident-actor door refuses.
    TestKindChirho,
}

impl LedgerHostAuthoringModeChirho {
    /// The marker this mode stamps into the emitted config, if any.
    ///
    /// Built from this crate's constants rather than from anything a caller supplied — see the
    /// module header on why the mode is a choice and not a value.
    pub(crate) fn authored_test_kind_marker_chirho(
        self,
    ) -> Option<LedgerHostTestKindMarkerConfigChirho> {
        match self {
            Self::ProductionChirho => None,
            Self::TestKindChirho => Some(LedgerHostTestKindMarkerConfigChirho {
                schema_chirho: LEDGER_HOST_TEST_KIND_MARKER_SCHEMA_V1_CHIRHO.to_owned(),
                // Operator-authored test-kind roots default to the CF8 loss-witness requirement (drill
                // posture). The single-node served-money dev exemption is set only by the dev bootstrap.
                loss_witness_exempt_chirho: false,
            }),
        }
    }

    /// Refuse an invocation whose issuer naming disagrees with the mode it declared.
    ///
    /// Checked BEFORE any secret store is touched, so a mode slip refuses with a mode identity
    /// rather than with whichever custody question happened to be asked first. The secret name is
    /// checked before the principal because it is the coordinate the operator typed on this
    /// invocation, while the principal came from a document that was reviewed earlier.
    pub(crate) fn refuse_mismatched_issuer_naming_chirho(
        self,
        issuer_secret_name_chirho: &str,
        issuer_principal_chirho: &str,
    ) -> LedgerRegenesisResultChirho<()> {
        for (coordinate_chirho, value_chirho) in [
            (
                LedgerHostAuthoringModeCoordinateChirho::IssuerSecretNameChirho,
                issuer_secret_name_chirho,
            ),
            (
                LedgerHostAuthoringModeCoordinateChirho::IssuerPrincipalChirho,
                issuer_principal_chirho,
            ),
        ] {
            let reserved_chirho =
                value_chirho.starts_with(LEDGER_HOST_TEST_KIND_ISSUER_PRINCIPAL_PREFIX_CHIRHO);
            match self {
                Self::TestKindChirho if !reserved_chirho => {
                    return Err(
                        LedgerRegenesisRefusalChirho::AuthoringTestKindReservedNameMissingChirho {
                            coordinate_chirho,
                        },
                    );
                }
                Self::ProductionChirho if reserved_chirho => {
                    return Err(
                        LedgerRegenesisRefusalChirho::AuthoringProductionReservedNameRefusedChirho {
                            coordinate_chirho,
                        },
                    );
                }
                Self::TestKindChirho | Self::ProductionChirho => {}
            }
        }
        Ok(())
    }
}
