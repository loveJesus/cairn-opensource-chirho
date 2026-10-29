// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The read-only sealed-plan chain must never regain signing capability, by EITHER door.
//!
//! A restore path walks this chain. It once demanded `Gd7ReconciliationSignerPortChirho` while using
//! only verifier-supertrait methods, so a caller that never signs had to hold a signing key —
//! authority conferred by a TYPE rather than by a use.
//!
//! # THE TWO DOORS, AND WHY A PARAMETER CHECK ALONE IS NOT ENOUGH
//!
//! Narrowing the parameters closes the FIRST door: nothing can sign through the capability the
//! caller supplied. It says nothing about the SECOND: a reachable function could construct or open a
//! signer internally and never mention it in its signature. This guard watches both.
//!
//! # LIMITS — split by KIND, because mixing them is how this file's own overstatement survived
//!
//! An earlier version had one heading, "WHAT THIS GUARD DOES NOT COVER", and put a claim about the
//! COMPLEMENTARY instrument inside a limits section about THIS one. That is what let it pass its
//! author's re-read: a limits heading advertises rigour, and **a rigour signal is an audit
//! suppressant** — the more carefully a structure says it has been checked, the less its contents
//! get checked. So the two kinds are separated, and this section is the FIRST place to audit rather
//! than the place to skip.
//!
//! ## MECHANISM — what this instrument structurally cannot do (reliable; needs no experiment)
//!
//! - **Text cannot see execution.** A call present but never run passes this guard. Demonstrated:
//!   a reviewer left `.sign_chirho(` in place behind `if false` and these guards stayed 3/3 while a
//!   behavioural arm failed at the first persist.
//! - **Text cannot compute a call closure.** A capability acquired inside a deeper helper this list
//!   does not name is invisible here. **This is no longer an abstract limit — it has a MEASURED
//!   instance.** See the A9 residual below, which compiles and is missed.
//! - **The body extractor is over-inclusive at the tail**, running to the next declaring line. That
//!   is the safe direction for MISSES and the UNSAFE one for FALSE ALARMS, so re-check the region
//!   boundary whenever a name joins the scanned set.
//!
//! ## COVERAGE — claims about the world this instrument meets. UNMEASURED UNTIL PROBED.
//!
//! Every line here is a work item, not a reassurance. Its author is systematically optimistic about
//! this kind of claim and reliable only about the kind above.
//!
//! - `[PROBED — was a real bypass, now closed]` the shared reducer body. A resolved, COMPILING
//!   internal signer acquisition planted outside its access-mode match left all three guards green.
//!   It is now in the scanned set with no allow-list.
//! - `[PROBED — was a real bypass, now closed]` first-textual-occurrence anchoring. One line of
//!   ordinary prose (`// fn NAME` above a declaration) redirected extraction into the comment while
//!   the total count stayed non-vacuous. Anchors are now RESOLVED declarations with a per-needle
//!   uniqueness assertion.
//! - `[PROBED — was a real bypass, now closed]` **B4: the door-two needle list was an ENUMERATED
//!   population.** A naturally written second production signer with a distinct type name, whose
//!   `impl` lived in a distant module, defeated all three literal needles: it compiled and the
//!   guards stayed 3/3. Door two now DERIVES its population by asking the trait on every run.
//! - `[PROBED — closed]` rebinding across a rename. `use X as Y;` and `type Y = X;` both put the
//!   implementor's name at file top, OUTSIDE every extracted body. Resolved to a fixpoint over both
//!   forms, workspace-wide. The `type` form MISSED the first version of the remedy and is the reason
//!   the fixpoint exists.
//! - `[PROBED — closed]` a factory handing out `Box<dyn Trait>` while the call site annotates
//!   nothing. Producers are derived by RETURN TYPE from the same literal.
//! - `[PROBED — was a real bypass, now closed]` **B7: a factory returning the CONCRETE type.** The
//!   most ordinary refactor there is — extracting duplicated construction into a free helper
//!   returning `Result<ExistingNodeGd7SignerChirho>` — evaded all four halves and compiled, handing
//!   the read-only chain the REAL production signer. Producers now test the return type against the
//!   trait OR any derived implementor OR any derived rebinding.
//! - `[UNPROBED]` whether every function reachable on the read-only path is named in the list at all.
//!
//! ## RESIDUALS — the CEILING of a text instrument, not oversights in this one
//!
//! A self-reported weakness is a hypothesis until it is planted. Each of these was planted and
//! compiled, so each is a fact about this instrument rather than a worry about it.
//!
//! Read them as one fact rather than a list of bugs: **door two is a text instrument, and every text
//! instrument samples a population.** The sampling has now been improved twice — enumerated to
//! derived (B4), derived to derived-plus-implementors (B7) — and each improvement was correct and
//! each left a residual of the same shape. That is the ceiling, and this guard sits at ENFORCED on
//! the DOCUMENTED → ENFORCED → UNREPRESENTABLE ladder because no text scanner computes a call
//! closure.
//!
//! - **A9 — an indirect holder. MISSES. Reachability: PLAUSIBLE.** A wrapper that CONSTRUCTS a
//!   signer internally and exposes a delegating method implements nothing, so it is not a derived
//!   implementor; its constructor returns the wrapper, so it is not a derived producer. A read-only
//!   body naming only the wrapper acquires signing authority unseen. Planted, compiled clean.
//!   Not closed here: catching it needs a transitive call closure, and a depth-1 approximation would
//!   fire on the honest delegation the shared reducer already performs, curable only by an
//!   allow-list — the seam a future violation hides in.
//! - **Derive-macro-generated impl — expected MISS. Reachability: LOW, and measured.** A
//!   `macro_rules!` body leaves the `impl` line in source, which is why a reviewer's macro arm
//!   reached it and it REFUSED. A proc-macro leaves no text at all, so by mechanism the implementor
//!   derivation cannot see it. Reaching that shape means ADDING a proc-macro crate to a workspace
//!   that has never had one — censused at 0 proc-macro crates against 105 manifests — which is a far
//!   louder act than extracting a helper.
//!
//! **THE CURE IS NAMED, AND IT IS NOT A BETTER SCANNER.** A residual with an identified cure reads
//! differently from one without, so: a CRATE BOUNDARY computes a real closure and `cargo` enforces
//! it. If the read-only plan reducer were extracted into a crate depending on `contract_chirho`'s
//! traits and NOT on the signer adapter's crate, nothing in it could construct a signer by any
//! spelling — factory, wrapper, macro or otherwise — because the type would not be in its dependency
//! graph. A9 and the derive-macro residual close at once, by construction.
//! Visibility narrowing is NOT the cure and that is measured, not assumed: production construction
//! of `ExistingNodeGd7SignerChirho` spans THREE crates (`cairn-cli-chirho`,
//! `cairn-ledger-host-chirho`, `cairn-ledger-geo-node-chirho`), so the constructors must stay `pub`
//! and `pub(crate)` cannot close anything.
//!
//! **So state door two's reach precisely: closed for DIRECT acquisition — constructing a signer,
//! rebinding its name, or calling a function that returns one, by trait or concrete type — and open
//! for INDIRECT acquisition through a type that holds one without implementing the trait.**
//!
//! # MUTATION RECORD — one row CORRECTED, kept here because the original travelled
//!
//! This guard's first landing recorded five mutations. One row was wrong and is superseded rather
//! than deleted, because the original claim is in a commit message that must not be amended — a
//! reviewer's findings are pinned to that SHA.
//!
//! ```text
//!   ORIGINAL   M2  acquire a signer internally (unimported)  ->  COMPILE-ERROR, "cannot ship"
//!   CORRECTED  M2  INCONCLUSIVE. The compile failure was an UNRESOLVED IMPORT, not any capability
//!                  property. A reviewer planted the same hazard properly resolved: it COMPILED
//!                  CLEANLY while all three guards stayed green. The class ships; only my malformed
//!                  instance did not.
//! ```
//!
//! **A NEGATIVE RESULT MUST NAME ITS CAUSE, or it is indistinguishable from an accident.** A
//! compile-fail arm asserts the DIAGNOSTIC IDENTITY — the trait-bound error naming the trait — never
//! a nonzero exit; then restores and confirms the baseline compiles again, proving the break was
//! yours and not ambient. An INCONCLUSIVE row is worth more than a green one because it names work
//! still owed: this row said "covered", so nobody looked again, and the real hole (the shared reducer
//! body) sat untested until an adversary who had not written the arm looked anyway.
//!
//! # WHAT THE COMPILE WITNESS ACTUALLY ESTABLISHES — scoped, because it was overstated here
//!
//! A verifier-only compile witness proves the **SUPPLIED TYPE-REQUIREMENT closure**: nothing signs
//! through the capability the caller handed in, at any depth, by any route. It does **NOT** establish
//! that no reachable function CONSTRUCTS a capability internally — that compiles cleanly, measured.
//! So door two is a SAMPLED guard property and this file is the sampler. The two instruments are
//! disjoint: neither can cover the other's door.
//!
//! # WHAT DERIVING CHANGED, AND WHAT IT DID NOT
//!
//! Door two is still a text instrument and still samples. What changed is WHAT it samples. It used
//! to sample the SIGNER POPULATION — a set that grows whenever an author writes a new type, so the
//! list aged silently and a guard that had gone blind still reported 3/3. It now samples only
//! RUST'S OWN GRAMMAR: one trait literal, two rebinding forms, one return position. That set does
//! not grow when the codebase does.
//!
//! **This is a change of kind, not of degree, and it is the only thing that separates the fix from
//! the defect.** Adding a fourth spelling would have been the same instrument with a longer list —
//! and the next naturally-written signer would have walked past it exactly as this one did.

use super::super::*;

/// Functions that exist ONLY on the read-only path. Every one must be verifier-only in both doors.
///
/// Resolved by NAME, never by file, because two of these live in a module that also owns the one
/// legitimately-signing function.
///
/// NO TRAILING `(` — and that is not a detail. The first version of this list spelled every needle
/// `fn NAME(`, which silently failed to find `reverify_record_inputs_read_only_chirho` because its
/// declaration is `fn NAME<'records_chirho>(`. A GENERIC PARAMETER sits between the name and the
/// paren. The count assertion below is the only reason that surfaced instead of quietly shrinking
/// this guard's coverage from seven functions to six.
const READ_ONLY_CHAIN_FUNCTIONS_CHIRHO: &[&str] = &[
    "fn enumerate_gd7_sealed_plan_obligations_chirho",
    "fn verify_linked_plan_chirho",
    "fn reverify_record_inputs_read_only_chirho",
    "fn load_matching_terminal_marker_required_chirho",
    "fn load_terminal_marker_optional_chirho",
    "fn verify_terminal_marker_bytes_chirho",
    "fn expected_unsigned_terminal_marker_chirho",
    // THE SHARED REDUCER, added after a reviewer proved its exclusion was a real bypass: a resolved,
    // COMPILING internal signer acquisition planted outside its access-mode match left all three
    // guards green and production `--no-run` compiled. It is scanned with NO ALLOW-LIST — measured,
    // its legitimate body trips neither door, because the persisting path DESTRUCTURES a signer from
    // the enum variant (naming no type, constructing nothing) and delegates the signing to a callee.
    // An allow-list added to accommodate honest code is the seam a future violation hides in.
    "fn reduce_record_inputs_with_marker_access_chirho",
];

/// DOOR ONE — the supplied capability. A signer-typed parameter re-widens what the caller must hold.
const SIGNER_PARAMETER_NEEDLE_CHIRHO: &str = "Gd7ReconciliationSignerPortChirho";

/// DOOR TWO, LITERAL HALF — spellings that no type-name census can express.
///
/// These are a CONSTRUCTOR METHOD and a CALL, not type names, so the derived census below cannot
/// reach them and they are not redundant with it. `ExistingNodeGd7SignerChirho` IS now derived, and
/// is kept here deliberately: if the derivation ever breaks, this line still fires on the one
/// implementor we know ships.
///
/// **NOTHING IS EVER ADDED TO THIS LIST TO CLOSE A FINDING.** That move — a fourth spelling — is
/// what B4 rejected: an enumerated list is a SAMPLED POPULATION, and sampling one level further out
/// reproduces the same hole with more ceremony. New coverage goes in the DERIVED half.
const INTERNAL_SIGNER_ACQUISITION_NEEDLES_CHIRHO: &[&str] = &[
    "ExistingNodeGd7SignerChirho",
    "open_existing_with_key_id_chirho",
    ".sign_chirho(",
];

/// DOOR TWO, DERIVED HALF — the trait, which is ONE stable literal, asked on every run.
///
/// # WHY THIS EXISTS (B4)
///
/// The literal list above was defeated by a plant that used none of its spellings: a naturally
/// written second production signer, with a distinct type name, constructed inside the shared
/// reducer. It COMPILED and all three guards stayed 3/3. A list of names is a census someone must
/// remember to re-run; `impl Gd7ReconciliationSignerPortChirho for` is a QUESTION THE GUARD ASKS
/// ITSELF. That is the whole difference, and it is the difference between safe-by-census and
/// safe-by-construction.
///
/// A future author who adds a signer implementation does not need to know this guard exists. The
/// derivation finds it on the next run, wherever in the production surface it was written.
const SIGNER_TRAIT_NAME_CHIRHO: &str = "Gd7ReconciliationSignerPortChirho";

/// The POSITIVE CONTROL on the derivation — non-vacuity, promoted from open question to requirement.
///
/// An empty derived set makes door two's derived half VACUOUSLY GREEN, which is green-by-emptiness
/// at the level of the guard's own input. This repo has been bitten by that at the build level, the
/// gate level, and the guard level, so the derivation asserts it can still find a member we know
/// ships rather than assuming it works.
///
/// If this fires, the production signer was RENAMED, not removed — re-resolve the name. It is a
/// control on the INSTRUMENT, not the population being checked: the checking set stays derived.
const KNOWN_PRODUCTION_SIGNER_IMPLEMENTOR_CHIRHO: &str = "ExistingNodeGd7SignerChirho";

/// An `impl` header may be wrapped by rustfmt; join at most this many lines looking for its `{`.
const MAX_IMPL_HEADER_LINES_CHIRHO: usize = 12;

/// What an `impl … Gd7ReconciliationSignerPortChirho for …` header names.
#[derive(Debug)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
enum SignerImplTargetChirho {
    /// A concrete type. This is the name a read-only body must not construct.
    NamedChirho(String),
    /// `impl<T: Bound> Trait for T` — ANY type meeting the bound is a signer, so no name can
    /// express the set and the derived model does not apply.
    BlanketChirho,
    /// The header could not be parsed. REFUSE; never skip.
    UnparsedChirho,
}

fn is_identifier_byte_chirho(byte_chirho: u8) -> bool {
    byte_chirho.is_ascii_alphanumeric() || byte_chirho == b'_'
}

/// `contains`, but only at IDENTIFIER BOUNDARIES.
///
/// A plain `contains` on a derived type name would fire on any longer identifier that merely has it
/// as a prefix — `FooSignerChirho` matching inside `FooSignerChirhoBuilder`. That is a FALSE ALARM,
/// and this file's body extractor is over-inclusive at the tail, so false alarms are the direction
/// that actually costs something here.
fn contains_identifier_chirho(haystack_chirho: &str, identifier_chirho: &str) -> bool {
    if identifier_chirho.is_empty() {
        return false;
    }
    let bytes_chirho = haystack_chirho.as_bytes();
    let mut from_chirho = 0_usize;
    while let Some(relative_chirho) = haystack_chirho[from_chirho..].find(identifier_chirho) {
        let start_chirho = from_chirho + relative_chirho;
        let end_chirho = start_chirho + identifier_chirho.len();
        let before_ok_chirho =
            start_chirho == 0 || !is_identifier_byte_chirho(bytes_chirho[start_chirho - 1]);
        let after_ok_chirho = end_chirho == bytes_chirho.len()
            || !is_identifier_byte_chirho(bytes_chirho[end_chirho]);
        if before_ok_chirho && after_ok_chirho {
            return true;
        }
        from_chirho = start_chirho + 1;
    }
    false
}

fn collapse_whitespace_chirho(text_chirho: &str) -> String {
    let mut out_chirho = String::with_capacity(text_chirho.len());
    let mut in_space_chirho = true;
    for character_chirho in text_chirho.chars() {
        if character_chirho.is_whitespace() {
            if !in_space_chirho {
                out_chirho.push(' ');
                in_space_chirho = true;
            }
        } else {
            out_chirho.push(character_chirho);
            in_space_chirho = false;
        }
    }
    out_chirho.trim_end().to_owned()
}

/// Does this line DECLARE an `impl` item — as opposed to merely containing the text of one?
///
/// Same discipline as [`line_declares_fn_chirho`], and for the same reason: exclusion happens HERE,
/// before matching, never as a post-filter. A doc line begins `///`, a comment `//`, and a trailing
/// comment on a code line does not begin the line at all — all three fail this test without needing
/// a carve-out per symptom.
fn line_declares_impl_chirho(line_chirho: &str) -> bool {
    let mut rest_chirho = line_chirho.trim_start();
    for qualifier_chirho in ["default ", "unsafe "] {
        if let Some(stripped_chirho) = rest_chirho.strip_prefix(qualifier_chirho) {
            rest_chirho = stripped_chirho.trim_start();
        }
    }
    rest_chirho.starts_with("impl ") || rest_chirho.starts_with("impl<")
}

/// Whitespace-collapsed `impl` headers, joined across rustfmt's line wrapping.
///
/// Joining matters: `impl Gd7ReconciliationSignerPortChirho\n    for SomeLongTypeChirho {` is one
/// header split over two lines, and a per-line scan would see the trait with no `for` and silently
/// derive nothing from it.
fn impl_headers_chirho(source_chirho: &str) -> Vec<String> {
    let lines_chirho: Vec<&str> = source_chirho.lines().collect();
    let mut headers_chirho = Vec::new();
    for (index_chirho, line_chirho) in lines_chirho.iter().enumerate() {
        if !line_declares_impl_chirho(line_chirho) {
            continue;
        }
        let mut joined_chirho = String::new();
        for offset_chirho in 0..MAX_IMPL_HEADER_LINES_CHIRHO {
            let Some(next_chirho) = lines_chirho.get(index_chirho + offset_chirho) else {
                break;
            };
            joined_chirho.push(' ');
            joined_chirho.push_str(next_chirho);
            if next_chirho.contains('{') || next_chirho.trim_end().ends_with(';') {
                break;
            }
        }
        headers_chirho.push(collapse_whitespace_chirho(&joined_chirho));
    }
    headers_chirho
}

/// The generic parameter names an `impl<…>` header declares, so `for T` can be told from `for Foo`.
fn impl_generic_parameters_chirho(header_chirho: &str) -> Vec<String> {
    let mut parameters_chirho = Vec::new();
    let Some(open_chirho) = header_chirho.find('<') else {
        return parameters_chirho;
    };
    // Only the `impl<…>` group, which must open before the trait name.
    if header_chirho.find(SIGNER_TRAIT_NAME_CHIRHO).unwrap_or(0) < open_chirho {
        return parameters_chirho;
    }
    let mut depth_chirho = 0_i32;
    let mut close_chirho = None;
    for (index_chirho, character_chirho) in header_chirho[open_chirho..].char_indices() {
        match character_chirho {
            '<' => depth_chirho += 1,
            '>' => {
                depth_chirho -= 1;
                if depth_chirho == 0 {
                    close_chirho = Some(open_chirho + index_chirho);
                    break;
                }
            }
            _ => {}
        }
    }
    let Some(close_chirho) = close_chirho else {
        return parameters_chirho;
    };
    for part_chirho in header_chirho[open_chirho + 1..close_chirho].split(',') {
        let name_chirho = part_chirho
            .split(':')
            .next()
            .unwrap_or("")
            .trim()
            .trim_start_matches("const ")
            .trim();
        if !name_chirho.is_empty() && !name_chirho.starts_with('\'') {
            parameters_chirho.push(name_chirho.to_owned());
        }
    }
    parameters_chirho
}

/// The concrete type an `impl … <signer trait> for …` header names, or why it could not be read.
///
/// Returns `None` for headers that do not mention the trait at all.
fn signer_impl_target_chirho(header_chirho: &str) -> Option<SignerImplTargetChirho> {
    let trait_at_chirho = header_chirho.find(SIGNER_TRAIT_NAME_CHIRHO)?;
    let after_trait_chirho = &header_chirho[trait_at_chirho + SIGNER_TRAIT_NAME_CHIRHO.len()..];
    let Some(for_at_chirho) = after_trait_chirho.find(" for ") else {
        return Some(SignerImplTargetChirho::UnparsedChirho);
    };
    let mut target_chirho = &after_trait_chirho[for_at_chirho + " for ".len()..];
    for terminator_chirho in ["{", " where "] {
        if let Some(cut_chirho) = target_chirho.find(terminator_chirho) {
            target_chirho = &target_chirho[..cut_chirho];
        }
    }
    // Reduce the type EXPRESSION to its base identifier: `&'a path::Wrapper<Key>` -> `Wrapper`.
    let base_chirho = target_chirho
        .trim()
        .trim_start_matches('&')
        .trim()
        .trim_start_matches("dyn ")
        .trim();
    let base_chirho = base_chirho.split('<').next().unwrap_or("").trim();
    let base_chirho = base_chirho.rsplit("::").next().unwrap_or("").trim();
    if base_chirho.is_empty()
        || !base_chirho
            .chars()
            .all(|c_chirho| c_chirho.is_alphanumeric() || c_chirho == '_')
    {
        return Some(SignerImplTargetChirho::UnparsedChirho);
    }
    if impl_generic_parameters_chirho(header_chirho)
        .iter()
        .any(|parameter_chirho| parameter_chirho == base_chirho)
    {
        return Some(SignerImplTargetChirho::BlanketChirho);
    }
    Some(SignerImplTargetChirho::NamedChirho(base_chirho.to_owned()))
}

/// The base identifier of a type expression: `&'a path::Wrapper<Key>` -> `Wrapper`.
fn base_type_identifier_chirho(expression_chirho: &str) -> String {
    let base_chirho = expression_chirho
        .trim()
        .trim_start_matches('&')
        .trim()
        .trim_start_matches("dyn ")
        .trim();
    let base_chirho = base_chirho.split('<').next().unwrap_or("").trim();
    let base_chirho = base_chirho.split(';').next().unwrap_or("").trim();
    base_chirho
        .rsplit("::")
        .next()
        .unwrap_or("")
        .trim()
        .to_owned()
}

/// The whole item text of every declaration whose first line starts with one of `prefixes`.
fn joined_items_starting_with_chirho(source_chirho: &str, prefixes_chirho: &[&str]) -> Vec<String> {
    let lines_chirho: Vec<&str> = source_chirho.lines().collect();
    let mut items_chirho = Vec::new();
    for (index_chirho, line_chirho) in lines_chirho.iter().enumerate() {
        let trimmed_chirho = line_chirho.trim_start();
        if !prefixes_chirho
            .iter()
            .any(|prefix_chirho| trimmed_chirho.starts_with(prefix_chirho))
        {
            continue;
        }
        let mut joined_chirho = String::new();
        for offset_chirho in 0..MAX_IMPL_HEADER_LINES_CHIRHO {
            let Some(next_chirho) = lines_chirho.get(index_chirho + offset_chirho) else {
                break;
            };
            joined_chirho.push(' ');
            joined_chirho.push_str(next_chirho);
            if next_chirho.contains(';') {
                break;
            }
        }
        items_chirho.push(collapse_whitespace_chirho(&joined_chirho));
    }
    items_chirho
}

/// Every OTHER NAME the production surface binds to a derived signer implementor.
///
/// # Q1, AND THE ARM THAT FOUND ITS SECOND HALF
///
/// A rebinding sits at file top, OUTSIDE every extracted function body, so a body scan is
/// structurally blind to it: the body names only the new name. The first version of this handled
/// `use X as Y;` and was defeated within the hour by `type Y = X;` — a builder-chosen arm, and it
/// MISSED, exit 0 with the plant in place.
///
/// # WHY THIS IS NOT "A FOURTH SPELLING", WHICH B4 FORBIDS
///
/// The rejected move is enumerating more SIGNER NAMES — an open population that grows every time an
/// author writes a new type, so a list of them is a sample that silently ages. What is enumerated
/// here is REBINDING SYNTAX, and Rust defines a closed set of those: `use … as …` and `type … = …`.
/// The signer population itself stays derived from the trait; these two forms only carry it across
/// a rename. Enumerating a language's own grammar is not sampling a world that changes underneath.
///
/// Resolved to a FIXPOINT so an alias of an alias is still reached, and WORKSPACE-WIDE rather than
/// per-file so a `pub type` re-exported into another module cannot launder the name across a file
/// boundary. Over-inclusive by design: the safe direction here is more names, not fewer.
fn rebound_signer_names_chirho(
    sources_chirho: &[(String, String)],
    implementors_chirho: &std::collections::BTreeSet<String>,
) -> std::collections::BTreeSet<String> {
    let mut known_chirho = implementors_chirho.clone();
    let mut rebound_chirho = std::collections::BTreeSet::new();

    // Fixpoint: each pass may bind a name that a later pass can then rebind again.
    for _pass_chirho in 0..MAX_IMPL_HEADER_LINES_CHIRHO {
        let before_chirho = known_chirho.len();
        for (_relative_chirho, source_chirho) in sources_chirho {
            // `use path::X as Y;` — including inside a braced group.
            for item_chirho in joined_items_starting_with_chirho(
                source_chirho,
                &["use ", "pub use ", "pub(crate) use ", "pub(super) use "],
            ) {
                let parts_chirho: Vec<&str> = item_chirho.split(" as ").collect();
                for position_chirho in 1..parts_chirho.len() {
                    let original_chirho = base_type_identifier_chirho(
                        &parts_chirho[position_chirho - 1]
                            .chars()
                            .rev()
                            .take_while(|c_chirho| {
                                c_chirho.is_alphanumeric() || *c_chirho == '_' || *c_chirho == ':'
                            })
                            .collect::<Vec<_>>()
                            .into_iter()
                            .rev()
                            .collect::<String>(),
                    );
                    let alias_chirho: String = parts_chirho[position_chirho]
                        .trim_start()
                        .chars()
                        .take_while(|c_chirho| c_chirho.is_alphanumeric() || *c_chirho == '_')
                        .collect();
                    if known_chirho.contains(&original_chirho) && !alias_chirho.is_empty() {
                        known_chirho.insert(alias_chirho.clone());
                        rebound_chirho.insert(alias_chirho);
                    }
                }
            }

            // `type Y = path::X;` — the form that defeated the first version of this function.
            for item_chirho in joined_items_starting_with_chirho(
                source_chirho,
                &["type ", "pub type ", "pub(crate) type ", "pub(super) type "],
            ) {
                let Some(equals_chirho) = item_chirho.find('=') else {
                    continue;
                };
                let alias_chirho: String = item_chirho[..equals_chirho]
                    .rsplit(' ')
                    .find(|token_chirho| !token_chirho.is_empty())
                    .unwrap_or("")
                    .split('<')
                    .next()
                    .unwrap_or("")
                    .chars()
                    .filter(|c_chirho| c_chirho.is_alphanumeric() || *c_chirho == '_')
                    .collect();
                let original_chirho =
                    base_type_identifier_chirho(&item_chirho[equals_chirho + 1..]);
                if known_chirho.contains(&original_chirho) && !alias_chirho.is_empty() {
                    known_chirho.insert(alias_chirho.clone());
                    rebound_chirho.insert(alias_chirho);
                }
            }
        }
        if known_chirho.len() == before_chirho {
            break;
        }
    }
    rebound_chirho
}

/// The one function on these modules' surface that legitimately signs — the NEGATIVE CONTROL.
///
/// If this ever stops containing a sign site, "narrowing" has become "weakening the write mode",
/// which every verifier-only assertion above would happily accept.
const SIGNING_CONTROL_FUNCTION_CHIRHO: &str = "fn persist_or_load_terminal_marker_chirho";

/// Text between an item's opening `{` and its MATCHING close, by brace counting.
///
/// Written after the naive version — "everything up to the first `}`" — truncated the marker-access
/// enum at its own VARIANT's closing brace, so `LoadRequiredChirho` fell outside the extracted body
/// and the guard reported the write mode had lost its signer. A false alarm rather than a false
/// pass, which is the right direction, but the lesson is that a delimiter search is not a parser.
fn braced_body_after_chirho(source_chirho: &str, anchor_chirho: &str) -> Option<String> {
    let anchor_start_chirho = source_chirho.find(anchor_chirho)?;
    let open_offset_chirho = source_chirho[anchor_start_chirho..].find('{')?;
    let body_start_chirho = anchor_start_chirho + open_offset_chirho;
    let mut depth_chirho = 0_usize;
    for (index_chirho, character_chirho) in source_chirho[body_start_chirho..].char_indices() {
        match character_chirho {
            '{' => depth_chirho += 1,
            '}' => {
                depth_chirho -= 1;
                if depth_chirho == 0 {
                    return Some(
                        source_chirho[body_start_chirho..body_start_chirho + index_chirho]
                            .to_owned(),
                    );
                }
            }
            _ => {}
        }
    }
    None
}

/// Does this line DECLARE a `fn` item — as opposed to merely containing the text of one?
///
/// Strips an optional visibility token, then the `async` / `const` / `unsafe` / `extern "..."`
/// qualifiers, and requires what remains to BEGIN with `fn `. A comment begins `//`, a string literal
/// begins `"`, a doc line begins `///`; all three fail this test WITHOUT NEEDING A CARVE-OUT, which
/// is the point — one rule applied at the right stage rather than a filter per symptom.
///
/// EXCLUSION HAPPENS HERE, BEFORE MATCHING, never as a post-filter on results. Filtering matches by a
/// property that lives on a different line is the category error that cost this fleet a real accessor
/// tonight.
fn line_declares_fn_chirho(line_chirho: &str) -> bool {
    let mut rest_chirho = line_chirho.trim_start();
    for visibility_chirho in ["pub(crate) ", "pub(super) ", "pub(self) ", "pub "] {
        if let Some(stripped_chirho) = rest_chirho.strip_prefix(visibility_chirho) {
            rest_chirho = stripped_chirho.trim_start();
            break;
        }
    }
    if rest_chirho.starts_with("pub(in ") {
        match rest_chirho.find(')') {
            Some(close_chirho) => rest_chirho = rest_chirho[close_chirho + 1..].trim_start(),
            None => return false,
        }
    }
    for qualifier_chirho in ["default ", "const ", "async ", "unsafe ", "extern "] {
        if let Some(stripped_chirho) = rest_chirho.strip_prefix(qualifier_chirho) {
            rest_chirho = stripped_chirho.trim_start();
        }
    }
    if rest_chirho.starts_with('"') {
        // `extern "C" fn` — step over the ABI string.
        match rest_chirho[1..].find('"') {
            Some(close_chirho) => rest_chirho = rest_chirho[close_chirho + 2..].trim_start(),
            None => return false,
        }
    }
    rest_chirho.starts_with("fn ")
}

/// Byte offsets of every line that DECLARES a fn whose name matches `needle` (`"fn NAME"`).
///
/// Returns ALL sites rather than the first, so the caller can REFUSE on ambiguity instead of
/// silently choosing. A reviewer redirected the previous first-textual-occurrence version into a
/// comment with one line of ordinary prose (`// fn NAME` above the declaration), leaving every guard
/// green and the count non-vacuous.
fn declaration_sites_chirho(source_chirho: &str, needle_chirho: &str) -> Vec<usize> {
    let mut sites_chirho = Vec::new();
    let mut offset_chirho = 0_usize;
    for line_chirho in source_chirho.split_inclusive('\n') {
        if line_chirho.contains(needle_chirho) && line_declares_fn_chirho(line_chirho) {
            sites_chirho.push(offset_chirho);
        }
        offset_chirho += line_chirho.len();
    }
    sites_chirho
}

/// Body text from a RESOLVED declaration offset to the next line that declares any fn.
///
/// Still over-inclusive at the tail by design — it may run past the closing brace — and that remains
/// the correct error direction for MISSES. It is NOT the safe direction for FALSE ALARMS, so the
/// region boundary is worth checking whenever a name is added to the scanned set.
fn function_body_from_site_chirho(source_chirho: &str, declaration_offset_chirho: usize) -> String {
    let rest_chirho = &source_chirho[declaration_offset_chirho..];
    let mut offset_chirho = 0_usize;
    for (index_chirho, line_chirho) in rest_chirho.split_inclusive('\n').enumerate() {
        if index_chirho > 0 && line_declares_fn_chirho(line_chirho) {
            return rest_chirho[..offset_chirho].to_owned();
        }
        offset_chirho += line_chirho.len();
    }
    rest_chirho.to_owned()
}

/// Production functions that HAND OUT a signer — derived from the same one trait literal.
///
/// # THE ARM THAT FORCED THIS, and why it is a PRODUCER check rather than a mention check
///
/// A factory `fn make(…) -> Box<dyn Gd7ReconciliationSignerPortChirho>` declared anywhere, called
/// from a read-only body that annotates nothing, names NEITHER the trait NOR any implementor at the
/// call site. Measured: it COMPILES and the derived-name half misses it. So it is a live hole, not
/// a theoretical one — an ordinary factory is exactly what a refactor produces.
///
/// **Only the RETURN TYPE is examined, and that distinction is load-bearing.** A function that TAKES
/// a signer also mentions the trait in its signature, and `persist_or_load_terminal_marker_chirho`
/// is precisely that — the legitimately-signing callee the shared reducer DELEGATES to in its
/// persisting mode. Keying on "the signature mentions the trait" would fire on that honest
/// delegation, and the only way to keep the suite green would be an allow-list — the seam this file
/// says a future violation hides in. Consumers are door one's business; door two is about ACQUIRING.
///
/// # B7 — WHY THE RETURN TYPE IS TESTED AGAINST NAMES, NOT ONLY AGAINST THE TRAIT
///
/// The first version demanded the TRAIT in return position. A reviewer planted the most ordinary
/// refactor there is — extracting duplicated construction into a free helper:
///
/// ```ignore
/// pub(crate) fn open_reconciliation_signer_chirho(root, key)
///     -> anyhow::Result<ExistingNodeGd7SignerChirho>
/// ```
///
/// It COMPILED and every half walked past it: no trait name for door one, the body spells the
/// FACTORY rather than the implementor, no rebinding, and the return type names the CONCRETE type
/// while the gate demanded the trait. It acquired the REAL production signer inside the function the
/// whole prerequisite exists to keep verifier-only.
///
/// **ORDERING IS THIS FUNCTION'S FAILURE MODE.** `signer_denoting_names_chirho` must arrive AFTER
/// the implementor ∪ rebinding fixpoint has converged. Derive producers too early and
/// `type S = ExistingNodeGd7SignerChirho; fn make_chirho() -> S` is missed — the very shape this
/// widening exists to close, reintroduced by evaluation order. That is why the set is a PARAMETER
/// rather than computed here: a caller cannot pass a set that has not been built yet.
fn derived_signer_producing_functions_chirho(
    sources_chirho: &[(String, String)],
    signer_denoting_names_chirho: &std::collections::BTreeSet<String>,
) -> std::collections::BTreeSet<String> {
    let mut producers_chirho = std::collections::BTreeSet::new();
    for (_relative_chirho, source_chirho) in sources_chirho {
        let lines_chirho: Vec<&str> = source_chirho.lines().collect();
        for (index_chirho, line_chirho) in lines_chirho.iter().enumerate() {
            if !line_declares_fn_chirho(line_chirho) {
                continue;
            }
            let mut joined_chirho = String::new();
            for offset_chirho in 0..MAX_IMPL_HEADER_LINES_CHIRHO {
                let Some(next_chirho) = lines_chirho.get(index_chirho + offset_chirho) else {
                    break;
                };
                joined_chirho.push(' ');
                joined_chirho.push_str(next_chirho);
                if next_chirho.contains('{') || next_chirho.trim_end().ends_with(';') {
                    break;
                }
            }
            let signature_chirho = collapse_whitespace_chirho(&joined_chirho);

            // Step PAST the parameter list, so a signer-TAKING parameter is not read as a return.
            let Some(open_chirho) = signature_chirho.find('(') else {
                continue;
            };
            let mut depth_chirho = 0_i32;
            let mut close_chirho = None;
            for (offset_chirho, character_chirho) in signature_chirho[open_chirho..].char_indices()
            {
                match character_chirho {
                    '(' => depth_chirho += 1,
                    ')' => {
                        depth_chirho -= 1;
                        if depth_chirho == 0 {
                            close_chirho = Some(open_chirho + offset_chirho);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let Some(close_chirho) = close_chirho else {
                continue;
            };
            let tail_chirho = &signature_chirho[close_chirho..];
            let Some(arrow_chirho) = tail_chirho.find("->") else {
                continue;
            };
            let mut return_type_chirho = &tail_chirho[arrow_chirho + 2..];
            for terminator_chirho in ["{", " where "] {
                if let Some(cut_chirho) = return_type_chirho.find(terminator_chirho) {
                    return_type_chirho = &return_type_chirho[..cut_chirho];
                }
            }
            // A signer arrives whether the return type spells the TRAIT, a concrete IMPLEMENTOR, or
            // any REBINDING of one. Identifier-boundary matched for the names, plain `contains` for
            // the trait, which cannot collide.
            let hands_out_a_signer_chirho = return_type_chirho.contains(SIGNER_TRAIT_NAME_CHIRHO)
                || signer_denoting_names_chirho
                    .iter()
                    .any(|name_chirho| contains_identifier_chirho(return_type_chirho, name_chirho));
            if !hands_out_a_signer_chirho {
                continue;
            }
            let Some(name_at_chirho) = signature_chirho.find("fn ") else {
                continue;
            };
            let name_chirho: String = signature_chirho[name_at_chirho + 3..]
                .chars()
                .take_while(|c_chirho| c_chirho.is_alphanumeric() || *c_chirho == '_')
                .collect();
            if !name_chirho.is_empty() {
                producers_chirho.insert(name_chirho);
            }
        }
    }
    producers_chirho
}

#[test]
fn gd7_read_only_sealed_plan_chain_stays_verifier_only_chirho() {
    // Per needle: every RESOLVED declaration site, across the whole production surface. Collected
    // before anything is judged, so ambiguity can REFUSE rather than be silently resolved by taking
    // the first.
    let mut sites_by_needle_chirho: Vec<(&str, Vec<String>)> = READ_ONLY_CHAIN_FUNCTIONS_CHIRHO
        .iter()
        .map(|needle_chirho| (*needle_chirho, Vec::new()))
        .collect();
    let mut violations_chirho: Vec<String> = Vec::new();

    // Read the production surface ONCE; the derivation and the body scan must see the SAME
    // population, or the guard checks bodies against an implementor set drawn from somewhere else.
    let sources_chirho: Vec<(String, String)> = workspace_production_rs_files_chirho()
        .into_iter()
        .map(|path_chirho| {
            let relative_chirho = workspace_relative_chirho(&path_chirho);
            let raw_chirho = std::fs::read_to_string(&path_chirho)
                .unwrap_or_else(|_| panic!("read {relative_chirho}"));
            (
                relative_chirho,
                production_text_chirho(&raw_chirho).into_owned(),
            )
        })
        .collect();

    // DERIVE the implementor set by asking the trait, over that same population.
    let mut derived_implementors_chirho: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    let mut derivation_refusals_chirho: Vec<String> = Vec::new();
    for (relative_chirho, source_chirho) in &sources_chirho {
        for header_chirho in impl_headers_chirho(source_chirho) {
            match signer_impl_target_chirho(&header_chirho) {
                None => {}
                Some(SignerImplTargetChirho::NamedChirho(name_chirho)) => {
                    derived_implementors_chirho.insert(name_chirho);
                }
                // REFUSE, never skip — both of these mean the derived model cannot express what the
                // header says, and a guard that quietly drops what it cannot read reports success
                // while covering less.
                Some(SignerImplTargetChirho::BlanketChirho) => derivation_refusals_chirho.push(
                    format!(
                        "{relative_chirho}: BLANKET impl of {SIGNER_TRAIT_NAME_CHIRHO} — \
                         `{header_chirho}`. Any type meeting that bound is a signer, so NO set of \
                         type names can express the implementor population and this guard's derived \
                         half is structurally inadequate. Migration path: this is a design decision, \
                         not a guard fix — a blanket signer impl means the read-only chain can \
                         acquire signing authority from a type that names nothing, and the \
                         narrowing this file exists to protect no longer holds."
                    ),
                ),
                Some(SignerImplTargetChirho::UnparsedChirho) => derivation_refusals_chirho.push(
                    format!(
                        "{relative_chirho}: AN UNRESOLVABLE SIGNING CAPABILITY. This declares an \
                         implementation of {SIGNER_TRAIT_NAME_CHIRHO} — a type that can SIGN — but \
                         the concrete type cannot be read out of `{header_chirho}`, so door two \
                         cannot tell whether the read-only chain constructs it. The guard REFUSES \
                         rather than deriving nothing, because a header it cannot parse is exactly \
                         where an implementor would hide.\n\
                         MIGRATION PATH, and read this before touching the guard: if the impl is \
                         MACRO-GENERATED, the concrete type is not in the source at all and NO text \
                         instrument can derive it — the refusal is correct and a green here would be \
                         a lie. Give the signer a hand-written `impl` in production source, or keep \
                         the macro and hand-write the impl for the one type that needs signing \
                         authority. If the header is merely shaped in a way this parser does not \
                         handle, widen the PARSER. \
                         DO NOT add an allow-list: this guard's coverage IS its refusal set, so an \
                         exemption does not quiet a false alarm — it deletes the check."
                    ),
                ),
            }
        }
    }

    // Q1: a rebinding sits at file top, OUTSIDE every extracted body, so the body names only the new
    // name and a body scan is structurally blind to it. Resolved to a fixpoint over both rebinding
    // forms Rust has, workspace-wide.
    let rebound_chirho = rebound_signer_names_chirho(&sources_chirho, &derived_implementors_chirho);

    // A factory hands out a capability while naming neither the trait nor a concrete type at the
    // call site. Derived from the same literal, by RETURN TYPE only — see the function's own header
    // for why a consumer must not be treated as a producer.
    //
    // ORDER IS LOAD-BEARING AND THIS IS THE ONLY PLACE IT IS VISIBLE: the union below is built from
    // `rebound_chirho`, so this line MUST stay after the fixpoint above. Moving it earlier silently
    // reopens `type S = <implementor>; fn make_chirho() -> S` — a miss with no failing test to
    // announce it, because an under-derived producer set simply finds less.
    let mut signer_denoting_names_chirho = derived_implementors_chirho.clone();
    signer_denoting_names_chirho.extend(rebound_chirho.iter().cloned());
    let producers_chirho =
        derived_signer_producing_functions_chirho(&sources_chirho, &signer_denoting_names_chirho);

    for (relative_chirho, source_chirho) in &sources_chirho {
        for (signature_chirho, sites_chirho) in &mut sites_by_needle_chirho {
            for declaration_offset_chirho in
                declaration_sites_chirho(source_chirho, signature_chirho)
            {
                sites_chirho.push(relative_chirho.clone());
                let body_chirho =
                    function_body_from_site_chirho(source_chirho, declaration_offset_chirho);

                // DOOR ONE.
                if body_chirho.contains(SIGNER_PARAMETER_NEEDLE_CHIRHO) {
                    violations_chirho.push(format!(
                        "{relative_chirho}: `{signature_chirho}` names \
                         {SIGNER_PARAMETER_NEEDLE_CHIRHO} — the read-only chain re-widened to demand \
                         a signing capability from its caller. Migration path: take \
                         `&dyn Gd7ReconciliationVerifierPortChirho`; if a signature genuinely needs \
                         to sign, it does not belong on this chain."
                    ));
                }

                // DOOR TWO, LITERAL HALF — a constructor method and a call, which no type-name
                // census can express.
                for needle_chirho in INTERNAL_SIGNER_ACQUISITION_NEEDLES_CHIRHO {
                    if body_chirho.contains(needle_chirho) {
                        violations_chirho.push(format!(
                            "{relative_chirho}: `{signature_chirho}` contains `{needle_chirho}` — a \
                             signing capability acquired INSIDE the read-only chain, which no \
                             parameter type can exclude. Migration path: move the work to the \
                             persisting mode, which carries its signer in \
                             `TerminalMarkerAccessChirho::PersistOrLoadChirho`."
                        ));
                    }
                }

                // DOOR TWO, DERIVED HALF — every type the TRAIT says is a signer, plus any name
                // this file rebinds one to. Identifier-boundary matched, so a longer identifier
                // that merely has one as a prefix does not raise a false alarm.
                // A CALL to a derived producer: the capability arrives without the body naming the
                // trait or any concrete type.
                for producer_chirho in &producers_chirho {
                    if contains_identifier_chirho(&body_chirho, producer_chirho) {
                        violations_chirho.push(format!(
                            "{relative_chirho}: `{signature_chirho}` calls `{producer_chirho}` — a \
                             function whose RETURN TYPE is {SIGNER_TRAIT_NAME_CHIRHO}, so the \
                             read-only chain acquires a signing capability without naming the trait \
                             or any concrete type at the call site. Derived by asking the trait, not \
                             from a list. Migration path: move the work to the persisting mode, which \
                             carries its signer in `TerminalMarkerAccessChirho::PersistOrLoadChirho`."
                        ));
                    }
                }

                for implementor_chirho in derived_implementors_chirho
                    .iter()
                    .chain(rebound_chirho.iter())
                {
                    if contains_identifier_chirho(&body_chirho, implementor_chirho) {
                        let via_chirho = if rebound_chirho.contains(implementor_chirho) {
                            " (a rebinding of a derived implementor, via `use … as …` or \
                             `type … = …`)"
                        } else {
                            ""
                        };
                        violations_chirho.push(format!(
                            "{relative_chirho}: `{signature_chirho}` names \
                             `{implementor_chirho}`{via_chirho} — a type the trait \
                             {SIGNER_TRAIT_NAME_CHIRHO} says can SIGN, constructed or referenced \
                             inside the read-only chain. This is door two's derived half: the name \
                             was not on any list, it was found by asking the trait. Migration path: \
                             move the work to the persisting mode, which carries its signer in \
                             `TerminalMarkerAccessChirho::PersistOrLoadChirho`. If this fires on a \
                             mention that cannot sign, narrow the SITE — do not add an allow-list, \
                             which is the seam a future violation hides in."
                        ));
                    }
                }
            }
        }
    }

    // THE DERIVATION MUST NOT HAVE FAILED SILENTLY.
    assert!(
        derivation_refusals_chirho.is_empty(),
        "door two's derived half could not read the implementor population:\n{}",
        derivation_refusals_chirho.join("\n")
    );

    // NON-VACUITY — claude2_chirho promoted this from open question to requirement, and it is the
    // reason this remedy is not itself green-by-emptiness. A derivation that finds NOTHING checks
    // every read-only body against an empty set and passes perfectly.
    assert!(
        derived_implementors_chirho.contains(KNOWN_PRODUCTION_SIGNER_IMPLEMENTOR_CHIRHO),
        "the derived signer-implementor set does not contain \
         {KNOWN_PRODUCTION_SIGNER_IMPLEMENTOR_CHIRHO}, so the derivation is not measuring the \
         production surface and door two's derived half is VACUOUS. Derived set: {:?}\n\
         If that implementor was renamed rather than removed, re-resolve this control's name. If it \
         genuinely no longer exists, the control must be re-pointed at whatever production type now \
         implements {SIGNER_TRAIT_NAME_CHIRHO} — never deleted, because an empty derived set is \
         indistinguishable from a clean one.",
        derived_implementors_chirho
    );

    // PER-NEEDLE UNIQUENESS — this REPLACES the old total-count assertion, which a reviewer defeated.
    //
    // The count version asserted "7 anchors found" and stayed non-vacuously green while one anchor
    // had been redirected into a comment: a WRONG anchor still counts. A total cannot distinguish
    // "matched the right things" from "matched the right NUMBER of things". So the assertion is now
    // a SET property per needle — exactly one resolved declaration each.
    //
    //   0  -> renamed, moved, or fell out of the production surface. A shrinking target list keeps
    //         reporting success while covering less, so this is a FAILURE and never a skip.
    //   >1 -> AMBIGUOUS. This is the redirect's signature, and the guard REFUSES rather than choosing
    //         one — a guard that picks among candidates has silently decided what it was asked to
    //         verify.
    for (signature_chirho, sites_chirho) in &sites_by_needle_chirho {
        assert_eq!(
            sites_chirho.len(),
            1,
            "`{signature_chirho}` resolved to {} declaration sites, expected exactly 1. Sites: {:?}\n\
             0 means it was renamed/moved/left the production surface — re-resolve the name against \
             the chain and update the list. More than 1 means the anchor is AMBIGUOUS and this guard \
             cannot know which body it is scanning; resolve the duplicate rather than letting the \
             scan choose.",
            sites_chirho.len(),
            sites_chirho
        );
    }

    assert!(
        violations_chirho.is_empty(),
        "the read-only sealed-plan chain regained signing capability:\n{}",
        violations_chirho.join("\n")
    );
}

#[test]
fn gd7_marker_access_mode_carries_the_signing_capability_as_data_chirho() {
    let mut inspected_chirho = 0_usize;
    let mut load_required_carries_payload_chirho = false;
    let mut persist_carries_signer_chirho = false;

    for path_chirho in workspace_production_rs_files_chirho() {
        let relative_chirho = workspace_relative_chirho(&path_chirho);
        let raw_chirho = std::fs::read_to_string(&path_chirho)
            .unwrap_or_else(|_| panic!("read {relative_chirho}"));
        let source_chirho = production_text_chirho(&raw_chirho);
        if !source_chirho.contains("enum TerminalMarkerAccessChirho") {
            continue;
        }
        inspected_chirho += 1;
        // Brace-COUNTED, not delimiter-searched. The variant's own `}` is not the enum's.
        let body_chirho =
            braced_body_after_chirho(&source_chirho, "enum TerminalMarkerAccessChirho")
                .expect("the marker-access enum declaration has a balanced body");

        // The read-only variant must be payload-free: no capability in scope means none to call.
        let load_required_chirho = body_chirho
            .find("LoadRequiredChirho")
            .expect("the marker-access enum declares its read-only variant");
        load_required_carries_payload_chirho = body_chirho[load_required_chirho..]
            .trim_start()
            .starts_with("LoadRequiredChirho {");
        persist_carries_signer_chirho = body_chirho.contains("PersistOrLoadChirho {")
            && body_chirho.contains(SIGNER_PARAMETER_NEEDLE_CHIRHO);
    }

    assert_eq!(
        inspected_chirho, 1,
        "expected exactly ONE production declaration of TerminalMarkerAccessChirho and found \
         {inspected_chirho}. Zero means it was renamed or left the production surface and this \
         guard is measuring nothing; more than one means the access mode forked and both need \
         review."
    );
    assert!(
        !load_required_carries_payload_chirho,
        "TerminalMarkerAccessChirho::LoadRequiredChirho gained a payload. The read-only arm having \
         NOTHING in scope is what makes its inability to sign structural rather than conventional; \
         if it now carries a capability, that property is gone."
    );
    assert!(
        persist_carries_signer_chirho,
        "TerminalMarkerAccessChirho::PersistOrLoadChirho no longer carries a signer. Either the \
         capability moved back to an ambient parameter — reintroducing the defect this guard \
         exists for — or the write mode stopped signing, which every verifier-only assertion in \
         this file would accept without complaint."
    );
}

#[test]
fn gd7_persisting_marker_mode_still_signs_chirho() {
    // THE NEGATIVE CONTROL, and it is not decoration. A prerequisite that "narrowed" by removing
    // signing from the persisting mode would satisfy every assertion above perfectly. This is the
    // only thing in this file standing between that and a green suite.
    let mut inspected_chirho = 0_usize;
    let mut signs_chirho = false;

    for path_chirho in workspace_production_rs_files_chirho() {
        let relative_chirho = workspace_relative_chirho(&path_chirho);
        let raw_chirho = std::fs::read_to_string(&path_chirho)
            .unwrap_or_else(|_| panic!("read {relative_chirho}"));
        let source_chirho = production_text_chirho(&raw_chirho);
        // RESOLVED declarations, same discipline as the scan above — a control anchored on first
        // textual occurrence would be redirectable by the very comment trick that holed this guard,
        // and a redirected CONTROL is worse than a redirected check: it silently stops anchoring
        // every assertion that depends on it.
        for declaration_offset_chirho in
            declaration_sites_chirho(&source_chirho, SIGNING_CONTROL_FUNCTION_CHIRHO)
        {
            inspected_chirho += 1;
            let body_chirho =
                function_body_from_site_chirho(&source_chirho, declaration_offset_chirho);
            signs_chirho = body_chirho.contains(".sign_chirho(")
                && body_chirho.contains(SIGNER_PARAMETER_NEEDLE_CHIRHO);
        }
    }

    assert_eq!(
        inspected_chirho, 1,
        "expected exactly ONE production `persist_or_load_terminal_marker_chirho` and found \
         {inspected_chirho}; a zero here means this control is measuring nothing and every \
         verifier-only assertion in this file is unanchored."
    );
    assert!(
        signs_chirho,
        "persist_or_load_terminal_marker_chirho no longer both TAKES a signer and CALLS \
         `.sign_chirho(`. Narrowing the read-only chain must not become weakening the write mode — \
         these are opposite changes that a verifier-only test suite cannot tell apart."
    );
}
