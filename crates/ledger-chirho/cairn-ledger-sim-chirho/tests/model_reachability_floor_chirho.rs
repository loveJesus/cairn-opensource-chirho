// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Every model in this crate must prove its state space goes somewhere, not just that no law broke.
//!
//! A bounded stateright model that stops exploring stays green on all of its `always` properties.
//! That is the cheapest possible green proof layer and the most expensive kind of wrong: the checker
//! reports success while the state space is a single node. `sometimes` is the guard, because
//! stateright FAILS a `sometimes` property that is never satisfied — so at least one deep state must
//! actually be reached.
//!
//! This pins the PROPERTY (each model carries a state-reading witness), never a count. There is no
//! number here to drift or to be gamed toward; the check fires exactly when a new model arrives
//! without a floor, and is silent otherwise.
//!
//! A witness whose closure ignores its state parameter would be satisfied in the initial state and
//! floors nothing, so the closure must actually read state. That is the difference between counting
//! `sometimes` occurrences and checking that they mean something.

use std::path::Path;

/// The parameter list of the first closure after a `sometimes(`, plus the body that follows it.
fn first_closure_chirho(segment_chirho: &str) -> Option<(&str, &str)> {
    let open_chirho = segment_chirho.find('|')?;
    let rest_chirho = &segment_chirho[open_chirho + 1..];
    let close_chirho = rest_chirho.find('|')?;
    Some((
        &rest_chirho[..close_chirho],
        &rest_chirho[close_chirho + 1..],
    ))
}

/// True when this `sometimes` witness actually reads state, rather than being satisfiable at once.
fn witness_reads_state_chirho(segment_chirho: &str) -> bool {
    let Some((params_chirho, body_chirho)) = first_closure_chirho(segment_chirho) else {
        return false;
    };
    let Some(last_chirho) = params_chirho.split(',').next_back() else {
        return false;
    };
    let name_chirho = last_chirho
        .trim()
        .split(':')
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    // A `_` binding cannot be referenced, so such a witness can never depend on the state.
    !name_chirho.is_empty() && name_chirho != "_" && body_chirho.contains(&name_chirho)
}

#[test]
fn a_witness_that_ignores_its_state_is_not_a_floor_chirho() {
    // The discriminator is tested on synthetic inputs because that is where both cases are
    // constructible: no real model in the tree has the bad shape, so a scan over real files alone
    // would pass for a reason unrelated to the logic under test.
    assert!(
        witness_reads_state_chirho(r#"sometimes("x", |_, state_chirho| state_chirho.done_chirho)"#),
        "a closure reading state IS a floor"
    );
    assert!(
        !witness_reads_state_chirho(r#"sometimes("x", |_, _| true)"#),
        "a closure ignoring state is satisfied in the initial state and floors nothing"
    );
    assert!(
        !witness_reads_state_chirho(r#"sometimes("x", |_model_chirho, _| 1 == 1)"#),
        "an underscore binding cannot be referenced, so it cannot depend on the state"
    );
}

#[test]
fn every_model_carries_a_state_reading_reachability_floor_chirho() {
    let dir_chirho = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/models_chirho");
    let mut checked_chirho = 0_usize;
    let mut floorless_chirho: Vec<String> = Vec::new();

    for entry_chirho in std::fs::read_dir(&dir_chirho).expect("models directory is readable") {
        let path_chirho = entry_chirho.expect("directory entry").path();
        let name_chirho = path_chirho
            .file_name()
            .and_then(|n_chirho| n_chirho.to_str())
            .unwrap_or_default()
            .to_string();
        if !name_chirho.ends_with(".rs") || name_chirho == "mod.rs" {
            continue;
        }
        let source_chirho =
            std::fs::read_to_string(&path_chirho).expect("model source is readable");
        // Test files carry their model's properties only by reference; the model file is the subject.
        if name_chirho.ends_with("_tests_chirho.rs") {
            continue;
        }
        if !source_chirho.contains("::always(") {
            continue; // not a property model
        }
        checked_chirho += 1;
        let has_floor_chirho = source_chirho
            .match_indices("sometimes(")
            .any(|(at_chirho, _)| witness_reads_state_chirho(&source_chirho[at_chirho..]));
        if !has_floor_chirho {
            floorless_chirho.push(name_chirho);
        }
    }

    // Positive control: if this enumeration ever finds nothing, the check itself has gone vacuous —
    // exactly the failure it exists to catch, one level up.
    assert!(
        checked_chirho >= 2,
        "expected to inspect the crate's property models, inspected {checked_chirho} -- \
         the guard's own enumeration is broken"
    );
    assert!(
        floorless_chirho.is_empty(),
        "these models assert `always` laws with no state-reading `sometimes` witness, so they can \
         be green while their state space goes nowhere: {floorless_chirho:?} -- add a witness that \
         names a state the model must actually reach"
    );
}
