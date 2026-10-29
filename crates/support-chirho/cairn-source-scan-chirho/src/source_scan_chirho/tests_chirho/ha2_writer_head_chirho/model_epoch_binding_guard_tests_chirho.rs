// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Keep Model D's hand-written epoch arithmetic tied to the production constant it stands for.
//!
//! WHY THIS EXISTS. The PRD cites Model D as proving the composite-epoch composition for GG3. The
//! model does NOT call `compose_writer_epoch_chirho`; it re-implements the packing itself as
//! `(geo_term << 32) | local_seq` with `u32::MAX` bounds. That duplication is legitimate — an
//! independent re-implementation is how model-checking earns its value, and a model that merely
//! called the code under test would prove nothing about it.
//!
//! The problem is that nothing PINS the two together. They agree today
//! (`WRITER_EPOCH_COMPONENT_BITS_CHIRHO = 32`), so the model's proof genuinely is about production's
//! arithmetic. Change that constant to 40 and production moves while the model keeps proving things
//! about a 32-bit split — **with every test green**, because the model has no reason to fail. The
//! model would then be a correct proof about a system that no longer exists.
//!
//! That is the shape this repo keeps finding: an instrument that keeps passing after its subject
//! moves. Here the instrument is a formal model, which makes it easier to trust and no less able to
//! drift.
//!
//! THE CORPUS IS THE CLAIM. This pins ONE constant against ONE model's hard-coded split. It does not
//! verify that the model's SEMANTICS match production's — only that the width they are built on is
//! the same number. A model that packed the fields in the wrong ORDER would still pass here.

use crate::source_scan_chirho::workspace_root_chirho;

const PRODUCTION_EPOCH_SOURCE_CHIRHO: &str =
    "crates/support-chirho/cairn-writer-head-chirho/src/writer_head_chirho.rs";

const MODEL_D_SOURCE_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-sim-chirho/src/models_chirho/model_d_geo_authority_chirho.rs";

fn read_source_chirho(rel_path_chirho: &str) -> String {
    let path_chirho = workspace_root_chirho().join(rel_path_chirho);
    std::fs::read_to_string(&path_chirho)
        .unwrap_or_else(|e_chirho| panic!("read {}: {e_chirho}", path_chirho.display()))
}

/// The declared width of each composite-epoch component in PRODUCTION.
fn production_component_bits_chirho(text_chirho: &str) -> u32 {
    let needle_chirho = "pub const WRITER_EPOCH_COMPONENT_BITS_CHIRHO: u32 = ";
    let start_chirho = text_chirho.find(needle_chirho).unwrap_or_else(|| {
        panic!("{PRODUCTION_EPOCH_SOURCE_CHIRHO} no longer declares {needle_chirho}")
    }) + needle_chirho.len();
    let rest_chirho = &text_chirho[start_chirho..];
    let end_chirho = rest_chirho
        .find(';')
        .expect("component-bits declaration is not terminated");
    rest_chirho[..end_chirho]
        .trim()
        .parse::<u32>()
        .expect("component bits is not a plain integer")
}

#[test]
fn model_d_epoch_split_matches_the_production_constant_chirho() {
    let production_chirho = read_source_chirho(PRODUCTION_EPOCH_SOURCE_CHIRHO);
    let model_chirho = read_source_chirho(MODEL_D_SOURCE_CHIRHO);
    assert!(
        model_chirho.len() > 500,
        "Model D read back nearly empty — this guard would pass vacuously"
    );

    let bits_chirho = production_component_bits_chirho(&production_chirho);
    let shift_left_chirho = format!("<< {bits_chirho}");
    let shift_right_chirho = format!(">> {bits_chirho}");

    assert!(
        model_chirho.contains(&shift_left_chirho) && model_chirho.contains(&shift_right_chirho),
        "Model D packs the composite epoch with a different width than production. Production \
         declares WRITER_EPOCH_COMPONENT_BITS_CHIRHO = {bits_chirho}, so the model must shift by \
         {bits_chirho} in both directions. The PRD cites Model D as PROVING the composite-epoch \
         composition; if the widths diverge, the model keeps proving a correct theorem about a \
         system that no longer exists, and every test stays green while it does. Re-derive the \
         model against the new width, or state explicitly that it models a different composition"
    );
}

#[test]
fn positive_control_a_width_change_would_be_caught_chirho() {
    // A guard whose green cannot be distinguished from a broken check is decoration. Prove the
    // comparison actually discriminates: the real model must NOT contain a width it does not use.
    let model_chirho = read_source_chirho(MODEL_D_SOURCE_CHIRHO);
    let production_chirho = read_source_chirho(PRODUCTION_EPOCH_SOURCE_CHIRHO);
    let bits_chirho = production_component_bits_chirho(&production_chirho);

    let wrong_bits_chirho = bits_chirho + 8;
    assert!(
        !model_chirho.contains(&format!("<< {wrong_bits_chirho}")),
        "the model unexpectedly contains a {wrong_bits_chirho}-bit shift, so this control cannot \
         distinguish agreement from coincidence"
    );
    // And the parser must actually read the declaration rather than defaulting.
    assert_eq!(
        bits_chirho, 32,
        "production component width changed; that is a real event, not a test failure to silence — \
         update Model D and this expectation together, in one reviewed commit"
    );
}
