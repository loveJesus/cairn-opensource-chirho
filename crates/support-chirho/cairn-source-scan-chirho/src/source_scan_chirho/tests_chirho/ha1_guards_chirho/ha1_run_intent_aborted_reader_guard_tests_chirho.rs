// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The pre-effect brick's reader (agy #25907, #25911): this release READS `aborted-chirho` and never writes it, so a
//! rollback to the previous binary lands on one that can fold the log. The compiler keeps the append door from writing
//! it, because the door's status parameter has no aborted variant. This census keeps the other production roads
//! closed: the status is spelled once in production, and a run-intent record is built in one production place, the
//! door. Both counts are exact, so a census that finds nothing (a dead instrument, a renamed item) is red as well.

use super::*;

const RUN_INTENT_MODULE_CHIRHO: &str =
    "src/execution_runtime_chirho/effect_chirho/run_intent_chirho.rs";

/// The literal `aborted-chirho` is spelled on exactly ONE production line, its const: a second spelling would be a
/// second road to writing the status.
///
/// MIGRATION PATH: the writer brick writes ABORTED through the door's enum and this const, so the count stays one. A
/// second production spelling must record its reason here.
#[test]
fn the_aborted_status_is_spelled_once_in_production_chirho() {
    let lines_chirho = production_source_lines_matching_chirho("\"aborted-chirho\"");
    assert_eq!(lines_chirho.len(), 1, "{lines_chirho:#?}");
    let (path_chirho, _line_chirho, text_chirho) = &lines_chirho[0];
    assert_eq!(path_chirho, RUN_INTENT_MODULE_CHIRHO, "{lines_chirho:#?}");
    assert!(
        text_chirho.starts_with("const RUN_INTENT_ABORTED_CHIRHO: &str ="),
        "{text_chirho}"
    );
}

/// A run-intent record is built in exactly ONE production place, the append door, whose status parameter cannot name
/// ABORTED. The record's fields are public, so a second constructor anywhere in the workspace would be a road around
/// the door. The census finds the type's definition and the door's literal, and nothing else.
///
/// MIGRATION PATH: a new production constructor (a repair tool, a migration) goes through the door, or records here
/// why it builds a record itself and which statuses it can write.
#[test]
fn a_run_intent_record_is_built_only_by_the_append_door_chirho() {
    let lines_chirho = production_source_lines_matching_chirho("RunIntentRecordChirho {");
    let texts_chirho: Vec<&str> = lines_chirho
        .iter()
        .map(|(_path_chirho, _line_chirho, text_chirho)| text_chirho.as_str())
        .collect();
    assert_eq!(lines_chirho.len(), 2, "{lines_chirho:#?}");
    assert!(
        lines_chirho.iter().all(
            |(path_chirho, _line_chirho, _text_chirho)| path_chirho == RUN_INTENT_MODULE_CHIRHO
        ),
        "{lines_chirho:#?}"
    );
    assert!(
        texts_chirho.contains(&"pub struct RunIntentRecordChirho {"),
        "{texts_chirho:?}"
    );
    assert!(
        texts_chirho.contains(&"let mut record_chirho = RunIntentRecordChirho {"),
        "{texts_chirho:?}"
    );
}
