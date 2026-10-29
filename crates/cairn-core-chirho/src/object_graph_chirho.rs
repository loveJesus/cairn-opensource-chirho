// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Walks the content-addressed object graph: finds the hash-shaped references inside stored bytes, and
//! gathers the transitive closure reachable from one hash.
//!
//! Both of these are STORE primitives and neither belongs to a product pillar, which is where they had
//! come to live -- the closure walk inside `publish_chirho` (app_runtime) and the reference scanner
//! inside `gc_chirho` (governance_flows). Neither touches publish state or collection state; both touch
//! only `cas_chirho` and `HashChirho`, which live here. Their consumers span several pillars plus the
//! CLI, and a primitive with consumers in several pillars belongs below all of them.

use crate::cas_chirho;
use crate::model_chirho::HashChirho;
use anyhow::Result;
use std::collections::HashSet;
use std::path::Path;

/// Conservatively find blake3 references: maximal runs of exactly 64 hex chars.
pub fn scan_hashes_chirho(bytes_chirho: &[u8]) -> Vec<HashChirho> {
    let text_chirho = String::from_utf8_lossy(bytes_chirho);
    let chars_chirho: Vec<char> = text_chirho.chars().collect();
    let mut out_chirho = Vec::new();
    let mut i_chirho = 0;
    while i_chirho < chars_chirho.len() {
        if chars_chirho[i_chirho].is_ascii_hexdigit() {
            let start_chirho = i_chirho;
            while i_chirho < chars_chirho.len() && chars_chirho[i_chirho].is_ascii_hexdigit() {
                i_chirho += 1;
            }
            if i_chirho - start_chirho == 64 {
                out_chirho.push(HashChirho(
                    chars_chirho[start_chirho..i_chirho].iter().collect(),
                ));
            }
        } else {
            i_chirho += 1;
        }
    }
    out_chirho
}

/// Gather the content-addressed closure reachable from `start` (a DAG hash): the DAG object, its
/// node objects, and their wasm + schema blobs. Conservative — scans each object for 64-hex tokens
/// and follows the ones that resolve to a stored object (false positives in raw blobs are skipped).
pub fn gather_closure_chirho(
    root_chirho: &Path,
    start_chirho: &HashChirho,
) -> Result<Vec<(String, Vec<u8>)>> {
    let mut seen_chirho: HashSet<String> = HashSet::new();
    let mut stack_chirho = vec![start_chirho.0.clone()];
    let mut out_chirho: Vec<(String, Vec<u8>)> = Vec::new();
    while let Some(hash_chirho) = stack_chirho.pop() {
        if !seen_chirho.insert(hash_chirho.clone()) {
            continue;
        }
        let bytes_chirho =
            match cas_chirho::get_chirho(root_chirho, &HashChirho(hash_chirho.clone())) {
                Ok(bytes_chirho) => bytes_chirho,
                Err(_) => continue, // a false-positive token (not a stored object) — skip
            };
        for ref_chirho in scan_hashes_chirho(&bytes_chirho) {
            if !seen_chirho.contains(&ref_chirho.0) {
                stack_chirho.push(ref_chirho.0);
            }
        }
        out_chirho.push((hash_chirho, bytes_chirho));
    }
    Ok(out_chirho)
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    /// A unique scratch store root under the OS temp dir.
    fn tmp_root_chirho() -> std::path::PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let nanos_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        std::env::temp_dir().join(format!(
            "cairn-object-graph-{nanos_chirho}-{n_chirho}-chirho"
        ))
    }

    #[test]
    fn a_hash_run_must_be_exactly_sixty_four_hex_chars_chirho() {
        // The property that matters, and the one a length-tolerant scan would silently break: a run
        // of 65 hex characters is NOT a hash with a spare character on the end. If this accepted
        // `>= 64` it would take the first 64 of that run and yield a hash NOBODY WROTE -- a
        // well-formed address pointing at the wrong object, or at nothing. Too-short is the benign
        // direction; too-long is the dangerous one, so both are pinned.
        let sixty_four_chirho = "a".repeat(64);
        assert_eq!(
            scan_hashes_chirho(sixty_four_chirho.as_bytes()),
            vec![HashChirho(sixty_four_chirho.clone())],
            "an exactly-64 hex run is a hash"
        );
        assert!(
            scan_hashes_chirho("b".repeat(63).as_bytes()).is_empty(),
            "63 hex chars is not a hash"
        );
        assert!(
            scan_hashes_chirho("c".repeat(65).as_bytes()).is_empty(),
            "65 hex chars must yield NOTHING -- taking the first 64 would invent an address that \
             was never written"
        );
    }

    #[test]
    fn scanning_finds_every_embedded_hash_and_ignores_non_hex_chirho() {
        let one_chirho = "0".repeat(64);
        let two_chirho = "f".repeat(64);
        let bytes_chirho = format!(r#"{{"a":"{one_chirho}","b":"zzz","c":"{two_chirho}"}}"#);
        assert_eq!(
            scan_hashes_chirho(bytes_chirho.as_bytes()),
            vec![HashChirho(one_chirho), HashChirho(two_chirho)],
            "both embedded hashes are found, in order, and the non-hex value is ignored"
        );
    }

    #[test]
    fn the_closure_is_transitive_and_visits_each_object_once_chirho() {
        let root_chirho = tmp_root_chirho();
        let leaf_chirho = cas_chirho::add_chirho(&root_chirho, b"leaf").expect("store leaf");
        let mid_chirho =
            cas_chirho::add_chirho(&root_chirho, leaf_chirho.0.as_bytes()).expect("mid");
        // `top` names the leaf TWICE, and that is what makes this arm reach the pop-time dedup. The
        // push-time `contains` check does not update `seen` inside its own loop, so a hash repeated
        // within ONE object's bytes is pushed twice regardless; only the guard at pop time stops the
        // second copy being walked and emitted. Written first with DISTINCT refs, it passed with that
        // guard removed -- a fixture that never entered the region where the property is decided.
        let top_chirho = cas_chirho::add_chirho(
            &root_chirho,
            format!("{} {} {}", mid_chirho.0, leaf_chirho.0, leaf_chirho.0).as_bytes(),
        )
        .expect("top");

        let closure_chirho = gather_closure_chirho(&root_chirho, &top_chirho).expect("closure");
        let hashes_chirho: Vec<&str> = closure_chirho.iter().map(|(h, _)| h.as_str()).collect();
        assert_eq!(
            hashes_chirho.len(),
            3,
            "top, mid and leaf -- reached transitively, and the leaf counted ONCE despite two \
             parents naming it"
        );
        for want_chirho in [&top_chirho, &mid_chirho, &leaf_chirho] {
            assert!(
                hashes_chirho.contains(&want_chirho.0.as_str()),
                "closure must contain {}",
                want_chirho.0
            );
        }
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn a_hash_shaped_token_that_is_not_a_stored_object_is_skipped_not_fatal_chirho() {
        // The scanner is deliberately syntactic, so it finds 64-hex runs that were never addresses --
        // a digest inside a document, say. The closure must step over those rather than fail, or any
        // object that happens to quote a hex string becomes unpublishable.
        let root_chirho = tmp_root_chirho();
        let ghost_chirho = "d".repeat(64);
        let top_chirho =
            cas_chirho::add_chirho(&root_chirho, ghost_chirho.as_bytes()).expect("store top");

        let closure_chirho = gather_closure_chirho(&root_chirho, &top_chirho)
            .expect("a false-positive token must not fail the walk");
        assert_eq!(
            closure_chirho.len(),
            1,
            "only the real object is returned; the unstored look-alike is skipped"
        );
        assert_eq!(closure_chirho[0].0, top_chirho.0);
        let _ = std::fs::remove_dir_all(&root_chirho);
    }
}
