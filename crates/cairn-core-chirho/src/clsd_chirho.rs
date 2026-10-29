// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Canonical logical state digest (CLSD) primitives for Gate 1 replay equivalence.
//!
//! This module is intentionally pure and serde-free: later live projection readers materialize
//! `ProjectionStateChirho`, and this module gives them one explicit byte grammar to hash.

use crate::model_chirho::HashChirho;
use std::collections::BTreeMap;

const CLSD_MAGIC_CHIRHO: &[u8] = b"cairn-clsd-v1-chirho";

pub type ProjectionEntriesChirho = BTreeMap<String, HashChirho>;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProjectionStateChirho {
    pub surfaces_chirho: BTreeMap<String, ProjectionEntriesChirho>,
}

impl ProjectionStateChirho {
    pub fn insert_chirho(
        &mut self,
        surface_chirho: impl Into<String>,
        key_chirho: impl Into<String>,
        value_chirho: HashChirho,
    ) {
        self.surfaces_chirho
            .entry(surface_chirho.into())
            .or_default()
            .insert(key_chirho.into(), value_chirho);
    }

    pub fn is_empty_chirho(&self) -> bool {
        self.surfaces_chirho.is_empty()
    }
}

pub fn clsd_encode_chirho(state_chirho: &ProjectionStateChirho) -> Vec<u8> {
    let mut out_chirho = Vec::new();
    encode_bytes_chirho(&mut out_chirho, CLSD_MAGIC_CHIRHO);
    encode_len_chirho(&mut out_chirho, state_chirho.surfaces_chirho.len());
    for (surface_chirho, entries_chirho) in &state_chirho.surfaces_chirho {
        encode_str_chirho(&mut out_chirho, surface_chirho);
        encode_len_chirho(&mut out_chirho, entries_chirho.len());
        for (key_chirho, value_chirho) in entries_chirho {
            encode_str_chirho(&mut out_chirho, key_chirho);
            encode_str_chirho(&mut out_chirho, &value_chirho.0);
        }
    }
    out_chirho
}

pub fn clsd_digest_chirho(state_chirho: &ProjectionStateChirho) -> HashChirho {
    HashChirho(
        blake3::hash(&clsd_encode_chirho(state_chirho))
            .to_hex()
            .to_string(),
    )
}

fn encode_len_chirho(out_chirho: &mut Vec<u8>, value_chirho: usize) {
    let value_chirho = u64::try_from(value_chirho).expect("CLSD collection length fits in u64");
    out_chirho.extend_from_slice(&value_chirho.to_le_bytes());
}

fn encode_bytes_chirho(out_chirho: &mut Vec<u8>, bytes_chirho: &[u8]) {
    encode_len_chirho(out_chirho, bytes_chirho.len());
    out_chirho.extend_from_slice(bytes_chirho);
}

fn encode_str_chirho(out_chirho: &mut Vec<u8>, value_chirho: &str) {
    encode_bytes_chirho(out_chirho, value_chirho.as_bytes());
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use std::process::Command;

    const CHILD_DIGEST_ENV_CHIRHO: &str = "CAIRN_CLSD_CHILD_DIGEST_CHIRHO";

    fn hash_chirho(label_chirho: &str) -> HashChirho {
        HashChirho(blake3::hash(label_chirho.as_bytes()).to_hex().to_string())
    }

    fn sample_state_chirho() -> ProjectionStateChirho {
        let mut state_chirho = ProjectionStateChirho::default();
        state_chirho.insert_chirho("refs-chirho", "main", hash_chirho("main"));
        state_chirho.insert_chirho("ledger-chirho", "row-2", hash_chirho("ledger-2"));
        state_chirho.insert_chirho("ledger-chirho", "row-1", hash_chirho("ledger-1"));
        state_chirho
    }

    #[test]
    fn clsd_digest_is_order_independent_chirho() {
        let mut first_chirho = ProjectionStateChirho::default();
        first_chirho.insert_chirho("ledger-chirho", "row-2", hash_chirho("ledger-2"));
        first_chirho.insert_chirho("refs-chirho", "main", hash_chirho("main"));
        first_chirho.insert_chirho("ledger-chirho", "row-1", hash_chirho("ledger-1"));

        let mut second_chirho = ProjectionStateChirho::default();
        second_chirho.insert_chirho("ledger-chirho", "row-1", hash_chirho("ledger-1"));
        second_chirho.insert_chirho("ledger-chirho", "row-2", hash_chirho("ledger-2"));
        second_chirho.insert_chirho("refs-chirho", "main", hash_chirho("main"));

        assert_eq!(
            clsd_encode_chirho(&first_chirho),
            clsd_encode_chirho(&second_chirho)
        );
        assert_eq!(
            clsd_digest_chirho(&first_chirho),
            clsd_digest_chirho(&second_chirho)
        );
    }

    #[test]
    fn clsd_length_prefixes_are_injective_chirho() {
        let same_hash_chirho = hash_chirho("same");
        let mut first_chirho = ProjectionStateChirho::default();
        first_chirho.insert_chirho("a", "bc", same_hash_chirho.clone());

        let mut second_chirho = ProjectionStateChirho::default();
        second_chirho.insert_chirho("ab", "c", same_hash_chirho);

        assert_ne!(
            clsd_encode_chirho(&first_chirho),
            clsd_encode_chirho(&second_chirho)
        );
        assert_ne!(
            clsd_digest_chirho(&first_chirho),
            clsd_digest_chirho(&second_chirho)
        );
    }

    #[test]
    fn clsd_digest_changes_when_value_changes_chirho() {
        let mut first_chirho = sample_state_chirho();
        let mut second_chirho = sample_state_chirho();
        second_chirho.insert_chirho("refs-chirho", "main", hash_chirho("changed-main"));

        assert_ne!(
            clsd_digest_chirho(&first_chirho),
            clsd_digest_chirho(&second_chirho)
        );
        first_chirho.insert_chirho("refs-chirho", "main", hash_chirho("changed-main"));
        assert_eq!(
            clsd_digest_chirho(&first_chirho),
            clsd_digest_chirho(&second_chirho)
        );
    }

    #[test]
    fn clsd_child_digest_process_chirho() {
        if std::env::var_os(CHILD_DIGEST_ENV_CHIRHO).is_none() {
            return;
        }
        println!(
            "CLSD_DIGEST_CHIRHO={}",
            clsd_digest_chirho(&sample_state_chirho()).0
        );
    }

    #[test]
    fn clsd_stable_across_process_restart_chirho() {
        if std::env::var_os(CHILD_DIGEST_ENV_CHIRHO).is_some() {
            return;
        }

        let expected_chirho = clsd_digest_chirho(&sample_state_chirho()).0;
        let output_chirho = Command::new(std::env::current_exe().expect("current test binary"))
            .env(CHILD_DIGEST_ENV_CHIRHO, "1")
            .arg("--exact")
            .arg("clsd_chirho::tests_chirho::clsd_child_digest_process_chirho")
            .arg("--nocapture")
            .output()
            .expect("spawn CLSD child digest process");

        assert!(
            output_chirho.status.success(),
            "child CLSD digest process failed: {}",
            String::from_utf8_lossy(&output_chirho.stderr)
        );
        let stdout_chirho = String::from_utf8(output_chirho.stdout).expect("child stdout UTF-8");
        assert!(
            stdout_chirho.contains(&format!("CLSD_DIGEST_CHIRHO={expected_chirho}")),
            "child stdout did not contain expected digest {expected_chirho}: {stdout_chirho}"
        );
    }
}
