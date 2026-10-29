// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Content-addressed store — the cairn of memorial stones.
//!
//! Objects live on disk under `<root>/objects-chirho/ab/cdef…`, git-style sharded by hash
//! prefix. Storing is idempotent by construction: identical bytes ⇒ identical address ⇒ same file.

use crate::model_chirho::HashChirho;
#[cfg(unix)]
use cairn_durable_chirho::cas_lifecycle_chirho::{
    publish_content_addressed_file_at_root_no_replace_chirho, CasLifecycleErrorKindChirho,
};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Hash bytes with blake3 → the object's content address.
pub fn hash_chirho(bytes_chirho: &[u8]) -> HashChirho {
    HashChirho(blake3::hash(bytes_chirho).to_hex().to_string())
}

/// On-disk path of an object, sharded by the first two hex chars of its hash.
pub(crate) fn object_path_chirho(root_chirho: &Path, addr_chirho: &HashChirho) -> PathBuf {
    let hex_chirho = &addr_chirho.0;
    root_chirho
        .join("objects-chirho")
        .join(&hex_chirho[0..2])
        .join(&hex_chirho[2..])
}

/// Add bytes to the store; returns the content address. Idempotent.
pub fn add_chirho(root_chirho: &Path, bytes_chirho: &[u8]) -> io::Result<HashChirho> {
    let addr_chirho = hash_chirho(bytes_chirho);
    #[cfg(unix)]
    {
        publish_content_addressed_file_at_root_no_replace_chirho(
            root_chirho,
            &addr_chirho.0,
            bytes_chirho,
        )
        .map_err(|error_chirho| {
            let kind_chirho = match error_chirho.kind_chirho() {
                CasLifecycleErrorKindChirho::CorruptWinnerChirho => io::ErrorKind::InvalidData,
                _ => io::ErrorKind::Other,
            };
            io::Error::new(kind_chirho, error_chirho)
        })?;
    }
    #[cfg(not(unix))]
    return Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic descriptor-relative no-replace CAS publication unavailable",
    ));
    Ok(addr_chirho)
}

/// What a content-addressed read actually found.
///
/// The three failure outcomes are kept apart HERE, where they are structurally distinct — a
/// missing path, a rehash that disagrees, and everything else — rather than guessed by a caller
/// from the fact that a read "did not succeed". A caller that must decide whether it may look for
/// a value somewhere else needs that decision to rest on genuine ABSENCE and nothing wider:
/// a tampered object is PRESENT, and an unreadable one may well be present too, so rescuing
/// either would let a fallback launder a live tamper (or a broken store) into a clean pass.
#[derive(Debug)]
pub enum CasReadOutcomeChirho {
    /// Bytes are present and re-hash to the requested address.
    VerifiedChirho(Vec<u8>),
    /// Nothing sits at the object path: `io::ErrorKind::NotFound` and only that. The one outcome
    /// for which looking elsewhere for the value is legitimate.
    AbsentChirho(io::Error),
    /// Bytes are present and do not re-hash to the requested address — tamper, by definition.
    ///
    /// It carries what the bytes DID hash to, and deliberately not the bytes. Handing every caller
    /// the payload that just failed its content-address check is an unused capability pointing the
    /// wrong way: this type exists to stop callers trusting unverified bytes, and a field that
    /// vends them arrives for free at every match site. It also travels — the enum derives `Debug`,
    /// so one `{:?}` in a refusal message or a test failure would print an attacker-controlled body
    /// that may be plaintext PII. Code that genuinely wants unverified bytes should read the object
    /// path deliberately, which is an explicit act a reviewer can see.
    TamperedChirho { actual_chirho: HashChirho },
    /// The object could not be read at all: permission, a directory in its place, a truncated or
    /// failing device. NOT absence — this says nothing about whether the object is there.
    UnreadableChirho(io::Error),
}

/// Fetch an object by content address, reporting precisely why not when it does not verify.
pub fn read_verified_chirho(root_chirho: &Path, addr_chirho: &HashChirho) -> CasReadOutcomeChirho {
    let bytes_chirho = match fs::read(object_path_chirho(root_chirho, addr_chirho)) {
        Ok(bytes_chirho) => bytes_chirho,
        Err(error_chirho) if error_chirho.kind() == io::ErrorKind::NotFound => {
            return CasReadOutcomeChirho::AbsentChirho(error_chirho)
        }
        Err(error_chirho) => return CasReadOutcomeChirho::UnreadableChirho(error_chirho),
    };
    let actual_chirho = hash_chirho(&bytes_chirho);
    if actual_chirho != *addr_chirho {
        return CasReadOutcomeChirho::TamperedChirho { actual_chirho };
    }
    CasReadOutcomeChirho::VerifiedChirho(bytes_chirho)
}

/// Read at most the caller's byte budget from one identity-stable regular object and rehash it.
pub fn read_verified_bounded_chirho(
    root_chirho: &Path,
    addr_chirho: &HashChirho,
    max_bytes_chirho: u64,
) -> CasReadOutcomeChirho {
    if addr_chirho.0.len() != 64
        || !addr_chirho
            .0
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
    {
        return CasReadOutcomeChirho::UnreadableChirho(io::Error::new(
            io::ErrorKind::InvalidInput,
            "content address must be 64 lowercase hexadecimal characters",
        ));
    }
    let bytes_chirho = match cairn_durable_chirho::read_identity_stable_bounded_regular_file_chirho(
        &object_path_chirho(root_chirho, addr_chirho),
        max_bytes_chirho,
    ) {
        Ok(bytes_chirho) => bytes_chirho,
        Err(error_chirho) if error_chirho.kind() == io::ErrorKind::NotFound => {
            return CasReadOutcomeChirho::AbsentChirho(error_chirho)
        }
        Err(error_chirho) => return CasReadOutcomeChirho::UnreadableChirho(error_chirho),
    };
    let actual_chirho = hash_chirho(&bytes_chirho);
    if actual_chirho != *addr_chirho {
        return CasReadOutcomeChirho::TamperedChirho { actual_chirho };
    }
    CasReadOutcomeChirho::VerifiedChirho(bytes_chirho)
}

/// Fetch an object by content address.
///
/// Collapses [`read_verified_chirho`]'s three failure outcomes back into one `io::Error`, which is
/// all most callers need. **Anything with a fallback — anything that treats "the read did not
/// succeed" as licence to look elsewhere, or to record the object as absent — must use
/// [`read_verified_chirho`] instead.**
///
/// Be precise about WHY, because the obvious reading is wrong in a way that invites the bug.
/// Today the collapsed error's KIND does happen to separate the cases: absence arrives as
/// `NotFound`, a content-address mismatch as `InvalidData`, and an unreadable object as whatever
/// the OS said (a directory in the object's place is `IsADirectory`). So a caller branching on
/// `kind() == NotFound` gets the right answer right now and will conclude this warning is
/// over-cautious.
///
/// **That separation is an implementation detail of this function, not a contract.** Nothing in the
/// signature states it and no compiler check enforces it, so a caller keying on the error kind is
/// resting on an undocumented invariant — and the failure mode when it shifts is silent and
/// privacy-shaped: an object that is PRESENT but could not be read gets recorded as ABSENT.
///
/// [`read_verified_chirho`] has no such gap — its four variants must be handled exhaustively, so
/// forgetting the unreadable case is a compile error rather than a false absence claim.
pub fn get_chirho(root_chirho: &Path, addr_chirho: &HashChirho) -> io::Result<Vec<u8>> {
    match read_verified_chirho(root_chirho, addr_chirho) {
        CasReadOutcomeChirho::VerifiedChirho(bytes_chirho) => Ok(bytes_chirho),
        CasReadOutcomeChirho::AbsentChirho(error_chirho)
        | CasReadOutcomeChirho::UnreadableChirho(error_chirho) => Err(error_chirho),
        CasReadOutcomeChirho::TamperedChirho { actual_chirho, .. } => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "content address mismatch: requested {}, actual {}",
                addr_chirho.0, actual_chirho.0
            ),
        )),
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_root_chirho() -> PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let nanos_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        std::env::temp_dir().join(format!("cairn-cas-test-{nanos_chirho}-{n_chirho}"))
    }

    #[test]
    fn same_bytes_same_address_chirho() {
        assert_eq!(hash_chirho(b"love Jesus"), hash_chirho(b"love Jesus"));
        assert_ne!(hash_chirho(b"a"), hash_chirho(b"b"));
    }

    #[test]
    fn get_rejects_tampered_address_body_chirho() {
        let root_chirho = tmp_root_chirho();
        let addr_chirho = add_chirho(&root_chirho, b"original wasm").unwrap();
        fs::write(
            object_path_chirho(&root_chirho, &addr_chirho),
            b"tampered wasm",
        )
        .unwrap();

        let error_chirho = get_chirho(&root_chirho, &addr_chirho).unwrap_err();
        assert_eq!(error_chirho.kind(), io::ErrorKind::InvalidData);
        assert!(error_chirho
            .to_string()
            .contains("content address mismatch"));

        let _ = fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn add_refuses_a_corrupt_preexisting_winner_without_overwrite_chirho() {
        let root_chirho = tmp_root_chirho();
        let intended_chirho = b"intended immutable bytes chirho";
        let address_chirho = hash_chirho(intended_chirho);
        let object_chirho = object_path_chirho(&root_chirho, &address_chirho);
        fs::create_dir_all(object_chirho.parent().unwrap()).unwrap();
        fs::write(&object_chirho, b"foreign corrupt winner chirho").unwrap();

        let error_chirho = add_chirho(&root_chirho, intended_chirho).unwrap_err();
        assert_eq!(error_chirho.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            fs::read(&object_chirho).unwrap(),
            b"foreign corrupt winner chirho"
        );
        fs::remove_dir_all(root_chirho).unwrap();
    }

    #[test]
    fn concurrent_same_hash_adds_converge_on_one_exact_object_chirho() {
        let root_chirho = tmp_root_chirho();
        fs::create_dir_all(&root_chirho).unwrap();
        let bytes_chirho = Arc::new(b"concurrent core CAS bytes chirho".to_vec());
        let expected_chirho = hash_chirho(&bytes_chirho);
        let barrier_chirho = Arc::new(Barrier::new(9));
        let mut publishers_chirho = Vec::new();
        for _publisher_index_chirho in 0..8 {
            let root_chirho = root_chirho.clone();
            let bytes_chirho = Arc::clone(&bytes_chirho);
            let barrier_chirho = Arc::clone(&barrier_chirho);
            publishers_chirho.push(std::thread::spawn(move || {
                barrier_chirho.wait();
                add_chirho(&root_chirho, &bytes_chirho).unwrap()
            }));
        }
        barrier_chirho.wait();
        for publisher_chirho in publishers_chirho {
            assert_eq!(publisher_chirho.join().unwrap(), expected_chirho);
        }
        assert_eq!(
            get_chirho(&root_chirho, &expected_chirho).unwrap(),
            *bytes_chirho
        );
        fs::remove_dir_all(root_chirho).unwrap();
    }
}
