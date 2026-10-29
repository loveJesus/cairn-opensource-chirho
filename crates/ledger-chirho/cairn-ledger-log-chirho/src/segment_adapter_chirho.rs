// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The B0 seam: drive the seqlog segment machinery through the money journal's OWN ports.
//!
//! Two thin bridges let the journal reuse the storage-agnostic seqlog segment code (base-seq
//! derivation, the signed manifest, rotation) over the exact `LedgerStoragePortChirho` and
//! `LedgerSignerPortChirho` it already holds — so one code path drives the real filesystem in
//! production and an in-memory fault-injectable store in the crash-matrix sim:
//!
//! - [`SegmentStorageOverLedgerPortChirho`] implements seqlog's `SegmentStorageChirho` by 1:1
//!   delegation to a `LedgerStoragePortChirho`.
//! - [`SegmentContinuityOverLedgerSignerPortChirho`] implements seqlog's `SegmentContinuityPortChirho`
//!   by delegating to a `LedgerSignerPortChirho`, so manifest entries are signed by the journal's key.
//!
//! Deviation #4 holds BY CONSTRUCTION: the `SegmentStorageChirho` trait deliberately exposes no
//! truncate, so the active-file torn-tail repair stays journal-owned (through the ledger port's
//! `truncate_durable_chirho`) and can never route through this adapter.

use anyhow::{anyhow, Result};
use cairn_ledger_model_chirho as _; // keep the model in the dep graph for the crate's other modules
use cairn_seqlog_chirho::segment_chirho::continuity_chirho::{
    SegmentContinuityPortChirho, SegmentSignatureChirho,
};
use cairn_seqlog_chirho::segment_chirho::storage_chirho::{
    SegmentPathChirho, SegmentStorageChirho,
};

use crate::ports_chirho::{LedgerSignerPortChirho, LedgerStoragePortChirho, StoragePathChirho};

/// A seqlog `SegmentStorageChirho` implemented over a ledger `LedgerStoragePortChirho`.
///
/// Every method is a THIN 1:1 delegation — no buffering, no reordering — so an injected fault hits
/// the same single op the filesystem impl would. The two ports key on the same flat UTF-8 string
/// space (`SegmentPathChirho(String)` ↔ `StoragePathChirho(String)`), so the coordinate map is an
/// injective newtype swap, never a lossy `&Path` conversion.
pub struct SegmentStorageOverLedgerPortChirho<'port_chirho> {
    port_chirho: &'port_chirho dyn LedgerStoragePortChirho,
}

impl<'port_chirho> SegmentStorageOverLedgerPortChirho<'port_chirho> {
    /// Wrap a ledger storage port as a segment store.
    pub fn new_chirho(port_chirho: &'port_chirho dyn LedgerStoragePortChirho) -> Self {
        Self { port_chirho }
    }

    /// Swap a segment key for a ledger storage key. Both are flat UTF-8 `String` coordinates and the
    /// segment key is already injective (its only `&Path` origin, `from_path_chirho`, is fail-closed
    /// on non-UTF-8), so injectivity carries across unchanged — never a lossy conversion.
    fn to_storage_chirho(path_chirho: &SegmentPathChirho) -> StoragePathChirho {
        StoragePathChirho::new_chirho(path_chirho.as_str_chirho())
    }
}

impl SegmentStorageChirho for SegmentStorageOverLedgerPortChirho<'_> {
    fn read_all_chirho(&self, path_chirho: &SegmentPathChirho) -> Result<Option<Vec<u8>>> {
        self.port_chirho
            .read_all_chirho(&Self::to_storage_chirho(path_chirho))
    }

    fn object_len_chirho(&self, path_chirho: &SegmentPathChirho) -> Result<Option<u64>> {
        self.port_chirho
            .object_len_chirho(&Self::to_storage_chirho(path_chirho))
    }

    fn read_range_chirho(
        &self,
        path_chirho: &SegmentPathChirho,
        offset_chirho: u64,
        len_chirho: u64,
    ) -> Result<Vec<u8>> {
        self.port_chirho.read_exact_range_chirho(
            &Self::to_storage_chirho(path_chirho),
            offset_chirho,
            len_chirho,
        )
    }

    fn write_durable_chirho(
        &self,
        path_chirho: &SegmentPathChirho,
        bytes_chirho: &[u8],
    ) -> Result<()> {
        // Atomic full-object replace ↔ the ledger port's atomic_write (temp + rename + fsync).
        self.port_chirho
            .atomic_write_chirho(&Self::to_storage_chirho(path_chirho), bytes_chirho)
    }

    fn append_durable_chirho(
        &self,
        path_chirho: &SegmentPathChirho,
        bytes_chirho: &[u8],
    ) -> Result<()> {
        // PLAIN torn-able durable append ↔ the ledger port's append_durable. NEVER atomic_write: the
        // manifest append must keep its fail-closed-on-torn-tail recovery (Deviation #4 asymmetry —
        // the manifest fails closed on a torn tail; the active file repairs, via the journal itself).
        self.port_chirho
            .append_durable_chirho(&Self::to_storage_chirho(path_chirho), bytes_chirho)
    }

    fn rename_chirho(
        &self,
        from_chirho: &SegmentPathChirho,
        to_chirho: &SegmentPathChirho,
    ) -> Result<()> {
        self.port_chirho.rename_chirho(
            &Self::to_storage_chirho(from_chirho),
            &Self::to_storage_chirho(to_chirho),
        )
    }

    fn remove_chirho(&self, path_chirho: &SegmentPathChirho) -> Result<()> {
        self.port_chirho
            .remove_chirho(&Self::to_storage_chirho(path_chirho))
    }

    fn list_dir_chirho(&self, dir_chirho: &SegmentPathChirho) -> Result<Vec<SegmentPathChirho>> {
        // The ledger port lists by KEY PREFIX; the segment trait wants the DIRECT CHILD files of `dir`.
        // In the flat keyspace a direct child is `<dir>/<name>` with no further `/`, so list with the
        // prefix `<dir>/` and drop any deeper descendant. (create_dir_all is a no-op here, so a dir is
        // never itself a key — only files under it are, matching the fs impl's is_file filter.)
        let prefix_chirho =
            StoragePathChirho::new_chirho(format!("{}/", dir_chirho.as_str_chirho()));
        let prefix_len_chirho = prefix_chirho.key_chirho().len();
        let mut children_chirho = Vec::new();
        for key_chirho in self.port_chirho.list_chirho(&prefix_chirho)? {
            let remainder_chirho = &key_chirho.key_chirho()[prefix_len_chirho..];
            if !remainder_chirho.contains('/') {
                // The ledger key is already a flat UTF-8 String; carry it across as an injective
                // segment key with no `&Path`/lossy conversion.
                children_chirho.push(SegmentPathChirho(key_chirho.key_chirho().to_string()));
            }
        }
        Ok(children_chirho)
    }

    fn exists_chirho(&self, path_chirho: &SegmentPathChirho) -> Result<bool> {
        self.port_chirho
            .exists_chirho(&Self::to_storage_chirho(path_chirho))
    }

    fn create_dir_all_chirho(&self, _dir_chirho: &SegmentPathChirho) -> Result<()> {
        // Flat logical keyspace: directories are implicit in the key string, so there is nothing to
        // materialize. The exists-FILES-only invariant (claude2 #4661) means the segment machinery
        // never `exists`-checks a DIR — only files / manifest / marker — so this no-op cannot mask a
        // real fs≡port divergence. (The journal's LedgerStoragePort has no directory concept at all.)
        Ok(())
    }
}

/// A seqlog `SegmentContinuityPortChirho` implemented over the ledger `LedgerSignerPortChirho`.
///
/// The manifest is signed by the SAME key the journal signs its records with. seqlog signs canonical
/// BYTES; the ledger signer signs a canonical LINE (`&str`). The manifest's canonical bytes are UTF-8
/// (JSON), so this bridges `&[u8]` ↔ `&str` fail-closed on non-UTF-8. Verification NEVER consults the
/// embedded key id — the trust root is the injected signer, exactly like the ledger port.
pub struct SegmentContinuityOverLedgerSignerPortChirho<'signer_chirho> {
    signer_chirho: &'signer_chirho dyn LedgerSignerPortChirho,
}

impl<'signer_chirho> SegmentContinuityOverLedgerSignerPortChirho<'signer_chirho> {
    /// Wrap a ledger signer port as a segment continuity port.
    pub fn new_chirho(signer_chirho: &'signer_chirho dyn LedgerSignerPortChirho) -> Self {
        Self { signer_chirho }
    }

    fn canonical_line_chirho(canonical_bytes_chirho: &[u8]) -> Result<&str> {
        std::str::from_utf8(canonical_bytes_chirho)
            .map_err(|_error_chirho| anyhow!("segment manifest canonical bytes are not UTF-8"))
    }
}

impl SegmentContinuityPortChirho for SegmentContinuityOverLedgerSignerPortChirho<'_> {
    fn sign_canonical_chirho(
        &self,
        canonical_bytes_chirho: &[u8],
    ) -> Result<SegmentSignatureChirho> {
        let line_chirho = Self::canonical_line_chirho(canonical_bytes_chirho)?;
        Ok(SegmentSignatureChirho(
            self.signer_chirho.sign_chirho(line_chirho)?,
        ))
    }

    fn verify_canonical_chirho(
        &self,
        canonical_bytes_chirho: &[u8],
        signature_chirho: &SegmentSignatureChirho,
    ) -> Result<()> {
        let line_chirho = Self::canonical_line_chirho(canonical_bytes_chirho)?;
        if self
            .signer_chirho
            .verify_chirho(line_chirho, &signature_chirho.0)
        {
            Ok(())
        } else {
            // Fail closed — the caller treats any invalid manifest signature as a hard reject.
            Err(anyhow!(
                "segment manifest signature does not verify against the journal key"
            ))
        }
    }

    fn key_id_chirho(&self) -> String {
        self.signer_chirho.key_id_chirho()
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    /// A minimal in-crate signer: label-only key id, sign = prefix-tag the line, verify = exact
    /// re-derive. Enough to prove the continuity bridge round-trips and fails closed — the LEGACY
    /// base-seq derive path (empty manifest) never signs/verifies, so this direct round-trip is the
    /// only place the continuity adapter's sign/verify is exercised until brick 3 wires rotation.
    struct TestSignerChirho;

    impl LedgerSignerPortChirho for TestSignerChirho {
        fn sign_chirho(&self, signed_content_line_chirho: &str) -> Result<String> {
            Ok(format!("sig::{signed_content_line_chirho}"))
        }

        fn key_id_chirho(&self) -> String {
            "test-signer-chirho".to_string()
        }

        fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
            sig_chirho == format!("sig::{signed_content_line_chirho}")
        }
    }

    #[test]
    fn continuity_bridge_signs_verifies_and_fails_closed_chirho() {
        let signer_chirho = TestSignerChirho;
        let continuity_chirho =
            SegmentContinuityOverLedgerSignerPortChirho::new_chirho(&signer_chirho);

        assert_eq!(continuity_chirho.key_id_chirho(), "test-signer-chirho");

        let bytes_chirho = br#"{"entry_chirho":"segment-manifest-line"}"#;
        let signature_chirho = continuity_chirho
            .sign_canonical_chirho(bytes_chirho)
            .unwrap();
        // Round-trip: the journal key signs the manifest bytes and verifies its own signature.
        continuity_chirho
            .verify_canonical_chirho(bytes_chirho, &signature_chirho)
            .unwrap();

        // Tampered bytes fail closed.
        assert!(continuity_chirho
            .verify_canonical_chirho(br#"{"entry_chirho":"tampered"}"#, &signature_chirho)
            .is_err());
        // Tampered signature fails closed.
        assert!(continuity_chirho
            .verify_canonical_chirho(bytes_chirho, &SegmentSignatureChirho("forged".to_string()))
            .is_err());
    }
}
