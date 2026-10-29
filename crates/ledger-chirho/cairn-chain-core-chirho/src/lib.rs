// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The ONE signed-chain law every ledger-family append-only log shares (CF4 brick-1 extraction,
//! rule-of-three ruled at design time: kind-registry + projection-registry + the CF2 saga log).
//!
//! The law: record 0's `prev` binds a DOMAIN-SEPARATED identity anchor (two logs can never splice
//! each other's chains); every record's seq is DENSE from 0; every record's `prev` binds the
//! blake3 digest of the PREVIOUS stored line's exact bytes. This crate is PURE — no storage, no
//! clock, no signer: each family keeps its own record types, signature arrangement, wire codec,
//! fold, torn-tail posture, and I/O, and hands this core only what the chain law needs. A family
//! hook failure aborts the walk fail-closed at that record.

/// A hex blake3 digest string — the chain coordinate. Families convert to their own digest
/// newtypes at the boundary; the core stays type-light so no family leaks into another.
pub type ChainDigestHexChirho = String;

/// Record 0's `prev` anchor: the domain-separated digest of the log family + instance identity, so
/// two logs (or two families over one id) can never splice each other's chains.
pub fn chain_anchor_hex_chirho(domain_chirho: &str, identity_chirho: &str) -> ChainDigestHexChirho {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(domain_chirho.as_bytes());
    hasher_chirho.update(b":");
    hasher_chirho.update(identity_chirho.as_bytes());
    hasher_chirho.finalize().to_hex().to_string()
}

/// The stored-line digest — the coordinate the NEXT record's `prev` binds. Always the exact stored
/// bytes of the line (byte-identity, never value-equality — a re-serialization is a different line).
pub fn stored_line_digest_hex_chirho(line_chirho: &str) -> ChainDigestHexChirho {
    blake3::hash(line_chirho.as_bytes()).to_hex().to_string()
}

/// Why the chain walk refused. `FamilyChirho` carries the family hook's own typed error (parse,
/// signature, identity, or op-law) verbatim — the core never flattens family semantics.
#[derive(Debug, PartialEq, Eq)]
pub enum ChainWalkErrorChirho<FamilyErrorChirho> {
    /// The record's seq is not the dense next index.
    DenseSeqChirho {
        expected_chirho: u64,
        found_chirho: u64,
    },
    /// The record's `prev` does not bind the prior stored line's digest (or the anchor at seq 0).
    PrevBindingChirho { seq_chirho: u64 },
    /// A family hook refused (parse / identity / signature / op law) — fail-closed at that record.
    FamilyChirho { error_chirho: FamilyErrorChirho },
}

impl<FamilyErrorChirho> From<FamilyErrorChirho> for ChainWalkErrorChirho<FamilyErrorChirho> {
    fn from(error_chirho: FamilyErrorChirho) -> Self {
        ChainWalkErrorChirho::FamilyChirho { error_chirho }
    }
}

/// One verified chain line: the family's parsed record plus the stored-line digest the next record
/// must bind.
#[derive(Debug)]
pub struct VerifiedChainLineChirho<RecordChirho> {
    pub record_chirho: RecordChirho,
    pub line_digest_chirho: ChainDigestHexChirho,
}

/// A successful walk: the verified lines in chain order plus the tail digest the NEXT append must
/// bind (the anchor for an empty log).
pub type VerifiedChainChirho<RecordChirho> = (
    Vec<VerifiedChainLineChirho<RecordChirho>>,
    ChainDigestHexChirho,
);

/// The family hooks the walk is parameterized over. Everything family-specific lives behind these
/// four functions; the core owns ONLY the dense-seq + prev-binding + anchor law.
pub trait ChainFamilyChirho {
    type RecordChirho;
    type ErrorChirho;

    /// Strict-parse ONE stored line into the family record (the family's canonical wire law —
    /// including its exact-reserialize byte-equality check, which stays family-owned).
    fn parse_line_chirho(&self, line_chirho: &str)
        -> Result<Self::RecordChirho, Self::ErrorChirho>;

    /// The record's chain seq.
    fn seq_chirho(&self, record_chirho: &Self::RecordChirho) -> u64;

    /// The record's `prev` binding, as the hex digest string it carries.
    fn prev_hex_chirho<'record_chirho>(
        &self,
        record_chirho: &'record_chirho Self::RecordChirho,
    ) -> &'record_chirho str;

    /// Every NON-chain law the family enforces per record — identity binding, signature
    /// verification (however many signatures the family carries), and any op-level precondition
    /// the family checks in walk order. Refusing here aborts the walk fail-closed.
    fn verify_record_chirho(
        &self,
        record_chirho: &Self::RecordChirho,
    ) -> Result<(), Self::ErrorChirho>;
}

/// The verified walk: every non-empty line through the family's strict parse, the dense-seq law,
/// the prev-binding law (anchored at `anchor_hex`), and the family's own per-record verification —
/// in that order, fail-closed at the first violation. Returns the verified records with their
/// stored-line digests and the final tail digest (the anchor for an empty log).
///
/// Torn-tail posture stays FAMILY-OWNED: callers hand this walk only the clean text they have
/// already deemed complete under their own law (config authority fails closed on a torn tail; the
/// money journal repairs; the saga log resumes-or-compensates).
pub fn walk_verified_chain_chirho<FamilyChirho: ChainFamilyChirho>(
    clean_text_chirho: &str,
    anchor_hex_chirho: &str,
    family_chirho: &FamilyChirho,
) -> Result<
    VerifiedChainChirho<FamilyChirho::RecordChirho>,
    ChainWalkErrorChirho<FamilyChirho::ErrorChirho>,
> {
    let mut verified_chirho = Vec::new();
    let mut tail_digest_chirho: ChainDigestHexChirho = anchor_hex_chirho.to_string();
    for (index_chirho, line_chirho) in clean_text_chirho
        .lines()
        .filter(|line_chirho| !line_chirho.trim().is_empty())
        .enumerate()
    {
        let record_chirho = family_chirho.parse_line_chirho(line_chirho)?;
        let seq_chirho = family_chirho.seq_chirho(&record_chirho);
        if seq_chirho != index_chirho as u64 {
            return Err(ChainWalkErrorChirho::DenseSeqChirho {
                expected_chirho: index_chirho as u64,
                found_chirho: seq_chirho,
            });
        }
        if family_chirho.prev_hex_chirho(&record_chirho) != tail_digest_chirho {
            return Err(ChainWalkErrorChirho::PrevBindingChirho { seq_chirho });
        }
        family_chirho.verify_record_chirho(&record_chirho)?;
        let line_digest_chirho = stored_line_digest_hex_chirho(line_chirho);
        tail_digest_chirho = line_digest_chirho.clone();
        verified_chirho.push(VerifiedChainLineChirho {
            record_chirho,
            line_digest_chirho,
        });
    }
    Ok((verified_chirho, tail_digest_chirho))
}

#[cfg(test)]
mod tests_chirho;
