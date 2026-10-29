// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)
//! The recovery and setup code itself: 15 random bytes shown once as 24 Crockford symbols in six groups, normalized the
//! same way at mint and at use, and stored only as a salted, domain-separated blake3 hash with an optional expiry.
//!
//! Design: `spec-chirho/workflows-chirho/identity-auth-chirho/self-service-recovery-code-chirho.md` ("The code", and
//! revision 3's expiry). Not Argon2id, on purpose: the code carries 120 uniformly random bits, so memory-hardness buys
//! nothing against it, while Argon2 on an anonymous road would be a CPU lever for a stranger.

use super::*;

/// The canonical Crockford base32 alphabet: no `I`, `L`, `O` or `U`.
const CROCKFORD_ALPHABET_CHIRHO: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const RECOVERY_CODE_BYTES_CHIRHO: usize = 15;
const RECOVERY_CODE_SYMBOLS_CHIRHO: usize = 24;
const RECOVERY_CODE_GROUP_CHIRHO: usize = 4;
/// The longest typed input normalized at all. Anything longer refuses before any work, so normalization is bounded.
const RECOVERY_CODE_MAX_TYPED_CHIRHO: usize = 64;
const RECOVERY_CODE_SALT_BYTES_CHIRHO: usize = 16;
const RECOVERY_CODE_HASH_CONTEXT_CHIRHO: &str = "cairn-recovery-code-hash-v1-chirho";
const RECOVERY_CODE_STATE_CONTEXT_CHIRHO: &str = "cairn-recovery-code-state-v1-chirho";
/// Every OPERATOR-minted code expires one lifetime after its mint, an invitation or an operator recovery code alike
/// (PFE #26035). Proposed at 7 days; L.J. settles it. The invitation email reads the real expiry from `--json`, so this
/// constant is the lifetime's one source.
pub const RECOVERY_CODE_OPERATOR_LIFETIME_MS_CHIRHO: u64 = 7 * 24 * 60 * 60 * 1000;

/// A code as stored in the key record: never the code itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct StoredRecoveryCodeChirho {
    pub(super) salt_chirho: String,
    pub(super) hash_chirho: String,
    pub(super) expires_ms_chirho: Option<u64>,
}

impl StoredRecoveryCodeChirho {
    /// Live through its expiry instant and dead after it, as a key and a session are. No expiry means none.
    pub(super) fn live_at_chirho(&self, now_ms_chirho: u64) -> bool {
        self.expires_ms_chirho
            .is_none_or(|expires_ms_chirho| now_ms_chirho <= expires_ms_chirho)
    }

    /// A digest naming this stored state in the events log, so a `used-chirho` or `burned-chirho` event joins its
    /// `minted-chirho` event without carrying the hash.
    pub(super) fn state_digest_chirho(&self) -> String {
        let mut hasher_chirho = blake3::Hasher::new_derive_key(RECOVERY_CODE_STATE_CONTEXT_CHIRHO);
        for part_chirho in [self.salt_chirho.as_bytes(), self.hash_chirho.as_bytes()] {
            hasher_chirho.update(&(part_chirho.len() as u64).to_le_bytes());
            hasher_chirho.update(part_chirho);
        }
        match self.expires_ms_chirho {
            Some(expires_ms_chirho) => {
                hasher_chirho.update(&[1]);
                hasher_chirho.update(&expires_ms_chirho.to_le_bytes());
            }
            None => {
                hasher_chirho.update(&[0]);
            }
        }
        hasher_chirho.finalize().to_hex().to_string()
    }
}

/// The key record's code fields, read strictly: both halves or neither, and an expiry only beside a code. Anything
/// else is INVALID KEY STATE, which fails closed as an internal error, never as "no code".
pub(super) fn stored_recovery_code_chirho(
    record_chirho: &IdentityKeyChirho,
) -> Result<Option<StoredRecoveryCodeChirho>> {
    match (
        &record_chirho.recovery_code_salt_chirho,
        &record_chirho.recovery_code_hash_chirho,
        record_chirho.recovery_code_expires_ms_chirho,
    ) {
        (None, None, None) => Ok(None),
        (Some(salt_chirho), Some(hash_chirho), expires_ms_chirho)
            if is_lower_hex_of_len_chirho(salt_chirho, RECOVERY_CODE_SALT_BYTES_CHIRHO * 2)
                && is_lower_hex_of_len_chirho(hash_chirho, 64) =>
        {
            Ok(Some(StoredRecoveryCodeChirho {
                salt_chirho: salt_chirho.clone(),
                hash_chirho: hash_chirho.clone(),
                expires_ms_chirho,
            }))
        }
        _ => bail!(
            "invalid recovery code state in the identity key of '{}'",
            record_chirho.principal_chirho
        ),
    }
}

fn is_lower_hex_of_len_chirho(value_chirho: &str, len_chirho: usize) -> bool {
    value_chirho.len() == len_chirho
        && value_chirho
            .bytes()
            .all(|byte_chirho| matches!(byte_chirho, b'0'..=b'9' | b'a'..=b'f'))
}

/// A freshly generated code: its display form, shown once, and its stored form. The display form is never stored.
pub(super) struct FreshRecoveryCodeChirho {
    pub(super) display_chirho: String,
    pub(super) stored_chirho: StoredRecoveryCodeChirho,
}

pub(super) fn fresh_recovery_code_chirho(
    expires_ms_chirho: Option<u64>,
) -> Result<FreshRecoveryCodeChirho> {
    let mut bytes_chirho = [0_u8; RECOVERY_CODE_BYTES_CHIRHO];
    OsRng.fill_bytes(&mut bytes_chirho);
    let symbols_chirho = encode_crockford_chirho(&bytes_chirho);
    let salt_chirho = random_salt_chirho();
    let hash_chirho = recovery_code_hash_chirho(&salt_chirho, &symbols_chirho)?;
    let display_chirho = symbols_chirho
        .as_bytes()
        .chunks(RECOVERY_CODE_GROUP_CHIRHO)
        .map(|group_chirho| String::from_utf8_lossy(group_chirho).into_owned())
        .collect::<Vec<_>>()
        .join("-");
    Ok(FreshRecoveryCodeChirho {
        display_chirho,
        stored_chirho: StoredRecoveryCodeChirho {
            salt_chirho,
            hash_chirho,
            expires_ms_chirho,
        },
    })
}

/// 120 bits as 24 five-bit symbols, most significant first.
fn encode_crockford_chirho(bytes_chirho: &[u8; RECOVERY_CODE_BYTES_CHIRHO]) -> String {
    let bits_chirho = bytes_chirho.iter().fold(0_u128, |acc_chirho, byte_chirho| {
        (acc_chirho << 8) | u128::from(*byte_chirho)
    });
    (0..RECOVERY_CODE_SYMBOLS_CHIRHO)
        .rev()
        .map(|index_chirho| {
            let symbol_chirho = (bits_chirho >> (index_chirho * 5)) & 0x1f;
            char::from(CROCKFORD_ALPHABET_CHIRHO[symbol_chirho as usize])
        })
        .collect()
}

/// Normalize what she typed, identically at mint and at use: drop `-` and whitespace, uppercase, fold the decode aliases
/// `O` to `0` and `I` or `L` to `1`, then require exactly 24 canonical symbols. `None` means it cannot be a code.
pub(super) fn normalize_recovery_code_chirho(typed_chirho: &str) -> Option<String> {
    if typed_chirho.len() > RECOVERY_CODE_MAX_TYPED_CHIRHO {
        return None;
    }
    let mut normalized_chirho = String::with_capacity(RECOVERY_CODE_SYMBOLS_CHIRHO);
    for c_chirho in typed_chirho.chars() {
        if c_chirho == '-' || c_chirho.is_whitespace() {
            continue;
        }
        if !c_chirho.is_ascii() {
            return None;
        }
        let folded_chirho = match c_chirho.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            other_chirho => other_chirho,
        };
        if !CROCKFORD_ALPHABET_CHIRHO.contains(&(folded_chirho as u8)) {
            return None;
        }
        normalized_chirho.push(folded_chirho);
    }
    (normalized_chirho.len() == RECOVERY_CODE_SYMBOLS_CHIRHO).then_some(normalized_chirho)
}

/// The domain-separated hash over the fixed-size salt and the normalized code. Both parts have fixed sizes, so their
/// concatenation is unambiguous.
pub(super) fn recovery_code_hash_chirho(
    salt_hex_chirho: &str,
    normalized_chirho: &str,
) -> Result<String> {
    #[cfg(test)]
    recovery_code_hash_metrics_chirho::note_chirho();
    let salt_chirho = hex_decode_chirho(salt_hex_chirho)?;
    if salt_chirho.len() != RECOVERY_CODE_SALT_BYTES_CHIRHO
        || normalized_chirho.len() != RECOVERY_CODE_SYMBOLS_CHIRHO
    {
        bail!("recovery code hash inputs have the wrong size");
    }
    let mut hasher_chirho = blake3::Hasher::new_derive_key(RECOVERY_CODE_HASH_CONTEXT_CHIRHO);
    hasher_chirho.update(&salt_chirho);
    hasher_chirho.update(normalized_chirho.as_bytes());
    Ok(hasher_chirho.finalize().to_hex().to_string())
}

/// Counts code hashes, for the arm that proves every refusing branch runs the same dummy work.
#[cfg(test)]
pub(super) mod recovery_code_hash_metrics_chirho {
    use std::cell::Cell;

    thread_local! {
        static HASHES_CHIRHO: Cell<u64> = const { Cell::new(0) };
    }

    pub(in crate::identity_chirho) fn note_chirho() {
        HASHES_CHIRHO.with(|count_chirho| count_chirho.set(count_chirho.get() + 1));
    }

    pub(in crate::identity_chirho) fn take_chirho() -> u64 {
        HASHES_CHIRHO.with(|count_chirho| count_chirho.replace(0))
    }
}
