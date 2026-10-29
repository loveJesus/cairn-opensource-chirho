// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Durable instance signing-key loading, signing, verification, and keyed derivation.

use anyhow::{anyhow, bail, Context, Result};
#[cfg(not(unix))]
use cairn_durable_chirho::write_file_durable_chirho;
use cairn_durable_chirho::write_file_durable_with_mode_chirho;
use cairn_seqlog_chirho::seqlog_chirho;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use std::io::Read;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

const SIGNING_KEY_FILE_CHIRHO: &str = "signing-key-chirho.bin";
const PUBKEY_FILE_CHIRHO: &str = "pubkey-chirho.hex";
const SIGNING_KEY_LOCK_CHIRHO: &str = "signing-key-chirho";
const SIGNING_KEY_BYTES_CHIRHO: usize = 32;
const PUBLIC_KEY_HEX_BYTES_CHIRHO: usize = 64;
const PUBLIC_KEY_FILE_MAX_BYTES_CHIRHO: usize = PUBLIC_KEY_HEX_BYTES_CHIRHO + 1;

struct SigningKeyHandleChirho {
    key_chirho: SigningKey,
}

/// A one-message proof that the caller currently possesses one validated pre-provisioned keypair.
/// It exposes only the public key id and signature, never a reusable private-key handle.
pub struct ExistingKeyPossessionChirho {
    key_id_chirho: String,
    signature_hex_chirho: String,
}

impl ExistingKeyPossessionChirho {
    pub fn key_id_chirho(&self) -> &str {
        &self.key_id_chirho
    }

    pub fn signature_hex_chirho(&self) -> &str {
        &self.signature_hex_chirho
    }

    pub fn into_signature_hex_chirho(self) -> String {
        self.signature_hex_chirho
    }
}

impl SigningKeyHandleChirho {
    pub fn sign_message_chirho(&self, message_chirho: &[u8]) -> String {
        hex_encode_chirho(&self.key_chirho.sign(message_chirho).to_bytes())
    }

    pub fn pubkey_hex_chirho(&self) -> String {
        hex_encode_chirho(self.key_chirho.verifying_key().as_bytes())
    }

    pub fn derive_key_chirho(&self, context_chirho: &str) -> [u8; 32] {
        blake3::derive_key(context_chirho, &self.key_chirho.to_bytes())
    }
}

fn signing_key_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join(SIGNING_KEY_FILE_CHIRHO)
}

fn pubkey_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join(PUBKEY_FILE_CHIRHO)
}

fn write_private_signing_key_chirho(path_chirho: &Path, bytes_chirho: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        write_file_durable_with_mode_chirho(path_chirho, bytes_chirho, 0o600)?;
        std::fs::set_permissions(path_chirho, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        write_file_durable_chirho(path_chirho, bytes_chirho)?;
    }
    Ok(())
}

fn write_public_signing_key_chirho(path_chirho: &Path, bytes_chirho: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        write_file_durable_with_mode_chirho(path_chirho, bytes_chirho, 0o600)?;
        std::fs::set_permissions(path_chirho, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        write_file_durable_chirho(path_chirho, bytes_chirho)?;
    }
    Ok(())
}

/// Load the cairn instance signing key, or generate + persist one on first use.
/// (v1: one instance key; per-node keys are deferred.)
fn load_or_create_signing_key_chirho(root_chirho: &Path) -> Result<SigningKeyHandleChirho> {
    seqlog_chirho::with_named_lock_chirho(root_chirho, SIGNING_KEY_LOCK_CHIRHO, || {
        let path_chirho = signing_key_path_chirho(root_chirho);
        if path_chirho.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path_chirho, std::fs::Permissions::from_mode(0o600))?;
            }
            let bytes_chirho = std::fs::read(&path_chirho)?;
            let seed_chirho: [u8; 32] = bytes_chirho
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("signing key must be 32 bytes"))?;
            Ok(SigningKeyHandleChirho {
                key_chirho: SigningKey::from_bytes(&seed_chirho),
            })
        } else {
            let key_chirho = SigningKey::generate(&mut OsRng);
            std::fs::create_dir_all(root_chirho)?;
            write_private_signing_key_chirho(&path_chirho, &key_chirho.to_bytes())?;
            // Explicit mode, NOT the umask. The verifier below refuses a public key that is
            // group/other-writable — anyone able to rewrite it can swap this node's identity — and
            // under the common umask 002 an unmoded write produces exactly that, so keygen would
            // create a key its own checker rejects. Measured on a real host: three nodes served
            // happily and never joined raft because of it.
            write_public_signing_key_chirho(
                &pubkey_path_chirho(root_chirho),
                hex_encode_chirho(&key_chirho.verifying_key().to_bytes()).as_bytes(),
            )?;
            Ok(SigningKeyHandleChirho { key_chirho })
        }
    })
}

/// Sign an arbitrary message with the cairn instance key; returns a hex signature.
pub fn sign_message_chirho(root_chirho: &Path, message_chirho: &[u8]) -> Result<String> {
    Ok(load_or_create_signing_key_chirho(root_chirho)?.sign_message_chirho(message_chirho))
}

/// Sign with an already-provisioned instance key without creating or changing key custody files.
pub fn sign_message_with_existing_key_chirho(
    root_chirho: &Path,
    message_chirho: &[u8],
) -> Result<String> {
    Ok(
        sign_with_existing_key_possession_chirho(root_chirho, message_chirho)?
            .into_signature_hex_chirho(),
    )
}

/// Sign one message while returning the matching key id from the same bounded custody load.
pub fn sign_with_existing_key_possession_chirho(
    root_chirho: &Path,
    message_chirho: &[u8],
) -> Result<ExistingKeyPossessionChirho> {
    let key_chirho = load_existing_signing_keypair_chirho(root_chirho)?;
    Ok(ExistingKeyPossessionChirho {
        key_id_chirho: key_chirho.pubkey_hex_chirho(),
        signature_hex_chirho: key_chirho.sign_message_chirho(message_chirho),
    })
}

/// The cairn instance public key, hex-encoded.
pub fn pubkey_hex_chirho(root_chirho: &Path) -> Result<String> {
    Ok(load_or_create_signing_key_chirho(root_chirho)?.pubkey_hex_chirho())
}

/// Read the existing cairn instance public key without creating a new signing key.
pub fn existing_pubkey_hex_chirho(root_chirho: &Path) -> Result<String> {
    let root_metadata_chirho = inspect_existing_key_root_chirho(root_chirho)?;
    let (stored_public_key_chirho, public_metadata_chirho) =
        read_existing_public_key_chirho(&pubkey_path_chirho(root_chirho))?;
    validate_existing_public_key_owner_chirho(&root_metadata_chirho, &public_metadata_chirho)?;
    Ok(stored_public_key_chirho)
}

/// Validate bounded existing private/public custody and return the matching public key.
/// This proves current possession without creating, chmodding, or rewriting either file.
pub fn existing_keypair_pubkey_hex_chirho(root_chirho: &Path) -> Result<String> {
    Ok(load_existing_signing_keypair_chirho(root_chirho)?.pubkey_hex_chirho())
}

pub fn derive_instance_key_chirho(root_chirho: &Path, context_chirho: &str) -> Result<[u8; 32]> {
    Ok(load_or_create_signing_key_chirho(root_chirho)?.derive_key_chirho(context_chirho))
}

/// Derive a context-bound key from the EXISTING instance key: it never creates or rewrites key
/// custody files, and the signing key never leaves this crate. A missing or out-of-custody key refuses.
pub fn derive_existing_instance_key_chirho(
    root_chirho: &Path,
    context_chirho: &str,
) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    Ok(zeroize::Zeroizing::new(
        load_existing_signing_keypair_chirho(root_chirho)?.derive_key_chirho(context_chirho),
    ))
}

/// Verify a hex signature over `message` with a hex ed25519 public key.
pub fn verify_with_pubkey_chirho(
    pubkey_hex_chirho: &str,
    message_chirho: &[u8],
    sig_hex_chirho: &str,
) -> Result<bool> {
    let pk_bytes_chirho = hex_decode_chirho(pubkey_hex_chirho)?;
    let pk_arr_chirho: [u8; 32] = pk_bytes_chirho
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("public key must be 32 bytes"))?;
    let vk_chirho = VerifyingKey::from_bytes(&pk_arr_chirho)
        .map_err(|e_chirho| anyhow!("bad public key: {e_chirho}"))?;
    verify_with_key_chirho(&vk_chirho, message_chirho, sig_hex_chirho)
}

pub fn verify_with_root_pubkey_chirho(
    root_chirho: &Path,
    message_chirho: &[u8],
    sig_hex_chirho: &str,
) -> Result<bool> {
    let vk_chirho = load_verifying_key_chirho(root_chirho)?;
    verify_with_key_chirho(&vk_chirho, message_chirho, sig_hex_chirho)
}

fn load_existing_signing_keypair_chirho(root_chirho: &Path) -> Result<SigningKeyHandleChirho> {
    let root_metadata_chirho = inspect_existing_key_root_chirho(root_chirho)?;
    let (mut seed_chirho, private_metadata_chirho) =
        read_existing_private_seed_chirho(&signing_key_path_chirho(root_chirho))?;
    let key_chirho = SigningKeyHandleChirho {
        key_chirho: SigningKey::from_bytes(&seed_chirho),
    };
    seed_chirho.zeroize();
    let (stored_public_key_chirho, public_metadata_chirho) =
        read_existing_public_key_chirho(&pubkey_path_chirho(root_chirho))?;
    validate_existing_key_owners_chirho(
        &root_metadata_chirho,
        &private_metadata_chirho,
        &public_metadata_chirho,
    )?;
    if stored_public_key_chirho != key_chirho.pubkey_hex_chirho() {
        bail!("existing signing key pair does not agree");
    }
    Ok(key_chirho)
}

fn inspect_existing_key_root_chirho(root_chirho: &Path) -> Result<std::fs::Metadata> {
    let root_metadata_chirho =
        std::fs::symlink_metadata(root_chirho).context("inspect existing signing-key root")?;
    if !root_metadata_chirho.is_dir() {
        bail!("existing signing-key root must be a nonsymlink directory");
    }
    Ok(root_metadata_chirho)
}

fn read_existing_private_seed_chirho(
    path_chirho: &Path,
) -> Result<(Zeroizing<[u8; SIGNING_KEY_BYTES_CHIRHO]>, std::fs::Metadata)> {
    let mut file_chirho = open_existing_file_chirho(path_chirho, "private signing key")?;
    let metadata_chirho = file_chirho
        .metadata()
        .context("inspect opened private signing key")?;
    if !metadata_chirho.is_file() || metadata_chirho.len() != SIGNING_KEY_BYTES_CHIRHO as u64 {
        bail!("existing private signing key must be exactly 32 bytes");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mode_chirho = metadata_chirho.permissions().mode() & 0o7777;
        if !matches!(mode_chirho, 0o400 | 0o600) {
            bail!("existing private signing key mode must be exactly 0400 or 0600");
        }
        if metadata_chirho.nlink() != 1 {
            bail!("existing private signing key must have exactly one filesystem link");
        }
    }
    let mut seed_chirho = Zeroizing::new([0_u8; SIGNING_KEY_BYTES_CHIRHO]);
    file_chirho
        .read_exact(seed_chirho.as_mut())
        .context("read existing private signing key")?;
    let mut overflow_chirho = [0_u8; 1];
    if file_chirho.read(&mut overflow_chirho)? != 0 {
        bail!("existing private signing key exceeds 32 bytes");
    }
    Ok((seed_chirho, metadata_chirho))
}

fn read_existing_public_key_chirho(path_chirho: &Path) -> Result<(String, std::fs::Metadata)> {
    let file_chirho = open_existing_file_chirho(path_chirho, "public signing key")?;
    let metadata_chirho = file_chirho
        .metadata()
        .context("inspect opened public signing key")?;
    if !metadata_chirho.is_file()
        || metadata_chirho.len() == 0
        || metadata_chirho.len() > PUBLIC_KEY_FILE_MAX_BYTES_CHIRHO as u64
    {
        bail!("existing public signing key exceeds its bounded hex encoding");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mode_chirho = metadata_chirho.permissions().mode() & 0o7777;
        if mode_chirho & 0o400 == 0
            || mode_chirho & 0o111 != 0
            || mode_chirho & 0o022 != 0
            || mode_chirho & 0o7000 != 0
        {
            bail!(
                "existing public signing key must be owner-readable, non-executable, and not group/other-writable"
            );
        }
        if metadata_chirho.nlink() != 1 {
            bail!("existing public signing key must have exactly one filesystem link");
        }
    }
    let mut bytes_chirho = Vec::with_capacity(metadata_chirho.len() as usize);
    file_chirho
        .take((PUBLIC_KEY_FILE_MAX_BYTES_CHIRHO + 1) as u64)
        .read_to_end(&mut bytes_chirho)
        .context("read existing public signing key")?;
    if bytes_chirho.len() > PUBLIC_KEY_FILE_MAX_BYTES_CHIRHO {
        bail!("existing public signing key exceeds its bounded hex encoding");
    }
    if bytes_chirho.last() == Some(&b'\n') {
        bytes_chirho.pop();
    }
    if bytes_chirho.len() != PUBLIC_KEY_HEX_BYTES_CHIRHO
        || !bytes_chirho
            .iter()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(byte_chirho))
    {
        bail!("existing public signing key must be exact lowercase hex");
    }
    Ok((
        String::from_utf8(bytes_chirho).context("existing public signing key must be UTF-8")?,
        metadata_chirho,
    ))
}

#[cfg(unix)]
fn open_existing_file_chirho(path_chirho: &Path, role_chirho: &str) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path_chirho)
        .with_context(|| format!("open existing {role_chirho} without following symlinks"))
}

#[cfg(not(unix))]
fn open_existing_file_chirho(path_chirho: &Path, role_chirho: &str) -> Result<std::fs::File> {
    std::fs::File::open(path_chirho).with_context(|| format!("open existing {role_chirho}"))
}

#[cfg(unix)]
fn validate_existing_key_owners_chirho(
    root_metadata_chirho: &std::fs::Metadata,
    private_metadata_chirho: &std::fs::Metadata,
    public_metadata_chirho: &std::fs::Metadata,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    validate_existing_public_key_owner_chirho(root_metadata_chirho, public_metadata_chirho)?;
    let root_uid_chirho = root_metadata_chirho.uid();
    if private_metadata_chirho.uid() != root_uid_chirho {
        bail!("existing signing-key root, private key, and public key must share one owner");
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_existing_key_owners_chirho(
    _root_metadata_chirho: &std::fs::Metadata,
    _private_metadata_chirho: &std::fs::Metadata,
    _public_metadata_chirho: &std::fs::Metadata,
) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn validate_existing_public_key_owner_chirho(
    root_metadata_chirho: &std::fs::Metadata,
    public_metadata_chirho: &std::fs::Metadata,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    if public_metadata_chirho.uid() != root_metadata_chirho.uid() {
        bail!("existing signing-key root and public key must share one owner");
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_existing_public_key_owner_chirho(
    _root_metadata_chirho: &std::fs::Metadata,
    _public_metadata_chirho: &std::fs::Metadata,
) -> Result<()> {
    Ok(())
}

fn verify_with_key_chirho(
    vk_chirho: &VerifyingKey,
    message_chirho: &[u8],
    sig_hex_chirho: &str,
) -> Result<bool> {
    let sig_bytes_chirho = hex_decode_chirho(sig_hex_chirho)?;
    let sig_arr_chirho: [u8; 64] = sig_bytes_chirho
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("signature must be 64 bytes"))?;
    Ok(vk_chirho
        .verify(message_chirho, &Signature::from_bytes(&sig_arr_chirho))
        .is_ok())
}

fn load_verifying_key_chirho(root_chirho: &Path) -> Result<VerifyingKey> {
    let path_chirho = pubkey_path_chirho(root_chirho);
    let hex_chirho = std::fs::read_to_string(&path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    let bytes_chirho = hex_decode_chirho(hex_chirho.trim())?;
    let arr_chirho: [u8; 32] = bytes_chirho
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("verifying key must be 32 bytes"))?;
    VerifyingKey::from_bytes(&arr_chirho)
        .map_err(|e_chirho| anyhow!("bad verifying key: {e_chirho}"))
}

pub(crate) fn hex_encode_chirho(bytes_chirho: &[u8]) -> String {
    let mut s_chirho = String::with_capacity(bytes_chirho.len() * 2);
    for b_chirho in bytes_chirho {
        s_chirho.push_str(&format!("{b_chirho:02x}"));
    }
    s_chirho
}

/// Decode hex by BYTES, never by `&str` slices: a signature or key string read from a tampered record may
/// hold multi-byte characters, and slicing one at a byte offset would panic instead of refusing.
pub(crate) fn hex_decode_chirho(s_chirho: &str) -> Result<Vec<u8>> {
    let bytes_chirho = s_chirho.as_bytes();
    if !bytes_chirho.len().is_multiple_of(2) {
        bail!("odd-length hex string");
    }
    bytes_chirho
        .chunks_exact(2)
        .map(|pair_chirho| {
            Ok((hex_nibble_chirho(pair_chirho[0])? << 4) | hex_nibble_chirho(pair_chirho[1])?)
        })
        .collect()
}

fn hex_nibble_chirho(byte_chirho: u8) -> Result<u8> {
    match byte_chirho {
        b'0'..=b'9' => Ok(byte_chirho - b'0'),
        b'a'..=b'f' => Ok(byte_chirho - b'a' + 10),
        b'A'..=b'F' => Ok(byte_chirho - b'A' + 10),
        _ => Err(anyhow!(
            "bad hex: byte {byte_chirho:#04x} is not a hex digit"
        )),
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_root_chirho() -> PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let nanos_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        std::env::temp_dir().join(format!("cairn-signer-test-{nanos_chirho}-{n_chirho}"))
    }

    fn write_seed_chirho(root_chirho: &Path, seed_chirho: [u8; 32]) {
        std::fs::create_dir_all(root_chirho).unwrap();
        std::fs::write(signing_key_path_chirho(root_chirho), seed_chirho).unwrap();
    }

    fn snapshot_tree_chirho(root_chirho: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        let mut snapshot_chirho = BTreeMap::new();
        if !root_chirho.exists() {
            return snapshot_chirho;
        }
        let mut paths_chirho = std::fs::read_dir(root_chirho)
            .unwrap()
            .map(|entry_chirho| entry_chirho.unwrap().path())
            .collect::<Vec<_>>();
        paths_chirho.sort();
        for path_chirho in paths_chirho {
            if path_chirho.is_file() {
                snapshot_chirho.insert(
                    path_chirho.strip_prefix(root_chirho).unwrap().to_path_buf(),
                    std::fs::read(path_chirho).unwrap(),
                );
            }
        }
        snapshot_chirho
    }

    fn snapshot_entry_names_chirho(root_chirho: &Path) -> Vec<PathBuf> {
        if !root_chirho.exists() {
            return Vec::new();
        }
        let mut names_chirho = std::fs::read_dir(root_chirho)
            .unwrap()
            .map(|entry_chirho| {
                entry_chirho
                    .unwrap()
                    .path()
                    .strip_prefix(root_chirho)
                    .unwrap()
                    .to_path_buf()
            })
            .collect::<Vec<_>>();
        names_chirho.sort();
        names_chirho
    }

    #[cfg(unix)]
    fn file_mode_chirho(path_chirho: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;

        std::fs::metadata(path_chirho).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn fixed_seed_signature_pubkey_and_derived_key_are_stable_chirho() {
        let root_chirho = tmp_root_chirho();
        let seed_chirho = [0x42; 32];
        write_seed_chirho(&root_chirho, seed_chirho);

        let handle_chirho = load_or_create_signing_key_chirho(&root_chirho).unwrap();
        let expected_key_chirho = SigningKey::from_bytes(&seed_chirho);
        let message_chirho = b"fixed signer extraction compatibility message";
        assert_eq!(
            handle_chirho.pubkey_hex_chirho(),
            hex_encode_chirho(expected_key_chirho.verifying_key().as_bytes())
        );
        assert_eq!(
            handle_chirho.sign_message_chirho(message_chirho),
            hex_encode_chirho(&expected_key_chirho.sign(message_chirho).to_bytes())
        );
        assert_eq!(
            handle_chirho.derive_key_chirho("cairn-signer-test-context-v1-chirho"),
            blake3::derive_key("cairn-signer-test-context-v1-chirho", &seed_chirho)
        );

        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[cfg(unix)]
    #[test]
    fn generated_signing_key_file_is_private_chirho() {
        use std::os::unix::fs::PermissionsExt;

        let root_chirho = tmp_root_chirho();
        let _sig_chirho = sign_message_chirho(&root_chirho, b"check permissions").unwrap();
        let mode_chirho = std::fs::metadata(signing_key_path_chirho(&root_chirho))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode_chirho, 0o600);
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn existing_key_signing_is_byte_unchanged_and_verifiable_chirho() {
        let root_chirho = tmp_root_chirho();
        sign_message_chirho(&root_chirho, b"provision existing signer").unwrap();
        let before_chirho = snapshot_tree_chirho(&root_chirho);
        let entry_names_before_chirho = snapshot_entry_names_chirho(&root_chirho);
        #[cfg(unix)]
        let modes_before_chirho = (
            file_mode_chirho(&signing_key_path_chirho(&root_chirho)),
            file_mode_chirho(&pubkey_path_chirho(&root_chirho)),
        );
        let message_chirho = b"existing-only cursor message";
        let possession_chirho =
            sign_with_existing_key_possession_chirho(&root_chirho, message_chirho).unwrap();
        assert_eq!(
            possession_chirho.key_id_chirho(),
            existing_pubkey_hex_chirho(&root_chirho).unwrap()
        );
        assert!(verify_with_pubkey_chirho(
            possession_chirho.key_id_chirho(),
            message_chirho,
            possession_chirho.signature_hex_chirho(),
        )
        .unwrap());
        assert!(!verify_with_pubkey_chirho(
            possession_chirho.key_id_chirho(),
            b"wrong existing-only cursor message",
            possession_chirho.signature_hex_chirho(),
        )
        .unwrap());
        let signature_chirho =
            sign_message_with_existing_key_chirho(&root_chirho, message_chirho).unwrap();
        assert_eq!(signature_chirho, possession_chirho.signature_hex_chirho());
        assert_eq!(
            existing_keypair_pubkey_hex_chirho(&root_chirho).unwrap(),
            existing_pubkey_hex_chirho(&root_chirho).unwrap()
        );
        assert!(
            verify_with_root_pubkey_chirho(&root_chirho, message_chirho, &signature_chirho)
                .unwrap()
        );
        assert_eq!(snapshot_tree_chirho(&root_chirho), before_chirho);
        assert_eq!(
            snapshot_entry_names_chirho(&root_chirho),
            entry_names_before_chirho
        );
        #[cfg(unix)]
        assert_eq!(
            (
                file_mode_chirho(&signing_key_path_chirho(&root_chirho)),
                file_mode_chirho(&pubkey_path_chirho(&root_chirho)),
            ),
            modes_before_chirho
        );
        let _ = std::fs::remove_dir_all(root_chirho);
    }

    #[test]
    fn existing_public_key_read_does_not_load_or_require_private_material_chirho() {
        let root_chirho = tmp_root_chirho();
        sign_message_chirho(&root_chirho, b"provision public-only read").unwrap();
        let expected_public_key_chirho = existing_pubkey_hex_chirho(&root_chirho).unwrap();
        std::fs::remove_file(signing_key_path_chirho(&root_chirho)).unwrap();

        assert_eq!(
            existing_pubkey_hex_chirho(&root_chirho).unwrap(),
            expected_public_key_chirho
        );
        assert!(existing_keypair_pubkey_hex_chirho(&root_chirho).is_err());
        let _ = std::fs::remove_dir_all(root_chirho);
    }

    #[test]
    fn existing_key_derivation_never_mints_and_equals_the_minting_derivation_chirho() {
        let context_chirho = "cairn-signer-existing-derive-test-v1-chirho";
        let missing_root_chirho = tmp_root_chirho();
        std::fs::create_dir_all(&missing_root_chirho).unwrap();
        let before_chirho = snapshot_tree_chirho(&missing_root_chirho);
        assert!(derive_existing_instance_key_chirho(&missing_root_chirho, context_chirho).is_err());
        assert_eq!(
            snapshot_tree_chirho(&missing_root_chirho),
            before_chirho,
            "it minted a key"
        );
        let _ = std::fs::remove_dir_all(missing_root_chirho);

        let root_chirho = tmp_root_chirho();
        sign_message_chirho(&root_chirho, b"provision the instance key").unwrap();
        let provisioned_chirho = snapshot_tree_chirho(&root_chirho);
        let existing_chirho =
            derive_existing_instance_key_chirho(&root_chirho, context_chirho).unwrap();
        assert_eq!(
            *existing_chirho,
            derive_instance_key_chirho(&root_chirho, context_chirho).unwrap()
        );
        assert_eq!(snapshot_tree_chirho(&root_chirho), provisioned_chirho);
        let _ = std::fs::remove_dir_all(root_chirho);
    }

    #[test]
    fn existing_key_signing_refuses_missing_or_mismatched_pairs_without_writes_chirho() {
        let absent_root_chirho = tmp_root_chirho();
        assert!(sign_with_existing_key_possession_chirho(&absent_root_chirho, b"absent").is_err());
        assert!(!absent_root_chirho.exists());

        let missing_root_chirho = tmp_root_chirho();
        std::fs::create_dir_all(&missing_root_chirho).unwrap();
        let missing_before_chirho = snapshot_tree_chirho(&missing_root_chirho);
        assert!(sign_message_with_existing_key_chirho(&missing_root_chirho, b"missing").is_err());
        assert_eq!(
            snapshot_tree_chirho(&missing_root_chirho),
            missing_before_chirho
        );
        let _ = std::fs::remove_dir_all(missing_root_chirho);

        let mismatched_root_chirho = tmp_root_chirho();
        sign_message_chirho(&mismatched_root_chirho, b"provision mismatched signer").unwrap();
        std::fs::write(pubkey_path_chirho(&mismatched_root_chirho), "00".repeat(32)).unwrap();
        let mismatched_before_chirho = snapshot_tree_chirho(&mismatched_root_chirho);
        assert!(
            sign_message_with_existing_key_chirho(&mismatched_root_chirho, b"mismatched").is_err()
        );
        assert_eq!(
            snapshot_tree_chirho(&mismatched_root_chirho),
            mismatched_before_chirho
        );
        let _ = std::fs::remove_dir_all(mismatched_root_chirho);
    }

    #[test]
    fn existing_key_apis_do_not_wait_for_the_create_path_lock_chirho() {
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let root_chirho = tmp_root_chirho();
        sign_message_chirho(&root_chirho, b"provision lock-independent signer").unwrap();

        let (held_sender_chirho, held_receiver_chirho) = mpsc::channel();
        let (release_sender_chirho, release_receiver_chirho) = mpsc::channel();
        let holder_root_chirho = root_chirho.clone();
        let holder_chirho = thread::spawn(move || {
            seqlog_chirho::with_named_lock_chirho(
                &holder_root_chirho,
                SIGNING_KEY_LOCK_CHIRHO,
                || -> Result<()> {
                    held_sender_chirho.send(()).unwrap();
                    release_receiver_chirho
                        .recv_timeout(Duration::from_secs(5))
                        .unwrap();
                    Ok(())
                },
            )
            .unwrap();
        });
        held_receiver_chirho
            .recv_timeout(Duration::from_secs(5))
            .unwrap();

        let (result_sender_chirho, result_receiver_chirho) = mpsc::channel();
        let caller_root_chirho = root_chirho.clone();
        let caller_chirho = thread::spawn(move || {
            let possession_result_chirho = sign_with_existing_key_possession_chirho(
                &caller_root_chirho,
                b"lock-independent possession",
            );
            let compatibility_result_chirho = sign_message_with_existing_key_chirho(
                &caller_root_chirho,
                b"lock-independent compatibility",
            );
            result_sender_chirho
                .send((possession_result_chirho, compatibility_result_chirho))
                .unwrap();
        });
        let result_before_release_chirho =
            result_receiver_chirho.recv_timeout(Duration::from_secs(2));
        release_sender_chirho.send(()).unwrap();
        holder_chirho.join().unwrap();
        caller_chirho.join().unwrap();

        let (possession_result_chirho, compatibility_result_chirho) = result_before_release_chirho
            .expect("existing-key APIs must not acquire the create lock");
        assert!(possession_result_chirho.is_ok());
        assert!(compatibility_result_chirho.is_ok());
        let _ = std::fs::remove_dir_all(root_chirho);
    }

    #[test]
    fn existing_keypair_reads_are_bounded_and_refuse_non_files_chirho() {
        let public_overflow_root_chirho = tmp_root_chirho();
        sign_message_chirho(&public_overflow_root_chirho, b"provision bounded public").unwrap();
        std::fs::write(
            pubkey_path_chirho(&public_overflow_root_chirho),
            vec![b'a'; PUBLIC_KEY_FILE_MAX_BYTES_CHIRHO + 1],
        )
        .unwrap();
        assert!(existing_keypair_pubkey_hex_chirho(&public_overflow_root_chirho).is_err());
        let _ = std::fs::remove_dir_all(public_overflow_root_chirho);

        let private_overflow_root_chirho = tmp_root_chirho();
        sign_message_chirho(&private_overflow_root_chirho, b"provision bounded private").unwrap();
        std::fs::write(
            signing_key_path_chirho(&private_overflow_root_chirho),
            vec![0x42; SIGNING_KEY_BYTES_CHIRHO + 1],
        )
        .unwrap();
        assert!(existing_keypair_pubkey_hex_chirho(&private_overflow_root_chirho).is_err());
        let _ = std::fs::remove_dir_all(private_overflow_root_chirho);

        let directory_root_chirho = tmp_root_chirho();
        std::fs::create_dir_all(&directory_root_chirho).unwrap();
        std::fs::create_dir(signing_key_path_chirho(&directory_root_chirho)).unwrap();
        std::fs::write(pubkey_path_chirho(&directory_root_chirho), "00".repeat(32)).unwrap();
        assert!(existing_keypair_pubkey_hex_chirho(&directory_root_chirho).is_err());
        let _ = std::fs::remove_dir_all(directory_root_chirho);

        let public_directory_root_chirho = tmp_root_chirho();
        sign_message_chirho(
            &public_directory_root_chirho,
            b"provision nonregular public",
        )
        .unwrap();
        std::fs::remove_file(pubkey_path_chirho(&public_directory_root_chirho)).unwrap();
        std::fs::create_dir(pubkey_path_chirho(&public_directory_root_chirho)).unwrap();
        assert!(existing_keypair_pubkey_hex_chirho(&public_directory_root_chirho).is_err());
        let _ = std::fs::remove_dir_all(public_directory_root_chirho);
    }

    #[cfg(unix)]
    #[test]
    fn existing_keypair_refuses_symlinked_private_and_public_files_chirho() {
        use std::os::unix::fs::symlink;

        let private_root_chirho = tmp_root_chirho();
        sign_message_chirho(&private_root_chirho, b"provision private symlink").unwrap();
        let private_target_chirho = private_root_chirho.join("private-target-chirho.bin");
        std::fs::copy(
            signing_key_path_chirho(&private_root_chirho),
            &private_target_chirho,
        )
        .unwrap();
        std::fs::remove_file(signing_key_path_chirho(&private_root_chirho)).unwrap();
        symlink(
            &private_target_chirho,
            signing_key_path_chirho(&private_root_chirho),
        )
        .unwrap();
        assert!(existing_keypair_pubkey_hex_chirho(&private_root_chirho).is_err());
        let _ = std::fs::remove_dir_all(private_root_chirho);

        let public_root_chirho = tmp_root_chirho();
        sign_message_chirho(&public_root_chirho, b"provision public symlink").unwrap();
        let public_target_chirho = public_root_chirho.join("public-target-chirho.hex");
        std::fs::copy(
            pubkey_path_chirho(&public_root_chirho),
            &public_target_chirho,
        )
        .unwrap();
        std::fs::remove_file(pubkey_path_chirho(&public_root_chirho)).unwrap();
        symlink(
            &public_target_chirho,
            pubkey_path_chirho(&public_root_chirho),
        )
        .unwrap();
        assert!(existing_keypair_pubkey_hex_chirho(&public_root_chirho).is_err());
        let _ = std::fs::remove_dir_all(public_root_chirho);
    }

    #[cfg(unix)]
    #[test]
    fn existing_key_reads_refuse_symlinked_roots_and_hardlinked_custody_chirho() {
        use std::os::unix::fs::symlink;

        let target_root_chirho = tmp_root_chirho();
        sign_message_chirho(&target_root_chirho, b"provision root symlink target").unwrap();
        let alias_root_chirho = tmp_root_chirho();
        symlink(&target_root_chirho, &alias_root_chirho).unwrap();
        assert!(existing_pubkey_hex_chirho(&alias_root_chirho).is_err());
        assert!(existing_keypair_pubkey_hex_chirho(&alias_root_chirho).is_err());
        std::fs::remove_file(&alias_root_chirho).unwrap();
        let _ = std::fs::remove_dir_all(target_root_chirho);

        let hardlink_root_chirho = tmp_root_chirho();
        sign_message_chirho(&hardlink_root_chirho, b"provision hardlink custody").unwrap();
        let private_alias_chirho = hardlink_root_chirho.join("private-alias-chirho.bin");
        std::fs::hard_link(
            signing_key_path_chirho(&hardlink_root_chirho),
            &private_alias_chirho,
        )
        .unwrap();
        assert!(existing_keypair_pubkey_hex_chirho(&hardlink_root_chirho).is_err());
        assert!(existing_pubkey_hex_chirho(&hardlink_root_chirho).is_ok());
        std::fs::remove_file(private_alias_chirho).unwrap();

        let public_alias_chirho = hardlink_root_chirho.join("public-alias-chirho.hex");
        std::fs::hard_link(
            pubkey_path_chirho(&hardlink_root_chirho),
            &public_alias_chirho,
        )
        .unwrap();
        assert!(existing_pubkey_hex_chirho(&hardlink_root_chirho).is_err());
        assert!(existing_keypair_pubkey_hex_chirho(&hardlink_root_chirho).is_err());
        let _ = std::fs::remove_dir_all(hardlink_root_chirho);
    }

    #[cfg(unix)]
    #[test]
    fn existing_keypair_enforces_exact_private_and_safe_public_modes_chirho() {
        use std::os::unix::fs::PermissionsExt;

        let root_chirho = tmp_root_chirho();
        sign_message_chirho(&root_chirho, b"provision custody modes").unwrap();
        let private_path_chirho = signing_key_path_chirho(&root_chirho);
        let public_path_chirho = pubkey_path_chirho(&root_chirho);

        for accepted_mode_chirho in [0o400, 0o600] {
            std::fs::set_permissions(
                &private_path_chirho,
                std::fs::Permissions::from_mode(accepted_mode_chirho),
            )
            .unwrap();
            assert!(existing_keypair_pubkey_hex_chirho(&root_chirho).is_ok());
        }
        for rejected_mode_chirho in [0o200, 0o640, 0o700] {
            std::fs::set_permissions(
                &private_path_chirho,
                std::fs::Permissions::from_mode(rejected_mode_chirho),
            )
            .unwrap();
            assert!(existing_keypair_pubkey_hex_chirho(&root_chirho).is_err());
        }

        std::fs::set_permissions(&private_path_chirho, std::fs::Permissions::from_mode(0o600))
            .unwrap();
        for accepted_mode_chirho in [0o400, 0o440, 0o644] {
            std::fs::set_permissions(
                &public_path_chirho,
                std::fs::Permissions::from_mode(accepted_mode_chirho),
            )
            .unwrap();
            assert!(existing_keypair_pubkey_hex_chirho(&root_chirho).is_ok());
        }
        for rejected_mode_chirho in [0o200, 0o744, 0o666] {
            std::fs::set_permissions(
                &public_path_chirho,
                std::fs::Permissions::from_mode(rejected_mode_chirho),
            )
            .unwrap();
            assert!(existing_keypair_pubkey_hex_chirho(&root_chirho).is_err());
        }

        let _ = std::fs::remove_dir_all(root_chirho);
    }

    #[test]
    fn existing_keypair_requires_canonical_lowercase_public_hex_chirho() {
        let root_chirho = tmp_root_chirho();
        sign_message_chirho(&root_chirho, b"provision canonical public").unwrap();
        let public_path_chirho = pubkey_path_chirho(&root_chirho);
        let lowercase_chirho = std::fs::read_to_string(&public_path_chirho).unwrap();
        std::fs::write(&public_path_chirho, lowercase_chirho.to_ascii_uppercase()).unwrap();
        assert!(existing_keypair_pubkey_hex_chirho(&root_chirho).is_err());

        std::fs::write(&public_path_chirho, format!("{lowercase_chirho}\n")).unwrap();
        assert!(existing_keypair_pubkey_hex_chirho(&root_chirho).is_ok());

        let _ = std::fs::remove_dir_all(root_chirho);
    }
    /// A key pair this tool creates must satisfy the checker this tool applies. The public key was
    /// previously written without an explicit mode, so under the common umask 002 it landed
    /// group-writable and `verify_signature_chirho`'s custody check refused it — keygen producing a
    /// key its own verifier rejects. Measured on a real host, where three nodes served normally and
    /// silently never joined raft.
    #[test]
    fn a_freshly_created_public_key_is_not_group_or_other_writable_chirho() {
        use std::os::unix::fs::PermissionsExt;
        let root_chirho = tmp_root_chirho();
        sign_message_chirho(&root_chirho, b"provision-chirho")
            .expect("provision a signing identity");
        let mode_chirho = std::fs::metadata(root_chirho.join(PUBKEY_FILE_CHIRHO))
            .expect("public key exists")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode_chirho & 0o022,
            0,
            "the public key must not be group/other-writable, got {mode_chirho:o} -- anyone able to \
             rewrite it can swap this node's identity, and the verifier refuses such a file"
        );
        assert_eq!(
            mode_chirho, 0o600,
            "the public key should be written with an explicit restrictive mode, not the umask"
        );
    }
}
