// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Probes the credential lock at real login checkpoints without timing-dependent absence claims.

use super::*;
use std::cell::RefCell;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LoginProbePointChirho {
    ProofChirho,
    AppendedChirho,
}

type LoginProbeHookChirho = Box<dyn Fn(LoginProbePointChirho) -> Result<()>>;

std::thread_local! {
    static LOGIN_PROBE_HOOK_CHIRHO: RefCell<Option<LoginProbeHookChirho>> = RefCell::new(None);
}

pub(super) fn observe_login_chirho(point_chirho: LoginProbePointChirho) -> Result<()> {
    LOGIN_PROBE_HOOK_CHIRHO.with(|hook_chirho| match hook_chirho.borrow().as_ref() {
        Some(hook_chirho) => hook_chirho(point_chirho),
        None => Ok(()),
    })
}

fn credential_lock_is_held_chirho(path_chirho: &Path) -> Result<bool> {
    let file_chirho = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path_chirho)?;
    match file_chirho.try_lock() {
        Ok(()) => Ok(false),
        Err(std::fs::TryLockError::WouldBlock) => Ok(true),
        Err(error_chirho) => Err(anyhow!("nonblocking credential lock probe: {error_chirho}")),
    }
}

#[test]
fn login_holds_credential_lock_at_proof_and_append_chirho() {
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-login-lock-probe-{}-{}-chirho",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let user_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        "first-secret-value",
    )
    .unwrap();
    let principal_chirho = user_chirho.principal_chirho;
    let lock_name_chirho = credential_lock_name_chirho(&principal_chirho);
    seqlog_chirho::with_named_lock_chirho(&root_chirho, &lock_name_chirho, || Ok(())).unwrap();
    let lock_path_chirho = root_chirho.join("locks-chirho").join(format!(
        "{}.lock",
        blake3::hash(lock_name_chirho.as_bytes()).to_hex()
    ));
    assert!(!credential_lock_is_held_chirho(&lock_path_chirho).unwrap());

    let (point_sender_chirho, point_receiver_chirho) = std::sync::mpsc::channel();
    let (resume_sender_chirho, resume_receiver_chirho) = std::sync::mpsc::channel();
    let root_for_worker_chirho = root_chirho.clone();
    let principal_for_worker_chirho = principal_chirho.clone();
    let worker_chirho = std::thread::spawn(move || {
        LOGIN_PROBE_HOOK_CHIRHO.with(|hook_chirho| {
            *hook_chirho.borrow_mut() = Some(Box::new(move |point_chirho| {
                point_sender_chirho.send(point_chirho)?;
                resume_receiver_chirho.recv_timeout(Duration::from_secs(10))?;
                Ok(())
            }));
        });
        login_identity_with_credential_chirho(
            &root_for_worker_chirho,
            &principal_for_worker_chirho,
            "first-secret-value",
        )
    });

    let observations_chirho = (|| -> Result<Vec<(LoginProbePointChirho, bool)>> {
        let mut observations_chirho = Vec::new();
        for _ in 0..2 {
            let point_chirho = point_receiver_chirho.recv_timeout(Duration::from_secs(10))?;
            let held_chirho = credential_lock_is_held_chirho(&lock_path_chirho)?;
            observations_chirho.push((point_chirho, held_chirho));
            resume_sender_chirho.send(())?;
        }
        Ok(observations_chirho)
    })();
    // Dropping the resume sender releases an interrupted worker through the hook's error path.
    drop(resume_sender_chirho);
    let login_chirho = worker_chirho.join().unwrap();
    let observations_chirho = observations_chirho.unwrap();
    let login_chirho = login_chirho.unwrap();
    assert_eq!(
        observations_chirho,
        vec![
            (LoginProbePointChirho::ProofChirho, true),
            (LoginProbePointChirho::AppendedChirho, true),
        ],
        "the credential lock must exclude another writer at proof and session append"
    );
    assert!(!credential_lock_is_held_chirho(&lock_path_chirho).unwrap());

    reset_identity_credential_chirho(
        &root_chirho,
        &principal_chirho,
        "second-secret-value",
        &principal_chirho,
        "audit-login-lock-reset-chirho",
    )
    .unwrap();
    assert!(session_is_revoked_chirho(
        &root_chirho,
        &signer_chirho::pubkey_hex_chirho(&root_chirho).unwrap(),
        &login_chirho.session_chirho,
    )
    .unwrap());
    assert!(validate_session_token_chirho(
        &root_chirho,
        &principal_chirho,
        &login_chirho.token_chirho
    )
    .unwrap()
    .is_none());
    let fresh_chirho = login_identity_with_credential_chirho(
        &root_chirho,
        &principal_chirho,
        "second-secret-value",
    )
    .unwrap();
    assert!(validate_session_token_chirho(
        &root_chirho,
        &principal_chirho,
        &fresh_chirho.token_chirho
    )
    .unwrap()
    .is_some());
    std::fs::remove_dir_all(&root_chirho).unwrap();
}
