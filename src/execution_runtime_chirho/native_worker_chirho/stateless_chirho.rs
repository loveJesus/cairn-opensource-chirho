// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Signed statelessness attestations for framed native workers.

use super::{
    load_native_program_chirho, materialize_native_executable_chirho, now_ms_chirho,
    run_native_stateless_probe_once_chirho, run_native_stateless_probe_reused_chirho,
    sandbox_status_chirho, NativeProgramSpecChirho, NativeSandboxModeChirho,
    NativeStatelessAttestationRecordChirho, NATIVE_ABI_BYTES_STDIO_FRAMED_CHIRHO,
};
use crate::model_chirho::HashChirho;
use crate::{cas_chirho, seqlog_chirho};
use anyhow::{bail, Context, Result};
use cairn_signer_chirho::signer_chirho;
use serde::de::DeserializeOwned;
use std::path::{Path, PathBuf};
use std::time::Duration;

const NATIVE_STATELESS_ATTESTATION_METHOD_CHIRHO: &str = "framed-repeat-fresh-reuse/v1-chirho";

pub fn attest_native_program_stateless_chirho(
    root_chirho: &Path,
    spec_chirho: &HashChirho,
    probe_input_chirho: &[u8],
) -> Result<NativeStatelessAttestationRecordChirho> {
    let spec_obj_chirho = load_native_program_chirho(root_chirho, spec_chirho)?;
    if spec_obj_chirho.abi_chirho != NATIVE_ABI_BYTES_STDIO_FRAMED_CHIRHO {
        bail!("native stateless attestation requires the framed bytes-stdio ABI");
    }
    if !spec_obj_chirho.capabilities_chirho.is_empty() {
        bail!("native stateless attestation is only for pure framed native executables");
    }
    if probe_input_chirho.is_empty() {
        bail!("native stateless attestation probe must be nonempty");
    }
    if probe_input_chirho.len() > spec_obj_chirho.max_input_bytes_chirho {
        bail!(
            "native stateless probe has {} bytes, over max {}",
            probe_input_chirho.len(),
            spec_obj_chirho.max_input_bytes_chirho
        );
    }
    let sandbox_chirho = sandbox_status_chirho(&spec_obj_chirho);
    if matches!(
        spec_obj_chirho.sandbox_mode_chirho,
        NativeSandboxModeChirho::RequiredSeccompChirho
    ) && !sandbox_chirho.seccomp_enforced_chirho
    {
        bail!(
            "native worker requires seccomp but this platform cannot enforce it: {}",
            sandbox_chirho.reason_chirho
        );
    }
    let executable_path_chirho =
        materialize_native_executable_chirho(root_chirho, spec_chirho, &spec_obj_chirho)?;
    let timeout_chirho = Duration::from_millis(spec_obj_chirho.timeout_ms_chirho);
    let fresh_output_chirho = run_native_stateless_probe_once_chirho(
        &executable_path_chirho,
        &spec_obj_chirho,
        probe_input_chirho,
        timeout_chirho,
    )?;
    let (reused_first_output_chirho, reused_second_output_chirho) =
        run_native_stateless_probe_reused_chirho(
            &executable_path_chirho,
            &spec_obj_chirho,
            probe_input_chirho,
            timeout_chirho,
        )?;
    if fresh_output_chirho != reused_first_output_chirho
        || reused_first_output_chirho != reused_second_output_chirho
    {
        bail!("native framed worker failed stateless repeat-probe attestation");
    }
    let probe_hash_chirho = cas_chirho::add_chirho(root_chirho, probe_input_chirho)?;
    let fresh_output_hash_chirho = cas_chirho::add_chirho(root_chirho, &fresh_output_chirho)?;
    let reused_first_hash_chirho =
        cas_chirho::add_chirho(root_chirho, &reused_first_output_chirho)?;
    let reused_second_hash_chirho =
        cas_chirho::add_chirho(root_chirho, &reused_second_output_chirho)?;
    seqlog_chirho::append_serialized_jsonl_chirho(
        root_chirho,
        &native_stateless_attestations_path_chirho(root_chirho),
        |seq_chirho| {
            let mut record_chirho = NativeStatelessAttestationRecordChirho {
                seq_chirho,
                spec_chirho: spec_chirho.clone(),
                executable_chirho: spec_obj_chirho.executable_chirho.clone(),
                abi_chirho: spec_obj_chirho.abi_chirho.clone(),
                method_chirho: NATIVE_STATELESS_ATTESTATION_METHOD_CHIRHO.to_string(),
                probe_input_chirho: probe_hash_chirho.clone(),
                fresh_output_chirho: fresh_output_hash_chirho.clone(),
                reused_first_output_chirho: reused_first_hash_chirho.clone(),
                reused_second_output_chirho: reused_second_hash_chirho.clone(),
                output_len_chirho: fresh_output_chirho.len(),
                sandbox_chirho: sandbox_chirho.clone(),
                attested_by_chirho: signer_chirho::pubkey_hex_chirho(root_chirho)?,
                at_ms_chirho: now_ms_chirho(),
                sig_chirho: String::new(),
            };
            record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
                root_chirho,
                &stateless_message_chirho(&record_chirho)?,
            )?;
            Ok(record_chirho)
        },
    )
}

pub fn load_native_stateless_attestations_chirho(
    root_chirho: &Path,
) -> Result<Vec<NativeStatelessAttestationRecordChirho>> {
    load_jsonl_chirho(&native_stateless_attestations_path_chirho(root_chirho))
}

pub fn verify_native_stateless_attestations_chirho(root_chirho: &Path) -> Result<usize> {
    let records_chirho = load_native_stateless_attestations_chirho(root_chirho)?;
    for (index_chirho, record_chirho) in records_chirho.iter().enumerate() {
        validate_native_stateless_attestation_record_chirho(
            root_chirho,
            record_chirho,
            index_chirho as u64,
        )?;
    }
    Ok(records_chirho.len())
}

pub(super) fn native_program_has_stateless_attestation_chirho(
    root_chirho: &Path,
    spec_chirho: &HashChirho,
    spec_obj_chirho: &NativeProgramSpecChirho,
) -> Result<bool> {
    if spec_obj_chirho.abi_chirho != NATIVE_ABI_BYTES_STDIO_FRAMED_CHIRHO
        || !spec_obj_chirho.capabilities_chirho.is_empty()
    {
        return Ok(false);
    }
    let records_chirho = load_native_stateless_attestations_chirho(root_chirho)?;
    for (index_chirho, record_chirho) in records_chirho.iter().enumerate() {
        validate_native_stateless_attestation_record_chirho(
            root_chirho,
            record_chirho,
            index_chirho as u64,
        )?;
        if &record_chirho.spec_chirho == spec_chirho
            && record_chirho.executable_chirho == spec_obj_chirho.executable_chirho
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn native_stateless_attestations_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("native-stateless-attestations-chirho.jsonl")
}

fn load_jsonl_chirho<T: DeserializeOwned>(path_chirho: &Path) -> Result<Vec<T>> {
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let text_chirho = std::fs::read_to_string(path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    text_chirho
        .lines()
        .filter(|line_chirho| !line_chirho.trim().is_empty())
        .map(|line_chirho| Ok(serde_json::from_str(line_chirho)?))
        .collect()
}

fn stateless_message_chirho(
    record_chirho: &NativeStatelessAttestationRecordChirho,
) -> Result<Vec<u8>> {
    let mut unsigned_chirho = record_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&unsigned_chirho)?)
}

fn validate_native_stateless_attestation_record_chirho(
    root_chirho: &Path,
    record_chirho: &NativeStatelessAttestationRecordChirho,
    expected_seq_chirho: u64,
) -> Result<()> {
    if record_chirho.seq_chirho != expected_seq_chirho {
        bail!("native stateless attestation seq gap at index {expected_seq_chirho}");
    }
    let spec_chirho = load_native_program_chirho(root_chirho, &record_chirho.spec_chirho)?;
    if spec_chirho.executable_chirho != record_chirho.executable_chirho {
        bail!("native stateless attestation executable does not match spec");
    }
    if record_chirho.abi_chirho != NATIVE_ABI_BYTES_STDIO_FRAMED_CHIRHO
        || spec_chirho.abi_chirho != NATIVE_ABI_BYTES_STDIO_FRAMED_CHIRHO
    {
        bail!("native stateless attestation is only valid for framed ABI specs");
    }
    if !spec_chirho.capabilities_chirho.is_empty() {
        bail!("native stateless attestation is only valid for pure specs");
    }
    if record_chirho.method_chirho != NATIVE_STATELESS_ATTESTATION_METHOD_CHIRHO {
        bail!(
            "unsupported native stateless attestation method '{}'",
            record_chirho.method_chirho
        );
    }
    if record_chirho.attested_by_chirho != signer_chirho::pubkey_hex_chirho(root_chirho)? {
        bail!("native stateless attestation was not signed by this cairn instance");
    }
    for hash_chirho in [
        &record_chirho.probe_input_chirho,
        &record_chirho.fresh_output_chirho,
        &record_chirho.reused_first_output_chirho,
        &record_chirho.reused_second_output_chirho,
    ] {
        let _ = cas_chirho::get_chirho(root_chirho, hash_chirho).with_context(|| {
            format!(
                "native stateless attestation CAS object {} missing",
                hash_chirho.0
            )
        })?;
    }
    if record_chirho.fresh_output_chirho != record_chirho.reused_first_output_chirho
        || record_chirho.reused_first_output_chirho != record_chirho.reused_second_output_chirho
    {
        bail!("native stateless attestation output hashes do not agree");
    }
    let output_chirho = cas_chirho::get_chirho(root_chirho, &record_chirho.fresh_output_chirho)?;
    if output_chirho.len() != record_chirho.output_len_chirho {
        bail!("native stateless attestation output length mismatch");
    }
    let valid_chirho = signer_chirho::verify_with_pubkey_chirho(
        &record_chirho.attested_by_chirho,
        &stateless_message_chirho(record_chirho)?,
        &record_chirho.sig_chirho,
    )?;
    if !valid_chirho {
        bail!("native stateless attestation signature invalid");
    }
    Ok(())
}
