// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Stdin/stdout client for the filesystem-custodied test-kind CF7 operator socket.
//!
//! The client has no ledger/elector opener and no network mode. It transports one canonical JSON
//! request to the already-running local winner process and prints one canonical JSON response.

use anyhow::{anyhow, bail, Context, Result};
use cairn_ledger_geo_node_testkind_chirho::{
    send_testkind_cf7_operator_request_chirho, TestkindCf7OperatorOutcomeChirho,
    TestkindCf7OperatorRequestChirho, TestkindCf7OperatorResponseChirho,
};
use cairn_ledger_host_chirho::{
    tenant_migration_destination_intent_digest_chirho,
    tenant_migration_writer_adoption_intent_digest_chirho,
    unsigned_tenant_migration_destination_message_chirho,
    unsigned_tenant_migration_writer_adoption_message_chirho,
    ResidentTestkindLossWitnessPhaseChirho, TenantMigrationDestinationIntentChirho,
    TenantMigrationDestinationRecordChirho, TenantMigrationWriterAdoptionIntentChirho,
    TenantMigrationWriterAdoptionRecordChirho, VerifiedTenantMigrationRootChirho,
    MAX_TENANT_MIGRATION_WRITER_ADOPTION_RECORD_BYTES_CHIRHO,
    TENANT_MIGRATION_DESTINATION_INTENT_DOMAIN_V1_CHIRHO,
    TENANT_MIGRATION_DESTINATION_INTENT_SCHEMA_V1_CHIRHO,
    TENANT_MIGRATION_DESTINATION_RECORD_DOMAIN_V1_CHIRHO,
    TENANT_MIGRATION_DESTINATION_RECORD_SCHEMA_V1_CHIRHO,
    TENANT_MIGRATION_WRITER_ADOPTION_INTENT_DOMAIN_V1_CHIRHO,
    TENANT_MIGRATION_WRITER_ADOPTION_INTENT_SCHEMA_V1_CHIRHO,
    TENANT_MIGRATION_WRITER_ADOPTION_RECORD_DOMAIN_V1_CHIRHO,
    TENANT_MIGRATION_WRITER_ADOPTION_RECORD_SCHEMA_V1_CHIRHO,
};
use cairn_signer_chirho::signer_chirho::existing_keypair_pubkey_hex_chirho;
use rand_core::{OsRng, RngCore};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const USAGE_CHIRHO: &str = "usage: cairn-ledger-geo-node-testkind-operator-chirho <selected-root> [preview-chirho <app> <owner> | execute-chirho <app> <owner> <preview-response.json> | replay-chirho <app> <owner> <execution-response.json> | conservation-read-chirho <execution-response.json> | loss-witness-current-chirho <phase> | loss-witness-sustained-chirho <phase> | loss-witness-deposed-sink-chirho <phase>]\nlegacy: cairn-ledger-geo-node-testkind-operator-chirho <selected-root> < canonical-request.json | migration-authorize-destination-chirho <target-root> <ed25519-seed-hex-file> <revision> (LOCAL, destination authority) | migration-authorize-writer-adoption-chirho <target-root> <destination-record.json> <activation-secret-name> <activation-principal> <storage-namespace> <journal-path> <cluster-id> <opening-epoch> (LOCAL, activation authority) | migration-begin-source-fence-chirho <target-root> <destination-record.json> [writer-adoption-record.json] | migration-activate-target-chirho <target-root>";
const MAX_REQUEST_PAYLOAD_BYTES_CHIRHO: usize = 64 * 1024;
const MAX_DESTINATION_RECORD_BYTES_CHIRHO: usize = 16 * 1024;
const VERSION_LINE_CHIRHO: &str = cairn_build_identity_chirho::version_line_chirho!(
    "cairn-ledger-geo-node-testkind-operator-chirho"
);

fn main() -> Result<()> {
    let mut args_chirho = std::env::args_os();
    let _program_chirho = args_chirho.next();
    let first_arg_chirho = args_chirho.next();
    if cairn_build_identity_chirho::is_version_request_chirho(
        first_arg_chirho
            .as_ref()
            .and_then(|arg_chirho| arg_chirho.to_str()),
    ) {
        println!("{VERSION_LINE_CHIRHO}");
        return Ok(());
    }
    let selected_root_chirho = first_arg_chirho
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!(USAGE_CHIRHO))?;
    let command_args_chirho = args_chirho.collect::<Vec<_>>();
    // A LOCAL-ONLY subcommand, deliberately handled before any request is built. Minting a
    // destination authorization is not something to ask the node to do: the whole point of the
    // authority port is that it verifies and cannot sign, so a node that could mint its own
    // destination would be authorizing its own migration. This runs on the operator's side, with
    // the operator's key, and its output is a file the operator then hands to the winner.
    if let [command_chirho, rest_chirho @ ..] = command_args_chirho.as_slice() {
        if command_chirho == "migration-authorize-destination-chirho" {
            return authorize_destination_chirho(&selected_root_chirho, rest_chirho);
        }
        if command_chirho == "migration-authorize-writer-adoption-chirho" {
            return authorize_writer_adoption_chirho(&selected_root_chirho, rest_chirho);
        }
    }
    let request_chirho = if command_args_chirho.is_empty() {
        read_canonical_request_from_stdin_chirho()?
    } else {
        request_from_command_chirho(&command_args_chirho)?
    };

    write_response_chirho(send_testkind_cf7_operator_request_chirho(
        &selected_root_chirho,
        &request_chirho,
    )?)
}

fn read_canonical_request_from_stdin_chirho() -> Result<TestkindCf7OperatorRequestChirho> {
    let mut request_bytes_chirho = Vec::new();
    std::io::stdin()
        .take((MAX_REQUEST_PAYLOAD_BYTES_CHIRHO + 2) as u64)
        .read_to_end(&mut request_bytes_chirho)
        .context("read one test-kind CF7 operator request from stdin")?;
    if request_bytes_chirho.len() > MAX_REQUEST_PAYLOAD_BYTES_CHIRHO + 1 {
        bail!("TestkindCf7OperatorRequestTooLargeChirho");
    }
    let request_wire_chirho = request_bytes_chirho
        .strip_suffix(b"\n")
        .ok_or_else(|| anyhow!("TestkindCf7OperatorRequestMissingNewlineChirho"))?;
    if request_wire_chirho.is_empty() || request_wire_chirho.contains(&b'\n') {
        bail!("TestkindCf7OperatorRequestNoncanonicalChirho");
    }
    let request_chirho: TestkindCf7OperatorRequestChirho =
        serde_json::from_slice(request_wire_chirho)
            .context("parse test-kind CF7 operator request")?;
    if serde_json::to_vec(&request_chirho)? != request_wire_chirho {
        bail!("TestkindCf7OperatorRequestNoncanonicalChirho");
    }
    Ok(request_chirho)
}

fn command_text_chirho(argument_chirho: &OsString, label_chirho: &str) -> Result<String> {
    argument_chirho
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("TestkindCf7Operator{label_chirho}Utf8RefusedChirho"))
}

fn read_canonical_json_file_chirho<ValueChirho>(
    path_chirho: &Path,
    maximum_chirho: usize,
    unreadable_identity_chirho: &str,
    malformed_identity_chirho: &str,
) -> Result<ValueChirho>
where
    ValueChirho: DeserializeOwned + Serialize,
{
    let bytes_chirho = std::fs::read(path_chirho).context(unreadable_identity_chirho.to_owned())?;
    if bytes_chirho.len() > maximum_chirho + 1 {
        bail!("{malformed_identity_chirho}");
    }
    let wire_chirho = bytes_chirho.strip_suffix(b"\n").unwrap_or(&bytes_chirho);
    if wire_chirho.is_empty() || wire_chirho.contains(&b'\n') {
        bail!("{malformed_identity_chirho}");
    }
    let value_chirho: ValueChirho =
        serde_json::from_slice(wire_chirho).context(malformed_identity_chirho.to_owned())?;
    if serde_json::to_vec(&value_chirho)? != wire_chirho {
        bail!("{malformed_identity_chirho}");
    }
    Ok(value_chirho)
}

fn read_canonical_response_chirho(path_chirho: &Path) -> Result<TestkindCf7OperatorResponseChirho> {
    let mut response_bytes_chirho = Vec::new();
    std::fs::File::open(path_chirho)
        .with_context(|| format!("open prior operator response {}", path_chirho.display()))?
        .take((MAX_REQUEST_PAYLOAD_BYTES_CHIRHO + 2) as u64)
        .read_to_end(&mut response_bytes_chirho)
        .with_context(|| format!("read prior operator response {}", path_chirho.display()))?;
    if response_bytes_chirho.len() > MAX_REQUEST_PAYLOAD_BYTES_CHIRHO + 1 {
        bail!("TestkindCf7OperatorPriorResponseTooLargeChirho");
    }
    let response_wire_chirho = response_bytes_chirho
        .strip_suffix(b"\n")
        .ok_or_else(|| anyhow!("TestkindCf7OperatorPriorResponseMissingNewlineChirho"))?;
    if response_wire_chirho.is_empty() || response_wire_chirho.contains(&b'\n') {
        bail!("TestkindCf7OperatorPriorResponseNoncanonicalChirho");
    }
    let response_chirho: TestkindCf7OperatorResponseChirho =
        serde_json::from_slice(response_wire_chirho)
            .context("parse prior test-kind CF7 operator response")?;
    if serde_json::to_vec(&response_chirho)? != response_wire_chirho {
        bail!("TestkindCf7OperatorPriorResponseNoncanonicalChirho");
    }
    if response_chirho.schema_chirho != "testkind-cf7-operator-response-v1-chirho" {
        bail!("TestkindCf7OperatorPriorResponseWrongSchemaChirho");
    }
    Ok(response_chirho)
}

fn request_from_command_chirho(
    arguments_chirho: &[OsString],
) -> Result<TestkindCf7OperatorRequestChirho> {
    let mode_chirho = arguments_chirho
        .first()
        .and_then(|argument_chirho| argument_chirho.to_str())
        .ok_or_else(|| anyhow!(USAGE_CHIRHO))?;
    match (mode_chirho, arguments_chirho) {
        ("preview-chirho", [_, app_chirho, owner_chirho]) => {
            Ok(TestkindCf7OperatorRequestChirho::preview_chirho(
                command_text_chirho(app_chirho, "App")?,
                command_text_chirho(owner_chirho, "Owner")?,
            ))
        }
        ("execute-chirho", [_, app_chirho, owner_chirho, response_path_chirho]) => {
            let response_chirho = read_canonical_response_chirho(Path::new(response_path_chirho))?;
            let TestkindCf7OperatorOutcomeChirho::PreviewChirho { preview_chirho } =
                response_chirho.outcome_chirho
            else {
                bail!("TestkindCf7OperatorExpectedPreviewResponseChirho");
            };
            Ok(TestkindCf7OperatorRequestChirho::execute_chirho(
                command_text_chirho(app_chirho, "App")?,
                command_text_chirho(owner_chirho, "Owner")?,
                preview_chirho,
            ))
        }
        ("replay-chirho", [_, app_chirho, owner_chirho, response_path_chirho]) => {
            let response_chirho = read_canonical_response_chirho(Path::new(response_path_chirho))?;
            let TestkindCf7OperatorOutcomeChirho::ExecutedChirho { evidence_chirho } =
                response_chirho.outcome_chirho
            else {
                bail!("TestkindCf7OperatorExpectedExecutionResponseChirho");
            };
            Ok(TestkindCf7OperatorRequestChirho::replay_chirho(
                command_text_chirho(app_chirho, "App")?,
                command_text_chirho(owner_chirho, "Owner")?,
                evidence_chirho,
            ))
        }
        ("conservation-read-chirho", [_, response_path_chirho]) => {
            let response_chirho = read_canonical_response_chirho(Path::new(response_path_chirho))?;
            let TestkindCf7OperatorOutcomeChirho::ExecutedChirho { evidence_chirho } =
                response_chirho.outcome_chirho
            else {
                bail!("TestkindCf7OperatorExpectedExecutionResponseChirho");
            };
            Ok(TestkindCf7OperatorRequestChirho::conservation_read_chirho(
                evidence_chirho.post_compensation_head_chirho,
            ))
        }
        (
            "migration-begin-source-fence-chirho",
            [_, target_root_chirho, record_path_chirho, adoption_path_chirho],
        ) => {
            // The path is a request. The two records are independent authorizations minted by keys
            // that are not this node's: destination authority chooses the target, while activation
            // authority permits writer adoption there. The winner verifies both before fencing.
            // This client checks only that each file parses; asserting more here would claim
            // authority the client does not have.
            let target_root_chirho = target_root_chirho
                .to_str()
                .ok_or_else(|| anyhow!("TestkindCf7OperatorTargetRootNotUtf8Chirho"))?;
            let destination_chirho = read_canonical_json_file_chirho(
                Path::new(record_path_chirho),
                MAX_DESTINATION_RECORD_BYTES_CHIRHO,
                "TestkindCf7OperatorDestinationRecordUnreadableChirho",
                "TestkindCf7OperatorDestinationRecordMalformedChirho",
            )?;
            let writer_adoption_chirho = read_canonical_json_file_chirho(
                Path::new(adoption_path_chirho),
                MAX_TENANT_MIGRATION_WRITER_ADOPTION_RECORD_BYTES_CHIRHO,
                "TestkindCf7OperatorWriterAdoptionRecordUnreadableChirho",
                "TestkindCf7OperatorWriterAdoptionRecordMalformedChirho",
            )?;
            Ok(
                TestkindCf7OperatorRequestChirho::migration_begin_source_fence_with_writer_adoption_chirho(
                    target_root_chirho.to_owned(),
                    destination_chirho,
                    Some(writer_adoption_chirho),
                ),
            )
        }
        ("migration-begin-source-fence-chirho", [_, target_root_chirho, record_path_chirho]) => {
            let target_root_chirho = target_root_chirho
                .to_str()
                .ok_or_else(|| anyhow!("TestkindCf7OperatorTargetRootNotUtf8Chirho"))?;
            let destination_chirho = read_canonical_json_file_chirho(
                Path::new(record_path_chirho),
                MAX_DESTINATION_RECORD_BYTES_CHIRHO,
                "TestkindCf7OperatorDestinationRecordUnreadableChirho",
                "TestkindCf7OperatorDestinationRecordMalformedChirho",
            )?;
            Ok(
                TestkindCf7OperatorRequestChirho::migration_begin_source_fence_chirho(
                    target_root_chirho.to_owned(),
                    destination_chirho,
                ),
            )
        }
        ("migration-activate-target-chirho", [_, target_root_chirho]) => {
            // The client passes a PATH and nothing else. Eligibility is computed on the winner from
            // the target root's own evidence — an operator cannot assert that a root is migratable.
            let target_root_chirho = target_root_chirho
                .to_str()
                .ok_or_else(|| anyhow!("TestkindCf7OperatorTargetRootNotUtf8Chirho"))?;
            Ok(
                TestkindCf7OperatorRequestChirho::migration_activate_target_chirho(
                    target_root_chirho.to_owned(),
                ),
            )
        }
        ("loss-witness-current-chirho", [_, phase_chirho]) => {
            let phase_chirho = loss_witness_phase_chirho(phase_chirho)?;
            Ok(TestkindCf7OperatorRequestChirho::loss_witness_current_chirho(phase_chirho))
        }
        ("loss-witness-sustained-chirho", [_, phase_chirho]) => {
            let phase_chirho = loss_witness_phase_chirho(phase_chirho)?;
            Ok(TestkindCf7OperatorRequestChirho::loss_witness_sustained_chirho(phase_chirho))
        }
        ("loss-witness-deposed-sink-chirho", [_, phase_chirho]) => {
            let phase_chirho = loss_witness_phase_chirho(phase_chirho)?;
            Ok(TestkindCf7OperatorRequestChirho::loss_witness_deposed_sink_chirho(phase_chirho))
        }
        _ => Err(anyhow!(USAGE_CHIRHO)),
    }
}

/// Resolve the one phase coordinate the loss-witness operations accept.
///
/// All three witness roles parse the same coordinate, so the refusal identity lives at exactly one
/// production site; three copies would let one drift while the guard still counted three.
fn loss_witness_phase_chirho(
    phase_chirho: &OsString,
) -> Result<ResidentTestkindLossWitnessPhaseChirho> {
    let phase_chirho = command_text_chirho(phase_chirho, "LossWitnessPhase")?;
    ResidentTestkindLossWitnessPhaseChirho::from_wire_token_chirho(&phase_chirho)
        .ok_or_else(|| anyhow!("TestkindCf8LossWitnessPhaseRefusedChirho"))
}

fn write_response_chirho(response_chirho: TestkindCf7OperatorResponseChirho) -> Result<()> {
    let mut response_bytes_chirho = serde_json::to_vec(&response_chirho)?;
    response_bytes_chirho.push(b'\n');
    std::io::stdout().write_all(&response_bytes_chirho)?;
    Ok(())
}

/// Mint one signed destination authorization for `source-root -> target-root`, locally.
///
/// Binds tenant identity, BOTH root binding digests and a revision, then signs
/// `domain:key-id:intent-digest` — the record's own domain is inside the signed bytes, so a
/// signature over an intent digest cannot be replayed as a signature over a record.
///
/// The key file is the OPERATOR's, never the node's, and the node refuses an authority key equal to
/// its own verifying key. Nothing here is trusted by the winner: it re-derives every field and
/// re-checks the signature against its configured authority before a fence is installed.
fn authorize_destination_chirho(source_root_chirho: &Path, args_chirho: &[OsString]) -> Result<()> {
    let [target_root_chirho, key_path_chirho, revision_chirho] = args_chirho else {
        bail!("usage: <source-root> migration-authorize-destination-chirho <target-root> <ed25519-seed-hex-file> <revision>");
    };
    let revision_chirho: u64 = command_text_chirho(revision_chirho, "revision")?
        .parse()
        .context("TestkindCf7OperatorDestinationRevisionInvalidChirho")?;
    let source_chirho = VerifiedTenantMigrationRootChirho::open_existing_chirho(source_root_chirho)
        .map_err(|refusal_chirho| anyhow!("source root refused: {refusal_chirho:?}"))?;
    let target_chirho =
        VerifiedTenantMigrationRootChirho::open_existing_chirho(Path::new(target_root_chirho))
            .map_err(|refusal_chirho| anyhow!("target root refused: {refusal_chirho:?}"))?;
    let seed_hex_chirho = std::fs::read_to_string(Path::new(key_path_chirho))
        .context("TestkindCf7OperatorAuthorityKeyUnreadableChirho")?;
    let seed_bytes_chirho: [u8; 32] = hex_to_32_chirho(seed_hex_chirho.trim())
        .ok_or_else(|| anyhow!("TestkindCf7OperatorAuthorityKeyMalformedChirho"))?;
    let signing_chirho = ed25519_dalek::SigningKey::from_bytes(&seed_bytes_chirho);
    let authority_key_id_chirho = hex_lower_chirho(signing_chirho.verifying_key().as_bytes());

    let intent_chirho = TenantMigrationDestinationIntentChirho {
        schema_chirho: TENANT_MIGRATION_DESTINATION_INTENT_SCHEMA_V1_CHIRHO.to_owned(),
        digest_domain_chirho: TENANT_MIGRATION_DESTINATION_INTENT_DOMAIN_V1_CHIRHO.to_owned(),
        tenant_id_chirho: source_chirho.tenant_id_chirho().to_owned(),
        source_root_digest_chirho: source_chirho
            .binding_identity_digest_hex_chirho()
            .map_err(|refusal_chirho| anyhow!("source digest refused: {refusal_chirho:?}"))?,
        destination_root_digest_chirho: target_chirho
            .binding_identity_digest_hex_chirho()
            .map_err(|refusal_chirho| anyhow!("target digest refused: {refusal_chirho:?}"))?,
        revision_chirho,
    };
    let intent_digest_chirho = tenant_migration_destination_intent_digest_chirho(&intent_chirho)
        .map_err(|refusal_chirho| anyhow!("intent digest refused: {refusal_chirho:?}"))?;
    let mut record_chirho = TenantMigrationDestinationRecordChirho {
        schema_chirho: TENANT_MIGRATION_DESTINATION_RECORD_SCHEMA_V1_CHIRHO.to_owned(),
        signature_domain_chirho: TENANT_MIGRATION_DESTINATION_RECORD_DOMAIN_V1_CHIRHO.to_owned(),
        intent_chirho,
        intent_digest_chirho,
        authority_key_id_chirho,
        sig_chirho: String::new(),
    };
    let message_chirho = unsigned_tenant_migration_destination_message_chirho(&record_chirho);
    record_chirho.sig_chirho = hex_lower_chirho(
        &ed25519_dalek::Signer::sign(&signing_chirho, message_chirho.as_bytes()).to_bytes(),
    );
    let mut stdout_chirho = std::io::stdout();
    stdout_chirho.write_all(&serde_json::to_vec(&record_chirho)?)?;
    stdout_chirho.write_all(b"\n")?;
    Ok(())
}

/// Resolve the activation authority's signing key from the SOURCE ROOT's own secret store.
///
/// CUSTODY: the seed never becomes a file the operator has to hold. The prior form took a 64-hex
/// seed PATH, which forced whoever ran the ceremony to materialise a second copy of a private key --
/// while the clause-6 foundation had deliberately done the opposite, minting raw bytes straight into
/// `secret-set` and deleting the temporary. `SecretValueChirho` zeroes its bytes on drop, and every
/// refusal below names only the FAILURE MODE: never the value, never the resolved path.
///
/// THREE outcomes, not two. An ABSENT secret and a PRESENT-BUT-WRONG-LENGTH one demand opposite
/// operator actions -- provision it, versus investigate what is stored under that name -- and this
/// repo has already paid for an error that meant both at once.
fn activation_signing_key_from_root_secret_chirho(
    source_root_chirho: &Path,
    activation_secret_name_chirho: &str,
) -> Result<ed25519_dalek::SigningKey> {
    let activation_secret_ref_chirho =
        cairn_secret_chirho::secret_chirho::secret_ref_chirho(activation_secret_name_chirho)
            .map_err(|_error_chirho| {
                anyhow!("TestkindCf7OperatorActivationSecretNameInvalidChirho")
            })?;
    let activation_secret_chirho = cairn_secret_chirho::secret_chirho::resolve_secret_ref_chirho(
        source_root_chirho,
        &activation_secret_ref_chirho,
    )
    .map_err(|_error_chirho| anyhow!("TestkindCf7OperatorActivationSecretUnresolvableChirho"))?;
    // The copy OUT of the zeroizing wrapper is itself secret material: `SecretValueChirho` wipes its
    // own buffer on drop, but a plain `[u8; 32]` lifted from it would not, so the seed would outlive
    // the custody type on the stack. `Zeroizing` restores the property this function claims (found
    // by gpt_chirho reviewing this commit; the same idiom is used by the role-bound signer loader).
    let seed_bytes_chirho: Zeroizing<[u8; 32]> = Zeroizing::new(
        activation_secret_chirho
            .as_bytes_chirho()
            .try_into()
            .map_err(|_error_chirho| {
                anyhow!("TestkindCf7OperatorActivationSecretMalformedChirho")
            })?,
    );
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed_bytes_chirho))
}

/// Mint one activation-authority co-signature for adopting an existing migrated journal.
///
/// The nonce comes from the OS here, never from operator text. Both root digests and both node
/// instance keys are re-derived from the selected roots, while the destination intent digest ties
/// this independent authority to the destination authority's exact record.
fn authorize_writer_adoption_chirho(
    source_root_chirho: &Path,
    args_chirho: &[OsString],
) -> Result<()> {
    let [target_root_chirho, destination_path_chirho, activation_secret_name_chirho, activation_principal_chirho, storage_namespace_chirho, journal_path_chirho, cluster_id_chirho, opening_epoch_chirho] =
        args_chirho
    else {
        bail!("usage: <source-root> migration-authorize-writer-adoption-chirho <target-root> <destination-record.json> <activation-secret-name> <activation-principal> <storage-namespace> <journal-path> <cluster-id> <opening-epoch>");
    };
    let target_path_chirho = Path::new(target_root_chirho);
    let destination_chirho: TenantMigrationDestinationRecordChirho =
        read_canonical_json_file_chirho(
            Path::new(destination_path_chirho),
            MAX_DESTINATION_RECORD_BYTES_CHIRHO,
            "TestkindCf7OperatorDestinationRecordUnreadableChirho",
            "TestkindCf7OperatorDestinationRecordMalformedChirho",
        )?;
    // CUSTODY: the activation seed is resolved from the SOURCE ROOT's own secret store and never
    // becomes a file the operator has to hold. The prior form took a 64-hex seed path, which forced
    // whoever ran the ceremony to materialise a second copy of a private key -- and the clause-6
    // foundation had deliberately done the opposite, minting raw bytes straight into `secret-set`
    // and deleting the temporary. `SecretValueChirho` zeroes its bytes on drop; nothing here writes
    // the seed to argv, stdout, or a refusal string, and the refusal identities name only the
    // FAILURE MODE, never the value and never the resolved path.
    let activation_secret_name_chirho =
        command_text_chirho(activation_secret_name_chirho, "ActivationSecretName")?;
    let signing_chirho = activation_signing_key_from_root_secret_chirho(
        source_root_chirho,
        &activation_secret_name_chirho,
    )?;
    let opening_epoch_chirho: u64 = command_text_chirho(opening_epoch_chirho, "OpeningEpoch")?
        .parse()
        .context("TestkindCf7OperatorWriterAdoptionOpeningEpochInvalidChirho")?;
    let record_chirho = build_writer_adoption_record_chirho(
        source_root_chirho,
        target_path_chirho,
        &destination_chirho,
        &signing_chirho,
        &command_text_chirho(activation_principal_chirho, "ActivationPrincipal")?,
        &command_text_chirho(storage_namespace_chirho, "StorageNamespace")?,
        &command_text_chirho(journal_path_chirho, "JournalPath")?,
        &command_text_chirho(cluster_id_chirho, "ClusterId")?,
        opening_epoch_chirho,
    )?;
    let mut stdout_chirho = std::io::stdout();
    stdout_chirho.write_all(&serde_json::to_vec(&record_chirho)?)?;
    stdout_chirho.write_all(b"\n")?;
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the signed adoption record binds one exact resident-writer coordinate"
)]
fn build_writer_adoption_record_chirho(
    source_root_chirho: &Path,
    target_path_chirho: &Path,
    destination_chirho: &TenantMigrationDestinationRecordChirho,
    signing_chirho: &ed25519_dalek::SigningKey,
    activation_principal_chirho: &str,
    storage_namespace_chirho: &str,
    journal_path_chirho: &str,
    cluster_id_chirho: &str,
    opening_epoch_chirho: u64,
) -> Result<TenantMigrationWriterAdoptionRecordChirho> {
    let source_chirho = VerifiedTenantMigrationRootChirho::open_existing_chirho(source_root_chirho)
        .map_err(|refusal_chirho| anyhow!("source root refused: {refusal_chirho:?}"))?;
    let target_chirho = VerifiedTenantMigrationRootChirho::open_existing_chirho(target_path_chirho)
        .map_err(|refusal_chirho| anyhow!("target root refused: {refusal_chirho:?}"))?;
    let source_root_digest_chirho = source_chirho
        .binding_identity_digest_hex_chirho()
        .map_err(|refusal_chirho| anyhow!("source digest refused: {refusal_chirho:?}"))?;
    let target_root_digest_chirho = target_chirho
        .binding_identity_digest_hex_chirho()
        .map_err(|refusal_chirho| anyhow!("target digest refused: {refusal_chirho:?}"))?;
    let destination_intent_digest_chirho =
        tenant_migration_destination_intent_digest_chirho(&destination_chirho.intent_chirho)
            .map_err(|refusal_chirho| {
                anyhow!("destination intent digest refused: {refusal_chirho:?}")
            })?;
    if destination_chirho.intent_digest_chirho != destination_intent_digest_chirho
        || destination_chirho.intent_chirho.tenant_id_chirho != source_chirho.tenant_id_chirho()
        || destination_chirho.intent_chirho.source_root_digest_chirho != source_root_digest_chirho
        || destination_chirho
            .intent_chirho
            .destination_root_digest_chirho
            != target_root_digest_chirho
    {
        bail!("TestkindCf7OperatorWriterAdoptionDestinationBindingRefusedChirho");
    }
    let activation_key_id_chirho = hex_lower_chirho(signing_chirho.verifying_key().as_bytes());
    if activation_key_id_chirho == destination_chirho.authority_key_id_chirho {
        bail!("TestkindCf7OperatorMigrationAuthorityRolesEqualChirho");
    }
    let mut attempt_nonce_bytes_chirho = [0_u8; 32];
    OsRng.fill_bytes(&mut attempt_nonce_bytes_chirho);
    let intent_chirho = TenantMigrationWriterAdoptionIntentChirho {
        schema_chirho: TENANT_MIGRATION_WRITER_ADOPTION_INTENT_SCHEMA_V1_CHIRHO.to_owned(),
        digest_domain_chirho: TENANT_MIGRATION_WRITER_ADOPTION_INTENT_DOMAIN_V1_CHIRHO.to_owned(),
        tenant_id_chirho: source_chirho.tenant_id_chirho().to_owned(),
        source_root_digest_chirho,
        target_root_digest_chirho,
        destination_intent_digest_chirho,
        destination_revision_chirho: destination_chirho.intent_chirho.revision_chirho,
        source_control_node_id_chirho: existing_keypair_pubkey_hex_chirho(source_root_chirho)
            .context("TestkindCf7OperatorSourceInstanceKeyUnavailableChirho")?,
        target_instance_node_id_chirho: existing_keypair_pubkey_hex_chirho(target_path_chirho)
            .context("TestkindCf7OperatorTargetInstanceKeyUnavailableChirho")?,
        storage_namespace_chirho: storage_namespace_chirho.to_owned(),
        journal_path_chirho: journal_path_chirho.to_owned(),
        cluster_id_chirho: cluster_id_chirho.to_owned(),
        opening_epoch_chirho,
        attempt_nonce_chirho: hex_lower_chirho(&attempt_nonce_bytes_chirho),
    };
    let intent_digest_chirho =
        tenant_migration_writer_adoption_intent_digest_chirho(&intent_chirho)
            .map_err(|refusal_chirho| anyhow!("adoption intent refused: {refusal_chirho:?}"))?;
    let mut record_chirho = TenantMigrationWriterAdoptionRecordChirho {
        schema_chirho: TENANT_MIGRATION_WRITER_ADOPTION_RECORD_SCHEMA_V1_CHIRHO.to_owned(),
        signature_domain_chirho: TENANT_MIGRATION_WRITER_ADOPTION_RECORD_DOMAIN_V1_CHIRHO
            .to_owned(),
        intent_chirho,
        intent_digest_chirho,
        activation_principal_chirho: activation_principal_chirho.to_owned(),
        signature_hex_chirho: String::new(),
    };
    let message_chirho = unsigned_tenant_migration_writer_adoption_message_chirho(&record_chirho);
    record_chirho.signature_hex_chirho = hex_lower_chirho(
        &ed25519_dalek::Signer::sign(signing_chirho, message_chirho.as_bytes()).to_bytes(),
    );
    Ok(record_chirho)
}

fn hex_to_32_chirho(hex_chirho: &str) -> Option<[u8; 32]> {
    if hex_chirho.len() != 64 {
        return None;
    }
    let mut out_chirho = [0u8; 32];
    for (index_chirho, byte_chirho) in out_chirho.iter_mut().enumerate() {
        *byte_chirho =
            u8::from_str_radix(hex_chirho.get(index_chirho * 2..index_chirho * 2 + 2)?, 16).ok()?;
    }
    Some(out_chirho)
}

fn hex_lower_chirho(bytes_chirho: &[u8]) -> String {
    bytes_chirho
        .iter()
        .map(|byte_chirho| format!("{byte_chirho:02x}"))
        .collect()
}

#[cfg(test)]
#[path = "operator-tests-chirho/mod_chirho.rs"]
mod tests_chirho;
