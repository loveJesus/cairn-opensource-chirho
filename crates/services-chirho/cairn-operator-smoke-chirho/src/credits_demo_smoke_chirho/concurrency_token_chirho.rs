// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Read-only derivation of the credits-demo spend concurrency token.
//!
//! Both the LocalPhaseB smoke preflight and the operator command call this module. The bounded
//! provider read verifies custody, schema, cardinality, and the exact seeded coordinate/value
//! before deriving the keyed row fingerprint. It has no provider-write or intent-recovery surface.

use anyhow::{bail, Context, Result};
use cairn_chirho::model_chirho::HashChirho;
use cairn_postgres_effect_chirho::crypto_chirho::{
    row_fingerprint_chirho, AdapterEvidenceKeyChirho,
};
use cairn_postgres_effect_chirho::ports_chirho::ReversiblePostgresDatabasePortChirho;
use postgres::Row;
use std::path::Path;

use super::constants_chirho;
use super::setup_chirho::{connect_pg_chirho, resolve_secret_string_chirho};

pub const CONCURRENCY_TOKEN_CUSTODY_REFUSAL_CHIRHO: &str =
    "CreditsDemoConcurrencyTokenCustodyUnavailableChirho";
pub const CONCURRENCY_TOKEN_PROVIDER_REFUSAL_CHIRHO: &str =
    "CreditsDemoConcurrencyTokenProviderUnavailableChirho";
pub const CONCURRENCY_TOKEN_SCHEMA_REFUSAL_CHIRHO: &str =
    "CreditsDemoConcurrencyTokenSchemaRefusedChirho";
pub const CONCURRENCY_TOKEN_ROW_COUNT_REFUSAL_CHIRHO: &str =
    "CreditsDemoConcurrencyTokenRowCountRefusedChirho";
pub const CONCURRENCY_TOKEN_BINDING_REFUSAL_CHIRHO: &str =
    "CreditsDemoConcurrencyTokenBindingRefusedChirho";

pub struct CreditsDemoConcurrencyTokenRequestChirho<'request_chirho> {
    pub root_chirho: &'request_chirho Path,
    pub connection_secret_name_chirho: &'request_chirho str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CreditsDemoSeedRowChirho {
    pub subject_chirho: String,
    pub row_key_chirho: String,
    pub value_chirho: Vec<u8>,
}

impl CreditsDemoSeedRowChirho {
    fn from_postgres_row_chirho(row_chirho: &Row) -> Self {
        Self {
            subject_chirho: row_chirho.get("subject_chirho"),
            row_key_chirho: row_chirho.get("row_key_chirho"),
            value_chirho: row_chirho.get("value_chirho"),
        }
    }
}

/// Operator entrypoint. Resolving the named DSN is a custody read; the only emitted value is the
/// token returned by the shared smoke/operator derivation below.
pub fn read_credits_demo_concurrency_token_chirho(
    request_chirho: &CreditsDemoConcurrencyTokenRequestChirho<'_>,
) -> Result<String> {
    let dsn_chirho = resolve_secret_string_chirho(
        request_chirho.root_chirho,
        request_chirho.connection_secret_name_chirho,
    )
    .map_err(|error_chirho| {
        anyhow::anyhow!(
            "{CONCURRENCY_TOKEN_CUSTODY_REFUSAL_CHIRHO}: PostgreSQL connection custody refused: {error_chirho}"
        )
    })?;
    read_credits_demo_concurrency_token_from_dsn_chirho(&dsn_chirho, request_chirho.root_chirho)
}

/// The ONE production token derivation. Smoke preflight and the read-only operator command both
/// enter here, so key rotation or row-fingerprint changes cannot split their money predicate.
pub(super) fn read_credits_demo_concurrency_token_from_dsn_chirho(
    dsn_chirho: &str,
    root_chirho: &Path,
) -> Result<String> {
    let adapter_key_chirho = load_adapter_evidence_key_chirho(root_chirho)?;
    let client_chirho = connect_pg_chirho(dsn_chirho).map_err(|error_chirho| {
        anyhow::anyhow!(
            "{CONCURRENCY_TOKEN_PROVIDER_REFUSAL_CHIRHO}: sanctioned PostgreSQL read unavailable: {error_chirho}"
        )
    })?;
    let mut database_chirho =
        cairn_postgres_effect_chirho::postgres_driver_chirho::PostgresDatabaseChirho::from_client_chirho(
            client_chirho,
        );
    database_chirho
        .verify_schema_ready_chirho()
        .map_err(|error_chirho| {
            anyhow::anyhow!(
                "{CONCURRENCY_TOKEN_SCHEMA_REFUSAL_CHIRHO}: adapter schema verifier refused: {error_chirho:?}"
            )
        })?;
    let mut client_chirho = database_chirho.into_client_chirho();

    // LIMIT 2 proves the exact-one law without scanning a growing provider table.
    let rows_chirho = client_chirho
        .query(
            "SELECT subject_chirho, row_key_chirho, value_chirho \
             FROM cairn_reversible_values_chirho \
             ORDER BY subject_chirho, row_key_chirho LIMIT 2",
            &[],
        )
        .map_err(|error_chirho| {
            anyhow::anyhow!(
                "{CONCURRENCY_TOKEN_SCHEMA_REFUSAL_CHIRHO}: seeded-row read refused: {error_chirho}"
            )
        })?
        .iter()
        .map(CreditsDemoSeedRowChirho::from_postgres_row_chirho)
        .collect::<Vec<_>>();

    derive_credits_demo_concurrency_token_from_rows_chirho(&adapter_key_chirho, &rows_chirho)
}

pub(super) fn derive_credits_demo_concurrency_token_from_rows_chirho(
    adapter_key_chirho: &AdapterEvidenceKeyChirho,
    rows_chirho: &[CreditsDemoSeedRowChirho],
) -> Result<String> {
    if rows_chirho.len() != 1 {
        bail!(
            "{CONCURRENCY_TOKEN_ROW_COUNT_REFUSAL_CHIRHO}: expected exactly one provider value row, observed {}{}",
            rows_chirho.len(),
            if rows_chirho.len() == 2 {
                " or more"
            } else {
                ""
            }
        );
    }
    let row_chirho = &rows_chirho[0];
    if row_chirho.subject_chirho != constants_chirho::FIXED_SUBJECT_CHIRHO {
        bail!(
            "{CONCURRENCY_TOKEN_BINDING_REFUSAL_CHIRHO}: sole row subject does not bind the reviewed credits-demo subject"
        );
    }
    if row_chirho.row_key_chirho != constants_chirho::FIXED_ROW_KEY_CHIRHO {
        bail!(
            "{CONCURRENCY_TOKEN_BINDING_REFUSAL_CHIRHO}: sole row key does not bind the reviewed credits-demo row"
        );
    }
    if row_chirho.value_chirho != constants_chirho::SEED_VALUE_CHIRHO {
        bail!(
            "{CONCURRENCY_TOKEN_BINDING_REFUSAL_CHIRHO}: sole row value does not match the reviewed seed value"
        );
    }

    Ok(row_fingerprint_chirho(
        adapter_key_chirho,
        &HashChirho(row_chirho.subject_chirho.clone()),
        &HashChirho(row_chirho.row_key_chirho.clone()),
        &row_chirho.value_chirho,
    )
    .0)
}

pub(super) fn load_adapter_evidence_key_chirho(
    root_chirho: &Path,
) -> Result<AdapterEvidenceKeyChirho> {
    let secret_chirho = cairn_chirho::secret_chirho::resolve_secret_ref_chirho(
        root_chirho,
        &cairn_chirho::secret_chirho::secret_ref_chirho(
            constants_chirho::ADAPTER_EVIDENCE_SECRET_NAME_CHIRHO,
        )
        .map_err(|error_chirho| {
            anyhow::anyhow!(
                "{CONCURRENCY_TOKEN_CUSTODY_REFUSAL_CHIRHO}: adapter evidence secret name refused: {error_chirho}"
            )
        })?,
    )
    .map_err(|error_chirho| {
        anyhow::anyhow!(
            "{CONCURRENCY_TOKEN_CUSTODY_REFUSAL_CHIRHO}: adapter evidence key unavailable: {error_chirho}"
        )
    })?;
    let bytes_chirho: [u8; 32] =
        secret_chirho
            .as_bytes_chirho()
            .try_into()
            .map_err(|_error_chirho| {
                anyhow::anyhow!(
                "{CONCURRENCY_TOKEN_CUSTODY_REFUSAL_CHIRHO}: adapter evidence key was not 32 bytes"
            )
            })?;
    AdapterEvidenceKeyChirho::new_chirho(bytes_chirho)
        .context(CONCURRENCY_TOKEN_CUSTODY_REFUSAL_CHIRHO)
}
