// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! S3-compatible blob-store adapter (Ceph RGW / Garage / MinIO, path-style + SigV4) for the two
//! existing storage seams: `ContentStoreChirho` (verify-on-read content gets — M142 holds on remote
//! reads) and `ReplicationSourceChirho` (raw pull bytes the receiver verifies), plus a push-side
//! mirror that re-hashes every local object BEFORE upload so local corruption never reaches the
//! bucket. The bucket byte-mirrors a store root: `objects-chirho/<2hex>/<62hex>` object keys and
//! allowlisted Gate 1 log names at the root — nothing else may live there, and the listing fails
//! closed on any foreign key. Part of Pillar B (HA-ideal program):
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/pillar-b-storage-read-path-chirho.md`.

use cairn_core_chirho::cas_chirho::hash_chirho;
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_core_chirho::ports_chirho::{
    verify_content_address_chirho, ContentReadChirho, ContentStoreChirho, StoreErrorChirho,
    StoreResultChirho,
};
use cairn_model_gate1_chirho::{GATE1_LOG_ANCHORS_FILE_CHIRHO, GATE1_RING_A_ANCHOR_TARGETS_CHIRHO};
use cairn_replication_chirho::{is_replicable_log_name_chirho, ReplicationSourceChirho};
use std::collections::HashSet;
use std::fmt;

pub mod http_chirho;
pub mod list_xml_chirho;
pub mod sigv4_chirho;

use http_chirho::S3HttpChirho;
use sigv4_chirho::{
    canonical_query_string_chirho, sha256_hex_chirho, sign_request_chirho, SigV4CredsChirho,
    SigV4RequestChirho, EMPTY_PAYLOAD_SHA256_CHIRHO,
};

/// The bucket prefix under which content-addressed objects live — byte-identical to the fs store's
/// on-disk layout, so a bucket is a mirror of a root.
pub const S3_OBJECTS_PREFIX_CHIRHO: &str = "objects-chirho/";

/// Backstop on listing pagination so a hostile endpoint cannot hold a replica in an endless loop.
pub const MAX_LIST_PAGES_CHIRHO: u64 = 100_000;

/// Configuration for one S3-compatible bucket endpoint. `endpoint_chirho` is an origin only
/// (`http(s)://host[:port]`, no path): requests are always path-style (`endpoint/bucket/key`),
/// which both Ceph RGW and Garage accept without DNS wildcards.
pub struct S3BlobStoreConfigChirho {
    pub endpoint_chirho: String,
    pub bucket_chirho: String,
    pub region_chirho: String,
    pub access_key_id_chirho: String,
    pub secret_access_key_chirho: String,
}

/// Credentials never render (R4): both key fields are fixed redaction labels in every `Debug` shape.
impl fmt::Debug for S3BlobStoreConfigChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho
            .debug_struct("S3BlobStoreConfigChirho")
            .field("endpoint_chirho", &self.endpoint_chirho)
            .field("bucket_chirho", &self.bucket_chirho)
            .field("region_chirho", &self.region_chirho)
            .field("access_key_id_chirho", &"[redacted-chirho]")
            .field("secret_access_key_chirho", &"[redacted-chirho]")
            .finish()
    }
}

/// Resolve a REQUIRED secret from a NAMED environment variable, failing closed on an unset or
/// empty value. Error messages carry only the variable's NAME, never any value (R4).
pub fn resolve_required_env_chirho(env_name_chirho: &str) -> anyhow::Result<String> {
    if env_name_chirho.trim().is_empty() {
        anyhow::bail!("credential env var name is empty");
    }
    match std::env::var(env_name_chirho) {
        Ok(value_chirho) if !value_chirho.trim().is_empty() => Ok(value_chirho),
        Ok(_) => anyhow::bail!("credential env var {env_name_chirho} is set but empty"),
        Err(_) => anyhow::bail!("credential env var {env_name_chirho} is not set"),
    }
}

/// The operator-file shape for pointing a bin or drill at a bucket: endpoint coordinates in the
/// clear, credentials ONLY as the NAMES of environment variables — the values never live in a
/// config file (the same posture as the HTTP transport's `resolve_bearer_from_env_chirho`).
#[derive(Clone, Debug, serde::Deserialize)]
pub struct S3OperatorEndpointConfigChirho {
    /// e.g. `http://10.100.0.1:3900` (a WG-mesh Garage node) — never a public endpoint without
    /// explicit L.J. approval.
    pub endpoint_url_chirho: String,
    pub bucket_chirho: String,
    pub region_chirho: String,
    /// NAME of the env var holding the access key id.
    pub access_key_id_env_chirho: String,
    /// NAME of the env var holding the secret access key.
    pub secret_access_key_env_chirho: String,
}

impl S3OperatorEndpointConfigChirho {
    /// Resolve both credential env vars fail-closed and build the adapter.
    pub fn connect_chirho(&self) -> anyhow::Result<S3BlobStoreChirho> {
        let access_key_id_chirho = resolve_required_env_chirho(&self.access_key_id_env_chirho)?;
        let secret_access_key_chirho =
            resolve_required_env_chirho(&self.secret_access_key_env_chirho)?;
        S3BlobStoreChirho::new_chirho(S3BlobStoreConfigChirho {
            endpoint_chirho: self.endpoint_url_chirho.clone(),
            bucket_chirho: self.bucket_chirho.clone(),
            region_chirho: self.region_chirho.clone(),
            access_key_id_chirho,
            secret_access_key_chirho,
        })
        .map_err(|error_chirho| anyhow::anyhow!("build s3 store: {error_chirho}"))
    }
}

/// The adapter: one bucket on one endpoint, speaking path-style S3 with SigV4. Holds credentials
/// privately (no `Debug`); all I/O goes through the hardened blocking transport.
pub struct S3BlobStoreChirho {
    endpoint_chirho: String,
    authority_chirho: String,
    bucket_chirho: String,
    creds_chirho: SigV4CredsChirho,
    http_chirho: S3HttpChirho,
}

impl S3BlobStoreChirho {
    /// Validate the config and build the adapter. Fails closed on a malformed endpoint (scheme
    /// missing, userinfo, path, query), bucket name, region, or empty credentials.
    pub fn new_chirho(config_chirho: S3BlobStoreConfigChirho) -> StoreResultChirho<Self> {
        let endpoint_chirho = config_chirho
            .endpoint_chirho
            .trim_end_matches('/')
            .to_string();
        let authority_chirho = endpoint_chirho
            .strip_prefix("http://")
            .or_else(|| endpoint_chirho.strip_prefix("https://"))
            .ok_or_else(|| {
                StoreErrorChirho::invalid_chirho("s3 endpoint must start with http:// or https://")
            })?
            .to_string();
        if authority_chirho.is_empty() || authority_chirho.contains(['/', '?', '#', '@', ' ']) {
            return Err(StoreErrorChirho::invalid_chirho(
                "s3 endpoint must be an origin only (http(s)://host[:port], no path/userinfo)",
            ));
        }
        let bucket_chirho = config_chirho.bucket_chirho;
        let bucket_ok_chirho = (3..=63).contains(&bucket_chirho.len())
            && bucket_chirho.bytes().all(|byte_chirho| {
                byte_chirho.is_ascii_lowercase()
                    || byte_chirho.is_ascii_digit()
                    || byte_chirho == b'-'
                    || byte_chirho == b'.'
            })
            && !bucket_chirho.starts_with(['-', '.'])
            && !bucket_chirho.ends_with(['-', '.']);
        if !bucket_ok_chirho {
            return Err(StoreErrorChirho::invalid_chirho(
                "s3 bucket name must be 3-63 chars of [a-z0-9.-], not edge-punctuated",
            ));
        }
        let region_ok_chirho = !config_chirho.region_chirho.is_empty()
            && config_chirho.region_chirho.bytes().all(|byte_chirho| {
                byte_chirho.is_ascii_lowercase()
                    || byte_chirho.is_ascii_digit()
                    || byte_chirho == b'-'
            });
        if !region_ok_chirho {
            return Err(StoreErrorChirho::invalid_chirho(
                "s3 region must be non-empty [a-z0-9-]",
            ));
        }
        if config_chirho.access_key_id_chirho.is_empty()
            || config_chirho.secret_access_key_chirho.is_empty()
        {
            return Err(StoreErrorChirho::invalid_chirho(
                "s3 credentials must be non-empty",
            ));
        }
        Ok(Self {
            endpoint_chirho,
            authority_chirho,
            bucket_chirho,
            creds_chirho: SigV4CredsChirho {
                access_key_id_chirho: config_chirho.access_key_id_chirho,
                secret_access_key_chirho: config_chirho.secret_access_key_chirho,
                region_chirho: config_chirho.region_chirho,
            },
            http_chirho: S3HttpChirho::new_chirho(),
        })
    }

    /// The bucket object key for a content address — the fs store's exact sharded layout.
    pub fn object_key_for_addr_chirho(addr_chirho: &HashChirho) -> StoreResultChirho<String> {
        let hex_chirho = &addr_chirho.0;
        let hex_ok_chirho = hex_chirho.len() == 64
            && hex_chirho.bytes().all(|byte_chirho| {
                byte_chirho.is_ascii_hexdigit() && !byte_chirho.is_ascii_uppercase()
            });
        if !hex_ok_chirho {
            return Err(StoreErrorChirho::invalid_chirho(
                "content address must be 64 lowercase hex chars",
            ));
        }
        Ok(format!(
            "{S3_OBJECTS_PREFIX_CHIRHO}{}/{}",
            &hex_chirho[..2],
            &hex_chirho[2..]
        ))
    }

    /// The content address a bucket object key names. The bucket is EXCLUSIVELY a cairn root
    /// mirror, so any foreign or malformed key fails the whole listing closed (R2) — a silent skip
    /// would be a coverage hole the fold verifier only catches later.
    pub fn addr_from_object_key_chirho(key_chirho: &str) -> StoreResultChirho<HashChirho> {
        let foreign_chirho = || {
            StoreErrorChirho::invalid_chirho(format!(
                "s3 listing returned a non-mirror key ({key_chirho:?}); refusing the whole listing"
            ))
        };
        let rest_chirho = key_chirho
            .strip_prefix(S3_OBJECTS_PREFIX_CHIRHO)
            .ok_or_else(foreign_chirho)?;
        let (shard_chirho, tail_chirho) =
            rest_chirho.split_at_checked(2).ok_or_else(foreign_chirho)?;
        let tail_chirho = tail_chirho.strip_prefix('/').ok_or_else(foreign_chirho)?;
        let shape_ok_chirho = shard_chirho.len() == 2
            && tail_chirho.len() == 62
            && shard_chirho
                .bytes()
                .chain(tail_chirho.bytes())
                .all(|byte_chirho| {
                    byte_chirho.is_ascii_hexdigit() && !byte_chirho.is_ascii_uppercase()
                });
        if !shape_ok_chirho {
            return Err(foreign_chirho());
        }
        Ok(HashChirho(format!("{shard_chirho}{tail_chirho}")))
    }

    fn url_for_chirho(&self, path_chirho: &str, canonical_query_chirho: &str) -> String {
        if canonical_query_chirho.is_empty() {
            format!("{}{path_chirho}", self.endpoint_chirho)
        } else {
            format!(
                "{}{path_chirho}?{canonical_query_chirho}",
                self.endpoint_chirho
            )
        }
    }

    fn signed_headers_chirho(
        &self,
        method_chirho: &str,
        path_chirho: &str,
        query_chirho: &[(String, String)],
        payload_sha256_hex_chirho: &str,
    ) -> Vec<(String, String)> {
        let timestamp_chirho = http_chirho::now_amz_timestamp_chirho();
        let signed_chirho = sign_request_chirho(
            &SigV4RequestChirho {
                method_chirho,
                path_chirho,
                query_chirho,
                host_chirho: &self.authority_chirho,
                payload_sha256_hex_chirho,
                amz_timestamp_chirho: &timestamp_chirho,
            },
            &self.creds_chirho,
        );
        vec![
            (
                "Authorization".to_string(),
                signed_chirho.authorization_chirho,
            ),
            ("x-amz-date".to_string(), signed_chirho.x_amz_date_chirho),
            (
                "x-amz-content-sha256".to_string(),
                signed_chirho.x_amz_content_sha256_chirho,
            ),
        ]
    }

    /// Signed GET of one bucket path; the URL query is the byte-identical canonical string that was
    /// signed, so sign-one-thing-send-another cannot happen. `404` is `None`.
    fn get_raw_chirho(
        &self,
        path_chirho: &str,
        query_chirho: &[(String, String)],
    ) -> StoreResultChirho<Option<Vec<u8>>> {
        let canonical_query_chirho = canonical_query_string_chirho(query_chirho);
        let headers_chirho = self.signed_headers_chirho(
            "GET",
            path_chirho,
            query_chirho,
            EMPTY_PAYLOAD_SHA256_CHIRHO,
        );
        self.http_chirho.get_optional_chirho(
            &self.url_for_chirho(path_chirho, &canonical_query_chirho),
            &headers_chirho,
        )
    }

    /// Signed PUT of one bucket object.
    fn put_raw_chirho(&self, path_chirho: &str, bytes_chirho: &[u8]) -> StoreResultChirho<()> {
        let payload_sha_chirho = sha256_hex_chirho(bytes_chirho);
        let headers_chirho =
            self.signed_headers_chirho("PUT", path_chirho, &[], &payload_sha_chirho);
        self.http_chirho.put_chirho(
            &self.url_for_chirho(path_chirho, ""),
            &headers_chirho,
            bytes_chirho,
        )
    }

    fn bucket_object_url_path_chirho(&self, key_chirho: &str) -> String {
        format!("/{}/{key_chirho}", self.bucket_chirho)
    }
}

impl ContentStoreChirho for S3BlobStoreChirho {
    /// Store bytes at their blake3 address (idempotent: same bytes, same key, same content).
    fn put_chirho(&self, bytes_chirho: &[u8]) -> StoreResultChirho<HashChirho> {
        let addr_chirho = hash_chirho(bytes_chirho);
        let key_chirho = Self::object_key_for_addr_chirho(&addr_chirho)?;
        self.put_raw_chirho(
            &self.bucket_object_url_path_chirho(&key_chirho),
            bytes_chirho,
        )?;
        Ok(addr_chirho)
    }
}

impl ContentReadChirho for S3BlobStoreChirho {
    /// Fetch bytes by content address, re-hashing them BEFORE the caller may trust them — the M142
    /// invariant held on remote reads: a tampered or substituted bucket object fails closed here.
    fn get_chirho(&self, addr_chirho: &HashChirho) -> StoreResultChirho<Option<Vec<u8>>> {
        let key_chirho = Self::object_key_for_addr_chirho(addr_chirho)?;
        let Some(bytes_chirho) =
            self.get_raw_chirho(&self.bucket_object_url_path_chirho(&key_chirho), &[])?
        else {
            return Ok(None);
        };
        verify_content_address_chirho(addr_chirho, &bytes_chirho)?;
        Ok(Some(bytes_chirho))
    }
}

impl S3BlobStoreChirho {
    /// The listing loop with an explicit page cap, so tests (and unusual operator tunings) can
    /// exercise the backstop without 100k loopback round-trips; the port impl passes
    /// [`MAX_LIST_PAGES_CHIRHO`]. Fails closed on foreign keys, duplicate keys, a stalled
    /// continuation token, or a page-count blowup — a partial or padded listing must never look
    /// complete.
    pub fn list_object_addrs_with_page_cap_chirho(
        &self,
        page_cap_chirho: u64,
    ) -> StoreResultChirho<Vec<HashChirho>> {
        let bucket_path_chirho = format!("/{}", self.bucket_chirho);
        let mut addrs_chirho: Vec<HashChirho> = Vec::new();
        let mut seen_chirho: HashSet<String> = HashSet::new();
        let mut token_chirho: Option<String> = None;
        for _page_chirho in 0..page_cap_chirho {
            let mut query_chirho = vec![
                ("list-type".to_string(), "2".to_string()),
                ("prefix".to_string(), S3_OBJECTS_PREFIX_CHIRHO.to_string()),
            ];
            if let Some(current_token_chirho) = &token_chirho {
                query_chirho.push((
                    "continuation-token".to_string(),
                    current_token_chirho.clone(),
                ));
            }
            let body_chirho = self
                .get_raw_chirho(&bucket_path_chirho, &query_chirho)?
                .ok_or_else(|| {
                    StoreErrorChirho::backend_chirho("s3 listing: bucket listing returned 404")
                })?;
            let body_text_chirho = String::from_utf8(body_chirho).map_err(|_| {
                StoreErrorChirho::invalid_chirho("s3 listing: response is not UTF-8")
            })?;
            let page_chirho = list_xml_chirho::parse_list_objects_v2_chirho(&body_text_chirho)?;
            for key_chirho in &page_chirho.keys_chirho {
                if !seen_chirho.insert(key_chirho.clone()) {
                    return Err(StoreErrorChirho::invalid_chirho(format!(
                        "s3 listing: duplicate key ({key_chirho:?}); refusing the whole listing"
                    )));
                }
                addrs_chirho.push(Self::addr_from_object_key_chirho(key_chirho)?);
            }
            if !page_chirho.is_truncated_chirho {
                // Deterministic order so a pull is reproducible, mirroring the localfs source.
                addrs_chirho.sort_by(|a_chirho, b_chirho| a_chirho.0.cmp(&b_chirho.0));
                return Ok(addrs_chirho);
            }
            if page_chirho.next_continuation_token_chirho == token_chirho {
                return Err(StoreErrorChirho::invalid_chirho(
                    "s3 listing: continuation token did not advance",
                ));
            }
            token_chirho = page_chirho.next_continuation_token_chirho;
        }
        Err(StoreErrorChirho::invalid_chirho(
            "s3 listing: page-count backstop exceeded",
        ))
    }
}

impl ReplicationSourceChirho for S3BlobStoreChirho {
    /// Every object address the bucket mirror offers, via paginated ListObjectsV2 under the
    /// objects prefix — the capped listing loop under the production page-cap backstop.
    fn list_object_addrs_chirho(&self) -> StoreResultChirho<Vec<HashChirho>> {
        self.list_object_addrs_with_page_cap_chirho(MAX_LIST_PAGES_CHIRHO)
    }

    /// Fetch one object's raw bytes WITHOUT verification — the receiver hash-verifies before
    /// anything lands in a served store (quarantining mismatches), mirroring the localfs source.
    fn fetch_object_chirho(&self, addr_chirho: &HashChirho) -> StoreResultChirho<Option<Vec<u8>>> {
        let key_chirho = Self::object_key_for_addr_chirho(addr_chirho)?;
        self.get_raw_chirho(&self.bucket_object_url_path_chirho(&key_chirho), &[])
    }

    /// Fetch one allowlisted public log by bare name. The allowlist is enforced adapter-side
    /// BEFORE any HTTP, mirroring the localfs source: a signing key, ref, or private file can
    /// never be requested by name (keys and plaintext never replicate).
    fn fetch_named_log_chirho(&self, name_chirho: &str) -> StoreResultChirho<Option<Vec<u8>>> {
        if !is_replicable_log_name_chirho(name_chirho) {
            return Err(StoreErrorChirho::invalid_chirho(format!(
                "replication log name is not an allowlisted public log: {name_chirho}"
            )));
        }
        self.get_raw_chirho(&self.bucket_object_url_path_chirho(name_chirho), &[])
    }
}

/// Schema tag for [`MirrorReportChirho`].
pub const S3_MIRROR_REPORT_SCHEMA_CHIRHO: &str = "s3-mirror-report-v1-chirho";

/// Push-side mirror evidence: schema-tagged counts plus the content addresses of refused corrupt
/// objects (hex only — no paths, no bytes), safe to print or persist as operator evidence.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MirrorReportChirho {
    pub schema_chirho: String,
    pub listed_chirho: u64,
    pub uploaded_chirho: u64,
    pub already_present_chirho: u64,
    pub corrupt_refused_chirho: Vec<String>,
    pub logs_uploaded_chirho: u64,
}

/// Mirror a source root into the bucket: upload every object the bucket lacks and the allowlisted
/// public logs. Every object is re-hashed against its address BEFORE upload (push-side M142, R1) —
/// a corrupt local object is refused and reported, never propagated; verified siblings still
/// upload, and the call then fails closed so the refusal cannot pass silently.
pub fn mirror_source_to_s3_chirho<S>(
    source_chirho: &S,
    s3_chirho: &S3BlobStoreChirho,
) -> StoreResultChirho<MirrorReportChirho>
where
    S: ReplicationSourceChirho + ?Sized,
{
    let existing_chirho: HashSet<String> = s3_chirho
        .list_object_addrs_chirho()?
        .into_iter()
        .map(|addr_chirho| addr_chirho.0)
        .collect();
    let source_addrs_chirho = source_chirho.list_object_addrs_chirho()?;
    let mut report_chirho = MirrorReportChirho {
        schema_chirho: S3_MIRROR_REPORT_SCHEMA_CHIRHO.to_string(),
        listed_chirho: source_addrs_chirho.len() as u64,
        uploaded_chirho: 0,
        already_present_chirho: 0,
        corrupt_refused_chirho: Vec::new(),
        logs_uploaded_chirho: 0,
    };
    for addr_chirho in &source_addrs_chirho {
        if existing_chirho.contains(&addr_chirho.0) {
            report_chirho.already_present_chirho += 1;
            continue;
        }
        let Some(bytes_chirho) = source_chirho.fetch_object_chirho(addr_chirho)? else {
            return Err(StoreErrorChirho::backend_chirho(format!(
                "mirror: source listed {} but did not offer its bytes",
                addr_chirho.0
            )));
        };
        if verify_content_address_chirho(addr_chirho, &bytes_chirho).is_err() {
            report_chirho
                .corrupt_refused_chirho
                .push(addr_chirho.0.clone());
            continue;
        }
        let stored_chirho = s3_chirho.put_chirho(&bytes_chirho)?;
        if &stored_chirho != addr_chirho {
            return Err(StoreErrorChirho::invalid_chirho(format!(
                "mirror: verified object {} stored under address {}",
                addr_chirho.0, stored_chirho.0
            )));
        }
        report_chirho.uploaded_chirho += 1;
    }
    let mut log_names_chirho: Vec<&str> = vec![
        GATE1_LOG_ANCHORS_FILE_CHIRHO,
        cairn_replication_chirho::ref_snapshot_chirho::REF_SNAPSHOT_LOG_FILE_CHIRHO,
    ];
    log_names_chirho.extend_from_slice(&GATE1_RING_A_ANCHOR_TARGETS_CHIRHO);
    for name_chirho in log_names_chirho {
        if let Some(bytes_chirho) = source_chirho.fetch_named_log_chirho(name_chirho)? {
            s3_chirho.put_raw_chirho(
                &s3_chirho.bucket_object_url_path_chirho(name_chirho),
                &bytes_chirho,
            )?;
            report_chirho.logs_uploaded_chirho += 1;
        }
    }
    if !report_chirho.corrupt_refused_chirho.is_empty() {
        let preview_chirho = report_chirho
            .corrupt_refused_chirho
            .iter()
            .take(3)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        return Err(StoreErrorChirho::invalid_chirho(format!(
            "mirror refused {} corrupt local object(s) [{preview_chirho}…]; {} verified object(s) and {} log(s) were still uploaded — repair the source root and re-run",
            report_chirho.corrupt_refused_chirho.len(),
            report_chirho.uploaded_chirho,
            report_chirho.logs_uploaded_chirho
        )));
    }
    Ok(report_chirho)
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    fn config_chirho() -> S3BlobStoreConfigChirho {
        S3BlobStoreConfigChirho {
            endpoint_chirho: "http://127.0.0.1:19000".to_string(),
            bucket_chirho: "cairn-test-bucket-chirho".to_string(),
            region_chirho: "garage".to_string(),
            access_key_id_chirho: "GKTESTAKIDCHIRHO".to_string(),
            secret_access_key_chirho: "SECRETVALUECHIRHO".to_string(),
        }
    }

    #[test]
    fn required_env_resolution_fails_closed_and_names_only_the_var_chirho() {
        // Unique names so parallel tests never race on process-global env state.
        let set_chirho = "CAIRN_S3_TEST_SET_KEY_CHIRHO";
        let empty_chirho = "CAIRN_S3_TEST_EMPTY_KEY_CHIRHO";
        let unset_chirho = "CAIRN_S3_TEST_UNSET_KEY_CHIRHO";
        std::env::set_var(set_chirho, "a-credential-value");
        std::env::set_var(empty_chirho, "  ");
        assert_eq!(
            resolve_required_env_chirho(set_chirho).unwrap(),
            "a-credential-value"
        );
        for (name_chirho, want_chirho) in [
            (empty_chirho, "set but empty"),
            (unset_chirho, "is not set"),
        ] {
            let message_chirho = resolve_required_env_chirho(name_chirho)
                .unwrap_err()
                .to_string();
            assert!(message_chirho.contains(want_chirho), "{message_chirho}");
            assert!(
                !message_chirho.contains("a-credential-value"),
                "{message_chirho}"
            );
        }
        assert!(resolve_required_env_chirho("").is_err());
        std::env::remove_var(set_chirho);
        std::env::remove_var(empty_chirho);
    }

    #[test]
    fn operator_endpoint_config_connects_via_env_names_only_chirho() {
        let id_env_chirho = "CAIRN_S3_TEST_OPERATOR_ID_CHIRHO";
        let secret_env_chirho = "CAIRN_S3_TEST_OPERATOR_SECRET_CHIRHO";
        let operator_chirho: S3OperatorEndpointConfigChirho = serde_json::from_str(&format!(
            r#"{{"endpoint_url_chirho":"http://127.0.0.1:19000",
                 "bucket_chirho":"cairn-test-bucket-chirho",
                 "region_chirho":"garage",
                 "access_key_id_env_chirho":"{id_env_chirho}",
                 "secret_access_key_env_chirho":"{secret_env_chirho}"}}"#
        ))
        .unwrap();
        // Missing env fails closed BEFORE any store is built, naming the var only. (No
        // `unwrap_err`: the store type deliberately has no `Debug` — R4.)
        let message_chirho = match operator_chirho.connect_chirho() {
            Ok(_) => panic!("connect must fail closed when the env var is unset"),
            Err(error_chirho) => error_chirho.to_string(),
        };
        assert!(message_chirho.contains(id_env_chirho), "{message_chirho}");
        std::env::set_var(id_env_chirho, "GKTESTAKIDCHIRHO");
        std::env::set_var(secret_env_chirho, "SECRETVALUECHIRHO");
        assert!(operator_chirho.connect_chirho().is_ok());
        // The config's own Debug never renders credential VALUES (it holds only env NAMES).
        let rendered_chirho = format!("{operator_chirho:?}");
        assert!(
            !rendered_chirho.contains("SECRETVALUECHIRHO"),
            "{rendered_chirho}"
        );
        std::env::remove_var(id_env_chirho);
        std::env::remove_var(secret_env_chirho);
    }

    #[test]
    fn maps_addresses_to_byte_mirror_keys_and_back_chirho() {
        let addr_chirho = hash_chirho(b"stone");
        let key_chirho = S3BlobStoreChirho::object_key_for_addr_chirho(&addr_chirho).unwrap();
        assert!(key_chirho.starts_with(S3_OBJECTS_PREFIX_CHIRHO));
        assert_eq!(
            key_chirho.len(),
            S3_OBJECTS_PREFIX_CHIRHO.len() + 2 + 1 + 62
        );
        assert_eq!(
            S3BlobStoreChirho::addr_from_object_key_chirho(&key_chirho).unwrap(),
            addr_chirho
        );
    }

    #[test]
    fn refuses_foreign_or_malformed_listing_keys_chirho() {
        for key_chirho in [
            "evil.txt",
            "objects-chirho/ab",
            "objects-chirho/ab/short",
            "objects-chirho/zz/GG…",
            "objects-chirho/ab/../secret",
            "signing-key-chirho.bin",
        ] {
            assert!(
                S3BlobStoreChirho::addr_from_object_key_chirho(key_chirho).is_err(),
                "should refuse: {key_chirho}"
            );
        }
        let upper_chirho = format!("{S3_OBJECTS_PREFIX_CHIRHO}AB/{}", "c".repeat(62));
        assert!(S3BlobStoreChirho::addr_from_object_key_chirho(&upper_chirho).is_err());
    }

    #[test]
    fn validates_endpoint_bucket_region_and_creds_chirho() {
        assert!(S3BlobStoreChirho::new_chirho(config_chirho()).is_ok());
        for (mutate_chirho, label_chirho) in [
            (
                Box::new(|config_chirho: &mut S3BlobStoreConfigChirho| {
                    config_chirho.endpoint_chirho = "127.0.0.1:19000".to_string()
                }) as Box<dyn Fn(&mut S3BlobStoreConfigChirho)>,
                "schemeless endpoint",
            ),
            (
                Box::new(|config_chirho: &mut S3BlobStoreConfigChirho| {
                    config_chirho.endpoint_chirho = "http://host/path".to_string()
                }),
                "endpoint with path",
            ),
            (
                Box::new(|config_chirho: &mut S3BlobStoreConfigChirho| {
                    config_chirho.endpoint_chirho = "http://user@host".to_string()
                }),
                "endpoint with userinfo",
            ),
            (
                Box::new(|config_chirho: &mut S3BlobStoreConfigChirho| {
                    config_chirho.bucket_chirho = "Bad_Bucket".to_string()
                }),
                "bucket charset",
            ),
            (
                Box::new(|config_chirho: &mut S3BlobStoreConfigChirho| {
                    config_chirho.region_chirho = String::new()
                }),
                "empty region",
            ),
            (
                Box::new(|config_chirho: &mut S3BlobStoreConfigChirho| {
                    config_chirho.secret_access_key_chirho = String::new()
                }),
                "empty secret",
            ),
        ] {
            let mut bad_chirho = config_chirho();
            mutate_chirho(&mut bad_chirho);
            assert!(
                S3BlobStoreChirho::new_chirho(bad_chirho).is_err(),
                "should refuse: {label_chirho}"
            );
        }
    }

    /// R4: the credential fields render only as fixed redaction labels.
    #[test]
    fn debug_shape_redacts_credentials_chirho() {
        let rendered_chirho = format!("{:?}", config_chirho());
        assert!(rendered_chirho.contains("[redacted-chirho]"));
        assert!(!rendered_chirho.contains("SECRETVALUECHIRHO"));
        assert!(!rendered_chirho.contains("GKTESTAKIDCHIRHO"));
    }
}
