// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! CF7 R-2: run the authored balance-read shape on a replica.
//!
//! The Query boundary is deliberately represented by one concrete R-1 port rather than a
//! dispatcher or an effect-handler registry. The two surrounding DAG segments are delegated to
//! the pure executor, which refuses any capability-bearing or native node before executing one.
//! Consequently adding a write/send/native handler requires changing this type's API and its P3
//! dependency surface; there is no node-name allowlist to widen accidentally.

use anyhow::{bail, Result};
use cairn_core_chirho::model_chirho::{DagChirho, HashChirho};
use cairn_core_chirho::ports_chirho::ContentReadChirho;
use cairn_pure_executor_chirho::{run_pure_dag_chirho, PureDagOutcomeChirho};
use serde::{Deserialize, Serialize};

use crate::projection_replication_chirho::{
    ReplicaMountedProjectionReadChirho, ReplicaMountedProjectionReadPortChirho,
    ReplicaProjectionMountCoordinateChirho,
};

/// The only Query scope admitted by the replica balance-read runner.
pub const BALANCE_QUERY_SCOPE_CHIRHO: &str = "credits-balance-chirho";
/// The authored Query node's fixed bounded limit.
pub const BALANCE_QUERY_LIMIT_CHIRHO: u64 = 1;
/// The pure executor's bounded output cap for each authored segment.
pub const BALANCE_DAG_OUTPUT_CAP_CHIRHO: usize = 64 * 1024;

/// The authored DAG split at its one blessed Query node. Neither segment may contain an effect or
/// native node: the pure executor checks that property before running either segment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicaBalanceReadDagChirho {
    pub before_query_dag_chirho: Option<DagChirho>,
    pub after_query_dag_chirho: Option<DagChirho>,
    /// The source-published expected hash for the final pure output.
    pub expected_output_hash_chirho: HashChirho,
}

/// A refusal is an expected 404-shaped result, not an executor fault. The node hash is retained so
/// operator evidence identifies the refused capability without exposing a new execution door.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplicaReadDagRefusalChirho {
    EffectNodeChirho { node_chirho: HashChirho },
    NativeNodeChirho { node_chirho: HashChirho },
}

impl ReplicaReadDagRefusalChirho {
    /// The replica surface maps every authority refusal to the same not-found response.
    pub const fn http_status_chirho(&self) -> u16 {
        404
    }
}

/// The successful served result, including the R-1 Degraded evidence and the bound output hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplicaBalanceReadResultChirho {
    pub bytes_chirho: Vec<u8>,
    pub output_hash_chirho: HashChirho,
    pub projection_read_chirho: ReplicaMountedProjectionReadChirho,
}

/// The only data permitted to cross into the replica HTML serve boundary. Account rows and
/// canonical view bytes remain inside the verified read-DAG runner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplicaBalancePageViewChirho {
    pub output_hash_chirho: HashChirho,
    pub lag_ms_chirho: u64,
    pub max_lag_ms_chirho: u64,
}

/// R-2's fixed admission surface. There is exactly one effect-capable field, and it is the
/// concrete R-1 projection-read port. No generic effect dispatcher can be supplied.
pub struct ReplicaBalanceReadDagRunnerChirho {
    projection_read_port_chirho: ReplicaMountedProjectionReadPortChirho,
    pinned_mount_coordinate_chirho: Option<ReplicaProjectionMountCoordinateChirho>,
}

fn bind_published_output_hash_chirho(
    bytes_chirho: &[u8],
    expected_output_hash_chirho: &HashChirho,
) -> Result<HashChirho> {
    let output_hash_chirho = HashChirho(blake3::hash(bytes_chirho).to_hex().to_string());
    if &output_hash_chirho != expected_output_hash_chirho {
        bail!("ReplicaPublishedOutputHashMismatchChirho");
    }
    Ok(output_hash_chirho)
}

impl ReplicaBalanceReadDagRunnerChirho {
    pub fn new_chirho(projection_read_port_chirho: ReplicaMountedProjectionReadPortChirho) -> Self {
        Self {
            projection_read_port_chirho,
            pinned_mount_coordinate_chirho: None,
        }
    }

    pub fn new_pinned_chirho(
        projection_read_port_chirho: ReplicaMountedProjectionReadPortChirho,
        pinned_mount_coordinate_chirho: ReplicaProjectionMountCoordinateChirho,
    ) -> Self {
        Self {
            projection_read_port_chirho,
            pinned_mount_coordinate_chirho: Some(pinned_mount_coordinate_chirho),
        }
    }

    pub fn pinned_mount_coordinate_chirho(
        &self,
    ) -> Option<&ReplicaProjectionMountCoordinateChirho> {
        self.pinned_mount_coordinate_chirho.as_ref()
    }

    pub fn current_mount_coordinate_chirho(
        &self,
    ) -> Result<ReplicaProjectionMountCoordinateChirho> {
        self.projection_read_port_chirho
            .current_mount_coordinate_chirho()
    }

    /// The production replica page has no authored transform: its bytes are the verified mounted
    /// projection, and the feeder-signed receipt supplies their expected digest. Workflow:
    /// `spec-chirho/workflows-chirho/distributed-ha-chirho/b2-replica-serve-design-chirho.md` §10.
    pub fn direct_verified_mount_dag_chirho(
        coordinate_chirho: &ReplicaProjectionMountCoordinateChirho,
    ) -> ReplicaBalanceReadDagChirho {
        ReplicaBalanceReadDagChirho {
            before_query_dag_chirho: None,
            after_query_dag_chirho: None,
            expected_output_hash_chirho: HashChirho(
                coordinate_chirho.view_digest_hex_chirho.clone(),
            ),
        }
    }

    pub fn run_page_chirho(
        &self,
        store_chirho: &dyn ContentReadChirho,
        dag_chirho: &ReplicaBalanceReadDagChirho,
        input_bytes_chirho: &[u8],
    ) -> Result<std::result::Result<ReplicaBalancePageViewChirho, ReplicaReadDagRefusalChirho>>
    {
        match self.run_chirho(store_chirho, dag_chirho, input_bytes_chirho)? {
            Ok(result_chirho) => Ok(Ok(ReplicaBalancePageViewChirho {
                output_hash_chirho: result_chirho.output_hash_chirho,
                lag_ms_chirho: result_chirho.projection_read_chirho.lag_ms_chirho,
                max_lag_ms_chirho: result_chirho.projection_read_chirho.max_lag_ms_chirho,
            })),
            Err(refusal_chirho) => Ok(Err(refusal_chirho)),
        }
    }

    /// Run the authored pure/query/pure shape and bind its final bytes to the published hash.
    pub(crate) fn run_chirho(
        &self,
        store_chirho: &dyn ContentReadChirho,
        dag_chirho: &ReplicaBalanceReadDagChirho,
        input_bytes_chirho: &[u8],
    ) -> Result<std::result::Result<ReplicaBalanceReadResultChirho, ReplicaReadDagRefusalChirho>>
    {
        let query_input_chirho = match dag_chirho.before_query_dag_chirho.as_ref() {
            Some(before_query_dag_chirho) => {
                match run_pure_dag_chirho(
                    store_chirho,
                    before_query_dag_chirho,
                    input_bytes_chirho,
                    BALANCE_DAG_OUTPUT_CAP_CHIRHO,
                )? {
                    PureDagOutcomeChirho::PayloadChirho { bytes_chirho, .. } => bytes_chirho,
                    PureDagOutcomeChirho::RefusedEffectfulChirho { node_chirho } => {
                        return Ok(Err(ReplicaReadDagRefusalChirho::EffectNodeChirho {
                            node_chirho,
                        }))
                    }
                    PureDagOutcomeChirho::RefusedNativeChirho { node_chirho } => {
                        return Ok(Err(ReplicaReadDagRefusalChirho::NativeNodeChirho {
                            node_chirho,
                        }))
                    }
                }
            }
            None => input_bytes_chirho.to_vec(),
        };

        // The Query request is authored, not caller-selected. Its bytes are evaluated by the
        // preceding pure segment only to preserve the DAG's dataflow; the fixed contract below is
        // the sole admission door and cannot be replaced with another capability.
        let _query_input_chirho = query_input_chirho;
        let projection_read_chirho = self
            .projection_read_port_chirho
            .read_published_projection_chirho(
                BALANCE_QUERY_SCOPE_CHIRHO,
                BALANCE_QUERY_LIMIT_CHIRHO,
            )?;
        if let Some(pinned_mount_coordinate_chirho) = &self.pinned_mount_coordinate_chirho {
            if projection_read_chirho.mount_coordinate_chirho() != *pinned_mount_coordinate_chirho {
                bail!("ReplicaProjectionMountCoordinateMismatchChirho");
            }
        }

        let final_bytes_chirho = match dag_chirho.after_query_dag_chirho.as_ref() {
            Some(after_query_dag_chirho) => {
                match run_pure_dag_chirho(
                    store_chirho,
                    after_query_dag_chirho,
                    &projection_read_chirho.view_bytes_chirho,
                    BALANCE_DAG_OUTPUT_CAP_CHIRHO,
                )? {
                    PureDagOutcomeChirho::PayloadChirho { bytes_chirho, .. } => bytes_chirho,
                    PureDagOutcomeChirho::RefusedEffectfulChirho { node_chirho } => {
                        return Ok(Err(ReplicaReadDagRefusalChirho::EffectNodeChirho {
                            node_chirho,
                        }))
                    }
                    PureDagOutcomeChirho::RefusedNativeChirho { node_chirho } => {
                        return Ok(Err(ReplicaReadDagRefusalChirho::NativeNodeChirho {
                            node_chirho,
                        }))
                    }
                }
            }
            None => projection_read_chirho.view_bytes_chirho.clone(),
        };

        let output_hash_chirho = bind_published_output_hash_chirho(
            &final_bytes_chirho,
            &dag_chirho.expected_output_hash_chirho,
        )?;
        Ok(Ok(ReplicaBalanceReadResultChirho {
            bytes_chirho: final_bytes_chirho,
            output_hash_chirho,
            projection_read_chirho,
        }))
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use cairn_core_chirho::model_chirho::{CapabilityChirho, NodeDefChirho};
    // Fixtures SEED the store, so the test module imports the write trait. Production code on
    // this chain cannot: the runner's signature takes only `&dyn ContentReadChirho`.
    use cairn_core_chirho::ports_chirho::ContentStoreChirho;
    use cairn_store_fs_chirho::FsContentStoreChirho;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_root_chirho() -> std::path::PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let root_chirho = std::env::temp_dir().join(format!(
            "cairn-r2-read-dag-{}-{}",
            std::process::id(),
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root_chirho);
        std::fs::create_dir_all(&root_chirho).unwrap();
        root_chirho
    }

    fn runner_chirho() -> ReplicaBalanceReadDagRunnerChirho {
        let identity_chirho =
            crate::projection_replication_chirho::ProjectionReplicationIdentityChirho {
                projection_name_chirho: BALANCE_QUERY_SCOPE_CHIRHO.to_owned(),
                descriptor_digest_chirho: "0".repeat(64),
                source_cluster_chirho: "test-cluster-chirho".to_owned(),
                source_genesis_digest_chirho: "1".repeat(64),
                feeder_pubkey_hex_chirho: "2".repeat(64),
            };
        let config_chirho =
            crate::projection_replication_chirho::ProjectionReplicaPullConfigChirho {
                source_url_chirho: "http://127.0.0.1:0".to_owned(),
                bearer_env_chirho: "CAIRN_R2_TEST_BEARER_CHIRHO".to_owned(),
                replica_root_chirho: temp_root_chirho(),
                identity_chirho,
                inspect_accounts_chirho: Vec::new(),
            };
        ReplicaBalanceReadDagRunnerChirho::new_chirho(
            ReplicaMountedProjectionReadPortChirho::new_chirho(config_chirho, 0, 1000),
        )
    }

    #[test]
    fn effect_segment_refuses_with_404_without_opening_query_door_chirho() {
        let root_chirho = temp_root_chirho();
        let store_chirho = FsContentStoreChirho::new_chirho(&root_chirho);
        let node_chirho = NodeDefChirho {
            name_chirho: "write-chirho".to_owned(),
            impl_wasm_chirho: HashChirho("a".repeat(64)),
            capabilities_chirho: vec![CapabilityChirho::WriteStoreChirho {
                prefix_chirho: "private-chirho".to_owned(),
            }],
            ..Default::default()
        };
        let node_hash_chirho = store_chirho
            .put_chirho(&serde_json::to_vec(&node_chirho).unwrap())
            .unwrap();
        let dag_chirho = ReplicaBalanceReadDagChirho {
            before_query_dag_chirho: Some(DagChirho {
                nodes_chirho: vec![node_hash_chirho.clone()],
                edges_chirho: Vec::new(),
            }),
            after_query_dag_chirho: None,
            expected_output_hash_chirho: HashChirho("b".repeat(64)),
        };
        let refusal_chirho = runner_chirho()
            .run_chirho(&store_chirho, &dag_chirho, b"request")
            .unwrap()
            .unwrap_err();
        assert_eq!(
            refusal_chirho,
            ReplicaReadDagRefusalChirho::EffectNodeChirho {
                node_chirho: node_hash_chirho
            }
        );
        assert_eq!(refusal_chirho.http_status_chirho(), 404);
    }

    #[test]
    fn query_contract_is_fixed_to_the_balance_scope_and_limit_chirho() {
        assert_eq!(BALANCE_QUERY_SCOPE_CHIRHO, "credits-balance-chirho");
        assert_eq!(BALANCE_QUERY_LIMIT_CHIRHO, 1);
    }

    #[test]
    fn published_hash_mismatch_refuses_by_identity_chirho() {
        let error_chirho =
            bind_published_output_hash_chirho(b"served-bytes-chirho", &HashChirho("0".repeat(64)))
                .expect_err("mismatched served bytes must not pass the source hash gate");
        assert!(error_chirho
            .to_string()
            .contains("ReplicaPublishedOutputHashMismatchChirho"));
    }
}
