// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Persistent content-addressed indexes over versioned state.

use crate::model_chirho::{
    CapabilityChirho, EffectChirho, HashChirho, RunKeyChirho, RunResultChirho,
};
use crate::{cache_chirho, cas_chirho, refs_chirho, store_chirho, versioned_chirho};
use anyhow::{anyhow, bail, Context, Result};
use cairn_writer_head_chirho::writer_head_chirho;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

const INDEX_REF_CHIRHO: &str = "index/entries-chirho";
const PROVENANCE_INDEX_REF_CHIRHO: &str = "index/provenance-chirho";
const PERSISTENT_INDEX_ROOT_SCHEMA_CHIRHO: &str = "persistent-index-root-v1-chirho";
const INVERTED_PROVENANCE_ROOT_SCHEMA_CHIRHO: &str = "inverted-provenance-root-v1-chirho";
const PERSISTENT_INDEX_KIND_CHIRHO: &str = "entries-chirho";
const INVERTED_PROVENANCE_KIND_CHIRHO: &str = "provenance-chirho";
const HAMT_MAX_DEPTH_CHIRHO: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistentIndexRootChirho {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub kind_chirho: String,
    pub view_chirho: u64,
    pub root_chirho: HashChirho,
    pub rows_chirho: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistentIndexProjectionChirho {
    pub record_chirho: PersistentIndexRootChirho,
    pub record_hash_chirho: HashChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistentIndexVerificationChirho {
    pub nodes_chirho: usize,
    pub rows_chirho: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvertedProvenanceRootChirho {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub kind_chirho: String,
    pub root_chirho: HashChirho,
    pub runs_indexed_chirho: usize,
    pub rows_chirho: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvertedProvenanceProjectionChirho {
    pub record_chirho: InvertedProvenanceRootChirho,
    pub record_hash_chirho: HashChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvertedProvenanceVerificationChirho {
    pub nodes_chirho: usize,
    pub rows_chirho: usize,
    pub runs_indexed_chirho: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProvenanceConsumerKindChirho {
    ProducesStateChirho,
    ConsumesInputStateChirho,
    ConsumesNodeVersionChirho,
    ConsumesParentRunChirho,
    ConsumesEffectRequestChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProvenanceConsumerChirho {
    pub kind_chirho: ProvenanceConsumerKindChirho,
    pub run_chirho: HashChirho,
    pub effect_seq_chirho: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependentEffectChirho {
    pub run_chirho: HashChirho,
    pub effect_seq_chirho: u64,
    pub capability_chirho: CapabilityChirho,
    pub request_chirho: HashChirho,
    pub response_chirho: Option<HashChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RunVisitChirho {
    run_chirho: HashChirho,
    include_effects_chirho: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HamtNodeChirho {
    BranchChirho {
        children_chirho: BTreeMap<String, HashChirho>,
    },
    LeafChirho {
        entries_chirho: Vec<HamtEntryChirho>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HamtEntryChirho {
    pub key_chirho: String,
    pub key_hash_chirho: String,
    pub value_chirho: HashChirho,
}

pub fn index_ref_chirho() -> &'static str {
    INDEX_REF_CHIRHO
}

pub fn provenance_index_ref_chirho() -> &'static str {
    PROVENANCE_INDEX_REF_CHIRHO
}

fn versioned_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("versioned-chirho.redb")
}

fn runs_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("runs-chirho")
}

pub fn empty_hamt_root_chirho(root_chirho: &Path) -> Result<HashChirho> {
    store_node_chirho(
        root_chirho,
        &HamtNodeChirho::BranchChirho {
            children_chirho: BTreeMap::new(),
        },
    )
}

pub fn put_hamt_entry_chirho(
    root_chirho: &Path,
    old_root_chirho: Option<&HashChirho>,
    key_chirho: &str,
    value_chirho: &[u8],
) -> Result<HashChirho> {
    let value_hash_chirho =
        cas_chirho::add_chirho(root_chirho, value_chirho).context("store indexed value in CAS")?;
    let entry_chirho = HamtEntryChirho {
        key_chirho: key_chirho.to_string(),
        key_hash_chirho: key_hash_chirho(key_chirho),
        value_chirho: value_hash_chirho,
    };
    match old_root_chirho {
        Some(root_hash_chirho) => {
            insert_entry_chirho(root_chirho, root_hash_chirho, entry_chirho, 0)
        }
        None => build_subtrie_chirho(root_chirho, vec![entry_chirho], 0),
    }
}

pub fn project_index_chirho(
    root_chirho: &Path,
    view_chirho: Option<u64>,
) -> Result<PersistentIndexProjectionChirho> {
    let store_chirho =
        versioned_chirho::VersionedStoreChirho::open_chirho(&versioned_path_chirho(root_chirho))?;
    let resolved_view_chirho = match view_chirho {
        Some(view_chirho) => view_chirho,
        None => store_chirho.current_view_chirho()?,
    };
    let entries_chirho = store_chirho.current_entries_at_chirho(resolved_view_chirho)?;
    drop(store_chirho);

    let hamt_root_chirho = build_hamt_from_entries_chirho(root_chirho, &entries_chirho)?;
    let record_chirho = PersistentIndexRootChirho {
        schema_chirho: PERSISTENT_INDEX_ROOT_SCHEMA_CHIRHO.to_string(),
        kind_chirho: PERSISTENT_INDEX_KIND_CHIRHO.to_string(),
        view_chirho: resolved_view_chirho,
        root_chirho: hamt_root_chirho,
        rows_chirho: entries_chirho.len(),
    };
    let record_hash_chirho = store_chirho::put_object_chirho(root_chirho, &record_chirho)?;
    writer_head_chirho::with_head_commit_chirho(root_chirho, || {
        refs_chirho::commit_head_chirho(
            root_chirho,
            INDEX_REF_CHIRHO,
            refs_chirho::HeadPreconditionChirho::AnyCurrentChirho,
            record_hash_chirho.clone(),
            "index-projection",
        )
    })?;
    Ok(PersistentIndexProjectionChirho {
        record_chirho,
        record_hash_chirho,
    })
}

pub fn rollback_index_ref_chirho(
    root_chirho: &Path,
    record_hash_chirho: &HashChirho,
) -> Result<PersistentIndexRootChirho> {
    let record_chirho = load_index_record_chirho(root_chirho, record_hash_chirho)?;
    writer_head_chirho::with_head_commit_chirho(root_chirho, || {
        let current_chirho = refs_chirho::load_refs_chirho(root_chirho)?
            .branches_chirho
            .get(INDEX_REF_CHIRHO)
            .cloned()
            .ok_or_else(|| anyhow!("no such branch '{INDEX_REF_CHIRHO}' to roll back"))?;
        refs_chirho::commit_head_chirho(
            root_chirho,
            INDEX_REF_CHIRHO,
            refs_chirho::HeadPreconditionChirho::ExpectedChirho(current_chirho),
            record_hash_chirho.clone(),
            "rollback",
        )
    })?;
    Ok(record_chirho)
}

pub fn load_index_record_chirho(
    root_chirho: &Path,
    record_hash_chirho: &HashChirho,
) -> Result<PersistentIndexRootChirho> {
    let record_chirho: PersistentIndexRootChirho =
        store_chirho::get_object_chirho(root_chirho, record_hash_chirho)
            .with_context(|| format!("load index root record {}", record_hash_chirho.0))?;
    validate_index_root_schema_chirho(&record_chirho)?;
    Ok(record_chirho)
}

pub fn get_index_value_chirho(
    root_chirho: &Path,
    record_hash_chirho: &HashChirho,
    key_chirho: &str,
) -> Result<Option<Vec<u8>>> {
    let record_chirho = load_index_record_chirho(root_chirho, record_hash_chirho)?;
    let Some(value_hash_chirho) =
        lookup_value_hash_chirho(root_chirho, &record_chirho.root_chirho, key_chirho)?
    else {
        return Ok(None);
    };
    Ok(Some(
        cas_chirho::get_chirho(root_chirho, &value_hash_chirho)
            .with_context(|| format!("indexed value {} missing", value_hash_chirho.0))?,
    ))
}

pub fn verify_index_chirho(
    root_chirho: &Path,
    record_hash_chirho: &HashChirho,
) -> Result<PersistentIndexVerificationChirho> {
    let record_chirho = load_index_record_chirho(root_chirho, record_hash_chirho)?;
    let store_chirho =
        versioned_chirho::VersionedStoreChirho::open_chirho(&versioned_path_chirho(root_chirho))?;
    let expected_entries_chirho =
        store_chirho.current_entries_at_chirho(record_chirho.view_chirho)?;
    drop(store_chirho);
    let expected_root_chirho = hash_hamt_from_entries_chirho(&expected_entries_chirho)?;
    if expected_root_chirho != record_chirho.root_chirho {
        bail!(
            "index projection mismatch for view v{}: record root {} expected {}",
            record_chirho.view_chirho,
            record_chirho.root_chirho.0,
            expected_root_chirho.0
        );
    }
    if expected_entries_chirho.len() != record_chirho.rows_chirho {
        bail!(
            "index row count mismatch: record={} source={}",
            record_chirho.rows_chirho,
            expected_entries_chirho.len()
        );
    }
    let mut seen_chirho = BTreeSet::new();
    let mut keys_chirho = BTreeSet::new();
    let rows_chirho = verify_node_chirho(
        root_chirho,
        &record_chirho.root_chirho,
        0,
        "",
        &mut seen_chirho,
        &mut keys_chirho,
    )?;
    if rows_chirho != record_chirho.rows_chirho {
        bail!(
            "index row count mismatch: record={} actual={}",
            record_chirho.rows_chirho,
            rows_chirho
        );
    }
    Ok(PersistentIndexVerificationChirho {
        nodes_chirho: seen_chirho.len(),
        rows_chirho,
    })
}

pub fn reachable_hamt_nodes_chirho(
    root_chirho: &Path,
    root_hash_chirho: &HashChirho,
) -> Result<BTreeSet<HashChirho>> {
    let mut seen_chirho = BTreeSet::new();
    collect_reachable_chirho(root_chirho, root_hash_chirho, &mut seen_chirho)?;
    Ok(seen_chirho)
}

pub fn project_inverted_provenance_index_chirho(
    root_chirho: &Path,
) -> Result<InvertedProvenanceProjectionChirho> {
    let runs_chirho = load_all_run_results_chirho(root_chirho)?;
    let consumers_chirho = provenance_consumers_for_runs_chirho(root_chirho, &runs_chirho)?;
    let hamt_root_chirho = build_hamt_from_pairs_chirho(root_chirho, &consumers_chirho)?;
    let record_chirho = InvertedProvenanceRootChirho {
        schema_chirho: INVERTED_PROVENANCE_ROOT_SCHEMA_CHIRHO.to_string(),
        kind_chirho: INVERTED_PROVENANCE_KIND_CHIRHO.to_string(),
        root_chirho: hamt_root_chirho,
        runs_indexed_chirho: runs_chirho.len(),
        rows_chirho: consumers_chirho.len(),
    };
    let record_hash_chirho = store_chirho::put_object_chirho(root_chirho, &record_chirho)?;
    writer_head_chirho::with_head_commit_chirho(root_chirho, || {
        refs_chirho::commit_head_chirho(
            root_chirho,
            PROVENANCE_INDEX_REF_CHIRHO,
            refs_chirho::HeadPreconditionChirho::AnyCurrentChirho,
            record_hash_chirho.clone(),
            "provenance-index-projection",
        )
    })?;
    Ok(InvertedProvenanceProjectionChirho {
        record_chirho,
        record_hash_chirho,
    })
}

pub fn load_inverted_provenance_record_chirho(
    root_chirho: &Path,
    record_hash_chirho: &HashChirho,
) -> Result<InvertedProvenanceRootChirho> {
    let record_chirho: InvertedProvenanceRootChirho =
        store_chirho::get_object_chirho(root_chirho, record_hash_chirho).with_context(|| {
            format!("load provenance index root record {}", record_hash_chirho.0)
        })?;
    validate_inverted_provenance_root_schema_chirho(&record_chirho)?;
    Ok(record_chirho)
}

pub fn verify_inverted_provenance_index_chirho(
    root_chirho: &Path,
    record_hash_chirho: &HashChirho,
) -> Result<InvertedProvenanceVerificationChirho> {
    let record_chirho = load_inverted_provenance_record_chirho(root_chirho, record_hash_chirho)?;
    let runs_chirho = load_all_run_results_chirho(root_chirho)?;
    let expected_consumers_chirho =
        provenance_consumers_for_runs_chirho(root_chirho, &runs_chirho)?;
    let expected_root_chirho = hash_hamt_from_pairs_chirho(&expected_consumers_chirho)?;
    if expected_root_chirho != record_chirho.root_chirho {
        bail!(
            "provenance index root mismatch: record {} expected {}",
            record_chirho.root_chirho.0,
            expected_root_chirho.0
        );
    }
    if runs_chirho.len() != record_chirho.runs_indexed_chirho {
        bail!(
            "provenance index run count mismatch: record={} actual={}",
            record_chirho.runs_indexed_chirho,
            runs_chirho.len()
        );
    }
    if expected_consumers_chirho.len() != record_chirho.rows_chirho {
        bail!(
            "provenance index row count mismatch: record={} actual={}",
            record_chirho.rows_chirho,
            expected_consumers_chirho.len()
        );
    }
    let mut seen_chirho = BTreeSet::new();
    let mut keys_chirho = BTreeSet::new();
    let rows_chirho = verify_node_chirho(
        root_chirho,
        &record_chirho.root_chirho,
        0,
        "",
        &mut seen_chirho,
        &mut keys_chirho,
    )?;
    if rows_chirho != record_chirho.rows_chirho {
        bail!(
            "provenance index stored row count mismatch: record={} actual={}",
            record_chirho.rows_chirho,
            rows_chirho
        );
    }
    for state_chirho in expected_consumers_chirho.keys() {
        let consumers_chirho = lookup_provenance_consumers_chirho(
            root_chirho,
            &record_chirho.root_chirho,
            state_chirho,
        )?;
        let expected_chirho = expected_consumers_chirho
            .get(state_chirho)
            .cloned()
            .unwrap_or_default();
        if consumers_chirho != expected_chirho {
            bail!("provenance index consumer mismatch for state {state_chirho}");
        }
    }
    Ok(InvertedProvenanceVerificationChirho {
        nodes_chirho: seen_chirho.len(),
        rows_chirho: record_chirho.rows_chirho,
        runs_indexed_chirho: record_chirho.runs_indexed_chirho,
    })
}

pub fn find_dependent_effects_chirho(
    root_chirho: &Path,
    record_hash_chirho: &HashChirho,
    state_chirho: &HashChirho,
) -> Result<Vec<DependentEffectChirho>> {
    let record_chirho = load_inverted_provenance_record_chirho(root_chirho, record_hash_chirho)?;
    let mut state_queue_chirho = VecDeque::from([state_chirho.clone()]);
    let mut run_queue_chirho = VecDeque::new();
    let mut seen_states_chirho = BTreeSet::new();
    let mut expanded_runs_chirho = BTreeSet::new();
    let mut effect_runs_chirho = BTreeSet::new();
    let mut effects_chirho: BTreeMap<(HashChirho, u64), DependentEffectChirho> = BTreeMap::new();

    if cache_chirho::load_sealed_result_chirho(root_chirho, state_chirho)?.is_some() {
        run_queue_chirho.push_back(RunVisitChirho {
            run_chirho: state_chirho.clone(),
            include_effects_chirho: true,
        });
    }

    while !state_queue_chirho.is_empty() || !run_queue_chirho.is_empty() {
        while let Some(next_state_chirho) = state_queue_chirho.pop_front() {
            if !seen_states_chirho.insert(next_state_chirho.clone()) {
                continue;
            }
            for consumer_chirho in lookup_provenance_consumers_chirho(
                root_chirho,
                &record_chirho.root_chirho,
                &next_state_chirho.0,
            )? {
                match consumer_chirho.kind_chirho {
                    ProvenanceConsumerKindChirho::ProducesStateChirho => {
                        run_queue_chirho.push_back(RunVisitChirho {
                            run_chirho: consumer_chirho.run_chirho,
                            include_effects_chirho: false,
                        });
                    }
                    ProvenanceConsumerKindChirho::ConsumesInputStateChirho
                    | ProvenanceConsumerKindChirho::ConsumesNodeVersionChirho
                    | ProvenanceConsumerKindChirho::ConsumesParentRunChirho => {
                        run_queue_chirho.push_back(RunVisitChirho {
                            run_chirho: consumer_chirho.run_chirho,
                            include_effects_chirho: true,
                        });
                    }
                    ProvenanceConsumerKindChirho::ConsumesEffectRequestChirho => {
                        add_effect_from_run_chirho(
                            root_chirho,
                            &consumer_chirho.run_chirho,
                            consumer_chirho.effect_seq_chirho,
                            &mut effects_chirho,
                        )?;
                        run_queue_chirho.push_back(RunVisitChirho {
                            run_chirho: consumer_chirho.run_chirho,
                            include_effects_chirho: true,
                        });
                    }
                }
            }
        }

        if let Some(next_run_chirho) = run_queue_chirho.pop_front() {
            if next_run_chirho.include_effects_chirho
                && effect_runs_chirho.insert(next_run_chirho.run_chirho.clone())
            {
                if let Some(result_chirho) = cache_chirho::load_sealed_result_chirho(
                    root_chirho,
                    &next_run_chirho.run_chirho,
                )? {
                    for effect_chirho in &result_chirho.effects_chirho {
                        insert_dependent_effect_chirho(
                            &result_chirho.run_chirho,
                            effect_chirho,
                            &mut effects_chirho,
                        );
                    }
                }
            }
            if !expanded_runs_chirho.insert(next_run_chirho.run_chirho.clone()) {
                continue;
            }
            for consumer_chirho in lookup_provenance_consumers_chirho(
                root_chirho,
                &record_chirho.root_chirho,
                &next_run_chirho.run_chirho.0,
            )? {
                if consumer_chirho.kind_chirho
                    == ProvenanceConsumerKindChirho::ConsumesParentRunChirho
                {
                    run_queue_chirho.push_back(RunVisitChirho {
                        run_chirho: consumer_chirho.run_chirho,
                        include_effects_chirho: true,
                    });
                }
            }
        }
    }

    Ok(effects_chirho.into_values().collect())
}

fn build_hamt_from_entries_chirho(
    root_chirho: &Path,
    entries_chirho: &[(String, Vec<u8>)],
) -> Result<HashChirho> {
    let mut root_hash_chirho: Option<HashChirho> = None;
    for (key_chirho, value_chirho) in entries_chirho {
        root_hash_chirho = Some(put_hamt_entry_chirho(
            root_chirho,
            root_hash_chirho.as_ref(),
            key_chirho,
            value_chirho,
        )?);
    }
    match root_hash_chirho {
        Some(root_hash_chirho) => Ok(root_hash_chirho),
        None => empty_hamt_root_chirho(root_chirho),
    }
}

fn build_hamt_from_pairs_chirho(
    root_chirho: &Path,
    entries_chirho: &BTreeMap<String, Vec<ProvenanceConsumerChirho>>,
) -> Result<HashChirho> {
    let mut root_hash_chirho: Option<HashChirho> = None;
    for (key_chirho, consumers_chirho) in entries_chirho {
        let value_chirho = serde_json::to_vec(consumers_chirho)
            .context("encode provenance index consumer vector")?;
        root_hash_chirho = Some(put_hamt_entry_chirho(
            root_chirho,
            root_hash_chirho.as_ref(),
            key_chirho,
            &value_chirho,
        )?);
    }
    match root_hash_chirho {
        Some(root_hash_chirho) => Ok(root_hash_chirho),
        None => empty_hamt_root_chirho(root_chirho),
    }
}

fn hash_hamt_from_entries_chirho(entries_chirho: &[(String, Vec<u8>)]) -> Result<HashChirho> {
    if entries_chirho.is_empty() {
        return hash_node_chirho(&HamtNodeChirho::BranchChirho {
            children_chirho: BTreeMap::new(),
        });
    }
    let mut indexed_entries_chirho = Vec::new();
    for (key_chirho, value_chirho) in entries_chirho {
        indexed_entries_chirho.push(HamtEntryChirho {
            key_chirho: key_chirho.clone(),
            key_hash_chirho: key_hash_chirho(key_chirho),
            value_chirho: cas_chirho::hash_chirho(value_chirho),
        });
    }
    hash_subtrie_chirho(indexed_entries_chirho, 0)
}

fn hash_hamt_from_pairs_chirho(
    entries_chirho: &BTreeMap<String, Vec<ProvenanceConsumerChirho>>,
) -> Result<HashChirho> {
    if entries_chirho.is_empty() {
        return hash_node_chirho(&HamtNodeChirho::BranchChirho {
            children_chirho: BTreeMap::new(),
        });
    }
    let mut indexed_entries_chirho = Vec::new();
    for (key_chirho, consumers_chirho) in entries_chirho {
        let value_chirho = serde_json::to_vec(consumers_chirho)
            .context("encode provenance index consumer vector")?;
        indexed_entries_chirho.push(HamtEntryChirho {
            key_chirho: key_chirho.clone(),
            key_hash_chirho: key_hash_chirho(key_chirho),
            value_chirho: cas_chirho::hash_chirho(&value_chirho),
        });
    }
    hash_subtrie_chirho(indexed_entries_chirho, 0)
}

fn provenance_consumers_for_runs_chirho(
    root_chirho: &Path,
    runs_chirho: &[RunResultChirho],
) -> Result<BTreeMap<String, Vec<ProvenanceConsumerChirho>>> {
    let mut out_chirho: BTreeMap<String, BTreeSet<ProvenanceConsumerChirho>> = BTreeMap::new();
    for result_chirho in runs_chirho {
        if let Some(run_key_chirho) =
            cache_chirho::load_run_key_chirho(root_chirho, &result_chirho.run_chirho)?
        {
            insert_run_key_consumers_chirho(
                &mut out_chirho,
                &result_chirho.run_chirho,
                &run_key_chirho,
            );
        }
        for parent_chirho in &result_chirho.parents_chirho {
            insert_provenance_consumer_chirho(
                &mut out_chirho,
                parent_chirho,
                ProvenanceConsumerKindChirho::ConsumesParentRunChirho,
                &result_chirho.run_chirho,
                None,
            );
        }
        for output_chirho in result_chirho.outputs_chirho.values() {
            insert_provenance_consumer_chirho(
                &mut out_chirho,
                output_chirho,
                ProvenanceConsumerKindChirho::ProducesStateChirho,
                &result_chirho.run_chirho,
                None,
            );
        }
        for effect_chirho in &result_chirho.effects_chirho {
            insert_provenance_consumer_chirho(
                &mut out_chirho,
                &effect_chirho.request_chirho,
                ProvenanceConsumerKindChirho::ConsumesEffectRequestChirho,
                &result_chirho.run_chirho,
                Some(effect_chirho.seq_chirho),
            );
        }
    }
    let consumers_chirho = out_chirho
        .into_iter()
        .map(|(state_chirho, consumers_chirho)| {
            (state_chirho, consumers_chirho.into_iter().collect())
        })
        .collect::<BTreeMap<_, _>>();
    Ok(consumers_chirho)
}

fn insert_run_key_consumers_chirho(
    out_chirho: &mut BTreeMap<String, BTreeSet<ProvenanceConsumerChirho>>,
    run_chirho: &HashChirho,
    run_key_chirho: &RunKeyChirho,
) {
    insert_provenance_consumer_chirho(
        out_chirho,
        &run_key_chirho.node_chirho,
        ProvenanceConsumerKindChirho::ConsumesNodeVersionChirho,
        run_chirho,
        None,
    );
    for input_chirho in run_key_chirho.inputs_chirho.values() {
        insert_provenance_consumer_chirho(
            out_chirho,
            input_chirho,
            ProvenanceConsumerKindChirho::ConsumesInputStateChirho,
            run_chirho,
            None,
        );
    }
}

fn insert_provenance_consumer_chirho(
    out_chirho: &mut BTreeMap<String, BTreeSet<ProvenanceConsumerChirho>>,
    state_chirho: &HashChirho,
    kind_chirho: ProvenanceConsumerKindChirho,
    run_chirho: &HashChirho,
    effect_seq_chirho: Option<u64>,
) {
    out_chirho
        .entry(state_chirho.0.clone())
        .or_default()
        .insert(ProvenanceConsumerChirho {
            kind_chirho,
            run_chirho: run_chirho.clone(),
            effect_seq_chirho,
        });
}

fn lookup_provenance_consumers_chirho(
    root_chirho: &Path,
    hamt_root_chirho: &HashChirho,
    state_chirho: &str,
) -> Result<Vec<ProvenanceConsumerChirho>> {
    let state_hash_chirho = HashChirho(state_chirho.to_string());
    let Some(value_hash_chirho) =
        lookup_value_hash_chirho(root_chirho, hamt_root_chirho, &state_hash_chirho.0)?
    else {
        return Ok(vec![]);
    };
    let bytes_chirho = cas_chirho::get_chirho(root_chirho, &value_hash_chirho)
        .with_context(|| format!("provenance consumer vector {} missing", value_hash_chirho.0))?;
    serde_json::from_slice(&bytes_chirho).context("decode provenance consumer vector")
}

fn insert_entry_chirho(
    root_chirho: &Path,
    node_hash_chirho: &HashChirho,
    entry_chirho: HamtEntryChirho,
    depth_chirho: usize,
) -> Result<HashChirho> {
    let node_chirho = load_node_verified_chirho(root_chirho, node_hash_chirho)?;
    match node_chirho {
        HamtNodeChirho::BranchChirho {
            mut children_chirho,
        } => {
            let slot_chirho = nibble_label_chirho(&entry_chirho.key_hash_chirho, depth_chirho)?;
            let child_chirho = children_chirho.get(&slot_chirho).cloned();
            let new_child_chirho = match child_chirho {
                Some(child_hash_chirho) => insert_entry_chirho(
                    root_chirho,
                    &child_hash_chirho,
                    entry_chirho,
                    depth_chirho + 1,
                )?,
                None => build_subtrie_chirho(root_chirho, vec![entry_chirho], depth_chirho + 1)?,
            };
            children_chirho.insert(slot_chirho, new_child_chirho);
            store_node_chirho(
                root_chirho,
                &HamtNodeChirho::BranchChirho { children_chirho },
            )
        }
        HamtNodeChirho::LeafChirho { mut entries_chirho } => {
            if let Some(existing_chirho) = entries_chirho
                .iter_mut()
                .find(|existing_chirho| existing_chirho.key_chirho == entry_chirho.key_chirho)
            {
                *existing_chirho = entry_chirho;
                entries_chirho.sort_by(|left_chirho, right_chirho| {
                    left_chirho.key_chirho.cmp(&right_chirho.key_chirho)
                });
                return store_node_chirho(
                    root_chirho,
                    &HamtNodeChirho::LeafChirho { entries_chirho },
                );
            }
            entries_chirho.push(entry_chirho);
            build_subtrie_chirho(root_chirho, entries_chirho, depth_chirho)
        }
    }
}

fn build_subtrie_chirho(
    root_chirho: &Path,
    mut entries_chirho: Vec<HamtEntryChirho>,
    depth_chirho: usize,
) -> Result<HashChirho> {
    entries_chirho
        .sort_by(|left_chirho, right_chirho| left_chirho.key_chirho.cmp(&right_chirho.key_chirho));
    if entries_chirho.len() <= 1 || depth_chirho >= HAMT_MAX_DEPTH_CHIRHO {
        return store_node_chirho(root_chirho, &HamtNodeChirho::LeafChirho { entries_chirho });
    }

    let mut groups_chirho: BTreeMap<String, Vec<HamtEntryChirho>> = BTreeMap::new();
    for entry_chirho in entries_chirho {
        groups_chirho
            .entry(nibble_label_chirho(
                &entry_chirho.key_hash_chirho,
                depth_chirho,
            )?)
            .or_default()
            .push(entry_chirho);
    }

    let mut children_chirho = BTreeMap::new();
    for (slot_chirho, grouped_entries_chirho) in groups_chirho {
        let child_hash_chirho =
            build_subtrie_chirho(root_chirho, grouped_entries_chirho, depth_chirho + 1)?;
        children_chirho.insert(slot_chirho, child_hash_chirho);
    }
    store_node_chirho(
        root_chirho,
        &HamtNodeChirho::BranchChirho { children_chirho },
    )
}

fn hash_subtrie_chirho(
    mut entries_chirho: Vec<HamtEntryChirho>,
    depth_chirho: usize,
) -> Result<HashChirho> {
    entries_chirho
        .sort_by(|left_chirho, right_chirho| left_chirho.key_chirho.cmp(&right_chirho.key_chirho));
    if entries_chirho.len() <= 1 || depth_chirho >= HAMT_MAX_DEPTH_CHIRHO {
        return hash_node_chirho(&HamtNodeChirho::LeafChirho { entries_chirho });
    }

    let mut groups_chirho: BTreeMap<String, Vec<HamtEntryChirho>> = BTreeMap::new();
    for entry_chirho in entries_chirho {
        groups_chirho
            .entry(nibble_label_chirho(
                &entry_chirho.key_hash_chirho,
                depth_chirho,
            )?)
            .or_default()
            .push(entry_chirho);
    }

    let mut children_chirho = BTreeMap::new();
    for (slot_chirho, grouped_entries_chirho) in groups_chirho {
        let child_hash_chirho = hash_subtrie_chirho(grouped_entries_chirho, depth_chirho + 1)?;
        children_chirho.insert(slot_chirho, child_hash_chirho);
    }
    hash_node_chirho(&HamtNodeChirho::BranchChirho { children_chirho })
}

fn lookup_value_hash_chirho(
    root_chirho: &Path,
    root_hash_chirho: &HashChirho,
    key_chirho: &str,
) -> Result<Option<HashChirho>> {
    let key_hash_chirho = key_hash_chirho(key_chirho);
    lookup_at_chirho(
        root_chirho,
        root_hash_chirho,
        key_chirho,
        &key_hash_chirho,
        0,
    )
}

fn lookup_at_chirho(
    root_chirho: &Path,
    node_hash_chirho: &HashChirho,
    key_chirho: &str,
    key_hash_chirho: &str,
    depth_chirho: usize,
) -> Result<Option<HashChirho>> {
    let node_chirho = load_node_verified_chirho(root_chirho, node_hash_chirho)?;
    match node_chirho {
        HamtNodeChirho::BranchChirho { children_chirho } => {
            if depth_chirho >= HAMT_MAX_DEPTH_CHIRHO {
                return Ok(None);
            }
            let slot_chirho = nibble_label_chirho(key_hash_chirho, depth_chirho)?;
            let Some(child_hash_chirho) = children_chirho.get(&slot_chirho) else {
                return Ok(None);
            };
            lookup_at_chirho(
                root_chirho,
                child_hash_chirho,
                key_chirho,
                key_hash_chirho,
                depth_chirho + 1,
            )
        }
        HamtNodeChirho::LeafChirho { entries_chirho } => Ok(entries_chirho
            .into_iter()
            .find(|entry_chirho| entry_chirho.key_chirho == key_chirho)
            .map(|entry_chirho| entry_chirho.value_chirho)),
    }
}

fn verify_node_chirho(
    root_chirho: &Path,
    node_hash_chirho: &HashChirho,
    depth_chirho: usize,
    prefix_chirho: &str,
    seen_chirho: &mut BTreeSet<HashChirho>,
    keys_chirho: &mut BTreeSet<String>,
) -> Result<usize> {
    if !seen_chirho.insert(node_hash_chirho.clone()) {
        return Ok(0);
    }
    let node_chirho = load_node_verified_chirho(root_chirho, node_hash_chirho)?;
    match node_chirho {
        HamtNodeChirho::BranchChirho { children_chirho } => {
            if depth_chirho >= HAMT_MAX_DEPTH_CHIRHO && !children_chirho.is_empty() {
                bail!("branch beyond HAMT depth");
            }
            let mut rows_chirho = 0;
            for (slot_chirho, child_hash_chirho) in children_chirho {
                if slot_chirho.len() != 1
                    || !slot_chirho
                        .chars()
                        .all(|c_chirho| c_chirho.is_ascii_hexdigit())
                {
                    bail!("invalid HAMT slot '{slot_chirho}'");
                }
                let child_prefix_chirho = format!("{prefix_chirho}{slot_chirho}");
                rows_chirho += verify_node_chirho(
                    root_chirho,
                    &child_hash_chirho,
                    depth_chirho + 1,
                    &child_prefix_chirho,
                    seen_chirho,
                    keys_chirho,
                )?;
            }
            Ok(rows_chirho)
        }
        HamtNodeChirho::LeafChirho { entries_chirho } => {
            let mut last_key_chirho: Option<String> = None;
            for entry_chirho in &entries_chirho {
                if entry_chirho.key_hash_chirho != key_hash_chirho(&entry_chirho.key_chirho) {
                    bail!("key hash mismatch for '{}'", entry_chirho.key_chirho);
                }
                if !entry_chirho.key_hash_chirho.starts_with(prefix_chirho) {
                    bail!(
                        "key '{}' stored under wrong HAMT path",
                        entry_chirho.key_chirho
                    );
                }
                if let Some(last_key_chirho) = &last_key_chirho {
                    if last_key_chirho >= &entry_chirho.key_chirho {
                        bail!("leaf entries out of order");
                    }
                }
                last_key_chirho = Some(entry_chirho.key_chirho.clone());
                if !keys_chirho.insert(entry_chirho.key_chirho.clone()) {
                    bail!("duplicate indexed key '{}'", entry_chirho.key_chirho);
                }
                cas_chirho::get_chirho(root_chirho, &entry_chirho.value_chirho).with_context(
                    || format!("indexed value {} missing", entry_chirho.value_chirho.0),
                )?;
            }
            Ok(entries_chirho.len())
        }
    }
}

fn collect_reachable_chirho(
    root_chirho: &Path,
    node_hash_chirho: &HashChirho,
    seen_chirho: &mut BTreeSet<HashChirho>,
) -> Result<()> {
    if !seen_chirho.insert(node_hash_chirho.clone()) {
        return Ok(());
    }
    let node_chirho = load_node_verified_chirho(root_chirho, node_hash_chirho)?;
    if let HamtNodeChirho::BranchChirho { children_chirho } = node_chirho {
        for child_hash_chirho in children_chirho.values() {
            collect_reachable_chirho(root_chirho, child_hash_chirho, seen_chirho)?;
        }
    }
    Ok(())
}

fn load_all_run_results_chirho(root_chirho: &Path) -> Result<Vec<RunResultChirho>> {
    let path_chirho = runs_path_chirho(root_chirho);
    if !path_chirho.exists() {
        return Ok(vec![]);
    }
    let mut runs_chirho = Vec::new();
    let mut run_hashes_chirho = Vec::new();
    for entry_chirho in std::fs::read_dir(&path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?
    {
        let entry_chirho = entry_chirho?;
        if !entry_chirho.file_type()?.is_file() {
            continue;
        }
        let Some(name_chirho) = entry_chirho
            .file_name()
            .to_str()
            .map(|name_chirho| name_chirho.to_string())
        else {
            continue;
        };
        run_hashes_chirho.push(HashChirho(name_chirho));
    }
    run_hashes_chirho.sort();
    for run_hash_chirho in run_hashes_chirho {
        if let Some(result_chirho) =
            cache_chirho::load_sealed_result_chirho(root_chirho, &run_hash_chirho)?
        {
            runs_chirho.push(result_chirho);
        }
    }
    Ok(runs_chirho)
}

fn add_effect_from_run_chirho(
    root_chirho: &Path,
    run_chirho: &HashChirho,
    effect_seq_chirho: Option<u64>,
    effects_chirho: &mut BTreeMap<(HashChirho, u64), DependentEffectChirho>,
) -> Result<()> {
    let Some(result_chirho) = cache_chirho::load_sealed_result_chirho(root_chirho, run_chirho)?
    else {
        return Ok(());
    };
    for effect_chirho in &result_chirho.effects_chirho {
        if effect_seq_chirho
            .map(|seq_chirho| seq_chirho == effect_chirho.seq_chirho)
            .unwrap_or(true)
        {
            insert_dependent_effect_chirho(
                &result_chirho.run_chirho,
                effect_chirho,
                effects_chirho,
            );
        }
    }
    Ok(())
}

fn insert_dependent_effect_chirho(
    run_chirho: &HashChirho,
    effect_chirho: &EffectChirho,
    effects_chirho: &mut BTreeMap<(HashChirho, u64), DependentEffectChirho>,
) {
    effects_chirho
        .entry((run_chirho.clone(), effect_chirho.seq_chirho))
        .or_insert_with(|| DependentEffectChirho {
            run_chirho: run_chirho.clone(),
            effect_seq_chirho: effect_chirho.seq_chirho,
            capability_chirho: effect_chirho.capability_chirho.clone(),
            request_chirho: effect_chirho.request_chirho.clone(),
            response_chirho: effect_chirho.response_chirho.clone(),
        });
}

fn store_node_chirho(root_chirho: &Path, node_chirho: &HamtNodeChirho) -> Result<HashChirho> {
    store_chirho::put_object_chirho(root_chirho, node_chirho)
}

fn hash_node_chirho(node_chirho: &HamtNodeChirho) -> Result<HashChirho> {
    store_chirho::hash_object_chirho(node_chirho)
}

fn load_node_verified_chirho(
    root_chirho: &Path,
    node_hash_chirho: &HashChirho,
) -> Result<HamtNodeChirho> {
    let node_chirho: HamtNodeChirho =
        store_chirho::get_object_chirho(root_chirho, node_hash_chirho)
            .with_context(|| format!("load HAMT node {}", node_hash_chirho.0))?;
    let actual_hash_chirho = store_chirho::hash_object_chirho(&node_chirho)?;
    if actual_hash_chirho != *node_hash_chirho {
        bail!(
            "HAMT node hash mismatch: expected {} actual {}",
            node_hash_chirho.0,
            actual_hash_chirho.0
        );
    }
    Ok(node_chirho)
}

fn validate_index_root_schema_chirho(record_chirho: &PersistentIndexRootChirho) -> Result<()> {
    validate_root_schema_chirho(
        "persistent index root",
        &record_chirho.schema_chirho,
        PERSISTENT_INDEX_ROOT_SCHEMA_CHIRHO,
    )?;
    if record_chirho.kind_chirho != PERSISTENT_INDEX_KIND_CHIRHO {
        bail!(
            "persistent index root kind '{}' is not '{}'",
            record_chirho.kind_chirho,
            PERSISTENT_INDEX_KIND_CHIRHO
        );
    }
    Ok(())
}

fn validate_inverted_provenance_root_schema_chirho(
    record_chirho: &InvertedProvenanceRootChirho,
) -> Result<()> {
    validate_root_schema_chirho(
        "inverted provenance root",
        &record_chirho.schema_chirho,
        INVERTED_PROVENANCE_ROOT_SCHEMA_CHIRHO,
    )?;
    if record_chirho.kind_chirho != INVERTED_PROVENANCE_KIND_CHIRHO {
        bail!(
            "inverted provenance root kind '{}' is not '{}'",
            record_chirho.kind_chirho,
            INVERTED_PROVENANCE_KIND_CHIRHO
        );
    }
    Ok(())
}

fn validate_root_schema_chirho(
    label_chirho: &str,
    schema_chirho: &str,
    expected_chirho: &str,
) -> Result<()> {
    if !schema_chirho.is_empty() && schema_chirho != expected_chirho {
        bail!("{label_chirho} has unsupported schema '{schema_chirho}'");
    }
    Ok(())
}

fn key_hash_chirho(key_chirho: &str) -> String {
    blake3::hash(key_chirho.as_bytes()).to_hex().to_string()
}

fn nibble_label_chirho(key_hash_chirho: &str, depth_chirho: usize) -> Result<String> {
    key_hash_chirho
        .as_bytes()
        .get(depth_chirho)
        .map(|byte_chirho| (*byte_chirho as char).to_string())
        .ok_or_else(|| anyhow!("HAMT depth exceeded key hash length"))
}

#[cfg(test)]
#[path = "index_chirho/tests_chirho.rs"]
mod tests_chirho;
