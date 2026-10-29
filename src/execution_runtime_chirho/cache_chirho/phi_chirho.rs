// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The builtin phi run path: pick the one live input of a merge node and pass its hash through
//! the cache unchanged, so a DAG can branch (one side skipped) and rejoin without a wasm body.

use super::*;

/// The one live input of a builtin phi node, and the only place that decides it.
///
/// Every declared input port must have been wired: a phi that received fewer inputs than it
/// declares would otherwise pass "exactly one live" on a port the DAG never fed. Exactly one of
/// the wired inputs must be something other than the skipped stone. The executor loop derives the
/// phi's PRIVACY from this input and the run path passes its HASH through, so both consult this
/// one selector and can never disagree about which input is live. What a phi passes through is
/// the same sealed VALUE its live branch recorded — it authors no plaintext, blob, or private
/// record — while its trace, like every node's, is a public content-addressed line that names
/// the live port, so which branch ran is recoverable from the run result (as it is from the
/// output hash itself).
/// Part of `spec-chirho/workflows-chirho/private-dag-edge-values-chirho.md`.
pub(crate) fn phi_live_input_chirho<'a>(
    root_chirho: &Path,
    node_def_chirho: &NodeDefChirho,
    inputs_chirho: &'a BTreeMap<String, HashChirho>,
) -> Result<(&'a String, &'a HashChirho)> {
    // Every declared port must have arrived. The converse — every arrived port is declared — is
    // the executor's edge gate in `collect_edge_inputs_chirho`, which runs before this selector
    // for every node; a count check here would be a second copy of it that nothing could arm.
    for port_chirho in &node_def_chirho.inputs_chirho {
        if !inputs_chirho.contains_key(&port_chirho.name_chirho) {
            bail!(
                "phi node '{}' declares input port '{}' but the DAG never wired it",
                node_def_chirho.name_chirho,
                port_chirho.name_chirho
            );
        }
    }
    let skipped_hash_chirho = skipped_stone_hash_chirho(root_chirho)?;
    let live_inputs_chirho: Vec<(&String, &HashChirho)> = inputs_chirho
        .iter()
        .filter(|(_port_chirho, hash_chirho)| *hash_chirho != &skipped_hash_chirho)
        .collect();
    if live_inputs_chirho.len() != 1 {
        bail!(
            "phi node '{}' requires exactly one live input; found {}",
            node_def_chirho.name_chirho,
            live_inputs_chirho.len()
        );
    }
    Ok(live_inputs_chirho[0])
}

pub(crate) fn run_phi_node_cached_chirho(
    root_chirho: &Path,
    node_def_chirho: &NodeDefChirho,
    node_hash_chirho: &HashChirho,
    inputs_chirho: &BTreeMap<String, HashChirho>,
    parents_chirho: &[HashChirho],
) -> Result<(RunResultChirho, bool)> {
    let (live_port_chirho, live_hash_chirho) =
        phi_live_input_chirho(root_chirho, node_def_chirho, inputs_chirho)?;
    let key_chirho =
        build_bytes_run_key_for_inputs_chirho(node_def_chirho, node_hash_chirho, inputs_chirho)?;
    let run_hash_chirho = store_chirho::hash_object_chirho(&key_chirho)?;
    store_run_key_chirho(root_chirho, &run_hash_chirho, &key_chirho)?;

    if let Some(cached_chirho) = load_resealable_pure_result_chirho(root_chirho, &run_hash_chirho)?
    {
        // A phi never stores a value: its output IS its live input. A sealed result that names
        // any other hash did not come from this rule — a bug in a later version, or a result
        // re-sealed by whoever holds the root key — so it is refused before its parents are
        // re-sealed rather than served. The seal carries tamper detection; this identity is the
        // belt behind it, and `cached_phi_result_naming_another_hash_is_refused_even_when_sealed`
        // is its arm.
        if cached_chirho
            .outputs_chirho
            .get(&output_port_chirho(node_def_chirho))
            != Some(live_hash_chirho)
        {
            bail!(
                "phi node '{}' cached result does not pass its live input through; refusing it",
                node_def_chirho.name_chirho
            );
        }
        let cached_chirho =
            cached_with_current_parents_chirho(root_chirho, cached_chirho, parents_chirho)?;
        return Ok((cached_chirho, true));
    }

    let mut outputs_chirho = BTreeMap::new();
    outputs_chirho.insert(
        output_port_chirho(node_def_chirho),
        (*live_hash_chirho).clone(),
    );
    let trace_text_chirho = format!(
        "phi node={} live_port={} input_count={}",
        node_def_chirho.name_chirho,
        live_port_chirho,
        inputs_chirho.len()
    );
    let trace_hash_chirho = cas_chirho::add_chirho(root_chirho, trace_text_chirho.as_bytes())?;
    let result_chirho = RunResultChirho {
        run_chirho: run_hash_chirho,
        outputs_chirho,
        effects_chirho: vec![],
        fuel_used_chirho: 0,
        trace_chirho: trace_hash_chirho,
        status_chirho: RunStatusChirho::OkChirho,
        parents_chirho: parents_chirho.to_vec(),
    };
    store_result_chirho(root_chirho, &result_chirho)?;
    Ok((result_chirho, false))
}
