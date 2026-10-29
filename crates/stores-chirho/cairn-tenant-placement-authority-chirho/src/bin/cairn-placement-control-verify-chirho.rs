// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Build a placement registry from a root's DURABLE SIGNED EVIDENCE and print what it says.
//!
//! This is the production caller the CF8 audit asks for: until it existed, `PlacementRegistryChirho`
//! was only ever constructed by tests, and the audit's phrase for the gap is "production callers rather
//! than caller-supplied in-memory values". Nothing here supplies a capacity number, a lifecycle state,
//! or a measurement — every one comes off disk through a signature check.
//!
//! It REPORTS and never decides: no demand is taken and nothing is admitted, so running it cannot move
//! a placement. The verifiers come from `resolve_control_plane_authorities_chirho`, so a key
//! arrangement where one holder speaks for two authorities is refused before any log is read.
//!
//! Output carries node ids, states and capacity numbers only — no key material, no filesystem paths,
//! no request bytes.
//!
//! Optionally it also PROBES a hypothetical placement — `demand=` and `headroom=`, each three
//! comma-separated numbers (cpu millicores, memory bytes, durable bytes). Probing consults the
//! registry's own four-clause admission conjunction and reports the refusals; it still admits nothing
//! and places nothing, so the answer to "why will this not land here" costs no authority.
//!
//! ```text
//! cairn-placement-control-verify-chirho <root> <capacity-key> <lifecycle-key> <topology-key> \
//!     <budget-key> \
//!     <node-id>=<measurement-key> [<node-id>=<measurement-key> ...] \
//!     [demand=<cpu>,<mem>,<durable>] [headroom=<cpu>,<mem>,<durable>]
//! ```

use cairn_placement_chirho::capacity_chirho::capacity_dominance_chirho::AllocatableCapacityChirho;
use cairn_tenant_placement_authority_chirho::control_plane_authorities_chirho::resolve_control_plane_authorities_chirho;
use cairn_tenant_placement_authority_chirho::placement_registry_load_chirho::{
    build_placement_control_plane_report_chirho, load_verified_placement_registry_chirho,
    render_placement_control_plane_report_chirho, PlacementProbeChirho,
};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE_REFUSAL_CHIRHO: &str = "PlacementControlPlaneUsageRefusedChirho";

/// Reserved left-hand sides in the `key=value` arguments, so they can never be read as node ids.
const DEMAND_KEY_CHIRHO: &str = "demand";
const HEADROOM_KEY_CHIRHO: &str = "headroom";

fn parse_capacity_chirho(value_chirho: &str) -> Result<AllocatableCapacityChirho, String> {
    let parts_chirho = value_chirho.split(',').collect::<Vec<_>>();
    if parts_chirho.len() != 3 {
        return Err(USAGE_REFUSAL_CHIRHO.to_string());
    }
    let mut numbers_chirho = [0u64; 3];
    for (slot_chirho, part_chirho) in numbers_chirho.iter_mut().zip(parts_chirho) {
        *slot_chirho = part_chirho
            .parse::<u64>()
            .map_err(|_error_chirho| USAGE_REFUSAL_CHIRHO.to_string())?;
    }
    Ok(AllocatableCapacityChirho {
        cpu_millicores_chirho: numbers_chirho[0],
        memory_bytes_chirho: numbers_chirho[1],
        durable_bytes_chirho: numbers_chirho[2],
    })
}

fn next_utf8_chirho(
    arguments_chirho: &mut impl Iterator<Item = OsString>,
) -> Result<String, &'static str> {
    arguments_chirho
        .next()
        .ok_or(USAGE_REFUSAL_CHIRHO)?
        .into_string()
        .map_err(|_value_chirho| USAGE_REFUSAL_CHIRHO)
}

fn run_chirho() -> Result<String, String> {
    let mut arguments_chirho = std::env::args_os();
    let _program_chirho = arguments_chirho.next();
    let root_chirho = PathBuf::from(next_utf8_chirho(&mut arguments_chirho)?);
    let capacity_key_chirho = next_utf8_chirho(&mut arguments_chirho)?;
    let lifecycle_key_chirho = next_utf8_chirho(&mut arguments_chirho)?;
    let topology_key_chirho = next_utf8_chirho(&mut arguments_chirho)?;
    let budget_key_chirho = next_utf8_chirho(&mut arguments_chirho)?;

    // The node set comes from the pairs, so a node can never be asked for without also naming the key
    // its own reports must carry.
    let mut node_measurement_keys_chirho = BTreeMap::new();
    let mut demand_chirho = None;
    let mut headroom_chirho = None;
    for argument_chirho in arguments_chirho {
        let pair_chirho = argument_chirho
            .into_string()
            .map_err(|_value_chirho| USAGE_REFUSAL_CHIRHO.to_string())?;
        let (left_chirho, right_chirho) = pair_chirho
            .split_once('=')
            .ok_or_else(|| USAGE_REFUSAL_CHIRHO.to_string())?;
        match left_chirho {
            DEMAND_KEY_CHIRHO => demand_chirho = Some(parse_capacity_chirho(right_chirho)?),
            HEADROOM_KEY_CHIRHO => headroom_chirho = Some(parse_capacity_chirho(right_chirho)?),
            node_id_chirho => {
                node_measurement_keys_chirho
                    .insert(node_id_chirho.to_string(), right_chirho.to_string());
            }
        }
    }
    // Headroom without a demand is a request nobody can answer, and defaulting the demand to zero
    // would silently answer a DIFFERENT question than the operator asked.
    if headroom_chirho.is_some() && demand_chirho.is_none() {
        return Err(USAGE_REFUSAL_CHIRHO.to_string());
    }
    let probe_chirho = demand_chirho.map(|demand_chirho| PlacementProbeChirho {
        demand_chirho,
        headroom_chirho: headroom_chirho.unwrap_or(AllocatableCapacityChirho {
            cpu_millicores_chirho: 0,
            memory_bytes_chirho: 0,
            durable_bytes_chirho: 0,
        }),
    });
    if node_measurement_keys_chirho.is_empty() {
        return Err(USAGE_REFUSAL_CHIRHO.to_string());
    }

    let authorities_chirho = resolve_control_plane_authorities_chirho(
        &capacity_key_chirho,
        &lifecycle_key_chirho,
        &topology_key_chirho,
        &budget_key_chirho,
        &node_measurement_keys_chirho,
    )
    .map_err(|refusal_chirho| format!("{refusal_chirho:?}"))?;

    let node_ids_chirho = node_measurement_keys_chirho
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    let registry_chirho = load_verified_placement_registry_chirho(
        &root_chirho,
        &node_ids_chirho,
        authorities_chirho.capacity_registrar_chirho(),
        authorities_chirho.lifecycle_chirho(),
        &authorities_chirho,
    )
    .map_err(|refusal_chirho| format!("{refusal_chirho:?}"))?;

    let report_chirho = build_placement_control_plane_report_chirho(
        &registry_chirho,
        &node_ids_chirho,
        probe_chirho,
    );
    render_placement_control_plane_report_chirho(&report_chirho)
        .map_err(|refusal_chirho| format!("{refusal_chirho:?}"))
}

fn main() -> ExitCode {
    match run_chirho() {
        Ok(rendered_chirho) => {
            println!("{rendered_chirho}");
            ExitCode::SUCCESS
        }
        Err(identity_chirho) => {
            eprintln!("{identity_chirho}");
            ExitCode::FAILURE
        }
    }
}
