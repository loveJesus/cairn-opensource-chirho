// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! A private DAG can branch and rejoin: a builtin phi whose live input is a private value passes
//! it through under the same subject — no plaintext in public CAS, no record authored by the phi,
//! the merge cached on replay — and the fences around it (rebind, unwired port, two/zero live) hold.
//!
//! The v1 fence this replaces read `private DAG inputs through builtin phi nodes are not supported`.
//! It arrived with the private-propagation machinery itself as a scope line, with no hazard and no
//! test behind it. These arms are the hazard analysis it never had.

use super::tests_chirho::{
    edge_chirho, store_bytes_node_chirho, store_skipped_node_chirho, tmp_root_chirho,
};
use super::*;
use crate::model_chirho::{
    builtin_phi_node_def_chirho, EdgePrivacyChirho, EdgePrivacySubjectSourceChirho,
    RequestContextChirho, RunStatusChirho,
};

const SUBJECT_CHIRHO: &str = "user/phi-private-branch-chirho";

fn request_context_chirho() -> RequestContextChirho {
    RequestContextChirho {
        user_principal_chirho: SUBJECT_CHIRHO.to_string(),
        app_chirho: "phi-private-branch-app-chirho".to_string(),
        owner_principal_chirho: "owner/phi-private-branch-chirho".to_string(),
        client_id_chirho: "browser-session-chirho".to_string(),
        token_hash_chirho: "token-phi-private-branch-chirho".to_string(),
        price_book_chirho: None,
        billing_policy_chirho: None,
        key_limit_chirho: None,
    }
}

fn private_edge_chirho(
    from_node_chirho: &HashChirho,
    to_node_chirho: &HashChirho,
    to_port_chirho: &str,
) -> EdgeChirho {
    let mut edge_chirho = edge_chirho(from_node_chirho, "out", to_node_chirho, to_port_chirho);
    edge_chirho.privacy_chirho = Some(EdgePrivacyChirho::PrivateBlobRefChirho {
        subject_source_chirho: EdgePrivacySubjectSourceChirho::RequestUserChirho,
    });
    edge_chirho
}

fn store_phi_chirho(root_chirho: &Path, input_ports_chirho: &[&str]) -> HashChirho {
    let schema_hash_chirho = cas_chirho::add_chirho(root_chirho, b"bytes").unwrap();
    let ports_chirho: Vec<String> = input_ports_chirho
        .iter()
        .map(|port_chirho| (*port_chirho).to_string())
        .collect();
    let node_chirho =
        builtin_phi_node_def_chirho("merge_chirho", &ports_chirho, "page", schema_hash_chirho);
    store_chirho::put_object_chirho(root_chirho, &node_chirho).unwrap()
}

/// Both branch roots are source nodes (the executor feeds the private request to every node with
/// no incoming edge); `live_port_chirho` names the phi port the live branch reaches.
struct BranchingDagChirho {
    dag_chirho: DagChirho,
    live_hash_chirho: HashChirho,
    phi_hash_chirho: HashChirho,
}

fn branching_dag_chirho(root_chirho: &Path, live_port_chirho: &str) -> BranchingDagChirho {
    let upcase_wat_chirho = include_str!("../../../examples-chirho/upcase-chirho.wat");
    let (_live_chirho, live_hash_chirho) = store_bytes_node_chirho(
        root_chirho,
        "render_live_chirho",
        upcase_wat_chirho.as_bytes(),
        "upcase_chirho",
    );
    let skip_hash_chirho = store_skipped_node_chirho(root_chirho, "render_skipped_chirho");
    let phi_hash_chirho = store_phi_chirho(root_chirho, &["rejected", "saved"]);
    let skipped_port_chirho = if live_port_chirho == "saved" {
        "rejected"
    } else {
        "saved"
    };
    BranchingDagChirho {
        dag_chirho: DagChirho {
            nodes_chirho: vec![
                live_hash_chirho.clone(),
                skip_hash_chirho.clone(),
                phi_hash_chirho.clone(),
            ],
            edges_chirho: vec![
                private_edge_chirho(&live_hash_chirho, &phi_hash_chirho, live_port_chirho),
                private_edge_chirho(&skip_hash_chirho, &phi_hash_chirho, skipped_port_chirho),
            ],
        },
        live_hash_chirho,
        phi_hash_chirho,
    }
}

fn run_private_chirho(
    root_chirho: &Path,
    dag_chirho: &DagChirho,
    input_chirho: &[u8],
) -> Result<DagRunReportChirho> {
    let context_chirho = request_context_chirho();
    run_dag_with_context_and_private_input_chirho(
        root_chirho,
        dag_chirho,
        SUBJECT_CHIRHO,
        input_chirho,
        Some(&context_chirho),
    )
}

fn output_of_chirho(
    root_chirho: &Path,
    report_chirho: &DagRunReportChirho,
    node_name_chirho: &str,
    port_chirho: &str,
) -> HashChirho {
    let run_chirho = report_chirho
        .node_runs_chirho
        .iter()
        .find(|run_chirho| run_chirho.node_name_chirho == node_name_chirho)
        .unwrap_or_else(|| panic!("{node_name_chirho} ran"));
    cache_chirho::load_result_chirho(root_chirho, &run_chirho.run_chirho)
        .unwrap()
        .unwrap()
        .outputs_chirho
        .get(port_chirho)
        .unwrap_or_else(|| panic!("{node_name_chirho} produced {port_chirho}"))
        .clone()
}

fn assert_private_phi_pass_through_chirho(live_port_chirho: &str) {
    let root_chirho = tmp_root_chirho();
    let fixture_chirho = branching_dag_chirho(&root_chirho, live_port_chirho);

    let report_chirho = run_private_chirho(&root_chirho, &fixture_chirho.dag_chirho, b"secret")
        .unwrap_or_else(|error_chirho| {
            panic!("a private DAG must branch through a phi (live port {live_port_chirho}): {error_chirho}")
        });
    assert_eq!(report_chirho.payload_chirho, b"SECRET");

    let live_out_chirho =
        output_of_chirho(&root_chirho, &report_chirho, "render_live_chirho", "out");
    let phi_out_chirho = output_of_chirho(&root_chirho, &report_chirho, "merge_chirho", "page");
    assert_eq!(
        phi_out_chirho, live_out_chirho,
        "the phi output IS the live input, by hash"
    );
    assert_eq!(report_chirho.payload_hash_chirho, phi_out_chirho);
    assert!(
        cas_chirho::get_chirho(&root_chirho, &phi_out_chirho).is_err(),
        "a private value that crossed a phi must never rest in public CAS"
    );
    assert!(
        dag_private_value_chirho::verified_private_dag_value_record_for_subject_chirho(
            &root_chirho,
            SUBJECT_CHIRHO,
            &phi_out_chirho,
        )
        .unwrap()
        .is_some(),
        "the value stays readable through its subject's verified record"
    );
    let records_chirho =
        dag_private_value_chirho::load_private_dag_value_records_chirho(&root_chirho).unwrap();
    assert!(
        records_chirho
            .iter()
            .all(|record_chirho| record_chirho.node_chirho.as_ref()
                != Some(&fixture_chirho.phi_hash_chirho)),
        "a phi stores nothing: no private record may name it as the producing node"
    );
    assert!(
        records_chirho
            .iter()
            .any(|record_chirho| record_chirho.node_chirho.as_ref()
                == Some(&fixture_chirho.live_hash_chirho)),
        "positive control: the live branch DID author the record the phi passes through"
    );

    let second_chirho =
        run_private_chirho(&root_chirho, &fixture_chirho.dag_chirho, b"secret").expect("replay");
    assert_eq!(second_chirho.payload_chirho, b"SECRET");
    assert!(
        second_chirho
            .node_runs_chirho
            .iter()
            .all(|run_chirho| run_chirho.cached_chirho),
        "every node, the phi included, replays from the cache"
    );
    crate::verify_chirho::verify_run_cache_chirho(&root_chirho)
        .expect("run-cache verification covers the private phi run");

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn private_live_input_passes_through_the_phi_under_its_subject_saved_side_chirho() {
    assert_private_phi_pass_through_chirho("saved");
}

#[test]
fn private_live_input_passes_through_the_phi_under_its_subject_rejected_side_chirho() {
    assert_private_phi_pass_through_chirho("rejected");
}

#[test]
fn phi_output_cannot_be_rebound_to_another_subject_chirho() {
    let root_chirho = tmp_root_chirho();
    let fixture_chirho = branching_dag_chirho(&root_chirho, "saved");
    let reverse_wat_chirho = include_str!("../../../examples-chirho/reverse-chirho.wat");
    let (_tail_chirho, tail_hash_chirho) = store_bytes_node_chirho(
        &root_chirho,
        "tail_chirho",
        reverse_wat_chirho.as_bytes(),
        "reverse_chirho",
    );
    let mut dag_chirho = fixture_chirho.dag_chirho.clone();
    dag_chirho.nodes_chirho.push(tail_hash_chirho.clone());
    let mut rebind_edge_chirho = edge_chirho(
        &fixture_chirho.phi_hash_chirho,
        "page",
        &tail_hash_chirho,
        "in",
    );
    rebind_edge_chirho.privacy_chirho = Some(EdgePrivacyChirho::PrivateBlobRefChirho {
        subject_source_chirho: EdgePrivacySubjectSourceChirho::AppSubjectChirho,
    });
    dag_chirho.edges_chirho.push(rebind_edge_chirho);

    let error_chirho = run_private_chirho(&root_chirho, &dag_chirho, b"secret")
        .expect_err(
            "a phi output owned by the request user cannot be re-sealed for the app subject",
        )
        .to_string();
    assert!(
        error_chirho.contains("cannot rebind inherited private data to a different subject"),
        "{error_chirho}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn phi_with_an_unwired_declared_port_refuses_chirho() {
    let root_chirho = tmp_root_chirho();
    let fixture_chirho = branching_dag_chirho(&root_chirho, "saved");
    let three_port_phi_chirho = store_phi_chirho(&root_chirho, &["rejected", "saved", "unwired"]);
    let dag_chirho = DagChirho {
        nodes_chirho: vec![
            fixture_chirho.dag_chirho.nodes_chirho[0].clone(),
            fixture_chirho.dag_chirho.nodes_chirho[1].clone(),
            three_port_phi_chirho.clone(),
        ],
        edges_chirho: fixture_chirho
            .dag_chirho
            .edges_chirho
            .iter()
            .map(|edge_chirho| EdgeChirho {
                to_node_chirho: three_port_phi_chirho.clone(),
                ..edge_chirho.clone()
            })
            .collect(),
    };
    let error_chirho = run_private_chirho(&root_chirho, &dag_chirho, b"secret")
        .expect_err("a phi port the DAG never wired must not be silently absent")
        .to_string();
    assert!(
        error_chirho.contains("declares input port 'unwired' but the DAG never wired it"),
        "{error_chirho}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn private_phi_still_refuses_two_live_and_zero_live_inputs_chirho() {
    let root_chirho = tmp_root_chirho();
    let upcase_wat_chirho = include_str!("../../../examples-chirho/upcase-chirho.wat");
    let (_a_chirho, a_hash_chirho) = store_bytes_node_chirho(
        &root_chirho,
        "left_live_chirho",
        upcase_wat_chirho.as_bytes(),
        "upcase_chirho",
    );
    let (_b_chirho, b_hash_chirho) = store_bytes_node_chirho(
        &root_chirho,
        "right_live_chirho",
        upcase_wat_chirho.as_bytes(),
        "upcase_chirho",
    );
    let phi_hash_chirho = store_phi_chirho(&root_chirho, &["rejected", "saved"]);
    let two_live_chirho = DagChirho {
        nodes_chirho: vec![
            a_hash_chirho.clone(),
            b_hash_chirho.clone(),
            phi_hash_chirho.clone(),
        ],
        edges_chirho: vec![
            private_edge_chirho(&a_hash_chirho, &phi_hash_chirho, "saved"),
            private_edge_chirho(&b_hash_chirho, &phi_hash_chirho, "rejected"),
        ],
    };
    let error_chirho = run_private_chirho(&root_chirho, &two_live_chirho, b"secret")
        .expect_err("two live private inputs")
        .to_string();
    assert!(
        error_chirho.contains("requires exactly one live input; found 2"),
        "{error_chirho}"
    );

    let left_skip_chirho = store_skipped_node_chirho(&root_chirho, "left_skip_chirho");
    let right_skip_chirho = store_skipped_node_chirho(&root_chirho, "right_skip_chirho");
    let phi2_hash_chirho = store_phi_chirho(&root_chirho, &["rejected", "saved"]);
    let zero_live_chirho = DagChirho {
        nodes_chirho: vec![
            left_skip_chirho.clone(),
            right_skip_chirho.clone(),
            phi2_hash_chirho.clone(),
        ],
        edges_chirho: vec![
            private_edge_chirho(&left_skip_chirho, &phi2_hash_chirho, "saved"),
            private_edge_chirho(&right_skip_chirho, &phi2_hash_chirho, "rejected"),
        ],
    };
    let error_chirho = run_private_chirho(&root_chirho, &zero_live_chirho, b"secret")
        .expect_err("zero live private inputs")
        .to_string();
    assert!(
        error_chirho.contains("requires exactly one live input; found 0"),
        "{error_chirho}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// The defect the end-to-end tree test found: on an authenticated route every node def is given
/// the request's identity/app-context capabilities, and the skipped path used that contextual def
/// to decide "pure or effect" — so a pure node downstream of a skipped blessed write refused with
/// `declares no executable effect capability` instead of skipping. This is the `render_saved`
/// position of every branching private DAG.
#[test]
fn pure_node_skipped_under_request_context_records_no_effect_chirho() {
    let root_chirho = tmp_root_chirho();
    let upcase_wat_chirho = include_str!("../../../examples-chirho/upcase-chirho.wat");
    let skip_hash_chirho = store_skipped_node_chirho(&root_chirho, "build_invalid_chirho");
    let (_pure_chirho, pure_hash_chirho) = store_bytes_node_chirho(
        &root_chirho,
        "render_after_skip_chirho",
        upcase_wat_chirho.as_bytes(),
        "upcase_chirho",
    );
    let (_live_chirho, live_hash_chirho) = store_bytes_node_chirho(
        &root_chirho,
        "render_live_chirho",
        upcase_wat_chirho.as_bytes(),
        "upcase_chirho",
    );
    let phi_hash_chirho = store_phi_chirho(&root_chirho, &["rejected", "saved"]);
    let dag_chirho = DagChirho {
        nodes_chirho: vec![
            skip_hash_chirho.clone(),
            pure_hash_chirho.clone(),
            live_hash_chirho.clone(),
            phi_hash_chirho.clone(),
        ],
        edges_chirho: vec![
            private_edge_chirho(&skip_hash_chirho, &pure_hash_chirho, "in"),
            private_edge_chirho(&pure_hash_chirho, &phi_hash_chirho, "saved"),
            private_edge_chirho(&live_hash_chirho, &phi_hash_chirho, "rejected"),
        ],
    };
    let report_chirho = run_private_chirho(&root_chirho, &dag_chirho, b"secret")
        .expect("a pure node fed the stone on an authenticated route is skipped, not refused");
    assert_eq!(report_chirho.payload_chirho, b"SECRET");
    let skipped_run_chirho = report_chirho
        .node_runs_chirho
        .iter()
        .find(|run_chirho| run_chirho.node_name_chirho == "render_after_skip_chirho")
        .unwrap();
    let skipped_result_chirho =
        cache_chirho::load_result_chirho(&root_chirho, &skipped_run_chirho.run_chirho)
            .unwrap()
            .unwrap();
    assert!(matches!(
        skipped_result_chirho.status_chirho,
        RunStatusChirho::SkippedChirho { .. }
    ));
    assert!(
        skipped_result_chirho.effects_chirho.is_empty(),
        "a skipped PURE node records no effect, context or not"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// claude2's M1 (audit of 00008db4): with the phi's declared ports all skipped, an edge into a
/// port the phi never declared would have been the one live input and its value the phi's output.
/// The executor's edge gate now refuses the edge for every node, phi or not, before any selector
/// runs; the arm asserts the refusal by identity, and that nothing about the phi rule was reached.
#[test]
fn edge_into_an_undeclared_phi_port_is_refused_before_the_selector_chirho() {
    let root_chirho = tmp_root_chirho();
    let upcase_wat_chirho = include_str!("../../../examples-chirho/upcase-chirho.wat");
    let left_skip_chirho = store_skipped_node_chirho(&root_chirho, "left_skip_chirho");
    let right_skip_chirho = store_skipped_node_chirho(&root_chirho, "right_skip_chirho");
    let (_smuggle_chirho, smuggle_hash_chirho) = store_bytes_node_chirho(
        &root_chirho,
        "smuggle_chirho",
        upcase_wat_chirho.as_bytes(),
        "upcase_chirho",
    );
    let phi_hash_chirho = store_phi_chirho(&root_chirho, &["rejected", "saved"]);
    let dag_chirho = DagChirho {
        nodes_chirho: vec![
            left_skip_chirho.clone(),
            right_skip_chirho.clone(),
            smuggle_hash_chirho.clone(),
            phi_hash_chirho.clone(),
        ],
        edges_chirho: vec![
            private_edge_chirho(&left_skip_chirho, &phi_hash_chirho, "saved"),
            private_edge_chirho(&right_skip_chirho, &phi_hash_chirho, "rejected"),
            private_edge_chirho(&smuggle_hash_chirho, &phi_hash_chirho, "undeclared"),
        ],
    };
    let error_chirho = run_private_chirho(&root_chirho, &dag_chirho, b"secret")
        .expect_err("an undeclared phi port must not become the live input")
        .to_string();
    assert!(
        error_chirho
            .contains("targets input port 'undeclared', which 'merge_chirho' does not declare"),
        "{error_chirho}"
    );
    assert!(
        !error_chirho.contains("exactly one live input"),
        "the phi selector must never have been consulted: {error_chirho}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// The same gate on an ordinary node, so it is pinned as the executor's rule rather than a phi
/// special case.
#[test]
fn edge_into_an_undeclared_port_of_a_pure_node_is_refused_chirho() {
    let root_chirho = tmp_root_chirho();
    let upcase_wat_chirho = include_str!("../../../examples-chirho/upcase-chirho.wat");
    let (_a_chirho, a_hash_chirho) = store_bytes_node_chirho(
        &root_chirho,
        "first_chirho",
        upcase_wat_chirho.as_bytes(),
        "upcase_chirho",
    );
    let (_b_chirho, b_hash_chirho) = store_bytes_node_chirho(
        &root_chirho,
        "second_chirho",
        upcase_wat_chirho.as_bytes(),
        "upcase_chirho",
    );
    let dag_chirho = DagChirho {
        nodes_chirho: vec![a_hash_chirho.clone(), b_hash_chirho.clone()],
        edges_chirho: vec![edge_chirho(
            &a_hash_chirho,
            "out",
            &b_hash_chirho,
            "sideways",
        )],
    };
    let error_chirho = run_dag_chirho(&root_chirho, &dag_chirho, b"hello")
        .expect_err("a pure node's undeclared port refuses too")
        .to_string();
    assert!(
        error_chirho
            .contains("targets input port 'sideways', which 'second_chirho' does not declare"),
        "{error_chirho}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// claude2's M2: the cached-output identity is the belt behind the run-result seal. A result that
/// is VALIDLY sealed (the root key signed it — a later bug, or whoever holds the key) but names a
/// hash other than the live input must still be refused, or the phi would serve a value its rule
/// never chose.
#[test]
fn cached_phi_result_naming_another_hash_is_refused_even_when_sealed_chirho() {
    let root_chirho = tmp_root_chirho();
    let fixture_chirho = branching_dag_chirho(&root_chirho, "saved");
    let report_chirho =
        run_private_chirho(&root_chirho, &fixture_chirho.dag_chirho, b"secret").unwrap();
    let phi_run_chirho = report_chirho
        .node_runs_chirho
        .iter()
        .find(|run_chirho| run_chirho.node_name_chirho == "merge_chirho")
        .unwrap()
        .run_chirho
        .clone();
    let mut forged_chirho = cache_chirho::load_result_chirho(&root_chirho, &phi_run_chirho)
        .unwrap()
        .unwrap();
    let decoy_chirho = cas_chirho::add_chirho(&root_chirho, b"not the live input").unwrap();
    assert_ne!(
        forged_chirho.outputs_chirho.get("page"),
        Some(&decoy_chirho)
    );
    forged_chirho
        .outputs_chirho
        .insert("page".to_string(), decoy_chirho.clone());
    // Re-store through the production path so the forged result carries a VALID seal: the arm is
    // about a wrong-but-authorised result, not about tamper the seal already catches.
    cache_chirho::store_result_chirho(&root_chirho, &forged_chirho).unwrap();
    assert_eq!(
        cache_chirho::load_sealed_result_chirho(&root_chirho, &phi_run_chirho)
            .unwrap()
            .unwrap()
            .outputs_chirho
            .get("page"),
        Some(&decoy_chirho),
        "positive control: the forged result loads with a valid seal"
    );

    let error_chirho = run_private_chirho(&root_chirho, &fixture_chirho.dag_chirho, b"secret")
        .expect_err("a sealed result naming another hash must not be served")
        .to_string();
    assert!(
        error_chirho.contains("cached result does not pass its live input through"),
        "{error_chirho}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}
