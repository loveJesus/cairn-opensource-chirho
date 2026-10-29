// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::strand_fence_liveness_tests_chirho::ElectorMeshChirho;
use super::*;

#[test]
fn deposed_loss_witness_reaches_the_final_sink_and_refuses_by_exact_authority_identity_chirho() {
    with_unbound_resident_fixture_chirho(
        "resident-final-sink-loss-witness",
        |root_chirho,
         group_chirho,
         local_node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let mesh_chirho = ElectorMeshChirho::new_chirho(group_chirho, local_node_chirho);
            let opening_term_chirho = mesh_chirho.elect_chirho(1, None);
            let birth_permit_chirho = ResidentLedgerBirthPermitChirho::for_test_chirho(
                root_chirho,
                journal_path_chirho.clone(),
                cluster_id_chirho.clone(),
                0,
            );
            drop(
                ResidentLedgerAuthorityChirho::create_bound_preactivation_chirho(
                    birth_permit_chirho,
                    ports_chirho,
                    mesh_chirho
                        .node_chirho(1)
                        .local_append_authority_handle_chirho(),
                )
                .expect("the resident is born under node 1's real election"),
            );
            let mut resident_chirho =
                ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                    root_chirho,
                    ports_chirho,
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                    mesh_chirho
                        .node_chirho(1)
                        .local_append_authority_handle_chirho(),
                )
                .expect("the resident opens under the same elected handle");

            let current_receipt_chirho = resident_chirho
                .record_testkind_loss_witness_chirho(resident_mint_request_chirho(
                    1,
                    "loss-witness-current-control-chirho",
                ))
                .expect("the same sink admits the current resident before deposition");
            assert_eq!(current_receipt_chirho.append_chirho.seq_chirho, 1);

            let higher_term_chirho = mesh_chirho.elect_chirho(2, Some(1));
            assert!(
                higher_term_chirho > opening_term_chirho,
                "the deposing election must advance the real raft term"
            );
            assert!(
                mesh_chirho
                    .node_chirho(2)
                    .current_leadership_chirho()
                    .is_leader_chirho
            );
            assert!(
                !mesh_chirho
                    .node_chirho(1)
                    .current_leadership_chirho()
                    .is_leader_chirho
            );

            let bytes_before_chirho = snapshot_files_chirho(root_chirho);
            let refusal_chirho = resident_chirho
                .record_testkind_loss_witness_chirho(resident_mint_request_chirho(
                    1,
                    "loss-witness-deposed-arm-chirho",
                ))
                .expect_err("the deposed resident must be rejected by the final sink");
            assert_eq!(
                refusal_chirho,
                ResidentLedgerAuthorityRefusalChirho::LocalGenerationRefusedChirho {
                    reason_chirho: LocalAppendAuthorityRefusalChirho::NotLocalLeaderChirho,
                },
                "only the sink authority identity carries this proof; neighbouring refusals do not"
            );
            assert_eq!(
                snapshot_files_chirho(root_chirho),
                bytes_before_chirho,
                "byte invariance is an adjacent safety assertion, not the authority proof"
            );
        },
    );
}
