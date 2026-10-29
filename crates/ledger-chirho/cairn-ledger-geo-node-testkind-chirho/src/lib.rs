// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Test-kind geo-node compositions: the winner posture with a synthetic reporting-only GD7
//! compensation provider wired through the winner-side door — never a production node.
//!
//! The production `cairn-ledger-geo-node-chirho` binary opens its resident actor through the
//! refusing default door and can complete no compensation. This crate is the ONE hosted-buildable
//! place that reaches a GD7 compensation-provider door, so a hosted item-6 drill can carry a
//! synthetic obligation to `CompletedChirho`. It reaches TWO doors, one per road, and the split is
//! by ELECTION posture rather than by taste:
//!
//! - [`eb_winner_opener_chirho`] — the SERVE road's winner posture, on the shared cluster elector
//!   that carries the winner's accepted handoff marker (door E-B).
//! - [`ea_seeding_opener_chirho`] — the SEEDING road's single-voter posture, injected into the
//!   credits-demo geo-seed road so a hosted drill root can be prepared from a test-kind config
//!   (door E-A).
//!
//! It is confined to test-kind use by two source guards:
//! `gd7_compensation_provider_door_has_no_shipping_binary_caller_chirho` (no shipping file may name
//! a door; its lawful population is the door definitions plus exactly these two files) and
//! `testkind_geo_node_stays_a_dev_only_edge_chirho` (this crate may never be a normal
//! `[dependencies]` edge of a production crate).

pub mod ea_seeding_opener_chirho;
pub mod eb_winner_opener_chirho;
pub mod ec_normal_settlement_opener_chirho;
pub mod operator_control_chirho;
pub mod reporting_provider_chirho;

pub use ea_seeding_opener_chirho::{
    run_testkind_credits_demo_geo_seed_chirho, testkind_seeding_resident_opener_chirho,
};
pub use eb_winner_opener_chirho::{
    open_testkind_winner_resident_with_reporting_provider_chirho, testkind_resident_opener_chirho,
};
pub use ec_normal_settlement_opener_chirho::testkind_normal_settlement_resident_opener_chirho;
pub use operator_control_chirho::{
    send_testkind_cf7_operator_request_chirho, start_testkind_cf7_operator_control_chirho,
    testkind_cf7_operator_socket_path_chirho, verify_cf7_conservation_row_chirho,
    TestkindCf7OperatorOperationChirho, TestkindCf7OperatorOutcomeChirho,
    TestkindCf7OperatorRefusalChirho, TestkindCf7OperatorRequestChirho,
    TestkindCf7OperatorResponseChirho, TestkindCompensationExecutionEvidenceChirho,
    TestkindLedgerHeadBindingChirho,
};
pub use reporting_provider_chirho::{
    TestkindSettlementReportingProviderChirho, TESTKIND_OBSERVATION_REF_CHIRHO,
    TESTKIND_PROVIDER_EFFECT_ID_CHIRHO,
};
