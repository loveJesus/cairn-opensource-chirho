// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Test modules for the writer elector, grouped in one subdir so the crate's `src/` stays under the
//! itty-bitty-scrollbars entry cap (and A1.2+ can add their own test modules without crowding it).
//! Declaration-only: each submodule is byte-for-byte what it was when it lived flat in `src/`.
//! `election_test_support_chirho` holds the shared `pub(crate)` helpers the other modules use as
//! `super::election_test_support_chirho`.

mod durable_store_tests_chirho;
mod dynamic_membership_a1_2_tests_chirho;
mod dynamic_membership_a1_3_tests_chirho;
mod election_latency_tests_chirho;
mod election_safety_chaos_tests_chirho;
mod election_test_support_chirho;
mod elector_port_tests_chirho;
mod lease_tier_wire_tests_chirho;
mod local_append_authority_tests_chirho;
mod raft_elector_tests_chirho;
mod raft_wire_tests_chirho;
mod repro_snap_dos_chirho;
mod shadow_canary_chirho;
