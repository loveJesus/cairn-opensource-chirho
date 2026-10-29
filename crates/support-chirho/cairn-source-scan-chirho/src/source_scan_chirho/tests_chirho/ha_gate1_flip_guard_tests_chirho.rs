// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

#[path = "ha_gate1_flip_chirho/shared_guard_helpers_tests_chirho.rs"]
mod shared_guard_helpers_chirho;

#[path = "ha_gate1_flip_chirho/authority_runtime_guard_tests_chirho.rs"]
mod authority_runtime_guard_tests_chirho;

#[path = "ha_gate1_flip_chirho/surface_inventory_guard_tests_chirho.rs"]
mod surface_inventory_guard_tests_chirho;

#[path = "ha_gate1_flip_chirho/subscribe_read_only_guard_tests_chirho.rs"]
mod subscribe_read_only_guard_tests_chirho;

#[path = "ha_gate1_flip_chirho/shipping_privacy_absence_guard_tests_chirho.rs"]
mod shipping_privacy_absence_guard_tests_chirho;

// W3 brick-1 job J0a: the frozen ledger-schema-v2 authority-inert guard (ElectedTerm zero-producer),
// grouped with the Gate-1 authority guards.
#[path = "ha_gate1_flip_chirho/w3_j0a_schema_guard_tests_chirho.rs"]
mod w3_j0a_schema_guard_tests_chirho;

#[path = "ha_gate1_flip_chirho/external_drop_source_guard_tests_chirho.rs"]
mod external_drop_source_guard_tests_chirho;
#[path = "ha_gate1_flip_chirho/identity_money_removal_guard_tests_chirho.rs"]
mod identity_money_removal_guard_tests_chirho;
#[path = "ha_gate1_flip_chirho/r6e_ledger_door_guard_tests_chirho.rs"]
mod r6e_ledger_door_guard_tests_chirho;
