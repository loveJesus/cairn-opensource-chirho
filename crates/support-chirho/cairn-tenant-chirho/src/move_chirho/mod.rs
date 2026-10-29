// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Moving a tenant root: the order it happens in, and the signed evidence that it did.
//!
//! `move_stages_chirho` is the rule — one writer, custody before handoff, erasure after, and a move
//! that stays reversible until retirement. `move_attestation_chirho` is what makes each step EVIDENCE
//! rather than an assertion: a verify-only port with no `sign_chirho`, so the party performing a move
//! cannot author the record that it went correctly.
//!
//! Both are pure. Whoever carries bytes and erases keys is an adapter, and the durable log lives in
//! `cairn-tenant-placement-authority-chirho` beside the other attestation stores.

pub mod move_attestation_chirho;
pub mod move_stages_chirho;
