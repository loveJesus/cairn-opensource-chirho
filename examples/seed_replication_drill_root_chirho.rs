// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Seeds a SYNTHETIC, fold-passable replication drill kit under an output directory, for exercising
//! the P3 reference binaries (`replication_source_chirho` / `replica_pull_chirho`) locally or on the
//! test fleet: a source root with real signed Ring-A anchors plus a few content-addressed drill
//! objects; an OPERATOR sign-root (PRIVATE — it stays on the operator machine, never on the fleet);
//! the operator-signed one-line membership roster; the exported source-signed anchor head; and a
//! pubkeys JSON for the pull config. Drill data only — no real root is read or touched. Part of the
//! distributed-HA P3 workflow (`spec-chirho/workflows-chirho/distributed-ha-chirho/`).

use anyhow::{anyhow, Context, Result};
use cairn_chirho::gate1_anchor_chirho::{
    append_gate1_ring_a_anchors_chirho, export_gate1_anchor_head_replication_chirho,
};
use cairn_core_chirho::ports_chirho::ContentStoreChirho;
use cairn_replication_chirho::membership_chirho::{
    unsigned_membership_roster_message_chirho, MembershipActionChirho,
    MembershipRosterRecordChirho, MEMBERSHIP_ROSTER_RECORD_SCHEMA_CHIRHO,
};
use cairn_signer_chirho::signer_chirho;
use cairn_store_fs_chirho::FsContentStoreChirho;
use std::path::Path;

fn main() -> Result<()> {
    let out_dir_chirho = std::env::args().nth(1).ok_or_else(|| {
        anyhow!("usage: seed_replication_drill_root_chirho <out_dir> [region_label]")
    })?;
    let region_label_chirho = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "drill-region-chirho".to_string());
    let out_chirho = Path::new(&out_dir_chirho);
    let source_root_chirho = out_chirho.join("source-root-chirho");
    let operator_root_chirho = out_chirho.join("operator-root-chirho");
    std::fs::create_dir_all(&source_root_chirho).context("create source root")?;
    std::fs::create_dir_all(&operator_root_chirho).context("create operator root")?;

    // Signed Ring-A anchors, so the replica-side fold has genuine digests to verify.
    //
    // CHANGED AT CF6 WAVE-1, and the reduction is stated rather than hidden: this used to seed real
    // ledger activity first, so the anchors covered a NON-EMPTY ledger family. The V1 token writer
    // died with the money spine and has no successor until the V2 ledger, so the ledger family is
    // now anchored empty. The fold, transport and object planes are still exercised end to end --
    // what is no longer exercised is a fold over ledger rows. Restore the seeding when V2 lands.
    append_gate1_ring_a_anchors_chirho(&source_root_chirho).context("append signed anchors")?;
    let head_chirho = export_gate1_anchor_head_replication_chirho(&source_root_chirho)
        .context("export signed anchor head")?;
    let source_pubkey_chirho = head_chirho.key_id_chirho.clone();
    let head_bytes_chirho = serde_json::to_vec(&head_chirho).context("render anchor head")?;

    // A few content-addressed drill objects so the object plane is exercised over the wire.
    let source_store_chirho = FsContentStoreChirho::new_chirho(&source_root_chirho);
    for body_chirho in [
        &b"replication-drill-object-alpha-chirho"[..],
        &b"replication-drill-object-beta-chirho"[..],
        &b"replication-drill-object-gamma-chirho"[..],
    ] {
        source_store_chirho
            .put_chirho(body_chirho)
            .context("seed drill object")?;
    }

    // The operator signs the one-line roster admitting the source. The operator key is the trust
    // root the replica pins — it lives here, on the operator machine, and never ships to the fleet.
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_root_chirho)
        .context("provision/read operator key")?;
    let mut record_chirho = MembershipRosterRecordChirho {
        schema_chirho: MEMBERSHIP_ROSTER_RECORD_SCHEMA_CHIRHO.to_string(),
        seq_chirho: 0,
        action_chirho: MembershipActionChirho::AddNodeChirho,
        node_pubkey_hex_chirho: source_pubkey_chirho.clone(),
        region_label_chirho: region_label_chirho.clone(),
        at_ms_chirho: 1,
        operator_key_id_chirho: operator_pubkey_chirho.clone(),
        sig_chirho: String::new(),
    };
    let message_chirho = unsigned_membership_roster_message_chirho(&record_chirho)
        .context("roster message bytes")?;
    record_chirho.sig_chirho =
        signer_chirho::sign_message_chirho(&operator_root_chirho, &message_chirho)
            .context("sign roster record")?;
    let roster_line_chirho = serde_json::to_vec(&record_chirho).context("render roster record")?;

    let roster_path_chirho = out_chirho.join("roster-chirho.jsonl");
    let head_path_chirho = out_chirho.join("anchor-head-chirho.json");
    let pubkeys_path_chirho = out_chirho.join("drill-pubkeys-chirho.json");
    std::fs::write(
        &roster_path_chirho,
        [roster_line_chirho, b"\n".to_vec()].concat(),
    )
    .context("write roster")?;
    std::fs::write(&head_path_chirho, &head_bytes_chirho).context("write anchor head")?;
    std::fs::write(
        &pubkeys_path_chirho,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_chirho": "replication-drill-pubkeys-v1-chirho",
            "operator_pubkey_hex_chirho": operator_pubkey_chirho,
            "source_pubkey_hex_chirho": source_pubkey_chirho,
            "region_label_chirho": region_label_chirho,
        }))
        .context("render pubkeys")?,
    )
    .context("write pubkeys")?;

    println!("drill kit seeded under {}", out_chirho.display());
    println!(
        "  source root (ship to the SOURCE host): {}",
        source_root_chirho.display()
    );
    println!("  roster / head / pubkeys (ship to the REPLICA host):");
    println!("    {}", roster_path_chirho.display());
    println!("    {}", head_path_chirho.display());
    println!("    {}", pubkeys_path_chirho.display());
    println!(
        "  operator root (PRIVATE, keep here): {}",
        operator_root_chirho.display()
    );
    println!("  operator pubkey: {operator_pubkey_chirho}");
    println!("  source pubkey:   {source_pubkey_chirho}");
    Ok(())
}
