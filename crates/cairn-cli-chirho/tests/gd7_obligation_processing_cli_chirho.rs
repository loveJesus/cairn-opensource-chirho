// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use std::fs;
use std::process::Command;

#[test]
fn gd7_obligation_processing_cli_displays_held_manual_terminal_chirho() {
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-gd7-cli-held-manual-{}-chirho",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root_chirho);
    let state_dir_chirho = root_chirho
        .join("gd7-reconciliation-chirho")
        .join("obligation-processing-chirho")
        .join("01")
        .join("23");
    fs::create_dir_all(&state_dir_chirho).expect("create CLI state directory");
    let state_path_chirho = state_dir_chirho
        .join("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.json");
    fs::write(
        state_path_chirho,
        r#"{
  "schema_chirho":"gd7-obligation-processing-v1-chirho",
  "mint_identity_digest_chirho":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "obligation_receipt_ref_chirho":"receipt-cli-held-manual-chirho",
  "canonical_obligation_digest_chirho":"abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
  "inverse_authority_ref_chirho":"inverse-cli-held-manual-chirho",
  "action_idempotency_key_chirho":"action-cli-held-manual-chirho",
  "provider_intent_chirho":null,
  "provider_observation_chirho":null,
  "journal_receipt_chirho":null,
  "terminal_progress_chirho":"held_manual_chirho"
}"#,
    )
    .expect("write CLI HeldManual state");

    let output_chirho = Command::new(env!("CARGO_BIN_EXE_cairn-chirho"))
        .args([
            "--root",
            root_chirho.to_str().expect("UTF-8 test root"),
            "gd7-obligation-processing-list",
        ])
        .output()
        .expect("run GD7 obligation CLI");
    assert!(output_chirho.status.success());
    let stdout_chirho = String::from_utf8(output_chirho.stdout).expect("CLI UTF-8 output");
    assert!(stdout_chirho.contains("VALID\tHeldManualChirho\t"));
    fs::remove_dir_all(root_chirho).expect("remove CLI state directory");
}
