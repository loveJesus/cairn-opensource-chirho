// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use std::fs::{DirBuilder, File};
use std::io::{BufRead, BufReader};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::Instant;

const CREDENTIAL_CHIRHO: &str = "component-fixture-credential-123456-chirho";
const PRIVATE_A_CHIRHO: &str = "privatealphaunitexamplechirho";
const PRIVATE_B_CHIRHO: &str = "privatebetaunitexamplechirho";
static SEQUENCE_CHIRHO: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

struct FixtureChirho {
    parent_chirho: PathBuf,
}

impl FixtureChirho {
    fn new_chirho() -> Self {
        let path_chirho = std::env::temp_dir().join(format!(
            "transient-example-{}-{}-{}-chirho",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            SEQUENCE_CHIRHO.fetch_add(1, Ordering::Relaxed)
        ));
        DirBuilder::new().mode(0o700).create(&path_chirho).unwrap();
        let parent_chirho = path_chirho.canonicalize().unwrap();
        std::fs::write(parent_chirho.join("credential-chirho"), CREDENTIAL_CHIRHO).unwrap();
        std::fs::set_permissions(
            parent_chirho.join("credential-chirho"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        std::fs::write(
            parent_chirho.join("node-chirho.wat"),
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../../examples-chirho/upcase-chirho.wat"
            )),
        )
        .unwrap();
        let manifest_chirho = serde_json::json!({
            "schema_chirho":cairn_model_app_chirho::APP_SOURCE_MANIFEST_SCHEMA_CHIRHO, "app_chirho":"fixture-chirho", "owner_chirho":"owner/unused-chirho",
            "nodes_chirho":[{"id_chirho":"node_chirho", "name_chirho":"upcase_chirho", "entry_chirho":"upcase_chirho", "fuel_chirho":1000000,
                "source_chirho":{"kind_chirho":"path-chirho","path_chirho":"node-chirho.wat"}}],
            "dags_chirho":[{"id_chirho":"dag_chirho", "nodes_chirho":["node_chirho"]}],
            "deploy_chirho":{
                "root_chirho":{"kind_chirho":"dag-id-chirho","id_chirho":"dag_chirho"},
                "request_access_policy_chirho":cairn_model_app_chirho::AppRequestAccessPolicyChirho::AuthenticatedChirho,
                "input_mode_chirho":cairn_model_app_chirho::AppInputModeChirho::PlainChirho,
                "routes_chirho":[{"route_chirho":"review-chirho", "source_chirho":{"kind_chirho":"dag-id-chirho","id_chirho":"dag_chirho"},
                    "input_mode_chirho":cairn_model_app_chirho::AppInputModeChirho::PrivateBlobRefChirho{subject_chirho:"request-user-chirho".into(),safe_metadata_chirho:Vec::new()},
                    "request_body_policy_chirho":cairn_model_app_chirho::AppRouteRequestBodyPolicyChirho::AcceptBodyChirho,
                    "response_content_type_chirho":"text/html"}]}});
        std::fs::write(
            parent_chirho.join("manifest-chirho.json"),
            serde_json::to_vec(&manifest_chirho).unwrap(),
        )
        .unwrap();
        Self { parent_chirho }
    }

    fn path_chirho(&self, name_chirho: &str) -> PathBuf {
        self.parent_chirho.join(name_chirho)
    }

    fn command_chirho(&self) -> Command {
        let binary_chirho = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .join("transient_review_testkind_serve_chirho");
        assert!(
            binary_chirho.is_file(),
            "build the example binary before its subprocess tests"
        );
        let mut command_chirho = Command::new(binary_chirho);
        command_chirho.env("CAIRN_TESTKIND_TRANSIENT_REVIEW_CHIRHO", "1");
        for (flag_chirho, path_chirho) in [
            ("--root-chirho", self.path_chirho("root-chirho")),
            (
                "--manifest-chirho",
                self.path_chirho("manifest-chirho.json"),
            ),
            (
                "--credential-file-chirho",
                self.path_chirho("credential-chirho"),
            ),
            ("--session-out-chirho", self.path_chirho("cookie-chirho")),
            ("--stop-file-chirho", self.path_chirho("stop-chirho")),
        ] {
            command_chirho.arg(flag_chirho).arg(path_chirho);
        }
        command_chirho.args(["--tenant-chirho", "unit-chirho", "--port-chirho", "0"]);
        command_chirho
    }

    fn start_chirho(&self) -> RunningChirho {
        let mut child_chirho = self
            .command_chirho()
            .stdout(Stdio::piped())
            .stderr(File::create(self.path_chirho("stderr-chirho")).unwrap())
            .spawn()
            .unwrap();
        let stdout_chirho = child_chirho.stdout.take().unwrap();
        let (send_chirho, frames_chirho) = channel();
        let reader_chirho = std::thread::spawn(move || {
            for line_chirho in BufReader::new(stdout_chirho).lines() {
                let line_chirho = line_chirho.unwrap();
                assert!(line_chirho.len() <= 4096, "producer frame bound");
                let frame_chirho: serde_json::Value =
                    serde_json::from_str(&line_chirho).expect("producer JSON frame");
                if send_chirho.send(frame_chirho).is_err() {
                    break;
                }
            }
        });
        RunningChirho {
            child_chirho,
            frames_chirho,
            reader_chirho: Some(reader_chirho),
        }
    }
}

impl Drop for FixtureChirho {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.parent_chirho).unwrap();
    }
}

struct RunningChirho {
    child_chirho: Child,
    frames_chirho: Receiver<serde_json::Value>,
    reader_chirho: Option<std::thread::JoinHandle<()>>,
}

impl RunningChirho {
    fn frame_chirho(&self, phase_chirho: &str) -> serde_json::Value {
        let frame_chirho = self
            .frames_chirho
            .recv_timeout(Duration::from_secs(40))
            .expect("producer phase missing");
        assert_eq!(
            frame_chirho["schema_chirho"],
            "transient-review-fixture-v1-chirho"
        );
        assert_eq!(frame_chirho["phase_chirho"], phase_chirho);
        assert_eq!(frame_chirho["read_authority_test_double_chirho"], true);
        frame_chirho
    }

    fn wait_chirho(&mut self) -> std::process::ExitStatus {
        let deadline_chirho = Instant::now() + Duration::from_secs(40);
        loop {
            if let Some(status_chirho) = self.child_chirho.try_wait().unwrap() {
                return status_chirho;
            }
            assert!(Instant::now() < deadline_chirho, "fixture did not stop");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for RunningChirho {
    fn drop(&mut self) {
        let _ = self.child_chirho.kill();
        let _ = self.child_chirho.wait();
        if let Some(reader_chirho) = self.reader_chirho.take() {
            reader_chirho.join().unwrap();
        }
    }
}

#[test]
fn no_opt_in_refuses_before_root_or_cookie_creation_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    let result_chirho = fixture_chirho
        .command_chirho()
        .env_remove("CAIRN_TESTKIND_TRANSIENT_REVIEW_CHIRHO")
        .output()
        .unwrap();
    assert!(!fixture_chirho.path_chirho("root-chirho").exists());
    assert!(!fixture_chirho.path_chirho("cookie-chirho").exists());
    assert_eq!(result_chirho.status.code(), Some(2));
    assert_eq!(
        result_chirho.stderr,
        b"TransientReviewOptInRequiredChirho\n"
    );
}

#[test]
fn existing_root_and_output_are_never_adopted_or_overwritten_chirho() {
    for collision_chirho in ["root-chirho", "cookie-chirho"] {
        let fixture_chirho = FixtureChirho::new_chirho();
        std::fs::write(
            fixture_chirho.path_chirho(collision_chirho),
            b"existing-chirho",
        )
        .unwrap();
        let result_chirho = fixture_chirho.command_chirho().output().unwrap();
        assert!(!result_chirho.status.success());
        assert_eq!(
            std::fs::read(fixture_chirho.path_chirho(collision_chirho)).unwrap(),
            b"existing-chirho"
        );
        assert_eq!(
            result_chirho.stderr,
            b"TransientReviewBridgeRefusedChirho\n"
        );
    }
}

#[test]
fn ownership_factory_never_adopts_an_existing_empty_root_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    let root_chirho = fixture_chirho.path_chirho("root-chirho");
    DirBuilder::new().mode(0o700).create(&root_chirho).unwrap();
    assert!(OwnedRootChirho::create_chirho(&root_chirho, "unit-chirho").is_err());
    assert_eq!(std::fs::read_dir(&root_chirho).unwrap().count(), 0);
    std::fs::remove_dir(&root_chirho).unwrap();
    assert!(OwnedRootChirho::create_chirho(&root_chirho, "unit-chirho").is_ok());
}

#[test]
fn descriptor_custody_refuses_a_replaced_public_root_without_latching_the_replacement_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    let owned_chirho =
        OwnedRootChirho::create_chirho(&fixture_chirho.path_chirho("root-chirho"), "unit-chirho")
            .unwrap();
    std::fs::rename(
        fixture_chirho.path_chirho("root-chirho"),
        fixture_chirho.path_chirho("original-chirho"),
    )
    .unwrap();
    DirBuilder::new()
        .mode(0o700)
        .create(fixture_chirho.path_chirho("root-chirho"))
        .unwrap();
    assert!(owned_chirho.activate_chirho().is_err());
    assert_eq!(
        std::fs::read_dir(fixture_chirho.path_chirho("root-chirho"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn actual_review_http_is_private_recomputed_and_root_byte_identical_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    let mut running_chirho = fixture_chirho.start_chirho();
    let before_chirho = running_chirho.frame_chirho("before-chirho");
    let ready_chirho = running_chirho.frame_chirho("ready-chirho");
    assert_eq!(
        before_chirho["snapshot_chirho"]["sentinel_seen_chirho"],
        true
    );
    assert_eq!(
        before_chirho["snapshot_chirho"]["unreadable_entries_chirho"],
        0
    );
    assert_eq!(
        before_chirho["manifest_blake3_chirho"],
        blake3::hash(&std::fs::read(fixture_chirho.path_chirho("manifest-chirho.json")).unwrap())
            .to_hex()
            .to_string()
    );
    let url_chirho = format!(
        "http://{}/app-chirho/fixture-chirho/review-chirho",
        ready_chirho["listener_chirho"].as_str().unwrap()
    );
    let cookie_chirho =
        std::fs::read_to_string(fixture_chirho.path_chirho("cookie-chirho")).unwrap();
    assert_eq!(
        std::fs::metadata(fixture_chirho.path_chirho("cookie-chirho"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let agent_chirho = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(Duration::from_secs(15))
        .build();
    for word_chirho in [PRIVATE_A_CHIRHO, PRIVATE_A_CHIRHO, PRIVATE_B_CHIRHO] {
        let answer_chirho = agent_chirho
            .post(&url_chirho)
            .set("Cookie", cookie_chirho.trim())
            .set("Content-Type", "application/x-www-form-urlencoded")
            .send_string(&format!(
                "document_chirho={word_chirho}&idempotency_key_chirho=unit-key-chirho"
            ))
            .unwrap();
        assert_eq!(answer_chirho.status(), 200);
        assert!(answer_chirho
            .header("Cache-Control")
            .unwrap()
            .contains("no-store"));
        let body_chirho = answer_chirho.into_string().unwrap();
        assert!(body_chirho.contains(&word_chirho.to_ascii_uppercase()));
        assert!(!body_chirho.contains("IDEMPOTENCY_KEY_CHIRHO"));
    }
    let anonymous_chirho = agent_chirho
        .post(&url_chirho)
        .set("Content-Type", "application/x-www-form-urlencoded")
        .send_string(
            "idempotency_key_chirho=anonymous-unit-chirho&document_chirho=anonymous-chirho",
        )
        .unwrap_err();
    assert!(matches!(anonymous_chirho, ureq::Error::Status(401, _)));
    std::fs::write(fixture_chirho.path_chirho("stop-chirho"), b"").unwrap();
    assert!(running_chirho.wait_chirho().success());
    let after_chirho = running_chirho.frame_chirho("after-chirho");
    running_chirho.frame_chirho("stopped-chirho");
    assert_eq!(
        before_chirho["snapshot_chirho"],
        after_chirho["snapshot_chirho"]
    );
    assert!(running_chirho.frames_chirho.try_recv().is_err());
    assert!(std::fs::read(fixture_chirho.path_chirho("stderr-chirho"))
        .unwrap()
        .is_empty());
    scan_chirho(
        &fixture_chirho.path_chirho("root-chirho"),
        &[
            CREDENTIAL_CHIRHO.as_bytes(),
            cookie_chirho.trim().as_bytes(),
            PRIVATE_A_CHIRHO.as_bytes(),
            PRIVATE_B_CHIRHO.as_bytes(),
        ],
    );
}

#[test]
fn activated_root_replacement_and_unwind_are_confined_to_a_test_child_chirho() {
    if std::env::var("TRANSIENT_CWD_TEST_CHILD_CHIRHO").as_deref() != Ok("1") {
        let output_chirho = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "fixture_chirho::tests_chirho::activated_root_replacement_and_unwind_are_confined_to_a_test_child_chirho", "--test-threads=1"])
            .env("TRANSIENT_CWD_TEST_CHILD_CHIRHO", "1").output().unwrap();
        assert!(output_chirho.status.success(), "isolated cwd probe failed");
        return;
    }
    use std::os::unix::fs::MetadataExt;
    let fixture_chirho = FixtureChirho::new_chirho();
    let original_chirho = std::fs::metadata(".").unwrap();
    let active_chirho =
        OwnedRootChirho::create_chirho(&fixture_chirho.path_chirho("root-chirho"), "unit-chirho")
            .unwrap()
            .activate_chirho()
            .unwrap();
    let tenant_chirho = std::fs::metadata(".").unwrap();
    let unwind_chirho = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = active_chirho.with_platform_chirho(|_path_chirho| -> Result<()> {
            panic!("injected platform operation panic chirho");
        });
    }));
    assert!(unwind_chirho.is_err());
    assert_eq!((tenant_chirho.dev(), tenant_chirho.ino()), {
        let restored_chirho = std::fs::metadata(".").unwrap();
        (restored_chirho.dev(), restored_chirho.ino())
    });
    std::fs::rename(
        fixture_chirho.path_chirho("root-chirho"),
        fixture_chirho.path_chirho("original-chirho"),
    )
    .unwrap();
    DirBuilder::new()
        .mode(0o700)
        .create(fixture_chirho.path_chirho("root-chirho"))
        .unwrap();
    assert!(active_chirho.latch_chirho().is_err());
    assert_eq!((original_chirho.dev(), original_chirho.ino()), {
        let restored_chirho = std::fs::metadata(".").unwrap();
        (restored_chirho.dev(), restored_chirho.ino())
    });
    assert_eq!(
        std::fs::read_dir(fixture_chirho.path_chirho("root-chirho"))
            .unwrap()
            .count(),
        0
    );
}

fn scan_chirho(path_chirho: &std::path::Path, needles_chirho: &[&[u8]]) {
    for entry_chirho in std::fs::read_dir(path_chirho).unwrap() {
        let path_chirho = entry_chirho.unwrap().path();
        if path_chirho.is_dir() {
            scan_chirho(&path_chirho, needles_chirho);
        } else {
            let bytes_chirho = std::fs::read(path_chirho).unwrap();
            for needle_chirho in needles_chirho {
                assert!(
                    !bytes_chirho
                        .windows(needle_chirho.len())
                        .any(|part_chirho| part_chirho == *needle_chirho),
                    "private fixture bytes persisted"
                );
            }
        }
    }
}

#[test]
fn unresolved_runtime_custody_exits_without_restoring_cwd_or_emitting_success_chirho() {
    if std::env::var_os("TRANSIENT_CUSTODY_CHILD_CHIRHO").is_none() {
        let fixture_chirho = FixtureChirho::new_chirho();
        let result_chirho = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "fixture_chirho::tests_chirho::unresolved_runtime_custody_exits_without_restoring_cwd_or_emitting_success_chirho",
                "--nocapture",
            ])
            .env("TRANSIENT_CUSTODY_CHILD_CHIRHO", &fixture_chirho.parent_chirho)
            .output()
            .unwrap();
        assert_eq!(result_chirho.status.code(), Some(1));
        assert_eq!(
            result_chirho.stderr,
            b"TransientReviewBridgeRefusedChirho\n"
        );
        assert!(!result_chirho
            .stdout
            .windows(b"custody-returned-chirho".len())
            .any(|part_chirho| part_chirho == b"custody-returned-chirho"));
        return;
    }
    let fixture_chirho = FixtureChirho {
        parent_chirho: PathBuf::from(std::env::var_os("TRANSIENT_CUSTODY_CHILD_CHIRHO").unwrap()),
    };
    let root_chirho =
        OwnedRootChirho::create_chirho(&fixture_chirho.path_chirho("root-chirho"), "unit-chirho")
            .unwrap()
            .activate_chirho()
            .unwrap()
            .latch_chirho()
            .unwrap();
    root_chirho.begin_runtime_chirho();
    // The parent owns cleanup even when a planted guard deletion lets this child return.
    std::mem::forget(fixture_chirho);
    drop(root_chirho);
    println!("custody-returned-chirho");
}

#[test]
fn missing_sentinel_on_stop_never_emits_after_or_stopped_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    let mut running_chirho = fixture_chirho.start_chirho();
    running_chirho.frame_chirho("before-chirho");
    running_chirho.frame_chirho("ready-chirho");
    std::fs::remove_file(
        fixture_chirho
            .path_chirho("root-chirho")
            .join(SENTINEL_PATH_CHIRHO),
    )
    .unwrap();
    std::fs::write(fixture_chirho.path_chirho("stop-chirho"), b"").unwrap();
    assert!(!running_chirho.wait_chirho().success());
    assert!(running_chirho.frames_chirho.try_recv().is_err());
    assert_eq!(
        std::fs::read(fixture_chirho.path_chirho("stderr-chirho")).unwrap(),
        b"TransientReviewBridgeRefusedChirho\n"
    );
}

#[test]
fn snapshot_refuses_unsupported_entries_and_missing_sentinel_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho();
    let root_chirho = fixture_chirho.path_chirho("root-chirho");
    std::fs::create_dir(&root_chirho).unwrap();
    assert!(snapshot_chirho(&root_chirho).is_err());
    std::fs::write(root_chirho.join(SENTINEL_PATH_CHIRHO), SENTINEL_CHIRHO).unwrap();
    assert!(Command::new("mkfifo")
        .args(["-m", "600"])
        .arg(root_chirho.join("unsupported-chirho"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success());
    assert!(snapshot_chirho(&root_chirho).is_err());
}
