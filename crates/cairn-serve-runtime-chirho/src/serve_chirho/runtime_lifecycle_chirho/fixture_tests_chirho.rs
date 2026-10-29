// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::{Condvar, Mutex};

#[derive(Default)]
struct ViewGateChirho {
    entered_chirho: std::sync::atomic::AtomicUsize,
    released_chirho: Mutex<bool>,
    wake_chirho: Condvar,
}

struct ViewHoldChirho(Arc<ViewGateChirho>);

impl ViewHoldChirho {
    async fn entered_chirho(&self, count_chirho: usize) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while self.0.entered_chirho.load(Ordering::Acquire) < count_chirho {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("real view job never reached its path open");
    }
}

impl Drop for ViewHoldChirho {
    fn drop(&mut self) {
        *self.0.released_chirho.lock().unwrap() = true;
        self.0.wake_chirho.notify_all();
    }
}

#[derive(Clone)]
struct ViewLogChirho {
    path_chirho: PathBuf,
    next_gate_chirho: Arc<Mutex<Option<Arc<ViewGateChirho>>>>,
    job_gate_chirho: Option<Arc<ViewGateChirho>>,
}

impl ViewLogChirho {
    fn hold_chirho(&self) -> ViewHoldChirho {
        let gate_chirho = Arc::new(ViewGateChirho::default());
        *self.next_gate_chirho.lock().unwrap() = Some(Arc::clone(&gate_chirho));
        ViewHoldChirho(gate_chirho)
    }
}

impl cairn_verified_prefix_view_chirho::PrefixLogChirho for ViewLogChirho {
    type RecordChirho = u64;
    type IndexChirho = u64;
    type JobLogChirho = Self;

    fn job_log_chirho(&self) -> Self {
        let mut job_chirho = self.clone();
        job_chirho.job_gate_chirho = self.next_gate_chirho.lock().unwrap().clone();
        job_chirho
    }
    fn path_chirho(&self) -> &Path {
        if let Some(gate_chirho) = &self.job_gate_chirho {
            gate_chirho.entered_chirho.fetch_add(1, Ordering::Release);
            let mut released_chirho = gate_chirho.released_chirho.lock().unwrap();
            while !*released_chirho {
                released_chirho = gate_chirho.wake_chirho.wait(released_chirho).unwrap();
            }
        }
        &self.path_chirho
    }
    fn verifier_id_chirho(&self) -> &str {
        "fixture-view-custody-chirho"
    }
    fn registry_chirho(&self) -> &'static cairn_verified_prefix_view_chirho::RegistryChirho<u64> {
        static REGISTRY_CHIRHO: cairn_verified_prefix_view_chirho::RegistryChirho<u64> =
            cairn_verified_prefix_view_chirho::RegistryChirho::new_chirho();
        &REGISTRY_CHIRHO
    }
    fn parse_chirho(&self, line_chirho: &str) -> Result<u64> {
        Ok(line_chirho.parse()?)
    }
    fn verify_and_fold_chirho(
        &self,
        index_chirho: &mut u64,
        record_chirho: u64,
        expected_seq_chirho: u64,
    ) -> Result<()> {
        anyhow::ensure!(record_chirho == expected_seq_chirho, "fixture sequence");
        *index_chirho += 1;
        Ok(())
    }
}

struct RootChirho(PathBuf);
static SEQUENCE_CHIRHO: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

impl RootChirho {
    fn new_chirho() -> Self {
        let platform_chirho = std::env::temp_dir().join(format!(
            "transient-lifecycle-{}-{}-{}-chirho",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            SEQUENCE_CHIRHO.fetch_add(1, Ordering::Relaxed)
        ));
        let root_chirho = tenant_chirho::root_for_tenant_chirho(
            &platform_chirho,
            &tenant_chirho::TenantIdChirho::TenantChirho("fixture-chirho".into()),
        )
        .unwrap();
        let owner_chirho = identity_chirho::register_identity_chirho(
            &root_chirho,
            identity_chirho::PrincipalKindChirho::OwnerChirho,
        )
        .unwrap()
        .principal_chirho;
        let wasm_chirho = cairn_chirho::cas_chirho::add_chirho(
            &root_chirho,
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../examples-chirho/upcase-chirho.wat"
            )),
        )
        .unwrap();
        let node_chirho = cairn_chirho::store_chirho::put_object_chirho(
            &root_chirho,
            &cairn_chirho::model_chirho::NodeDefChirho {
                name_chirho: "drain_node_chirho".into(),
                impl_wasm_chirho: wasm_chirho,
                entry_chirho: "upcase_chirho".into(),
                fuel_limit_chirho: 1_000_000,
                ..Default::default()
            },
        )
        .unwrap();
        let dag_chirho = cairn_chirho::store_chirho::put_object_chirho(
            &root_chirho,
            &cairn_chirho::model_chirho::DagChirho {
                nodes_chirho: vec![node_chirho],
                edges_chirho: Vec::new(),
            },
        )
        .unwrap();
        app_chirho::deploy_app_chirho(
            &root_chirho,
            "drain-fixture-chirho",
            dag_chirho.clone(),
            &owner_chirho,
        )
        .unwrap();
        app_chirho::deploy_app_route_chirho(
            &root_chirho,
            "drain-fixture-chirho",
            "view-chirho",
            dag_chirho,
            &owner_chirho,
        )
        .unwrap();
        for route_chirho in [None, Some("view-chirho")] {
            app_chirho::set_app_input_policy_chirho(
                &root_chirho,
                "drain-fixture-chirho",
                route_chirho,
                &owner_chirho,
                app_chirho::AppInputModeChirho::PlainChirho,
            )
            .unwrap();
        }
        cairn_writer_head_chirho::writer_head_chirho::issue_elected_writer_fence_for_root_chirho(
            &root_chirho,
            7,
        )
        .unwrap();
        Self(root_chirho)
    }

    async fn server_chirho(&self) -> PreparedTransientReviewServerChirho {
        prepare_fixture_inner_chirho(
            &self.0,
            TcpListener::bind("127.0.0.1:0").await.unwrap(),
            ConfiguredLedgerHostRuntimePortsChirho::uncomposed_chirho(),
        )
        .await
        .unwrap()
    }
}

impl Drop for RootChirho {
    fn drop(&mut self) {
        let platform_chirho = self.0.parent().unwrap().parent().unwrap();
        std::fs::remove_dir_all(platform_chirho).unwrap();
    }
}

async fn health_chirho(address_chirho: SocketAddr) {
    tokio::task::spawn_blocking(move || {
        let mut stream_chirho = std::net::TcpStream::connect(address_chirho).unwrap();
        stream_chirho
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream_chirho
            .write_all(
                b"GET /healthz-chirho HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
        let mut answer_chirho = String::new();
        stream_chirho.read_to_string(&mut answer_chirho).unwrap();
        assert!(
            answer_chirho.starts_with("HTTP/1.1 200"),
            "health was not served"
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn prepared_listener_is_owned_but_no_request_runs_before_the_caller_baseline_chirho() {
    let root_chirho = RootChirho::new_chirho();
    let server_chirho = root_chirho.server_chirho().await;
    let address_chirho = server_chirho.local_addr_chirho().unwrap();
    assert!(TcpListener::bind(address_chirho).await.is_err());
    tokio::task::spawn_blocking(move || {
        let mut stream_chirho = std::net::TcpStream::connect(address_chirho).unwrap();
        stream_chirho
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        stream_chirho
            .write_all(b"GET /healthz-chirho HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        let mut byte_chirho = [0];
        assert!(matches!(
            stream_chirho.read(&mut byte_chirho).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));
    })
    .await
    .unwrap();
    drop(server_chirho);
}

#[tokio::test]
async fn shutdown_waits_for_detached_execution_custody_after_http_has_drained_chirho() {
    let root_chirho = RootChirho::new_chirho();
    let server_chirho = root_chirho.server_chirho().await;
    let address_chirho = server_chirho.local_addr_chirho().unwrap();
    let permit_chirho = Arc::clone(&server_chirho.inflight_chirho)
        .try_acquire_owned()
        .unwrap();
    let (release_chirho, held_chirho) = tokio::sync::oneshot::channel();
    let custodian_chirho = tokio::spawn(async move {
        let _permit_chirho = permit_chirho;
        let _ = held_chirho.await;
    });
    let stop_chirho = Arc::new(AtomicBool::new(false));
    let mut serving_chirho = tokio::spawn(
        server_chirho.serve_until_chirho(Arc::clone(&stop_chirho), Duration::from_secs(10)),
    );
    health_chirho(address_chirho).await;
    stop_chirho.store(true, Ordering::Release);
    assert!(
        tokio::time::timeout(Duration::from_millis(150), &mut serving_chirho)
            .await
            .is_err()
    );
    release_chirho.send(()).unwrap();
    custodian_chirho.await.unwrap();
    serving_chirho.await.unwrap().unwrap();
}

#[tokio::test]
async fn shutdown_also_waits_for_cancelled_pre_admission_auth_work_chirho() {
    let root_chirho = RootChirho::new_chirho();
    let server_chirho = root_chirho.server_chirho().await;
    let address_chirho = server_chirho.local_addr_chirho().unwrap();
    let auth_chirho = Arc::clone(&server_chirho.auth_custody_chirho);
    let (started_chirho, running_chirho) = tokio::sync::oneshot::channel();
    let (release_chirho, held_chirho) = std::sync::mpsc::channel();
    let waiting_chirho = tokio::spawn(async move {
        auth_blocking_chirho::run_blocking_auth_with_permits_chirho(&auth_chirho, move || {
            started_chirho.send(()).unwrap();
            let _ = held_chirho.recv();
            Ok(())
        })
        .await
    });
    running_chirho.await.unwrap();
    waiting_chirho.abort();
    assert!(waiting_chirho.await.unwrap_err().is_cancelled());
    let stop_chirho = Arc::new(AtomicBool::new(false));
    let mut serving_chirho = tokio::spawn(
        server_chirho.serve_until_chirho(Arc::clone(&stop_chirho), Duration::from_secs(10)),
    );
    health_chirho(address_chirho).await;
    stop_chirho.store(true, Ordering::Release);
    assert!(
        tokio::time::timeout(Duration::from_millis(150), &mut serving_chirho)
            .await
            .is_err(),
        "auth work outlived its cancelled handler and must remain in the drain"
    );
    release_chirho.send(()).unwrap();
    serving_chirho.await.unwrap().unwrap();
}

#[tokio::test]
async fn initialization_and_shutdown_wait_for_live_and_orphaned_view_jobs_chirho() {
    use cairn_verified_prefix_view_chirho::{
        active_background_jobs_chirho, drop_view_chirho, with_current_view_chirho,
        BackgroundJobChirho, ViewRulesChirho,
    };
    let root_chirho = RootChirho::new_chirho();
    let path_chirho = root_chirho.0.join("fixture-view-chirho.jsonl");
    std::fs::write(&path_chirho, b"0\n").unwrap();
    let log_chirho = ViewLogChirho {
        path_chirho,
        next_gate_chirho: Arc::new(Mutex::new(None)),
        job_gate_chirho: None,
    };
    let rules_chirho = ViewRulesChirho {
        full_verify_every_ms_chirho: 1,
        slot_cap_chirho: 8,
    };
    let at_chirho = |now_chirho| {
        with_current_view_chirho(&log_chirho, &rules_chirho, || now_chirho, |_, _| ())
            .unwrap()
            .1
    };
    assert_eq!(at_chirho(0).started_chirho, None);
    let held_chirho = log_chirho.hold_chirho();
    assert_eq!(
        at_chirho(2).started_chirho,
        Some(BackgroundJobChirho::IntegrityPassChirho)
    );
    held_chirho.entered_chirho(1).await;
    drop_view_chirho(&log_chirho);
    at_chirho(3);
    assert_eq!(
        at_chirho(5).started_chirho,
        Some(BackgroundJobChirho::IntegrityPassChirho)
    );
    held_chirho.entered_chirho(2).await;
    assert!(
        active_background_jobs_chirho() >= 2,
        "an orphaned view job must not vanish from custody when its handle is replaced"
    );
    let preparation_chirho = prepare_fixture_inner_chirho(
        &root_chirho.0,
        TcpListener::bind("127.0.0.1:0").await.unwrap(),
        ConfiguredLedgerHostRuntimePortsChirho::uncomposed_chirho(),
    );
    tokio::pin!(preparation_chirho);
    assert!(
        tokio::time::timeout(Duration::from_millis(150), &mut preparation_chirho)
            .await
            .is_err(),
        "initialization cannot permit a cwd switch while a view job can still open its log"
    );
    drop(held_chirho);
    let server_chirho = preparation_chirho.await.unwrap();
    assert_eq!(active_background_jobs_chirho(), 0);

    let held_chirho = log_chirho.hold_chirho();
    assert_eq!(
        at_chirho(7).started_chirho,
        Some(BackgroundJobChirho::IntegrityPassChirho)
    );
    held_chirho.entered_chirho(1).await;
    let address_chirho = server_chirho.local_addr_chirho().unwrap();
    let stop_chirho = Arc::new(AtomicBool::new(false));
    let mut serving_chirho = tokio::spawn(
        server_chirho.serve_until_chirho(Arc::clone(&stop_chirho), Duration::from_secs(10)),
    );
    health_chirho(address_chirho).await;
    stop_chirho.store(true, Ordering::Release);
    assert!(
        tokio::time::timeout(Duration::from_millis(150), &mut serving_chirho)
            .await
            .is_err(),
        "a post-drain snapshot cannot race a detached view job"
    );
    drop(held_chirho);
    serving_chirho.await.unwrap().unwrap();
    assert_eq!(active_background_jobs_chirho(), 0);
}

#[tokio::test]
async fn unresolved_custody_times_out_instead_of_claiming_a_successful_drain_chirho() {
    let root_chirho = RootChirho::new_chirho();
    let server_chirho = root_chirho.server_chirho().await;
    let address_chirho = server_chirho.local_addr_chirho().unwrap();
    let pool_chirho = Arc::clone(&server_chirho.inflight_chirho);
    let permit_chirho = Arc::clone(&pool_chirho).try_acquire_owned().unwrap();
    let stop_chirho = Arc::new(AtomicBool::new(false));
    let serving_chirho = tokio::spawn(
        server_chirho.serve_until_chirho(Arc::clone(&stop_chirho), Duration::from_millis(150)),
    );
    health_chirho(address_chirho).await;
    stop_chirho.store(true, Ordering::Release);
    let failure_chirho = serving_chirho.await.unwrap().unwrap_err();
    assert!(failure_chirho
        .to_string()
        .contains("TransientReviewDrainTimeoutChirho"));
    assert!(
        pool_chirho.try_acquire_owned().is_err(),
        "admission must stay closed"
    );
    drop(permit_chirho);
}

#[tokio::test]
async fn non_loopback_listener_refuses_before_opening_a_root_chirho() {
    let listener_chirho = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let result_chirho = prepare_fixture_inner_chirho(
        Path::new("does-not-exist-chirho"),
        listener_chirho,
        ConfiguredLedgerHostRuntimePortsChirho::uncomposed_chirho(),
    )
    .await;
    assert!(result_chirho
        .err()
        .unwrap()
        .to_string()
        .contains("TransientReviewLoopbackRequiredChirho"));
}

struct HeldReadChirho {
    entered_chirho: std::sync::mpsc::Sender<()>,
    released_chirho: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    confirms_chirho: std::sync::atomic::AtomicUsize,
}

impl cairn_write_relay_chirho::ServedLocalReadAuthorityPortChirho for HeldReadChirho {
    fn begin_local_read_chirho(
        &self,
    ) -> std::result::Result<
        cairn_write_relay_chirho::ServedLocalReadAuthorityWitnessChirho,
        cairn_write_relay_chirho::ServedWriteRelayFailureChirho,
    > {
        Ok(
            cairn_write_relay_chirho::ServedLocalReadAuthorityWitnessChirho::new_chirho(
                "fixture-owner-chirho".into(),
                7,
            ),
        )
    }
    fn confirm_local_read_chirho(
        &self,
        _witness_chirho: &cairn_write_relay_chirho::ServedLocalReadAuthorityWitnessChirho,
    ) -> std::result::Result<(), cairn_write_relay_chirho::ServedWriteRelayFailureChirho> {
        if self.confirms_chirho.fetch_add(1, Ordering::SeqCst) == 0 {
            self.entered_chirho.send(()).unwrap();
            let mut released_chirho = self.released_chirho.0.lock().unwrap();
            while !*released_chirho {
                released_chirho = self.released_chirho.1.wait(released_chirho).unwrap();
            }
        }
        Ok(())
    }
}

struct LocalDispatchChirho;

impl cairn_write_relay_chirho::ServedWriteDispatchPortChirho for LocalDispatchChirho {
    fn dispatch_chirho<'a>(
        &'a self,
        _input_chirho: cairn_write_relay_chirho::ServedWriteDispatchInputChirho,
    ) -> cairn_write_relay_chirho::ServedWriteDispatchFutureChirho<'a> {
        Box::pin(async {
            Ok(cairn_write_relay_chirho::ServedWriteDispatchOutcomeChirho::ExecuteLocallyChirho)
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_real_transient_read_keeps_shutdown_pending_until_its_blocking_work_ends_chirho(
) {
    let root_chirho = RootChirho::new_chirho();
    let (entered_chirho, observed_chirho) = std::sync::mpsc::channel();
    let released_chirho = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let ports_chirho = ConfiguredLedgerHostRuntimePortsChirho::uncomposed_chirho()
        .with_served_write_relay_chirho(
            Arc::new(LocalDispatchChirho),
            Arc::new(HeldReadChirho {
                entered_chirho,
                released_chirho: Arc::clone(&released_chirho),
                confirms_chirho: std::sync::atomic::AtomicUsize::new(0),
            }),
            ServedWriteRelayDestinationSlotChirho::new_chirho(),
        );
    let server_chirho = prepare_fixture_inner_chirho(
        &root_chirho.0,
        TcpListener::bind("127.0.0.1:0").await.unwrap(),
        ports_chirho,
    )
    .await
    .unwrap();
    let address_chirho = server_chirho.local_addr_chirho().unwrap();
    let stop_chirho = Arc::new(AtomicBool::new(false));
    let mut serving_chirho = tokio::spawn(
        server_chirho.serve_until_chirho(Arc::clone(&stop_chirho), Duration::from_secs(10)),
    );
    health_chirho(address_chirho).await;
    let mut client_chirho = std::net::TcpStream::connect(address_chirho).unwrap();
    client_chirho
        .write_all(
            b"GET /app-chirho/drain-fixture-chirho/view-chirho HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .unwrap();
    tokio::task::spawn_blocking(move || observed_chirho.recv_timeout(Duration::from_secs(10)))
        .await
        .unwrap()
        .unwrap();
    drop(client_chirho);
    stop_chirho.store(true, Ordering::Release);
    let held_chirho = tokio::time::timeout(Duration::from_millis(150), &mut serving_chirho)
        .await
        .is_err();
    *released_chirho.0.lock().unwrap() = true;
    released_chirho.1.notify_all();
    assert!(
        held_chirho,
        "cancelled HTTP must not release the still-running transient work"
    );
    serving_chirho.await.unwrap().unwrap();
}
