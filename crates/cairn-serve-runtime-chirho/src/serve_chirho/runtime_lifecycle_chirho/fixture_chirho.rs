// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Prepares the real money-free router before readiness and drains its execution custody on stop.
//!
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/write-forwarding-chirho/transient-review-fixture-chirho/lifecycle-source-chirho.md`.

use super::*;
use anyhow::{bail, Context};
use std::future::IntoFuture;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

const FIXTURE_INFLIGHT_CHIRHO: usize = 8;
const MAX_DRAIN_CHIRHO: Duration = Duration::from_secs(60);

/// Owns a bound listener and initialized real router, but accepts nothing until consumed.
pub struct PreparedTransientReviewServerChirho {
    listener_chirho: TcpListener,
    router_chirho: Router,
    inflight_chirho: Arc<Semaphore>,
    auth_custody_chirho: Arc<Semaphore>,
    auth_capacity_chirho: usize,
}

/// The example supplies its existing ports; this adapter creates no read or write authority.
#[cfg(feature = "dev-transient-review-fixture-chirho")]
pub async fn prepare_transient_review_server_chirho(
    root_chirho: &Path,
    listener_chirho: TcpListener,
    ports_chirho: ConfiguredLedgerHostRuntimePortsChirho,
) -> Result<PreparedTransientReviewServerChirho> {
    if std::env::var("CAIRN_TESTKIND_TRANSIENT_REVIEW_CHIRHO").as_deref() != Ok("1") {
        bail!("TransientReviewOptInRequiredChirho");
    }
    prepare_fixture_inner_chirho(root_chirho, listener_chirho, ports_chirho).await
}

async fn prepare_fixture_inner_chirho(
    root_chirho: &Path,
    listener_chirho: TcpListener,
    ports_chirho: ConfiguredLedgerHostRuntimePortsChirho,
) -> Result<PreparedTransientReviewServerChirho> {
    if listener_chirho.local_addr()?.ip() != Ipv4Addr::LOCALHOST {
        bail!("TransientReviewLoopbackRequiredChirho");
    }
    if ports_chirho.ledger_host_chirho.is_some()
        || ports_chirho.postgres_effect_chirho.is_some()
        || ports_chirho.process_stop_chirho.is_some()
        || ports_chirho.startup_posture_chirho
            != ConfiguredServeStartupPostureChirho::RecoverRunIntentsAndMonitorChirho
    {
        bail!("TransientReviewMoneyFreeCompositionRequiredChirho");
    }
    if !matches!(
        tenant_chirho::tenant_id_for_root_chirho(root_chirho)?,
        tenant_chirho::TenantIdChirho::TenantChirho(_)
    ) || cairn_writer_head_chirho::writer_head_chirho::writer_authority_era_chirho(root_chirho)?
        != cairn_writer_head_chirho::writer_head_chirho::WriterAuthorityEraChirho::ElectedChirho
    {
        bail!("TransientReviewElectedTenantRequiredChirho");
    }
    let prepared_chirho = prepare_http_runtime_chirho(
        root_chirho,
        ServeOptionsChirho {
            inflight_limit_chirho: FIXTURE_INFLIGHT_CHIRHO,
            auth_tokens_chirho: ServeAuthTokensChirho::default(),
            announce_chirho: false,
            domain_routing_enabled_chirho: false,
            served_request_limits_chirho: ServedRequestAbuseLimitsChirho::default(),
            projection_read_chirho: None,
            postgres_effect_chirho: None,
            llm_served_chirho: None,
            ledger_monitor_chirho: None,
            write_dispatch_chirho: ports_chirho.write_dispatch_chirho,
            local_read_authority_chirho: ports_chirho.local_read_authority_chirho,
            write_destination_slot_chirho: ports_chirho.write_destination_slot_chirho,
            startup_posture_chirho: ports_chirho.startup_posture_chirho,
        },
    )
    .await?;
    // Await the SAME read views production warms, rather than launching untracked threads past baseline.
    let warm_root_chirho = root_chirho.to_path_buf();
    tokio::time::timeout(Duration::from_secs(30), async move {
        tokio::task::spawn_blocking(move || -> Result<()> {
            cairn_chirho::identity_chirho::warm_auth_attempt_view_chirho(&warm_root_chirho)?;
            cairn_chirho::privacy_chirho::warm_private_blob_view_chirho(&warm_root_chirho)?;
            cairn_chirho::dag_private_value_chirho::warm_private_value_view_chirho(
                &warm_root_chirho,
            )?;
            cairn_chirho::effect_chirho::run_intent_chirho::warm_run_intent_view_chirho(
                &warm_root_chirho,
            )?;
            cairn_chirho::identity_chirho::warm_session_views_chirho(&warm_root_chirho)?;
            cairn_chirho::oauth_chirho::warm_scoped_token_views_chirho(&warm_root_chirho)?;
            Ok(())
        })
        .await??;
        while cairn_verified_prefix_view_chirho::active_background_jobs_chirho() != 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("TransientReviewInitializationTimeoutChirho")??;
    let inflight_chirho = Arc::clone(&prepared_chirho.state_chirho.inflight_chirho);
    let (auth_custody_chirho, auth_capacity_chirho) =
        auth_blocking_chirho::fixture_auth_custody_chirho();
    let router_chirho = router_for_state_chirho(prepared_chirho.state_chirho, false)?;
    Ok(PreparedTransientReviewServerChirho {
        listener_chirho,
        router_chirho,
        inflight_chirho,
        auth_custody_chirho,
        auth_capacity_chirho,
    })
}

impl PreparedTransientReviewServerChirho {
    pub fn local_addr_chirho(&self) -> Result<SocketAddr> {
        Ok(self.listener_chirho.local_addr()?)
    }

    /// Success means HTTP handlers AND all shared F1 permit custody have ended. A closed semaphore
    /// cannot admit new work; only then is its full available count a quiescence witness.
    pub async fn serve_until_chirho(
        self,
        stop_chirho: Arc<AtomicBool>,
        drain_timeout_chirho: Duration,
    ) -> Result<()> {
        if drain_timeout_chirho.is_zero()
            || drain_timeout_chirho > MAX_DRAIN_CHIRHO
            || stop_chirho.load(Ordering::Acquire)
        {
            bail!("TransientReviewLifecycleInvalidChirho");
        }
        let server_chirho = axum::serve(
            self.listener_chirho,
            self.router_chirho
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(wait_for_serve_stop_chirho(Arc::clone(&stop_chirho)))
        .into_future();
        tokio::pin!(server_chirho);
        let completed_chirho = tokio::select! {
            result_chirho = &mut server_chirho => {
                result_chirho?;
                if !stop_chirho.load(Ordering::Acquire) {
                    bail!("TransientReviewUnexpectedServerStopChirho");
                }
                true
            }
            () = wait_for_serve_stop_chirho(Arc::clone(&stop_chirho)) => false,
        };
        self.inflight_chirho.close();
        tokio::time::timeout(drain_timeout_chirho, async {
            if !completed_chirho {
                server_chirho.await?;
            }
            while self.inflight_chirho.available_permits() != FIXTURE_INFLIGHT_CHIRHO
                || self.auth_custody_chirho.available_permits() != self.auth_capacity_chirho
                || cairn_verified_prefix_view_chirho::active_background_jobs_chirho() != 0
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Ok::<(), anyhow::Error>(())
        })
        .await
        .context("TransientReviewDrainTimeoutChirho")??;
        Ok(())
    }
}

#[cfg(test)]
#[path = "fixture_tests_chirho.rs"]
mod tests_chirho;
