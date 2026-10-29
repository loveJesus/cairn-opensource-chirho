// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The async fire-and-forget Raft driver (the PRODUCTION message pump, vs the synchronous test bus).
//! Each node runs its own driver: a timer calls `tick_once_chirho`, and every message the elector emits
//! (a heartbeat, a vote, a vote response) is POSTed to the target peer's fire endpoint and NOT waited on
//! — the peer, in turn, steps it and pumps ITS own replies onward. So every node independently sends the
//! messages it is responsible for (each already signed by that node when authentication is on), which is
//! the peer-to-peer model a real cluster needs; the request/response bus was only a deterministic test
//! harness. The driver still drives an ELECTION-ONLY elector, so it mints nothing.
//!
//! Each configured peer owns one fixed delivery worker and one bounded queue. Enqueue never waits on
//! network I/O; saturation drops the message and increments an observable counter, after which Raft
//! retries through its normal heartbeat/replication loop. Thread and queued-byte growth are therefore
//! bounded over time rather than proportional to a stalled peer's message history.

use crate::MAX_RAFT_MESSAGE_BYTES_CHIRHO;
use anyhow::{bail, Context, Result};
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::Arc;
use std::sync::Mutex;
use std::thread::JoinHandle;
use std::time::Duration;
use url::{Host, Url};

/// The route a peer POSTs a fire-and-forget (no-reply) Raft message to.
pub const RAFT_FIRE_PATH_CHIRHO: &str = "/raft-fire-chirho";
/// Per-peer backlog. Raft retries dropped replication/election traffic, so a stalled peer cannot
/// consume unbounded memory or create an unbounded number of delivery threads. Combined with the
/// message and peer caps, worst-case queued bytes are fixed for one consistency group.
const OUTBOUND_QUEUE_CAPACITY_CHIRHO: usize = 8;
const MAX_OUTBOUND_PEERS_CHIRHO: usize = 16;
const MAX_OUTBOUND_REQUEST_TIMEOUT_CHIRHO: Duration = Duration::from_secs(5);

fn saturating_increment_chirho(counter_chirho: &AtomicU64) {
    let _ = counter_chirho.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count_chirho| {
        Some(count_chirho.saturating_add(1))
    });
}

pub(crate) fn validate_outbound_config_chirho(
    peers_chirho: &[(u64, String)],
    request_timeout_chirho: Duration,
) -> Result<()> {
    if request_timeout_chirho.is_zero()
        || request_timeout_chirho > MAX_OUTBOUND_REQUEST_TIMEOUT_CHIRHO
    {
        bail!("outbound raft request timeout must be inside the bounded delivery window");
    }
    if peers_chirho.len() > MAX_OUTBOUND_PEERS_CHIRHO {
        bail!("outbound raft peer set exceeds the per-group worker bound");
    }
    let mut peer_ids_chirho = HashSet::with_capacity(peers_chirho.len());
    for (raft_id_chirho, base_url_chirho) in peers_chirho {
        if *raft_id_chirho == 0 || !peer_ids_chirho.insert(*raft_id_chirho) {
            bail!("outbound raft peer ids must be nonzero and unique");
        }
        let parsed_url_chirho = Url::parse(base_url_chirho)
            .with_context(|| format!("parse outbound raft peer {raft_id_chirho} URL"))?;
        if !matches!(
            parsed_url_chirho.host(),
            Some(Host::Ipv4(_)) | Some(Host::Ipv6(_))
        ) || parsed_url_chirho.cannot_be_a_base()
            || parsed_url_chirho.username() != ""
            || parsed_url_chirho.password().is_some()
            || parsed_url_chirho.query().is_some()
            || parsed_url_chirho.fragment().is_some()
            || !matches!(parsed_url_chirho.scheme(), "http" | "https")
            || !matches!(parsed_url_chirho.path(), "" | "/")
        {
            bail!(
                "outbound raft peer URLs must be HTTP(S) numeric mesh origins without credentials, path, query, or fragment"
            );
        }
    }
    Ok(())
}

struct OutboundPeerChirho {
    fire_url_chirho: String,
    sender_chirho: Option<SyncSender<Vec<u8>>>,
    worker_chirho: Option<JoinHandle<()>>,
}

/// Result of one nonblocking retryable-traffic enqueue pass. The caller can observe saturation without
/// retaining message bytes; one-shot control traffic uses `deliver_required_control_chirho` instead.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[must_use]
pub struct OutboundEnqueueReportChirho {
    pub enqueued_messages_chirho: usize,
    pub dropped_messages_chirho: usize,
}

/// One node's driver: its elector plus the base URLs of its PEERS (every voter except itself). It ticks
/// the elector and pumps the resulting messages to peers; it also steps inbound messages and pumps their
/// replies. Cheap to share behind an `Arc`; every peer has one fixed worker and bounded queue.
pub struct RaftDriverChirho {
    elector_chirho: Arc<RaftWriterElectorChirho>,
    /// Peer raft id -> fixed delivery worker (this node's own id is deliberately absent).
    peers_chirho: HashMap<u64, OutboundPeerChirho>,
    control_agent_chirho: ureq::Agent,
    stop_chirho: Arc<AtomicBool>,
    dropped_outbound_messages_chirho: Arc<AtomicU64>,
    /// Ticks whose elector call returned an error. A failing tick produces no messages, so without
    /// this a node that cannot make progress is indistinguishable from a healthy idle one.
    tick_failures_chirho: Arc<AtomicU64>,
    /// The most recent tick error, kept so an operator learns WHY rather than only THAT. A count
    /// alone still leaves you guessing, which was the whole problem.
    last_tick_error_chirho: Arc<Mutex<Option<String>>>,
}

impl RaftDriverChirho {
    /// Build a driver for `elector_chirho` that delivers to `peers_chirho` (raft id -> base URL, excluding
    /// self). Startup creates exactly one bounded delivery worker per peer and builds its HTTP agent
    /// with the required bounded timeout so shutdown cannot wait forever on a stalled peer.
    pub fn new_chirho(
        elector_chirho: Arc<RaftWriterElectorChirho>,
        peers_chirho: Vec<(u64, String)>,
        request_timeout_chirho: Duration,
    ) -> Result<Self> {
        validate_outbound_config_chirho(&peers_chirho, request_timeout_chirho)?;
        let agent_chirho = ureq::AgentBuilder::new()
            .timeout(request_timeout_chirho)
            .build();
        let stop_chirho = Arc::new(AtomicBool::new(false));
        let dropped_outbound_messages_chirho = Arc::new(AtomicU64::new(0));
        let tick_failures_chirho = Arc::new(AtomicU64::new(0));
        let last_tick_error_chirho = Arc::new(Mutex::new(None));
        let mut outbound_peers_chirho = HashMap::with_capacity(peers_chirho.len());
        for (raft_id_chirho, base_url_chirho) in peers_chirho {
            let (sender_chirho, receiver_chirho) =
                sync_channel::<Vec<u8>>(OUTBOUND_QUEUE_CAPACITY_CHIRHO);
            let worker_stop_chirho = stop_chirho.clone();
            let worker_agent_chirho = agent_chirho.clone();
            let worker_drops_chirho = dropped_outbound_messages_chirho.clone();
            let url_chirho = format!(
                "{}{}",
                base_url_chirho.trim_end_matches('/'),
                RAFT_FIRE_PATH_CHIRHO
            );
            let worker_url_chirho = url_chirho.clone();
            let worker_chirho = std::thread::Builder::new()
                .name(format!("cairn-raft-outbound-{raft_id_chirho}-chirho"))
                .spawn(move || {
                    while let Ok(bytes_chirho) = receiver_chirho.recv() {
                        if worker_stop_chirho.load(Ordering::Acquire) {
                            break;
                        }
                        if worker_agent_chirho
                            .post(&worker_url_chirho)
                            .send_bytes(&bytes_chirho)
                            .is_err()
                        {
                            saturating_increment_chirho(&worker_drops_chirho);
                        }
                    }
                })
                .with_context(|| {
                    format!("start bounded outbound raft worker for peer {raft_id_chirho}")
                })?;
            outbound_peers_chirho.insert(
                raft_id_chirho,
                OutboundPeerChirho {
                    fire_url_chirho: url_chirho,
                    sender_chirho: Some(sender_chirho),
                    worker_chirho: Some(worker_chirho),
                },
            );
        }
        Ok(Self {
            elector_chirho,
            peers_chirho: outbound_peers_chirho,
            control_agent_chirho: agent_chirho,
            stop_chirho,
            dropped_outbound_messages_chirho,
            tick_failures_chirho,
            last_tick_error_chirho,
        })
    }

    /// The elector this driver drives (for reading leadership).
    pub fn elector_chirho(&self) -> &Arc<RaftWriterElectorChirho> {
        &self.elector_chirho
    }

    /// Number of outbound messages not delivered because the message was oversized, the peer was
    /// unknown, its bounded queue was full/disconnected, or its bounded HTTP request failed. Monotonic
    /// operational evidence; no message bytes are retained.
    pub fn dropped_outbound_messages_chirho(&self) -> u64 {
        self.dropped_outbound_messages_chirho
            .load(Ordering::Relaxed)
    }

    fn record_outbound_drop_chirho(&self) {
        saturating_increment_chirho(&self.dropped_outbound_messages_chirho);
    }

    /// Enqueue retryable Raft traffic without waiting on network I/O. Full/disconnected queues and
    /// unknown peer ids are reported and counted; Raft retries through later ticks.
    pub fn pump_chirho(&self, outbound_chirho: Vec<(u64, Vec<u8>)>) -> OutboundEnqueueReportChirho {
        let mut report_chirho = OutboundEnqueueReportChirho::default();
        for (to_chirho, bytes_chirho) in outbound_chirho {
            if bytes_chirho.len() > MAX_RAFT_MESSAGE_BYTES_CHIRHO {
                self.record_outbound_drop_chirho();
                report_chirho.dropped_messages_chirho += 1;
                continue;
            }
            let Some(peer_chirho) = self.peers_chirho.get(&to_chirho) else {
                self.record_outbound_drop_chirho();
                report_chirho.dropped_messages_chirho += 1;
                continue;
            };
            let Some(sender_chirho) = &peer_chirho.sender_chirho else {
                self.record_outbound_drop_chirho();
                report_chirho.dropped_messages_chirho += 1;
                continue;
            };
            match sender_chirho.try_send(bytes_chirho) {
                Ok(()) => report_chirho.enqueued_messages_chirho += 1,
                Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                    self.record_outbound_drop_chirho();
                    report_chirho.dropped_messages_chirho += 1;
                }
            }
        }
        report_chirho
    }

    /// Deliver one-shot control traffic on an acknowledged bounded path. Unlike retryable Raft traffic,
    /// these messages are not allowed to disappear behind a full queue or a failed HTTP request.
    pub fn deliver_required_control_chirho(
        &self,
        outbound_chirho: Vec<(u64, Vec<u8>)>,
    ) -> Result<()> {
        for (to_chirho, bytes_chirho) in outbound_chirho {
            if bytes_chirho.len() > MAX_RAFT_MESSAGE_BYTES_CHIRHO {
                self.record_outbound_drop_chirho();
                bail!("required outbound raft control message exceeds the message bound");
            }
            let Some(peer_chirho) = self.peers_chirho.get(&to_chirho) else {
                self.record_outbound_drop_chirho();
                bail!("required outbound raft control target is not a configured peer");
            };
            if let Err(error_chirho) = self
                .control_agent_chirho
                .post(&peer_chirho.fire_url_chirho)
                .send_bytes(&bytes_chirho)
            {
                self.record_outbound_drop_chirho();
                return Err(error_chirho).with_context(|| {
                    format!("deliver required outbound raft control message to peer {to_chirho}")
                });
            }
        }
        Ok(())
    }

    /// Advance the elector's clock once and pump whatever messages that produces — the driver's timer
    /// calls this. A wedged elector read is contained inside `tick_encoded_chirho`, so this never panics.
    pub fn tick_once_chirho(&self) {
        // A failing tick is contained here so the timer thread cannot die, but it must not be
        // SILENT: a node whose ticks all fail serves happily, dials nobody, and looks exactly like a
        // healthy idle node. Counting the failures is what makes "serving but not progressing"
        // observable instead of something an operator has to infer from an absent socket.
        let outbound_chirho = match self.elector_chirho.tick_encoded_chirho() {
            Ok(outbound_chirho) => outbound_chirho,
            Err(error_chirho) => {
                saturating_increment_chirho(&self.tick_failures_chirho);
                if let Ok(mut slot_chirho) = self.last_tick_error_chirho.lock() {
                    *slot_chirho = Some(format!("{error_chirho:#}"));
                }
                Vec::new()
            }
        };
        let _report_chirho = self.pump_chirho(outbound_chirho);
    }

    /// How many ticks failed inside the elector. Non-zero means this node is not making raft
    /// progress, however healthy its listener looks.
    pub fn tick_failures_chirho(&self) -> u64 {
        self.tick_failures_chirho.load(Ordering::Acquire)
    }

    /// The most recent tick error, if any.
    pub fn last_tick_error_chirho(&self) -> Option<String> {
        self.last_tick_error_chirho
            .lock()
            .ok()
            .and_then(|slot_chirho| slot_chirho.clone())
    }

    /// Start an election now and pump the messages that carry it — a deterministic kick so a test (or an
    /// operator) need not wait for the first election timeout.
    pub fn campaign_now_chirho(&self) {
        let outbound_chirho = self
            .elector_chirho
            .campaign_encoded_chirho()
            .unwrap_or_default();
        let _report_chirho = self.pump_chirho(outbound_chirho);
    }

    /// Step one inbound encoded message and pump its replies onward — the fire endpoint's body. Returns
    /// an error only if the message failed to verify/decode (so the endpoint can answer 400); a stepped
    /// message's replies are delivered fire-and-forget.
    pub fn step_and_pump_chirho(&self, message_bytes_chirho: &[u8]) -> anyhow::Result<()> {
        let outbound_chirho = self
            .elector_chirho
            .step_encoded_chirho(message_bytes_chirho)?;
        let _report_chirho = self.pump_chirho(outbound_chirho);
        Ok(())
    }
}

impl Drop for RaftDriverChirho {
    fn drop(&mut self) {
        self.stop_chirho.store(true, Ordering::Release);
        for peer_chirho in self.peers_chirho.values_mut() {
            peer_chirho.sender_chirho.take();
        }
        for peer_chirho in self.peers_chirho.values_mut() {
            let Some(worker_chirho) = peer_chirho.worker_chirho.take() else {
                continue;
            };
            let _ = worker_chirho.join();
        }
    }
}
