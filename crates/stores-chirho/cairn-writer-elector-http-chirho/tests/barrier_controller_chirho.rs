// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Harness-only reversible TCP barrier. This file is compiled only as integration-test support.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BarrierModeChirho {
    NetworkPartitionChirho,
    HungDriverChirho,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BarrierDirectionChirho {
    BidirectionalChirho,
    OneDirectionChirho,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BarrierAdmissionRefusalChirho {
    AsymmetricTransportChirho,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub(crate) enum BarrierPhaseChirho {
    ArmedChirho,
    DisconnectedChirho,
    HealedChirho,
    CleanedChirho,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BarrierStatusChirho {
    pub(crate) mode_chirho: BarrierModeChirho,
    pub(crate) phase_chirho: BarrierPhaseChirho,
}

pub(crate) struct TcpBarrierControllerChirho {
    open_chirho: Arc<AtomicBool>,
    stop_chirho: Arc<AtomicBool>,
    status_chirho: Arc<Mutex<BarrierStatusChirho>>,
    worker_chirho: Option<JoinHandle<()>>,
}

impl TcpBarrierControllerChirho {
    pub(crate) fn arm_chirho(
        listener_chirho: TcpListener,
        upstream_chirho: SocketAddr,
        mode_chirho: BarrierModeChirho,
    ) -> Self {
        Self::try_arm_chirho(
            listener_chirho,
            upstream_chirho,
            mode_chirho,
            BarrierDirectionChirho::BidirectionalChirho,
        )
        .expect("the default barrier is bidirectional")
    }

    pub(crate) fn try_arm_chirho(
        listener_chirho: TcpListener,
        upstream_chirho: SocketAddr,
        mode_chirho: BarrierModeChirho,
        direction_chirho: BarrierDirectionChirho,
    ) -> Result<Self, BarrierAdmissionRefusalChirho> {
        if direction_chirho != BarrierDirectionChirho::BidirectionalChirho {
            return Err(BarrierAdmissionRefusalChirho::AsymmetricTransportChirho);
        }
        listener_chirho
            .set_nonblocking(true)
            .expect("barrier listener becomes nonblocking");
        let open_chirho = Arc::new(AtomicBool::new(true));
        let stop_chirho = Arc::new(AtomicBool::new(false));
        let status_chirho = Arc::new(Mutex::new(BarrierStatusChirho {
            mode_chirho,
            phase_chirho: BarrierPhaseChirho::ArmedChirho,
        }));
        let open_for_worker_chirho = open_chirho.clone();
        let stop_for_worker_chirho = stop_chirho.clone();
        let worker_chirho = thread::spawn(move || {
            while !stop_for_worker_chirho.load(Ordering::Relaxed) {
                match listener_chirho.accept() {
                    Ok((client_chirho, _)) => {
                        if !open_for_worker_chirho.load(Ordering::Relaxed) {
                            let _ = client_chirho.shutdown(std::net::Shutdown::Both);
                            continue;
                        }
                        let Ok(server_chirho) = TcpStream::connect(upstream_chirho) else {
                            continue;
                        };
                        for (from_chirho, to_chirho) in [
                            (
                                client_chirho.try_clone().expect("clone barrier client"),
                                server_chirho.try_clone().expect("clone barrier server"),
                            ),
                            (server_chirho, client_chirho),
                        ] {
                            let open_for_pump_chirho = open_for_worker_chirho.clone();
                            thread::spawn(move || {
                                pump_until_disconnected_chirho(
                                    from_chirho,
                                    to_chirho,
                                    open_for_pump_chirho,
                                )
                            });
                        }
                    }
                    Err(error_chirho)
                        if matches!(
                            error_chirho.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                        ) =>
                    {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            open_chirho,
            stop_chirho,
            status_chirho,
            worker_chirho: Some(worker_chirho),
        })
    }

    pub(crate) fn disconnect_chirho(&self) -> BarrierStatusChirho {
        self.open_chirho.store(false, Ordering::Relaxed);
        let mut status_guard_chirho = self.status_chirho.lock().expect("barrier status lock");
        status_guard_chirho.phase_chirho = BarrierPhaseChirho::DisconnectedChirho;
        *status_guard_chirho
    }

    pub(crate) fn heal_chirho(&self) -> BarrierStatusChirho {
        self.open_chirho.store(true, Ordering::Relaxed);
        let mut status_guard_chirho = self.status_chirho.lock().expect("barrier status lock");
        status_guard_chirho.phase_chirho = BarrierPhaseChirho::HealedChirho;
        *status_guard_chirho
    }

    pub(crate) fn status_chirho(&self) -> BarrierStatusChirho {
        *self.status_chirho.lock().expect("barrier status lock")
    }

    pub(crate) fn cleanup_chirho(&mut self) -> BarrierStatusChirho {
        self.open_chirho.store(false, Ordering::Relaxed);
        self.stop_chirho.store(true, Ordering::Relaxed);
        if let Some(worker_chirho) = self.worker_chirho.take() {
            let _ = worker_chirho.join();
        }
        let mut status_guard_chirho = self.status_chirho.lock().expect("barrier status lock");
        status_guard_chirho.phase_chirho = BarrierPhaseChirho::CleanedChirho;
        *status_guard_chirho
    }
}

impl Drop for TcpBarrierControllerChirho {
    fn drop(&mut self) {
        let _ = self.cleanup_chirho();
    }
}

fn pump_until_disconnected_chirho(
    mut from_chirho: TcpStream,
    mut to_chirho: TcpStream,
    open_chirho: Arc<AtomicBool>,
) {
    let _ = from_chirho.set_read_timeout(Some(Duration::from_millis(50)));
    let mut buffer_chirho = [0_u8; 8192];
    while open_chirho.load(Ordering::Relaxed) {
        match from_chirho.read(&mut buffer_chirho) {
            Ok(0) => break,
            Ok(read_chirho) if to_chirho.write_all(&buffer_chirho[..read_chirho]).is_ok() => {}
            Ok(_) => break,
            Err(error_chirho)
                if matches!(
                    error_chirho.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => break,
        }
    }
    let _ = from_chirho.shutdown(std::net::Shutdown::Both);
    let _ = to_chirho.shutdown(std::net::Shutdown::Both);
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn barrier_disconnects_an_existing_stream_and_reports_each_phase_chirho() {
        let upstream_listener_chirho = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
        let upstream_addr_chirho = upstream_listener_chirho
            .local_addr()
            .expect("read upstream address");
        let upstream_thread_chirho = thread::spawn(move || {
            let (_stream_chirho, _) = upstream_listener_chirho.accept().expect("accept upstream");
            thread::sleep(Duration::from_secs(1));
        });

        let barrier_listener_chirho = TcpListener::bind("127.0.0.1:0").expect("bind barrier");
        let barrier_addr_chirho = barrier_listener_chirho
            .local_addr()
            .expect("read barrier address");
        let mut controller_chirho = TcpBarrierControllerChirho::arm_chirho(
            barrier_listener_chirho,
            upstream_addr_chirho,
            BarrierModeChirho::NetworkPartitionChirho,
        );
        assert_eq!(
            controller_chirho.status_chirho().phase_chirho,
            BarrierPhaseChirho::ArmedChirho
        );

        let mut client_chirho = TcpStream::connect(barrier_addr_chirho).expect("connect barrier");
        client_chirho
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("set client timeout");
        thread::sleep(Duration::from_millis(50));

        assert_eq!(
            controller_chirho.disconnect_chirho().phase_chirho,
            BarrierPhaseChirho::DisconnectedChirho
        );
        let mut byte_chirho = [0_u8; 1];
        let read_result_chirho = client_chirho.read(&mut byte_chirho);
        let disconnected_chirho = match &read_result_chirho {
            Ok(0) => true,
            Err(error_chirho) => matches!(
                error_chirho.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::TimedOut
            ),
            Ok(_) => false,
        };
        assert!(
            disconnected_chirho,
            "disconnect must tear down an existing stream: {read_result_chirho:?}"
        );
        assert_eq!(
            controller_chirho.heal_chirho().phase_chirho,
            BarrierPhaseChirho::HealedChirho
        );
        assert_eq!(
            controller_chirho.cleanup_chirho().phase_chirho,
            BarrierPhaseChirho::CleanedChirho
        );
        upstream_thread_chirho.join().expect("upstream exits");
    }

    #[test]
    fn barrier_status_distinguishes_partition_and_hung_driver_modes_chirho() {
        let upstream_listener_chirho = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
        let upstream_addr_chirho = upstream_listener_chirho
            .local_addr()
            .expect("read upstream address");
        let partition_listener_chirho = TcpListener::bind("127.0.0.1:0").expect("bind partition");
        let driver_listener_chirho = TcpListener::bind("127.0.0.1:0").expect("bind driver");
        let mut partition_barrier_chirho = TcpBarrierControllerChirho::arm_chirho(
            partition_listener_chirho,
            upstream_addr_chirho,
            BarrierModeChirho::NetworkPartitionChirho,
        );
        let mut driver_barrier_chirho = TcpBarrierControllerChirho::arm_chirho(
            driver_listener_chirho,
            upstream_addr_chirho,
            BarrierModeChirho::HungDriverChirho,
        );
        assert_eq!(
            partition_barrier_chirho.status_chirho().mode_chirho,
            BarrierModeChirho::NetworkPartitionChirho
        );
        assert_eq!(
            driver_barrier_chirho.status_chirho().mode_chirho,
            BarrierModeChirho::HungDriverChirho
        );
        assert_ne!(
            partition_barrier_chirho.status_chirho().mode_chirho,
            driver_barrier_chirho.status_chirho().mode_chirho
        );
        partition_barrier_chirho.cleanup_chirho();
        driver_barrier_chirho.cleanup_chirho();
    }

    #[test]
    fn one_direction_only_plant_refuses_partition_classification_chirho() {
        let upstream_listener_chirho = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
        let upstream_addr_chirho = upstream_listener_chirho
            .local_addr()
            .expect("read upstream address");
        let barrier_listener_chirho = TcpListener::bind("127.0.0.1:0").expect("bind barrier");
        let refusal_result_chirho = TcpBarrierControllerChirho::try_arm_chirho(
            barrier_listener_chirho,
            upstream_addr_chirho,
            BarrierModeChirho::NetworkPartitionChirho,
            BarrierDirectionChirho::OneDirectionChirho,
        );
        let refusal_chirho = match refusal_result_chirho {
            Err(refusal_chirho) => refusal_chirho,
            Ok(_) => panic!("asymmetric reachability must not be classified as a partition"),
        };
        assert_eq!(
            refusal_chirho,
            BarrierAdmissionRefusalChirho::AsymmetricTransportChirho
        );
    }
}
