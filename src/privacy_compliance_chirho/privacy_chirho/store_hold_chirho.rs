// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! TESTS ONLY: a one-shot hold that parks a private store between its admission and its key file, so a test can force the interleaving an erasure must never fall into (R-C5-4a).

use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Mutex;

struct ArmedHoldChirho {
    root_chirho: PathBuf,
    reached_chirho: Sender<()>,
    release_chirho: Receiver<()>,
}

static ARMED_HOLD_CHIRHO: Mutex<Option<ArmedHoldChirho>> = Mutex::new(None);

/// Arm the hold for one store on this root. The test receives "reached" and sends "release".
pub(crate) fn arm_chirho(root_chirho: &Path) -> (Receiver<()>, Sender<()>) {
    let (reached_tx_chirho, reached_rx_chirho) = channel();
    let (release_tx_chirho, release_rx_chirho) = channel();
    *ARMED_HOLD_CHIRHO.lock().unwrap() = Some(ArmedHoldChirho {
        root_chirho: root_chirho.to_path_buf(),
        reached_chirho: reached_tx_chirho,
        release_chirho: release_rx_chirho,
    });
    (reached_rx_chirho, release_tx_chirho)
}

/// Where a store sits after admission and before its key file. Only the armed root's next store waits.
pub(crate) fn reach_chirho(root_chirho: &Path) {
    let armed_chirho = {
        let mut slot_chirho = ARMED_HOLD_CHIRHO.lock().unwrap();
        match slot_chirho.as_ref() {
            Some(armed_chirho) if armed_chirho.root_chirho == root_chirho => slot_chirho.take(),
            _ => None,
        }
    };
    if let Some(armed_chirho) = armed_chirho {
        let _ = armed_chirho.reached_chirho.send(());
        let _ = armed_chirho.release_chirho.recv();
    }
}
