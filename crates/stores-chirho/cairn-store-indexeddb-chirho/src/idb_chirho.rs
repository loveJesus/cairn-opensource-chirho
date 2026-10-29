// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! The **wasm-only** IndexedDB + Web Locks layer (compiled only under `cfg(target_arch = "wasm32",
//! feature = "browser-chirho")`). All of the IndexedDB request→future ceremony and the Web Locks
//! bridge live here, so the generic `KvAsyncChirho` adapter in `lib.rs` stays small and readable.
//!
//! IndexedDB requests are event-based (onsuccess/onerror), so `await_request_chirho` bridges one
//! `IdbRequest` into a future via a `futures_channel` oneshot (closures kept alive across the await,
//! then dropped — no leak). [`with_web_lock_chirho`] wraps a critical section in the Web Locks API
//! (`navigator.locks.request`) for cross-tab append serialization; it is reached through `js_sys`
//! `Reflect` (web-sys gates `LockManager` behind `web_sys_unstable_apis`, which we avoid so the build
//! gate needs no special flag). It is compile-verified here and exercised through the documented
//! browser harness — cross-tab behaviour is not headless-testable.

use crate::{KvAsyncAuditLogChirho, KvAsyncChirho};
use anyhow::{anyhow, Result};
use cairn_core_chirho::ports_chirho::AuditLogAsyncChirho;
use js_sys::{Function, Promise, Reflect};
use std::cell::RefCell;
use std::rc::Rc;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::{future_to_promise, JsFuture};

/// Bridge one event-based `IdbRequest` into a future. The onsuccess/onerror closures are held in
/// local bindings across the `.await` (so they outlive the callback) and dropped right after.
async fn await_request_chirho(req_chirho: &web_sys::IdbRequest) -> Result<JsValue> {
    let (tx_chirho, rx_chirho) = futures_channel::oneshot::channel::<Result<JsValue, JsValue>>();
    let tx_chirho = Rc::new(RefCell::new(Some(tx_chirho)));

    let req_success_chirho = req_chirho.clone();
    let tx_success_chirho = tx_chirho.clone();
    let onsuccess_chirho = Closure::<dyn FnMut()>::new(move || {
        if let Some(tx_chirho) = tx_success_chirho.borrow_mut().take() {
            let _ = tx_chirho.send(req_success_chirho.result());
        }
    });

    let req_error_chirho = req_chirho.clone();
    let tx_error_chirho = tx_chirho.clone();
    let onerror_chirho = Closure::<dyn FnMut()>::new(move || {
        if let Some(tx_chirho) = tx_error_chirho.borrow_mut().take() {
            let err_chirho = req_error_chirho
                .error()
                .ok()
                .flatten()
                .map(JsValue::from)
                .unwrap_or(JsValue::NULL);
            let _ = tx_chirho.send(Err(err_chirho));
        }
    });

    req_chirho.set_onsuccess(Some(onsuccess_chirho.as_ref().unchecked_ref()));
    req_chirho.set_onerror(Some(onerror_chirho.as_ref().unchecked_ref()));
    let out_chirho = rx_chirho
        .await
        .map_err(|_| anyhow!("idb request canceled"))?;
    drop(onsuccess_chirho);
    drop(onerror_chirho);
    out_chirho.map_err(|e_chirho| anyhow!("idb request failed: {e_chirho:?}"))
}

/// A real browser IndexedDB-backed [`KvAsyncChirho`]: one object store of `key -> string`. Opened
/// once (creating the store on first upgrade) and shared via `Rc`.
pub struct IdbKvChirho {
    db_chirho: Rc<web_sys::IdbDatabase>,
    store_chirho: String,
}

impl IdbKvChirho {
    /// Open (or create) `db_name_chirho` with a single object store `store_name_chirho`.
    pub async fn open_chirho(db_name_chirho: &str, store_name_chirho: &str) -> Result<Self> {
        let factory_chirho = web_sys::window()
            .ok_or_else(|| anyhow!("no window (not a browser context)"))?
            .indexed_db()
            .map_err(|_| anyhow!("indexedDB access denied"))?
            .ok_or_else(|| anyhow!("indexedDB unavailable"))?;
        let open_req_chirho = factory_chirho
            .open_with_u32(db_name_chirho, 1)
            .map_err(|_| anyhow!("indexedDB open failed"))?;

        let store_name_owned_chirho = store_name_chirho.to_string();
        let open_req_upgrade_chirho = open_req_chirho.clone();
        let onupgrade_chirho = Closure::<dyn FnMut()>::new(move || {
            if let Ok(result_chirho) = open_req_upgrade_chirho.result() {
                if let Ok(db_chirho) = result_chirho.dyn_into::<web_sys::IdbDatabase>() {
                    let _ = db_chirho.create_object_store(&store_name_owned_chirho);
                }
            }
        });
        open_req_chirho.set_onupgradeneeded(Some(onupgrade_chirho.as_ref().unchecked_ref()));
        await_request_chirho(open_req_chirho.as_ref()).await?;
        drop(onupgrade_chirho);

        let db_chirho = open_req_chirho
            .result()
            .map_err(|_| anyhow!("idb open produced no result"))?
            .dyn_into::<web_sys::IdbDatabase>()
            .map_err(|_| anyhow!("idb open result is not an IdbDatabase"))?;
        Ok(Self {
            db_chirho: Rc::new(db_chirho),
            store_chirho: store_name_chirho.to_string(),
        })
    }

    fn store_chirho(
        &self,
        mode_chirho: web_sys::IdbTransactionMode,
    ) -> Result<web_sys::IdbObjectStore> {
        let txn_chirho = self
            .db_chirho
            .transaction_with_str_and_mode(&self.store_chirho, mode_chirho)
            .map_err(|_| anyhow!("idb transaction failed"))?;
        txn_chirho
            .object_store(&self.store_chirho)
            .map_err(|_| anyhow!("idb object_store missing"))
    }
}

impl KvAsyncChirho for IdbKvChirho {
    async fn get_chirho(&self, key_chirho: &str) -> Result<Option<String>> {
        let store_chirho = self.store_chirho(web_sys::IdbTransactionMode::Readonly)?;
        let req_chirho = store_chirho
            .get(&JsValue::from_str(key_chirho))
            .map_err(|_| anyhow!("idb get failed"))?;
        let val_chirho = await_request_chirho(&req_chirho).await?;
        if val_chirho.is_undefined() || val_chirho.is_null() {
            Ok(None)
        } else {
            Ok(val_chirho.as_string())
        }
    }

    async fn set_chirho(&self, key_chirho: &str, value_chirho: &str) -> Result<()> {
        let store_chirho = self.store_chirho(web_sys::IdbTransactionMode::Readwrite)?;
        let req_chirho = store_chirho
            .put_with_key(
                &JsValue::from_str(value_chirho),
                &JsValue::from_str(key_chirho),
            )
            .map_err(|_| anyhow!("idb put failed (quota or security error)"))?;
        await_request_chirho(&req_chirho).await?;
        Ok(())
    }

    async fn keys_with_prefix_chirho(&self, prefix_chirho: &str) -> Result<Vec<String>> {
        let store_chirho = self.store_chirho(web_sys::IdbTransactionMode::Readonly)?;
        let req_chirho = store_chirho
            .get_all_keys()
            .map_err(|_| anyhow!("idb get_all_keys failed"))?;
        let val_chirho = await_request_chirho(&req_chirho).await?;
        let mut keys_chirho = Vec::new();
        for key_value_chirho in js_sys::Array::from(&val_chirho).iter() {
            if let Some(key_chirho) = key_value_chirho.as_string() {
                if key_chirho.starts_with(prefix_chirho) {
                    keys_chirho.push(key_chirho);
                }
            }
        }
        Ok(keys_chirho)
    }
}

/// Run `work_chirho` while holding a cross-tab Web Lock named `name_chirho` (the audit-append
/// critical section, in a browser composition root). The lock is released when `work_chirho`
/// completes. `work_chirho` must be `'static` (it is handed to JS via `future_to_promise`), so a
/// browser composition root captures owned / `Rc` handles rather than borrows. Reached via `js_sys`
/// `Reflect` to avoid the `web_sys_unstable_apis` gate; cross-tab serialization is exercised by the
/// documented harness (not headless-testable).
pub async fn with_web_lock_chirho<F>(name_chirho: &str, work_chirho: F) -> Result<()>
where
    F: core::future::Future<Output = Result<()>> + 'static,
{
    let (tx_chirho, rx_chirho) = futures_channel::oneshot::channel::<Result<()>>();
    let tx_chirho = Rc::new(RefCell::new(Some(tx_chirho)));
    let work_chirho = Rc::new(RefCell::new(Some(work_chirho)));

    let tx_cb_chirho = tx_chirho.clone();
    let work_cb_chirho = work_chirho.clone();
    let callback_chirho =
        Closure::<dyn FnMut(JsValue) -> Promise>::new(move |_lock_chirho: JsValue| {
            let tx_inner_chirho = tx_cb_chirho.clone();
            let work_inner_chirho = work_cb_chirho.borrow_mut().take();
            future_to_promise(async move {
                if let Some(work_chirho) = work_inner_chirho {
                    let result_chirho = work_chirho.await;
                    if let Some(tx_chirho) = tx_inner_chirho.borrow_mut().take() {
                        let _ = tx_chirho.send(result_chirho);
                    }
                }
                Ok(JsValue::UNDEFINED)
            })
        });

    // navigator.locks.request(name, callback) via Reflect (no web_sys_unstable_apis cfg needed).
    let navigator_chirho = web_sys::window()
        .ok_or_else(|| anyhow!("no window (not a browser context)"))?
        .navigator();
    let locks_chirho = Reflect::get(navigator_chirho.as_ref(), &JsValue::from_str("locks"))
        .map_err(|_| anyhow!("navigator.locks unavailable (Web Locks API unsupported)"))?;
    if locks_chirho.is_undefined() || locks_chirho.is_null() {
        return Err(anyhow!(
            "navigator.locks unavailable (Web Locks API unsupported)"
        ));
    }
    let request_fn_chirho: Function = Reflect::get(&locks_chirho, &JsValue::from_str("request"))
        .map_err(|_| anyhow!("navigator.locks.request missing"))?
        .dyn_into()
        .map_err(|_| anyhow!("navigator.locks.request is not a function"))?;
    let promise_chirho: Promise = request_fn_chirho
        .call2(
            &locks_chirho,
            &JsValue::from_str(name_chirho),
            callback_chirho.as_ref(),
        )
        .map_err(|_| anyhow!("navigator.locks.request call failed"))?
        .dyn_into()
        .map_err(|_| anyhow!("navigator.locks.request did not return a promise"))?;
    JsFuture::from(promise_chirho)
        .await
        .map_err(|_| anyhow!("web lock request rejected"))?;
    drop(callback_chirho);
    rx_chirho
        .await
        .map_err(|_| anyhow!("web lock critical section dropped"))?
}

/// Composition-root helper: perform ONE audit append under a cross-tab Web Lock. This is the concrete
/// demonstration of wiring [`with_web_lock_chirho`] around a real append — it takes the `IdbKvChirho`
/// and the append inputs BY VALUE so the critical-section future is `'static` (the constraint
/// `navigator.locks` imposes). The generic `KvAsyncAuditLogChirho::append_chirho` itself stays
/// lock-free + portable; this wraps it for browsers that need cross-tab ordering. NOTE: the append is
/// still a record-`put` + head-`put` (two IndexedDB operations, not one transaction); the lock
/// serializes them across tabs but does not make them a single IDB transaction.
pub async fn locked_idb_append_chirho(
    kv_chirho: IdbKvChirho,
    namespace_chirho: &str,
    lock_name_chirho: &str,
    writer_chirho: String,
    payload_chirho: Vec<u8>,
) -> Result<()> {
    let log_chirho = KvAsyncAuditLogChirho::new_chirho(kv_chirho, namespace_chirho);
    with_web_lock_chirho(lock_name_chirho, async move {
        let _record_hash_chirho = log_chirho
            .append_chirho(&writer_chirho, &payload_chirho)
            .await
            .map_err(anyhow::Error::from)?;
        Ok(())
    })
    .await
}
