//! Self-refreshing SCITT root key store with periodic and on-demand refresh.
//!
//! [`RefreshableKeyStore`] wraps a [`ScittKeyStore`] with background periodic
//! refresh (default 24h) and cooldown-gated on-demand refresh when an
//! [`UnknownKeyId`](super::error::ScittError::UnknownKeyId) is encountered.
//!
//! # Merge semantics
//!
//! Keys once loaded are **never evicted** — each refresh only adds newly
//! discovered keys. This ensures that a signing key used in the past remains
//! verifiable even if the TL stops advertising it.
//!
//! # Anti-amplification
//!
//! On-demand refresh is rate-limited by a configurable cooldown (default 5
//! minutes). Within the cooldown window, `refresh_if_cooldown_elapsed`
//! returns immediately without making a network call. This prevents an
//! attacker from using garbage `kid` values to turn every agent into a
//! reflector against the transparency log.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, RwLock};
use tokio_util::sync::CancellationToken;

use super::ClockFn;
use super::client::ScittClient;
use super::error::ScittError;
use super::root_keys::ScittKeyStore;
use super::system_clock;

/// Default background refresh interval: 24 hours.
const DEFAULT_KEY_REFRESH_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Default on-demand cooldown: 5 minutes.
///
/// Within this window after a refresh, `refresh_if_cooldown_elapsed` is a
/// no-op. This bounds the worst-case TL request rate to `1 / cooldown`
/// regardless of inbound traffic volume.
const DEFAULT_ON_DEMAND_COOLDOWN: Duration = Duration::from_secs(5 * 60);

/// Internal mutable state protected by `RwLock`.
struct KeyStoreState {
    /// Current immutable snapshot. Readers clone the `Arc` cheaply.
    snapshot: Arc<ScittKeyStore>,
    /// Unix timestamp of last successful refresh, or `None` if never refreshed.
    last_refreshed: Option<i64>,
}

/// Shared inner state wrapped in `Arc` for cheap cloning.
struct Inner {
    /// `None` means this is a static store (tests / offline). `do_refresh`
    /// is a no-op when the client is absent.
    client: Option<Arc<dyn ScittClient>>,
    /// Cooldown in seconds for on-demand refresh.
    on_demand_cooldown_secs: i64,
    /// Clock function for cooldown and timestamp tracking.
    clock: ClockFn,
    state: RwLock<KeyStoreState>,
    /// Serialises on-demand refresh attempts so that concurrent
    /// `UnknownKeyId` callers don't all bypass the cooldown check.
    refresh_gate: Mutex<()>,
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshableKeyStoreInner")
            .field("has_client", &self.client.is_some())
            .field("cooldown_secs", &self.on_demand_cooldown_secs)
            .finish_non_exhaustive()
    }
}

/// A self-refreshing SCITT root key store.
///
/// Wraps [`ScittKeyStore`] with periodic background refresh and
/// cooldown-gated on-demand refresh. The store is `Clone` (wraps
/// `Arc<Inner>`) so a single instance can be shared across verifier
/// and supplier components.
///
/// # Construction
///
/// ```rust,ignore
/// // With a client for live refresh
/// let store = RefreshableKeyStore::new(initial_keys, scitt_client);
/// let _handle = store.start_background_refresh_default();
///
/// // Static / offline (no refresh capability)
/// let store = RefreshableKeyStore::from_static(initial_keys);
/// ```
#[derive(Clone, Debug)]
pub struct RefreshableKeyStore {
    inner: Arc<Inner>,
}

impl RefreshableKeyStore {
    /// Create a refreshable store from initial keys and a client for future refreshes.
    ///
    /// The initial keys are typically fetched at startup via
    /// [`ScittClient::fetch_root_keys`]. The `client` is used for periodic
    /// and on-demand refreshes only.
    pub fn new(initial: ScittKeyStore, client: Arc<dyn ScittClient>) -> Self {
        Self {
            inner: Arc::new(Inner {
                client: Some(client),
                on_demand_cooldown_secs: DEFAULT_ON_DEMAND_COOLDOWN
                    .as_secs()
                    .try_into()
                    .unwrap_or(i64::MAX),
                clock: system_clock(),
                state: RwLock::new(KeyStoreState {
                    snapshot: Arc::new(initial),
                    last_refreshed: None,
                }),
                refresh_gate: Mutex::new(()),
            }),
        }
    }

    /// Create a refreshable store with a custom on-demand cooldown.
    pub fn with_cooldown(
        initial: ScittKeyStore,
        client: Arc<dyn ScittClient>,
        cooldown: Duration,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                client: Some(client),
                on_demand_cooldown_secs: cooldown.as_secs().try_into().unwrap_or(i64::MAX),
                clock: system_clock(),
                state: RwLock::new(KeyStoreState {
                    snapshot: Arc::new(initial),
                    last_refreshed: None,
                }),
                refresh_gate: Mutex::new(()),
            }),
        }
    }

    /// Create a static store with no refresh capability.
    ///
    /// Useful for tests and offline environments where root keys are known
    /// ahead of time. [`do_refresh`](Self::do_refresh) is a silent no-op and
    /// [`refresh_if_cooldown_elapsed`](Self::refresh_if_cooldown_elapsed)
    /// always returns `Ok(false)`.
    pub fn from_static(initial: ScittKeyStore) -> Self {
        Self {
            inner: Arc::new(Inner {
                client: None,
                on_demand_cooldown_secs: DEFAULT_ON_DEMAND_COOLDOWN
                    .as_secs()
                    .try_into()
                    .unwrap_or(i64::MAX),
                clock: system_clock(),
                state: RwLock::new(KeyStoreState {
                    snapshot: Arc::new(initial),
                    last_refreshed: None,
                }),
                refresh_gate: Mutex::new(()),
            }),
        }
    }

    /// Override the clock function used for cooldown and timestamp tracking.
    ///
    /// Must be called before cloning the store. Defaults to [`system_clock`](super::system_clock).
    #[allow(clippy::expect_used)] // Intentional: builder-phase invariant, Arc is unshared
    pub fn with_clock(mut self, clock: ClockFn) -> Self {
        Arc::get_mut(&mut self.inner)
            .expect("with_clock must be called before cloning")
            .clock = clock;
        self
    }

    /// Get a cheap `Arc` clone of the current key snapshot.
    ///
    /// This is the primary read path — pass the snapshot to
    /// [`verify_receipt`](super::receipt::verify_receipt) or
    /// [`verify_status_token`](super::status_token::verify_status_token).
    pub async fn current_snapshot(&self) -> Arc<ScittKeyStore> {
        self.inner.state.read().await.snapshot.clone()
    }

    /// Attempt an on-demand refresh if the cooldown has elapsed.
    ///
    /// - If within cooldown (or no client): returns `Ok(false)` immediately.
    /// - If refresh succeeds: returns `Ok(true)`.
    /// - If the network call or parse fails: returns `Err(ScittError)`.
    ///   The existing snapshot is unchanged on failure.
    ///
    /// This is the path triggered by
    /// [`UnknownKeyId`](super::error::ScittError::UnknownKeyId) in the
    /// verifier retry logic.
    pub async fn refresh_if_cooldown_elapsed(&self) -> Result<bool, ScittError> {
        if self.inner.client.is_none() {
            return Ok(false);
        }

        // Serialise on-demand refresh: only one caller enters the gate at a
        // time. Others wait, then re-check the cooldown (which will likely
        // show that a refresh just happened and return false).
        let _guard = self.inner.refresh_gate.lock().await;

        let should_refresh = {
            let state = self.inner.state.read().await;
            match state.last_refreshed {
                None => true,
                Some(ts) => {
                    let now = (self.inner.clock)();
                    (now - ts) >= self.inner.on_demand_cooldown_secs
                }
            }
        };

        if !should_refresh {
            return Ok(false);
        }

        self.do_refresh().await?;
        Ok(true)
    }

    /// Force an immediate refresh regardless of cooldown.
    ///
    /// Fetches new keys from the TL, parses them, and merges into the
    /// existing store. Existing keys are never removed — only new `kid`
    /// entries are added. Updates `last_refreshed` on success.
    ///
    /// If no client is configured (static store), this is a silent no-op.
    ///
    /// # Errors
    ///
    /// Returns [`ScittError`] if the fetch or parse fails. The existing
    /// snapshot is unchanged on failure.
    pub async fn do_refresh(&self) -> Result<(), ScittError> {
        let Some(client) = &self.inner.client else {
            tracing::debug!("Static RefreshableKeyStore — refresh is a no-op");
            return Ok(());
        };

        // Fetch new keys before acquiring any lock.
        let key_strings = client.fetch_root_keys().await?;

        // Merge under the write lock so that a concurrent refresh cannot
        // overwrite keys added by another in-flight refresh.
        let now = (self.inner.clock)();
        let mut state = self.inner.state.write().await;
        let merged = state.snapshot.merge_from(&key_strings);
        state.snapshot = Arc::new(merged);
        state.last_refreshed = Some(now);

        Ok(())
    }

    /// Start periodic background key refresh.
    ///
    /// The background task runs every `interval`, fetching and merging new
    /// keys. Errors are logged at `tracing::warn!` and do not terminate the
    /// loop. The task is cancelled when the returned [`KeyRefreshHandle`] is
    /// dropped.
    pub fn start_background_refresh(&self, interval: Duration) -> KeyRefreshHandle {
        let cancel = CancellationToken::new();
        let store = self.clone();
        let cancel_clone = cancel.clone();

        let task = tokio::spawn(async move {
            tracing::info!(
                interval_secs = interval.as_secs(),
                "SCITT root key background refresh started"
            );
            let mut consecutive_failures: u32 = 0;
            loop {
                tokio::select! {
                    () = tokio::time::sleep(interval) => {
                        match store.do_refresh().await {
                            Ok(()) => {
                                consecutive_failures = 0;
                                let count = store.current_snapshot().await.len();
                                tracing::debug!(key_count = count, "SCITT root keys refreshed");
                            }
                            Err(e) => {
                                consecutive_failures = consecutive_failures.saturating_add(1);
                                tracing::warn!(
                                    error = %e,
                                    consecutive_failures,
                                    "Background SCITT key refresh failed"
                                );
                            }
                        }
                    }
                    () = cancel_clone.cancelled() => {
                        tracing::debug!("SCITT key background refresh cancelled");
                        break;
                    }
                }
            }
        });

        KeyRefreshHandle { cancel, task }
    }

    /// Start background refresh with the default 24-hour interval.
    pub fn start_background_refresh_default(&self) -> KeyRefreshHandle {
        self.start_background_refresh(DEFAULT_KEY_REFRESH_INTERVAL)
    }

    /// Number of keys currently in the store.
    pub async fn len(&self) -> usize {
        self.inner.state.read().await.snapshot.len()
    }

    /// Returns `true` if the store contains no keys.
    pub async fn is_empty(&self) -> bool {
        self.inner.state.read().await.snapshot.is_empty()
    }

    /// Returns the Unix timestamp of the last successful refresh, or `None`.
    pub async fn last_refreshed(&self) -> Option<i64> {
        self.inner.state.read().await.last_refreshed
    }

    /// Returns the number of seconds since the last successful refresh,
    /// or `None` if no refresh has succeeded yet.
    ///
    /// Useful for staleness monitoring: operators can alert when this value
    /// exceeds a threshold (e.g., 2× the refresh interval).
    pub async fn last_refreshed_age_secs(&self) -> Option<i64> {
        let last = self.inner.state.read().await.last_refreshed?;
        let now = (self.inner.clock)();
        Some(now - last)
    }
}

/// Handle to a background key refresh task. Cancels the task on drop.
pub struct KeyRefreshHandle {
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for KeyRefreshHandle {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}

impl std::fmt::Debug for KeyRefreshHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyRefreshHandle")
            .field("cancelled", &self.cancel.is_cancelled())
            .field("task_finished", &self.task.is_finished())
            .finish()
    }
}

// =========================================================================
// Tests
// =========================================================================

#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use base64::Engine as _;
    use base64::prelude::BASE64_STANDARD;
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::EncodePublicKey as _;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::scitt::client::MockScittClient;

    // ── Test helpers ─────────────────────────────────────────────────

    fn make_c2sp_key_string(seed: u8, name: &str) -> String {
        let signing_key = SigningKey::from_slice(&[seed; 32]).unwrap();
        let verifying_key = signing_key.verifying_key();
        let spki_doc = verifying_key.to_public_key_der().unwrap();
        let spki_der = spki_doc.as_bytes();
        let digest = Sha256::digest(spki_der);
        let kid: [u8; 4] = [digest[0], digest[1], digest[2], digest[3]];
        let key_hash_hex = hex::encode(kid);
        let spki_b64 = BASE64_STANDARD.encode(spki_der);
        format!("{name}+{key_hash_hex}+{spki_b64}")
    }

    fn make_store_with_key(seed: u8) -> (ScittKeyStore, [u8; 4]) {
        let key_string = make_c2sp_key_string(seed, "tl.example.com");
        let store = ScittKeyStore::from_c2sp_keys(&[key_string]).unwrap();
        let signing_key = SigningKey::from_slice(&[seed; 32]).unwrap();
        let spki_doc = signing_key.verifying_key().to_public_key_der().unwrap();
        let digest = Sha256::digest(spki_doc.as_bytes());
        let kid: [u8; 4] = [digest[0], digest[1], digest[2], digest[3]];
        (store, kid)
    }

    // ── Construction ────────────────────────────────────────────────

    #[tokio::test]
    async fn new_contains_initial_keys() {
        let (store, kid) = make_store_with_key(1);
        let client: Arc<dyn ScittClient> = Arc::new(MockScittClient::new());
        let refreshable = RefreshableKeyStore::new(store, client);

        let snapshot = refreshable.current_snapshot().await;
        assert_eq!(snapshot.len(), 1);
        assert!(snapshot.get(kid).is_ok());
    }

    #[tokio::test]
    async fn from_static_refresh_is_noop() {
        let (store, kid) = make_store_with_key(1);
        let refreshable = RefreshableKeyStore::from_static(store);

        // do_refresh succeeds but does nothing
        refreshable.do_refresh().await.unwrap();
        assert!(refreshable.last_refreshed().await.is_none());

        // refresh_if_cooldown_elapsed returns false
        assert!(!refreshable.refresh_if_cooldown_elapsed().await.unwrap());

        // Keys are still intact
        let snapshot = refreshable.current_snapshot().await;
        assert!(snapshot.get(kid).is_ok());
    }

    // ── do_refresh ──────────────────────────────────────────────────

    #[tokio::test]
    async fn do_refresh_merges_new_keys_preserves_existing() {
        let (store, kid1) = make_store_with_key(1);
        let key2_string = make_c2sp_key_string(2, "tl2.example.com");
        let (_, kid2) = make_store_with_key(2);

        let client: Arc<dyn ScittClient> =
            Arc::new(MockScittClient::new().with_root_keys(vec![key2_string]));
        let refreshable = RefreshableKeyStore::new(store, client);

        refreshable.do_refresh().await.unwrap();

        let snapshot = refreshable.current_snapshot().await;
        assert_eq!(snapshot.len(), 2);
        assert!(snapshot.get(kid1).is_ok());
        assert!(snapshot.get(kid2).is_ok());
    }

    #[tokio::test]
    async fn do_refresh_does_not_overwrite_existing_kid() {
        let (store, kid) = make_store_with_key(1);
        let key1_string = make_c2sp_key_string(1, "tl.example.com");
        let original_name = store.get(kid).unwrap().name.clone();

        // Client returns the same key — should not replace
        let client: Arc<dyn ScittClient> =
            Arc::new(MockScittClient::new().with_root_keys(vec![key1_string]));
        let refreshable = RefreshableKeyStore::new(store, client);

        refreshable.do_refresh().await.unwrap();

        let snapshot = refreshable.current_snapshot().await;
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot.get(kid).unwrap().name, original_name);
    }

    #[tokio::test]
    async fn do_refresh_fails_gracefully_preserves_snapshot() {
        let (store, kid) = make_store_with_key(1);

        let client: Arc<dyn ScittClient> =
            Arc::new(MockScittClient::new().with_error("root_keys", || ScittError::NotACoseSign1));
        let refreshable = RefreshableKeyStore::new(store, client);

        let result = refreshable.do_refresh().await;
        assert!(result.is_err());

        // Snapshot unchanged
        let snapshot = refreshable.current_snapshot().await;
        assert_eq!(snapshot.len(), 1);
        assert!(snapshot.get(kid).is_ok());
        assert!(refreshable.last_refreshed().await.is_none());
    }

    // ── Cooldown logic ──────────────────────────────────────────────

    #[tokio::test]
    async fn refresh_if_cooldown_elapsed_returns_true_when_never_refreshed() {
        let (store, _) = make_store_with_key(1);
        let key2_string = make_c2sp_key_string(2, "tl2.example.com");

        let client: Arc<dyn ScittClient> =
            Arc::new(MockScittClient::new().with_root_keys(vec![key2_string]));
        let refreshable = RefreshableKeyStore::new(store, client);

        assert!(refreshable.last_refreshed().await.is_none());
        let result = refreshable.refresh_if_cooldown_elapsed().await.unwrap();
        assert!(result);
        assert!(refreshable.last_refreshed().await.is_some());
    }

    #[tokio::test]
    async fn refresh_if_cooldown_elapsed_returns_false_within_cooldown() {
        let key_string = make_c2sp_key_string(1, "tl.example.com");

        let client: Arc<dyn ScittClient> =
            Arc::new(MockScittClient::new().with_root_keys(vec![key_string.clone()]));
        // Use a very long cooldown so we're always within it after first refresh
        let refreshable = RefreshableKeyStore::with_cooldown(
            ScittKeyStore::from_c2sp_keys(&[key_string]).unwrap(),
            client,
            Duration::from_secs(3600),
        );

        // First refresh — should succeed (never refreshed)
        let first = refreshable.refresh_if_cooldown_elapsed().await.unwrap();
        assert!(first);

        // Second refresh immediately — within cooldown
        let second = refreshable.refresh_if_cooldown_elapsed().await.unwrap();
        assert!(!second);
    }

    #[tokio::test]
    async fn refresh_if_cooldown_elapsed_returns_true_after_cooldown() {
        let (store, _) = make_store_with_key(1);
        let key_string = make_c2sp_key_string(1, "tl.example.com");

        let client: Arc<dyn ScittClient> =
            Arc::new(MockScittClient::new().with_root_keys(vec![key_string]));
        // Use a zero-second cooldown so it's always elapsed
        let refreshable = RefreshableKeyStore::with_cooldown(store, client, Duration::ZERO);

        // First refresh
        let first = refreshable.refresh_if_cooldown_elapsed().await.unwrap();
        assert!(first);

        // Second refresh immediately — cooldown is 0s so it's already elapsed
        let second = refreshable.refresh_if_cooldown_elapsed().await.unwrap();
        assert!(second);
    }

    #[tokio::test]
    async fn custom_cooldown_is_respected() {
        let (store, _) = make_store_with_key(1);
        let key_string = make_c2sp_key_string(1, "tl.example.com");

        let client: Arc<dyn ScittClient> =
            Arc::new(MockScittClient::new().with_root_keys(vec![key_string]));
        let refreshable =
            RefreshableKeyStore::with_cooldown(store, client, Duration::from_secs(9999));

        // First call triggers refresh (never refreshed before)
        assert!(refreshable.refresh_if_cooldown_elapsed().await.unwrap());

        // Within cooldown — returns false
        assert!(!refreshable.refresh_if_cooldown_elapsed().await.unwrap());
    }

    // ── Timestamp tracking ──────────────────────────────────────────

    #[tokio::test]
    async fn last_refreshed_updates_on_success() {
        let (store, _) = make_store_with_key(1);
        let key_string = make_c2sp_key_string(1, "tl.example.com");
        let client: Arc<dyn ScittClient> =
            Arc::new(MockScittClient::new().with_root_keys(vec![key_string]));
        let refreshable = RefreshableKeyStore::new(store, client);

        assert!(refreshable.last_refreshed().await.is_none());
        refreshable.do_refresh().await.unwrap();

        let ts = refreshable.last_refreshed().await.unwrap();
        let now = chrono::Utc::now().timestamp();
        assert!((now - ts).abs() < 5);
    }

    #[tokio::test]
    async fn last_refreshed_unchanged_on_failure() {
        let (store, _) = make_store_with_key(1);
        let client: Arc<dyn ScittClient> =
            Arc::new(MockScittClient::new().with_error("root_keys", || ScittError::NotACoseSign1));
        let refreshable = RefreshableKeyStore::new(store, client);

        let _ = refreshable.do_refresh().await;
        assert!(refreshable.last_refreshed().await.is_none());
    }

    // ── Background refresh ──────────────────────────────────────────

    #[tokio::test]
    async fn background_refresh_handle_cancels_on_drop() {
        let (store, _) = make_store_with_key(1);
        let client: Arc<dyn ScittClient> = Arc::new(MockScittClient::new());
        let refreshable = RefreshableKeyStore::new(store, client);

        let cancel = {
            let handle = refreshable.start_background_refresh(Duration::from_secs(3600));
            let cancel = handle.cancel.clone();
            assert!(!cancel.is_cancelled());
            drop(handle);
            cancel
        };

        assert!(cancel.is_cancelled());
    }

    // ── Concurrency ─────────────────────────────────────────────────

    #[tokio::test]
    async fn concurrent_readers_during_refresh() {
        let (store, kid) = make_store_with_key(1);
        let key2_string = make_c2sp_key_string(2, "tl2.example.com");

        let client: Arc<dyn ScittClient> =
            Arc::new(MockScittClient::new().with_root_keys(vec![key2_string]));
        let refreshable = RefreshableKeyStore::new(store, client);

        // Spawn 10 concurrent readers
        let mut handles = Vec::new();
        for _ in 0..10 {
            let store_clone = refreshable.clone();
            handles.push(tokio::spawn(async move {
                let snapshot = store_clone.current_snapshot().await;
                assert!(snapshot.get(kid).is_ok());
            }));
        }

        // Refresh concurrently with readers
        refreshable.do_refresh().await.unwrap();

        // All readers should complete without deadlock
        for handle in handles {
            handle.await.unwrap();
        }

        // After refresh, both keys present
        let snapshot = refreshable.current_snapshot().await;
        assert_eq!(snapshot.len(), 2);
    }

    // ── Send + Sync ─────────────────────────────────────────────────

    const fn _assert_send_sync<T: Send + Sync>() {}
    const _: () = _assert_send_sync::<RefreshableKeyStore>();
    const _: () = _assert_send_sync::<KeyRefreshHandle>();
}
