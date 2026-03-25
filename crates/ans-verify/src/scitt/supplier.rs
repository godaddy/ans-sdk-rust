//! Agent-side SCITT header supplier for outgoing HTTP traffic.
//!
//! [`ScittHeaderSupplier`] is a self-refreshing provider of an agent's own
//! SCITT headers (`X-SCITT-Receipt`, `X-ANS-Status-Token`). It fetches
//! artifacts from the TL, verifies them (COSE signature + Merkle), caches
//! them, and returns Base64-encoded values ready for HTTP headers.
//!
//! The supplier is `Clone` (wraps `Arc<Inner>`) so a single instance can
//! be shared across server middleware and client request builders.
//!
//! # Lazy initialization
//!
//! Construction is infallible — no network calls. The first call to
//! [`ScittHeaderSupplier::current_headers`] or [`ScittHeaderSupplier::start_auto_refresh`]
//! triggers the initial fetch lazily.
//!
//! # Background refresh
//!
//! Call [`ScittHeaderSupplier::start_auto_refresh`] to keep the status token fresh.
//! The token is re-fetched at 50% TTL. The background task is cancelled on drop
//! of the returned [`ScittRefreshHandle`].

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::client::ScittClient;
use super::error::ScittError;
use super::receipt::verify_receipt;
use super::root_keys::ScittKeyStore;
use super::status_token::verify_status_token;

/// Default clock skew tolerance for status token verification (30 seconds).
const DEFAULT_CLOCK_SKEW: Duration = Duration::from_secs(30);

/// Minimum refresh interval to avoid tight loops on very short-lived tokens.
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(10);

/// Ready-to-use header values for outgoing HTTP traffic.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ScittOutgoingHeaders {
    /// Base64-encoded receipt, if available. Set as `X-SCITT-Receipt` header value.
    pub receipt_base64: Option<String>,
    /// Base64-encoded status token, if fresh. Set as `X-ANS-Status-Token` header value.
    pub status_token_base64: Option<String>,
}

/// Handle to a background refresh task. Cancels the task on drop.
pub struct ScittRefreshHandle {
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for ScittRefreshHandle {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl std::fmt::Debug for ScittRefreshHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScittRefreshHandle")
            .field("cancelled", &self.cancel.is_cancelled())
            .field("task_finished", &self.task.is_finished())
            .finish()
    }
}

/// Cached artifacts held under the `RwLock`.
#[derive(Debug, Default)]
struct CachedArtifacts {
    /// Raw receipt bytes (`COSE_Sign1`), already verified.
    receipt_bytes: Option<Vec<u8>>,
    /// Raw status token bytes (`COSE_Sign1`), already verified.
    status_token_bytes: Option<Vec<u8>>,
    /// Token expiry (Unix timestamp) for refresh scheduling.
    token_exp: Option<i64>,
}

/// Inner state shared via `Arc`.
struct ScittHeaderSupplierInner {
    agent_id: Uuid,
    client: Arc<dyn ScittClient>,
    key_store: Arc<ScittKeyStore>,
    clock_skew: Duration,
    artifacts: RwLock<CachedArtifacts>,
}

impl std::fmt::Debug for ScittHeaderSupplierInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScittHeaderSupplierInner")
            .field("agent_id", &self.agent_id)
            .field("clock_skew", &self.clock_skew)
            .finish_non_exhaustive()
    }
}

/// A self-refreshing provider of an agent's own SCITT headers for outgoing HTTP traffic.
///
/// # Example
///
/// ```rust,ignore
/// let supplier = ScittHeaderSupplier::new(agent_id, scitt_client, key_store);
/// let _refresh = supplier.start_auto_refresh(); // keep token fresh
///
/// let headers = supplier.current_headers().await;
/// if let Some(receipt) = &headers.receipt_base64 {
///     response.headers_mut().insert("X-SCITT-Receipt", receipt.parse().unwrap());
/// }
/// ```
#[derive(Clone, Debug)]
pub struct ScittHeaderSupplier {
    inner: Arc<ScittHeaderSupplierInner>,
}

impl ScittHeaderSupplier {
    /// Create a supplier. Construction is infallible — no network calls.
    ///
    /// The first call to [`current_headers`](Self::current_headers) or
    /// [`start_auto_refresh`](Self::start_auto_refresh) triggers the initial fetch.
    pub fn new(
        agent_id: Uuid,
        client: Arc<dyn ScittClient>,
        key_store: Arc<ScittKeyStore>,
    ) -> Self {
        Self {
            inner: Arc::new(ScittHeaderSupplierInner {
                agent_id,
                client,
                key_store,
                clock_skew: DEFAULT_CLOCK_SKEW,
                artifacts: RwLock::new(CachedArtifacts::default()),
            }),
        }
    }

    /// Create a supplier with custom clock skew tolerance for token verification.
    pub fn with_clock_skew(
        agent_id: Uuid,
        client: Arc<dyn ScittClient>,
        key_store: Arc<ScittKeyStore>,
        clock_skew: Duration,
    ) -> Self {
        Self {
            inner: Arc::new(ScittHeaderSupplierInner {
                agent_id,
                client,
                key_store,
                clock_skew,
                artifacts: RwLock::new(CachedArtifacts::default()),
            }),
        }
    }

    /// Start background auto-refresh of the status token.
    ///
    /// The token is re-fetched at 50% TTL. The background task is cancelled
    /// when the returned [`ScittRefreshHandle`] is dropped.
    ///
    /// If no artifacts have been fetched yet, the first refresh cycle fetches them.
    pub fn start_auto_refresh(&self) -> ScittRefreshHandle {
        let cancel = CancellationToken::new();
        let supplier = self.inner.clone();
        let cancel_clone = cancel.clone();

        let task = tokio::spawn(async move {
            // Initial fetch if needed
            if supplier.artifacts.read().await.receipt_bytes.is_none() {
                Self::do_refresh_inner(&supplier).await;
            }

            loop {
                let sleep_duration = {
                    let artifacts = supplier.artifacts.read().await;
                    compute_refresh_interval(artifacts.token_exp)
                };

                tokio::select! {
                    () = tokio::time::sleep(sleep_duration) => {
                        Self::do_refresh_inner(&supplier).await;
                    }
                    () = cancel_clone.cancelled() => {
                        tracing::debug!(agent_id = %supplier.agent_id, "SCITT auto-refresh cancelled");
                        break;
                    }
                }
            }
        });

        ScittRefreshHandle { cancel, task }
    }

    /// Get the current headers for outgoing HTTP requests/responses.
    ///
    /// On first call, performs initial fetch (lazy init). If the fetch fails,
    /// returns `None` for both fields (remote verifier falls back to badge).
    ///
    /// If the status token has expired, returns `None` for the token field.
    pub async fn current_headers(&self) -> ScittOutgoingHeaders {
        // Lazy init: fetch if we have nothing cached
        {
            let artifacts = self.inner.artifacts.read().await;
            if artifacts.receipt_bytes.is_none() && artifacts.status_token_bytes.is_none() {
                drop(artifacts); // release read lock before taking write path
                Self::do_refresh_inner(&self.inner).await;
            }
        }

        let artifacts = self.inner.artifacts.read().await;

        let receipt_base64 = artifacts
            .receipt_bytes
            .as_ref()
            .map(|b| BASE64_STANDARD.encode(b));

        // Only return token if it hasn't expired
        let status_token_base64 = match (&artifacts.status_token_bytes, artifacts.token_exp) {
            (Some(bytes), Some(exp)) => {
                let now = chrono::Utc::now().timestamp();
                if now < exp {
                    Some(BASE64_STANDARD.encode(bytes))
                } else {
                    tracing::debug!(
                        agent_id = %self.inner.agent_id,
                        exp,
                        now,
                        "Cached status token has expired"
                    );
                    None
                }
            }
            _ => None,
        };

        ScittOutgoingHeaders {
            receipt_base64,
            status_token_base64,
        }
    }

    /// Force an immediate refresh of both receipt and status token.
    ///
    /// Useful after certificate renewal or version bump.
    pub async fn refresh_now(&self) -> Result<(), ScittError> {
        self.fetch_and_store_receipt(&self.inner).await?;
        self.fetch_and_store_token(&self.inner).await?;
        Ok(())
    }

    /// Internal refresh that logs errors instead of propagating them.
    async fn do_refresh_inner(inner: &ScittHeaderSupplierInner) {
        if let Err(e) = Self::fetch_and_store_receipt_static(inner).await {
            tracing::warn!(
                agent_id = %inner.agent_id,
                error = %e,
                "Failed to refresh SCITT receipt"
            );
        }
        if let Err(e) = Self::fetch_and_store_token_static(inner).await {
            tracing::warn!(
                agent_id = %inner.agent_id,
                error = %e,
                "Failed to refresh SCITT status token"
            );
        }
    }

    /// Fetch, verify, and store the receipt.
    async fn fetch_and_store_receipt(
        &self,
        inner: &ScittHeaderSupplierInner,
    ) -> Result<(), ScittError> {
        Self::fetch_and_store_receipt_static(inner).await
    }

    /// Fetch, verify, and store the status token.
    async fn fetch_and_store_token(
        &self,
        inner: &ScittHeaderSupplierInner,
    ) -> Result<(), ScittError> {
        Self::fetch_and_store_token_static(inner).await
    }

    /// Fetch, verify, and store the receipt (static version for use in spawned tasks).
    async fn fetch_and_store_receipt_static(
        inner: &ScittHeaderSupplierInner,
    ) -> Result<(), ScittError> {
        let bytes = inner.client.fetch_receipt(inner.agent_id).await?;

        // Verify before caching
        let verified = verify_receipt(&bytes, &inner.key_store)?;

        tracing::debug!(
            agent_id = %inner.agent_id,
            tree_size = verified.tree_size,
            leaf_index = verified.leaf_index,
            "SCITT receipt verified and cached"
        );

        let mut artifacts = inner.artifacts.write().await;
        artifacts.receipt_bytes = Some(bytes);
        Ok(())
    }

    /// Fetch, verify, and store the status token (static version for use in spawned tasks).
    async fn fetch_and_store_token_static(
        inner: &ScittHeaderSupplierInner,
    ) -> Result<(), ScittError> {
        let bytes = inner.client.fetch_status_token(inner.agent_id).await?;

        // Verify before caching
        let verified = verify_status_token(&bytes, &inner.key_store, inner.clock_skew)?;

        tracing::debug!(
            agent_id = %inner.agent_id,
            exp = verified.payload.exp,
            status = ?verified.payload.status,
            "SCITT status token verified and cached"
        );

        let mut artifacts = inner.artifacts.write().await;
        artifacts.status_token_bytes = Some(bytes);
        artifacts.token_exp = Some(verified.payload.exp);
        Ok(())
    }
}

/// Compute the refresh interval: 50% of remaining TTL, clamped to a minimum.
fn compute_refresh_interval(token_exp: Option<i64>) -> Duration {
    let Some(exp) = token_exp else {
        // No token yet — retry quickly
        return MIN_REFRESH_INTERVAL;
    };
    let now = chrono::Utc::now().timestamp();
    let remaining_secs = (exp - now).max(0);
    // Refresh at 50% TTL
    let half_ttl = remaining_secs / 2;
    let interval = Duration::from_secs(half_ttl.max(0).cast_unsigned());
    interval.max(MIN_REFRESH_INTERVAL)
}

#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ans_types::{BadgeStatus, CertEntry, CertFingerprint, StatusTokenPayload};
    use base64::prelude::BASE64_STANDARD;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::hazmat::PrehashSigner as _;
    use p256::pkcs8::EncodePublicKey as _;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::scitt::client::MockScittClient;
    use crate::scitt::cose::compute_sig_structure_digest;
    use crate::scitt::merkle::build_tree_and_proof;
    use crate::scitt::root_keys::ScittKeyStore;

    // ── Test helpers ─────────────────────────────────────────────────────

    fn make_key_and_store(seed: u8) -> (SigningKey, ScittKeyStore) {
        let signing_key = SigningKey::from_slice(&[seed; 32]).unwrap();
        let verifying_key = signing_key.verifying_key();
        let spki_doc = verifying_key.to_public_key_der().unwrap();
        let spki_der = spki_doc.as_bytes();
        let digest = Sha256::digest(spki_der);
        let kid: [u8; 4] = [digest[0], digest[1], digest[2], digest[3]];
        let key_hash_hex = hex::encode(kid);
        let spki_b64 = BASE64_STANDARD.encode(spki_der);
        let key_string = format!("tl.example.com+{key_hash_hex}+{spki_b64}");
        let store = ScittKeyStore::from_c2sp_keys(&[key_string]).unwrap();
        (signing_key, store)
    }

    fn build_protected_bytes(signing_key: &SigningKey) -> Vec<u8> {
        let spki_doc = signing_key.verifying_key().to_public_key_der().unwrap();
        let spki_der = spki_doc.as_bytes();
        let digest = Sha256::digest(spki_der);
        let kid = vec![digest[0], digest[1], digest[2], digest[3]];

        let pairs = vec![
            (
                ciborium::Value::Integer(1.into()),
                ciborium::Value::Integer((-7_i64).into()),
            ),
            (
                ciborium::Value::Integer(4.into()),
                ciborium::Value::Bytes(kid),
            ),
            (
                ciborium::Value::Integer(395.into()),
                ciborium::Value::Integer(1.into()),
            ),
        ];
        let map = ciborium::Value::Map(pairs);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&map, &mut buf).unwrap();
        buf
    }

    fn build_vdp_map(tree_size: u64, leaf_index: u64, hash_path: &[[u8; 32]]) -> ciborium::Value {
        let path_values: Vec<ciborium::Value> = hash_path
            .iter()
            .map(|h| ciborium::Value::Bytes(h.to_vec()))
            .collect();

        ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer((-1_i64).into()),
                ciborium::Value::Integer(tree_size.into()),
            ),
            (
                ciborium::Value::Integer((-2_i64).into()),
                ciborium::Value::Integer(leaf_index.into()),
            ),
            (
                ciborium::Value::Integer((-3_i64).into()),
                ciborium::Value::Array(path_values),
            ),
        ])
    }

    fn make_receipt_bytes(signing_key: &SigningKey, event: &[u8]) -> Vec<u8> {
        let leaves: &[&[u8]] = &[event];
        let (_, hash_path) = build_tree_and_proof(leaves, 0);

        let protected_bytes = build_protected_bytes(signing_key);
        let payload = event.to_vec();
        let digest = compute_sig_structure_digest(&protected_bytes, &payload);
        let (sig, _): (p256::ecdsa::Signature, _) = signing_key.sign_prehash(&digest).unwrap();
        let sig_bytes = sig.to_bytes().to_vec();

        let vdp = build_vdp_map(1, 0, &hash_path);
        let unprotected = ciborium::Value::Map(vec![(ciborium::Value::Integer(396.into()), vdp)]);

        let array = ciborium::Value::Array(vec![
            ciborium::Value::Bytes(protected_bytes),
            unprotected,
            ciborium::Value::Bytes(payload),
            ciborium::Value::Bytes(sig_bytes),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&array, &mut buf).unwrap();
        buf
    }

    fn make_status_token_bytes(signing_key: &SigningKey, exp: i64) -> Vec<u8> {
        let agent_id = Uuid::nil();
        let fp = CertFingerprint::from_bytes([0u8; 32]);
        let fp_hex = fp.to_hex();

        let payload_obj = StatusTokenPayload::new(
            agent_id,
            BadgeStatus::Active,
            chrono::Utc::now().timestamp(),
            exp,
            "ans://v1.0.0.agent.example.com".to_string(),
            vec![],
            vec![CertEntry::new(fp, "X509-DV-SERVER".to_string())],
            BTreeMap::new(),
        );

        // Encode payload as CBOR integer-keyed map
        let payload_pairs = vec![
            (
                ciborium::Value::Integer(1.into()),
                ciborium::Value::Text(payload_obj.agent_id.to_string()),
            ),
            (
                ciborium::Value::Integer(2.into()),
                ciborium::Value::Text("ACTIVE".to_string()),
            ),
            (
                ciborium::Value::Integer(3.into()),
                ciborium::Value::Integer(payload_obj.iat.into()),
            ),
            (
                ciborium::Value::Integer(4.into()),
                ciborium::Value::Integer(exp.into()),
            ),
            (
                ciborium::Value::Integer(5.into()),
                ciborium::Value::Text(payload_obj.ans_name.clone()),
            ),
            (
                ciborium::Value::Integer(6.into()),
                ciborium::Value::Array(vec![]),
            ),
            (
                ciborium::Value::Integer(7.into()),
                ciborium::Value::Array(vec![ciborium::Value::Map(vec![
                    (
                        ciborium::Value::Text("fingerprint".to_string()),
                        ciborium::Value::Text(format!("SHA256:{fp_hex}")),
                    ),
                    (
                        ciborium::Value::Text("cert_type".to_string()),
                        ciborium::Value::Text("X509-DV-SERVER".to_string()),
                    ),
                ])]),
            ),
            (
                ciborium::Value::Integer(8.into()),
                ciborium::Value::Map(vec![]),
            ),
        ];
        let payload_map = ciborium::Value::Map(payload_pairs);
        let mut payload_bytes = Vec::new();
        ciborium::ser::into_writer(&payload_map, &mut payload_bytes).unwrap();

        let protected_bytes = build_protected_bytes(signing_key);
        let digest = compute_sig_structure_digest(&protected_bytes, &payload_bytes);
        let (sig, _): (p256::ecdsa::Signature, _) = signing_key.sign_prehash(&digest).unwrap();
        let sig_bytes = sig.to_bytes().to_vec();

        let unprotected = ciborium::Value::Map(vec![]);
        let array = ciborium::Value::Array(vec![
            ciborium::Value::Bytes(protected_bytes),
            unprotected,
            ciborium::Value::Bytes(payload_bytes),
            ciborium::Value::Bytes(sig_bytes),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&array, &mut buf).unwrap();
        buf
    }

    // ── Construction tests ────────────────────────────────────────────

    #[test]
    fn new_is_infallible() {
        let (_, store) = make_key_and_store(1);
        let client: Arc<dyn ScittClient> = Arc::new(MockScittClient::new());
        let _supplier = ScittHeaderSupplier::new(Uuid::new_v4(), client, Arc::new(store));
    }

    #[test]
    fn supplier_is_clone() {
        let (_, store) = make_key_and_store(1);
        let client: Arc<dyn ScittClient> = Arc::new(MockScittClient::new());
        let supplier = ScittHeaderSupplier::new(Uuid::new_v4(), client, Arc::new(store));
        let _cloned = supplier.clone();
    }

    #[test]
    fn supplier_debug() {
        let (_, store) = make_key_and_store(1);
        let client: Arc<dyn ScittClient> = Arc::new(MockScittClient::new());
        let supplier = ScittHeaderSupplier::new(Uuid::new_v4(), client, Arc::new(store));
        let dbg = format!("{supplier:?}");
        assert!(dbg.contains("ScittHeaderSupplier"));
    }

    // ── current_headers with no artifacts ─────────────────────────────

    #[tokio::test]
    async fn current_headers_returns_none_when_client_fails() {
        let (_, store) = make_key_and_store(1);
        let agent_id = Uuid::new_v4();
        // Client has no configured responses → NotFound errors
        let client: Arc<dyn ScittClient> = Arc::new(MockScittClient::new());
        let supplier = ScittHeaderSupplier::new(agent_id, client, Arc::new(store));

        let headers = supplier.current_headers().await;
        assert!(headers.receipt_base64.is_none());
        assert!(headers.status_token_base64.is_none());
    }

    // ── current_headers with valid artifacts ──────────────────────────

    #[tokio::test]
    async fn current_headers_returns_receipt_and_token() {
        let (signing_key, store) = make_key_and_store(1);
        let agent_id = Uuid::nil();
        let exp = chrono::Utc::now().timestamp() + 3600;

        let receipt_bytes = make_receipt_bytes(&signing_key, b"test-event");
        let token_bytes = make_status_token_bytes(&signing_key, exp);

        let client: Arc<dyn ScittClient> = Arc::new(
            MockScittClient::new()
                .with_receipt(agent_id, receipt_bytes.clone())
                .with_status_token(agent_id, token_bytes.clone()),
        );
        let supplier = ScittHeaderSupplier::new(agent_id, client, Arc::new(store));

        let headers = supplier.current_headers().await;
        assert!(headers.receipt_base64.is_some());
        assert!(headers.status_token_base64.is_some());

        // Verify the base64 values decode to the original bytes
        let decoded_receipt = BASE64_STANDARD
            .decode(headers.receipt_base64.unwrap())
            .unwrap();
        assert_eq!(decoded_receipt, receipt_bytes);
    }

    // ── Expired token handling ────────────────────────────────────────

    #[tokio::test]
    async fn current_headers_returns_none_for_expired_token() {
        let (signing_key, store) = make_key_and_store(1);
        let agent_id = Uuid::nil();
        // Token expires 1 second from now; we need to use a token that was
        // valid when verify_status_token runs but will be expired by the time
        // current_headers checks. We use 2h in the past to make verify fail.
        // Instead, test by manually injecting expired artifacts.
        let receipt_bytes = make_receipt_bytes(&signing_key, b"test-event");

        let client: Arc<dyn ScittClient> =
            Arc::new(MockScittClient::new().with_receipt(agent_id, receipt_bytes));

        let supplier = ScittHeaderSupplier::new(agent_id, client, Arc::new(store));

        // Manually inject an expired token
        {
            let mut artifacts = supplier.inner.artifacts.write().await;
            artifacts.status_token_bytes = Some(vec![0xDE, 0xAD]);
            artifacts.token_exp = Some(946_684_800); // year 2000
        }

        let headers = supplier.current_headers().await;
        // Receipt was not fetched (only manually injected token), but receipt fetch failed
        // Token should be None because it's expired
        assert!(headers.status_token_base64.is_none());
    }

    // ── refresh_now ───────────────────────────────────────────────────

    #[tokio::test]
    async fn refresh_now_updates_artifacts() {
        let (signing_key, store) = make_key_and_store(1);
        let agent_id = Uuid::nil();
        let exp = chrono::Utc::now().timestamp() + 3600;

        let receipt_bytes = make_receipt_bytes(&signing_key, b"event");
        let token_bytes = make_status_token_bytes(&signing_key, exp);

        let client: Arc<dyn ScittClient> = Arc::new(
            MockScittClient::new()
                .with_receipt(agent_id, receipt_bytes)
                .with_status_token(agent_id, token_bytes),
        );
        let supplier = ScittHeaderSupplier::new(agent_id, client, Arc::new(store));

        // Initially empty
        {
            let artifacts = supplier.inner.artifacts.read().await;
            assert!(artifacts.receipt_bytes.is_none());
        }

        // After refresh
        supplier.refresh_now().await.unwrap();

        {
            let artifacts = supplier.inner.artifacts.read().await;
            assert!(artifacts.receipt_bytes.is_some());
            assert!(artifacts.status_token_bytes.is_some());
            assert!(artifacts.token_exp.is_some());
        }
    }

    #[tokio::test]
    async fn refresh_now_fails_on_bad_receipt() {
        let (_, store) = make_key_and_store(1);
        let agent_id = Uuid::nil();

        // Configure client with invalid receipt bytes
        let client: Arc<dyn ScittClient> =
            Arc::new(MockScittClient::new().with_receipt(agent_id, vec![0x00, 0x01, 0x02]));
        let supplier = ScittHeaderSupplier::new(agent_id, client, Arc::new(store));

        let result = supplier.refresh_now().await;
        assert!(result.is_err());
    }

    // ── auto-refresh handle ──────────────────────────────────────────

    #[tokio::test]
    async fn auto_refresh_handle_debug() {
        let (_, store) = make_key_and_store(1);
        let client: Arc<dyn ScittClient> = Arc::new(MockScittClient::new());
        let supplier = ScittHeaderSupplier::new(Uuid::new_v4(), client, Arc::new(store));

        let handle = supplier.start_auto_refresh();
        let dbg = format!("{handle:?}");
        assert!(dbg.contains("ScittRefreshHandle"));
        drop(handle);
    }

    #[tokio::test]
    async fn auto_refresh_cancels_on_drop() {
        let (_, store) = make_key_and_store(1);
        let client: Arc<dyn ScittClient> = Arc::new(MockScittClient::new());
        let supplier = ScittHeaderSupplier::new(Uuid::new_v4(), client, Arc::new(store));

        let cancel = {
            let handle = supplier.start_auto_refresh();
            // Extract cancel token reference before dropping
            let cancel = handle.cancel.clone();
            assert!(!cancel.is_cancelled());
            drop(handle);
            cancel
        };

        // After drop, the token should be cancelled
        assert!(cancel.is_cancelled());
    }

    // ── compute_refresh_interval ─────────────────────────────────────

    #[test]
    fn refresh_interval_none_returns_minimum() {
        let interval = compute_refresh_interval(None);
        assert_eq!(interval, MIN_REFRESH_INTERVAL);
    }

    #[test]
    fn refresh_interval_far_future_returns_half_ttl() {
        let exp = chrono::Utc::now().timestamp() + 3600; // 1 hour
        let interval = compute_refresh_interval(Some(exp));
        // 50% of ~3600 = ~1800, allow tolerance
        assert!(interval.as_secs() >= 1790);
        assert!(interval.as_secs() <= 1810);
    }

    #[test]
    fn refresh_interval_past_returns_minimum() {
        let exp = chrono::Utc::now().timestamp() - 100; // already expired
        let interval = compute_refresh_interval(Some(exp));
        assert_eq!(interval, MIN_REFRESH_INTERVAL);
    }

    #[test]
    fn refresh_interval_very_short_ttl_clamped_to_minimum() {
        let exp = chrono::Utc::now().timestamp() + 5; // 5 seconds
        let interval = compute_refresh_interval(Some(exp));
        assert_eq!(interval, MIN_REFRESH_INTERVAL);
    }

    // ── ScittOutgoingHeaders ─────────────────────────────────────────

    #[test]
    fn outgoing_headers_default_is_none() {
        let headers = ScittOutgoingHeaders::default();
        assert!(headers.receipt_base64.is_none());
        assert!(headers.status_token_base64.is_none());
    }
}
