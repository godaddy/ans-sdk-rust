//! SCITT-specific caches for verified receipts and status tokens.
//!
//! These caches are independent of the existing [`BadgeCache`](crate::BadgeCache).
//! They store already-verified artifacts received from remote agents in HTTP
//! headers. The verifier side does NOT proactively refresh — when a cached token
//! expires, the next request from that agent will carry a fresh token, or the
//! verifier falls back to badge.
//!
//! - [`ReceiptCache`]: Fixed TTL (default 24h). Receipts are immutable Merkle proofs.
//! - [`StatusTokenCache`]: Per-entry TTL derived from the token's `exp` claim.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use moka::future::Cache;
use moka::policy::Expiry;
use uuid::Uuid;

use super::receipt::VerifiedReceipt;
use super::status_token::VerifiedStatusToken;

/// Default receipt cache TTL: 24 hours.
///
/// Receipts are immutable (append-only Merkle proofs). The spec says "cache
/// indefinitely" — 24h is a conservative operational default to bound memory.
const DEFAULT_RECEIPT_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Default maximum cache entries.
const DEFAULT_MAX_ENTRIES: u64 = 1000;

/// Cache for verified SCITT receipts, keyed by agent ID.
///
/// Receipts are immutable proofs of append-only log inclusion. They use a
/// fixed TTL (default 24h) since the receipt content never changes — only
/// the tree grows. This cache is used on the verifier side to avoid
/// re-verifying receipts that have already been validated from remote
/// agents' HTTP headers.
pub struct ReceiptCache {
    cache: Cache<Uuid, Arc<VerifiedReceipt>>,
    ttl: Duration,
}

impl fmt::Debug for ReceiptCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceiptCache")
            .field("ttl", &self.ttl)
            .field("entry_count", &self.cache.entry_count())
            .finish()
    }
}

impl ReceiptCache {
    /// Create a new receipt cache with the given TTL and max capacity.
    pub fn new(ttl: Duration, max_entries: u64) -> Self {
        let cache = Cache::builder()
            .max_capacity(max_entries)
            .time_to_live(ttl)
            .build();
        Self { cache, ttl }
    }

    /// Create a new receipt cache with default settings (24h TTL, 1000 entries).
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_RECEIPT_TTL, DEFAULT_MAX_ENTRIES)
    }

    /// Get a cached receipt by agent ID.
    pub async fn get(&self, agent_id: &Uuid) -> Option<Arc<VerifiedReceipt>> {
        self.cache.get(agent_id).await
    }

    /// Insert a verified receipt into the cache.
    pub async fn insert(&self, agent_id: Uuid, receipt: Arc<VerifiedReceipt>) {
        self.cache.insert(agent_id, receipt).await;
    }

    /// Invalidate a cached receipt.
    pub async fn invalidate(&self, agent_id: &Uuid) {
        self.cache.invalidate(agent_id).await;
    }

    /// Returns the number of entries in the cache.
    pub fn entry_count(&self) -> u64 {
        self.cache.entry_count()
    }

    /// Returns the configured TTL.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }
}

impl Default for ReceiptCache {
    fn default() -> Self {
        Self::with_defaults()
    }
}

/// Per-entry expiry policy for status tokens.
///
/// Each status token carries its own `exp` claim (Unix timestamp). The cache
/// entry's TTL is set to the remaining time until `exp`, ensuring tokens are
/// evicted precisely when they expire rather than on a uniform schedule.
struct StatusTokenExpiry;

impl Expiry<Uuid, Arc<VerifiedStatusToken>> for StatusTokenExpiry {
    fn expire_after_create(
        &self,
        _key: &Uuid,
        value: &Arc<VerifiedStatusToken>,
        _created_at: Instant,
    ) -> Option<Duration> {
        let now = chrono::Utc::now().timestamp();
        let remaining = (value.payload.exp - now).max(0).cast_unsigned();
        Some(Duration::from_secs(remaining))
    }

    // On read: keep the current expiration (don't reset on access).

    fn expire_after_update(
        &self,
        _key: &Uuid,
        value: &Arc<VerifiedStatusToken>,
        _updated_at: Instant,
        _duration_until_expiry: Option<Duration>,
    ) -> Option<Duration> {
        // Recalculate TTL from the new token's exp claim.
        let now = chrono::Utc::now().timestamp();
        let remaining = (value.payload.exp - now).max(0).cast_unsigned();
        Some(Duration::from_secs(remaining))
    }
}

/// Cache for verified SCITT status tokens, keyed by agent ID.
///
/// Uses per-entry TTL derived from each token's `exp` claim via the Moka
/// [`Expiry`] trait. When a token expires, the cache automatically evicts it.
/// The verifier does not proactively refresh — the next request from that agent
/// will carry a fresh token in its headers.
pub struct StatusTokenCache {
    cache: Cache<Uuid, Arc<VerifiedStatusToken>>,
}

impl fmt::Debug for StatusTokenCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StatusTokenCache")
            .field("entry_count", &self.cache.entry_count())
            .finish()
    }
}

impl StatusTokenCache {
    /// Create a new status token cache with the given max capacity.
    pub fn new(max_entries: u64) -> Self {
        let cache = Cache::builder()
            .max_capacity(max_entries)
            .expire_after(StatusTokenExpiry)
            .build();
        Self { cache }
    }

    /// Create a new status token cache with default settings (1000 entries).
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_MAX_ENTRIES)
    }

    /// Get a cached status token by agent ID.
    pub async fn get(&self, agent_id: &Uuid) -> Option<Arc<VerifiedStatusToken>> {
        self.cache.get(agent_id).await
    }

    /// Insert a verified status token into the cache.
    ///
    /// The entry's TTL is automatically derived from the token's `exp` claim.
    pub async fn insert(&self, agent_id: Uuid, token: Arc<VerifiedStatusToken>) {
        self.cache.insert(agent_id, token).await;
    }

    /// Invalidate a cached status token.
    pub async fn invalidate(&self, agent_id: &Uuid) {
        self.cache.invalidate(agent_id).await;
    }

    /// Returns the number of entries in the cache.
    pub fn entry_count(&self) -> u64 {
        self.cache.entry_count()
    }
}

impl Default for StatusTokenCache {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ans_types::{BadgeStatus, CertFingerprint, StatusTokenPayload};

    use super::*;

    fn make_verified_receipt(tree_size: u64, leaf_index: u64) -> VerifiedReceipt {
        VerifiedReceipt {
            tree_size,
            leaf_index,
            root_hash: [0u8; 32],
            event_bytes: b"test-event".to_vec(),
            key_id: [0xDE, 0xAD, 0xBE, 0xEF],
            iss: None,
            iat: None,
        }
    }

    fn make_verified_token(exp: i64) -> VerifiedStatusToken {
        let fp = CertFingerprint::from_bytes([0u8; 32]);
        VerifiedStatusToken {
            payload: StatusTokenPayload::new(
                Uuid::nil(),
                BadgeStatus::Active,
                0,
                exp,
                ans_types::AnsName::parse("ans://v1.0.0.agent.example.com").unwrap(),
                vec![],
                vec![ans_types::CertEntry::new(fp, "X509-DV-SERVER".to_string())],
                BTreeMap::new(),
            ),
            key_id: [0xDE, 0xAD, 0xBE, 0xEF],
        }
    }

    // ── ReceiptCache tests ──────────────────────────────────────────────────

    #[tokio::test]
    async fn receipt_cache_insert_and_get() {
        let cache = ReceiptCache::with_defaults();
        let agent_id = Uuid::new_v4();
        let receipt = Arc::new(make_verified_receipt(10, 3));

        cache.insert(agent_id, receipt.clone()).await;
        let cached = cache.get(&agent_id).await;

        assert!(cached.is_some());
        let cached = cached.unwrap();
        assert_eq!(cached.tree_size, 10);
        assert_eq!(cached.leaf_index, 3);
    }

    #[tokio::test]
    async fn receipt_cache_miss() {
        let cache = ReceiptCache::with_defaults();
        let result = cache.get(&Uuid::new_v4()).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn receipt_cache_invalidate() {
        let cache = ReceiptCache::with_defaults();
        let agent_id = Uuid::new_v4();
        let receipt = Arc::new(make_verified_receipt(1, 0));

        cache.insert(agent_id, receipt).await;
        assert!(cache.get(&agent_id).await.is_some());

        cache.invalidate(&agent_id).await;
        assert!(cache.get(&agent_id).await.is_none());
    }

    #[tokio::test]
    async fn receipt_cache_entry_count() {
        let cache = ReceiptCache::with_defaults();
        assert_eq!(cache.entry_count(), 0);

        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        cache
            .insert(id1, Arc::new(make_verified_receipt(1, 0)))
            .await;
        cache
            .insert(id2, Arc::new(make_verified_receipt(2, 1)))
            .await;

        // Moka updates entry count asynchronously; run pending tasks
        cache.cache.run_pending_tasks().await;
        assert_eq!(cache.entry_count(), 2);
    }

    #[tokio::test]
    async fn receipt_cache_custom_ttl() {
        let cache = ReceiptCache::new(Duration::from_secs(1), 100);
        assert_eq!(cache.ttl(), Duration::from_secs(1));
    }

    #[tokio::test]
    async fn receipt_cache_overwrite() {
        let cache = ReceiptCache::with_defaults();
        let agent_id = Uuid::new_v4();

        cache
            .insert(agent_id, Arc::new(make_verified_receipt(5, 2)))
            .await;
        cache
            .insert(agent_id, Arc::new(make_verified_receipt(10, 7)))
            .await;

        let cached = cache.get(&agent_id).await.unwrap();
        assert_eq!(cached.tree_size, 10);
        assert_eq!(cached.leaf_index, 7);
    }

    // ── StatusTokenCache tests ──────────────────────────────────────────────

    #[tokio::test]
    async fn token_cache_insert_and_get() {
        let cache = StatusTokenCache::with_defaults();
        let agent_id = Uuid::new_v4();
        // Token expires far in the future
        let token = Arc::new(make_verified_token(4_102_444_800));

        cache.insert(agent_id, token.clone()).await;
        let cached = cache.get(&agent_id).await;

        assert!(cached.is_some());
        assert_eq!(cached.unwrap().payload.status, BadgeStatus::Active);
    }

    #[tokio::test]
    async fn token_cache_miss() {
        let cache = StatusTokenCache::with_defaults();
        let result = cache.get(&Uuid::new_v4()).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn token_cache_invalidate() {
        let cache = StatusTokenCache::with_defaults();
        let agent_id = Uuid::new_v4();
        let token = Arc::new(make_verified_token(4_102_444_800));

        cache.insert(agent_id, token).await;
        assert!(cache.get(&agent_id).await.is_some());

        cache.invalidate(&agent_id).await;
        assert!(cache.get(&agent_id).await.is_none());
    }

    #[tokio::test]
    async fn token_cache_already_expired_evicted() {
        let cache = StatusTokenCache::with_defaults();
        let agent_id = Uuid::new_v4();
        // Token already expired (year 2000)
        let token = Arc::new(make_verified_token(946_684_800));

        cache.insert(agent_id, token).await;
        // Run pending tasks so moka processes the zero-TTL eviction
        cache.cache.run_pending_tasks().await;

        // Should be evicted immediately (or on next access)
        let cached = cache.get(&agent_id).await;
        assert!(cached.is_none(), "already-expired token should be evicted");
    }

    #[tokio::test]
    async fn token_cache_entry_count() {
        let cache = StatusTokenCache::with_defaults();
        assert_eq!(cache.entry_count(), 0);

        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        cache
            .insert(id1, Arc::new(make_verified_token(4_102_444_800)))
            .await;
        cache
            .insert(id2, Arc::new(make_verified_token(4_102_444_800)))
            .await;

        cache.cache.run_pending_tasks().await;
        assert_eq!(cache.entry_count(), 2);
    }

    #[tokio::test]
    async fn token_cache_overwrite_with_new_expiry() {
        let cache = StatusTokenCache::with_defaults();
        let agent_id = Uuid::new_v4();

        // Insert with far-future expiry
        cache
            .insert(agent_id, Arc::new(make_verified_token(4_102_444_800)))
            .await;

        // Overwrite with different expiry
        let new_exp = chrono::Utc::now().timestamp() + 3600; // 1 hour from now
        cache
            .insert(agent_id, Arc::new(make_verified_token(new_exp)))
            .await;

        let cached = cache.get(&agent_id).await.unwrap();
        assert_eq!(cached.payload.exp, new_exp);
    }

    // ── StatusTokenExpiry unit tests ────────────────────────────────────────

    #[test]
    fn expiry_future_token_returns_positive_duration() {
        let expiry = StatusTokenExpiry;
        let exp = chrono::Utc::now().timestamp() + 3600; // 1 hour from now
        let token = Arc::new(make_verified_token(exp));

        let duration = expiry.expire_after_create(&Uuid::nil(), &token, Instant::now());
        assert!(duration.is_some());
        let dur = duration.unwrap();
        // Should be roughly 3600 seconds (allow 10s tolerance for test execution)
        assert!(dur.as_secs() >= 3590);
        assert!(dur.as_secs() <= 3610);
    }

    #[test]
    fn expiry_past_token_returns_zero_duration() {
        let expiry = StatusTokenExpiry;
        // Token expired in the past
        let token = Arc::new(make_verified_token(946_684_800));

        let duration = expiry.expire_after_create(&Uuid::nil(), &token, Instant::now());
        assert!(duration.is_some());
        assert_eq!(duration.unwrap(), Duration::from_secs(0));
    }

    #[test]
    fn expiry_exactly_now_returns_zero() {
        let expiry = StatusTokenExpiry;
        let now = chrono::Utc::now().timestamp();
        let token = Arc::new(make_verified_token(now));

        let duration = expiry.expire_after_create(&Uuid::nil(), &token, Instant::now());
        assert!(duration.is_some());
        // 0 or 1 second depending on timing
        assert!(duration.unwrap().as_secs() <= 1);
    }
}
