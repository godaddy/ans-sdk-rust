//! Verification logic for ANS trust verification.
//!
//! This module provides:
//! - `ServerVerifier`: For clients verifying servers
//! - `ClientVerifier`: For servers verifying mTLS clients
//! - `AnsVerifier`: High-level facade combining both

use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::join_all;

use crate::cache::{BadgeCache, CacheConfig, CacheKey};
use crate::dane::{DanePolicy, DaneVerificationResult, verify_dane};
use crate::dns::{
    BadgeRecord, DnsLookupResult, DnsResolver, DnsResolverConfig, HickoryDnsResolver,
};
use crate::error::{AnsError, AnsResult, DaneError, DnsError, TlogError, VerificationError};
use crate::tlog::{HttpTransparencyLogClient, TransparencyLogClient};
use ans_types::{AnsName, Badge, BadgeStatus, CertFingerprint, CryptoError, Fqdn, Version};

/// Parsed certificate data: (Common Name, DNS SANs, URI SANs).
type ParsedCertData = (Option<String>, Vec<String>, Vec<String>);

/// Extracted identity information from a certificate.
///
/// This struct holds the relevant identity information extracted from
/// an X.509 certificate for ANS verification purposes.
///
/// In production, construct via [`CertIdentity::from_der`]. The [`CertIdentity::new`]
/// and [`CertIdentity::from_fingerprint_and_cn`] constructors are available only
/// when the `test-support` feature is enabled.
#[derive(Debug, Clone)]
pub struct CertIdentity {
    /// Common Name (CN) from the certificate subject.
    pub(crate) common_name: Option<String>,
    /// DNS Subject Alternative Names.
    pub(crate) dns_sans: Vec<String>,
    /// URI Subject Alternative Names.
    pub(crate) uri_sans: Vec<String>,
    /// Certificate fingerprint.
    pub(crate) fingerprint: CertFingerprint,
}

impl CertIdentity {
    /// Returns the Common Name (CN) from the certificate subject.
    pub fn common_name(&self) -> Option<&str> {
        self.common_name.as_deref()
    }

    /// Returns the DNS Subject Alternative Names.
    pub fn dns_sans(&self) -> &[String] {
        &self.dns_sans
    }

    /// Returns the URI Subject Alternative Names.
    pub fn uri_sans(&self) -> &[String] {
        &self.uri_sans
    }

    /// Returns the certificate fingerprint.
    pub fn fingerprint(&self) -> &CertFingerprint {
        &self.fingerprint
    }

    /// Create a new `CertIdentity` from components.
    ///
    /// Use this when you've already extracted the certificate information
    /// using your TLS library (e.g., rustls, native-tls, openssl).
    /// If you have DER-encoded bytes, prefer [`CertIdentity::from_der`].
    pub fn new(
        common_name: Option<String>,
        dns_sans: Vec<String>,
        uri_sans: Vec<String>,
        fingerprint: CertFingerprint,
    ) -> Self {
        Self {
            common_name,
            dns_sans,
            uri_sans,
            fingerprint,
        }
    }

    /// Create from DER-encoded certificate bytes.
    ///
    /// Computes the SHA-256 fingerprint and extracts the Subject CN and
    /// Subject Alternative Names (DNS, URI) using x509-parser.
    pub fn from_der(der: &[u8]) -> Result<Self, CryptoError> {
        let fingerprint = CertFingerprint::from_der(der);
        let (common_name, dns_sans, uri_sans) = Self::parse_cert_der(der)?;

        Ok(Self {
            common_name,
            dns_sans,
            uri_sans,
            fingerprint,
        })
    }

    /// Create from fingerprint and CN only.
    ///
    /// Sets `dns_sans` to `[cn]` and `uri_sans` to empty.
    /// If you have DER-encoded bytes, prefer [`CertIdentity::from_der`].
    pub fn from_fingerprint_and_cn(fingerprint: CertFingerprint, cn: String) -> Self {
        Self {
            common_name: Some(cn.clone()),
            dns_sans: vec![cn],
            uri_sans: vec![],
            fingerprint,
        }
    }

    /// Parse DER certificate to extract CN and SANs using x509-parser.
    fn parse_cert_der(der: &[u8]) -> Result<ParsedCertData, CryptoError> {
        use x509_parser::prelude::*;

        let (_, cert) = X509Certificate::from_der(der)
            .map_err(|e| CryptoError::ParseFailed(format!("X.509 parse error: {e}")))?;

        // Extract Subject CN
        let cn = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|attr| attr.as_str().ok())
            .map(String::from);

        // Extract SANs from the SubjectAlternativeName extension
        let mut dns_sans = Vec::new();
        let mut uri_sans = Vec::new();

        if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
            for name in &san_ext.value.general_names {
                match name {
                    GeneralName::DNSName(dns) => dns_sans.push((*dns).to_string()),
                    GeneralName::URI(uri) => uri_sans.push((*uri).to_string()),
                    _ => {}
                }
            }
        }

        Ok((cn, dns_sans, uri_sans))
    }

    /// Get the FQDN from the certificate.
    ///
    /// Prefers DNS SAN over CN, following RFC 6125 recommendations.
    pub fn fqdn(&self) -> Option<&str> {
        self.dns_sans
            .first()
            .map(std::string::String::as_str)
            .or(self.common_name.as_deref())
    }

    /// Get the ANS name from URI SANs.
    pub fn ans_name(&self) -> Option<AnsName> {
        self.uri_sans
            .iter()
            .filter(|uri| uri.starts_with("ans://"))
            .find_map(|uri| AnsName::parse(uri).ok())
    }

    /// Extract version from ANS name in URI SAN.
    pub fn version(&self) -> Option<Version> {
        self.ans_name().map(|name| name.version().clone())
    }
}

/// Result of a verification operation.
#[derive(Debug)]
#[non_exhaustive]
pub enum VerificationOutcome {
    /// Verification passed.
    Verified {
        /// The verified badge.
        badge: Badge,
        /// The fingerprint that matched.
        matched_fingerprint: CertFingerprint,
    },

    /// Not an ANS agent (no badge DNS record found).
    NotAnsAgent {
        /// The FQDN that was looked up.
        fqdn: String,
    },

    /// Badge status is invalid for connections.
    InvalidStatus {
        /// The invalid status.
        status: BadgeStatus,
        /// The badge with invalid status.
        badge: Badge,
    },

    /// Certificate fingerprint does not match badge.
    FingerprintMismatch {
        /// Expected fingerprint from badge.
        expected: String,
        /// Actual fingerprint from certificate.
        actual: String,
        /// The badge that didn't match.
        badge: Badge,
    },

    /// Hostname does not match badge.
    HostnameMismatch {
        /// Expected hostname from badge.
        expected: String,
        /// Actual hostname from certificate.
        actual: String,
        /// The badge that didn't match.
        badge: Badge,
    },

    /// ANS name does not match badge (mTLS client verification).
    AnsNameMismatch {
        /// Expected ANS name from badge.
        expected: String,
        /// Actual ANS name from certificate.
        actual: String,
        /// The badge that didn't match.
        badge: Badge,
    },

    /// Verification failed due to a DNS error.
    DnsError(DnsError),

    /// Verification failed due to a transparency log error.
    TlogError(TlogError),

    /// Verification failed due to a certificate error.
    CertError(CryptoError),

    /// Verification failed due to a parse error.
    ParseError(ans_types::ParseError),

    /// Verification failed due to a DANE/TLSA error.
    DaneError(DaneError),
}

impl VerificationOutcome {
    /// Check if verification was successful.
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }

    /// Check if the agent is not registered with ANS.
    pub fn is_not_ans_agent(&self) -> bool {
        matches!(self, Self::NotAnsAgent { .. })
    }

    /// Get the badge if verification succeeded or partially completed.
    pub fn badge(&self) -> Option<&Badge> {
        match self {
            Self::Verified { badge, .. }
            | Self::InvalidStatus { badge, .. }
            | Self::FingerprintMismatch { badge, .. }
            | Self::HostnameMismatch { badge, .. }
            | Self::AnsNameMismatch { badge, .. } => Some(badge),
            _ => None,
        }
    }

    /// Convert to a Result.
    pub fn into_result(self) -> AnsResult<Badge> {
        match self {
            Self::Verified { badge, .. } => Ok(badge),
            Self::NotAnsAgent { fqdn } => Err(AnsError::Dns(DnsError::NotFound { fqdn })),
            Self::InvalidStatus { status, .. } => {
                Err(AnsError::Verification(VerificationError::InvalidStatus {
                    status,
                }))
            }
            Self::FingerprintMismatch {
                expected, actual, ..
            } => Err(AnsError::Verification(
                VerificationError::FingerprintMismatch { expected, actual },
            )),
            Self::HostnameMismatch {
                expected, actual, ..
            } => Err(AnsError::Verification(
                VerificationError::HostnameMismatch { expected, actual },
            )),
            Self::AnsNameMismatch {
                expected, actual, ..
            } => Err(AnsError::Verification(VerificationError::AnsNameMismatch {
                expected,
                actual,
            })),
            Self::DnsError(e) => Err(AnsError::Dns(e)),
            Self::TlogError(e) => Err(AnsError::TransparencyLog(e)),
            Self::CertError(e) => Err(AnsError::Certificate(e)),
            Self::ParseError(e) => Err(AnsError::Parse(e)),
            Self::DaneError(e) => Err(AnsError::Verification(
                VerificationError::DaneVerificationFailed(e),
            )),
        }
    }
}

/// Failure handling policy.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub enum FailurePolicy {
    /// Reject on any failure (most secure).
    #[default]
    FailClosed,

    /// Use cached badge if available, otherwise reject.
    FailOpenWithCache {
        /// Maximum age of cached badge to accept.
        max_staleness: Duration,
    },
}

/// Validate that a badge URL's domain is in the trusted RA domains set.
///
/// Returns `Ok(())` if:
/// - `trusted` is `None` (no restriction configured — allow all domains)
/// - The URL's host is present in the trusted set
///
/// Returns `Err(TlogError::UntrustedDomain)` if the host is not trusted.
fn validate_badge_domain(trusted: Option<&HashSet<String>>, url: &str) -> Result<(), TlogError> {
    let Some(trusted) = trusted else {
        return Ok(());
    };
    let parsed = url::Url::parse(url)
        .map_err(|e| TlogError::InvalidUrl(format!("Badge URL is invalid: {e}")))?;
    let domain = parsed
        .host_str()
        .ok_or_else(|| TlogError::InvalidUrl(format!("Badge URL has no host: {url}")))?;
    if trusted.contains(domain) {
        Ok(())
    } else {
        Err(TlogError::UntrustedDomain {
            domain: domain.to_string(),
            trusted: trusted.iter().cloned().collect(),
        })
    }
}

/// Server verifier for clients verifying agent servers.
pub struct ServerVerifier {
    dns_resolver: Arc<dyn DnsResolver>,
    tlog_client: Arc<dyn TransparencyLogClient>,
    cache: Option<Arc<BadgeCache>>,
    failure_policy: FailurePolicy,
    dane_policy: DanePolicy,
    /// Port to use for TLSA lookups (default: 443).
    dane_port: u16,
    /// Optional set of trusted RA domains for badge URL validation.
    trusted_ra_domains: Option<HashSet<String>>,
}

impl fmt::Debug for ServerVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerVerifier")
            .field("failure_policy", &self.failure_policy)
            .field("dane_policy", &self.dane_policy)
            .field("dane_port", &self.dane_port)
            .field("has_cache", &self.cache.is_some())
            .field("has_trusted_ra_domains", &self.trusted_ra_domains.is_some())
            .finish_non_exhaustive()
    }
}

impl ServerVerifier {
    /// Create a new builder.
    pub fn builder() -> ServerVerifierBuilder {
        ServerVerifierBuilder::default()
    }

    /// Verify an agent server.
    ///
    /// # Steps
    /// 1. DNS lookup for `_ans-badge` TXT record (with `_ra-badge` fallback)
    /// 2. Fetch preferred badge from transparency log (newest ACTIVE first)
    /// 3. Validate badge status
    /// 4. Compare certificate fingerprint to badge
    /// 5. On mismatch with multiple records, try all badges by fingerprint
    ///    (handles multi-version transitions where both versions are ACTIVE)
    /// 6. If still no match, refresh-on-mismatch (handles cert renewal)
    /// 7. Compare certificate CN to badge agent.host
    pub async fn verify(&self, fqdn: &Fqdn, server_cert: &CertIdentity) -> VerificationOutcome {
        tracing::info!(fqdn = %fqdn, "Starting server verification");
        tracing::debug!(
            cert_cn = ?server_cert.common_name,
            cert_fingerprint = %server_cert.fingerprint,
            "Certificate details"
        );

        // Check cache first — scan all versioned badges by fingerprint
        if let Some(cache) = &self.cache {
            let cached_badges = cache.get_all_for_fqdn(fqdn).await;
            if !cached_badges.is_empty() {
                tracing::debug!(fqdn = %fqdn, count = cached_badges.len(), "Scanning cached badges");
                for cached in &cached_badges {
                    let outcome = self.verify_against_badge(&cached.badge, server_cert, true);
                    if outcome.is_success() {
                        tracing::debug!(fqdn = %fqdn, "Cache hit — badge matched");
                        return outcome;
                    }
                }
                // No cached badge matched — fall through to DNS+TLog
                tracing::info!(fqdn = %fqdn, "No cached badge matched fingerprint, fetching fresh");
            }
        }

        // DNS lookup
        tracing::debug!(fqdn = %fqdn, "Performing DNS lookup for _ans-badge / _ra-badge");
        let records = match self.dns_resolver.lookup_badge(fqdn).await {
            Ok(DnsLookupResult::Found(records)) => {
                tracing::debug!(count = records.len(), "Found badge records");
                for (i, r) in records.iter().enumerate() {
                    tracing::debug!(index = i, version = ?r.version, url = %r.url, "Badge record");
                }
                records
            }
            Ok(DnsLookupResult::NotFound) => {
                tracing::warn!(fqdn = %fqdn, "No badge record found - not an ANS agent");
                return VerificationOutcome::NotAnsAgent {
                    fqdn: fqdn.to_string(),
                };
            }
            Err(e) => {
                tracing::error!(fqdn = %fqdn, error = %e, "DNS lookup failed");
                return self.handle_dns_error(e, fqdn, server_cert).await;
            }
        };

        // Server certs don't contain version info. Try all badge records by
        // fingerprint to handle multi-version transitions where both versions
        // are ACTIVE (see AGENT_TO_AGENT_FLOW §5.3).
        let outcome = self
            .verify_against_records(&records, fqdn, server_cert)
            .await;

        if !outcome.is_success() {
            return outcome;
        }

        // Perform DANE verification if enabled
        if self.dane_policy.should_verify() {
            match self.verify_dane(fqdn, server_cert).await {
                Ok(result) => {
                    if !result.is_acceptable(self.dane_policy) {
                        tracing::error!(
                            fqdn = %fqdn,
                            dane_policy = ?self.dane_policy,
                            "DANE verification failed"
                        );
                        return VerificationOutcome::DaneError(DaneError::FingerprintMismatch);
                    }
                }
                Err(e) => {
                    tracing::error!(fqdn = %fqdn, error = %e, "DANE verification error");
                    return VerificationOutcome::DaneError(e);
                }
            }
        }

        outcome
    }

    /// Try all badge records to find one matching the server certificate.
    ///
    /// Server certificates don't contain version info, so during multi-version
    /// transitions (where multiple versions are ACTIVE), we must try each badge
    /// by fingerprint comparison. Prefers newest ACTIVE badge, falls back to
    /// older versions and AHP-deprecated badges.
    ///
    /// If no badge matches from any record, falls back to refresh-on-mismatch
    /// (handles the certificate renewal case where the `TLog` was recently updated).
    async fn verify_against_records(
        &self,
        records: &[BadgeRecord],
        fqdn: &Fqdn,
        server_cert: &CertIdentity,
    ) -> VerificationOutcome {
        // Sort by version descending (newest first)
        let mut sorted: Vec<_> = records.iter().collect();
        sorted.sort_by(|a, b| b.version.cmp(&a.version));

        // Pre-populate the version index from DNS records
        if let Some(cache) = &self.cache {
            let versions: Vec<Version> =
                sorted.iter().filter_map(|r| r.version().cloned()).collect();
            if !versions.is_empty() {
                cache.set_version_index(fqdn, versions).await;
            }
        }

        // Fetch all badges in parallel
        let results = self.fetch_badges_parallel(&sorted).await;

        let mut last_mismatch: Option<VerificationOutcome> = None;
        let mut last_error: Option<AnsError> = None;

        for (record, result) in results {
            let badge = match result {
                Ok(b) => b,
                Err(e) => {
                    tracing::debug!(url = %record.url, error = %e, "Failed to fetch badge, trying next");
                    last_error = Some(AnsError::TransparencyLog(e));
                    continue;
                }
            };

            tracing::debug!(
                version = ?record.version,
                status = ?badge.status,
                "Checking badge record"
            );

            // Cache every successfully fetched badge by version
            if let Some(cache) = &self.cache {
                let version = record
                    .version()
                    .cloned()
                    .or_else(|| badge.agent_version().parse::<Version>().ok());
                if let Some(v) = &version {
                    cache.insert_for_fqdn_version(fqdn, v, badge.clone()).await;
                    tracing::debug!(fqdn = %fqdn, version = %v, "Cached badge by version");
                }
            }

            let outcome = self.verify_against_badge(&badge, server_cert, true);

            match &outcome {
                VerificationOutcome::Verified { .. } => {
                    return outcome;
                }
                VerificationOutcome::FingerprintMismatch { .. } => {
                    tracing::debug!(version = ?record.version, "Fingerprint mismatch, trying next record");
                    last_mismatch = Some(outcome);
                }
                // Non-fingerprint failures (status rejected, hostname mismatch) are terminal
                _ => return outcome,
            }
        }

        // No badge matched by fingerprint. Try refresh-on-mismatch for the
        // cert renewal case (TLog updated after our DNS lookup).
        if last_mismatch.is_some() {
            tracing::info!(fqdn = %fqdn, "No badge matched, attempting refresh-on-mismatch");
            return self.verify_with_refresh(fqdn, server_cert).await;
        }

        // All fetches failed
        match last_error {
            Some(e) => self.handle_ans_error(e, fqdn, server_cert).await,
            None => VerificationOutcome::NotAnsAgent {
                fqdn: fqdn.to_string(),
            },
        }
    }

    /// Perform DANE/TLSA verification.
    async fn verify_dane(
        &self,
        fqdn: &Fqdn,
        cert: &CertIdentity,
    ) -> Result<DaneVerificationResult, DaneError> {
        tracing::debug!(
            fqdn = %fqdn,
            port = self.dane_port,
            policy = ?self.dane_policy,
            "Starting DANE verification"
        );

        let tlsa_records = self
            .dns_resolver
            .get_tlsa_records(fqdn, self.dane_port)
            .await?;

        verify_dane(
            &tlsa_records,
            &cert.fingerprint,
            self.dane_policy,
            fqdn,
            self.dane_port,
        )
    }

    /// Pre-fetch badges for caching (before TLS connection).
    ///
    /// Fetches ALL badge records from DNS, then fetches and caches each badge
    /// by version. Returns the preferred (newest active) badge.
    pub async fn prefetch(&self, fqdn: &Fqdn) -> Result<Badge, AnsError> {
        let records = match self.dns_resolver.lookup_badge(fqdn).await {
            Ok(DnsLookupResult::Found(records)) => records,
            Ok(DnsLookupResult::NotFound) => {
                return Err(AnsError::Dns(DnsError::NotFound {
                    fqdn: fqdn.to_string(),
                }));
            }
            Err(e) => return Err(AnsError::Dns(e)),
        };

        // Sort by version descending (newest first)
        let mut sorted: Vec<_> = records.iter().collect();
        sorted.sort_by(|a, b| b.version.cmp(&a.version));

        // Pre-populate the version index from DNS records
        if let Some(cache) = &self.cache {
            let versions: Vec<Version> =
                sorted.iter().filter_map(|r| r.version().cloned()).collect();
            if !versions.is_empty() {
                cache.set_version_index(fqdn, versions).await;
            }
        }

        // Fetch ALL badges in parallel, then process results
        let results = self.fetch_badges_parallel(&sorted).await;

        let mut preferred: Option<Badge> = None;
        let mut last_error = None;

        for (record, result) in results {
            match result {
                Ok(badge) => {
                    // Cache by version
                    if let Some(cache) = &self.cache {
                        let version = record
                            .version()
                            .cloned()
                            .or_else(|| badge.agent_version().parse::<Version>().ok());
                        if let Some(v) = &version {
                            cache.insert_for_fqdn_version(fqdn, v, badge.clone()).await;
                            tracing::debug!(fqdn = %fqdn, version = %v, "Prefetch: cached badge");
                        }
                    }

                    // Track preferred (first active, then deprecated, as fallback)
                    if preferred.is_none()
                        && (badge.status.is_active() || badge.status == BadgeStatus::Deprecated)
                    {
                        preferred = Some(badge);
                    }
                }
                Err(e) => {
                    last_error = Some(e);
                }
            }
        }

        match preferred {
            Some(badge) => Ok(badge),
            None => match last_error {
                Some(e) => Err(AnsError::TransparencyLog(e)),
                None => Err(AnsError::TransparencyLog(TlogError::InvalidResponse(
                    "no badge records available".to_string(),
                ))),
            },
        }
    }

    /// Refresh-on-mismatch: invalidate cache, re-fetch from DNS and `TLog`, re-verify.
    ///
    /// Called when no badge record matched by fingerprint. Handles the cert
    /// renewal case where the `TLog` was updated after the initial fetch.
    /// Tries all records to also handle multi-version transitions.
    async fn verify_with_refresh(
        &self,
        fqdn: &Fqdn,
        server_cert: &CertIdentity,
    ) -> VerificationOutcome {
        // Invalidate all cached badges for this FQDN
        if let Some(cache) = &self.cache {
            cache.invalidate_fqdn(fqdn).await;
        }

        // Re-fetch from DNS + tlog, trying all records
        let records = match self.dns_resolver.lookup_badge(fqdn).await {
            Ok(DnsLookupResult::Found(records)) => records,
            Ok(DnsLookupResult::NotFound) => {
                return VerificationOutcome::NotAnsAgent {
                    fqdn: fqdn.to_string(),
                };
            }
            Err(e) => return VerificationOutcome::DnsError(e),
        };

        // Try all records — this is the final answer (no further refresh)
        self.verify_against_records_final(&records, fqdn, server_cert)
            .await
    }

    /// Try all badge records without further refresh fallback (terminal attempt).
    async fn verify_against_records_final(
        &self,
        records: &[BadgeRecord],
        fqdn: &Fqdn,
        server_cert: &CertIdentity,
    ) -> VerificationOutcome {
        let mut sorted: Vec<_> = records.iter().collect();
        sorted.sort_by(|a, b| b.version.cmp(&a.version));

        // Pre-populate the version index from DNS records
        if let Some(cache) = &self.cache {
            let versions: Vec<Version> =
                sorted.iter().filter_map(|r| r.version().cloned()).collect();
            if !versions.is_empty() {
                cache.set_version_index(fqdn, versions).await;
            }
        }

        // Fetch all badges in parallel
        let results = self.fetch_badges_parallel(&sorted).await;

        let mut last_mismatch: Option<VerificationOutcome> = None;
        let mut last_error: Option<AnsError> = None;

        for (record, result) in results {
            let badge = match result {
                Ok(b) => b,
                Err(e) => {
                    last_error = Some(AnsError::TransparencyLog(e));
                    continue;
                }
            };

            // Cache every successfully fetched badge by version
            if let Some(cache) = &self.cache {
                let version = record
                    .version()
                    .cloned()
                    .or_else(|| badge.agent_version().parse::<Version>().ok());
                if let Some(v) = &version {
                    cache.insert_for_fqdn_version(fqdn, v, badge.clone()).await;
                }
            }

            let outcome = self.verify_against_badge(&badge, server_cert, true);

            match &outcome {
                VerificationOutcome::Verified { .. } => {
                    return outcome;
                }
                VerificationOutcome::FingerprintMismatch { .. } => {
                    last_mismatch = Some(outcome);
                }
                _ => return outcome,
            }
        }

        // Return last mismatch or last error
        if let Some(mismatch) = last_mismatch {
            return mismatch;
        }
        match last_error {
            Some(e) => self.handle_ans_error(e, fqdn, server_cert).await,
            None => VerificationOutcome::NotAnsAgent {
                fqdn: fqdn.to_string(),
            },
        }
    }

    /// Fetch badges from the transparency log in parallel.
    ///
    /// Validates badge domains first (pure check), then fires all HTTP requests
    /// concurrently via `join_all`. Returns results paired with their records,
    /// preserving the input ordering.
    async fn fetch_badges_parallel<'a>(
        &self,
        records: &'a [&'a BadgeRecord],
    ) -> Vec<(&'a BadgeRecord, Result<Badge, TlogError>)> {
        // Pair each record with a future: domain-invalid records get an
        // immediate Err, valid ones get a real TLog fetch.
        let futures: Vec<_> = records
            .iter()
            .map(|record| {
                let tlog = &self.tlog_client;
                let trusted = &self.trusted_ra_domains;
                async move {
                    if let Err(e) = validate_badge_domain(trusted.as_ref(), &record.url) {
                        (*record, Err(e))
                    } else {
                        let result = tlog.fetch_badge(&record.url).await;
                        (*record, result)
                    }
                }
            })
            .collect();

        join_all(futures).await
    }

    #[allow(clippy::unused_self)] // logically part of ServerVerifier; may use self in future
    fn verify_against_badge(
        &self,
        badge: &Badge,
        cert: &CertIdentity,
        is_server: bool,
    ) -> VerificationOutcome {
        let cert_type = if is_server { "server" } else { "identity" };
        tracing::debug!(cert_type, "Verifying certificate against badge");

        // Check status
        if badge.status.should_reject() {
            tracing::warn!(
                status = ?badge.status,
                "Badge status is not valid for connections"
            );
            return VerificationOutcome::InvalidStatus {
                status: badge.status,
                badge: badge.clone(),
            };
        }
        tracing::debug!(status = ?badge.status, "Badge status is valid");

        // Compare fingerprint
        let expected_fp = if is_server {
            badge.server_cert_fingerprint()
        } else {
            badge.identity_cert_fingerprint()
        };

        tracing::debug!(
            expected = %expected_fp,
            actual = %cert.fingerprint,
            "Comparing certificate fingerprints"
        );

        if !cert.fingerprint.matches(expected_fp) {
            tracing::error!(
                expected = %expected_fp,
                actual = %cert.fingerprint,
                "Certificate fingerprint MISMATCH"
            );
            return VerificationOutcome::FingerprintMismatch {
                expected: expected_fp.to_string(),
                actual: cert.fingerprint.to_string(),
                badge: badge.clone(),
            };
        }
        tracing::debug!("Fingerprint matches");

        // Compare hostname
        let expected_host = badge.agent_host();
        let actual_host = cert.fqdn().unwrap_or("");

        tracing::debug!(
            expected = %expected_host,
            actual = %actual_host,
            "Comparing hostnames"
        );

        if !actual_host.eq_ignore_ascii_case(expected_host) {
            tracing::error!(
                expected = %expected_host,
                actual = %actual_host,
                "Hostname MISMATCH"
            );
            return VerificationOutcome::HostnameMismatch {
                expected: expected_host.to_string(),
                actual: actual_host.to_string(),
                badge: badge.clone(),
            };
        }

        tracing::info!(
            agent = %badge.agent_name(),
            host = %badge.agent_host(),
            "Verification SUCCESSFUL"
        );
        VerificationOutcome::Verified {
            badge: badge.clone(),
            matched_fingerprint: cert.fingerprint.clone(),
        }
    }

    async fn handle_dns_error(
        &self,
        error: DnsError,
        fqdn: &Fqdn,
        cert: &CertIdentity,
    ) -> VerificationOutcome {
        match self.failure_policy {
            FailurePolicy::FailClosed => VerificationOutcome::DnsError(error),
            FailurePolicy::FailOpenWithCache { max_staleness } => {
                if let Some(cache) = &self.cache {
                    for cached in cache.get_all_for_fqdn(fqdn).await {
                        if cached.fetched_at.elapsed() < max_staleness {
                            let outcome = self.verify_against_badge(&cached.badge, cert, true);
                            if outcome.is_success() {
                                return outcome;
                            }
                        }
                    }
                }
                VerificationOutcome::DnsError(error)
            }
        }
    }

    async fn handle_ans_error(
        &self,
        error: AnsError,
        fqdn: &Fqdn,
        cert: &CertIdentity,
    ) -> VerificationOutcome {
        match self.failure_policy {
            FailurePolicy::FailClosed => match error {
                AnsError::TransparencyLog(e) => VerificationOutcome::TlogError(e),
                AnsError::Dns(e) => VerificationOutcome::DnsError(e),
                AnsError::Certificate(e) => VerificationOutcome::CertError(e),
                AnsError::Parse(e) => VerificationOutcome::ParseError(e),
                AnsError::Verification(_) => VerificationOutcome::NotAnsAgent {
                    fqdn: fqdn.to_string(),
                },
            },
            FailurePolicy::FailOpenWithCache { max_staleness } => {
                if let Some(cache) = &self.cache {
                    for cached in cache.get_all_for_fqdn(fqdn).await {
                        if cached.fetched_at.elapsed() < max_staleness {
                            let outcome = self.verify_against_badge(&cached.badge, cert, true);
                            if outcome.is_success() {
                                return outcome;
                            }
                        }
                    }
                }
                match error {
                    AnsError::TransparencyLog(e) => VerificationOutcome::TlogError(e),
                    AnsError::Dns(e) => VerificationOutcome::DnsError(e),
                    AnsError::Certificate(e) => VerificationOutcome::CertError(e),
                    AnsError::Parse(e) => VerificationOutcome::ParseError(e),
                    AnsError::Verification(_) => VerificationOutcome::NotAnsAgent {
                        fqdn: fqdn.to_string(),
                    },
                }
            }
        }
    }
}

/// Builder for `ServerVerifier`.
#[derive(Default)]
pub struct ServerVerifierBuilder {
    dns_resolver: Option<Arc<dyn DnsResolver>>,
    tlog_client: Option<Arc<dyn TransparencyLogClient>>,
    cache: Option<Arc<BadgeCache>>,
    failure_policy: FailurePolicy,
    dane_policy: DanePolicy,
    dane_port: Option<u16>,
    trusted_ra_domains: Option<HashSet<String>>,
}

impl fmt::Debug for ServerVerifierBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerVerifierBuilder")
            .field("failure_policy", &self.failure_policy)
            .field("dane_policy", &self.dane_policy)
            .field("dane_port", &self.dane_port)
            .field("has_dns_resolver", &self.dns_resolver.is_some())
            .field("has_tlog_client", &self.tlog_client.is_some())
            .field("has_cache", &self.cache.is_some())
            .finish_non_exhaustive()
    }
}

impl ServerVerifierBuilder {
    /// Set a custom DNS resolver.
    pub fn dns_resolver(mut self, resolver: Arc<dyn DnsResolver>) -> Self {
        self.dns_resolver = Some(resolver);
        self
    }

    /// Set a custom transparency log client.
    pub fn tlog_client(mut self, client: Arc<dyn TransparencyLogClient>) -> Self {
        self.tlog_client = Some(client);
        self
    }

    /// Enable caching with default configuration.
    pub fn with_cache(mut self) -> Self {
        self.cache = Some(Arc::new(BadgeCache::with_defaults()));
        self
    }

    /// Enable caching with custom configuration.
    pub fn with_cache_config(mut self, config: CacheConfig) -> Self {
        self.cache = Some(Arc::new(BadgeCache::new(config)));
        self
    }

    /// Use an existing cache.
    pub fn cache(mut self, cache: Arc<BadgeCache>) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Set the failure policy.
    pub fn failure_policy(mut self, policy: FailurePolicy) -> Self {
        self.failure_policy = policy;
        self
    }

    /// Set the DANE/TLSA verification policy.
    ///
    /// - `DanePolicy::Disabled`: Skip DANE verification entirely (default)
    /// - `DanePolicy::ValidateIfPresent`: Verify TLSA if records exist, skip if not
    /// - `DanePolicy::Required`: Require TLSA records to exist and match
    pub fn dane_policy(mut self, policy: DanePolicy) -> Self {
        self.dane_policy = policy;
        self
    }

    /// Enable DANE verification if TLSA records are present.
    ///
    /// This is a convenience method equivalent to `.dane_policy(DanePolicy::ValidateIfPresent)`.
    pub fn with_dane_if_present(mut self) -> Self {
        self.dane_policy = DanePolicy::ValidateIfPresent;
        self
    }

    /// Require DANE verification (fail if no TLSA records).
    ///
    /// This is a convenience method equivalent to `.dane_policy(DanePolicy::Required)`.
    pub fn require_dane(mut self) -> Self {
        self.dane_policy = DanePolicy::Required;
        self
    }

    /// Set the port for TLSA lookups (default: 443).
    pub fn dane_port(mut self, port: u16) -> Self {
        self.dane_port = Some(port);
        self
    }

    /// Restrict badge URL fetches to a set of trusted RA domains.
    ///
    /// When configured, badge URLs discovered via DNS TXT records will be
    /// validated against this set before any HTTP request is made. URLs
    /// pointing to hosts not in the set are rejected with
    /// `TlogError::UntrustedDomain`.
    ///
    /// By default (`None`), all domains are allowed.
    pub fn trusted_ra_domains(
        mut self,
        domains: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.trusted_ra_domains = Some(domains.into_iter().map(Into::into).collect());
        self
    }

    /// Build the verifier.
    pub async fn build(self) -> AnsResult<ServerVerifier> {
        let dns_resolver = match self.dns_resolver {
            Some(r) => r,
            None => Arc::new(
                HickoryDnsResolver::new()
                    .await
                    .map_err(|e| AnsError::Dns(DnsError::ResolverError(e.to_string())))?,
            ),
        };

        let tlog_client = self
            .tlog_client
            .unwrap_or_else(|| Arc::new(HttpTransparencyLogClient::new()));

        Ok(ServerVerifier {
            dns_resolver,
            tlog_client,
            cache: self.cache,
            failure_policy: self.failure_policy,
            dane_policy: self.dane_policy,
            dane_port: self.dane_port.unwrap_or(443),
            trusted_ra_domains: self.trusted_ra_domains,
        })
    }
}

/// Client verifier for servers verifying mTLS agent clients.
pub struct ClientVerifier {
    dns_resolver: Arc<dyn DnsResolver>,
    tlog_client: Arc<dyn TransparencyLogClient>,
    cache: Option<Arc<BadgeCache>>,
    failure_policy: FailurePolicy,
    /// Optional set of trusted RA domains for badge URL validation.
    trusted_ra_domains: Option<HashSet<String>>,
}

impl fmt::Debug for ClientVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientVerifier")
            .field("failure_policy", &self.failure_policy)
            .field("has_cache", &self.cache.is_some())
            .field("has_trusted_ra_domains", &self.trusted_ra_domains.is_some())
            .finish_non_exhaustive()
    }
}

impl ClientVerifier {
    /// Create a new builder.
    pub fn builder() -> ClientVerifierBuilder {
        ClientVerifierBuilder::default()
    }

    /// Verify an mTLS client certificate.
    ///
    /// # Steps
    /// 1. Extract CN (FQDN) and URI SAN (`ANSName`) from certificate
    /// 2. Parse version from `ANSName`
    /// 3. DNS lookup for `_ans-badge` (with `_ra-badge` fallback) using CN as FQDN
    /// 4. Select badge matching version from certificate
    /// 5. Compare identity cert fingerprint, CN, and URI SAN to badge
    /// 6. On fingerprint mismatch, refresh badge and re-verify once
    #[allow(clippy::too_many_lines)] // verification flow reads best as a single method
    pub async fn verify(&self, client_cert: &CertIdentity) -> VerificationOutcome {
        tracing::info!("Starting mTLS client verification");
        tracing::debug!(
            cn = ?client_cert.common_name,
            dns_sans = ?client_cert.dns_sans,
            uri_sans = ?client_cert.uri_sans,
            fingerprint = %client_cert.fingerprint,
            "Client certificate details"
        );

        // Extract FQDN from certificate
        let Some(fqdn_str) = client_cert.fqdn() else {
            tracing::error!("No CN or DNS SAN found in client certificate");
            return VerificationOutcome::CertError(CryptoError::NoCommonName);
        };

        let fqdn = match Fqdn::new(fqdn_str) {
            Ok(f) => f,
            Err(e) => {
                tracing::error!(fqdn = %fqdn_str, error = %e, "Invalid FQDN in certificate");
                return VerificationOutcome::ParseError(e);
            }
        };
        tracing::debug!(fqdn = %fqdn, "Extracted FQDN from certificate");

        // Extract ANS name and version from URI SAN
        let ans_name = if let Some(n) = client_cert.ans_name() {
            tracing::debug!(ans_name = %n, "Found ANS name in URI SAN");
            n
        } else {
            tracing::error!(uri_sans = ?client_cert.uri_sans, "No ANS name (ans://) found in URI SANs");
            return VerificationOutcome::CertError(CryptoError::NoUriSan);
        };

        let version = ans_name.version().clone();
        tracing::debug!(version = %version, "Parsed version from ANS name");

        // Check cache first
        if let Some(cache) = &self.cache
            && let Some(cached) = cache.get_by_fqdn_version(&fqdn, &version).await
        {
            tracing::debug!(fqdn = %fqdn, version = %version, "Using cached badge");
            let outcome = self.verify_client_against_badge(&cached.badge, client_cert, &ans_name);
            // Refresh-on-mismatch for cached badges
            if matches!(outcome, VerificationOutcome::FingerprintMismatch { .. }) {
                tracing::info!(fqdn = %fqdn, "Fingerprint mismatch on cached badge, refreshing");
                return self
                    .verify_client_with_refresh(&fqdn, &version, client_cert, &ans_name)
                    .await;
            }
            return outcome;
        }

        // DNS lookup
        tracing::debug!(fqdn = %fqdn, version = %version, "Looking up badge for version");
        let badge_record = match self
            .dns_resolver
            .find_badge_for_version(&fqdn, &version)
            .await
        {
            Ok(Some(record)) => {
                tracing::debug!(url = %record.url, "Found badge record for version");
                record
            }
            Ok(None) => {
                tracing::debug!("No badge for specific version, trying preferred badge");
                // Try to find any badge
                match self.dns_resolver.find_preferred_badge(&fqdn).await {
                    Ok(Some(record)) => {
                        tracing::debug!(url = %record.url, version = ?record.version, "Using preferred badge");
                        record
                    }
                    Ok(None) => {
                        tracing::warn!(fqdn = %fqdn, "No badge record found - not an ANS agent");
                        return VerificationOutcome::NotAnsAgent {
                            fqdn: fqdn.to_string(),
                        };
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "DNS lookup failed");
                        return self
                            .handle_dns_error(e, &fqdn, &version, client_cert, &ans_name)
                            .await;
                    }
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "DNS lookup failed");
                return self
                    .handle_dns_error(e, &fqdn, &version, client_cert, &ans_name)
                    .await;
            }
        };

        // Validate badge URL domain before fetching
        if let Err(e) = validate_badge_domain(self.trusted_ra_domains.as_ref(), &badge_record.url) {
            return self
                .handle_tlog_error(e, &fqdn, &version, client_cert, &ans_name)
                .await;
        }

        // Fetch badge
        tracing::debug!(url = %badge_record.url, "Fetching badge from transparency log");
        let badge = match self.tlog_client.fetch_badge(&badge_record.url).await {
            Ok(b) => {
                tracing::debug!(
                    status = ?b.status,
                    agent_host = %b.agent_host(),
                    ans_name = %b.agent_name(),
                    "Fetched badge successfully"
                );
                b
            }
            Err(e) => {
                tracing::error!(url = %badge_record.url, error = %e, "Failed to fetch badge");
                return self
                    .handle_tlog_error(e, &fqdn, &version, client_cert, &ans_name)
                    .await;
            }
        };

        // Cache the badge (tracked for multi-version lookups)
        if let Some(cache) = &self.cache {
            cache
                .insert_for_fqdn_version(&fqdn, &version, badge.clone())
                .await;
            tracing::debug!(fqdn = %fqdn, version = %version, "Cached badge");
        }

        let outcome = self.verify_client_against_badge(&badge, client_cert, &ans_name);
        // Refresh-on-mismatch for freshly fetched badges
        if matches!(outcome, VerificationOutcome::FingerprintMismatch { .. }) {
            tracing::info!(fqdn = %fqdn, "Fingerprint mismatch, attempting refresh");
            return self
                .verify_client_with_refresh(&fqdn, &version, client_cert, &ans_name)
                .await;
        }
        outcome
    }

    #[allow(clippy::unused_self)] // logically part of ClientVerifier; may use self in future
    fn verify_client_against_badge(
        &self,
        badge: &Badge,
        cert: &CertIdentity,
        ans_name: &AnsName,
    ) -> VerificationOutcome {
        tracing::debug!("Verifying client certificate against badge");

        // Check status
        if badge.status.should_reject() {
            tracing::warn!(status = ?badge.status, "Badge status is not valid for connections");
            return VerificationOutcome::InvalidStatus {
                status: badge.status,
                badge: badge.clone(),
            };
        }
        tracing::debug!(status = ?badge.status, "Badge status is valid");

        // Compare fingerprint (identity cert for mTLS clients)
        let expected_fp = badge.identity_cert_fingerprint();
        tracing::debug!(
            expected = %expected_fp,
            actual = %cert.fingerprint,
            "Comparing identity certificate fingerprints"
        );

        if !cert.fingerprint.matches(expected_fp) {
            tracing::error!(
                expected = %expected_fp,
                actual = %cert.fingerprint,
                "Identity certificate fingerprint MISMATCH"
            );
            return VerificationOutcome::FingerprintMismatch {
                expected: expected_fp.to_string(),
                actual: cert.fingerprint.to_string(),
                badge: badge.clone(),
            };
        }
        tracing::debug!("Identity fingerprint matches");

        // Compare hostname
        let expected_host = badge.agent_host();
        let actual_host = cert.fqdn().unwrap_or("");
        tracing::debug!(
            expected = %expected_host,
            actual = %actual_host,
            "Comparing hostnames"
        );

        if !actual_host.eq_ignore_ascii_case(expected_host) {
            tracing::error!(
                expected = %expected_host,
                actual = %actual_host,
                "Hostname MISMATCH"
            );
            return VerificationOutcome::HostnameMismatch {
                expected: expected_host.to_string(),
                actual: actual_host.to_string(),
                badge: badge.clone(),
            };
        }
        tracing::debug!("Hostname matches");

        // Compare ANS name
        let expected_ans_name = badge.agent_name();
        tracing::debug!(
            expected = %expected_ans_name,
            actual = %ans_name,
            "Comparing ANS names"
        );

        if ans_name.to_string() != expected_ans_name {
            tracing::error!(
                expected = %expected_ans_name,
                actual = %ans_name,
                "ANS name MISMATCH"
            );
            return VerificationOutcome::AnsNameMismatch {
                expected: expected_ans_name.to_string(),
                actual: ans_name.to_string(),
                badge: badge.clone(),
            };
        }

        tracing::info!(
            agent = %badge.agent_name(),
            host = %badge.agent_host(),
            "Client verification SUCCESSFUL"
        );
        VerificationOutcome::Verified {
            badge: badge.clone(),
            matched_fingerprint: cert.fingerprint.clone(),
        }
    }

    /// Refresh-on-mismatch for client verification.
    ///
    /// Invalidates the cache, re-fetches the badge from the transparency log,
    /// and re-verifies. This handles certificate renewals where the badge
    /// was updated but the verifier had a stale copy.
    async fn verify_client_with_refresh(
        &self,
        fqdn: &Fqdn,
        version: &Version,
        client_cert: &CertIdentity,
        ans_name: &AnsName,
    ) -> VerificationOutcome {
        // Invalidate cache
        if let Some(cache) = &self.cache {
            cache
                .invalidate(&CacheKey::fqdn_version(fqdn, version))
                .await;
        }

        // Re-fetch from DNS
        let badge_record = match self
            .dns_resolver
            .find_badge_for_version(fqdn, version)
            .await
        {
            Ok(Some(record)) => record,
            Ok(None) => match self.dns_resolver.find_preferred_badge(fqdn).await {
                Ok(Some(record)) => record,
                Ok(None) => {
                    return VerificationOutcome::NotAnsAgent {
                        fqdn: fqdn.to_string(),
                    };
                }
                Err(e) => return VerificationOutcome::DnsError(e),
            },
            Err(e) => return VerificationOutcome::DnsError(e),
        };

        // Validate badge URL domain before re-fetch
        if let Err(e) = validate_badge_domain(self.trusted_ra_domains.as_ref(), &badge_record.url) {
            return VerificationOutcome::TlogError(e);
        }

        // Re-fetch badge from transparency log
        let badge = match self.tlog_client.fetch_badge(&badge_record.url).await {
            Ok(b) => b,
            Err(e) => return VerificationOutcome::TlogError(e),
        };

        // Cache the refreshed badge (tracked for multi-version lookups)
        if let Some(cache) = &self.cache {
            cache
                .insert_for_fqdn_version(fqdn, version, badge.clone())
                .await;
        }

        // Re-verify — this is the final answer
        self.verify_client_against_badge(&badge, client_cert, ans_name)
    }

    async fn handle_dns_error(
        &self,
        error: DnsError,
        fqdn: &Fqdn,
        version: &Version,
        cert: &CertIdentity,
        ans_name: &AnsName,
    ) -> VerificationOutcome {
        match self.failure_policy {
            FailurePolicy::FailClosed => VerificationOutcome::DnsError(error),
            FailurePolicy::FailOpenWithCache { max_staleness } => {
                if let Some(cache) = &self.cache
                    && let Some(cached) = cache.get_by_fqdn_version(fqdn, version).await
                    && cached.fetched_at.elapsed() < max_staleness
                {
                    return self.verify_client_against_badge(&cached.badge, cert, ans_name);
                }
                VerificationOutcome::DnsError(error)
            }
        }
    }

    async fn handle_tlog_error(
        &self,
        error: TlogError,
        fqdn: &Fqdn,
        version: &Version,
        cert: &CertIdentity,
        ans_name: &AnsName,
    ) -> VerificationOutcome {
        match self.failure_policy {
            FailurePolicy::FailClosed => VerificationOutcome::TlogError(error),
            FailurePolicy::FailOpenWithCache { max_staleness } => {
                if let Some(cache) = &self.cache
                    && let Some(cached) = cache.get_by_fqdn_version(fqdn, version).await
                    && cached.fetched_at.elapsed() < max_staleness
                {
                    return self.verify_client_against_badge(&cached.badge, cert, ans_name);
                }
                VerificationOutcome::TlogError(error)
            }
        }
    }
}

/// Builder for `ClientVerifier`.
#[derive(Default)]
pub struct ClientVerifierBuilder {
    dns_resolver: Option<Arc<dyn DnsResolver>>,
    tlog_client: Option<Arc<dyn TransparencyLogClient>>,
    cache: Option<Arc<BadgeCache>>,
    failure_policy: FailurePolicy,
    trusted_ra_domains: Option<HashSet<String>>,
}

impl fmt::Debug for ClientVerifierBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientVerifierBuilder")
            .field("failure_policy", &self.failure_policy)
            .field("has_dns_resolver", &self.dns_resolver.is_some())
            .field("has_tlog_client", &self.tlog_client.is_some())
            .field("has_cache", &self.cache.is_some())
            .finish_non_exhaustive()
    }
}

impl ClientVerifierBuilder {
    /// Set a custom DNS resolver.
    pub fn dns_resolver(mut self, resolver: Arc<dyn DnsResolver>) -> Self {
        self.dns_resolver = Some(resolver);
        self
    }

    /// Set a custom transparency log client.
    pub fn tlog_client(mut self, client: Arc<dyn TransparencyLogClient>) -> Self {
        self.tlog_client = Some(client);
        self
    }

    /// Enable caching with default configuration.
    pub fn with_cache(mut self) -> Self {
        self.cache = Some(Arc::new(BadgeCache::with_defaults()));
        self
    }

    /// Enable caching with custom configuration.
    pub fn with_cache_config(mut self, config: CacheConfig) -> Self {
        self.cache = Some(Arc::new(BadgeCache::new(config)));
        self
    }

    /// Use an existing cache.
    pub fn cache(mut self, cache: Arc<BadgeCache>) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Set the failure policy.
    pub fn failure_policy(mut self, policy: FailurePolicy) -> Self {
        self.failure_policy = policy;
        self
    }

    /// Restrict badge URL fetches to a set of trusted RA domains.
    ///
    /// When configured, badge URLs discovered via DNS TXT records will be
    /// validated against this set before any HTTP request is made. URLs
    /// pointing to hosts not in the set are rejected with
    /// `TlogError::UntrustedDomain`.
    ///
    /// By default (`None`), all domains are allowed.
    pub fn trusted_ra_domains(
        mut self,
        domains: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.trusted_ra_domains = Some(domains.into_iter().map(Into::into).collect());
        self
    }

    /// Build the verifier.
    pub async fn build(self) -> AnsResult<ClientVerifier> {
        let dns_resolver = match self.dns_resolver {
            Some(r) => r,
            None => Arc::new(
                HickoryDnsResolver::new()
                    .await
                    .map_err(|e| AnsError::Dns(DnsError::ResolverError(e.to_string())))?,
            ),
        };

        let tlog_client = self
            .tlog_client
            .unwrap_or_else(|| Arc::new(HttpTransparencyLogClient::new()));

        Ok(ClientVerifier {
            dns_resolver,
            tlog_client,
            cache: self.cache,
            failure_policy: self.failure_policy,
            trusted_ra_domains: self.trusted_ra_domains,
        })
    }
}

/// High-level ANS verifier combining server and client verification.
pub struct AnsVerifier {
    server_verifier: ServerVerifier,
    client_verifier: ClientVerifier,
    #[cfg(feature = "rustls")]
    private_ca_pem: Option<Vec<u8>>,
}

impl fmt::Debug for AnsVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnsVerifier")
            .field("server_verifier", &self.server_verifier)
            .field("client_verifier", &self.client_verifier)
            .finish_non_exhaustive()
    }
}

impl AnsVerifier {
    /// Create a new verifier with default configuration.
    pub async fn new() -> AnsResult<Self> {
        Self::builder().build().await
    }

    /// Create a builder for custom configuration.
    pub fn builder() -> AnsVerifierBuilder {
        AnsVerifierBuilder::default()
    }

    /// Verify an agent server (client-side verification).
    pub async fn verify_server(
        &self,
        fqdn: impl AsRef<str>,
        server_cert: &CertIdentity,
    ) -> VerificationOutcome {
        let fqdn = match Fqdn::new(fqdn.as_ref()) {
            Ok(f) => f,
            Err(e) => return VerificationOutcome::ParseError(e),
        };
        self.server_verifier.verify(&fqdn, server_cert).await
    }

    /// Verify an mTLS client (server-side verification).
    pub async fn verify_client(&self, client_cert: &CertIdentity) -> VerificationOutcome {
        self.client_verifier.verify(client_cert).await
    }

    /// Pre-fetch a badge for caching (before TLS connection).
    pub async fn prefetch(&self, fqdn: impl AsRef<str>) -> AnsResult<Badge> {
        let fqdn = Fqdn::new(fqdn.as_ref())?;
        self.server_verifier.prefetch(&fqdn).await
    }

    /// Create a rustls [`AnsClientCertVerifier`](crate::AnsClientCertVerifier) for server-side mTLS.
    ///
    /// Requires `private_ca_pem` to have been set on the builder.
    /// Returns a verifier that validates client certificate chains against the ANS Private CA.
    /// Client certificates are **required**.
    #[cfg(feature = "rustls")]
    pub fn client_cert_verifier(&self) -> AnsResult<crate::AnsClientCertVerifier> {
        let pem = self.private_ca_pem.as_ref().ok_or_else(|| {
            AnsError::Verification(VerificationError::Configuration(
                "private_ca_pem is required for client_cert_verifier".into(),
            ))
        })?;
        crate::AnsClientCertVerifier::from_pem(pem).map_err(|e| {
            AnsError::Verification(VerificationError::Configuration(format!(
                "Failed to build client cert verifier: {e}"
            )))
        })
    }

    /// Create a rustls [`AnsClientCertVerifier`](crate::AnsClientCertVerifier) that allows optional client certs.
    ///
    /// Requires `private_ca_pem` to have been set on the builder.
    /// Use this when the server should accept both authenticated and unauthenticated clients.
    #[cfg(feature = "rustls")]
    pub fn client_cert_verifier_optional(&self) -> AnsResult<crate::AnsClientCertVerifier> {
        let pem = self.private_ca_pem.as_ref().ok_or_else(|| {
            AnsError::Verification(VerificationError::Configuration(
                "private_ca_pem is required for client_cert_verifier_optional".into(),
            ))
        })?;
        crate::AnsClientCertVerifier::from_pem_optional(pem).map_err(|e| {
            AnsError::Verification(VerificationError::Configuration(format!(
                "Failed to build optional client cert verifier: {e}"
            )))
        })
    }

    /// Create a rustls [`AnsServerCertVerifier`](crate::AnsServerCertVerifier) for a specific badge fingerprint.
    ///
    /// Typically called after [`prefetch()`](Self::prefetch) to get the expected fingerprint
    /// from the badge's `attestations.server_cert.fingerprint` field.
    #[cfg(feature = "rustls")]
    pub fn server_cert_verifier(
        &self,
        fingerprint: &CertFingerprint,
    ) -> AnsResult<crate::AnsServerCertVerifier> {
        crate::AnsServerCertVerifier::new(fingerprint.clone()).map_err(|e| {
            AnsError::Verification(VerificationError::Configuration(format!(
                "Failed to build server cert verifier: {e}"
            )))
        })
    }
}

/// Builder for `AnsVerifier`.
#[derive(Default)]
pub struct AnsVerifierBuilder {
    dns_resolver: Option<Arc<dyn DnsResolver>>,
    dns_config: Option<DnsResolverConfig>,
    dns_nameservers: Option<Vec<std::net::Ipv4Addr>>,
    tlog_client: Option<Arc<dyn TransparencyLogClient>>,
    cache_config: Option<CacheConfig>,
    failure_policy: FailurePolicy,
    dane_policy: DanePolicy,
    dane_port: Option<u16>,
    trusted_ra_domains: Option<HashSet<String>>,
    #[cfg(feature = "rustls")]
    private_ca_pem: Option<Vec<u8>>,
}

impl fmt::Debug for AnsVerifierBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnsVerifierBuilder")
            .field("dns_config", &self.dns_config)
            .field("failure_policy", &self.failure_policy)
            .field("dane_policy", &self.dane_policy)
            .field("dane_port", &self.dane_port)
            .field("has_dns_resolver", &self.dns_resolver.is_some())
            .field("has_tlog_client", &self.tlog_client.is_some())
            .field("has_cache_config", &self.cache_config.is_some())
            .finish_non_exhaustive()
    }
}

impl AnsVerifierBuilder {
    /// Set a custom DNS resolver.
    pub fn dns_resolver(mut self, resolver: Arc<dyn DnsResolver>) -> Self {
        self.dns_resolver = Some(resolver);
        self
    }

    /// Use a preset DNS resolver configuration (Cloudflare, Google, etc.).
    ///
    /// # Example
    /// ```rust,no_run
    /// use ans_verify::{AnsVerifier, DnsResolverConfig};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let verifier = AnsVerifier::builder()
    ///     .dns_preset(DnsResolverConfig::CloudflareTls)
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn dns_preset(mut self, preset: DnsResolverConfig) -> Self {
        self.dns_config = Some(preset);
        self
    }

    /// Use Cloudflare DNS (1.1.1.1).
    pub fn dns_cloudflare(self) -> Self {
        self.dns_preset(DnsResolverConfig::Cloudflare)
    }

    /// Use Cloudflare DNS over TLS.
    pub fn dns_cloudflare_tls(self) -> Self {
        self.dns_preset(DnsResolverConfig::CloudflareTls)
    }

    /// Use Google Public DNS (8.8.8.8).
    pub fn dns_google(self) -> Self {
        self.dns_preset(DnsResolverConfig::Google)
    }

    /// Use Google DNS over TLS.
    pub fn dns_google_tls(self) -> Self {
        self.dns_preset(DnsResolverConfig::GoogleTls)
    }

    /// Use Quad9 DNS (9.9.9.9).
    pub fn dns_quad9(self) -> Self {
        self.dns_preset(DnsResolverConfig::Quad9)
    }

    /// Use custom DNS nameservers.
    ///
    /// # Example
    /// ```rust,no_run
    /// use ans_verify::AnsVerifier;
    /// use std::net::Ipv4Addr;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let verifier = AnsVerifier::builder()
    ///     .dns_nameservers(&[
    ///         Ipv4Addr::new(1, 1, 1, 1),
    ///         Ipv4Addr::new(8, 8, 8, 8),
    ///     ])
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn dns_nameservers(mut self, nameservers: &[std::net::Ipv4Addr]) -> Self {
        self.dns_nameservers = Some(nameservers.to_vec());
        self
    }

    /// Set a custom transparency log client.
    pub fn tlog_client(mut self, client: Arc<dyn TransparencyLogClient>) -> Self {
        self.tlog_client = Some(client);
        self
    }

    /// Enable caching with default configuration.
    pub fn with_caching(mut self) -> Self {
        self.cache_config = Some(CacheConfig::default());
        self
    }

    /// Enable caching with custom configuration.
    pub fn with_cache_config(mut self, config: CacheConfig) -> Self {
        self.cache_config = Some(config);
        self
    }

    /// Set the failure policy.
    pub fn failure_policy(mut self, policy: FailurePolicy) -> Self {
        self.failure_policy = policy;
        self
    }

    /// Set the DANE/TLSA verification policy.
    ///
    /// - `DanePolicy::Disabled`: Skip DANE verification entirely (default)
    /// - `DanePolicy::ValidateIfPresent`: Verify TLSA if records exist, skip if not
    /// - `DanePolicy::Required`: Require TLSA records to exist and match
    pub fn dane_policy(mut self, policy: DanePolicy) -> Self {
        self.dane_policy = policy;
        self
    }

    /// Enable DANE verification if TLSA records are present.
    pub fn with_dane_if_present(mut self) -> Self {
        self.dane_policy = DanePolicy::ValidateIfPresent;
        self
    }

    /// Require DANE verification (fail if no TLSA records).
    pub fn require_dane(mut self) -> Self {
        self.dane_policy = DanePolicy::Required;
        self
    }

    /// Set the port for TLSA lookups (default: 443).
    pub fn dane_port(mut self, port: u16) -> Self {
        self.dane_port = Some(port);
        self
    }

    /// Restrict badge URL fetches to a set of trusted RA domains.
    ///
    /// When configured, badge URLs discovered via DNS TXT records will be
    /// validated against this set before any HTTP request is made.
    pub fn trusted_ra_domains(
        mut self,
        domains: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.trusted_ra_domains = Some(domains.into_iter().map(Into::into).collect());
        self
    }

    /// Set the ANS Private CA certificate (PEM-encoded).
    ///
    /// Required for mTLS client verification. The Private CA is used during
    /// the TLS handshake to validate that client certificates chain to the
    /// ANS Private CA. Different environments (OTE, PROD) use different CAs.
    ///
    /// The PEM bytes are typically loaded from configuration, not hardcoded.
    #[cfg(feature = "rustls")]
    pub fn private_ca_pem(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.private_ca_pem = Some(pem.into());
        self
    }

    /// Build the verifier.
    pub async fn build(self) -> AnsResult<AnsVerifier> {
        // Determine DNS resolver: custom > nameservers > preset > default
        let dns_resolver: Arc<dyn DnsResolver> = if let Some(r) = self.dns_resolver {
            r
        } else if let Some(nameservers) = self.dns_nameservers {
            Arc::new(
                HickoryDnsResolver::with_nameservers(&nameservers)
                    .await
                    .map_err(|e| AnsError::Dns(DnsError::ResolverError(e.to_string())))?,
            )
        } else if let Some(preset) = self.dns_config {
            Arc::new(
                HickoryDnsResolver::with_preset(preset)
                    .await
                    .map_err(|e| AnsError::Dns(DnsError::ResolverError(e.to_string())))?,
            )
        } else {
            Arc::new(
                HickoryDnsResolver::new()
                    .await
                    .map_err(|e| AnsError::Dns(DnsError::ResolverError(e.to_string())))?,
            )
        };

        let tlog_client: Arc<dyn TransparencyLogClient> = self
            .tlog_client
            .unwrap_or_else(|| Arc::new(HttpTransparencyLogClient::new()));

        let cache = self.cache_config.map(|c| Arc::new(BadgeCache::new(c)));
        let dane_port = self.dane_port.unwrap_or(443);

        let server_verifier = ServerVerifier {
            dns_resolver: dns_resolver.clone(),
            tlog_client: tlog_client.clone(),
            cache: cache.clone(),
            failure_policy: self.failure_policy,
            dane_policy: self.dane_policy,
            dane_port,
            trusted_ra_domains: self.trusted_ra_domains.clone(),
        };

        let client_verifier = ClientVerifier {
            dns_resolver,
            tlog_client,
            cache,
            failure_policy: self.failure_policy,
            trusted_ra_domains: self.trusted_ra_domains,
        };

        Ok(AnsVerifier {
            server_verifier,
            client_verifier,
            #[cfg(feature = "rustls")]
            private_ca_pem: self.private_ca_pem,
        })
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::MockDnsResolver;
    use crate::tlog::MockTransparencyLogClient;
    use chrono::Utc;
    use uuid::Uuid;

    // Compile-time thread safety proof — fails compilation if any field
    // breaks Send/Sync (e.g., Rc, RefCell added to a struct).
    const fn _assert_send_sync<T: Send + Sync>() {}
    const _: () = _assert_send_sync::<ServerVerifier>();
    const _: () = _assert_send_sync::<ClientVerifier>();
    const _: () = _assert_send_sync::<AnsVerifier>();
    const _: () = _assert_send_sync::<BadgeCache>();

    fn create_test_badge(host: &str, version: &str, server_fp: &str, identity_fp: &str) -> Badge {
        serde_json::from_value(serde_json::json!({
            "status": "ACTIVE",
            "schemaVersion": "V1",
            "payload": {
                "logId": Uuid::new_v4().to_string(),
                "producer": {
                    "event": {
                        "ansId": Uuid::new_v4().to_string(),
                        "ansName": format!("ans://{version}.{host}"),
                        "eventType": "AGENT_REGISTERED",
                        "agent": { "host": host, "name": "Test Agent", "version": version },
                        "attestations": {
                            "domainValidation": "ACME-DNS-01",
                            "identityCert": { "fingerprint": identity_fp, "type": "X509-OV-CLIENT" },
                            "serverCert": { "fingerprint": server_fp, "type": "X509-DV-SERVER" }
                        },
                        "expiresAt": (Utc::now() + chrono::Duration::days(365)).to_rfc3339(),
                        "issuedAt": Utc::now().to_rfc3339(),
                        "raId": "test-ra",
                        "timestamp": Utc::now().to_rfc3339()
                    },
                    "keyId": "test-key",
                    "signature": "test-sig"
                }
            }
        })).expect("test badge JSON should be valid")
    }

    fn create_test_cert_identity(cn: &str, fingerprint: &str) -> CertIdentity {
        CertIdentity {
            common_name: Some(cn.to_string()),
            dns_sans: vec![cn.to_string()],
            uri_sans: vec![],
            fingerprint: CertFingerprint::parse(fingerprint).unwrap(),
        }
    }

    #[tokio::test]
    async fn test_server_verification_success() {
        let host = "test.example.com";
        let fingerprint = "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";

        let badge = create_test_badge(host, "v1.0.0", fingerprint, "SHA256:aaa");
        let badge_url = "https://tlog.example.com/v1/agents/test-id";

        let dns_record = BadgeRecord {
            format_version: "ans-badge1".to_string(),
            version: Some(Version::new(1, 0, 0)),
            url: badge_url.to_string(),
        };

        let dns_resolver = Arc::new(MockDnsResolver::new().with_records(host, vec![dns_record]));

        let tlog_client = Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, badge));

        let verifier = ServerVerifier {
            dns_resolver,
            tlog_client,
            cache: None,
            failure_policy: FailurePolicy::FailClosed,
            dane_policy: DanePolicy::Disabled,
            dane_port: 443,
            trusted_ra_domains: None,
        };

        let cert = create_test_cert_identity(host, fingerprint);
        let fqdn = Fqdn::new(host).unwrap();

        let outcome = verifier.verify(&fqdn, &cert).await;
        assert!(outcome.is_success());
    }

    #[tokio::test]
    async fn test_server_verification_not_ans_agent() {
        let dns_resolver = Arc::new(MockDnsResolver::new());
        let tlog_client = Arc::new(MockTransparencyLogClient::new());

        let verifier = ServerVerifier {
            dns_resolver,
            tlog_client,
            cache: None,
            failure_policy: FailurePolicy::FailClosed,
            dane_policy: DanePolicy::Disabled,
            dane_port: 443,
            trusted_ra_domains: None,
        };

        let cert = create_test_cert_identity(
            "unknown.example.com",
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
        );
        let fqdn = Fqdn::new("unknown.example.com").unwrap();

        let outcome = verifier.verify(&fqdn, &cert).await;
        assert!(outcome.is_not_ans_agent());
    }

    #[tokio::test]
    async fn test_server_verification_fingerprint_mismatch() {
        let host = "test.example.com";
        let badge_fingerprint =
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";
        let cert_fingerprint =
            "SHA256:0000000000000000000000000000000000000000000000000000000000000000";

        let badge = create_test_badge(host, "v1.0.0", badge_fingerprint, "SHA256:aaa");
        let badge_url = "https://tlog.example.com/v1/agents/test-id";

        let dns_record = BadgeRecord {
            format_version: "ans-badge1".to_string(),
            version: Some(Version::new(1, 0, 0)),
            url: badge_url.to_string(),
        };

        let dns_resolver = Arc::new(MockDnsResolver::new().with_records(host, vec![dns_record]));

        let tlog_client = Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, badge));

        let verifier = ServerVerifier {
            dns_resolver,
            tlog_client,
            cache: None,
            failure_policy: FailurePolicy::FailClosed,
            dane_policy: DanePolicy::Disabled,
            dane_port: 443,
            trusted_ra_domains: None,
        };

        let cert = create_test_cert_identity(host, cert_fingerprint);
        let fqdn = Fqdn::new(host).unwrap();

        let outcome = verifier.verify(&fqdn, &cert).await;
        assert!(matches!(
            outcome,
            VerificationOutcome::FingerprintMismatch { .. }
        ));
    }

    #[tokio::test]
    async fn test_server_verification_invalid_status() {
        let host = "test.example.com";
        let fingerprint = "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";

        let mut badge = create_test_badge(host, "v1.0.0", fingerprint, "SHA256:aaa");
        badge.status = BadgeStatus::Revoked;

        let badge_url = "https://tlog.example.com/v1/agents/test-id";

        let dns_record = BadgeRecord {
            format_version: "ans-badge1".to_string(),
            version: Some(Version::new(1, 0, 0)),
            url: badge_url.to_string(),
        };

        let dns_resolver = Arc::new(MockDnsResolver::new().with_records(host, vec![dns_record]));

        let tlog_client = Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, badge));

        let verifier = ServerVerifier {
            dns_resolver,
            tlog_client,
            cache: None,
            failure_policy: FailurePolicy::FailClosed,
            dane_policy: DanePolicy::Disabled,
            dane_port: 443,
            trusted_ra_domains: None,
        };

        let cert = create_test_cert_identity(host, fingerprint);
        let fqdn = Fqdn::new(host).unwrap();

        let outcome = verifier.verify(&fqdn, &cert).await;
        assert!(matches!(
            outcome,
            VerificationOutcome::InvalidStatus {
                status: BadgeStatus::Revoked,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn test_verification_outcome_is_success() {
        let badge = create_test_badge(
            "test.example.com",
            "v1.0.0",
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
            "SHA256:aaa",
        );

        let outcome = VerificationOutcome::Verified {
            badge,
            matched_fingerprint: CertFingerprint::parse(
                "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
            )
            .unwrap(),
        };

        assert!(outcome.is_success());
        assert!(!outcome.is_not_ans_agent());
    }

    #[tokio::test]
    async fn test_verification_with_cache() {
        let host = "test.example.com";
        let fingerprint = "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";

        let badge = create_test_badge(host, "v1.0.0", fingerprint, "SHA256:aaa");
        let cache = Arc::new(BadgeCache::with_defaults());
        let fqdn = Fqdn::new(host).unwrap();

        // Pre-populate cache
        cache
            .insert_for_fqdn_version(&fqdn, &Version::new(1, 0, 0), badge)
            .await;

        // Create verifier with empty DNS/TLog (should use cache)
        let dns_resolver = Arc::new(MockDnsResolver::new());
        let tlog_client = Arc::new(MockTransparencyLogClient::new());

        let verifier = ServerVerifier {
            dns_resolver,
            tlog_client,
            cache: Some(cache),
            failure_policy: FailurePolicy::FailClosed,
            dane_policy: DanePolicy::Disabled,
            dane_port: 443,
            trusted_ra_domains: None,
        };

        let cert = create_test_cert_identity(host, fingerprint);

        let outcome = verifier.verify(&fqdn, &cert).await;
        assert!(outcome.is_success());
    }

    #[test]
    fn test_cert_identity_from_components() {
        let fingerprint = CertFingerprint::parse(
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
        )
        .unwrap();

        let identity = CertIdentity::new(
            Some("test.example.com".to_string()),
            vec!["test.example.com".to_string()],
            vec!["ans://v1.0.0.test.example.com".to_string()],
            fingerprint,
        );

        assert_eq!(identity.fqdn(), Some("test.example.com"));
        assert!(identity.ans_name().is_some());
        assert_eq!(identity.version(), Some(Version::new(1, 0, 0)));
    }

    #[test]
    fn test_cert_identity_from_fingerprint_and_cn() {
        let fingerprint = CertFingerprint::parse(
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
        )
        .unwrap();

        let identity =
            CertIdentity::from_fingerprint_and_cn(fingerprint, "test.example.com".to_string());

        assert_eq!(identity.fqdn(), Some("test.example.com"));
        assert!(identity.ans_name().is_none()); // No URI SANs
    }

    // =========================================================================
    // ClientVerifier Tests
    // =========================================================================

    fn create_mtls_cert_identity(host: &str, version: &str, fingerprint: &str) -> CertIdentity {
        CertIdentity {
            common_name: Some(host.to_string()),
            dns_sans: vec![host.to_string()],
            uri_sans: vec![format!("ans://{}.{}", version, host)],
            fingerprint: CertFingerprint::parse(fingerprint).unwrap(),
        }
    }

    #[tokio::test]
    async fn test_client_verification_success() {
        let host = "test.example.com";
        let version = "v1.0.0";
        let identity_fp = "SHA256:aebdc9da0c20d6d5e4999a773839095ed050a9d7252bf212056fddc0c38f3496";
        let server_fp = "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";

        let badge = create_test_badge(host, version, server_fp, identity_fp);
        let badge_url = "https://tlog.example.com/v1/agents/test-id";

        let dns_record = BadgeRecord {
            format_version: "ans-badge1".to_string(),
            version: Some(Version::new(1, 0, 0)),
            url: badge_url.to_string(),
        };

        let dns_resolver = Arc::new(MockDnsResolver::new().with_records(host, vec![dns_record]));
        let tlog_client = Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, badge));

        let verifier = ClientVerifier {
            dns_resolver,
            tlog_client,
            cache: None,
            failure_policy: FailurePolicy::FailClosed,
            trusted_ra_domains: None,
        };

        let cert = create_mtls_cert_identity(host, version, identity_fp);
        let outcome = verifier.verify(&cert).await;

        assert!(outcome.is_success(), "Expected success, got: {:?}", outcome);
    }

    #[tokio::test]
    async fn test_client_verification_no_fqdn() {
        let dns_resolver = Arc::new(MockDnsResolver::new());
        let tlog_client = Arc::new(MockTransparencyLogClient::new());

        let verifier = ClientVerifier {
            dns_resolver,
            tlog_client,
            cache: None,
            failure_policy: FailurePolicy::FailClosed,
            trusted_ra_domains: None,
        };

        // Create cert with no CN or DNS SANs
        let cert = CertIdentity {
            common_name: None,
            dns_sans: vec![],
            uri_sans: vec!["ans://v1.0.0.test.example.com".to_string()],
            fingerprint: CertFingerprint::parse(
                "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
            )
            .unwrap(),
        };

        let outcome = verifier.verify(&cert).await;
        assert!(matches!(outcome, VerificationOutcome::CertError(_)));
    }

    #[tokio::test]
    async fn test_client_verification_no_ans_name() {
        let dns_resolver = Arc::new(MockDnsResolver::new());
        let tlog_client = Arc::new(MockTransparencyLogClient::new());

        let verifier = ClientVerifier {
            dns_resolver,
            tlog_client,
            cache: None,
            failure_policy: FailurePolicy::FailClosed,
            trusted_ra_domains: None,
        };

        // Create cert with CN but no URI SANs
        let cert = CertIdentity {
            common_name: Some("test.example.com".to_string()),
            dns_sans: vec!["test.example.com".to_string()],
            uri_sans: vec![],
            fingerprint: CertFingerprint::parse(
                "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
            )
            .unwrap(),
        };

        let outcome = verifier.verify(&cert).await;
        assert!(matches!(outcome, VerificationOutcome::CertError(_)));
    }

    #[tokio::test]
    async fn test_client_verification_fingerprint_mismatch() {
        let host = "test.example.com";
        let version = "v1.0.0";
        let badge_identity_fp =
            "SHA256:aebdc9da0c20d6d5e4999a773839095ed050a9d7252bf212056fddc0c38f3496";
        let cert_identity_fp =
            "SHA256:0000000000000000000000000000000000000000000000000000000000000000";

        let badge = create_test_badge(host, version, "SHA256:server", badge_identity_fp);
        let badge_url = "https://tlog.example.com/v1/agents/test-id";

        let dns_record = BadgeRecord {
            format_version: "ans-badge1".to_string(),
            version: Some(Version::new(1, 0, 0)),
            url: badge_url.to_string(),
        };

        let dns_resolver = Arc::new(MockDnsResolver::new().with_records(host, vec![dns_record]));
        let tlog_client = Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, badge));

        let verifier = ClientVerifier {
            dns_resolver,
            tlog_client,
            cache: None,
            failure_policy: FailurePolicy::FailClosed,
            trusted_ra_domains: None,
        };

        let cert = create_mtls_cert_identity(host, version, cert_identity_fp);
        let outcome = verifier.verify(&cert).await;

        assert!(matches!(
            outcome,
            VerificationOutcome::FingerprintMismatch { .. }
        ));
    }

    #[tokio::test]
    async fn test_client_verification_ans_name_mismatch() {
        let host = "test.example.com";
        let badge_version = "v1.0.0";
        let cert_version = "v2.0.0";
        let identity_fp = "SHA256:aebdc9da0c20d6d5e4999a773839095ed050a9d7252bf212056fddc0c38f3496";

        // Badge has v1.0.0, cert has v2.0.0
        let badge = create_test_badge(host, badge_version, "SHA256:server", identity_fp);
        let badge_url = "https://tlog.example.com/v1/agents/test-id";

        let dns_record = BadgeRecord {
            format_version: "ans-badge1".to_string(),
            version: Some(Version::new(2, 0, 0)),
            url: badge_url.to_string(),
        };

        let dns_resolver = Arc::new(MockDnsResolver::new().with_records(host, vec![dns_record]));
        let tlog_client = Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, badge));

        let verifier = ClientVerifier {
            dns_resolver,
            tlog_client,
            cache: None,
            failure_policy: FailurePolicy::FailClosed,
            trusted_ra_domains: None,
        };

        let cert = create_mtls_cert_identity(host, cert_version, identity_fp);
        let outcome = verifier.verify(&cert).await;

        assert!(matches!(
            outcome,
            VerificationOutcome::AnsNameMismatch { .. }
        ));
    }

    // =========================================================================
    // VerificationOutcome Tests
    // =========================================================================

    #[test]
    fn test_verification_outcome_badge() {
        let badge = create_test_badge(
            "test.example.com",
            "v1.0.0",
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
            "SHA256:aaa",
        );

        // Verified has badge
        let outcome = VerificationOutcome::Verified {
            badge: badge.clone(),
            matched_fingerprint: CertFingerprint::parse(
                "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
            )
            .unwrap(),
        };
        assert!(outcome.badge().is_some());

        // InvalidStatus has badge
        let outcome = VerificationOutcome::InvalidStatus {
            status: BadgeStatus::Revoked,
            badge: badge.clone(),
        };
        assert!(outcome.badge().is_some());

        // FingerprintMismatch has badge
        let outcome = VerificationOutcome::FingerprintMismatch {
            expected: "SHA256:a".to_string(),
            actual: "SHA256:b".to_string(),
            badge: badge.clone(),
        };
        assert!(outcome.badge().is_some());

        // HostnameMismatch has badge
        let outcome = VerificationOutcome::HostnameMismatch {
            expected: "a.com".to_string(),
            actual: "b.com".to_string(),
            badge: badge.clone(),
        };
        assert!(outcome.badge().is_some());

        // AnsNameMismatch has badge
        let outcome = VerificationOutcome::AnsNameMismatch {
            expected: "ans://v1.0.0.a.com".to_string(),
            actual: "ans://v2.0.0.a.com".to_string(),
            badge,
        };
        assert!(outcome.badge().is_some());

        // NotAnsAgent has no badge
        let outcome = VerificationOutcome::NotAnsAgent {
            fqdn: "test.com".to_string(),
        };
        assert!(outcome.badge().is_none());

        // DnsError has no badge
        let outcome = VerificationOutcome::DnsError(DnsError::NotFound {
            fqdn: "test.com".to_string(),
        });
        assert!(outcome.badge().is_none());
    }

    #[test]
    fn test_verification_outcome_into_result() {
        let badge = create_test_badge(
            "test.example.com",
            "v1.0.0",
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
            "SHA256:aaa",
        );

        // Verified -> Ok
        let outcome = VerificationOutcome::Verified {
            badge: badge.clone(),
            matched_fingerprint: CertFingerprint::parse(
                "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
            )
            .unwrap(),
        };
        assert!(outcome.into_result().is_ok());

        // NotAnsAgent -> Err
        let outcome = VerificationOutcome::NotAnsAgent {
            fqdn: "test.com".to_string(),
        };
        assert!(outcome.into_result().is_err());

        // InvalidStatus -> Err
        let outcome = VerificationOutcome::InvalidStatus {
            status: BadgeStatus::Revoked,
            badge: badge.clone(),
        };
        assert!(outcome.into_result().is_err());

        // FingerprintMismatch -> Err
        let outcome = VerificationOutcome::FingerprintMismatch {
            expected: "a".to_string(),
            actual: "b".to_string(),
            badge: badge.clone(),
        };
        assert!(outcome.into_result().is_err());

        // HostnameMismatch -> Err
        let outcome = VerificationOutcome::HostnameMismatch {
            expected: "a.com".to_string(),
            actual: "b.com".to_string(),
            badge: badge.clone(),
        };
        assert!(outcome.into_result().is_err());

        // AnsNameMismatch -> Err
        let outcome = VerificationOutcome::AnsNameMismatch {
            expected: "a".to_string(),
            actual: "b".to_string(),
            badge,
        };
        assert!(outcome.into_result().is_err());

        // DnsError -> Err
        let outcome = VerificationOutcome::DnsError(DnsError::NotFound {
            fqdn: "test.com".to_string(),
        });
        assert!(outcome.into_result().is_err());

        // TlogError -> Err
        let outcome = VerificationOutcome::TlogError(TlogError::ServiceUnavailable);
        assert!(outcome.into_result().is_err());

        // DaneError -> Err
        let outcome = VerificationOutcome::DaneError(DaneError::FingerprintMismatch);
        assert!(outcome.into_result().is_err());
    }

    // =========================================================================
    // Hostname Mismatch Tests
    // =========================================================================

    #[tokio::test]
    async fn test_server_verification_hostname_mismatch() {
        let badge_host = "badge.example.com";
        let cert_host = "different.example.com";
        let fingerprint = "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";

        let badge = create_test_badge(badge_host, "v1.0.0", fingerprint, "SHA256:aaa");
        let badge_url = "https://tlog.example.com/v1/agents/test-id";

        let dns_record = BadgeRecord {
            format_version: "ans-badge1".to_string(),
            version: Some(Version::new(1, 0, 0)),
            url: badge_url.to_string(),
        };

        // DNS lookup uses cert_host but badge contains badge_host
        let dns_resolver =
            Arc::new(MockDnsResolver::new().with_records(cert_host, vec![dns_record]));
        let tlog_client = Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, badge));

        let verifier = ServerVerifier {
            dns_resolver,
            tlog_client,
            cache: None,
            failure_policy: FailurePolicy::FailClosed,
            dane_policy: DanePolicy::Disabled,
            dane_port: 443,
            trusted_ra_domains: None,
        };

        let cert = create_test_cert_identity(cert_host, fingerprint);
        let fqdn = Fqdn::new(cert_host).unwrap();

        let outcome = verifier.verify(&fqdn, &cert).await;
        assert!(
            matches!(outcome, VerificationOutcome::HostnameMismatch { .. }),
            "Expected HostnameMismatch, got: {:?}",
            outcome
        );
    }

    // =========================================================================
    // Prefetch Tests
    // =========================================================================

    #[tokio::test]
    async fn test_server_verifier_prefetch_success() {
        let host = "test.example.com";
        let fingerprint = "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";

        let badge = create_test_badge(host, "v1.0.0", fingerprint, "SHA256:aaa");
        let badge_url = "https://tlog.example.com/v1/agents/test-id";

        let dns_record = BadgeRecord {
            format_version: "ans-badge1".to_string(),
            version: Some(Version::new(1, 0, 0)),
            url: badge_url.to_string(),
        };

        let dns_resolver = Arc::new(MockDnsResolver::new().with_records(host, vec![dns_record]));
        let tlog_client =
            Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, badge.clone()));

        let verifier = ServerVerifier {
            dns_resolver,
            tlog_client,
            cache: Some(Arc::new(BadgeCache::with_defaults())),
            failure_policy: FailurePolicy::FailClosed,
            dane_policy: DanePolicy::Disabled,
            dane_port: 443,
            trusted_ra_domains: None,
        };

        let fqdn = Fqdn::new(host).unwrap();
        let result = verifier.prefetch(&fqdn).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap().agent_host(), host);
    }

    #[tokio::test]
    async fn test_server_verifier_prefetch_not_found() {
        let dns_resolver = Arc::new(MockDnsResolver::new());
        let tlog_client = Arc::new(MockTransparencyLogClient::new());

        let verifier = ServerVerifier {
            dns_resolver,
            tlog_client,
            cache: None,
            failure_policy: FailurePolicy::FailClosed,
            dane_policy: DanePolicy::Disabled,
            dane_port: 443,
            trusted_ra_domains: None,
        };

        let fqdn = Fqdn::new("unknown.example.com").unwrap();
        let result = verifier.prefetch(&fqdn).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AnsError::Dns(_)));
    }

    // =========================================================================
    // FailurePolicy Tests
    // =========================================================================

    #[tokio::test]
    async fn test_failure_policy_fail_open_with_cache_no_cache() {
        let dns_resolver = Arc::new(MockDnsResolver::new().with_error(
            "test.example.com",
            DnsError::LookupFailed {
                fqdn: "test.example.com".to_string(),
                reason: "timeout".to_string(),
            },
        ));
        let tlog_client = Arc::new(MockTransparencyLogClient::new());

        let verifier = ServerVerifier {
            dns_resolver,
            tlog_client,
            cache: Some(Arc::new(BadgeCache::with_defaults())),
            failure_policy: FailurePolicy::FailOpenWithCache {
                max_staleness: Duration::from_secs(600),
            },
            dane_policy: DanePolicy::Disabled,
            dane_port: 443,
            trusted_ra_domains: None,
        };

        let cert = create_test_cert_identity(
            "test.example.com",
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
        );
        let fqdn = Fqdn::new("test.example.com").unwrap();

        let outcome = verifier.verify(&fqdn, &cert).await;
        // No cached badge, so returns DNS error
        assert!(matches!(outcome, VerificationOutcome::DnsError(_)));
    }

    #[tokio::test]
    async fn test_failure_policy_fail_open_with_cache_uses_cache() {
        let host = "test.example.com";
        let fingerprint = "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";

        let badge = create_test_badge(host, "v1.0.0", fingerprint, "SHA256:aaa");
        let cache = Arc::new(BadgeCache::with_defaults());
        let fqdn = Fqdn::new(host).unwrap();

        // Pre-populate cache
        cache
            .insert_for_fqdn_version(&fqdn, &Version::new(1, 0, 0), badge)
            .await;

        let dns_resolver = Arc::new(MockDnsResolver::new().with_error(
            host,
            DnsError::LookupFailed {
                fqdn: host.to_string(),
                reason: "timeout".to_string(),
            },
        ));
        let tlog_client = Arc::new(MockTransparencyLogClient::new());

        let verifier = ServerVerifier {
            dns_resolver,
            tlog_client,
            cache: Some(cache),
            failure_policy: FailurePolicy::FailOpenWithCache {
                max_staleness: Duration::from_secs(600),
            },
            dane_policy: DanePolicy::Disabled,
            dane_port: 443,
            trusted_ra_domains: None,
        };

        let cert = create_test_cert_identity(host, fingerprint);

        let outcome = verifier.verify(&fqdn, &cert).await;
        // Should use cached badge and verify successfully
        assert!(
            outcome.is_success(),
            "Expected success with cache, got: {:?}",
            outcome
        );
    }

    #[test]
    fn test_cert_identity_from_der_server_cert() {
        use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, SanType};

        // Generate a server certificate on the fly
        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "test.agent.local");
        params.subject_alt_names.push(SanType::DnsName(
            "test.agent.local".to_string().try_into().unwrap(),
        ));
        params.subject_alt_names.push(SanType::URI(
            "ans://v1.0.0.test.agent.local".try_into().unwrap(),
        ));
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        let cert = params.self_signed(&key_pair).unwrap();
        let der = cert.der();

        let identity = CertIdentity::from_der(der).expect("should parse DER certificate");

        // Verify CN
        assert_eq!(
            identity.common_name.as_deref(),
            Some("test.agent.local"),
            "CN should be test.agent.local"
        );

        // Verify DNS SAN
        assert!(
            identity.dns_sans.contains(&"test.agent.local".to_string()),
            "DNS SANs should contain test.agent.local, got: {:?}",
            identity.dns_sans
        );

        // Verify URI SAN (ANS name)
        assert!(
            identity
                .uri_sans
                .contains(&"ans://v1.0.0.test.agent.local".to_string()),
            "URI SANs should contain ans://v1.0.0.test.agent.local, got: {:?}",
            identity.uri_sans
        );

        // Verify fingerprint matches what we compute from the same DER bytes
        let expected_fp = CertFingerprint::from_der(der);
        assert_eq!(
            identity.fingerprint, expected_fp,
            "Fingerprint should match computed fingerprint from same DER"
        );

        // Verify convenience methods
        assert_eq!(identity.fqdn(), Some("test.agent.local"));
        let ans_name = identity.ans_name().expect("should have ANS name");
        assert_eq!(ans_name.fqdn().as_str(), "test.agent.local");
        assert_eq!(identity.version(), Some(Version::new(1, 0, 0)));
    }

    #[test]
    fn test_cert_identity_from_der_client_cert() {
        use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, SanType};

        // Generate a client (identity) certificate on the fly
        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "test.agent.local");
        params.subject_alt_names.push(SanType::DnsName(
            "test.agent.local".to_string().try_into().unwrap(),
        ));
        params.subject_alt_names.push(SanType::URI(
            "ans://v1.0.0.test.agent.local".try_into().unwrap(),
        ));
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];

        let cert = params.self_signed(&key_pair).unwrap();
        let der = cert.der();

        let identity = CertIdentity::from_der(der).expect("should parse DER certificate");

        assert_eq!(identity.common_name.as_deref(), Some("test.agent.local"));
        assert!(identity.dns_sans.contains(&"test.agent.local".to_string()));
        assert!(
            identity
                .uri_sans
                .contains(&"ans://v1.0.0.test.agent.local".to_string())
        );

        let expected_fp = CertFingerprint::from_der(der);
        assert_eq!(identity.fingerprint, expected_fp);
    }

    #[test]
    fn test_cert_identity_from_der_invalid_bytes() {
        let result = CertIdentity::from_der(b"not a certificate");
        assert!(result.is_err(), "Should fail on invalid DER bytes");
    }

    #[tokio::test]
    async fn test_server_verifier_builder_dane_policy() {
        let dns = Arc::new(MockDnsResolver::new());
        let tlog = Arc::new(MockTransparencyLogClient::new());

        // with_dane_if_present convenience method
        let verifier = ServerVerifier::builder()
            .dns_resolver(dns.clone())
            .tlog_client(tlog.clone())
            .with_dane_if_present()
            .build()
            .await
            .unwrap();
        assert_eq!(verifier.dane_policy, DanePolicy::ValidateIfPresent);

        // require_dane convenience method
        let verifier = ServerVerifier::builder()
            .dns_resolver(dns.clone())
            .tlog_client(tlog.clone())
            .require_dane()
            .build()
            .await
            .unwrap();
        assert_eq!(verifier.dane_policy, DanePolicy::Required);

        // explicit dane_policy
        let verifier = ServerVerifier::builder()
            .dns_resolver(dns.clone())
            .tlog_client(tlog.clone())
            .dane_policy(DanePolicy::Disabled)
            .build()
            .await
            .unwrap();
        assert_eq!(verifier.dane_policy, DanePolicy::Disabled);
    }

    #[tokio::test]
    async fn test_server_verifier_builder_dane_port() {
        let dns = Arc::new(MockDnsResolver::new());
        let tlog = Arc::new(MockTransparencyLogClient::new());

        // Default port is 443
        let verifier = ServerVerifier::builder()
            .dns_resolver(dns.clone())
            .tlog_client(tlog.clone())
            .build()
            .await
            .unwrap();
        assert_eq!(verifier.dane_port, 443);

        // Custom port
        let verifier = ServerVerifier::builder()
            .dns_resolver(dns.clone())
            .tlog_client(tlog.clone())
            .dane_port(8443)
            .build()
            .await
            .unwrap();
        assert_eq!(verifier.dane_port, 8443);
    }

    #[tokio::test]
    async fn test_server_verifier_builder_failure_policy() {
        let dns = Arc::new(MockDnsResolver::new());
        let tlog = Arc::new(MockTransparencyLogClient::new());

        let verifier = ServerVerifier::builder()
            .dns_resolver(dns)
            .tlog_client(tlog)
            .failure_policy(FailurePolicy::FailClosed)
            .build()
            .await
            .unwrap();
        assert!(matches!(verifier.failure_policy, FailurePolicy::FailClosed));
    }

    // =========================================================================
    // Refresh-on-Mismatch Tests
    // =========================================================================

    #[tokio::test]
    async fn test_server_verification_refresh_on_mismatch_succeeds() {
        let host = "test.example.com";
        let old_fp = "SHA256:0000000000000000000000000000000000000000000000000000000000000000";
        let new_fp = "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";

        // First badge has old fingerprint (will mismatch)
        // After refresh, tlog returns badge with new fingerprint
        let badge_url = "https://tlog.example.com/v1/agents/test-id";
        let updated_badge = create_test_badge(host, "v1.0.0", new_fp, "SHA256:aaa");

        let dns_record = BadgeRecord {
            format_version: "ans-badge1".to_string(),
            version: Some(Version::new(1, 0, 0)),
            url: badge_url.to_string(),
        };

        let dns_resolver = Arc::new(MockDnsResolver::new().with_records(host, vec![dns_record]));
        // Mock always returns updated badge (simulates tlog updated after cert renewal)
        let tlog_client =
            Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, updated_badge));

        let cache = Arc::new(BadgeCache::with_defaults());
        let fqdn = Fqdn::new(host).unwrap();

        // Pre-populate cache with stale badge (old fingerprint)
        let stale_badge = create_test_badge(host, "v1.0.0", old_fp, "SHA256:aaa");
        cache
            .insert_for_fqdn_version(&fqdn, &Version::new(1, 0, 0), stale_badge)
            .await;

        let verifier = ServerVerifier {
            dns_resolver,
            tlog_client,
            cache: Some(cache),
            failure_policy: FailurePolicy::FailClosed,
            dane_policy: DanePolicy::Disabled,
            dane_port: 443,
            trusted_ra_domains: None,
        };

        // Cert has the NEW fingerprint — cache has OLD → mismatch → refresh → success
        let cert = create_test_cert_identity(host, new_fp);
        let outcome = verifier.verify(&fqdn, &cert).await;
        assert!(
            outcome.is_success(),
            "Expected success after refresh, got: {:?}",
            outcome
        );
    }

    #[tokio::test]
    async fn test_server_verification_refresh_on_mismatch_still_fails() {
        let host = "test.example.com";
        let badge_fp = "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";
        let cert_fp = "SHA256:0000000000000000000000000000000000000000000000000000000000000000";

        let badge_url = "https://tlog.example.com/v1/agents/test-id";
        // Badge always has badge_fp, cert always has cert_fp — never matches
        let badge = create_test_badge(host, "v1.0.0", badge_fp, "SHA256:aaa");

        let dns_record = BadgeRecord {
            format_version: "ans-badge1".to_string(),
            version: Some(Version::new(1, 0, 0)),
            url: badge_url.to_string(),
        };

        let dns_resolver = Arc::new(MockDnsResolver::new().with_records(host, vec![dns_record]));
        let tlog_client = Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, badge));

        let verifier = ServerVerifier {
            dns_resolver,
            tlog_client,
            cache: None,
            failure_policy: FailurePolicy::FailClosed,
            dane_policy: DanePolicy::Disabled,
            dane_port: 443,
            trusted_ra_domains: None,
        };

        let cert = create_test_cert_identity(host, cert_fp);
        let fqdn = Fqdn::new(host).unwrap();

        let outcome = verifier.verify(&fqdn, &cert).await;
        assert!(
            matches!(outcome, VerificationOutcome::FingerprintMismatch { .. }),
            "Expected FingerprintMismatch after refresh still fails, got: {:?}",
            outcome
        );
    }

    #[tokio::test]
    async fn test_client_verification_refresh_on_mismatch_succeeds() {
        let host = "test.example.com";
        let version = "v1.0.0";
        let old_identity_fp =
            "SHA256:0000000000000000000000000000000000000000000000000000000000000000";
        let new_identity_fp =
            "SHA256:aebdc9da0c20d6d5e4999a773839095ed050a9d7252bf212056fddc0c38f3496";
        let server_fp = "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";

        let badge_url = "https://tlog.example.com/v1/agents/test-id";
        // Tlog returns updated badge with new identity fingerprint
        let updated_badge = create_test_badge(host, version, server_fp, new_identity_fp);

        let dns_record = BadgeRecord {
            format_version: "ans-badge1".to_string(),
            version: Some(Version::new(1, 0, 0)),
            url: badge_url.to_string(),
        };

        let dns_resolver = Arc::new(MockDnsResolver::new().with_records(host, vec![dns_record]));
        let tlog_client =
            Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, updated_badge));

        let cache = Arc::new(BadgeCache::with_defaults());
        let fqdn = Fqdn::new(host).unwrap();
        let ver = Version::new(1, 0, 0);

        // Pre-populate cache with stale badge (old identity fingerprint)
        let stale_badge = create_test_badge(host, version, server_fp, old_identity_fp);
        cache
            .insert_for_fqdn_version(&fqdn, &ver, stale_badge)
            .await;

        let verifier = ClientVerifier {
            dns_resolver,
            tlog_client,
            cache: Some(cache),
            failure_policy: FailurePolicy::FailClosed,
            trusted_ra_domains: None,
        };

        // Client cert has new fingerprint — cache has old → mismatch → refresh → success
        let cert = create_mtls_cert_identity(host, version, new_identity_fp);
        let outcome = verifier.verify(&cert).await;
        assert!(
            outcome.is_success(),
            "Expected success after client refresh, got: {:?}",
            outcome
        );
    }

    // =========================================================================
    // Trusted RA Domain Validation Tests
    // =========================================================================

    #[test]
    fn test_validate_badge_domain_unit_allows_when_none() {
        assert!(validate_badge_domain(None, "https://tlog.example.com/v1/agents/test").is_ok());
    }

    #[test]
    fn test_validate_badge_domain_unit_allows_trusted() {
        let trusted: HashSet<String> = ["tlog.example.com".to_string()].into();
        assert!(
            validate_badge_domain(Some(&trusted), "https://tlog.example.com/v1/agents/test")
                .is_ok()
        );
    }

    #[test]
    fn test_validate_badge_domain_unit_rejects_untrusted() {
        let trusted: HashSet<String> = ["tlog.example.com".to_string()].into();
        let err = validate_badge_domain(Some(&trusted), "https://evil.attacker.com/v1/agents/test")
            .unwrap_err();
        assert!(
            matches!(err, TlogError::UntrustedDomain { domain, .. } if domain == "evil.attacker.com")
        );
    }

    #[test]
    fn test_validate_badge_domain_unit_multiple_trusted() {
        let trusted: HashSet<String> = [
            "tlog1.example.com".to_string(),
            "tlog2.example.com".to_string(),
        ]
        .into();
        assert!(validate_badge_domain(Some(&trusted), "https://tlog1.example.com/badge").is_ok());
        assert!(validate_badge_domain(Some(&trusted), "https://tlog2.example.com/badge").is_ok());
        assert!(validate_badge_domain(Some(&trusted), "https://tlog3.example.com/badge").is_err());
    }

    #[tokio::test]
    async fn test_trusted_ra_none_allows_all() {
        let host = "test.example.com";
        let fingerprint = "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";
        let badge = create_test_badge(host, "v1.0.0", fingerprint, "SHA256:aaa");
        let badge_url = "https://any-domain.example.com/v1/agents/test-id";

        let dns_record = BadgeRecord {
            format_version: "ans-badge1".to_string(),
            version: Some(Version::new(1, 0, 0)),
            url: badge_url.to_string(),
        };
        let dns_resolver = Arc::new(MockDnsResolver::new().with_records(host, vec![dns_record]));
        let tlog_client = Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, badge));

        let verifier = ServerVerifier {
            dns_resolver,
            tlog_client,
            cache: None,
            failure_policy: FailurePolicy::FailClosed,
            dane_policy: DanePolicy::Disabled,
            dane_port: 443,
            trusted_ra_domains: None,
        };

        let cert = create_test_cert_identity(host, fingerprint);
        let fqdn = Fqdn::new(host).unwrap();
        let outcome = verifier.verify(&fqdn, &cert).await;
        assert!(outcome.is_success(), "None should allow all domains");
    }

    #[tokio::test]
    async fn test_trusted_ra_allows_trusted_domain() {
        let host = "test.example.com";
        let fingerprint = "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";
        let badge = create_test_badge(host, "v1.0.0", fingerprint, "SHA256:aaa");
        let badge_url = "https://tlog.example.com/v1/agents/test-id";

        let dns_record = BadgeRecord {
            format_version: "ans-badge1".to_string(),
            version: Some(Version::new(1, 0, 0)),
            url: badge_url.to_string(),
        };
        let dns_resolver = Arc::new(MockDnsResolver::new().with_records(host, vec![dns_record]));
        let tlog_client = Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, badge));

        let verifier = ServerVerifier {
            dns_resolver,
            tlog_client,
            cache: None,
            failure_policy: FailurePolicy::FailClosed,
            dane_policy: DanePolicy::Disabled,
            dane_port: 443,
            trusted_ra_domains: Some(["tlog.example.com".to_string()].into()),
        };

        let cert = create_test_cert_identity(host, fingerprint);
        let fqdn = Fqdn::new(host).unwrap();
        let outcome = verifier.verify(&fqdn, &cert).await;
        assert!(outcome.is_success(), "Trusted domain should succeed");
    }

    #[tokio::test]
    async fn test_trusted_ra_rejects_untrusted_domain() {
        let host = "test.example.com";
        let fingerprint = "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";
        let badge = create_test_badge(host, "v1.0.0", fingerprint, "SHA256:aaa");
        let badge_url = "https://evil.attacker.com/v1/agents/test-id";

        let dns_record = BadgeRecord {
            format_version: "ans-badge1".to_string(),
            version: Some(Version::new(1, 0, 0)),
            url: badge_url.to_string(),
        };
        let dns_resolver = Arc::new(MockDnsResolver::new().with_records(host, vec![dns_record]));
        let tlog_client = Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, badge));

        let verifier = ServerVerifier {
            dns_resolver,
            tlog_client,
            cache: None,
            failure_policy: FailurePolicy::FailClosed,
            dane_policy: DanePolicy::Disabled,
            dane_port: 443,
            trusted_ra_domains: Some(["tlog.example.com".to_string()].into()),
        };

        let cert = create_test_cert_identity(host, fingerprint);
        let fqdn = Fqdn::new(host).unwrap();
        let outcome = verifier.verify(&fqdn, &cert).await;
        assert!(
            matches!(
                outcome,
                VerificationOutcome::TlogError(TlogError::UntrustedDomain { .. })
            ),
            "Untrusted domain should be rejected, got: {:?}",
            outcome
        );
    }

    #[tokio::test]
    async fn test_trusted_ra_client_rejects_untrusted() {
        let host = "test.example.com";
        let version = "v1.0.0";
        let identity_fp = "SHA256:aebdc9da0c20d6d5e4999a773839095ed050a9d7252bf212056fddc0c38f3496";
        let server_fp = "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";
        let badge = create_test_badge(host, version, server_fp, identity_fp);
        let badge_url = "https://evil.attacker.com/v1/agents/test-id";

        let dns_record = BadgeRecord {
            format_version: "ans-badge1".to_string(),
            version: Some(Version::new(1, 0, 0)),
            url: badge_url.to_string(),
        };
        let dns_resolver = Arc::new(MockDnsResolver::new().with_records(host, vec![dns_record]));
        let tlog_client = Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, badge));

        let verifier = ClientVerifier {
            dns_resolver,
            tlog_client,
            cache: None,
            failure_policy: FailurePolicy::FailClosed,
            trusted_ra_domains: Some(["tlog.example.com".to_string()].into()),
        };

        let cert = create_mtls_cert_identity(host, version, identity_fp);
        let outcome = verifier.verify(&cert).await;
        assert!(
            matches!(
                outcome,
                VerificationOutcome::TlogError(TlogError::UntrustedDomain { .. })
            ),
            "Client verifier should reject untrusted domain, got: {:?}",
            outcome
        );
    }

    #[tokio::test]
    async fn test_trusted_ra_builder_propagation() {
        let dns_resolver = Arc::new(MockDnsResolver::new());
        let tlog_client = Arc::new(MockTransparencyLogClient::new());

        let verifier = ServerVerifier::builder()
            .dns_resolver(dns_resolver as Arc<dyn DnsResolver>)
            .tlog_client(tlog_client as Arc<dyn TransparencyLogClient>)
            .trusted_ra_domains(["tlog.example.com", "tlog2.example.com"])
            .build()
            .await
            .unwrap();

        // Verify the builder propagated the trusted domains correctly
        let trusted = verifier.trusted_ra_domains.as_ref().unwrap();
        assert!(trusted.contains("tlog.example.com"));
        assert!(trusted.contains("tlog2.example.com"));
        assert_eq!(trusted.len(), 2);
    }

    // =========================================================================
    // 7a: VerificationOutcome::into_result() — CertError and ParseError branches
    // =========================================================================

    #[test]
    fn test_outcome_into_result_cert_error() {
        let outcome =
            VerificationOutcome::CertError(CryptoError::ParseFailed("bad cert".to_string()));
        let err = outcome.into_result().unwrap_err();
        assert!(matches!(err, AnsError::Certificate(_)));
    }

    #[test]
    fn test_outcome_into_result_parse_error() {
        let outcome = VerificationOutcome::ParseError(ans_types::ParseError::InvalidFqdn(
            "bad fqdn".to_string(),
        ));
        let err = outcome.into_result().unwrap_err();
        assert!(matches!(err, AnsError::Parse(_)));
    }

    #[test]
    fn test_outcome_into_result_dane_error() {
        let outcome = VerificationOutcome::DaneError(DaneError::FingerprintMismatch);
        let err = outcome.into_result().unwrap_err();
        assert!(matches!(
            err,
            AnsError::Verification(VerificationError::DaneVerificationFailed(_))
        ));
    }

    #[test]
    fn test_outcome_into_result_dns_error() {
        let outcome = VerificationOutcome::DnsError(DnsError::Timeout {
            fqdn: "test.example.com".to_string(),
        });
        let err = outcome.into_result().unwrap_err();
        assert!(matches!(err, AnsError::Dns(DnsError::Timeout { .. })));
    }

    #[test]
    fn test_outcome_into_result_tlog_error() {
        let outcome = VerificationOutcome::TlogError(TlogError::ServiceUnavailable);
        let err = outcome.into_result().unwrap_err();
        assert!(matches!(
            err,
            AnsError::TransparencyLog(TlogError::ServiceUnavailable)
        ));
    }

    // =========================================================================
    // 7b: AnsVerifierBuilder DNS presets
    // =========================================================================

    #[tokio::test]
    async fn test_builder_dns_cloudflare() {
        let dns = Arc::new(MockDnsResolver::new());
        let tlog = Arc::new(MockTransparencyLogClient::new());

        // Test that the builder method configures correctly
        let verifier = AnsVerifier::builder()
            .dns_resolver(dns as Arc<dyn DnsResolver>)
            .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
            .dns_cloudflare() // preset is ignored when custom resolver is set
            .build()
            .await
            .unwrap();

        // Verify the builder produces a working verifier
        let dbg = format!("{verifier:?}");
        assert!(dbg.contains("AnsVerifier"));
    }

    #[tokio::test]
    async fn test_builder_dns_nameservers() {
        let tlog = Arc::new(MockTransparencyLogClient::new());

        let verifier = AnsVerifier::builder()
            .dns_nameservers(&[std::net::Ipv4Addr::new(1, 1, 1, 1)])
            .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
            .build()
            .await
            .unwrap();

        let dbg = format!("{verifier:?}");
        assert!(dbg.contains("AnsVerifier"));
    }

    #[tokio::test]
    async fn test_builder_dns_preset_path() {
        let tlog = Arc::new(MockTransparencyLogClient::new());

        let verifier = AnsVerifier::builder()
            .dns_preset(DnsResolverConfig::Cloudflare)
            .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
            .build()
            .await
            .unwrap();

        let dbg = format!("{verifier:?}");
        assert!(dbg.contains("AnsVerifier"));
    }

    // =========================================================================
    // 7c: AnsVerifier rustls methods
    // =========================================================================

    #[cfg(feature = "rustls")]
    #[tokio::test]
    async fn test_client_cert_verifier_without_pem() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dns = Arc::new(MockDnsResolver::new());
        let tlog = Arc::new(MockTransparencyLogClient::new());

        let verifier = AnsVerifier::builder()
            .dns_resolver(dns as Arc<dyn DnsResolver>)
            .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
            .build()
            .await
            .unwrap();

        let result = verifier.client_cert_verifier();
        assert!(result.is_err());
    }

    #[cfg(feature = "rustls")]
    #[tokio::test]
    async fn test_client_cert_verifier_with_pem() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = rcgen::generate_simple_self_signed(vec!["ANS Test CA".to_string()]).unwrap();
        let ca_pem = ca.cert.pem();

        let dns = Arc::new(MockDnsResolver::new());
        let tlog = Arc::new(MockTransparencyLogClient::new());

        let verifier = AnsVerifier::builder()
            .dns_resolver(dns as Arc<dyn DnsResolver>)
            .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
            .private_ca_pem(ca_pem.as_bytes().to_vec())
            .build()
            .await
            .unwrap();

        let cv = verifier.client_cert_verifier().unwrap();
        assert!(cv.requires_client_cert());
    }

    #[cfg(feature = "rustls")]
    #[tokio::test]
    async fn test_client_cert_verifier_optional_with_pem() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = rcgen::generate_simple_self_signed(vec!["ANS Test CA".to_string()]).unwrap();
        let ca_pem = ca.cert.pem();

        let dns = Arc::new(MockDnsResolver::new());
        let tlog = Arc::new(MockTransparencyLogClient::new());

        let verifier = AnsVerifier::builder()
            .dns_resolver(dns as Arc<dyn DnsResolver>)
            .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
            .private_ca_pem(ca_pem.as_bytes().to_vec())
            .build()
            .await
            .unwrap();

        let cv = verifier.client_cert_verifier_optional().unwrap();
        assert!(!cv.requires_client_cert());
    }

    #[cfg(feature = "rustls")]
    #[tokio::test]
    async fn test_server_cert_verifier() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dns = Arc::new(MockDnsResolver::new());
        let tlog = Arc::new(MockTransparencyLogClient::new());

        let verifier = AnsVerifier::builder()
            .dns_resolver(dns as Arc<dyn DnsResolver>)
            .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
            .build()
            .await
            .unwrap();

        let fp = CertFingerprint::parse(
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
        )
        .unwrap();
        let sv = verifier.server_cert_verifier(&fp).unwrap();
        assert_eq!(sv.expected_fingerprint(), &fp);
    }

    // =========================================================================
    // 7d: Builder configuration methods
    // =========================================================================

    #[tokio::test]
    async fn test_builder_with_caching() {
        let dns = Arc::new(MockDnsResolver::new());
        let tlog = Arc::new(MockTransparencyLogClient::new());

        let verifier = AnsVerifier::builder()
            .dns_resolver(dns as Arc<dyn DnsResolver>)
            .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
            .with_caching()
            .build()
            .await
            .unwrap();

        // Verify the verifier was built with caching
        assert!(format!("{verifier:?}").contains("has_cache"));
    }

    #[tokio::test]
    async fn test_builder_with_cache_config() {
        let dns = Arc::new(MockDnsResolver::new());
        let tlog = Arc::new(MockTransparencyLogClient::new());

        let verifier = AnsVerifier::builder()
            .dns_resolver(dns as Arc<dyn DnsResolver>)
            .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
            .with_cache_config(CacheConfig::default())
            .build()
            .await
            .unwrap();

        assert!(format!("{verifier:?}").contains("AnsVerifier"));
    }

    #[tokio::test]
    async fn test_builder_with_dane_if_present() {
        let dns = Arc::new(MockDnsResolver::new());
        let tlog = Arc::new(MockTransparencyLogClient::new());

        let verifier = ServerVerifier::builder()
            .dns_resolver(dns as Arc<dyn DnsResolver>)
            .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
            .with_dane_if_present()
            .build()
            .await
            .unwrap();

        assert_eq!(verifier.dane_policy, DanePolicy::ValidateIfPresent);
    }

    #[tokio::test]
    async fn test_builder_require_dane() {
        let dns = Arc::new(MockDnsResolver::new());
        let tlog = Arc::new(MockTransparencyLogClient::new());

        let verifier = ServerVerifier::builder()
            .dns_resolver(dns as Arc<dyn DnsResolver>)
            .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
            .require_dane()
            .build()
            .await
            .unwrap();

        assert_eq!(verifier.dane_policy, DanePolicy::Required);
    }

    #[tokio::test]
    async fn test_builder_dane_port() {
        let dns = Arc::new(MockDnsResolver::new());
        let tlog = Arc::new(MockTransparencyLogClient::new());

        let verifier = ServerVerifier::builder()
            .dns_resolver(dns as Arc<dyn DnsResolver>)
            .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
            .dane_port(8443)
            .build()
            .await
            .unwrap();

        assert_eq!(verifier.dane_port, 8443);
    }

    #[tokio::test]
    async fn test_builder_trusted_ra_domains() {
        let dns = Arc::new(MockDnsResolver::new());
        let tlog = Arc::new(MockTransparencyLogClient::new());

        let verifier = ServerVerifier::builder()
            .dns_resolver(dns as Arc<dyn DnsResolver>)
            .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
            .trusted_ra_domains(["tlog.example.com"])
            .build()
            .await
            .unwrap();

        assert!(verifier.trusted_ra_domains.is_some());
        assert!(
            verifier
                .trusted_ra_domains
                .unwrap()
                .contains("tlog.example.com")
        );
    }

    // =========================================================================
    // 7e: DANE Required failure path
    // =========================================================================

    #[tokio::test]
    async fn test_dane_required_no_tlsa_records() {
        let host = "test.example.com";
        let fingerprint = "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";

        let badge = create_test_badge(host, "v1.0.0", fingerprint, "SHA256:aaa");
        let badge_url = "https://tlog.example.com/v1/agents/test-id";

        let dns_record = BadgeRecord {
            format_version: "ans-badge1".to_string(),
            version: Some(Version::new(1, 0, 0)),
            url: badge_url.to_string(),
        };

        // No TLSA records configured — DANE Required should fail
        let dns_resolver = Arc::new(MockDnsResolver::new().with_records(host, vec![dns_record]));
        let tlog_client = Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, badge));

        let verifier = ServerVerifier {
            dns_resolver,
            tlog_client,
            cache: None,
            failure_policy: FailurePolicy::FailClosed,
            dane_policy: DanePolicy::Required,
            dane_port: 443,
            trusted_ra_domains: None,
        };

        let cert = create_test_cert_identity(host, fingerprint);
        let fqdn = Fqdn::new(host).unwrap();

        let outcome = verifier.verify(&fqdn, &cert).await;
        assert!(
            matches!(outcome, VerificationOutcome::DaneError(_)),
            "Expected DaneError for required DANE with no TLSA records, got: {outcome:?}"
        );
    }

    // =========================================================================
    // VerificationOutcome helpers
    // =========================================================================

    #[test]
    fn test_outcome_badge_returns_none_for_errors() {
        let outcome = VerificationOutcome::DnsError(DnsError::Timeout {
            fqdn: "test.example.com".to_string(),
        });
        assert!(outcome.badge().is_none());

        let outcome = VerificationOutcome::NotAnsAgent {
            fqdn: "test.example.com".to_string(),
        };
        assert!(outcome.badge().is_none());
    }

    #[test]
    fn test_outcome_badge_returns_some_for_mismatches() {
        let badge = create_test_badge(
            "test.example.com",
            "v1.0.0",
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
            "SHA256:aaa",
        );

        let outcome = VerificationOutcome::HostnameMismatch {
            expected: "test.example.com".to_string(),
            actual: "other.example.com".to_string(),
            badge,
        };
        assert!(outcome.badge().is_some());
    }

    #[test]
    fn test_server_verifier_debug_format() {
        let dbg = format!("{:?}", ServerVerifierBuilder::default());
        assert!(dbg.contains("ServerVerifierBuilder"));
    }
}
