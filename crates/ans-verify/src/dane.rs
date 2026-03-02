//! DANE/TLSA verification for certificate binding to DNS.
//!
//! DANE (DNS-Based Authentication of Named Entities) binds certificates to DNS names
//! via TLSA records, providing additional verification independent of the transparency log.

use crate::error::DaneError;
use ans_types::{CertFingerprint, Fqdn};

/// DANE verification policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum DanePolicy {
    /// Never check TLSA records (skip DANE verification entirely).
    #[default]
    Disabled,

    /// Validate TLSA records if present; skip if not found.
    /// This is a permissive mode that adds security when available.
    ValidateIfPresent,

    /// Require TLSA records to exist and validate.
    /// Connections are rejected if TLSA records are missing or don't match.
    Required,
}

impl DanePolicy {
    /// Check if DANE verification should be performed.
    pub fn should_verify(&self) -> bool {
        !matches!(self, Self::Disabled)
    }

    /// Check if TLSA records are required.
    pub fn is_required(&self) -> bool {
        matches!(self, Self::Required)
    }
}

/// TLSA certificate usage field values (RFC 6698).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum TlsaUsage {
    /// CA constraint (PKIX-TA)
    CaConstraint = 0,
    /// Service certificate constraint (PKIX-EE)
    ServiceCertificateConstraint = 1,
    /// Trust anchor assertion (DANE-TA)
    TrustAnchorAssertion = 2,
    /// Domain-issued certificate (DANE-EE) - most common for ANS
    DomainIssuedCertificate = 3,
}

impl TryFrom<u8> for TlsaUsage {
    type Error = DaneError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::CaConstraint),
            1 => Ok(Self::ServiceCertificateConstraint),
            2 => Ok(Self::TrustAnchorAssertion),
            3 => Ok(Self::DomainIssuedCertificate),
            _ => Err(DaneError::InvalidRecord {
                reason: format!("invalid TLSA usage: {value}"),
            }),
        }
    }
}

/// TLSA selector field values (RFC 6698).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum TlsaSelector {
    /// Full certificate
    FullCertificate = 0,
    /// `SubjectPublicKeyInfo`
    SubjectPublicKeyInfo = 1,
}

impl TryFrom<u8> for TlsaSelector {
    type Error = DaneError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::FullCertificate),
            1 => Ok(Self::SubjectPublicKeyInfo),
            _ => Err(DaneError::InvalidRecord {
                reason: format!("invalid TLSA selector: {value}"),
            }),
        }
    }
}

/// TLSA matching type field values (RFC 6698).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum TlsaMatchingType {
    /// No hash - exact match
    NoHash = 0,
    /// SHA-256 hash
    Sha256 = 1,
    /// SHA-512 hash
    Sha512 = 2,
}

impl TryFrom<u8> for TlsaMatchingType {
    type Error = DaneError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::NoHash),
            1 => Ok(Self::Sha256),
            2 => Ok(Self::Sha512),
            _ => Err(DaneError::InvalidRecord {
                reason: format!("invalid TLSA matching type: {value}"),
            }),
        }
    }
}

/// A parsed TLSA record.
///
/// Format: `_port._tcp.hostname IN TLSA usage selector matching_type certificate_data`
///
/// Example: `_443._tcp.agent.example.com IN TLSA 3 0 1 <sha256-fingerprint>`
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TlsaRecord {
    /// Certificate usage (0-3)
    pub usage: TlsaUsage,
    /// Selector (0=full cert, 1=SPKI)
    pub selector: TlsaSelector,
    /// Matching type (0=exact, 1=SHA-256, 2=SHA-512)
    pub matching_type: TlsaMatchingType,
    /// Certificate association data (fingerprint or raw data)
    pub certificate_data: Vec<u8>,
}

impl TlsaRecord {
    /// Create a new TLSA record from components.
    pub fn new(
        usage: TlsaUsage,
        selector: TlsaSelector,
        matching_type: TlsaMatchingType,
        certificate_data: Vec<u8>,
    ) -> Self {
        Self {
            usage,
            selector,
            matching_type,
            certificate_data,
        }
    }

    /// Parse a TLSA record from raw RDATA bytes.
    pub fn from_rdata(rdata: &[u8]) -> Result<Self, DaneError> {
        if rdata.len() < 4 {
            return Err(DaneError::InvalidRecord {
                reason: "TLSA record too short".to_string(),
            });
        }

        let usage = TlsaUsage::try_from(rdata[0])?;
        let selector = TlsaSelector::try_from(rdata[1])?;
        let matching_type = TlsaMatchingType::try_from(rdata[2])?;
        let certificate_data = rdata[3..].to_vec();

        Ok(Self {
            usage,
            selector,
            matching_type,
            certificate_data,
        })
    }

    /// Check if this TLSA record is in a format we can verify.
    ///
    /// Currently only supports DANE-EE (usage=3), full certificate (selector=0),
    /// SHA-256 (`matching_type=1`) which is the ANS standard format.
    pub fn is_verifiable(&self) -> bool {
        self.usage == TlsaUsage::DomainIssuedCertificate
            && self.selector == TlsaSelector::FullCertificate
            && self.matching_type == TlsaMatchingType::Sha256
    }

    /// Check if this TLSA record matches a certificate fingerprint.
    ///
    /// Currently only supports DANE-EE (usage=3), full certificate (selector=0),
    /// SHA-256 (`matching_type=1`) which is the ANS standard format.
    ///
    /// Returns `None` if the record format is not supported (different from not matching).
    pub fn matches_fingerprint(&self, cert_fingerprint: &CertFingerprint) -> Option<bool> {
        // ANS uses: DANE-EE (3), Full Certificate (0), SHA-256 (1)
        if self.usage != TlsaUsage::DomainIssuedCertificate {
            tracing::debug!(
                usage = ?self.usage,
                "TLSA usage is not DANE-EE, cannot verify"
            );
            return None;
        }

        if self.selector != TlsaSelector::FullCertificate {
            tracing::debug!(
                selector = ?self.selector,
                "TLSA selector is not full certificate (SPKI not yet supported), cannot verify"
            );
            return None;
        }

        if self.matching_type != TlsaMatchingType::Sha256 {
            tracing::debug!(
                matching_type = ?self.matching_type,
                "TLSA matching type is not SHA-256, cannot verify"
            );
            return None;
        }

        // Compare raw bytes using constant-time equality to prevent timing side-channels.
        // Both sides are SHA-256 hashes (32 bytes). If the TLSA data has wrong length,
        // the comparison fails (not a timing concern since length is not secret).
        let cert_bytes = cert_fingerprint.as_bytes();
        let matches = if self.certificate_data.len() == cert_bytes.len() {
            use subtle::ConstantTimeEq;
            bool::from(self.certificate_data.ct_eq(cert_bytes.as_slice()))
        } else {
            false
        };

        tracing::debug!(
            tlsa_fingerprint = %hex::encode(&self.certificate_data),
            cert_fingerprint = %cert_fingerprint,
            matches,
            "TLSA fingerprint comparison"
        );

        Some(matches)
    }
}

/// Result of DANE verification.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum DaneVerificationResult {
    /// TLSA record matched the certificate.
    Verified {
        /// The TLSA record that matched.
        matched_record: TlsaRecord,
    },
    /// No TLSA records found (not an error if policy is `ValidateIfPresent`).
    NoRecords,
    /// TLSA records found but none matched.
    Mismatch {
        /// Number of TLSA records checked.
        records_checked: usize,
    },
    /// DNSSEC validation failed.
    DnssecFailed,
    /// Verification was skipped (policy is Disabled).
    Skipped,
}

impl DaneVerificationResult {
    /// Check if verification passed or was appropriately skipped.
    pub fn is_acceptable(&self, policy: DanePolicy) -> bool {
        match self {
            Self::Verified { .. } | Self::Skipped => true,
            Self::NoRecords => !policy.is_required(),
            Self::Mismatch { .. } | Self::DnssecFailed => false,
        }
    }
}

/// Verify a certificate against TLSA records.
pub fn verify_dane(
    records: &[TlsaRecord],
    cert_fingerprint: &CertFingerprint,
    policy: DanePolicy,
    fqdn: &Fqdn,
    port: u16,
) -> Result<DaneVerificationResult, DaneError> {
    if !policy.should_verify() {
        tracing::debug!("DANE verification disabled by policy");
        return Ok(DaneVerificationResult::Skipped);
    }

    if records.is_empty() {
        tracing::debug!(fqdn = %fqdn, port, "No TLSA records found");
        if policy.is_required() {
            return Err(DaneError::NoTlsaRecords {
                fqdn: fqdn.to_string(),
                port,
            });
        }
        return Ok(DaneVerificationResult::NoRecords);
    }

    tracing::debug!(
        fqdn = %fqdn,
        port,
        record_count = records.len(),
        "Checking TLSA records"
    );

    // Check each TLSA record
    let mut has_unsupported = false;

    for record in records {
        match record.matches_fingerprint(cert_fingerprint) {
            Some(true) => {
                tracing::info!(
                    fqdn = %fqdn,
                    port,
                    "DANE verification PASSED - certificate matches TLSA record"
                );
                return Ok(DaneVerificationResult::Verified {
                    matched_record: record.clone(),
                });
            }
            Some(false) => {
                tracing::debug!("TLSA record checked but did not match");
            }
            None => {
                // Record is in unsupported format (e.g., SPKI selector)
                has_unsupported = true;
                tracing::warn!(
                    usage = ?record.usage,
                    selector = ?record.selector,
                    matching_type = ?record.matching_type,
                    "TLSA record in unsupported format"
                );
            }
        }
    }

    // If records exist but none matched, fail
    // This includes both: records in supported format that didn't match,
    // AND records in unsupported format (we can't verify them, so we fail)
    if has_unsupported {
        tracing::error!(
            fqdn = %fqdn,
            port,
            "DANE verification FAILED - TLSA records present but in unsupported format (only DANE-EE + FullCert + SHA256 supported)"
        );
        return Err(DaneError::InvalidRecord {
            reason: "TLSA record format not supported (only usage=3, selector=0, matching_type=1)"
                .to_string(),
        });
    }

    tracing::warn!(
        fqdn = %fqdn,
        port,
        records_checked = records.len(),
        "DANE verification FAILED - no TLSA record matched certificate"
    );

    Err(DaneError::FingerprintMismatch)
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dane_policy_defaults_to_disabled() {
        assert_eq!(DanePolicy::default(), DanePolicy::Disabled);
    }

    #[test]
    fn test_dane_policy_should_verify() {
        assert!(!DanePolicy::Disabled.should_verify());
        assert!(DanePolicy::ValidateIfPresent.should_verify());
        assert!(DanePolicy::Required.should_verify());
    }

    #[test]
    fn test_dane_policy_is_required() {
        assert!(!DanePolicy::Disabled.is_required());
        assert!(!DanePolicy::ValidateIfPresent.is_required());
        assert!(DanePolicy::Required.is_required());
    }

    #[test]
    fn test_tlsa_record_from_rdata() {
        // Usage=3, Selector=0, MatchingType=1, followed by SHA-256 hash
        let mut rdata = vec![3, 0, 1];
        let hash = hex::decode("e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904")
            .unwrap();
        rdata.extend(&hash);

        let record = TlsaRecord::from_rdata(&rdata).unwrap();
        assert_eq!(record.usage, TlsaUsage::DomainIssuedCertificate);
        assert_eq!(record.selector, TlsaSelector::FullCertificate);
        assert_eq!(record.matching_type, TlsaMatchingType::Sha256);
        assert_eq!(record.certificate_data, hash);
    }

    #[test]
    fn test_tlsa_record_matches_fingerprint() {
        let hash = hex::decode("e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904")
            .unwrap();

        let record = TlsaRecord::new(
            TlsaUsage::DomainIssuedCertificate,
            TlsaSelector::FullCertificate,
            TlsaMatchingType::Sha256,
            hash,
        );

        let fingerprint = CertFingerprint::parse(
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
        )
        .unwrap();

        assert_eq!(record.matches_fingerprint(&fingerprint), Some(true));
    }

    #[test]
    fn test_tlsa_record_does_not_match_different_fingerprint() {
        let hash = hex::decode("e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904")
            .unwrap();

        let record = TlsaRecord::new(
            TlsaUsage::DomainIssuedCertificate,
            TlsaSelector::FullCertificate,
            TlsaMatchingType::Sha256,
            hash,
        );

        let fingerprint = CertFingerprint::parse(
            "SHA256:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();

        assert_eq!(record.matches_fingerprint(&fingerprint), Some(false));
    }

    #[test]
    fn test_tlsa_record_unsupported_format_returns_none() {
        let hash = hex::decode("e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904")
            .unwrap();

        // SPKI selector is not supported
        let record = TlsaRecord::new(
            TlsaUsage::DomainIssuedCertificate,
            TlsaSelector::SubjectPublicKeyInfo,
            TlsaMatchingType::Sha256,
            hash,
        );

        let fingerprint = CertFingerprint::parse(
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
        )
        .unwrap();

        // Should return None because format is not supported
        assert_eq!(record.matches_fingerprint(&fingerprint), None);
    }

    #[test]
    fn test_verify_dane_disabled() {
        let fqdn = Fqdn::new("test.example.com").unwrap();
        let fingerprint = CertFingerprint::parse(
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
        )
        .unwrap();

        let result = verify_dane(&[], &fingerprint, DanePolicy::Disabled, &fqdn, 443).unwrap();
        assert!(matches!(result, DaneVerificationResult::Skipped));
    }

    #[test]
    fn test_verify_dane_no_records_validate_if_present() {
        let fqdn = Fqdn::new("test.example.com").unwrap();
        let fingerprint = CertFingerprint::parse(
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
        )
        .unwrap();

        let result =
            verify_dane(&[], &fingerprint, DanePolicy::ValidateIfPresent, &fqdn, 443).unwrap();
        assert!(matches!(result, DaneVerificationResult::NoRecords));
        assert!(result.is_acceptable(DanePolicy::ValidateIfPresent));
    }

    #[test]
    fn test_verify_dane_no_records_required() {
        let fqdn = Fqdn::new("test.example.com").unwrap();
        let fingerprint = CertFingerprint::parse(
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
        )
        .unwrap();

        let result = verify_dane(&[], &fingerprint, DanePolicy::Required, &fqdn, 443);
        assert!(matches!(result, Err(DaneError::NoTlsaRecords { .. })));
    }

    #[test]
    fn test_verify_dane_match() {
        let fqdn = Fqdn::new("test.example.com").unwrap();
        let hash = hex::decode("e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904")
            .unwrap();

        let record = TlsaRecord::new(
            TlsaUsage::DomainIssuedCertificate,
            TlsaSelector::FullCertificate,
            TlsaMatchingType::Sha256,
            hash,
        );

        let fingerprint = CertFingerprint::parse(
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
        )
        .unwrap();

        let result =
            verify_dane(&[record], &fingerprint, DanePolicy::Required, &fqdn, 443).unwrap();
        assert!(matches!(result, DaneVerificationResult::Verified { .. }));
    }

    #[test]
    fn test_verify_dane_mismatch() {
        let fqdn = Fqdn::new("test.example.com").unwrap();
        let hash = hex::decode("e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904")
            .unwrap();

        let record = TlsaRecord::new(
            TlsaUsage::DomainIssuedCertificate,
            TlsaSelector::FullCertificate,
            TlsaMatchingType::Sha256,
            hash,
        );

        let fingerprint = CertFingerprint::parse(
            "SHA256:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();

        let result = verify_dane(&[record], &fingerprint, DanePolicy::Required, &fqdn, 443);
        assert!(matches!(result, Err(DaneError::FingerprintMismatch)));
    }

    #[test]
    fn test_verification_result_is_acceptable() {
        let record = TlsaRecord::new(
            TlsaUsage::DomainIssuedCertificate,
            TlsaSelector::FullCertificate,
            TlsaMatchingType::Sha256,
            vec![0; 32],
        );

        // Verified is always acceptable
        let verified = DaneVerificationResult::Verified {
            matched_record: record,
        };
        assert!(verified.is_acceptable(DanePolicy::Disabled));
        assert!(verified.is_acceptable(DanePolicy::ValidateIfPresent));
        assert!(verified.is_acceptable(DanePolicy::Required));

        // NoRecords is acceptable unless Required
        let no_records = DaneVerificationResult::NoRecords;
        assert!(no_records.is_acceptable(DanePolicy::Disabled));
        assert!(no_records.is_acceptable(DanePolicy::ValidateIfPresent));
        assert!(!no_records.is_acceptable(DanePolicy::Required));

        // Skipped is always acceptable
        let skipped = DaneVerificationResult::Skipped;
        assert!(skipped.is_acceptable(DanePolicy::Disabled));
        assert!(skipped.is_acceptable(DanePolicy::ValidateIfPresent));
        assert!(skipped.is_acceptable(DanePolicy::Required));

        // Mismatch is never acceptable
        let mismatch = DaneVerificationResult::Mismatch { records_checked: 1 };
        assert!(!mismatch.is_acceptable(DanePolicy::Disabled));
        assert!(!mismatch.is_acceptable(DanePolicy::ValidateIfPresent));
        assert!(!mismatch.is_acceptable(DanePolicy::Required));
    }

    // ── TlsaRecord::from_rdata edge cases ────────────────────────────

    #[test]
    fn test_tlsa_from_rdata_too_short() {
        let result = TlsaRecord::from_rdata(&[3, 0]);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DaneError::InvalidRecord { .. }
        ));
    }

    #[test]
    fn test_tlsa_from_rdata_empty() {
        let result = TlsaRecord::from_rdata(&[]);
        assert!(result.is_err());
    }

    // ── TryFrom<u8> invalid values ───────────────────────────────────

    #[test]
    fn test_tlsa_usage_invalid() {
        let result = TlsaUsage::try_from(4_u8);
        assert!(result.is_err());
    }

    #[test]
    fn test_tlsa_selector_invalid() {
        let result = TlsaSelector::try_from(2_u8);
        assert!(result.is_err());
    }

    #[test]
    fn test_tlsa_matching_type_invalid() {
        let result = TlsaMatchingType::try_from(3_u8);
        assert!(result.is_err());
    }

    // ── is_verifiable ────────────────────────────────────────────────

    #[test]
    fn test_is_verifiable_true() {
        let record = TlsaRecord::new(
            TlsaUsage::DomainIssuedCertificate,
            TlsaSelector::FullCertificate,
            TlsaMatchingType::Sha256,
            vec![0; 32],
        );
        assert!(record.is_verifiable());
    }

    #[test]
    fn test_is_verifiable_wrong_usage() {
        let record = TlsaRecord::new(
            TlsaUsage::CaConstraint,
            TlsaSelector::FullCertificate,
            TlsaMatchingType::Sha256,
            vec![0; 32],
        );
        assert!(!record.is_verifiable());
    }

    #[test]
    fn test_is_verifiable_wrong_selector() {
        let record = TlsaRecord::new(
            TlsaUsage::DomainIssuedCertificate,
            TlsaSelector::SubjectPublicKeyInfo,
            TlsaMatchingType::Sha256,
            vec![0; 32],
        );
        assert!(!record.is_verifiable());
    }

    #[test]
    fn test_is_verifiable_wrong_matching_type() {
        let record = TlsaRecord::new(
            TlsaUsage::DomainIssuedCertificate,
            TlsaSelector::FullCertificate,
            TlsaMatchingType::Sha512,
            vec![0; 64],
        );
        assert!(!record.is_verifiable());
    }

    // ── matches_fingerprint edge cases ───────────────────────────────

    #[test]
    fn test_matches_fingerprint_non_dane_ee() {
        let hash = vec![0u8; 32];
        let record = TlsaRecord::new(
            TlsaUsage::CaConstraint,
            TlsaSelector::FullCertificate,
            TlsaMatchingType::Sha256,
            hash,
        );
        let fp = CertFingerprint::from_bytes([0u8; 32]);
        assert_eq!(record.matches_fingerprint(&fp), None);
    }

    #[test]
    fn test_matches_fingerprint_non_sha256() {
        let hash = vec![0u8; 64];
        let record = TlsaRecord::new(
            TlsaUsage::DomainIssuedCertificate,
            TlsaSelector::FullCertificate,
            TlsaMatchingType::Sha512,
            hash,
        );
        let fp = CertFingerprint::from_bytes([0u8; 32]);
        assert_eq!(record.matches_fingerprint(&fp), None);
    }

    // ── DaneVerificationResult::DnssecFailed ─────────────────────────

    #[test]
    fn test_dnssec_failed_is_not_acceptable() {
        let result = DaneVerificationResult::DnssecFailed;
        assert!(!result.is_acceptable(DanePolicy::Disabled));
        assert!(!result.is_acceptable(DanePolicy::ValidateIfPresent));
        assert!(!result.is_acceptable(DanePolicy::Required));
    }
}
