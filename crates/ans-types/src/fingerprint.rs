//! Certificate fingerprint computation and comparison.
//!
//! All fingerprint comparisons use constant-time equality to prevent
//! timing side-channel attacks that could leak fingerprint values.

use crate::error::CryptoError;
use sha2::{Digest, Sha256};
use std::fmt;
use subtle::ConstantTimeEq;

/// SHA-256 certificate fingerprint in `SHA256:<hex>` format.
///
/// Equality comparisons are constant-time to prevent timing side-channels.
#[derive(Clone)]
pub struct CertFingerprint {
    bytes: [u8; 32],
}

impl PartialEq for CertFingerprint {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl Eq for CertFingerprint {}

impl std::hash::Hash for CertFingerprint {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

impl CertFingerprint {
    /// Compute fingerprint from DER-encoded certificate.
    pub fn from_der(der: &[u8]) -> Self {
        let hash = Sha256::digest(der);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        Self { bytes }
    }

    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Parse from `SHA256:<hex>` string format.
    ///
    /// # Errors
    /// Returns `CryptoError::InvalidFingerprint` if the format is invalid.
    pub fn parse(s: &str) -> Result<Self, CryptoError> {
        // Handle both "SHA256:" and "sha256:" prefixes
        let hex_str = s
            .strip_prefix("SHA256:")
            .or_else(|| s.strip_prefix("sha256:"))
            .ok_or_else(|| CryptoError::InvalidFingerprint {
                fingerprint: s.to_string(),
            })?;

        let bytes = hex::decode(hex_str).map_err(|_| CryptoError::InvalidFingerprint {
            fingerprint: s.to_string(),
        })?;

        if bytes.len() != 32 {
            return Err(CryptoError::InvalidFingerprint {
                fingerprint: s.to_string(),
            });
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self { bytes: arr })
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Format as hex string without prefix.
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    /// Check if this fingerprint matches a string representation.
    pub fn matches(&self, other: &str) -> bool {
        match Self::parse(other) {
            Ok(parsed) => self == &parsed,
            Err(_) => false,
        }
    }
}

impl fmt::Display for CertFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SHA256:{}", hex::encode(self.bytes))
    }
}

impl fmt::Debug for CertFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CertFingerprint({self})")
    }
}

impl std::str::FromStr for CertFingerprint {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl serde::Serialize for CertFingerprint {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for CertFingerprint {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

impl TryFrom<&str> for CertFingerprint {
    type Error = CryptoError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::parse(s)
    }
}

impl TryFrom<String> for CertFingerprint {
    type Error = CryptoError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_from_der() {
        let der = b"test certificate data";
        let fp = CertFingerprint::from_der(der);
        assert_eq!(fp.as_bytes().len(), 32);
    }

    #[test]
    fn test_fingerprint_parse_uppercase() {
        let fp_str = "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";
        let fp = CertFingerprint::parse(fp_str).unwrap();
        assert_eq!(fp.to_string(), fp_str);
    }

    #[test]
    fn test_fingerprint_parse_lowercase() {
        let fp_str = "sha256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";
        let fp = CertFingerprint::parse(fp_str).unwrap();
        // Output is always uppercase prefix
        assert_eq!(
            fp.to_string(),
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
        );
    }

    #[test]
    fn test_fingerprint_roundtrip() {
        let original = "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";
        let fp = CertFingerprint::parse(original).unwrap();
        let formatted = fp.to_string();
        let reparsed = CertFingerprint::parse(&formatted).unwrap();
        assert_eq!(fp, reparsed);
    }

    #[test]
    fn test_fingerprint_matches() {
        let fp = CertFingerprint::parse(
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
        )
        .unwrap();

        assert!(
            fp.matches("SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904")
        );
        assert!(
            fp.matches("sha256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904")
        );
        assert!(
            !fp.matches("SHA256:0000000000000000000000000000000000000000000000000000000000000000")
        );
    }

    #[test]
    fn test_fingerprint_invalid_format() {
        assert!(CertFingerprint::parse("MD5:abc123").is_err());
        assert!(CertFingerprint::parse("SHA256:toolshort").is_err());
        assert!(CertFingerprint::parse("invalid").is_err());
        assert!(CertFingerprint::parse("SHA256:gggg").is_err()); // invalid hex
    }

    #[test]
    fn test_fingerprint_equality() {
        let fp1 = CertFingerprint::parse(
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
        )
        .unwrap();
        let fp2 = CertFingerprint::parse(
            "sha256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
        )
        .unwrap();
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_to_hex() {
        let fp = CertFingerprint::parse(
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
        )
        .unwrap();
        assert_eq!(
            fp.to_hex(),
            "e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
        );
    }

    #[test]
    fn test_from_bytes() {
        let bytes = [0xab_u8; 32];
        let fp = CertFingerprint::from_bytes(bytes);
        assert_eq!(fp.as_bytes(), &bytes);
    }

    #[test]
    fn test_debug_formatting() {
        let fp = CertFingerprint::from_bytes([0u8; 32]);
        let dbg = format!("{fp:?}");
        assert!(dbg.starts_with("CertFingerprint(SHA256:"));
    }

    #[test]
    fn test_from_str_trait() {
        let fp: CertFingerprint =
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
                .parse()
                .unwrap();
        assert_eq!(fp.as_bytes().len(), 32);
    }

    #[test]
    fn test_try_from_str() {
        let fp = CertFingerprint::try_from(
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
        )
        .unwrap();
        assert_eq!(fp.as_bytes().len(), 32);
    }

    #[test]
    fn test_try_from_string() {
        let fp = CertFingerprint::try_from(
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904".to_string(),
        )
        .unwrap();
        assert_eq!(fp.as_bytes().len(), 32);
    }

    #[test]
    fn test_serde_deserialization_error() {
        let result = serde_json::from_str::<CertFingerprint>(r#""MD5:abc""#);
        assert!(result.is_err());
    }

    #[test]
    fn test_matches_with_invalid_input() {
        let fp = CertFingerprint::from_bytes([0u8; 32]);
        assert!(!fp.matches("invalid-no-prefix"));
        assert!(!fp.matches(""));
    }

    #[test]
    fn test_hash_consistency() {
        use std::collections::HashSet;
        let fp1 = CertFingerprint::parse(
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
        )
        .unwrap();
        let fp2 = fp1.clone();
        let mut set = HashSet::new();
        set.insert(fp1);
        assert!(set.contains(&fp2));
    }

    #[test]
    fn test_serde_roundtrip() {
        let fp = CertFingerprint::parse(
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
        )
        .unwrap();
        let json = serde_json::to_string(&fp).unwrap();
        let deserialized: CertFingerprint = serde_json::from_str(&json).unwrap();
        assert_eq!(fp, deserialized);
    }
}
