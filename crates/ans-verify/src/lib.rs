#![warn(missing_docs)]

//! # ANS Trust Verification Library
//!
//! This library implements the ANS (Agent Name Service) Trust Verification Flow,
//! providing tools for verifying agent identity and trust status.
//!
//! ## Overview
//!
//! The ANS architecture uses a dual-certificate model:
//! - **Public Server Certificate**: Issued by a public CA (e.g., Let's Encrypt)
//! - **Private Identity Certificate**: Issued by the ANS Private CA
//!
//! Verification relies on:
//! - DNS `_ans-badge` TXT records pointing to the transparency log (with `_ra-badge` fallback)
//! - Transparency Log API returning badges with status and certificate fingerprints
//! - Certificate fingerprint comparison
//! - Optional DANE/TLSA verification for additional DNS-based certificate binding
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use ans_verify::{AnsVerifier, VerificationOutcome, CertIdentity};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let verifier = AnsVerifier::new().await?;
//!
//!     // After TLS handshake, extract server certificate and verify
//!     let cert_der: &[u8] = &[]; // Your certificate bytes
//!     let cert_identity = CertIdentity::from_der(cert_der)?;
//!
//!     let outcome = verifier
//!         .verify_server("agent.example.com", &cert_identity)
//!         .await;
//!
//!     match outcome {
//!         VerificationOutcome::Verified { badge, .. } => {
//!             println!("Verified ANS agent: {}", badge.agent_name());
//!         }
//!         VerificationOutcome::NotAnsAgent { fqdn } => {
//!             println!("Not a registered ANS agent: {}", fqdn);
//!         }
//!         _ => println!("Verification failed"),
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Features
//!
//! - DNS-based badge discovery via `_ans-badge` TXT records (with `_ra-badge` fallback)
//! - Transparency Log API integration for badge retrieval
//! - Certificate fingerprint verification (SHA-256)
//! - Optional DANE/TLSA verification with configurable policies
//! - DNSSEC validation support
//! - Configurable DNS resolvers (System, Cloudflare, Google, Quad9)
//! - Response caching with configurable TTL
//! - Async-first design with tokio
//! - Optional rustls integration for TLS handshake verification

mod cache;
mod dane;
mod dns;
mod error;
mod tlog;
mod verify;

#[cfg(feature = "rustls")]
mod rustls_verifier;

#[cfg(feature = "scitt")]
mod scitt;

// Re-export types from ans-types for convenience
pub use ans_types::{
    AgentEvent, AgentInfo, AnsName, Attestations, Badge, BadgePayload, BadgeStatus,
    CertAttestation, CertFingerprint, CryptoError, EventType, Fqdn, MerkleProof, ParseError,
    Producer, Version,
};

// Re-export from this crate
pub use cache::{BadgeCache, CacheConfig, CacheKey, CachedBadge};
pub use dane::{
    DanePolicy, DaneVerificationResult, TlsaMatchingType, TlsaRecord, TlsaSelector, TlsaUsage,
};
#[cfg(any(test, feature = "test-support"))]
pub use dns::MockDnsResolver;
pub use dns::{BadgeRecord, DnsResolver, DnsResolverConfig, HickoryDnsResolver};
pub use error::{
    AnsError, AnsResult, DaneError, DnsError, HttpError, TlogError, VerificationError,
};
#[cfg(any(test, feature = "test-support"))]
pub use tlog::MockTransparencyLogClient;
pub use tlog::{AuditResponse, HttpTransparencyLogClient, TransparencyLogClient};
pub use verify::{
    AnsVerifier, AnsVerifierBuilder, CertIdentity, ClientVerifier, FailurePolicy, ServerVerifier,
    VerificationOutcome,
};

#[cfg(feature = "scitt")]
pub use verify::{ScittConfig, ScittTierPolicy};

#[cfg(feature = "rustls")]
pub use rustls_verifier::{AnsClientCertVerifier, AnsServerCertVerifier};

#[cfg(feature = "scitt")]
pub use scitt::{
    HttpScittClient, MAX_COSE_INPUT_SIZE, ParsedCoseSign1, ProtectedHeader, ReceiptCache,
    ScittClient, ScittError, ScittHeaderSupplier, ScittHeaders, ScittKeyStore,
    ScittOutgoingHeaders, ScittRefreshHandle, StatusTokenCache, TrustedKey, VerifiedReceipt,
    VerifiedStatusToken, build_sig_structure, compute_leaf_hash, compute_sig_structure_digest,
    matches_identity_cert, matches_server_cert, parse_c2sp_key, parse_cose_sign1,
    verify_merkle_inclusion, verify_receipt, verify_status_token,
};

#[cfg(all(feature = "scitt", any(test, feature = "test-support")))]
pub use scitt::MockScittClient;
