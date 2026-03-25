//! SCITT (Supply Chain Integrity, Transparency, and Trust) verification.
//!
//! This module provides offline verification of agent identity via
//! SCITT receipts (Merkle inclusion proofs) and status tokens (signed
//! current-status claims). It is gated behind the `scitt` feature flag.
//!
//! # Architecture
//!
//! - **`error`**: [`ScittError`] enum covering all SCITT failure modes
//! - **`headers`**: [`ScittHeaders`] for extracting SCITT artifacts from HTTP headers
//!
//! # Feature flag
//!
//! All types in this module require `features = ["scitt"]` in `Cargo.toml`.
//! The lightweight data types ([`VerificationTier`], [`StatusTokenPayload`],
//! [`CertEntry`]) live in `ans-types` and are always available.

mod client;
mod cose;
mod error;
mod headers;
mod merkle;
mod receipt;
mod root_keys;
mod scitt_cache;
mod status_token;
mod supplier;

pub use client::{HttpScittClient, ScittClient};
pub use cose::{
    MAX_COSE_INPUT_SIZE, ParsedCoseSign1, ProtectedHeader, build_sig_structure,
    compute_sig_structure_digest, parse_cose_sign1,
};
pub use error::ScittError;
pub use headers::ScittHeaders;
pub use merkle::{compute_leaf_hash, verify_merkle_inclusion};
pub use receipt::{VerifiedReceipt, verify_receipt};
pub use root_keys::{ScittKeyStore, TrustedKey, parse_c2sp_key};
pub use scitt_cache::{ReceiptCache, StatusTokenCache};
pub use status_token::{
    VerifiedStatusToken, matches_identity_cert, matches_server_cert, verify_status_token,
};
pub use supplier::{ScittHeaderSupplier, ScittOutgoingHeaders, ScittRefreshHandle};

#[cfg(any(test, feature = "test-support"))]
pub use client::MockScittClient;
