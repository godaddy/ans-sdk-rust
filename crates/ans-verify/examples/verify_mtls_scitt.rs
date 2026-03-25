#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
//! Example: SCITT-enhanced mTLS client verification
//!
//! Demonstrates verifying a client's identity certificate during mTLS
//! using SCITT status tokens for offline-capable trust verification.
//!
//! ```bash
//! RUST_LOG=ans_verify=debug cargo run -p ans-verify --features scitt --example verify_mtls_scitt
//! ```

use std::sync::Arc;

use ans_verify::{
    AnsVerifier, CertFingerprint, CertIdentity, ScittConfig, ScittHeaders, ScittKeyStore,
    ScittTierPolicy, VerificationOutcome,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ans_verify=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // 1. Configure SCITT root keys
    let key_store = Arc::new(ScittKeyStore::from_c2sp_keys(&[]).unwrap_or_else(|e| {
        panic!("Failed to create key store: {e}");
    }));

    // 2. Build verifier with SCITT (RequireScitt policy for strict environments)
    let verifier = AnsVerifier::builder()
        .dns_google()
        .with_caching()
        .scitt_config(ScittConfig::new().with_tier_policy(ScittTierPolicy::RequireScitt))
        .scitt_key_store(key_store)
        .build()
        .await?;

    // 3. Simulate client certificate from mTLS handshake
    //    The client cert has a CN with the FQDN and a URI SAN with the ANS name.
    let client_fqdn = "agent.example.com";
    let client_cert = CertIdentity::new(
        Some(client_fqdn.to_string()),
        vec![client_fqdn.to_string()],
        vec![format!("ans://v1.0.0.{client_fqdn}")],
        CertFingerprint::parse(
            "SHA256:AEBDC9DA0C20D6D5E4999A773839095ED050A9D7252BF212056FDDC0C38F3496",
        )?,
    );

    // 4. Simulate SCITT headers from the HTTP request
    //    In production, extract from the client's HTTP request headers.
    let headers = ScittHeaders::new(None, None);

    println!("Verifying mTLS client with SCITT: {client_fqdn}");
    let outcome = verifier
        .verify_client_with_scitt(&client_cert, &headers)
        .await;

    match outcome {
        VerificationOutcome::ScittVerified {
            tier,
            status_token,
            badge,
            ..
        } => {
            println!("SCITT Verified (tier: {tier:?})");
            println!("  Status: {:?}", status_token.payload.status);
            if let Some(b) = badge {
                println!("  Badge: {} ({})", b.agent_name(), b.agent_host());
            }
        }
        VerificationOutcome::Verified { badge, .. } => {
            println!(
                "Badge-only verified: {} ({})",
                badge.agent_name(),
                badge.agent_host()
            );
        }
        VerificationOutcome::ScittError(e) => {
            println!("SCITT verification failed: {e}");
            println!("  (RequireScitt policy: no badge fallback)");
        }
        other => {
            println!("Verification result: {other:?}");
        }
    }

    Ok(())
}
