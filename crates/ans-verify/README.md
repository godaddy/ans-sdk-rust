# ans-verify

Trust verification library for the Agent Name Service (ANS).

## Overview

This crate implements the ANS trust verification flow, combining DNS lookups, transparency log badge retrieval, and certificate fingerprint comparison to verify agent identities.

## Quick Start

```rust
use ans_verify::{AnsVerifier, CertIdentity, CertFingerprint, VerificationOutcome};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let verifier = AnsVerifier::builder()
        .with_caching()
        .build()
        .await?;

    // Server verification (client-side)
    // After TLS handshake, construct CertIdentity from the server certificate
    let server_cert = CertIdentity::from_der(&cert_der_bytes)?;
    let outcome = verifier.verify_server("agent.example.com", &server_cert).await;
    if outcome.is_success() {
        println!("Server verified");
    }

    // Client verification (server-side mTLS)
    let client_cert = CertIdentity::from_der(&client_cert_der)?;
    let outcome = verifier.verify_client(&client_cert).await;

    Ok(())
}
```

## Verification Flow

### Server Verification

When connecting to an ANS agent server:

1. DNS lookup `_ans-badge.{fqdn}` (fallback: `_ra-badge`) for the transparency log URL
2. Fetch badge from transparency log API
3. Validate badge status (Active, Warning, Deprecated allowed)
4. Compare server certificate fingerprint to badge attestation
5. Compare certificate CN to badge agent host
6. Optional: DANE/TLSA verification

### Client Verification (mTLS)

When accepting mTLS connections from ANS agent clients:

1. Extract FQDN from certificate CN, version from URI SAN
2. DNS lookup by FQDN, match badge to certificate version
3. Compare identity certificate fingerprint to badge attestation
4. Compare ANS name from URI SAN to badge

## Configuration

### DNS Presets

```rust
use ans_verify::AnsVerifier;

let verifier = AnsVerifier::builder()
    .dns_cloudflare()  // or .dns_google(), .dns_quad9()
    .build()
    .await?;
```

### Failure Policies

| Policy | Behavior |
|---|---|
| `FailClosed` | Reject on any error (default) |
| `FailOpenWithCache` | Allow if a cached badge exists within max staleness |

### DANE/TLSA

```rust
use ans_verify::ServerVerifier;

let verifier = ServerVerifier::builder()
    .with_dane_if_present()  // verify TLSA if records exist
    // or .require_dane()    // fail if no TLSA records
    .dane_port(8443)         // custom port (default: 443)
    .build()
    .await?;
```

### Badge Caching

```rust
let verifier = AnsVerifier::builder()
    .with_caching()   // enable Moka-based TTL cache
    .build()
    .await?;
```

### Trusted RA Domains

Restrict badge URL fetches to known transparency log hosts. This prevents DNS-based redirections to attacker-controlled servers:

```rust
let verifier = ServerVerifier::builder()
    .trusted_ra_domains(["tlog.example.com", "tlog2.example.com"])
    .build()
    .await?;
```

When configured, badge URLs discovered via DNS TXT records are validated before any HTTP request is made. URLs pointing to hosts not in the set are rejected with `TlogError::UntrustedDomain`. By default (`None`), all domains are allowed.

## Traits

Implement these traits for custom backends:

### `DnsResolver`

```rust
#[async_trait]
pub trait DnsResolver: Send + Sync {
    async fn lookup_badge(&self, fqdn: &Fqdn) -> Result<DnsLookupResult<BadgeRecord>, DnsError>;
    async fn lookup_tlsa(&self, fqdn: &Fqdn, port: u16) -> Result<DnsLookupResult<TlsaRecord>, DnsError>;
    // Default methods: get_badge_records(), find_badge_for_version()
}
```

### `TransparencyLogClient`

```rust
#[async_trait]
pub trait TransparencyLogClient: Send + Sync {
    async fn fetch_badge(&self, url: &str) -> Result<Badge, TlogError>;
    async fn fetch_badge_by_id(&self, agent_id: Uuid) -> Result<Badge, TlogError>;
    async fn fetch_audit(&self, agent_id: Uuid, limit: Option<u32>, offset: Option<u32>)
        -> Result<AuditResponse, TlogError>;
}
```

## Testing

Mock implementations are provided behind the `test-support` feature flag:

```toml
[dev-dependencies]
ans-verify = { ..., features = ["test-support"] }
```

```rust
use ans_verify::{MockDnsResolver, MockTransparencyLogClient};

let dns = Arc::new(MockDnsResolver::new()
    .with_records("agent.example.com", vec![badge_record]));

let tlog = Arc::new(MockTransparencyLogClient::new()
    .with_badge("https://tlog.example.com/badge", badge));

let verifier = ServerVerifier::builder()
    .dns_resolver(dns)
    .tlog_client(tlog)
    .build()
    .await?;
```

## Feature Flags

| Feature | Description |
|---|---|
| `rustls` | Enables `AnsServerCertVerifier` and `AnsClientCertVerifier` for rustls TLS integration |
| `test-support` | Exposes `MockDnsResolver` and `MockTransparencyLogClient` for use in downstream integration tests |

## License

MIT
