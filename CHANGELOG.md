# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - Unreleased

### Added

- **ans-types**: Shared domain types — `Fqdn`, `AnsName`, `Version`, `Badge`, `CertFingerprint`
- **ans-verify**: Trust verification with DNS and transparency log integration
  - `ServerVerifier` for client-side TLS verification
  - `ClientVerifier` for server-side mTLS verification
  - `AnsVerifier` high-level facade combining both
  - `HickoryDnsResolver` for `_ans-badge` / `_ra-badge` TXT record lookup
  - `HttpTransparencyLogClient` for badge API access
  - `BadgeCache` with TTL-based caching via moka
  - DANE/TLSA verification support
  - rustls integration (`AnsServerCertVerifier`, `AnsClientCertVerifier`) behind `rustls` feature flag
  - Mock implementations behind `test-support` feature flag
- **ans-client**: ANS Registry API client
  - Agent registration, discovery, and resolution
  - Certificate management (server and identity CSRs)
  - Agent revocation with RFC 5280 reason codes
  - Event pagination for Agent Host Providers
  - JWT and API key authentication with `secrecy::SecretString`
  - HTTPS-only enforcement by default (`.allow_insecure()` opt-out)

### Security

- All public types annotated with `#[non_exhaustive]` for semver-safe evolution
- Authentication secrets wrapped in `secrecy::SecretString` (zeroized on drop)
- `reqwest` types hidden behind SDK-owned wrappers to decouple semver
- `unsafe_code` forbidden at workspace level
- Panic-prevention lints (`unwrap_used`, `expect_used`, `panic`) denied in production code
- Constant-time certificate fingerprint comparison via `subtle::ConstantTimeEq`
- HTTPS enforced on `AnsClientBuilder` base URL by default
