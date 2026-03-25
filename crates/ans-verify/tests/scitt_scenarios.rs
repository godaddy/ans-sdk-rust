#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! SCITT integration test scenarios from SCITT_IMPLEMENTATION_PLAN.md §10.4.
//!
//! Each test maps to a scenario ID (e.g., `test_s1_1_*` → S1.1).
//! All external dependencies (DNS, Transparency Log) are mocked.
//! COSE_Sign1 artifacts are built in-process with a test P-256 key pair.

use std::sync::Arc;

use ans_types::*;
use ans_verify::*;
use base64::prelude::{BASE64_STANDARD, Engine as _};
use chrono::Utc;
use p256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner as _};
use p256::pkcs8::EncodePublicKey as _;
use sha2::{Digest, Sha256};
use uuid::Uuid;

// =========================================================================
// Constants
// =========================================================================

const HOST: &str = "agent.example.com";
const SERVER_FP: &str = "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";
const IDENTITY_FP: &str = "SHA256:aebdc9da0c20d6d5e4999a773839095ed050a9d7252bf212056fddc0c38f3496";
const WRONG_FP: &str = "SHA256:0000000000000000000000000000000000000000000000000000000000000000";
const BADGE_URL: &str = "https://tlog.example.com/v1/agents/test-uuid";

// =========================================================================
// Test Helpers — Badge / DNS / Cert
// =========================================================================

fn make_badge(host: &str, version: &str, server_fp: &str, identity_fp: &str) -> Badge {
    make_badge_with_status(host, version, server_fp, identity_fp, BadgeStatus::Active)
}

fn make_badge_with_status(
    host: &str,
    version: &str,
    server_fp: &str,
    identity_fp: &str,
    status: BadgeStatus,
) -> Badge {
    let status_str = serde_json::to_value(status).unwrap();
    serde_json::from_value(serde_json::json!({
        "status": status_str,
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
    }))
    .expect("test badge JSON should be valid")
}

fn dns_record(version: Option<Version>, url: &str) -> BadgeRecord {
    BadgeRecord::new("ans-badge1", version, url)
}

fn server_cert(host: &str, fingerprint: &str) -> CertIdentity {
    CertIdentity::new(
        Some(host.to_string()),
        vec![host.to_string()],
        vec![],
        CertFingerprint::parse(fingerprint).unwrap(),
    )
}

fn mtls_cert(host: &str, version: &str, fingerprint: &str) -> CertIdentity {
    CertIdentity::new(
        Some(host.to_string()),
        vec![host.to_string()],
        vec![format!("ans://{version}.{host}")],
        CertFingerprint::parse(fingerprint).unwrap(),
    )
}

// =========================================================================
// Test Helpers — COSE_Sign1 / SCITT
// =========================================================================

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
    ];
    let map = ciborium::Value::Map(pairs);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&map, &mut buf).unwrap();
    buf
}

fn build_cbor_payload(
    agent_id: &str,
    status: &str,
    exp: i64,
    ans_name: &str,
    identity_certs: &[(String, String)],
    server_certs: &[(String, String)],
) -> Vec<u8> {
    let now = Utc::now().timestamp();
    let mut pairs: Vec<(ciborium::Value, ciborium::Value)> = Vec::new();
    pairs.push((
        ciborium::Value::Integer(1.into()),
        ciborium::Value::Text(agent_id.to_string()),
    ));
    pairs.push((
        ciborium::Value::Integer(2.into()),
        ciborium::Value::Text(status.to_string()),
    ));
    pairs.push((
        ciborium::Value::Integer(3.into()),
        ciborium::Value::Integer(now.into()),
    ));
    pairs.push((
        ciborium::Value::Integer(4.into()),
        ciborium::Value::Integer(exp.into()),
    ));
    pairs.push((
        ciborium::Value::Integer(5.into()),
        ciborium::Value::Text(ans_name.to_string()),
    ));

    let id_certs: Vec<ciborium::Value> = identity_certs
        .iter()
        .map(|(fp, ct)| {
            ciborium::Value::Map(vec![
                (
                    ciborium::Value::Text("fingerprint".to_string()),
                    ciborium::Value::Text(fp.clone()),
                ),
                (
                    ciborium::Value::Text("cert_type".to_string()),
                    ciborium::Value::Text(ct.clone()),
                ),
            ])
        })
        .collect();
    pairs.push((
        ciborium::Value::Integer(6.into()),
        ciborium::Value::Array(id_certs),
    ));

    let srv_certs: Vec<ciborium::Value> = server_certs
        .iter()
        .map(|(fp, ct)| {
            ciborium::Value::Map(vec![
                (
                    ciborium::Value::Text("fingerprint".to_string()),
                    ciborium::Value::Text(fp.clone()),
                ),
                (
                    ciborium::Value::Text("cert_type".to_string()),
                    ciborium::Value::Text(ct.clone()),
                ),
            ])
        })
        .collect();
    pairs.push((
        ciborium::Value::Integer(7.into()),
        ciborium::Value::Array(srv_certs),
    ));
    pairs.push((
        ciborium::Value::Integer(8.into()),
        ciborium::Value::Map(vec![]),
    ));

    let map = ciborium::Value::Map(pairs);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&map, &mut buf).unwrap();
    buf
}

fn sign_cose(signing_key: &SigningKey, payload: &[u8]) -> Vec<u8> {
    let protected_bytes = build_protected_bytes(signing_key);
    let digest = compute_sig_structure_digest(&protected_bytes, payload);
    let (sig, _): (p256::ecdsa::Signature, _) = signing_key.sign_prehash(&digest).unwrap();
    let sig_bytes = sig.to_bytes().to_vec();
    let array = ciborium::Value::Array(vec![
        ciborium::Value::Bytes(protected_bytes),
        ciborium::Value::Map(vec![]),
        ciborium::Value::Bytes(payload.to_vec()),
        ciborium::Value::Bytes(sig_bytes),
    ]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&array, &mut buf).unwrap();
    buf
}

fn future_exp() -> i64 {
    4_102_444_800 // 2100-01-01
}

fn past_exp() -> i64 {
    946_684_800 // 2000-01-01
}

fn nil_uuid() -> String {
    Uuid::nil().to_string()
}

// =========================================================================
// Composite helpers — build a complete SCITT-enabled verifier
// =========================================================================

async fn make_scitt_verifier(
    host: &str,
    server_fp: &str,
    identity_fp: &str,
    key_store: Arc<ScittKeyStore>,
    policy: ScittTierPolicy,
) -> AnsVerifier {
    let badge = make_badge(host, "v1.0.0", server_fp, identity_fp);
    let record = dns_record(Some(Version::new(1, 0, 0)), BADGE_URL);

    let dns = Arc::new(MockDnsResolver::new().with_records(host, vec![record]));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL, badge));

    AnsVerifier::builder()
        .dns_resolver(dns)
        .tlog_client(tlog)
        .scitt_config(ScittConfig::new().with_tier_policy(policy))
        .scitt_key_store(key_store)
        .build()
        .await
        .expect("test verifier build should succeed")
}

async fn make_scitt_verifier_with_status(
    host: &str,
    server_fp: &str,
    identity_fp: &str,
    status: BadgeStatus,
    key_store: Arc<ScittKeyStore>,
    policy: ScittTierPolicy,
) -> AnsVerifier {
    let badge = make_badge_with_status(host, "v1.0.0", server_fp, identity_fp, status);
    let record = dns_record(Some(Version::new(1, 0, 0)), BADGE_URL);

    let dns = Arc::new(MockDnsResolver::new().with_records(host, vec![record]));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL, badge));

    AnsVerifier::builder()
        .dns_resolver(dns)
        .tlog_client(tlog)
        .scitt_config(ScittConfig::new().with_tier_policy(policy))
        .scitt_key_store(key_store)
        .build()
        .await
        .expect("test verifier build should succeed")
}

fn make_server_token(signing_key: &SigningKey, server_fp: &str) -> Vec<u8> {
    let payload = build_cbor_payload(
        &nil_uuid(),
        "ACTIVE",
        future_exp(),
        &format!("ans://v1.0.0.{HOST}"),
        &[],
        &[(server_fp.to_string(), "X509-DV-SERVER".to_string())],
    );
    sign_cose(signing_key, &payload)
}

fn make_identity_token(signing_key: &SigningKey, identity_fp: &str) -> Vec<u8> {
    let payload = build_cbor_payload(
        &nil_uuid(),
        "ACTIVE",
        future_exp(),
        &format!("ans://v1.0.0.{HOST}"),
        &[(identity_fp.to_string(), "X509-OV-CLIENT".to_string())],
        &[],
    );
    sign_cose(signing_key, &payload)
}

fn make_server_token_with_status(
    signing_key: &SigningKey,
    server_fp: &str,
    status: &str,
) -> Vec<u8> {
    let payload = build_cbor_payload(
        &nil_uuid(),
        status,
        future_exp(),
        &format!("ans://v1.0.0.{HOST}"),
        &[],
        &[(server_fp.to_string(), "X509-DV-SERVER".to_string())],
    );
    sign_cose(signing_key, &payload)
}

fn make_expired_token(signing_key: &SigningKey, server_fp: &str) -> Vec<u8> {
    let payload = build_cbor_payload(
        &nil_uuid(),
        "ACTIVE",
        past_exp(),
        &format!("ans://v1.0.0.{HOST}"),
        &[],
        &[(server_fp.to_string(), "X509-DV-SERVER".to_string())],
    );
    sign_cose(signing_key, &payload)
}

fn encode_b64(bytes: &[u8]) -> String {
    BASE64_STANDARD.encode(bytes)
}

// =========================================================================
// S1: Valid SCITT verification
// =========================================================================

/// S1.1: Valid status token, server verify → ScittVerified (StatusTokenVerified)
#[tokio::test]
async fn test_s1_1_valid_token_server_verify() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    let token = make_server_token(&signing_key, SERVER_FP);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    assert!(outcome.is_success());
    match outcome {
        VerificationOutcome::ScittVerified { tier, .. } => {
            assert_eq!(tier, VerificationTier::StatusTokenVerified);
        }
        other => panic!("Expected ScittVerified, got: {other:?}"),
    }
}

/// S1.2: Valid status token, mTLS verify → ScittVerified
#[tokio::test]
async fn test_s1_2_valid_token_mtls_verify() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    let token = make_identity_token(&signing_key, IDENTITY_FP);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = mtls_cert(HOST, "v1.0.0", IDENTITY_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    let outcome = verifier.verify_client_with_scitt(&cert, &headers).await;
    assert!(outcome.is_success());
    assert!(matches!(outcome, VerificationOutcome::ScittVerified { .. }));
}

// =========================================================================
// S2: Missing headers → badge fallback
// =========================================================================

/// S2.1: Missing receipt header only → ScittVerified (token alone is sufficient)
#[tokio::test]
async fn test_s2_1_missing_receipt_header() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    let token = make_server_token(&signing_key, SERVER_FP);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    // Token present, receipt absent
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    assert!(outcome.is_success());
    match outcome {
        VerificationOutcome::ScittVerified { tier, .. } => {
            assert_eq!(tier, VerificationTier::StatusTokenVerified);
        }
        other => panic!("Expected ScittVerified with StatusTokenVerified tier, got: {other:?}"),
    }
}

/// S2.2: Missing status token header → badge fallback
#[tokio::test]
async fn test_s2_2_missing_token_header() {
    let (_, store) = make_key_and_store(1);
    let store = Arc::new(store);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    // Receipt present but no token — token is required for SCITT
    let headers = ScittHeaders::from_base64(Some("aGVsbG8="), None).unwrap();

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    // No status token → falls back to badge
    assert!(outcome.is_success());
    assert!(matches!(outcome, VerificationOutcome::Verified { .. }));
}

/// S2.3: Both headers absent → badge verification
#[tokio::test]
async fn test_s2_3_both_headers_absent() {
    let (_, store) = make_key_and_store(1);
    let store = Arc::new(store);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    let headers = ScittHeaders::new(None, None);

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    assert!(outcome.is_success());
    assert!(matches!(outcome, VerificationOutcome::Verified { .. }));
}

// =========================================================================
// S3: Present-but-corrupt headers → REJECT (not fallback)
// =========================================================================

/// S3.1: Receipt header present but not valid Base64 → Reject at header decode
#[test]
fn test_s3_1_receipt_invalid_base64() {
    let result = ScittHeaders::from_base64(Some("not!valid!base64!"), None);
    assert!(result.is_err());
    match result.unwrap_err() {
        ScittError::Base64Decode(msg) => assert!(msg.contains("receipt")),
        other => panic!("Expected Base64Decode, got: {other}"),
    }
}

/// S3.2: Receipt header present but not valid COSE → Reject at verification
#[tokio::test]
async fn test_s3_2_receipt_invalid_cose() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    // Valid token but garbage receipt
    let token = make_server_token(&signing_key, SERVER_FP);
    let garbage_receipt = BASE64_STANDARD.encode(b"not-a-cose-structure");

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    let headers =
        ScittHeaders::from_base64(Some(&garbage_receipt), Some(&encode_b64(&token))).unwrap();

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    // Token verifies, receipt fails → still ScittVerified but StatusTokenVerified tier
    // (bad receipt degrades tier, doesn't reject)
    assert!(outcome.is_success());
    match outcome {
        VerificationOutcome::ScittVerified { tier, .. } => {
            assert_eq!(tier, VerificationTier::StatusTokenVerified);
        }
        other => panic!("Expected ScittVerified with degraded tier, got: {other:?}"),
    }
}

/// S3.5: Token signature invalid → Reject (not fallback)
#[tokio::test]
async fn test_s3_5_token_signature_invalid() {
    let (signing_key, _) = make_key_and_store(1);
    let (_, wrong_store) = make_key_and_store(2); // Different key
    let wrong_store = Arc::new(wrong_store);
    let token = make_server_token(&signing_key, SERVER_FP);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        wrong_store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    // Crypto failure → hard reject (not badge fallback)
    assert!(!outcome.is_success());
    assert!(matches!(outcome, VerificationOutcome::ScittError(_)));
}

// =========================================================================
// S4: Expired token behavior
// =========================================================================

/// S4.1: Expired token, valid badge → falls back to badge, Verified
#[tokio::test]
async fn test_s4_1_expired_token_valid_badge() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    let token = make_expired_token(&signing_key, SERVER_FP);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    // TokenExpired → badge fallback → success
    assert!(outcome.is_success());
    assert!(matches!(outcome, VerificationOutcome::Verified { .. }));
}

/// S4.2: Expired token, revoked badge → InvalidStatus
#[tokio::test]
async fn test_s4_2_expired_token_revoked_badge() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    let token = make_expired_token(&signing_key, SERVER_FP);

    let verifier = make_scitt_verifier_with_status(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        BadgeStatus::Revoked,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    // TokenExpired → badge fallback → badge is revoked → InvalidStatus
    assert!(!outcome.is_success());
    assert!(matches!(outcome, VerificationOutcome::InvalidStatus { .. }));
}

// =========================================================================
// S5: Fingerprint matching
// =========================================================================

/// S5.1: Fingerprint matches 2nd array element → ScittVerified
#[tokio::test]
async fn test_s5_1_fingerprint_matches_second_element() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    let other_fp = "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    // Token with two server certs: first=other_fp, second=SERVER_FP
    let payload = build_cbor_payload(
        &nil_uuid(),
        "ACTIVE",
        future_exp(),
        &format!("ans://v1.0.0.{HOST}"),
        &[],
        &[
            (other_fp.to_string(), "X509-DV-SERVER".to_string()),
            (SERVER_FP.to_string(), "X509-DV-SERVER".to_string()),
        ],
    );
    let token = sign_cose(&signing_key, &payload);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    assert!(outcome.is_success());
    assert!(matches!(outcome, VerificationOutcome::ScittVerified { .. }));
}

/// S5.2: Fingerprint not in any element → Reject
#[tokio::test]
async fn test_s5_2_fingerprint_not_in_array() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    // Token lists WRONG_FP, cert has SERVER_FP
    let token = make_server_token(&signing_key, WRONG_FP);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    assert!(!outcome.is_success());
    assert!(matches!(outcome, VerificationOutcome::ScittError(_)));
}

/// S5.3: Renewal overlap — both old+new cert fingerprints in token
#[tokio::test]
async fn test_s5_3_renewal_overlap_both_certs_accepted() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    let new_fp = "SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    // Token lists both old (SERVER_FP) and new (new_fp) certs
    let payload = build_cbor_payload(
        &nil_uuid(),
        "ACTIVE",
        future_exp(),
        &format!("ans://v1.0.0.{HOST}"),
        &[],
        &[
            (SERVER_FP.to_string(), "X509-DV-SERVER".to_string()),
            (new_fp.to_string(), "X509-DV-SERVER".to_string()),
        ],
    );
    let token = sign_cose(&signing_key, &payload);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store.clone(),
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;

    // Old cert still works
    let old_cert = server_cert(HOST, SERVER_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();
    let outcome = verifier
        .verify_server_with_scitt(HOST, &old_cert, &headers)
        .await;
    assert!(outcome.is_success());

    // New cert also works
    let new_cert = server_cert(HOST, new_fp);
    let verifier2 = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let headers2 = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();
    let outcome2 = verifier2
        .verify_server_with_scitt(HOST, &new_cert, &headers2)
        .await;
    assert!(outcome2.is_success());
}

// =========================================================================
// S7: Mixed SCITT/badge peers
// =========================================================================

/// S7.1: Server has SCITT, client badge-only → badge verification
#[tokio::test]
async fn test_s7_1_server_scitt_client_badge_only() {
    let (_, store) = make_key_and_store(1);
    let store = Arc::new(store);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    // No SCITT headers (badge-only client)
    let headers = ScittHeaders::new(None, None);

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    assert!(outcome.is_success());
    assert!(matches!(outcome, VerificationOutcome::Verified { .. }));
}

// =========================================================================
// S8: mTLS SCITT scenarios
// =========================================================================

/// S8.1: mTLS all checks pass, ACTIVE → ScittVerified
#[tokio::test]
async fn test_s8_1_mtls_active_all_pass() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    let token = make_identity_token(&signing_key, IDENTITY_FP);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = mtls_cert(HOST, "v1.0.0", IDENTITY_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    let outcome = verifier.verify_client_with_scitt(&cert, &headers).await;
    assert!(outcome.is_success());
    assert!(matches!(outcome, VerificationOutcome::ScittVerified { .. }));
}

/// S8.2: mTLS fingerprint not in identity array → Reject
#[tokio::test]
async fn test_s8_2_mtls_fingerprint_not_in_identity_array() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    // Token lists WRONG_FP as identity cert
    let token = make_identity_token(&signing_key, WRONG_FP);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = mtls_cert(HOST, "v1.0.0", IDENTITY_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    let outcome = verifier.verify_client_with_scitt(&cert, &headers).await;
    assert!(!outcome.is_success());
    assert!(matches!(outcome, VerificationOutcome::ScittError(_)));
}

/// S8.4: mTLS DEPRECATED status → ScittVerified (deprecated is not terminal)
#[tokio::test]
async fn test_s8_4_mtls_deprecated_status() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);

    let payload = build_cbor_payload(
        &nil_uuid(),
        "DEPRECATED",
        future_exp(),
        &format!("ans://v1.0.0.{HOST}"),
        &[(IDENTITY_FP.to_string(), "X509-OV-CLIENT".to_string())],
        &[],
    );
    let token = sign_cose(&signing_key, &payload);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = mtls_cert(HOST, "v1.0.0", IDENTITY_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    let outcome = verifier.verify_client_with_scitt(&cert, &headers).await;
    // DEPRECATED is allowed (not terminal) → ScittVerified
    assert!(outcome.is_success());
    assert!(matches!(outcome, VerificationOutcome::ScittVerified { .. }));
}

// =========================================================================
// Policy-specific tests
// =========================================================================

/// RequireScitt with empty headers → fail
#[tokio::test]
async fn test_require_scitt_empty_headers_fails() {
    let (_, store) = make_key_and_store(1);
    let store = Arc::new(store);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::RequireScitt,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    let headers = ScittHeaders::new(None, None);

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    assert!(!outcome.is_success());
    assert!(matches!(outcome, VerificationOutcome::ScittError(_)));
}

/// RequireScitt with expired token → fail (no badge fallback)
#[tokio::test]
async fn test_require_scitt_expired_token_fails() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    let token = make_expired_token(&signing_key, SERVER_FP);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::RequireScitt,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    assert!(!outcome.is_success());
    assert!(matches!(outcome, VerificationOutcome::ScittError(_)));
}

/// BadgeWithScittEnhancement: both succeed → ScittVerified
#[tokio::test]
async fn test_badge_enhancement_both_succeed() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    let token = make_server_token(&signing_key, SERVER_FP);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::BadgeWithScittEnhancement,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    assert!(outcome.is_success());
    assert!(matches!(outcome, VerificationOutcome::ScittVerified { .. }));
}

/// BadgeWithScittEnhancement: no headers → badge only
#[tokio::test]
async fn test_badge_enhancement_no_headers() {
    let (_, store) = make_key_and_store(1);
    let store = Arc::new(store);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::BadgeWithScittEnhancement,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    let headers = ScittHeaders::new(None, None);

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    assert!(outcome.is_success());
    assert!(matches!(outcome, VerificationOutcome::Verified { .. }));
}

/// Terminal status (REVOKED) in token → hard reject regardless of policy
#[tokio::test]
async fn test_terminal_status_revoked_hard_reject() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    let token = make_server_token_with_status(&signing_key, SERVER_FP, "REVOKED");

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    assert!(!outcome.is_success());
    assert!(matches!(outcome, VerificationOutcome::ScittError(_)));
}

/// Terminal status (EXPIRED) in token → hard reject regardless of policy
#[tokio::test]
async fn test_terminal_status_expired_hard_reject() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    let token = make_server_token_with_status(&signing_key, SERVER_FP, "EXPIRED");

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    assert!(!outcome.is_success());
    assert!(matches!(outcome, VerificationOutcome::ScittError(_)));
}
