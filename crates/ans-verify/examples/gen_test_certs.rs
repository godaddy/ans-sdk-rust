#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
//! Certificate Generation Utility for ANS Testing
//!
//! Generates a test PKI hierarchy for local ANS verification testing:
//! - CA certificate (simulates ANS Private CA)
//! - Server certificate (for TLS server identity)
//! - Client certificate (for mTLS client identity)
//!
//! Run with:
//! ```bash
//! cargo run --example gen_test_certs -- --output-dir ./test-certs
//! ```
//!
//! This will create:
//! - test-certs/ca.pem, test-certs/ca.key
//! - test-certs/server.pem, test-certs/server.key
//! - test-certs/client.pem, test-certs/client.key

use std::fs;
use std::path::PathBuf;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};

const DEFAULT_HOST: &str = "test.agent.local";
const DEFAULT_VERSION: &str = "v1.0.0";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let output_dir = if let Some(idx) = args.iter().position(|a| a == "--output-dir") {
        PathBuf::from(args.get(idx + 1).expect("Missing output directory"))
    } else {
        PathBuf::from("./test-certs")
    };

    let host = std::env::var("ANS_TEST_HOST").unwrap_or_else(|_| DEFAULT_HOST.to_string());
    let version = std::env::var("ANS_TEST_VERSION").unwrap_or_else(|_| DEFAULT_VERSION.to_string());

    println!("Generating test certificates...");
    println!("  Output directory: {}", output_dir.display());
    println!("  Host: {}", host);
    println!("  Version: {}", version);
    println!();

    // Create output directory
    fs::create_dir_all(&output_dir)?;

    // Generate CA
    println!("Generating CA certificate...");
    let (ca_cert, ca_params, ca_key) = generate_ca("ANS Test CA")?;
    let ca_cert_pem = ca_cert.pem();
    let ca_key_pem = ca_key.serialize_pem();

    fs::write(output_dir.join("ca.pem"), &ca_cert_pem)?;
    fs::write(output_dir.join("ca.key"), &ca_key_pem)?;
    println!("  Created: ca.pem, ca.key");

    // Generate Server Certificate
    println!("Generating server certificate...");
    let (server_cert_pem, server_key_pem, server_fingerprint) =
        generate_server_cert(&host, &version, &ca_params, &ca_key)?;

    fs::write(output_dir.join("server.pem"), &server_cert_pem)?;
    fs::write(output_dir.join("server.key"), &server_key_pem)?;
    println!("  Created: server.pem, server.key");
    println!("  Fingerprint: {}", server_fingerprint);

    // Generate Client Certificate
    println!("Generating client certificate...");
    let (client_cert_pem, client_key_pem, client_fingerprint) =
        generate_client_cert(&host, &version, &ca_params, &ca_key)?;

    fs::write(output_dir.join("client.pem"), &client_cert_pem)?;
    fs::write(output_dir.join("client.key"), &client_key_pem)?;
    println!("  Created: client.pem, client.key");
    println!("  Fingerprint: {}", client_fingerprint);

    // Write a summary file for use in tests
    let summary = format!(
        r#"# Test Certificate Summary
# Generated for ANS local testing

HOST={}
VERSION={}
ANS_NAME=ans://{}.{}

CA_FINGERPRINT={}
SERVER_FINGERPRINT={}
CLIENT_FINGERPRINT={}
"#,
        host,
        version,
        version,
        host,
        compute_fingerprint(ca_cert.der()),
        server_fingerprint,
        client_fingerprint
    );
    fs::write(output_dir.join("summary.txt"), summary)?;

    println!();
    println!("Certificate generation complete!");
    println!();
    println!("To use these certificates:");
    println!("  export ANS_TEST_CERTS_DIR={}", output_dir.display());
    println!("  cargo run --example local_mtls");

    Ok(())
}

fn generate_ca(cn: &str) -> Result<(rcgen::Certificate, CertificateParams, KeyPair), rcgen::Error> {
    let key_pair = KeyPair::generate()?;

    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, cn);
    params
        .distinguished_name
        .push(DnType::OrganizationName, "ANS Test");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    let cert = params.self_signed(&key_pair)?;
    Ok((cert, params, key_pair))
}

fn generate_server_cert(
    host: &str,
    version: &str,
    ca_params: &CertificateParams,
    ca_key: &KeyPair,
) -> Result<(String, String, String), rcgen::Error> {
    let key_pair = KeyPair::generate()?;

    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, host);
    params
        .distinguished_name
        .push(DnType::OrganizationName, "ANS Test");

    // DNS SAN for hostname
    params
        .subject_alt_names
        .push(SanType::DnsName(host.to_string().try_into().unwrap()));

    // URI SAN for ANS name
    let ans_name = format!("ans://{}.{}", version, host);
    params
        .subject_alt_names
        .push(SanType::URI(ans_name.try_into().unwrap()));

    // Server certificate key usage
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];

    let issuer = rcgen::Issuer::from_params(ca_params, ca_key);
    let cert = params.signed_by(&key_pair, &issuer)?;
    let fingerprint = compute_fingerprint(cert.der());

    Ok((cert.pem(), key_pair.serialize_pem(), fingerprint))
}

fn generate_client_cert(
    host: &str,
    version: &str,
    ca_params: &CertificateParams,
    ca_key: &KeyPair,
) -> Result<(String, String, String), rcgen::Error> {
    let key_pair = KeyPair::generate()?;

    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, host);
    params
        .distinguished_name
        .push(DnType::OrganizationName, "ANS Test");

    // DNS SAN for hostname
    params
        .subject_alt_names
        .push(SanType::DnsName(host.to_string().try_into().unwrap()));

    // URI SAN for ANS name (required for identity certificates)
    let ans_name = format!("ans://{}.{}", version, host);
    params
        .subject_alt_names
        .push(SanType::URI(ans_name.try_into().unwrap()));

    // Client certificate key usage
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];

    let issuer = rcgen::Issuer::from_params(ca_params, ca_key);
    let cert = params.signed_by(&key_pair, &issuer)?;
    let fingerprint = compute_fingerprint(cert.der());

    Ok((cert.pem(), key_pair.serialize_pem(), fingerprint))
}

fn compute_fingerprint(der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(der);
    format!("SHA256:{}", hex::encode(hash))
}
