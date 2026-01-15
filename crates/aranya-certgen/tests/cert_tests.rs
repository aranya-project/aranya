//! Integration tests for certificate generation.

use aranya_certgen::{CaCert, CertGenError, SaveOptions};
use x509_parser::prelude::*;

#[test]
fn test_ca_cert_roundtrip() {
    let ca = CaCert::new("Test CA", 365).expect("should create CA");

    let dir = tempfile::tempdir().unwrap();

    ca.save(dir.path(), "ca", None).expect("should save");
    let loaded = CaCert::load(dir.path(), "ca").expect("should load");

    assert_eq!(ca.cert_pem(), loaded.cert_pem());

    // Verify the files are named correctly
    assert!(dir.path().join("ca.crt.pem").exists());
    assert!(dir.path().join("ca.key.pem").exists());
}

#[test]
fn test_signed_cert_save() {
    let ca = CaCert::new("Test CA", 365).expect("should create CA");

    let cert = ca
        .generate("test-server", 365)
        .expect("should generate cert");

    let dir = tempfile::tempdir().unwrap();

    cert.save(dir.path(), "server", None).expect("should save");

    // Verify the files are named correctly
    assert!(dir.path().join("server.crt.pem").exists());
    assert!(dir.path().join("server.key.pem").exists());
}

#[test]
fn test_multiple_certs_are_unique() {
    let ca = CaCert::new("Test CA", 365).expect("should create CA");

    let cert1 = ca
        .generate("server-1", 365)
        .expect("should generate cert 1");
    let cert2 = ca
        .generate("server-2", 365)
        .expect("should generate cert 2");

    // Each generated cert should be unique
    assert_ne!(cert1.cert_pem(), cert2.cert_pem());
}

#[test]
fn test_cert_signed_by_ca() {
    let ca = CaCert::new("Test CA", 365).expect("should create CA");

    let cert = ca
        .generate("test-server", 365)
        .expect("should generate cert");

    // Parse the CA certificate to get its public key
    let (_, ca_pem) = parse_x509_pem(ca.cert_pem().as_bytes()).expect("should parse CA PEM");
    let ca_cert = ca_pem.parse_x509().expect("should parse CA cert");

    // Parse the signed certificate
    let (_, signed_pem) =
        parse_x509_pem(cert.cert_pem().as_bytes()).expect("should parse signed PEM");
    let signed_cert = signed_pem.parse_x509().expect("should parse signed cert");

    // Verify the signed certificate's signature using the CA's public key
    signed_cert
        .verify_signature(Some(ca_cert.public_key()))
        .expect("certificate should be signed by CA");
}

#[test]
fn test_save_fails_if_dir_not_exists() {
    let ca = CaCert::new("Test CA", 365).expect("should create CA");

    let dir = tempfile::tempdir().unwrap();
    let nonexistent = dir.path().join("nonexistent");

    let result = ca.save(&nonexistent, "ca", None);

    assert!(
        matches!(result, Err(CertGenError::DirNotFound(_))),
        "expected DirNotFound error, got {:?}",
        result
    );
}

#[test]
fn test_save_fails_if_file_exists() {
    let ca = CaCert::new("Test CA", 365).expect("should create CA");

    let dir = tempfile::tempdir().unwrap();

    // Save once successfully
    ca.save(dir.path(), "ca", None)
        .expect("first save should succeed");

    // Second save should fail because files exist
    let result = ca.save(dir.path(), "ca", None);

    assert!(
        matches!(result, Err(CertGenError::FileExists(_))),
        "expected FileExists error, got {:?}",
        result
    );
}

#[test]
fn test_save_with_create_parents() {
    let ca = CaCert::new("Test CA", 365).expect("should create CA");

    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("a").join("b").join("c");

    // Should succeed with create_parents option
    ca.save(&nested, "ca", Some(SaveOptions::default().create_parents()))
        .expect("save with create_parents should succeed");

    assert!(nested.join("ca.crt.pem").exists());
    assert!(nested.join("ca.key.pem").exists());
}

#[test]
fn test_save_with_force() {
    let ca = CaCert::new("Test CA", 365).expect("should create CA");

    let dir = tempfile::tempdir().unwrap();

    // Save once
    ca.save(dir.path(), "ca", None)
        .expect("first save should succeed");

    // Second save with force should succeed
    ca.save(dir.path(), "ca", Some(SaveOptions::default().force()))
        .expect("save with force should succeed");
}
