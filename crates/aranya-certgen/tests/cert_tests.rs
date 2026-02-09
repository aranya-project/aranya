//! Integration tests for certificate generation.

#![allow(clippy::panic)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use aranya_certgen::{CaCert, CertGenError, CertPaths, SaveOptions};
use x509_parser::prelude::*;

#[test]
fn test_ca_cert_roundtrip() {
    let ca = CaCert::new("Test CA", 365).expect("should create CA");

    let dir = tempfile::tempdir().unwrap();
    let paths = CertPaths::new(dir.path().join("ca"));

    ca.save(&paths, SaveOptions::default())
        .expect("should save");
    let loaded = CaCert::load(&paths).expect("should load");

    assert_eq!(ca.cert_pem(), loaded.cert_pem());

    // Verify the files are named correctly
    assert!(paths.cert().exists());
    assert!(paths.key().exists());
}

#[test]
fn test_signed_cert_save() {
    let ca = CaCert::new("Test CA", 365).expect("should create CA");

    let cert = ca
        .generate("test-server", 365)
        .expect("should generate cert");

    let dir = tempfile::tempdir().unwrap();
    let paths = CertPaths::new(dir.path().join("server"));

    cert.save(&paths, SaveOptions::default())
        .expect("should save");

    // Verify the files are named correctly
    assert!(paths.cert().exists());
    assert!(paths.key().exists());
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
    let paths = CertPaths::new(dir.path().join("nonexistent").join("ca"));

    let result = ca.save(&paths, SaveOptions::default());

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
    let paths = CertPaths::new(dir.path().join("ca"));

    // Save once successfully
    ca.save(&paths, SaveOptions::default())
        .expect("first save should succeed");

    // Second save should fail because files exist
    let result = ca.save(&paths, SaveOptions::default());

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
    let paths = CertPaths::new(dir.path().join("a").join("b").join("c").join("ca"));

    // Should succeed with create_parents option
    ca.save(&paths, SaveOptions::default().create_parents())
        .expect("save with create_parents should succeed");

    assert!(paths.cert().exists());
    assert!(paths.key().exists());
}

#[test]
fn test_save_with_force() {
    let ca = CaCert::new("Test CA", 365).expect("should create CA");

    let dir = tempfile::tempdir().unwrap();
    let paths = CertPaths::new(dir.path().join("ca"));

    // Save once
    ca.save(&paths, SaveOptions::default())
        .expect("first save should succeed");

    // Second save with force should succeed
    ca.save(&paths, SaveOptions::default().force())
        .expect("save with force should succeed");
}

#[test]
fn test_hostname_cn_creates_dns_san() {
    let ca = CaCert::new("Test CA", 365).expect("should create CA");

    let cert = ca
        .generate("my-server.local", 365)
        .expect("should generate cert");

    // Parse the certificate and verify SANs
    let (_, pem) = parse_x509_pem(cert.cert_pem().as_bytes()).expect("should parse PEM");
    let x509_cert = pem.parse_x509().expect("should parse cert");

    // Get Subject Alternative Names extension
    let san_ext = x509_cert
        .get_extension_unique(&oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
        .expect("should have SAN extension")
        .expect("SAN extension should exist");

    let san = match san_ext.parsed_extension() {
        ParsedExtension::SubjectAlternativeName(san) => san,
        _ => panic!("expected SubjectAlternativeName"),
    };

    // Should have exactly one DNS SAN matching the CN
    assert_eq!(san.general_names.len(), 1);
    match &san.general_names[0] {
        GeneralName::DNSName(name) => assert_eq!(*name, "my-server.local"),
        other => panic!("expected DNSName, got {:?}", other),
    }
}

#[test]
fn test_ipv4_cn_creates_ip_san() {
    let ca = CaCert::new("Test CA", 365).expect("should create CA");

    let cert = ca
        .generate("127.0.0.1", 365)
        .expect("should generate cert with IPv4 CN");

    // Parse the certificate and verify SANs
    let (_, pem) = parse_x509_pem(cert.cert_pem().as_bytes()).expect("should parse PEM");
    let x509_cert = pem.parse_x509().expect("should parse cert");

    // Get Subject Alternative Names extension
    let san_ext = x509_cert
        .get_extension_unique(&oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
        .expect("should have SAN extension")
        .expect("SAN extension should exist");

    let san = match san_ext.parsed_extension() {
        ParsedExtension::SubjectAlternativeName(san) => san,
        _ => panic!("expected SubjectAlternativeName"),
    };

    // Should have exactly one IP SAN matching the CN
    assert_eq!(san.general_names.len(), 1);
    match &san.general_names[0] {
        GeneralName::IPAddress(bytes) => {
            assert_eq!(bytes.len(), 4);
            let arr: [u8; 4] = (*bytes).try_into().expect("should be 4 bytes");
            assert_eq!(
                IpAddr::V4(Ipv4Addr::from(arr)),
                "127.0.0.1".parse::<IpAddr>().unwrap()
            );
        }
        other => panic!("expected IPAddress, got {:?}", other),
    }
}

#[test]
fn test_ipv6_cn_creates_ip_san() {
    let ca = CaCert::new("Test CA", 365).expect("should create CA");

    let cert = ca
        .generate("::1", 365)
        .expect("should generate cert with IPv6 CN");

    // Parse the certificate and verify SANs
    let (_, pem) = parse_x509_pem(cert.cert_pem().as_bytes()).expect("should parse PEM");
    let x509_cert = pem.parse_x509().expect("should parse cert");

    // Get Subject Alternative Names extension
    let san_ext = x509_cert
        .get_extension_unique(&oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
        .expect("should have SAN extension")
        .expect("SAN extension should exist");

    let san = match san_ext.parsed_extension() {
        ParsedExtension::SubjectAlternativeName(san) => san,
        _ => panic!("expected SubjectAlternativeName"),
    };

    // Should have exactly one IP SAN matching the CN
    assert_eq!(san.general_names.len(), 1);
    match &san.general_names[0] {
        GeneralName::IPAddress(bytes) => {
            assert_eq!(bytes.len(), 16);
            let arr: [u8; 16] = (*bytes).try_into().expect("should be 16 bytes");
            assert_eq!(
                IpAddr::V6(Ipv6Addr::from(arr)),
                "::1".parse::<IpAddr>().unwrap()
            );
        }
        other => panic!("expected IPAddress, got {:?}", other),
    }
}
