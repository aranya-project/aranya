//! Certificate types for CA and signed certificates.

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, DnValue, ExtendedKeyUsagePurpose,
    IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use time::{Duration, OffsetDateTime};

use crate::error::CertGenError;

/// Options for saving certificates to disk.
#[derive(Debug, Clone, Default)]
pub struct SaveOptions {
    /// Create parent directories if they don't exist.
    pub create_parents: bool,
    /// Overwrite existing files.
    pub force: bool,
}

impl SaveOptions {
    /// Enable creating parent directories if they don't exist.
    pub fn create_parents(mut self) -> Self {
        self.create_parents = true;
        self
    }

    /// Enable overwriting existing files.
    pub fn force(mut self) -> Self {
        self.force = true;
        self
    }
}

/// A Certificate Authority (CA) certificate that can sign other certificates.
///
/// `CaCert` holds a CA certificate and its private key, and can generate
/// signed certificates. All generated keys use P-256 ECDSA.
///
/// # Example
///
/// ```no_run
/// use aranya_certgen::CaCert;
///
/// // Create a new CA and save
/// let ca = CaCert::new("My CA", 365).unwrap();
/// ca.save("ca", None).unwrap();  // Creates ./ca.crt.pem and ./ca.key.pem
///
/// // Generate a signed certificate
/// let signed = ca.generate("my-server", 365).unwrap();
/// signed.save("server", None).unwrap();  // Creates ./server.crt.pem and ./server.key.pem
/// ```
pub struct CaCert {
    cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

impl CaCert {
    /// Creates a new Certificate Authority (CA) with a self-signed certificate.
    ///
    /// Generates a new P-256 ECDSA key pair and creates a self-signed CA certificate
    /// that can be used to sign other certificates.
    ///
    /// # Arguments
    ///
    /// * `cn` - The Common Name (CN) for the CA certificate.
    /// * `days` - The validity period in days from now.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `days` is 0 ([`CertGenError::InvalidDays`])
    /// - Key generation or certificate signing fails ([`CertGenError::Generate`])
    ///
    /// # Example
    ///
    /// ```no_run
    /// use aranya_certgen::CaCert;
    ///
    /// let ca = CaCert::new("My Root CA", 365)?;
    /// ca.save("ca", None)?;
    /// # Ok::<(), aranya_certgen::CertGenError>(())
    /// ```
    pub fn new(cn: &str, days: u32) -> Result<Self, CertGenError> {
        if days == 0 {
            return Err(CertGenError::InvalidDays);
        }
        let (cert, key) = generate_root_ca(cn, days)?;
        let cert_pem = cert.pem();
        let issuer = Issuer::from_ca_cert_pem(&cert_pem, key)?;

        Ok(Self { cert_pem, issuer })
    }

    /// Generates a leaf certificate signed by this CA.
    ///
    /// Creates a new P-256 ECDSA key pair and generates a certificate signed by
    /// this CA. The resulting certificate cannot sign other certificates.
    ///
    /// # Arguments
    ///
    /// * `cn` - The Common Name (CN) for the certificate.
    /// * `days` - The validity period in days from now. Must be greater than 0.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `days` is 0 ([`CertGenError::InvalidDays`])
    /// - Key generation or certificate signing fails ([`CertGenError::Generate`])
    ///
    /// # Example
    ///
    /// ```no_run
    /// use aranya_certgen::CaCert;
    ///
    /// let ca = CaCert::new("My CA", 365)?;
    /// let signed = ca.generate("server", 365)?;
    /// signed.save("server", None)?;
    /// # Ok::<(), aranya_certgen::CertGenError>(())
    /// ```
    pub fn generate(&self, cn: &str, days: u32) -> Result<SignedCert, CertGenError> {
        if days == 0 {
            return Err(CertGenError::InvalidDays);
        }
        let (cert, key) = generate_signed_cert(cn, &self.issuer, days)?;
        let cert_pem = cert.pem();

        Ok(SignedCert { cert_pem, key })
    }

    /// Loads a CA certificate and private key from PEM files.
    ///
    /// # Arguments
    ///
    /// * `path` - Path prefix for the certificate and key files.
    ///   - `"ca"` → loads `./ca.crt.pem` and `./ca.key.pem`
    ///   - `"./certs/ca"` → loads `./certs/ca.crt.pem` and `./certs/ca.key.pem`
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The files cannot be read ([`CertGenError::Io`])
    /// - The certificate cannot be parsed ([`CertGenError::ParseCert`])
    /// - The private key cannot be parsed ([`CertGenError::ParseKey`])
    ///
    /// # Example
    ///
    /// ```no_run
    /// use aranya_certgen::CaCert;
    ///
    /// let ca = CaCert::load("ca")?;
    /// let ca = CaCert::load("./certs/myca")?;
    /// # Ok::<(), aranya_certgen::CertGenError>(())
    /// ```
    pub fn load(path: &str) -> Result<Self, CertGenError> {
        let path = Path::new(path);
        let cert_path = path.with_extension("crt.pem");
        let key_path = path.with_extension("key.pem");

        let cert_pem =
            fs::read_to_string(&cert_path).map_err(|e| CertGenError::io(&cert_path, e))?;
        let key_pem = fs::read_to_string(&key_path).map_err(|e| CertGenError::io(&key_path, e))?;

        let key = KeyPair::from_pem(&key_pem).map_err(|e| CertGenError::parse_key(&key_path, e))?;
        let issuer = Issuer::from_ca_cert_pem(&cert_pem, key)
            .map_err(|e| CertGenError::parse_cert(&cert_path, e))?;

        Ok(Self { cert_pem, issuer })
    }

    /// Saves the CA certificate and private key to PEM files.
    ///
    /// # Arguments
    ///
    /// * `path` - Path prefix for the certificate and key files.
    ///   - `"ca"` → saves to `./ca.crt.pem` and `./ca.key.pem`
    ///   - `"./certs/ca"` → saves to `./certs/ca.crt.pem` and `./certs/ca.key.pem`
    /// * `options` - Optional settings for directory creation and file overwriting.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - [`CertGenError::DirNotFound`] if directory doesn't exist and `create_parents` is false
    /// - [`CertGenError::FileExists`] if files exist and `force` is false
    /// - [`CertGenError::Io`] if writing files fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// use aranya_certgen::{CaCert, SaveOptions};
    ///
    /// let ca = CaCert::new("My CA", 365)?;
    /// ca.save("ca", None)?;
    /// ca.save("./certs/ca", Some(SaveOptions::default().create_parents().force()))?;
    /// # Ok::<(), aranya_certgen::CertGenError>(())
    /// ```
    pub fn save(&self, path: &str, options: Option<SaveOptions>) -> Result<(), CertGenError> {
        save_cert_and_key(
            path,
            &self.cert_pem,
            &self.issuer.key().serialize_pem(),
            options,
        )
    }

    /// Returns the certificate as a PEM-encoded string.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// Returns the private key as a PEM-encoded string.
    pub fn key_pem(&self) -> String {
        self.issuer.key().serialize_pem()
    }
}

impl std::fmt::Debug for CaCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaCert")
            .field("cert_pem", &"<PEM data>")
            .finish_non_exhaustive()
    }
}

/// A signed leaf certificate that cannot sign other certificates.
///
/// `SignedCert` holds a certificate signed by a CA and its private key.
/// Unlike [`CaCert`], this type cannot be used to sign other certificates.
///
/// # Example
///
/// ```no_run
/// use aranya_certgen::CaCert;
///
/// let ca = CaCert::new("My CA", 365).unwrap();
/// let signed = ca.generate("my-server", 365).unwrap();
/// signed.save("server", None).unwrap();  // Creates ./server.crt.pem and ./server.key.pem
/// ```
pub struct SignedCert {
    cert_pem: String,
    key: KeyPair,
}

impl SignedCert {
    /// Saves the certificate and private key to PEM files.
    ///
    /// # Arguments
    ///
    /// * `path` - Path prefix for the certificate and key files.
    ///   - `"server"` → saves to `./server.crt.pem` and `./server.key.pem`
    ///   - `"./certs/server"` → saves to `./certs/server.crt.pem` and `./certs/server.key.pem`
    /// * `options` - Optional settings for directory creation and file overwriting.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - [`CertGenError::DirNotFound`] if directory doesn't exist and `create_parents` is false
    /// - [`CertGenError::FileExists`] if files exist and `force` is false
    /// - [`CertGenError::Io`] if writing files fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// use aranya_certgen::{CaCert, SaveOptions};
    ///
    /// let ca = CaCert::new("My CA", 365)?;
    /// let signed = ca.generate("server", 365)?;
    /// signed.save("server", None)?;
    /// signed.save("./certs/server", Some(SaveOptions::default().create_parents().force()))?;
    /// # Ok::<(), aranya_certgen::CertGenError>(())
    /// ```
    pub fn save(&self, path: &str, options: Option<SaveOptions>) -> Result<(), CertGenError> {
        save_cert_and_key(path, &self.cert_pem, &self.key.serialize_pem(), options)
    }

    /// Returns the certificate as a PEM-encoded string.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// Returns the private key as a PEM-encoded string.
    pub fn key_pem(&self) -> String {
        self.key.serialize_pem()
    }
}

impl std::fmt::Debug for SignedCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedCert")
            .field("cert_pem", &"<PEM data>")
            .finish_non_exhaustive()
    }
}

// ============================================================================
// Internal helper functions
// ============================================================================

/// Saves a certificate and private key to PEM files.
///
/// The path is used as a prefix: `path.crt.pem` and `path.key.pem`.
fn save_cert_and_key(
    path: impl AsRef<Path>,
    cert_pem: &str,
    key_pem: &str,
    options: Option<SaveOptions>,
) -> Result<(), CertGenError> {
    let options = options.unwrap_or_default();
    let path = path.as_ref();
    let cert_path = path.with_extension("crt.pem");
    let key_path = path.with_extension("key.pem");

    // Check/create parent directory
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() && !dir.exists() {
            if options.create_parents {
                fs::create_dir_all(dir).map_err(|e| CertGenError::io(dir, e))?;
            } else {
                return Err(CertGenError::DirNotFound(dir.display().to_string()));
            }
        }
    }

    // Check for existing files
    if !options.force {
        if cert_path.exists() {
            return Err(CertGenError::FileExists(cert_path.display().to_string()));
        }
        if key_path.exists() {
            return Err(CertGenError::FileExists(key_path.display().to_string()));
        }
    }

    fs::write(&cert_path, cert_pem).map_err(|e| CertGenError::io(&cert_path, e))?;

    // Write private key with restrictive permissions set at creation time
    // to prevent race condition where others could read the key before
    // permissions are set.
    let mut key_options = OpenOptions::new();
    key_options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    key_options.mode(0o600);
    let mut key_file = key_options
        .open(&key_path)
        .map_err(|e| CertGenError::io(&key_path, e))?;
    key_file
        .write_all(key_pem.as_bytes())
        .map_err(|e| CertGenError::io(&key_path, e))?;

    Ok(())
}

/// Generates a self-signed root CA certificate with a P-256 ECDSA private key.
fn generate_root_ca(cn: &str, days: u32) -> Result<(Certificate, KeyPair), CertGenError> {
    let mut params = CertificateParams::default();

    params
        .distinguished_name
        .push(DnType::CommonName, DnValue::Utf8String(cn.to_string()));
    params.distinguished_name.push(
        DnType::OrganizationName,
        DnValue::Utf8String("Certificate Authority".to_string()),
    );

    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];

    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + Duration::days(i64::from(days));

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    Ok((cert, key_pair))
}

/// Generates a certificate signed by a CA with a P-256 ECDSA private key.
fn generate_signed_cert(
    cn: &str,
    issuer: &Issuer<'_, KeyPair>,
    days: u32,
) -> Result<(Certificate, KeyPair), CertGenError> {
    let mut params = CertificateParams::default();

    params
        .distinguished_name
        .push(DnType::CommonName, DnValue::Utf8String(cn.to_string()));

    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];

    // Add CN as DNS SAN for rustls compatibility (rustls ignores CN, only checks SAN).
    // TODO: We've considered adding explicit SAN support (--dns, --ip flags) but decided
    // against it for now to keep the tool simple. If needed, this can be added later.
    params.subject_alt_names = vec![SanType::DnsName(cn.to_string().try_into()?)];

    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + Duration::days(i64::from(days));

    let key_pair = KeyPair::generate()?;
    let cert = params.signed_by(&key_pair, issuer)?;

    Ok((cert, key_pair))
}
