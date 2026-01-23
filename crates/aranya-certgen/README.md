# aranya-certgen

A CLI tool for generating root CA certificates and signed certificates.

All generated keys currently use **P-256 ECDSA** (NIST P-256 / secp256r1 curve with ECDSA signatures).
The crypto implementation may change in the future based on best practices (e.g. switching to HPKE).

## Building

```bash
cargo build --release -p aranya-certgen
```

The binary will be at `target/release/aranya-certgen`.

## Usage

### Create a Root CA

```bash
aranya-certgen ca --cn "My Company CA"
```

### Create a Signed Certificate

```bash
aranya-certgen signed ca --cn webserver
```

## Commands

### `aranya-certgen ca`

Create a new root Certificate Authority (CA) with a P-256 ECDSA private key.

| Option | Description | Default |
|--------|-------------|---------|
| `--cn <NAME>` | Common Name (CN) for the root CA | required |
| `-o, --output <PATH>` | Output path prefix (creates {output}.crt.pem and {output}.key.pem) | `ca` |
| `--days <DAYS>` | Validity period in days | `365` |
| `-p` | Create parent directories if they don't exist | — |
| `-f, --force` | Overwrite existing files | — |

### `aranya-certgen signed <CA>`

Create a new certificate signed by an existing root CA with a P-256 ECDSA private key.

The CA path prefix is required to ensure the expected CA certificate is used for signing.

| Argument/Option | Description | Default |
|-----------------|-------------|---------|
| `<CA>` | Path prefix for CA files (loads {CA}.crt.pem and {CA}.key.pem) | required |
| `--cn <NAME>` | Common Name (CN) for the certificate | required |
| `-o, --output <PATH>` | Output path prefix (creates {output}.crt.pem and {output}.key.pem) | `cert` |
| `--days <DAYS>` | Validity period in days | `365` |
| `-p` | Create parent directories if they don't exist | — |
| `-f, --force` | Overwrite existing files | — |

## Example Output

```
$ aranya-certgen ca --cn "My Company CA"
Generating root CA certificate...
  Certificate: ./ca.crt.pem

$ aranya-certgen signed ca --cn webserver
Generating certificate 'webserver'...
  Certificate: ./cert.crt.pem
```

## Renewing Certificates

To renew or reissue a device certificate, generate a new certificate using the same CA:

```bash
# Load existing CA and generate a new certificate
aranya-certgen signed ca --cn webserver --days 365 -f
```

The `-f` (force) flag overwrites the existing certificate files. The new certificate will:
- Have a new key pair (more secure than reusing keys)
- Have a fresh validity period starting from now
- Be signed by the same CA, so clients trusting the CA will accept the new certificate

**Note:** If you need to preserve the existing private key (not recommended), this tool does not currently support that workflow. You would need to use OpenSSL or similar tools to create a CSR with the existing key.

### Renewing the CA Certificate

CA certificates can also be renewed, but this requires all device certificates to be reissued since they reference the CA:

```bash
# Generate new CA (will invalidate existing device certs once daemon reloads new CA)
aranya-certgen ca --cn "My Company CA" --days 365 -f

# Reissue all device certificates
aranya-certgen signed ca --cn webserver --days 365 -f
aranya-certgen signed ca --cn device1 -o device1 --days 365 -f
# ... repeat for all devices
```

## Comparison with OpenSSL

This tool simplifies certificate generation compared to OpenSSL while guaranteeing use of expected P-256 ECDSA keys.

certgen:
```
aranya-certgen ca --cn "My Company CA" --days 365

aranya-certgen signed ca --cn webserver --days 365
```

openssl:
```
openssl req -x509 \
    -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout ca.key -nodes \
    -days 365 \
    -subj "/CN=My Company CA" \
    -out ca.pem

openssl req -x509 \
    -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout server.key -nodes \
    -CA ca.pem -CAkey ca.key \
    -days 365 \
    -subj "/CN=webserver" \
    -out server.pem
```
