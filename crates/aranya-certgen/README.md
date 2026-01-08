# aranya-certgen

A CLI tool for generating root CA certificates and signed certificates.

All generated keys use **P-256 ECDSA** (NIST P-256 / secp256r1 curve with ECDSA signatures).

## Installation

```bash
cargo install --path crates/aranya-certgen
```

## Usage

### Create a Root CA

```bash
aranya-certgen ca --cert ca.pem --key ca.key --ca-name "My Company CA"
```

### Create a Signed Certificate

```bash
aranya-certgen signed \
  --ca-cert ca.pem --ca-key ca.key \
  --cert server.pem --key server.key \
  --cn webserver \
  --dns example.com --dns www.example.com \
  --ip 192.168.1.10
```

## Commands

### `aranya-certgen ca`

Create a new root Certificate Authority (CA) with a P-256 ECDSA private key.

| Option | Description | Default |
|--------|-------------|---------|
| `--cert <PATH>` | Path for the CA certificate file (PEM format) | required |
| `--key <PATH>` | Path for the CA P-256 ECDSA private key file (PEM format) | required |
| `--ca-name <NAME>` | Common Name (CN) for the root CA | `My Root CA` |
| `--validity-days <DAYS>` | Validity period in days | `365` |

### `aranya-certgen signed`

Create a new certificate signed by an existing root CA with a P-256 ECDSA private key.

| Option | Description | Default |
|--------|-------------|---------|
| `--cert <PATH>` | Path for the output certificate file (PEM format) | required |
| `--key <PATH>` | Path for the output P-256 ECDSA private key file (PEM format) | required |
| `--ca-cert <PATH>` | Path to the CA certificate file (PEM format) | required |
| `--ca-key <PATH>` | Path to the CA P-256 ECDSA private key file (PEM format) | required |
| `--cn <NAME>` | Common Name (CN) for the certificate | required |
| `--dns <HOSTNAME>` | DNS name for SAN (can be repeated) | — |
| `--ip <ADDRESS>` | IP address for SAN (can be repeated) | — |
| `--validity-days <DAYS>` | Validity period in days | `365` |

## Example Output

```
$ aranya-certgen ca --cert ca.pem --key ca.key --ca-name "My Company CA"
Generating root CA certificate...
  Root CA certificate: ca.pem
  Root CA private key: ca.key

$ aranya-certgen signed --ca-cert ca.pem --ca-key ca.key \
    --cert server.pem --key server.key \
    --cn webserver --dns example.com --ip 192.168.1.10
Generating certificate 'webserver'...
  Certificate: server.pem
  Private key: server.key
  SANs:
    - DNS: example.com
    - IP:  192.168.1.10
```

## Comparison with OpenSSL

This tool simplifies certificate generation compared to OpenSSL:

| Aspect | aranya-certgen | OpenSSL |
|--------|---------|---------|
| Commands for CA + 1 cert | 2 | 6+ |
| Intermediate files | None | CSR, serial |
| SAN syntax | `--dns x --ip y` | `-extfile <(echo "...")` |
| Key algorithm | P-256 ECDSA (built-in) | Must specify manually |

## License

Apache-2.0
