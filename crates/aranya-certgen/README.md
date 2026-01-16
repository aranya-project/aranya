# aranya-certgen

A CLI tool for generating root CA certificates and signed certificates.

All generated keys use **P-256 ECDSA** (NIST P-256 / secp256r1 curve with ECDSA signatures).

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
aranya-certgen signed --cn webserver
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

### `aranya-certgen signed`

Create a new certificate signed by an existing root CA with a P-256 ECDSA private key.

| Option | Description | Default |
|--------|-------------|---------|
| `--cn <NAME>` | Common Name (CN) for the certificate | required |
| `-o, --output <PATH>` | Output path prefix (creates {output}.crt.pem and {output}.key.pem) | `cert` |
| `--ca <PATH>` | Path prefix for CA files (loads {ca}.crt.pem and {ca}.key.pem) | `ca` |
| `--days <DAYS>` | Validity period in days | `365` |
| `-p` | Create parent directories if they don't exist | — |
| `-f, --force` | Overwrite existing files | — |

## Example Output

```
$ aranya-certgen ca --cn "My Company CA"
Generating root CA certificate...
  Certificate: ./ca.crt.pem

$ aranya-certgen signed --cn webserver
Generating certificate 'webserver'...
  Certificate: ./cert.crt.pem
```

## Comparison with OpenSSL

This tool simplifies certificate generation compared to OpenSSL while guaranteeing use of expected P-256 ECDSA keys.

certgen:
```
aranya-certgen ca --cn "My Company CA" --days 365

aranya-certgen signed --cn webserver --days 365
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
