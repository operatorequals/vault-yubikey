# `vault-yubikey`

A Go Package and CLI tool to login into Hashicorp Vault / OpenBao using TLS Certificates generated inside Yubikeys.

<!--TOC-->

- [Usage Examples](#usage-examples)
  - [Registering a new TLS Certificate](#registering-a-new-tls-certificate)
  - [Logging in with TLS Certificate](#logging-in-with-tls-certificate)
- [Building](#building)
- [Configuration](#configuration)
  - [YAML Schema](#yaml-schema)
    - [CSR Fields](#csr-fields)
    - [Yubikey Fields](#yubikey-fields)
    - [Vault Fields](#vault-fields)
  - [Environment Variables](#environment-variables)
    - [Configuration File Variables](#configuration-file-variables)
    - [Vault Connection Variables](#vault-connection-variables)
    - [Vault Configuration Variables](#vault-configuration-variables)
    - [Yubikey Variables](#yubikey-variables)
    - [CSR Variables](#csr-variables)
    - [Security Variables](#security-variables)
- [Import in your code](#import-in-your-code)
  - [Basic Usage](#basic-usage)
- [References](#references)
- [License](#license)

<!--TOC-->

## Usage Examples

### Registering a new TLS Certificate

```bash
$ export MGMT_KEY=010203040506070801020304050607080102030405060708
$ vault-yubikey register --management-key-env MGMT_KEY --config config.yaml

=== Configuration Summary ===

CSR Configuration:
-------------
Subject: C=US, ST=California, L=San Francisco, O=My Organization Inc., OU=Engineering, CN=john.torakis@example.com
                Postal Code: 94105
               Street Address: 123 Main Street
              IP Addresses: 192.168.1.1, 10.0.0.1
            Email Addresses: john.torakis@example.com
                  Key Usage: (default) digital-signature, key-encipherment, key-agreement
         Extended Key Usage: (default) client-auth
                    Extra: map[createdby:vault-yubikey]

Yubikey Configuration:
----------------------
              Algorithm: rsa2048
                   Slot: 9a
           Touch Policy: always

Vault Configuration:
-------------------
        Generated Auth Path: auth/cert/login
      Generated PKI Sign Path: pki/sign/yubikey
              Vault Address: https://localhost:8200
              Skip Verify: true

=== End of Configuration ===
Do you want to proceed with these settings? [y/n]: y
Enter YubiKey PIN:
2026/03/20 14:29:28 Found 1 smart card(s):
  1: Yubico YubiKey OTP+FIDO+CCID 00 00
2026/03/20 14:29:28 Connected to Yubico YubiKey OTP+FIDO+CCID 00 00
2026/03/20 14:29:28 Generating RSA2048 key pair in YubiKey. Might take a while...
2026/03/20 14:29:32 Generated key pair in YubiKey
2026/03/20 14:29:32 Accessing the RSA2048 key pair in YubiKey.
 *** Might need to touch the Yubikey ***
2026/03/20 14:29:33 Certificate signed!
-----BEGIN CERTIFICATE-----
MIIFATCCAumgAwIBAgIUanGAxR7vcAsHZRWBgW6k01oRYdcwDQYJKoZIhvcNAQEL
[...]
alCpK/G3L8FYD8VsSAuiimSPhbMtMGG2h1+i/huNVUtwSKg76A==
-----END CERTIFICATE-----
2026/03/20 14:29:33 Certificate successfully generated and stored in YubiKey
```

### Logging in with TLS Certificate

```bash
$ vault-yubikey login --config config.yaml
Enter YubiKey PIN:
2026/03/20 14:19:59 Found 1 smart card(s):
  1: Yubico YubiKey OTP+FIDO+CCID 00 00
2026/03/20 14:19:59 Connected to Yubico YubiKey OTP+FIDO+CCID 00 00
Accessing the key pair in YubiKey.
 *** Might need to touch the Yubikey ***
Successfully authenticated to Vault and token stored
```

The token is stored in `$HOME/.vault-token` file, where it is automatically read by `vault` and `bao` CLI.

## Building

The [`go-piv/piv-go`](https://github.com/go-piv/piv-go) dependency required `CGO`, so you can build for your system with:
```bash
git clone https://github.com/operatorequals/vault-yubikey
cd vault-yubikey
CGO_ENABLED=true go build -o vault-yubikey ./cmd/*.go
./vault-yubikey
```

## Configuration

The configuration can be provided to `vault-yubikey` using the `config` option or be read from the `$HOME/.vault-yubikey.yaml` file.

The configuration file provides options for the Certificate Signing Request (CSR) generation and signing (Subject, Expiration, etc), as well as Yubikey PIV options (PIV Slot, Touch Policy) and Vault / OpenBao  connectivity (address, PKI mount and role, TLS Cert Auth mount, etc).

Most variables can be overriden by Environment Variables, including the Vault client ones (e.g: `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_SKIP_VERIFY`, etc).

### YAML Schema

The configuration file uses YAML format and contains three main sections: `csr`, `yubikey`, and `vault`.

```yaml
# Certificate Signing Request (CSR) Configuration
csr:
  # Subject fields
  common_name: "admin@example.com"
  organization: "My Organization Inc."
  organizational_unit: "Engineering"
  country: "US"
  locality: "San Francisco"
  province: "California"
  street_address: "123 Main Street"
  postal_code: "94105"

  # Certificate extensions (SAN entries)
  dns_names:
    - "example.com"
    - "*.example.com"
  email_addresses:
    - "admin@example.com"
  ip_addresses:
    - "192.168.1.1"
    - "10.0.0.1"
  uris:
    - "https://service.example.com"

  # Certificate expiration (default: 90d)
  ttl: "90d"

  # Additional certificate fields
  extra:
    createdby: "vault-yubikey"

# Yubikey Configuration
yubikey:
  # Algorithm for key generation
  # Options: rsa1024, rsa2048, rsa3072, rsa4096, ec256, ec384, ed25519
  algorithm: "rsa2048"

  # Yubikey slot to use for key storage
  # Options: 9a (authentication), 9c (signature), 9d (key management), 9e (card authentication)
  slot: "9a"

  # Touch policy for Yubikey operations
  # Options: always, never, cached
  touch_policy: "always"

# Vault Configuration
vault:
  # Vault server address
  vault_address: "https://vault.example.com:8200"

  # PKI engine configuration
  pki_mount: "pki"
  pki_role: "yubikey"

  # Certificate authentication configuration
  cert_auth_mount: "cert"
  cert_auth_role: "yubikey" # if "" all registered certs will be tried

  # TLS verification
  ca_file: "/etc/ssl/certs/vault-ca.pem"
  skip_verify: false
```

#### CSR Fields

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| `common_name` | string | Common Name (CN) - typically a hostname or email | Required. Can be overriden by `--common-name` flag in CLI and `ykvault.NewCertificate` argument |
| `organization` | string | Organization name (O) | - |
| `organizational_unit` | string | Organizational unit (OU) | - |
| `country` | string | Country code (C) - 2 letter ISO code | - |
| `locality` | string | City/Locality (L) | - |
| `province` | string | State/Province (ST) | - |
| `street_address` | string | Street address (optional) | - |
| `postal_code` | string | Postal/ZIP code (optional) | - |
| `dns_names` | list[string] | DNS SAN entries | - |
| `email_addresses` | list[string] | Email SAN entries | - |
| `ip_addresses` | list[string] | IP address SAN entries | - |
| `uris` | list[string] | URI SAN entries | - |
| `ttl` | duration | Certificate expiration | 90d |
| `extra` | map[string]string | Additional certificate fields | - |
| `key_usage` | list[string] | Key usage extensions | digital-signature, key-encipherment, key-agreement |
| `ext_key_usage` | list[string] | Extended key usage | client-auth |

#### Yubikey Fields

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| `algorithm` | string | Key algorithm (rsa1024, rsa2048, rsa3072, rsa4096, ec256, ec384, ed25519) | rsa2048 |
| `slot` | string | Yubikey slot (9a, 9c, 9d, 9e) | 9a |
| `touch_policy` | string | Touch requirement (always, never, cached) | always |

#### Vault Fields

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| `vault_address` | string | Vault server URL | https://127.0.0.1:8200 |
| `pki_mount` | string | PKI secrets engine mount path | pki |
| `pki_role` | string | PKI role for certificate signing | yubikey |
| `cert_auth_mount` | string | TLS auth method mount path | cert |
| `cert_auth_role` | string | TLS auth role name | - |
| `ca_file` | string | Path to CA certificate for TLS verification | - |
| `skip_verify` | bool | Skip TLS verification (not recommended) | false |

### Environment Variables

Most configuration values can be overridden using environment variables. Environment variables take precedence over values in the configuration file.

#### Configuration File Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VAULT_YUBIKEY_CONFIG` | Path to configuration file | ~/.vault-yubikey.yaml |

#### Vault Connection Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VAULT_ADDR` | Vault server address | https://127.0.0.1:8200 |
| `VAULT_TOKEN` | Vault authentication token | - |
| `VAULT_SKIP_VERIFY` | Skip TLS verification (true/false) | false |
| `VAULT_CA_FILE` | Path to CA certificate for TLS verification | - |

#### Vault Configuration Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VAULT_PKI_MOUNT` | PKI secrets engine mount path | pki |
| `VAULT_PKI_ROLE` | PKI role for certificate signing | yubikey |
| `VAULT_CERT_AUTH_MOUNT` | TLS auth method mount path | cert |
| `VAULT_CERT_AUTH_ROLE` | TLS auth role name | - |

#### Yubikey Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VAULT_YUBIKEY_ALGORITHM` | Key algorithm (rsa2048, ec256, etc.) | rsa2048 |
| `VAULT_YUBIKEY_SLOT` | Yubikey slot (9a, 9c, 9d, 9e) | 9a |
| `VAULT_YUBIKEY_TOUCH` | Touch policy (always, never, cached) | always |

#### CSR Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CSR_COMMON_NAME` | Certificate Common Name (CN) | - |
| `CSR_ORGANIZATION` | Organization name (O) | - |
| `CSR_ORGANIZATIONAL_UNIT` | Organizational unit (OU) | - |
| `CSR_COUNTRY` | Country code (C) | - |
| `CSR_LOCALITY` | City/Locality (L) | - |
| `CSR_PROVINCE` | State/Province (ST) | - |
| `CSR_STREET_ADDRESS` | Street address | - |
| `CSR_POSTAL_CODE` | Postal/ZIP code | - |
| `CSR_DNS_NAMES` | DNS SAN entries (comma-separated) | - |
| `CSR_EMAIL_ADDRESSES` | Email SAN entries (comma-separated) | - |
| `CSR_IP_ADDRESSES` | IP address SAN entries (comma-separated) | - |
| `CSR_URIS` | URI SAN entries (comma-separated) | - |
| `CERT_TTL` | Certificate expiration | 90d |
| `CSR_KEY_USAGE` | Key usage extensions (comma-separated) | - |
| `CSR_EXT_KEY_USAGE` | Extended key usage (comma-separated) | - |

#### Security Variables

These variables should be used carefully and not stored in shell history or configuration files:

| Variable | Description |
|----------|-------------|
| `VAULT_YUBIKEY_PIN` | YubiKey PIN (to use with --pin-env flag) |
| `VAULT_YUBIKEY_MANAGEMENT_KEY` | YubiKey management key in hex format (to use with --management-key-env flag) |

## Import in your code

You can use `vault-yubikey` as a Go library in your own applications. The main package is `github.com/operatorequals/vault-yubikey/pkg/yk-vault`.

### Basic Usage

```go
package main

import (
    "fmt"
    "log"

    "github.com/operatorequals/vault-yubikey/pkg/config"
    ykvault "github.com/operatorequals/vault-yubikey/pkg/yk-vault"
)

func main() {
    // Load configuration
    cfg, err := config.LoadConfig(nil) // nil uses default config file path
    if err != nil {
        log.Fatalf("Failed to load config: %v", err)
    }

    // Register a new certificate
    pin := "123456" // Should be obtained securely
    managementKey := "010203040506070801020304050607080102030405060708"
    commonName := "user@example.com"

    cert, err := ykvault.NewCertificate(cfg, pin, managementKey, commonName)
    if err != nil {
        log.Fatalf("Failed to create certificate: %v", err)
    }

    fmt.Printf("Certificate created successfully: %s\n", cert.Subject.CommonName)

    // Login using the certificate
    err = ykvault.Login(cfg, pin)
    if err != nil {
        log.Fatalf("Failed to login: %v", err)
    }

    fmt.Println("Successfully authenticated to Vault")
}
```

## References

* This project has started from a blog post, explaining fundamentals  of Vault-Yubikey mTLS authentication, but does not handle the generation of keypairs inside the Yubikey, and uses imported keys instead:
  https://www.malgregator.com/post/vault-authentication-with-yubikey/

* Yubikeys are currently used for Vault authentication through U2F (not PIV certificates) with 3rd party plugins:
  https://github.com/bruj0/vault-plugin-auth-u2f

* Currently a [fork](https://github.com/tianon/piv-go/tree/shared) of [`go-piv/piv-go`](https://github.com/go-piv/piv-go) is used that allows for shared (non-blocking) connections to Yubikey. Without it, one needs to terminate all processes using the Yubikey before running the tool.

## License

This project is licensed under the *GNU General Public License v3.0*.

You are free to use, modify, and distribute this software under the terms of the GPL v3 license. For the full license text, see the [LICENSE](LICENSE) file or visit https://www.gnu.org/licenses/gpl-3.0.en.html.
