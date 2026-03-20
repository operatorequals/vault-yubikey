# `vault-yubikey`

A Go Package and CLI tool to login into Hashicorp Vault / OpenBao using TLS Certificates generated inside Yubikeys.


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
BQAwITEfMB0GA1UEAxMWVmF1bHQgSW50ZXJuYWwgUm9vdCBDQTAeFw0yNjAzMjAx
MjI5MDNaFw0yNjAzMjExMjQ5MzNaMCMxITAfBgNVBAMMGGpvaG4udG9yYWtpc0Bl
eGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANdvPzLW
jhM2yy3drTq6wc+rqlcTrKl6mGSzYdS0ZhC0umtYodwm6+aiDH4sQ2CgE0Lc2F6x
//+IM+DPIxMjwX8D0h4bejxqVJN1TQLF9mTfS1dvJIK/aeGSrPoXXa45IgOE2uDG
YYT3wCMyQkv1wxXRif2JOS4UUV/4aXPWaAomg+2Pho227xVfS+OtNCdsfh3TBisa
Ta8SrkZsuYo7QlSAPOlkoRL6934UN19ew7qukYKvOwndxTA7OUQp59ZFc0ym9Q2g
SUuonml9BqyXUKv0k7GTj1Ofi67CR2spXkRZOuROWBFgPBRQus6wny6PDIOKXVCy
z883JF4fHMSu0HcCAwEAAaOCAS0wggEpMA4GA1UdDwEB/wQEAwIDqDATBgNVHSUE
DDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQUVVAezpOGoqlwFYISGDlRbQj881MwHwYD
VR0jBBgwFoAU46DHcHu/vwWXUDl4/6GNhbCh2nowYgYIKwYBBQUHAQEEVjBUMCkG
CCsGAQUFBzABhh1odHRwOi8vdmF1bHQ6ODIwMC92MS9wa2kvb2NzcDAnBggrBgEF
BQcwAoYbaHR0cDovL3ZhdWx0OjgyMDAvdjEvcGtpL2NhMC8GA1UdEQQoMCaBGGpv
aG4udG9yYWtpc0BleGFtcGxlLmNvbYcEwKgBAYcECgAAATAtBgNVHR8EJjAkMCKg
IKAehhxodHRwOi8vdmF1bHQ6ODIwMC92MS9wa2kvY3JsMA0GCSqGSIb3DQEBCwUA
A4ICAQACSxbgoLJWiGfvJHvT2PpHcGqXCxP9MASZN2LW15TNGBF3IOHnsRKDNkoO
H7+29igYV6ZEGRSWIsbTSkubZ0oV8HhW0E58RpvhD8wepVMY4u2houpTXu3UEug+
ejqXcCu4yyA2HBQG3LIU+yUzYD3NBcerUDCSjDpNjC/iS4ZLwrlLeNxTmSm/q1bd
qHo16dUWMq4qA0yD5bGeKE4qH9r706F8lJ6aHUCgT4Tku1m3bzllT8WTEYOrDRnh
O5HbJZEJEdY1XMNHRZOwc89F4miMzEkXEkj6zDf+MD/9WCB2USmOwjbAg90+Ne4F
pHCS4ki9E/2ZqrIJ09bbWA79HSNiIpkUjCCUMQlGapl9K/lHhedhyee4Mz97rFzs
eTV22yuuRZ/s9KbeWuwjjjvQaPMHVNPg69t6ay7uWZ6wezevRbNzFdMfynQi1Lgb
1I17//Cta2QjkZ+vFj1pmA8y1s72A099C9nQ7cXlvpgkob8CEANHcV8WCcH6U5dc
A+nTXH+D4ToMmSM/FJKuO9zKDAHFlBSV4r81YkhayjNoy2WbNUy+hDbt7UcwExb3
dFxl6wONkCQypdSuVfUiykc7y9SFHQsdLi1Z7Jk8uVRDKWujaISsfwFwCtoSvbj3
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

## Configuration

### YAML Schema

### Environment Variables

## Import in your code


## License
