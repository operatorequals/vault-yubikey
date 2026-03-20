// Copyright (C) 2026 Ioannis Torakis <john.torakis@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only.txt

package config

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-piv/piv-go/v2/piv"
	"github.com/spf13/viper"
)

// Config holds all configuration for the vault-yubikey tool
type Config struct {
	// CSR configuration - structured fields for certificate signing request
	CSR CSRConfig `mapstructure:"csr"`

	// Yubikey configuration
	Yubikey YubikeyConfig `mapstructure:"yubikey"`

	// Vault configuration
	Vault VaultConfig `mapstructure:"vault"`
}

// CSRConfig contains structured fields for Certificate Signing Request
type CSRConfig struct {
	// Subject fields
	CommonName         string `mapstructure:"common_name"`
	Organization       string `mapstructure:"organization"`
	OrganizationalUnit string `mapstructure:"organizational_unit"`
	Country            string `mapstructure:"country"`
	Locality           string `mapstructure:"locality"` // City
	Province           string `mapstructure:"province"` // State
	StreetAddress      string `mapstructure:"street_address"`
	PostalCode         string `mapstructure:"postal_code"`

	// Additional certificate fields
	DNSNames       []string `mapstructure:"dns_names"`
	EmailAddresses []string `mapstructure:"email_addresses"`
	IPAddresses    []string `mapstructure:"ip_addresses"`
	URIs           []string `mapstructure:"uris"`

	// Certificate Expiration
	TTL time.Duration `mapstructure:"ttl"`

	// Extra fields for certificate
	Extra map[string]string `mapstructure:"extra"`

	// Key usage settings
	KeyUsage         []string `mapstructure:"key_usage"`
	ExtendedKeyUsage []string `mapstructure:"ext_key_usage"`
}

// YubikeyConfig contains Yubikey-specific settings
type YubikeyConfig struct {
	Algorithm   string `mapstructure:"algorithm"`
	Slot        string `mapstructure:"slot"`
	TouchPolicy string `mapstructure:"touch_policy"`

	// Parsed values (not from config directly)
	SlotParsed        piv.Slot        `json:"-"`
	AlgorithmParsed   piv.Algorithm   `json:"-"`
	TouchPolicyParsed piv.TouchPolicy `json:"-"`
}

// VaultConfig contains Vault-specific settings
type VaultConfig struct {
	PKIMount     string `mapstructure:"pki_mount"`
	PKIRole      string `mapstructure:"pki_role"`
	CertAuthPath string `mapstructure:"cert_auth_mount"`
	CertAuthRole string `mapstructure:"cert_auth_role"`
	VaultAddress string `mapstructure:"vault_address"`
	CAFile       string `mapstructure:"ca_file"`
	SkipVerify   bool   `mapstructure:"skip_verify"`
}

// Environment variable names
const (
	EnvConfigFile            = "VAULT_YUBIKEY_CONFIG"
	EnvVaultAddress          = "VAULT_ADDR"
	EnvVaultPKIMount         = "VAULT_PKI_MOUNT"
	EnvVaultPKIRole          = "VAULT_PKI_ROLE"
	EnvVaultCertAuthMount    = "VAULT_CERT_AUTH_MOUNT"
	EnvVaultCertAuthRole     = "VAULT_CERT_AUTH_ROLE"
	EnvVaultCAFile           = "VAULT_CA_FILE"
	EnvVaultSkipVerify       = "VAULT_SKIP_VERIFY"
	EnvYubikeyAlgorithm      = "VAULT_YUBIKEY_ALGORITHM"
	EnvYubikeySlot           = "VAULT_YUBIKEY_SLOT"
	EnvYubikeyTouchPolicy    = "VAULT_YUBIKEY_TOUCH"
	EnvCertificateCommonName = "CERT_COMMON_NAME"
	EnvCertificateTimeToLive = "CERT_TTL"

	// CSR field environment variables
	EnvCSRCommonName         = "CSR_COMMON_NAME"
	EnvCSROrganization       = "CSR_ORGANIZATION"
	EnvCSROrganizationalUnit = "CSR_ORGANIZATIONAL_UNIT"
	EnvCSRCountry            = "CSR_COUNTRY"
	EnvCSRLocality           = "CSR_LOCALITY"
	EnvCSRProvince           = "CSR_PROVINCE"
	EnvCSRStreetAddress      = "CSR_STREET_ADDRESS"
	EnvCSRPostalCode         = "CSR_POSTAL_CODE"
	EnvCSRDNSNames           = "CSR_DNS_NAMES"
	EnvCSREmailAddresses     = "CSR_EMAIL_ADDRESSES"
	EnvCSRIPAddresses        = "CSR_IP_ADDRESSES"
	EnvCSRURIs               = "CSR_URIS"
	EnvCSRKeyUsage           = "CSR_KEY_USAGE"
	EnvCSRExtendedKeyUsage   = "CSR_EXT_KEY_USAGE"
)

// Default configuration values
const (
	DefaultConfigFile         = "~/.vault-yubikey.yaml"
	DefaultVaultAddress       = "https://127.0.0.1:8200"
	DefaultPKIMount           = "pki"
	DefaultPKIMountRole       = "yubikey"
	DefaultCertMount          = "cert"
	DefaultCertMountRole      = "" // The empty value tries to match all roles
	DefaultYubikeyAlgorithm   = "rsa2048"
	DefaultYubikeySlot        = "9a"
	DefaultYubikeyTouchPolicy = "always"

	DefaultCertificateTimeToLive = "90d" // 3 months
)

// LoadConfig loads configuration from YAML file and environment variables
// Environment variables take precedence over YAML file values
func LoadConfig(filename *string) (*Config, error) {
	v := viper.New()

	// Set up config file search paths
	configFile := os.Getenv(EnvConfigFile)
	if filename != nil {
		configFile = *filename
	} else if configFile == "" {
		configFile = DefaultConfigFile
	}

	// Expand ~ to home directory
	if strings.HasPrefix(configFile, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		configFile = filepath.Join(home, configFile[2:])
	}

	// Check if config file exists
	if _, err := os.Stat(configFile); err == nil {
		v.SetConfigFile(configFile)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("failed to read config file %s: %w", configFile, err)
		}
	}

	// Enable automatic environment variable reading
	v.AutomaticEnv()

	// Set up environment variable bindings for nested keys
	// Yubikey settings
	bindEnvVar(v, "yubikey.algorithm", EnvYubikeyAlgorithm)
	bindEnvVar(v, "yubikey.slot", EnvYubikeySlot)
	bindEnvVar(v, "yubikey.touch_policy", EnvYubikeyTouchPolicy)

	// Vault settings
	bindEnvVar(v, "vault.pki_mount", EnvVaultPKIMount)
	bindEnvVar(v, "vault.pki_role", EnvVaultPKIRole)
	bindEnvVar(v, "vault.cert_auth_mount", EnvVaultCertAuthMount)
	bindEnvVar(v, "vault.cert_auth_role", EnvVaultCertAuthRole)
	bindEnvVar(v, "vault.vault_address", EnvVaultAddress)
	bindEnvVar(v, "vault.ca_file", EnvVaultCAFile)
	bindEnvVar(v, "vault.skip_verify", EnvVaultSkipVerify)

	// CSR
	// CSR settings
	bindEnvVar(v, "csr.common_name", EnvCSRCommonName)
	bindEnvVar(v, "csr.organization", EnvCSROrganization)
	bindEnvVar(v, "csr.organizational_unit", EnvCSROrganizationalUnit)
	bindEnvVar(v, "csr.country", EnvCSRCountry)
	bindEnvVar(v, "csr.locality", EnvCSRLocality)
	bindEnvVar(v, "csr.province", EnvCSRProvince)
	bindEnvVar(v, "csr.street_address", EnvCSRStreetAddress)
	bindEnvVar(v, "csr.postal_code", EnvCSRPostalCode)
	bindEnvVar(v, "csr.dns_names", EnvCSRDNSNames)
	bindEnvVar(v, "csr.email_addresses", EnvCSREmailAddresses)
	bindEnvVar(v, "csr.ip_addresses", EnvCSRIPAddresses)
	bindEnvVar(v, "csr.uris", EnvCSRURIs)
	bindEnvVar(v, "csr.ttl", EnvCertificateTimeToLive)
	bindEnvVar(v, "csr.key_usage", EnvCSRKeyUsage)
	bindEnvVar(v, "csr.ext_key_usage", EnvCSRExtendedKeyUsage)

	// Set defaults
	setVaultDefaults(v)
	setYubikeyDefaults(v)

	// Unmarshal config
	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Parse and validate Yubikey settings
	if err := config.parseYubikeySettings(); err != nil {
		return nil, fmt.Errorf("failed to parse yubikey settings: %w", err)
	}

	// v.SetDefault("csr.ttl", DefaultCertificateTimeToLive)

	// Set default values for CSR fields
	// if config.CSR.Organization == "" {
	// 	config.CSR.Organization = "ACME INC."
	// }

	return &config, nil
}

// bindEnvVar binds an environment variable to a config key
func bindEnvVar(v *viper.Viper, key, envVar string) {
	if err := v.BindEnv(key, envVar); err != nil {
		// Silently ignore bind errors - they're not critical
	}
}

// setVaultDefaults sets default values for Vault configuration
func setVaultDefaults(v *viper.Viper) {
	v.SetDefault("vault.vault_address", DefaultVaultAddress)
	v.SetDefault("vault.pki_mount", DefaultPKIMount)
	v.SetDefault("vault.pki_role", DefaultPKIMountRole)
	v.SetDefault("vault.cert_auth_mount", DefaultCertMount)
	v.SetDefault("vault.cert_auth_role", DefaultCertMountRole)
	v.SetDefault("vault.skip_verify", false)
}

// setYubikeyDefaults sets default values for Yubikey configuration
func setYubikeyDefaults(v *viper.Viper) {
	v.SetDefault("yubikey.algorithm", DefaultYubikeyAlgorithm)
	v.SetDefault("yubikey.slot", DefaultYubikeySlot)
	v.SetDefault("yubikey.touch_policy", DefaultYubikeyTouchPolicy)
}

// ParseSlot parses a slot string into a piv.Slot
func ParseSlot(slot string) (piv.Slot, error) {
	slot = strings.ToLower(strings.TrimSpace(slot))
	switch slot {
	case "9a", "authentication", "auth":
		return piv.SlotAuthentication, nil
	case "9c", "signature", "sign":
		return piv.SlotSignature, nil
	case "9d", "key-management", "keymgmt":
		return piv.SlotKeyManagement, nil
	case "9e", "card-authentication", "cardauth":
		return piv.SlotCardAuthentication, nil
	default:
		var zeroSlot piv.Slot
		return zeroSlot, fmt.Errorf("invalid yubikey slot: %s (supported: 9a, 9c, 9d, 9e)", slot)
	}
}

// ParseAlgorithm parses an algorithm string into a piv.Algorithm
func ParseAlgorithm(algorithm string) (piv.Algorithm, error) {
	algorithm = strings.ToLower(strings.TrimSpace(algorithm))
	switch algorithm {
	case "ec256", "ec256p", "p256", "ecdsa-p256":
		return piv.AlgorithmEC256, nil
	case "ec384", "ec384p", "p384", "ecdsa-p384":
		return piv.AlgorithmEC384, nil
	case "rsa1024":
		return piv.AlgorithmRSA1024, nil
	case "rsa2048", "rsa":
		return piv.AlgorithmRSA2048, nil
	case "rsa3072":
		return piv.AlgorithmRSA3072, nil
	case "rsa4096":
		return piv.AlgorithmRSA4096, nil
	case "ed25519":
		return piv.AlgorithmEd25519, nil
	default:
		var zeroAlgorithm piv.Algorithm
		return zeroAlgorithm, fmt.Errorf("invalid algorithm: %s (supported: ec256, ec384, rsa1024, rsa2048, rsa3072, rsa4096, ed25519)", algorithm)
	}
}

// ParseTouchPolicy parses a touch policy string into a piv.TouchPolicy
func ParseTouchPolicy(touchPolicy string) (piv.TouchPolicy, error) {
	touchPolicy = strings.ToLower(strings.TrimSpace(touchPolicy))
	switch touchPolicy {
	case "always", "true", "1", "yes", "touch":
		return piv.TouchPolicyAlways, nil
	case "never", "false", "0", "no", "no-touch", "no_touch", "notouch":
		return piv.TouchPolicyNever, nil
	case "cached", "cache", "once":
		return piv.TouchPolicyCached, nil
	default:
		var zeroTouchPolicy piv.TouchPolicy
		return zeroTouchPolicy, fmt.Errorf("invalid touch policy: %s (supported: always, never, cached, cached-with-timeout)", touchPolicy)
	}
}

// parseYubikeySettings parses string values from config into piv-go types
func (c *Config) parseYubikeySettings() error {
	var err error

	c.Yubikey.SlotParsed, err = ParseSlot(c.Yubikey.Slot)
	if err != nil {
		return err
	}

	c.Yubikey.AlgorithmParsed, err = ParseAlgorithm(c.Yubikey.Algorithm)
	if err != nil {
		return err
	}

	c.Yubikey.TouchPolicyParsed, err = ParseTouchPolicy(c.Yubikey.TouchPolicy)
	if err != nil {
		return err
	}

	return nil
}

// GetSlot returns the piv.Slot for the configuration
func (c *Config) GetCSRTTLString() string {
	return time.Duration.String(c.CSR.TTL)
}

// GetSlot returns the piv.Slot for the configuration
func (c *Config) GetSlot() piv.Slot {
	return c.Yubikey.SlotParsed
}

// GetAlgorithm returns the piv.Algorithm for the configuration
func (c *Config) GetAlgorithm() piv.Algorithm {
	return c.Yubikey.AlgorithmParsed
}

// GetTouchPolicy returns the piv.TouchPolicy for the configuration
func (c *Config) GetTouchPolicy() piv.TouchPolicy {
	return c.Yubikey.TouchPolicyParsed
}

// GetVaultPKISignPath returns the endpoint to use with Logical.Write()
// in order to sign a CSR that already contains its Common Name
func (c *Config) GetVaultPKISignPath() (string, error) {
	if c.Vault.PKIMount == "" || c.Vault.PKIRole == "" {
		return "", fmt.Errorf("could not create signing path, missing mount or role")
	}
	return fmt.Sprintf(
		"%s/sign/%s",
		strings.Trim(c.Vault.PKIMount, "/"),
		strings.Trim(c.Vault.PKIRole, "/"),
	), nil
}

// GetVaultAuthPath returns the endpoint to connect with mTLS to Login
func (c *Config) GetVaultAuthPath() (string, error) {
	if c.Vault.CertAuthPath == "" {
		return "", fmt.Errorf("could not create authentication path, missing mount")
	}

	return fmt.Sprintf(
		"auth/%s/login",
		strings.TrimPrefix(
			strings.Trim(c.Vault.CertAuthPath, "/"),
			"auth/"),
	), nil
}

// ParseManagementKey parses a hex string into a 24-byte management key
func ParseManagementKey(hexKey string) ([24]byte, error) {
	var key [24]byte

	// Remove any spaces or hyphens
	cleaned := strings.ReplaceAll(strings.ReplaceAll(hexKey, " ", ""), "-", "")

	// Parse hex string
	data, err := hex.DecodeString(cleaned)
	if err != nil {
		return key, fmt.Errorf("failed to parse management key hex: %w", err)
	}

	// Check length
	if len(data) != 24 {
		return key, fmt.Errorf("management key must be 24 bytes (48 hex characters), got %d bytes", len(data))
	}

	copy(key[:], data)
	return key, nil
}

// ParseKeyUsage parses key usage strings into x509.KeyUsage bitmask
func ParseKeyUsage(usages []string) (x509.KeyUsage, error) {
	var keyUsage x509.KeyUsage

	if len(usages) == 0 {
		// Return default key usage: Digital Signature, Key Encipherment, Key Agreement
		return x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement, nil
	}

	for _, usage := range usages {
		switch strings.ToLower(strings.TrimSpace(usage)) {
		case "digital-signature", "digital_signature", "digitalsignature":
			keyUsage |= x509.KeyUsageDigitalSignature
		case "content-commitment", "content_commitment", "contentcommitment":
			keyUsage |= x509.KeyUsageContentCommitment
		case "key-encipherment", "key_encipherment", "keyencipherment":
			keyUsage |= x509.KeyUsageKeyEncipherment
		case "data-encipherment", "data_encipherment", "dataencipherment":
			keyUsage |= x509.KeyUsageDataEncipherment
		case "key-agreement", "key_agreement", "keyagreement":
			keyUsage |= x509.KeyUsageKeyAgreement
		case "cert-sign", "cert_sign", "certsign", "certificate-sign", "certificate_sign", "certificatesign":
			keyUsage |= x509.KeyUsageCertSign
		case "crl-sign", "crl_sign", "crlsign":
			keyUsage |= x509.KeyUsageCRLSign
		case "encipher-only", "encipher_only", "encipheronly":
			keyUsage |= x509.KeyUsageEncipherOnly
		case "decipher-only", "decipher_only", "decipheronly":
			keyUsage |= x509.KeyUsageDecipherOnly
		default:
			return 0, fmt.Errorf("unknown key usage: %s", usage)
		}
	}

	return keyUsage, nil
}

// ParseExtendedKeyUsage parses extended key usage strings into []x509.ExtKeyUsage
func ParseExtendedKeyUsage(usages []string) ([]x509.ExtKeyUsage, error) {

	// Default is the ClientAuth
	if len(usages) == 0 {
		return []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil
	}

	var extKeyUsages []x509.ExtKeyUsage

	for _, usage := range usages {
		var extKeyUsage x509.ExtKeyUsage
		switch strings.ToLower(strings.TrimSpace(usage)) {
		case "any", "any-extended-key-usage":
			extKeyUsage = x509.ExtKeyUsageAny
		case "server-auth", "server-authentication":
			extKeyUsage = x509.ExtKeyUsageServerAuth
		case "client-auth", "client-authentication":
			extKeyUsage = x509.ExtKeyUsageClientAuth
		case "code-signing", "codesigning":
			extKeyUsage = x509.ExtKeyUsageCodeSigning
		case "email-protection", "emailprotection":
			extKeyUsage = x509.ExtKeyUsageEmailProtection
		case "ipsec-end-system", "ipsecendsystem":
			extKeyUsage = x509.ExtKeyUsageIPSECEndSystem
		case "ipsec-tunnel", "ipsectunnel":
			extKeyUsage = x509.ExtKeyUsageIPSECTunnel
		case "ipsec-user", "ipsecuser":
			extKeyUsage = x509.ExtKeyUsageIPSECUser
		case "time-stamping", "timestamping":
			extKeyUsage = x509.ExtKeyUsageTimeStamping
		case "ocsp-signing", "ocspsigning":
			extKeyUsage = x509.ExtKeyUsageOCSPSigning
		case "microsoft-sgc", "microsoft-sgc-com", "microsoftsgc":
			extKeyUsage = x509.ExtKeyUsageMicrosoftServerGatedCrypto
		case "netscape-sgc", "netscape-sgc-com", "netscapesgc":
			extKeyUsage = x509.ExtKeyUsageNetscapeServerGatedCrypto
		default:
			return nil, fmt.Errorf("unknown extended key usage: %s", usage)
		}
		extKeyUsages = append(extKeyUsages, extKeyUsage)
	}

	return extKeyUsages, nil
}
