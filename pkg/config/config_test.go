// Copyright (C) 2026 Ioannis Torakis <john.torakis@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only.txt

package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-piv/piv-go/v2/piv"
)

func TestLoadConfig_DefaultValues(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir := t.TempDir()

	// Set home directory to temp dir to avoid reading user's actual config
	oldHome := os.Getenv("HOME")
	t.Cleanup(func() {
		os.Setenv("HOME", oldHome)
	})
	os.Setenv("HOME", tmpDir)

	// Clear any existing environment variables that might interfere
	clearTestEnvVars()

	// Load config without a file (should use defaults)
	config, err := LoadConfig(nil)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// Check Vault defaults
	if config.Vault.VaultAddress != DefaultVaultAddress {
		t.Errorf("Expected VaultAddress %s, got %s", DefaultVaultAddress, config.Vault.VaultAddress)
	}
	if config.Vault.PKIMount != DefaultPKIMount {
		t.Errorf("Expected PKIMount '%s', got '%s'", DefaultPKIMount, config.Vault.PKIMount)
	}
	if config.Vault.PKIRole != DefaultPKIMountRole {
		t.Errorf("Expected PKIRole '%s', got '%s'", DefaultPKIMountRole, config.Vault.PKIRole)
	}
	if config.Vault.CertAuthPath != DefaultCertMount {
		t.Errorf("Expected CertAuthPath '%s', got '%s'", DefaultCertMount, config.Vault.CertAuthPath)
	}
	if config.Vault.CertAuthRole != DefaultCertMountRole {
		t.Errorf("Expected CertAuthRole '%s', got '%s'", DefaultCertMountRole, config.Vault.CertAuthRole)
	}
	if config.Vault.SkipVerify != false {
		t.Errorf("Expected SkipVerify false, got %v", config.Vault.SkipVerify)
	}

	// Check Yubikey defaults
	if config.Yubikey.Algorithm != DefaultYubikeyAlgorithm {
		t.Errorf("Expected Algorithm %s, got %s", DefaultYubikeyAlgorithm, config.Yubikey.Algorithm)
	}
	if config.Yubikey.Slot != DefaultYubikeySlot {
		t.Errorf("Expected Slot %s, got %s", DefaultYubikeySlot, config.Yubikey.Slot)
	}
	if config.Yubikey.TouchPolicy != DefaultYubikeyTouchPolicy {
		t.Errorf("Expected TouchPolicy %s, got %s", DefaultYubikeyTouchPolicy, config.Yubikey.TouchPolicy)
	}

	// Check parsed Yubikey values
	if config.Yubikey.AlgorithmParsed != piv.AlgorithmRSA2048 {
		t.Errorf("Expected AlgorithmParsed RSA2048, got %v", config.Yubikey.AlgorithmParsed)
	}
	if config.Yubikey.SlotParsed != piv.SlotAuthentication {
		t.Errorf("Expected SlotParsed Authentication, got %v", config.Yubikey.SlotParsed)
	}
	if config.Yubikey.TouchPolicyParsed != piv.TouchPolicyAlways {
		t.Errorf("Expected TouchPolicyParsed Always, got %v", config.Yubikey.TouchPolicyParsed)
	}
}

func TestLoadConfig_WithFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test config file
	configContent := `
csr:
  common_name: "test.example.com"
  organization: "Test Org"
  organizational_unit: "Test Unit"
  country: "US"
  locality: "San Francisco"
  province: "California"
  street_address: "123 Test St"
  postal_code: "94105"
  dns_names:
    - "example.com"
    - "test.example.com"
  email_addresses:
    - "admin@example.com"
  ip_addresses:
    - "192.168.1.1"
  uris:
    - "spiffe://example.com/service"

yubikey:
  algorithm: "ec256"
  slot: "9c"
  touch_policy: "cached"

vault:
  vault_address: "https://vault.example.com:8200"
  pki_mount: "pki-intermediate"
  pki_role: "test-role"
  cert_auth_mount: "cert-auth"
  cert_auth_role: "test-role"
  ca_file: "/etc/ssl/certs/ca.pem"
  skip_verify: true
`
	configFile := filepath.Join(tmpDir, "test-config.yaml")
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	// Clear environment variables
	clearTestEnvVars()

	// Load config from file
	config, err := LoadConfig(&configFile)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// Check CSR fields
	if config.CSR.CommonName != "test.example.com" {
		t.Errorf("Expected CommonName 'test.example.com', got '%s'", config.CSR.CommonName)
	}
	if config.CSR.Organization != "Test Org" {
		t.Errorf("Expected Organization 'Test Org', got '%s'", config.CSR.Organization)
	}
	if config.CSR.OrganizationalUnit != "Test Unit" {
		t.Errorf("Expected OrganizationalUnit 'Test Unit', got '%s'", config.CSR.OrganizationalUnit)
	}
	if config.CSR.Country != "US" {
		t.Errorf("Expected Country 'US', got '%s'", config.CSR.Country)
	}
	if config.CSR.Locality != "San Francisco" {
		t.Errorf("Expected Locality 'San Francisco', got '%s'", config.CSR.Locality)
	}
	if config.CSR.Province != "California" {
		t.Errorf("Expected Province 'California', got '%s'", config.CSR.Province)
	}
	if config.CSR.StreetAddress != "123 Test St" {
		t.Errorf("Expected StreetAddress '123 Test St', got '%s'", config.CSR.StreetAddress)
	}
	if config.CSR.PostalCode != "94105" {
		t.Errorf("Expected PostalCode '94105', got '%s'", config.CSR.PostalCode)
	}
	if len(config.CSR.DNSNames) != 2 || config.CSR.DNSNames[0] != "example.com" {
		t.Errorf("Expected DNSNames [example.com test.example.com], got %v", config.CSR.DNSNames)
	}
	if len(config.CSR.EmailAddresses) != 1 || config.CSR.EmailAddresses[0] != "admin@example.com" {
		t.Errorf("Expected EmailAddresses [admin@example.com], got %v", config.CSR.EmailAddresses)
	}
	if len(config.CSR.IPAddresses) != 1 || config.CSR.IPAddresses[0] != "192.168.1.1" {
		t.Errorf("Expected IPAddresses [192.168.1.1], got %v", config.CSR.IPAddresses)
	}
	if len(config.CSR.URIs) != 1 || config.CSR.URIs[0] != "spiffe://example.com/service" {
		t.Errorf("Expected URIs [spiffe://example.com/service], got %v", config.CSR.URIs)
	}

	// Check Yubikey settings
	if config.Yubikey.Algorithm != "ec256" {
		t.Errorf("Expected Algorithm 'ec256', got '%s'", config.Yubikey.Algorithm)
	}
	if config.Yubikey.Slot != "9c" {
		t.Errorf("Expected Slot '9c', got '%s'", config.Yubikey.Slot)
	}
	if config.Yubikey.TouchPolicy != "cached" {
		t.Errorf("Expected TouchPolicy 'cached', got '%s'", config.Yubikey.TouchPolicy)
	}
	if config.Yubikey.AlgorithmParsed != piv.AlgorithmEC256 {
		t.Errorf("Expected AlgorithmParsed EC256, got %v", config.Yubikey.AlgorithmParsed)
	}
	if config.Yubikey.SlotParsed != piv.SlotSignature {
		t.Errorf("Expected SlotParsed Signature, got %v", config.Yubikey.SlotParsed)
	}
	if config.Yubikey.TouchPolicyParsed != piv.TouchPolicyCached {
		t.Errorf("Expected TouchPolicyParsed Cached, got %v", config.Yubikey.TouchPolicyParsed)
	}

	// Check Vault settings
	if config.Vault.VaultAddress != "https://vault.example.com:8200" {
		t.Errorf("Expected VaultAddress 'https://vault.example.com:8200', got '%s'", config.Vault.VaultAddress)
	}
	if config.Vault.PKIMount != "pki-intermediate" {
		t.Errorf("Expected PKIMount 'pki-intermediate', got '%s'", config.Vault.PKIMount)
	}
	if config.Vault.PKIRole != "test-role" {
		t.Errorf("Expected PKIRole 'test-role', got '%s'", config.Vault.PKIRole)
	}
	if config.Vault.CertAuthPath != "cert-auth" {
		t.Errorf("Expected CertAuthPath 'cert-auth', got '%s'", config.Vault.CertAuthPath)
	}
	if config.Vault.CAFile != "/etc/ssl/certs/ca.pem" {
		t.Errorf("Expected CAFile '/etc/ssl/certs/ca.pem', got '%s'", config.Vault.CAFile)
	}
	if config.Vault.CertAuthRole != "test-role" {
		t.Errorf("Expected CertAuthRole 'test-role', got '%s'", config.Vault.CertAuthRole)
	}
	if config.Vault.CAFile != "/etc/ssl/certs/ca.pem" {
		t.Errorf("Expected CAFile '/etc/ssl/certs/ca.pem', got '%s'", config.Vault.CAFile)
	}
	if config.Vault.SkipVerify != true {
		t.Errorf("Expected SkipVerify true, got %v", config.Vault.SkipVerify)
	}
}

func TestLoadConfig_EnvOverrides(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test config file
	configContent := `
yubikey:
  algorithm: "rsa2048"
  slot: "9a"
  touch_policy: "always"

vault:
  vault_address: "https://vault.example.com:8200"
`
	configFile := filepath.Join(tmpDir, "test-config.yaml")
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	// Set environment variables
	t.Setenv(EnvYubikeyAlgorithm, "ec384")
	t.Setenv(EnvYubikeySlot, "9c")
	t.Setenv(EnvYubikeyTouchPolicy, "never")
	t.Setenv(EnvVaultAddress, "https://override.example.com:8200")
	t.Setenv(EnvVaultPKIMount, "pki-override")
	t.Setenv(EnvVaultPKIRole, "role-override")
	t.Setenv(EnvVaultCertAuthMount, "cert-override")
	t.Setenv(EnvVaultCertAuthRole, "cert-role-override")

	// Load config
	config, err := LoadConfig(&configFile)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// Environment variables should override file values
	if config.Yubikey.Algorithm != "ec384" {
		t.Errorf("Expected Algorithm 'ec384' from env, got '%s'", config.Yubikey.Algorithm)
	}
	if config.Yubikey.Slot != "9c" {
		t.Errorf("Expected Slot '9c' from env, got '%s'", config.Yubikey.Slot)
	}
	if config.Yubikey.TouchPolicy != "never" {
		t.Errorf("Expected TouchPolicy 'never' from env, got '%s'", config.Yubikey.TouchPolicy)
	}
	if config.Vault.VaultAddress != "https://override.example.com:8200" {
		t.Errorf("Expected VaultAddress from env, got '%s'", config.Vault.VaultAddress)
	}
	if config.Vault.PKIMount != "pki-override" {
		t.Errorf("Expected PKIMount from env, got '%s'", config.Vault.PKIMount)
	}
	if config.Vault.PKIRole != "role-override" {
		t.Errorf("Expected PKIRole from env, got '%s'", config.Vault.PKIRole)
	}
	if config.Vault.CertAuthPath != "cert-override" {
		t.Errorf("Expected CertAuthPath from env, got '%s'", config.Vault.CertAuthPath)
	}
	if config.Vault.CertAuthRole != "cert-role-override" {
		t.Errorf("Expected CertAuthRole from env, got '%s'", config.Vault.CertAuthRole)
	}
}

func TestParseYubikeySettings_Slots(t *testing.T) {
	tests := []struct {
		name     string
		slot     string
		expected piv.Slot
	}{
		{"9a", "9a", piv.SlotAuthentication},
		{"authentication", "authentication", piv.SlotAuthentication},
		{"auth", "auth", piv.SlotAuthentication},
		{"9c", "9c", piv.SlotSignature},
		{"signature", "signature", piv.SlotSignature},
		{"sign", "sign", piv.SlotSignature},
		{"9d", "9d", piv.SlotKeyManagement},
		{"key-management", "key-management", piv.SlotKeyManagement},
		{"keymgmt", "keymgmt", piv.SlotKeyManagement},
		{"9e", "9e", piv.SlotCardAuthentication},
		{"card-authentication", "card-authentication", piv.SlotCardAuthentication},
		{"cardauth", "cardauth", piv.SlotCardAuthentication},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the independent ParseSlot function directly
			result, err := ParseSlot(tt.slot)
			if err != nil {
				t.Errorf("ParseSlot failed for slot '%s': %v", tt.slot, err)
			}
			if result != tt.expected {
				t.Errorf("Expected SlotParsed %v for slot '%s', got %v", tt.expected, tt.slot, result)
			}

			// Also test through the Config method for backward compatibility
			config := &Config{
				Yubikey: YubikeyConfig{
					Slot:        tt.slot,
					Algorithm:   DefaultYubikeyAlgorithm,
					TouchPolicy: DefaultYubikeyTouchPolicy,
				},
			}
			err = config.parseYubikeySettings()
			if err != nil {
				t.Errorf("parseYubikeySettings failed for slot '%s': %v", tt.slot, err)
			}
			if config.Yubikey.SlotParsed != tt.expected {
				t.Errorf("Expected SlotParsed %v for slot '%s', got %v", tt.expected, tt.slot, config.Yubikey.SlotParsed)
			}
		})
	}
}

func TestParseYubikeySettings_Algorithms(t *testing.T) {
	tests := []struct {
		name     string
		algo     string
		expected piv.Algorithm
	}{
		{"ec256", "ec256", piv.AlgorithmEC256},
		{"ec256p", "ec256p", piv.AlgorithmEC256},
		{"p256", "p256", piv.AlgorithmEC256},
		{"ecdsa-p256", "ecdsa-p256", piv.AlgorithmEC256},
		{"ec384", "ec384", piv.AlgorithmEC384},
		{"ec384p", "ec384p", piv.AlgorithmEC384},
		{"p384", "p384", piv.AlgorithmEC384},
		{"ecdsa-p384", "ecdsa-p384", piv.AlgorithmEC384},
		{"rsa1024", "rsa1024", piv.AlgorithmRSA1024},
		{"rsa2048", "rsa2048", piv.AlgorithmRSA2048},
		{"rsa", "rsa", piv.AlgorithmRSA2048},
		{"rsa3072", "rsa3072", piv.AlgorithmRSA3072},
		{"rsa4096", "rsa4096", piv.AlgorithmRSA4096},
		{"ed25519", "ed25519", piv.AlgorithmEd25519},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the independent ParseAlgorithm function directly
			result, err := ParseAlgorithm(tt.algo)
			if err != nil {
				t.Errorf("ParseAlgorithm failed for algorithm '%s': %v", tt.algo, err)
			}
			if result != tt.expected {
				t.Errorf("Expected AlgorithmParsed %v for algorithm '%s', got %v", tt.expected, tt.algo, result)
			}

			// Also test through the Config method for backward compatibility
			config := &Config{
				Yubikey: YubikeyConfig{
					Slot:        DefaultYubikeySlot,
					Algorithm:   tt.algo,
					TouchPolicy: DefaultYubikeyTouchPolicy,
				},
			}
			err = config.parseYubikeySettings()
			if err != nil {
				t.Errorf("parseYubikeySettings failed for algorithm '%s': %v", tt.algo, err)
			}
			if config.Yubikey.AlgorithmParsed != tt.expected {
				t.Errorf("Expected AlgorithmParsed %v for algorithm '%s', got %v", tt.expected, tt.algo, config.Yubikey.AlgorithmParsed)
			}
		})
	}
}

func TestParseYubikeySettings_TouchPolicies(t *testing.T) {
	tests := []struct {
		name     string
		policy   string
		expected piv.TouchPolicy
	}{
		{"always", "always", piv.TouchPolicyAlways},
		{"true", "true", piv.TouchPolicyAlways},
		{"1", "1", piv.TouchPolicyAlways},
		{"yes", "yes", piv.TouchPolicyAlways},
		{"touch", "touch", piv.TouchPolicyAlways},
		{"never", "never", piv.TouchPolicyNever},
		{"false", "false", piv.TouchPolicyNever},
		{"0", "0", piv.TouchPolicyNever},
		{"no", "no", piv.TouchPolicyNever},
		{"no-touch", "no-touch", piv.TouchPolicyNever},
		{"cached", "cached", piv.TouchPolicyCached},
		{"cache", "cache", piv.TouchPolicyCached},
		{"once", "once", piv.TouchPolicyCached},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the independent ParseTouchPolicy function directly
			result, err := ParseTouchPolicy(tt.policy)
			if err != nil {
				t.Errorf("ParseTouchPolicy failed for touch policy '%s': %v", tt.policy, err)
			}
			if result != tt.expected {
				t.Errorf("Expected TouchPolicyParsed %v for policy '%s', got %v", tt.expected, tt.policy, result)
			}

			// Also test through the Config method for backward compatibility
			config := &Config{
				Yubikey: YubikeyConfig{
					Slot:        DefaultYubikeySlot,
					Algorithm:   DefaultYubikeyAlgorithm,
					TouchPolicy: tt.policy,
				},
			}
			err = config.parseYubikeySettings()
			if err != nil {
				t.Errorf("parseYubikeySettings failed for touch policy '%s': %v", tt.policy, err)
			}
			if config.Yubikey.TouchPolicyParsed != tt.expected {
				t.Errorf("Expected TouchPolicyParsed %v for policy '%s', got %v", tt.expected, tt.policy, config.Yubikey.TouchPolicyParsed)
			}
		})
	}
}

func TestParseYubikeySettings_InvalidValues(t *testing.T) {
	tests := []struct {
		name    string
		slot    string
		algo    string
		policy  string
		wantErr bool
		errMsg  string
	}{
		{"Invalid Slot", "99", DefaultYubikeyAlgorithm, DefaultYubikeyTouchPolicy, true, "invalid yubikey slot"},
		{"Invalid Algorithm", DefaultYubikeySlot, "invalid", DefaultYubikeyTouchPolicy, true, "invalid algorithm"},
		{"Invalid Touch Policy", DefaultYubikeySlot, DefaultYubikeyAlgorithm, "invalid", true, "invalid touch policy"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test through the Config method for backward compatibility
			config := &Config{
				Yubikey: YubikeyConfig{
					Slot:        tt.slot,
					Algorithm:   tt.algo,
					TouchPolicy: tt.policy,
				},
			}
			err := config.parseYubikeySettings()
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.errMsg)
				} else if !contains(err.Error(), tt.errMsg) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
			}

			// Also test the independent parsing functions
			if tt.slot != DefaultYubikeySlot {
				_, err := ParseSlot(tt.slot)
				if err == nil {
					t.Errorf("ParseSlot: Expected error for invalid slot '%s'", tt.slot)
				}
			}
			if tt.algo != DefaultYubikeyAlgorithm {
				_, err := ParseAlgorithm(tt.algo)
				if err == nil {
					t.Errorf("ParseAlgorithm: Expected error for invalid algorithm '%s'", tt.algo)
				}
			}
			if tt.policy != DefaultYubikeyTouchPolicy {
				_, err := ParseTouchPolicy(tt.policy)
				if err == nil {
					t.Errorf("ParseTouchPolicy: Expected error for invalid touch policy '%s'", tt.policy)
				}
			}
		})
	}
}

func TestParseYubikeySettings_Whitespace(t *testing.T) {
	config := &Config{
		Yubikey: YubikeyConfig{
			Slot:        "  9a  ",
			Algorithm:   "  RSA2048  ",
			TouchPolicy: "  ALWAYS  ",
		},
	}
	err := config.parseYubikeySettings()
	if err != nil {
		t.Errorf("parseYubikeySettings failed: %v", err)
	}
	if config.Yubikey.SlotParsed != piv.SlotAuthentication {
		t.Errorf("Expected SlotParsed Authentication, got %v", config.Yubikey.SlotParsed)
	}
	if config.Yubikey.AlgorithmParsed != piv.AlgorithmRSA2048 {
		t.Errorf("Expected AlgorithmParsed RSA2048, got %v", config.Yubikey.AlgorithmParsed)
	}
	if config.Yubikey.TouchPolicyParsed != piv.TouchPolicyAlways {
		t.Errorf("Expected TouchPolicyParsed Always, got %v", config.Yubikey.TouchPolicyParsed)
	}
}

func TestParseManagementKey(t *testing.T) {
	tests := []struct {
		name    string
		hexKey  string
		wantErr bool
		wantKey [24]byte
	}{
		{
			name:    "Valid 48 char hex",
			hexKey:  "0102030405060708090a0b0c0d0e0f101112131415161718",
			wantErr: false,
			wantKey: [24]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24},
		},
		{
			name:    "Valid with spaces",
			hexKey:  "01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18",
			wantErr: false,
			wantKey: [24]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24},
		},
		{
			name:    "Valid with hyphens",
			hexKey:  "01020304-05060708-090a0b0c-0d0e0f10-11121314-15161718",
			wantErr: false,
			wantKey: [24]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24},
		},
		{
			name:    "Invalid hex string",
			hexKey:  "gggggggggggggggggggggggggggggggggggggggggggggggg",
			wantErr: true,
		},
		{
			name:    "Too short",
			hexKey:  "0102030405060708090a0b0c0d0e0f1011121314151617",
			wantErr: true,
		},
		{
			name:    "Too long",
			hexKey:  "0102030405060708090a0b0c0d0e0f10111213141516171819",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ParseManagementKey(tt.hexKey)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
				if key != tt.wantKey {
					t.Errorf("Expected key %v, got %v", tt.wantKey, key)
				}
			}
		})
	}
}

func TestGetters(t *testing.T) {
	config := &Config{
		Yubikey: YubikeyConfig{
			SlotParsed:        piv.SlotKeyManagement,
			AlgorithmParsed:   piv.AlgorithmEC384,
			TouchPolicyParsed: piv.TouchPolicyCached,
		},
	}

	if config.GetSlot() != piv.SlotKeyManagement {
		t.Errorf("GetSlot() = %v, want %v", config.GetSlot(), piv.SlotKeyManagement)
	}
	if config.GetAlgorithm() != piv.AlgorithmEC384 {
		t.Errorf("GetAlgorithm() = %v, want %v", config.GetAlgorithm(), piv.AlgorithmEC384)
	}
	if config.GetTouchPolicy() != piv.TouchPolicyCached {
		t.Errorf("GetTouchPolicy() = %v, want %v", config.GetTouchPolicy(), piv.TouchPolicyCached)
	}
}

func TestLoadConfig_WithTildePath(t *testing.T) {
	// Set up a temporary directory to act as home
	tmpDir := t.TempDir()
	oldHome := os.Getenv("HOME")
	t.Cleanup(func() {
		os.Setenv("HOME", oldHome)
	})
	os.Setenv("HOME", tmpDir)

	// Create a config file in the "home" directory
	configContent := `
yubikey:
  algorithm: "ec384"
`
	configFile := filepath.Join(tmpDir, "test-config.yaml")
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	clearTestEnvVars()

	// Load config with tilde path
	tildePath := "~/test-config.yaml"
	config, err := LoadConfig(&tildePath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if config.Yubikey.Algorithm != "ec384" {
		t.Errorf("Expected Algorithm 'ec384', got '%s'", config.Yubikey.Algorithm)
	}
}

func TestCSR_EnvVariables(t *testing.T) {
	tmpDir := t.TempDir()

	// Create empty config file
	configFile := filepath.Join(tmpDir, "test-config.yaml")
	if err := os.WriteFile(configFile, []byte{}, 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	// Set CSR environment variables
	t.Setenv(EnvCSRCommonName, "env.example.com")
	t.Setenv(EnvCSROrganization, "Env Org")
	t.Setenv(EnvCSRCountry, "DE")
	t.Setenv(EnvCSRLocality, "Berlin")
	t.Setenv(EnvCSRDNSNames, "env1.example.com,env2.example.com")

	config, err := LoadConfig(&configFile)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if config.CSR.CommonName != "env.example.com" {
		t.Errorf("Expected CommonName from env, got '%s'", config.CSR.CommonName)
	}
	if config.CSR.Organization != "Env Org" {
		t.Errorf("Expected Organization from env, got '%s'", config.CSR.Organization)
	}
	if config.CSR.Country != "DE" {
		t.Errorf("Expected Country from env, got '%s'", config.CSR.Country)
	}
	if config.CSR.Locality != "Berlin" {
		t.Errorf("Expected Locality from env, got '%s'", config.CSR.Locality)
	}
}

func TestCertificateCommonName(t *testing.T) {
	tmpDir := t.TempDir()

	// Create empty config file
	configFile := filepath.Join(tmpDir, "test-config.yaml")
	if err := os.WriteFile(configFile, []byte{}, 0644); err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	clearTestEnvVars()

	// Note: CertificateCommonName is not populated by LoadConfig from env
	// It's meant to be set directly on the config struct after loading
	// This test verifies that the field exists and can be set

	config, err := LoadConfig(&configFile)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// The field should be empty after LoadConfig
	if config.CSR.CommonName != "" {
		t.Errorf("Expected CertificateCommonName to be empty after LoadConfig, got '%s'", config.CSR.CommonName)
	}

	// But it can be set directly
	config.CSR.CommonName = "test.example.com"
	if config.CSR.CommonName != "test.example.com" {
		t.Errorf("Expected CertificateCommonName to be settable, got '%s'", config.CSR.CommonName)
	}
}

func TestParseSlot(t *testing.T) {
	tests := []struct {
		name    string
		slot    string
		wantErr bool
	}{
		// Valid inputs
		{"9a", "9a", false},
		{"authentication", "authentication", false},
		{"auth", "auth", false},
		{"9c", "9c", false},
		{"signature", "signature", false},
		{"sign", "sign", false},
		{"9d", "9d", false},
		{"key-management", "key-management", false},
		{"keymgmt", "keymgmt", false},
		{"9e", "9e", false},
		{"card-authentication", "card-authentication", false},
		{"cardauth", "cardauth", false},
		// Invalid inputs
		{"invalid", "99", true},
		{"empty", "", true},
		{"unknown", "unknown", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseSlot(tt.slot)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error for slot '%s', got nil", tt.slot)
				}
			} else {
				if err != nil {
					t.Errorf("ParseSlot failed for slot '%s': %v", tt.slot, err)
				}
				var zeroSlot piv.Slot
				if result == zeroSlot {
					t.Errorf("Expected non-zero slot for valid input '%s', got %v", tt.slot, result)
				}
			}
		})
	}
}

func TestParseAlgorithm(t *testing.T) {
	tests := []struct {
		name    string
		algo    string
		wantErr bool
	}{
		// Valid inputs
		{"ec256", "ec256", false},
		{"ec256p", "ec256p", false},
		{"p256", "p256", false},
		{"ecdsa-p256", "ecdsa-p256", false},
		{"ec384", "ec384", false},
		{"ec384p", "ec384p", false},
		{"p384", "p384", false},
		{"ecdsa-p384", "ecdsa-p384", false},
		{"rsa1024", "rsa1024", false},
		{"rsa2048", "rsa2048", false},
		{"rsa", "rsa", false},
		{"rsa3072", "rsa3072", false},
		{"rsa4096", "rsa4096", false},
		{"ed25519", "ed25519", false},
		// Invalid inputs
		{"invalid", "invalid", true},
		{"empty", "", true},
		{"unknown", "unknown", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseAlgorithm(tt.algo)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error for algorithm '%s', got nil", tt.algo)
				}
			} else {
				if err != nil {
					t.Errorf("ParseAlgorithm failed for algorithm '%s': %v", tt.algo, err)
				}
				var zeroAlgorithm piv.Algorithm
				if result == zeroAlgorithm {
					t.Errorf("Expected non-zero algorithm for valid input '%s', got %v", tt.algo, result)
				}
			}
		})
	}
}

func TestParseTouchPolicy(t *testing.T) {
	tests := []struct {
		name    string
		policy  string
		wantErr bool
	}{
		// Valid inputs
		{"always", "always", false},
		{"true", "true", false},
		{"1", "1", false},
		{"yes", "yes", false},
		{"touch", "touch", false},
		{"never", "never", false},
		{"false", "false", false},
		{"0", "0", false},
		{"no", "no", false},
		{"no-touch", "no-touch", false},
		{"cached", "cached", false},
		{"cache", "cache", false},
		{"once", "once", false},
		// Invalid inputs
		{"invalid", "invalid", true},
		{"empty", "", true},
		{"unknown", "unknown", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseTouchPolicy(tt.policy)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error for touch policy '%s', got nil", tt.policy)
				}
			} else {
				if err != nil {
					t.Errorf("ParseTouchPolicy failed for touch policy '%s': %v", tt.policy, err)
				}
				var zeroTouchPolicy piv.TouchPolicy
				if result == zeroTouchPolicy {
					t.Errorf("Expected non-zero touch policy for valid input '%s', got %v", tt.policy, result)
				}
			}
		})
	}
}

// Helper functions

func clearTestEnvVars() {
	envVars := []string{
		EnvConfigFile,
		EnvVaultAddress,
		EnvVaultPKIMount,
		EnvVaultPKIRole,
		EnvVaultCertAuthMount,
		EnvVaultCertAuthRole,
		EnvVaultCAFile,
		EnvVaultSkipVerify,
		EnvYubikeyAlgorithm,
		EnvYubikeySlot,
		EnvYubikeyTouchPolicy,
		EnvCertificateCommonName,
		EnvCSRCommonName,
		EnvCSROrganization,
		EnvCSROrganizationalUnit,
		EnvCSRCountry,
		EnvCSRLocality,
		EnvCSRProvince,
		EnvCSRStreetAddress,
		EnvCSRPostalCode,
		EnvCSRDNSNames,
		EnvCSREmailAddresses,
		EnvCSRIPAddresses,
		EnvCSRURIs,
	}
	for _, env := range envVars {
		os.Unsetenv(env)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
