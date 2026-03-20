// Copyright (C) 2026 Ioannis Torakis <john.torakis@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only.txt

package ykvault

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-piv/piv-go/v2/piv"
	"github.com/hashicorp/vault/api"

	"github.com/operatorequals/vault-yubikey/pkg/config"
)

const (
	vaultTokenPath = "~/.vault-token"
)

// Login authenticates to Vault using the certificate stored in YubiKey and stores the token
func Login(cfg *config.Config, pin string) error {

	// Connect to YubiKey
	yubikey, err := GetYubikey()
	if err != nil {
		return fmt.Errorf("failed to open YubiKey: %w", err)
	}
	// Ensure connection is always closed, even on panic
	defer func() {
		if yubikey != nil {
			yubikey.Close()
		}
	}()

	// Get certificate from YubiKey
	slot := cfg.GetSlot()
	cert, err := yubikey.Certificate(slot)
	if err != nil {
		return fmt.Errorf("failed to get certificate from YubiKey: %w", err)
	}

	// Authenticate with Vault using TLS certificate
	token, err := authenticateWithVaultTLS(cfg, cert, yubikey, pin)
	if err != nil {
		return fmt.Errorf("failed to authenticate with Vault: %w", err)
	}

	// Store token to file
	if err := storeToken(token); err != nil {
		return fmt.Errorf("failed to store token: %w", err)
	}

	fmt.Println("Successfully authenticated to Vault and token stored")

	// Close connection explicitly before returning
	yubikey.Close()
	yubikey = nil

	return nil
}

// authenticateWithVaultTLS performs TLS certificate authentication with Vault
func authenticateWithVaultTLS(cfg *config.Config, cert *x509.Certificate, yubikey *piv.YubiKey, pin string) (string, error) {
	slot := cfg.GetSlot()

	fmt.Printf("Accessing the key pair in YubiKey.\n *** Might need to touch the Yubikey *** \n")
	signer, err := yubikey.PrivateKey(slot, cert.PublicKey.(crypto.PublicKey), piv.KeyAuth{PIN: pin})
	if err != nil {
		return "", fmt.Errorf("failed to load Yubikey private key: %w", err)
	}

	// Create a custom HTTP client with the YubiKey certificate
	tlsCert := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  signer,
		Leaf:        cert,
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{tlsCert},
		InsecureSkipVerify: cfg.Vault.SkipVerify,
	}

	// Set CA file if provided
	if cfg.Vault.CAFile != "" {
		caCert, err := os.ReadFile(cfg.Vault.CAFile)
		if err != nil {
			return "", fmt.Errorf("failed to read CA file: %w", err)
		}
		caCertPool := tlsConfig.RootCAs
		if caCertPool == nil {
			caCertPool, err = x509.SystemCertPool()
			if err != nil {
				return "", fmt.Errorf("failed to create system cert pool: %w", err)
			}
		}
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return "", errors.New("failed to append CA certificate to pool")
		}
		tlsConfig.RootCAs = caCertPool
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	httpClient := &http.Client{
		Transport: transport,
	}

	// Create Vault client with custom HTTP client
	vaultCfg := api.DefaultConfig()
	vaultCfg.Address = cfg.Vault.VaultAddress
	vaultCfg.HttpClient = httpClient

	client, err := api.NewClient(vaultCfg)
	if err != nil {
		return "", fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Build the full login path
	loginPath, err := cfg.GetVaultAuthPath()
	if err != nil {
		return "", fmt.Errorf("failed to create Vault auth path: %w", err)
	}

	// Prepare login request
	data := map[string]interface{}{}

	// Add auth role if specified
	if cfg.Vault.CertAuthRole != "" {
		data["name"] = cfg.Vault.CertAuthRole
	}

	// Perform login
	secret, err := client.Logical().Write(loginPath, data)
	if err != nil {
		return "", fmt.Errorf("failed to login to Vault: %w", err)
	}

	if secret == nil || secret.Auth == nil {
		return "", errors.New("Vault returned nil response")
	}

	token := secret.Auth.ClientToken
	if token == "" {
		return "", errors.New("failed to extract token from Vault response")
	}

	return token, nil
}

// storeToken writes the Vault token to the token file
func storeToken(token string) error {
	// Expand ~ to home directory
	tokenPath := vaultTokenPath
	if strings.HasPrefix(tokenPath, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		tokenPath = filepath.Join(home, tokenPath[2:])
	}

	// Write token to file
	err := os.WriteFile(tokenPath, []byte(token), 0600)
	if err != nil {
		return fmt.Errorf("failed to write token file: %w", err)
	}

	return nil
}
