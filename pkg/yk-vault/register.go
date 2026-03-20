// Copyright (C) 2026 Ioannis Torakis <john.torakis@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only.txt

package ykvault

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"

	"github.com/go-piv/piv-go/v2/piv"

	"github.com/operatorequals/vault-yubikey/pkg/config"
)

// NewCertificate generates a key pair in YubiKey, creates a CSR, sends it to Vault for signing,
// and stores the signed certificate in the YubiKey.
func NewCertificate(cfg *config.Config, pin string, managementKey string, certificateCommonName string) (*x509.Certificate, error) {

	// Parse management key
	mgmtKey, err := config.ParseManagementKey(managementKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse management key: %w", err)
	}

	// Connect to YubiKey
	yubikey, err := GetYubikey()
	if err != nil {
		return nil, fmt.Errorf("failed to open YubiKey: %w", err)
	}
	defer func() {
		if yubikey != nil {
			yubikey.Close()
		}
	}()

	// Generate key pair in YubiKey
	slot := cfg.GetSlot()
	algorithm := cfg.GetAlgorithm()
	touchPolicy := cfg.GetTouchPolicy()

	log.Printf("Generating %s key pair in YubiKey. Might take a while...\n", strings.ToUpper(cfg.Yubikey.Algorithm))

	pubKey, err := yubikey.GenerateKey(mgmtKey[:], slot, piv.Key{
		Algorithm:   algorithm,
		PINPolicy:   piv.PINPolicyAlways,
		TouchPolicy: touchPolicy,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate key in YubiKey: %w", err)
	}

	log.Println("Generated key pair in YubiKey")

	log.Printf("Accessing the %s key pair in YubiKey.\n *** Might need to touch the Yubikey *** \n", strings.ToUpper(cfg.Yubikey.Algorithm))

	signer, err := yubikey.PrivateKey(slot, pubKey, piv.KeyAuth{PIN: pin})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve private key from YubiKey: %w", err)
	}

	// Create Certificate Signing Request
	csr, err := createCSR(pubKey, signer.(crypto.Signer), cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	// Sign CSR with Vault
	signedCert, err := signCSRWithVault(cfg, csr)
	if err != nil {
		return nil, fmt.Errorf("failed to sign CSR with Vault: %w", err)
	}

	// Import certificate to YubiKey
	err = yubikey.SetCertificate(mgmtKey[:], slot, signedCert)
	if err != nil {
		return nil, fmt.Errorf("failed to import certificate to YubiKey: %w", err)
	}

	log.Println("Certificate successfully generated and stored in YubiKey")

	return signedCert, nil
}

// createCSR creates a Certificate Signing Request using the public key from YubiKey
func createCSR(pubKey crypto.PublicKey, signer crypto.Signer, cfg *config.Config) (*x509.CertificateRequest, error) {

	subject := pkix.Name{
		CommonName:         cfg.CSR.CommonName,
		Organization:       []string{cfg.CSR.Organization},
		OrganizationalUnit: []string{cfg.CSR.OrganizationalUnit},
		Country:            []string{cfg.CSR.Country},
		Locality:           []string{cfg.CSR.Locality},
		Province:           []string{cfg.CSR.Province},
		StreetAddress:      []string{cfg.CSR.StreetAddress},
		PostalCode:         []string{cfg.CSR.PostalCode},
	}

	// Parse IP addresses from config
	var ipAddresses []net.IP
	for _, ipStr := range cfg.CSR.IPAddresses {
		ip := net.ParseIP(ipStr)
		if ip != nil {
			ipAddresses = append(ipAddresses, ip)
		}
	}

	// Parse URIs from config
	var uris []*url.URL
	for _, uriStr := range cfg.CSR.URIs {
		uri, err := url.Parse(uriStr)
		if err == nil {
			uris = append(uris, uri)
		}
	}

	/*
		// Initialize extra extensions slice
		var extraExtensions []pkix.Extension

		// Create KeyUsage extension
		keyUsageExt, err := CreateKeyUsageExtension(cfg.CSR.KeyUsage)
		if err != nil {
			return nil, fmt.Errorf("failed to create key usage extension: %w", err)
		}
		extraExtensions = append(extraExtensions, keyUsageExt)

		// Create ExtendedKeyUsage extension
		extKeyUsageExt, err := CreateExtendedKeyUsageExtension(cfg.CSR.ExtendedKeyUsage)
		if err != nil {
			return nil, fmt.Errorf("failed to create extended key usage extension: %w", err)
		}
		if extKeyUsageExt.Id != nil {
			extraExtensions = append(extraExtensions, extKeyUsageExt)
		}

		// Create custom extension from extra fields
		if cfg.CSR.Extra != nil && len(cfg.CSR.Extra) > 0 {
			// Encode extra fields as JSON
			extraJSON, err := json.Marshal(cfg.CSR.Extra)
			if err != nil {
				return nil, fmt.Errorf("failed to encode extra fields: %w", err)
			}

			// Create a single extension with all extra fields
			ext := pkix.Extension{
				// Custom OID for vault-yubikey metadata
				Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 53217, 1, 1},
				Critical: false,
				Value:    extraJSON,
			}
			extraExtensions = append(extraExtensions, ext)
		}
	*/

	template := x509.CertificateRequest{
		Subject:        subject,
		DNSNames:       cfg.CSR.DNSNames,
		EmailAddresses: cfg.CSR.EmailAddresses,
		IPAddresses:    ipAddresses,
		URIs:           uris,
		PublicKey:      pubKey,
		// Extensions:     extraExtensions,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	return csr, nil
}

// signCSRWithVault sends the CSR to Vault's PKI backend and returns a signed certificate
func signCSRWithVault(cfg *config.Config, csr *x509.CertificateRequest) (*x509.Certificate, error) {
	// Create Vault client with proper configuration
	client, err := GetVaultClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Encode CSR to PEM format
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr.Raw,
	})

	// Build the full PKI signing path using the config method
	pkiPath, err := cfg.GetVaultPKISignPath()
	if err != nil {
		return nil, fmt.Errorf("failed fetch Vault signing path: %w", err)
	}

	// Prepare request data for Vault PKI sign endpoint
	data := map[string]interface{}{
		"csr":    string(csrPEM),
		"format": "pem",
		"ttl":    cfg.GetCSRTTLString(),
	}

	// Call Vault PKI sign endpoint
	secret, err := client.Logical().Write(pkiPath, data)
	if err != nil {
		return nil, fmt.Errorf("failed to sign CSR with Vault: %w", err)
	}

	if secret == nil {
		return nil, errors.New("Vault returned nil response")
	}

	// Extract certificate from response
	certData, ok := secret.Data["certificate"].(string)
	if !ok {
		return nil, errors.New("failed to extract certificate from Vault response")
	}

	log.Println("Certificate signed!")
	fmt.Println(certData)

	// Parse the PEM certificate
	block, _ := pem.Decode([]byte(certData))
	if block == nil {
		return nil, errors.New("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}
