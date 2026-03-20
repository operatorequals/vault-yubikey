// Copyright (C) 2026 Ioannis Torakis <john.torakis@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only.txt

// GatePlane/vault-yubikey-ng/pkg/yk-vault/helpers.go
package ykvault

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"

	"github.com/operatorequals/vault-yubikey/pkg/config"
)

// CreateKeyUsageExtension creates a KeyUsage extension from config
func CreateKeyUsageExtension(keyUsage []string) (pkix.Extension, error) {
	usage, err := config.ParseKeyUsage(keyUsage)
	if err != nil {
		return pkix.Extension{}, err
	}

	keyUsageBytes, err := asn1.Marshal(usage)
	if err != nil {
		return pkix.Extension{}, err
	}

	return pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 15}, // KeyUsage OID
		Critical: true,
		Value:    keyUsageBytes,
	}, nil
}

// CreateExtendedKeyUsageExtension creates an ExtendedKeyUsage extension from config
func CreateExtendedKeyUsageExtension(extKeyUsages []string) (pkix.Extension, error) {
	usages, err := config.ParseExtendedKeyUsage(extKeyUsages)
	if err != nil {
		return pkix.Extension{}, err
	}

	// Create slice of OIDs from extended key usages
	oids := make([]asn1.ObjectIdentifier, 0, len(usages))
	for _, extKeyUsage := range usages {
		oid := extKeyUsageOID(extKeyUsage)
		if len(oid) > 0 {
			oids = append(oids, oid)
		}
	}

	// If no OIDs were created, return an empty extension
	if len(oids) == 0 {
		return pkix.Extension{}, nil
	}

	extKeyUsageBytes, err := asn1.Marshal(oids)
	if err != nil {
		return pkix.Extension{}, err
	}

	return pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 37}, // ExtendedKeyUsage OID
		Critical: false,
		Value:    extKeyUsageBytes,
	}, nil
}

// extKeyUsageOID returns the ASN.1 OID for a given Extended Key Usage
// by using the standard library's CreateCertificate to resolve the OID
func extKeyUsageOID(eku x509.ExtKeyUsage) asn1.ObjectIdentifier {
	// Create a dummy certificate with the ExtKeyUsage to trigger OID resolution
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		ExtKeyUsage:           []x509.ExtKeyUsage{eku},
		BasicConstraintsValid: true,
	}

	// Use CreateCertificate to generate a certificate with proper OID mapping
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil
	}

	// Parse the certificate to extract the OID from its extensions
	parsedCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil
	}

	// Find the ExtendedKeyUsage extension and extract the OID
	for _, ext := range parsedCert.Extensions {
		if ext.Id.Equal([]int{2, 5, 29, 37}) { // ExtendedKeyUsage OID
			var oids []asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(ext.Value, &oids); err == nil && len(oids) > 0 {
				return oids[0]
			}
		}
	}

	return nil
}
