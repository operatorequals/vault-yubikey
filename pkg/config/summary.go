// Copyright (C) 2026 Ioannis Torakis <john.torakis@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only.txt

package config

import (
	"fmt"
	"strings"
)

// PrintConfigSummary prints a formatted summary of the configuration
func (c *Config) PrintConfigSummary() {
	fmt.Println("=== Configuration Summary ===")
	fmt.Println()

	// Print CSR Configuration
	fmt.Println("CSR Configuration:")
	fmt.Println("-------------")

	// Print subject information in openssl-like format
	fmt.Print("Subject: ")
	subjectParts := []string{}

	if c.CSR.Country != "" {
		subjectParts = append(subjectParts, fmt.Sprintf("C=%s", c.CSR.Country))
	}
	if c.CSR.Province != "" {
		subjectParts = append(subjectParts, fmt.Sprintf("ST=%s", c.CSR.Province))
	}
	if c.CSR.Locality != "" {
		subjectParts = append(subjectParts, fmt.Sprintf("L=%s", c.CSR.Locality))
	}
	if c.CSR.Organization != "" {
		subjectParts = append(subjectParts, fmt.Sprintf("O=%s", c.CSR.Organization))
	}
	if c.CSR.OrganizationalUnit != "" {
		subjectParts = append(subjectParts, fmt.Sprintf("OU=%s", c.CSR.OrganizationalUnit))
	}
	if c.CSR.CommonName != "" {
		subjectParts = append(subjectParts, fmt.Sprintf("CN=%s", c.CSR.CommonName))
	}

	if len(subjectParts) > 0 {
		fmt.Println(strings.Join(subjectParts, ", "))
	} else {
		fmt.Println("None specified")
	}

	// Print additional subject fields
	if c.CSR.PostalCode != "" {
		fmt.Printf("                Postal Code: %s\n", c.CSR.PostalCode)
	}
	if c.CSR.StreetAddress != "" {
		fmt.Printf("               Street Address: %s\n", c.CSR.StreetAddress)
	}

	// Print SANs
	if len(c.CSR.DNSNames) > 0 {
		fmt.Printf("                DNS Names: %s\n", strings.Join(c.CSR.DNSNames, ", "))
	}
	if len(c.CSR.IPAddresses) > 0 {
		fmt.Printf("              IP Addresses: %s\n", strings.Join(c.CSR.IPAddresses, ", "))
	}
	if len(c.CSR.URIs) > 0 {
		fmt.Printf("                     URIs: %s\n", strings.Join(c.CSR.URIs, ", "))
	}
	if len(c.CSR.EmailAddresses) > 0 {
		fmt.Printf("            Email Addresses: %s\n", strings.Join(c.CSR.EmailAddresses, ", "))
	}

	// Print TTL
	if c.CSR.TTL > 0 {
		fmt.Printf("                       TTL: %s\n", c.CSR.TTL.String())
	}

	// Print Key Usage
	if len(c.CSR.KeyUsage) > 0 {
		fmt.Printf("                  Key Usage: %s\n", strings.Join(c.CSR.KeyUsage, ", "))
	} else {
		fmt.Printf("                  Key Usage: (default) digital-signature, key-encipherment, key-agreement\n")
	}

	// Print Extended Key Usage
	if len(c.CSR.ExtendedKeyUsage) > 0 {
		fmt.Printf("         Extended Key Usage: %s\n", strings.Join(c.CSR.ExtendedKeyUsage, ", "))
	} else {
		fmt.Printf("         Extended Key Usage: (default) client-auth\n")
	}

	// Print extra fields
	if len(c.CSR.Extra) > 0 {
		fmt.Printf("                    Extra: %v\n", c.CSR.Extra)
	}

	fmt.Println()

	// Print Yubikey Configuration
	fmt.Println("Yubikey Configuration:")
	fmt.Println("----------------------")
	fmt.Printf("              Algorithm: %s\n", c.Yubikey.Algorithm)
	fmt.Printf("                   Slot: %s\n", c.Yubikey.Slot)
	fmt.Printf("           Touch Policy: %s\n", c.Yubikey.TouchPolicy)
	fmt.Println()

	// Print Vault Configuration
	fmt.Println("Vault Configuration:")
	fmt.Println("-------------------")

	// Get generated paths
	authPath, err := c.GetVaultAuthPath()
	if err == nil {
		fmt.Printf("        Generated Auth Path: %s\n", authPath)
	}

	signPath, err := c.GetVaultPKISignPath()
	if err == nil {
		fmt.Printf("      Generated PKI Sign Path: %s\n", signPath)
	}

	fmt.Printf("              Vault Address: %s\n", c.Vault.VaultAddress)
	if c.Vault.CertAuthRole != "" {
		fmt.Printf("           Cert Auth Role: %s\n", c.Vault.CertAuthRole)
	}
	if c.Vault.CAFile != "" {
		fmt.Printf("                   CA File: %s\n", c.Vault.CAFile)
	}
	fmt.Printf("              Skip Verify: %t\n", c.Vault.SkipVerify)

	fmt.Println()
	fmt.Println("=== End of Configuration ===")
}
