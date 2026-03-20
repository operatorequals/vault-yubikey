// Copyright (C) 2026 Ioannis Torakis <john.torakis@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only.txt

package main

import (
	"fmt"
	"os"

	"github.com/operatorequals/vault-yubikey/pkg/config"
	ykvault "github.com/operatorequals/vault-yubikey/pkg/yk-vault"
	"github.com/spf13/cobra"
)

var configFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "vault-yubikey",
	Short: "A tool for managing Vault authentication using YubiKey",
	Long: `vault-yubikey is a CLI tool that helps you manage HashiCorp Vault / OpenBao
authentication using YubiKey certificates. It supports registering new certificates
with Vault and logging in using existing certificates stored on your YubiKey.`,
}

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate to Vault using YubiKey certificate",
	Long: `Login to Vault using a certificate stored on your YubiKey.
This command will:
1. Connect to your YubiKey
2. Retrieve the certificate from the configured slot
3. Authenticate to Vault using mutual TLS
4. Store the received token locally`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Load configuration
		cfg, err := config.LoadConfig(&configFile)
		if err != nil {
			return fmt.Errorf("failed to load configuration: %w", err)
		}

		// Get PIN from flag or prompt
		pin, err := cmd.Flags().GetString("pin")
		if err != nil {
			return fmt.Errorf("failed to get PIN flag: %w", err)
		}

		if pin == "" {
			pin, err = promptForInput("Enter YubiKey PIN: ")
			if err != nil {
				return fmt.Errorf("failed to read PIN: %w", err)
			}
			if pin == "" {
				return fmt.Errorf("PIN is required")
			}
		}

		// Perform login
		return ykvault.Login(cfg, pin)
	},
}

// registerCmd represents the register command
var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Register a new certificate with Vault",
	Long: `Generate a new key pair on your YubiKey, create a certificate signing request,
sign it with Vault, and store the resulting certificate on the YubiKey.

This command will:
1. Connect to your YubiKey
2. Generate a new key pair in the configured slot
3. Create a Certificate Signing Request (CSR)
4. Send the CSR to Vault for signing
5. Store the signed certificate on the YubiKey`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Load configuration
		cfg, err := config.LoadConfig(&configFile)
		if err != nil {
			return fmt.Errorf("failed to load configuration: %w", err)
		}

		// Get required flags
		pin, err := cmd.Flags().GetString("pin")
		if err != nil {
			return fmt.Errorf("failed to get PIN flag: %w", err)
		}

		managementKey, err := cmd.Flags().GetString("management-key")
		if err != nil {
			return fmt.Errorf("failed to get management key flag: %w", err)
		}

		commonName, err := cmd.Flags().GetString("common-name")
		if err != nil {
			return fmt.Errorf("failed to get common name flag: %w", err)
		}
		// Override CN from the
		if commonName == "" {
			if cfg.CSR.CommonName == "" {
				return fmt.Errorf("A Common Name (CN) is needed and not provided")
			}
		} else {
			cfg.CSR.CommonName = commonName
		}

		cfg.PrintConfigSummary()

		// Prompt for confirmation
		confirmed, err := promptForYesNo("Do you want to proceed with these settings?")
		if err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}
		if !confirmed {
			fmt.Println("Registration cancelled.")
			return nil
		}

		if pin == "" {
			pin, err = promptForInput("Enter YubiKey PIN: ")
			if err != nil {
				return fmt.Errorf("failed to read PIN: %w", err)
			}
			if pin == "" {
				return fmt.Errorf("PIN is required")
			}
		}

		if managementKey == "" {
			managementKey, err = promptForInput("Enter YubiKey management key (48 hex characters): ")
			if err != nil {
				return fmt.Errorf("failed to read management key: %w", err)
			}
			if managementKey == "" {
				return fmt.Errorf("management key is required")
			}
		}

		// Perform registration
		_, err = ykvault.NewCertificate(cfg, pin, managementKey, commonName)
		return err
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	// Root command flags
	rootCmd.PersistentFlags().StringVar(&configFile, "config", "", "Path to config file (default: ~/.vault-yubikey.yaml)")

	// Login command flags
	loginCmd.Flags().String("pin", "", "YubiKey PIN (required)")
	loginCmd.Flags().String("pin-env", "VAULT_YUBIKEY_PIN", "Environment variable containing YubiKey PIN")

	// Register command flags
	registerCmd.Flags().String("pin", "", "YubiKey PIN (required)")
	registerCmd.Flags().String("pin-env", "VAULT_YUBIKEY_PIN", "Environment variable containing YubiKey PIN")
	registerCmd.Flags().String("management-key", "", "YubiKey management key in hex format (48 hex characters, required)")
	registerCmd.Flags().String("management-key-env", "VAULT_YUBIKEY_MANAGEMENT_KEY", "Environment variable containing YubiKey management key")
	registerCmd.Flags().String("common-name", "", "Certificate Common Name (overrides config file)")

	// Add commands to root
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(registerCmd)

	// Pre-run hooks to read PIN from environment if not provided via flag
	loginCmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		pin, _ := cmd.Flags().GetString("pin")
		pinEnv, _ := cmd.Flags().GetString("pin-env")
		if pin == "" && pinEnv != "" {
			if envPin := os.Getenv(pinEnv); envPin != "" {
				return cmd.Flags().Set("pin", envPin)
			}
		}
		return nil
	}

	registerCmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		pin, _ := cmd.Flags().GetString("pin")
		pinEnv, _ := cmd.Flags().GetString("pin-env")
		if pin == "" && pinEnv != "" {
			if envPin := os.Getenv(pinEnv); envPin != "" {
				return cmd.Flags().Set("pin", envPin)
			}
		}

		managementKey, _ := cmd.Flags().GetString("management-key")
		managementKeyEnv, _ := cmd.Flags().GetString("management-key-env")
		if managementKey == "" && managementKeyEnv != "" {
			if envManagementKey := os.Getenv(managementKeyEnv); envManagementKey != "" {
				return cmd.Flags().Set("management-key", envManagementKey)
			}
		}
		return nil
	}
}

func main() {
	Execute()
}
