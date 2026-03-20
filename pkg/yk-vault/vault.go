// Copyright (C) 2026 Ioannis Torakis <john.torakis@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only.txt

package ykvault

import (
	"fmt"

	"github.com/hashicorp/vault/api"

	"github.com/operatorequals/vault-yubikey/pkg/config"
)

func GetVaultClient(cfg *config.Config) (*api.Client, error) {

	vaultCfg := api.DefaultConfig()
	vaultCfg.Address = cfg.Vault.VaultAddress
	vaultCfg.ConfigureTLS(&api.TLSConfig{
		CACert:   cfg.Vault.CAFile,
		Insecure: cfg.Vault.SkipVerify,
	})

	client, err := api.NewClient(vaultCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	return client, nil
}
