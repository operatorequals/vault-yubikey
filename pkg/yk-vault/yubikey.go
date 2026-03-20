// Copyright (C) 2026 Ioannis Torakis <john.torakis@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only.txt

package ykvault

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"time"

	backoff "github.com/cenkalti/backoff/v4"
	"github.com/go-piv/piv-go/v2/piv"
)

// CheckYubikey checks if a YubiKey is connected and can be accessed
func CheckYubikey() error {
	yubikey, err := GetYubikey()
	if err != nil {
		return fmt.Errorf("failed to open YubiKey: %w", err)
	}
	defer yubikey.Close()

	// Try to get the device info to verify it's working
	_, err = yubikey.Serial()
	if err != nil {
		return fmt.Errorf("failed to get YubiKey serial: %w", err)
	}

	log.Println("YubiKey detected and accessible")
	return nil
}

// GetYubikey connects to a YubiKey with retry logic
func GetYubikey() (*piv.YubiKey, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, fmt.Errorf("failed to list smart cards: %w", err)
	}

	if len(cards) == 0 {
		return nil, errors.New("no YubiKey or smart card found. Please ensure your YubiKey is connected")
	}

	log.Printf("Found %d smart card(s):\n", len(cards))
	for i, card := range cards {
		fmt.Printf("  %d: %s\n", i+1, card)
	}

	// Try to open YubiKey with exponential backoff retry
	var yubikey *piv.YubiKey
	err = retryWithBackoff(func() error {
		var err error
		// Using shared Yubikey access
		// https://github.com/go-piv/piv-go/pull/182
		pivClient := piv.Client{
			Shared: true,
			Rand:   rand.Reader,
		}
		yubikey, err = pivClient.Open(cards[0])
		return err
	}, 10*time.Second)

	if err != nil {
		return nil, err
	}

	log.Printf("Connected to %s\n", cards[0])
	return yubikey, nil
}

// ListYubikeys lists all connected YubiKeys
func ListYubikeys() error {
	cards, err := piv.Cards()
	if err != nil {
		return fmt.Errorf("failed to list YubiKeys: %w", err)
	}

	if len(cards) == 0 {
		log.Println("No YubiKeys found")
		return nil
	}

	log.Printf("Found %d YubiKey(s):\n", len(cards))
	for i, card := range cards {
		log.Printf("  %d: %s\n", i+1, card)
	}

	return nil
}

// retryWithBackoff retries a function with exponential backoff
func retryWithBackoff(operation func() error, maxElapsedTime time.Duration) error {
	backoffStrategy := backoff.NewExponentialBackOff()
	backoffStrategy.MaxElapsedTime = maxElapsedTime

	return backoff.Retry(operation, backoffStrategy)
}
