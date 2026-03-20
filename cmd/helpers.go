// Copyright (C) 2026 Ioannis Torakis <john.torakis@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only.txt

// GatePlane/vault-yubikey-ng/cmd/helpers.go
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// promptForYesNo prompts the user for a yes/no response and returns a boolean
func promptForYesNo(prompt string) (bool, error) {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Printf("%s [y/n]: ", prompt)

		response, err := reader.ReadString('\n')
		if err != nil {
			return false, fmt.Errorf("failed to read response: %w", err)
		}

		response = strings.TrimSpace(strings.ToLower(response))
		switch response {
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		default:
			fmt.Println("Please enter 'y' or 'n'")
		}
	}
}

// promptForInput prompts the user for input and returns the entered value
func promptForInput(prompt string) (string, error) {
	fmt.Print(prompt)
	input, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	fmt.Println() // Add newline after password input
	return strings.TrimSpace(string(input)), nil
}
