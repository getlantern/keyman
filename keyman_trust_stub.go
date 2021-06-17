// +build !darwin,!windows,!linux

package keyman

import (
	"fmt"
)

func DeleteTrustedRootByName(commonName string, prompt string) error {
	return fmt.Errorf("DeleteTrustedRootByName is not supported on this platform")
}

// AddAsTrustedRoot adds the certificate to the user's trust store as a trusted
// root CA. If elevatePrompt is provided, privilege escalation will be requested (if
// required) and the user will be prompted with the given text.
// returns true if any actual changes were made
func (cert *Certificate) AddAsTrustedRootIfNeeded(elevatePrompt, installPromptTitle, installPromptContent string) (bool, error) {
	return false, fmt.Errorf("AddAsTrustedRootIfNeeded is not supported on this platform")
}
