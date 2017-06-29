package keyman

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
)

// InstallToUserKeyChain adds the certificate to the user's keychain.
func (cert *Certificate) InstallToUserKeyChain() error {
	tempFileName, err := cert.WriteToTempFile()
	defer func() {
		if err := os.Remove(tempFileName); err != nil {
			log.Debugf("Unable to remove file: %v", err)
		}
	}()
	if err != nil {
		return fmt.Errorf("Unable to create temp file: %s", err)
	}

	// Add it as a trusted cert
	cmd := exec.Command("security", "add-trusted-cert", "-k", keychainPath(), tempFileName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Unable to run security command: %s\n%s", err, out)
	} else {
		return nil
	}
}

// Checks whether this certificate is install based purely on looking for a cert
// in the system keychain that has the same common name.  This function returns
// true if there are one or more certs in the system keychain whose common name
// matches this cert.
func (cert *Certificate) IsInstalled() (bool, error) {
	cmd := exec.Command("security", "find-certificate", "-c", cert.X509().Subject.CommonName, keychainPath())
	err := cmd.Run()

	found := err == nil
	return found, nil
}

func keychainPath() string {
	usr, _ := user.Current()
	return filepath.Join(usr.HomeDir, "Library", "Keychains", "login.keychain")
}
