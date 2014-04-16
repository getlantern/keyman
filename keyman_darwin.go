package keyman

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
)

func (cert *Certificate) AddToUserTrustStore() error {
	// Get user's home folder
	usr, err := user.Current()
	if err != nil {
		return err
	}
	// Create a temp file containing the certificate
	tempFile, err := ioutil.TempFile("", "tempCert")
	defer os.Remove(tempFile.Name())
	if err != nil {
		return err
	}
	err = cert.WriteToFile(tempFile.Name())
	if err != nil {
		return err
	}
	// Add it as a trusted cert
	cmd := exec.Command("security", "add-trusted-cert", "-k", usr.HomeDir+"/Library/Keychains/login.keychain", tempFile.Name())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Unable to run security command: %s\n%s", err, out)
	} else {
		return nil
	}
}
