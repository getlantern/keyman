package keyman

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
)

// AddAsTrustedRoot adds the certificate to the user's trust store as a trusted
// root CA.
func (cert *Certificate) AddAsTrustedRoot() error {
	// Create a temp file containing the certificate
	tempFile, err := ioutil.TempFile("", "tempCert")
	defer os.Remove(tempFile.Name())
	if err != nil {
		return fmt.Errorf("Unable to create temp file: %s", err)
	}
	err = cert.WriteToFile(tempFile.Name())
	if err != nil {
		return fmt.Errorf("Unable to save certificate to temp file: %s", err)
	}

	nssdb, err := getUserNssdb()
	if err != nil {
		return err
	}

	// Add it as a trusted cert
	// https://code.google.com/p/chromium/wiki/LinuxCertManagement#Add_a_certificate
	cmd := exec.Command("certutil", "-d", nssdb, "-A", "-t", "C,,", "-n", cert.X509().Subject.CommonName, "-i", tempFile.Name())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Unable to run certutil command: %s\n%s", err, out)
	} else {
		return nil
	}
}

// Checks whether this certificate is install based purely on looking for a cert
// in the user's nssdb that has the same common name.  This function returns
// true if there are one or more certs in the nssdb whose common name
// matches this cert.
func (cert *Certificate) IsInstalled() (bool, error) {
	nssdb, err := getUserNssdb()
	if err != nil {
		return false, err
	}

	cmd := exec.Command("certutil", "-d", nssdb, "-L", "-n", cert.X509().Subject.CommonName)
	err = cmd.Run()
	return err == nil, nil
}

func getUserNssdb() (string, error) {
	// get the user's home dir
	usr, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("Unable to get current user: %s", err)
	}
	return "sql:" + usr.HomeDir + "/.pki/nssdb", nil
}
