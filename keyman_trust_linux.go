package keyman

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

var (
	nssDBs = []string{
		filepath.Join(os.Getenv("HOME"), ".pki/nssdb"),
		filepath.Join(os.Getenv("HOME"), "snap/chromium/current/.pki/nssdb"), // Snapcraft
		"/etc/pki/nssdb", // CentOS 7
	}
	FirefoxProfile = os.Getenv("HOME") + "/.mozilla/firefox/*"
)

func DeleteTrustedRootByName(commonName string, prompt string) error {
	return forEachNSSProfile(func(profile string) error {
		cmd := exec.Command("certutil", "-d", profile, "-D", "-n", commonName)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("Unable to run certutil command: %s\n%s", err, out)
		}
		return nil
	})
}

// AddAsTrustedRoot adds the certificate to the user's trust store as a trusted
// root CA. Supports Chrome and Firefox
func (cert *Certificate) AddAsTrustedRoot(prompt string) error {
	tempFileName, err := cert.WriteToTempFile()
	defer os.Remove(tempFileName)
	if err != nil {
		return fmt.Errorf("Unable to create temp file: %s", err)
	}

	return forEachNSSProfile(func(profile string) error {
		// Add it as a trusted cert
		// https://code.google.com/p/chromium/wiki/LinuxCertManagement#Add_a_certificate
		cmd := exec.Command("certutil", "-d", profile, "-A", "-t", "C,,", "-n", cert.X509().Subject.CommonName, "-i", tempFileName)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("Unable to run certutil command: %s\n%s", err, out)
		}
		return nil
	})
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func forEachNSSProfile(f func(profile string) error) error {
	profiles, _ := filepath.Glob(FirefoxProfile)
	profiles = append(profiles, nssDBs...)
	for _, profile := range profiles {
		if stat, err := os.Stat(profile); err != nil || !stat.IsDir() {
			continue
		}
		if pathExists(filepath.Join(profile, "cert9.db")) {
			if err := f("sql:" + profile); err != nil {
				return err
			}
		} else if pathExists(filepath.Join(profile, "cert8.db")) {
			if err := f("dbm:" + profile); err != nil {
				return err
			}
		}
	}
	return nil
}

// IsInstalled checks whether this certificate is install based purely on looking for a cert
// in the user's nssdb that has the same common name.  This function returns
// true if there are one or more certs in the nssdb whose common name
// matches this cert.
func (cert *Certificate) IsInstalled() (bool, error) {
	found := false
	err := forEachNSSProfile(func(profile string) error {
		cmd := exec.Command("certutil", "-d", profile, "-L", "-n", cert.X509().Subject.CommonName)
		err := cmd.Run()

		if err == nil {
			found = true
		}
		return nil
	})

	return found, err
}
