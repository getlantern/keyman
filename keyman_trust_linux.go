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
			return fmt.Errorf("Unable to run certutil command: %w\n%s", err, out)
		}
		return nil
	})
}

func (cert *Certificate) isInstalled(profile string) bool {
	cmd := exec.Command("certutil", "-d", profile, "-L", "-n", cert.X509().Subject.CommonName)
	err := cmd.Run()

	return err == nil
}

// AddAsTrustedRootIfNeeded adds the certificate to the user's trust store as a trusted
// root CA. Supports Chrome and Firefox
// elevatePrompt, installPromptTitle, installPromptContent are ignored, kept for API compatibility with other platforms
// If installAttempted is provided it will be called on any attempt to modify system cert store
func (cert *Certificate) AddAsTrustedRootIfNeeded(elevatePrompt, installPromptTitle, installPromptContent string, installAttempted func(error)) error {
	tempFileName, err := cert.WriteToTempFile()
	defer func() {
		if err := os.Remove(tempFileName); err != nil {
			log.Debugf("Unable to remove file: %v", err)
		}
	}()
	if err != nil {
		return fmt.Errorf("Unable to create temp file: %s", err)
	}
	return forEachNSSProfile(func(profile string) error {
		if !cert.isInstalled(profile) {
			// Add it as a trusted cert
			// https://code.google.com/p/chromium/wiki/LinuxCertManagement#Add_a_certificate
			cmd := exec.Command("certutil", "-d", profile, "-A", "-t", "C,,", "-n", cert.X509().Subject.CommonName, "-i", tempFileName)
			out, err := cmd.CombinedOutput()
			if installAttempted != nil {
				installAttempted(err)
			}
			if err != nil {
				return fmt.Errorf("Unable to run certutil command: %w\n%s", err, out)
			}
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
