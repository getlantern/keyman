package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/getlantern/keyman"
)

const (
	commonName = "trustdemo.getlantern.org"
)

func main() {
	pk, err := keyman.GeneratePK(2048)
	if err != nil {
		log.Fatalf("Unable to generate PK: %v", err)
	}

	cert, err := pk.TLSCertificateFor(time.Now().Add(24*time.Hour), false, nil, "Lantern", commonName, "san1.com", "san2.com")
	if err != nil {
		log.Fatalf("Unable to generate certificate: %v", err)
	}

	if err = cert.AddAsTrustedRootIfNeeded(fmt.Sprintf("Please allow trustdemo to install a certificate for %v", commonName), "Prompt Title", "Prompt Body", func(err error) {
		fmt.Printf("Cert installation attempted with resut: %v", err)
	}); err != nil {
		log.Fatalf("Unable to add as trusted root: %v", err)
	}

	in := bufio.NewReader(os.Stdin)
	fmt.Printf("Installed certificate with common name %v, hit Enter to continue ...", commonName)
	in.ReadString('\n')

	err = keyman.DeleteTrustedRootByName(commonName, fmt.Sprintf("Please allow trustdemo to uninstall the certificate for %v", commonName))
	if err != nil {
		log.Fatalf("Unable to delete trusted root: %v", err)
	}
	fmt.Printf("Uninstalled certificate with common name %v", commonName)
}
