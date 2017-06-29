package main

import (
	"log"
	"time"

	"github.com/getlantern/keyman"
)

func main() {
	pk, err := keyman.GeneratePK(2048)
	if err != nil {
		log.Fatal(err)
	}

	cert, err := pk.TLSCertificateFor("Lantern", "www.google.com", time.Now().Add(24*time.Hour), false, nil)
	if err != nil {
		log.Fatal(err)
	}

	cert.InstallToUserKeyChain()
}
