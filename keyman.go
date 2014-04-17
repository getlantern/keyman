package keyman

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

const (
	PEM_HEADER_PRIVATE_KEY = "RSA PRIVATE KEY"
	PEM_HEADER_PUBLIC_KEY  = "RSA PRIVATE KEY"
	PEM_HEADER_CERTIFICATE = "CERTIFICATE"
)

// PrivateKey is a convenience wrapper for rsa.PrivateKey
type PrivateKey struct {
	rsaKey *rsa.PrivateKey
}

// Certificate is a convenience wrapper for x509.Certificate
type Certificate struct {
	cert     *x509.Certificate
	derBytes []byte
}

// GeneratePK generates a PrivateKey with a specified size in bits.
func GeneratePK(bits int) (key *PrivateKey, err error) {
	var rsaKey *rsa.PrivateKey
	rsaKey, err = rsa.GenerateKey(rand.Reader, bits)
	if err == nil {
		key = &PrivateKey{rsaKey: rsaKey}
	}
	return
}

// LoadPKFromFile loads a PrivateKey from a file
func LoadPKFromFile(filename string) (key *PrivateKey, err error) {
	privateKeyData, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("Unable to read private key file from file %s: %s", filename, err)
	}
	block, _ := pem.Decode(privateKeyData)
	if block == nil {
		return nil, fmt.Errorf("Unable to decode PEM encoded private key data: %s", err)
	}
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Unable to decode X509 private key data: %s", err)
	}
	return &PrivateKey{rsaKey: rsaKey}, nil
}

// PEMEncoded encodes the PrivateKey in PEM
func (key *PrivateKey) PEMEncoded() (pemBytes []byte) {
	return pem.EncodeToMemory(&pem.Block{Type: PEM_HEADER_PRIVATE_KEY, Bytes: x509.MarshalPKCS1PrivateKey(key.rsaKey)})
}

// WriteToFile writes the PrivateKey to the given file
func (key *PrivateKey) WriteToFile(filename string) (err error) {
	keyOut, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("Failed to open %s for writing: %s", filename, err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: PEM_HEADER_PRIVATE_KEY, Bytes: x509.MarshalPKCS1PrivateKey(key.rsaKey)}); err != nil {
		return fmt.Errorf("Unable to PEM encode private key: %s", err)
	}
	keyOut.Close()
	return
}

/*
Certificate() generates a certificate for the Public Key of the given
PrivateKey based on the given template and signed by the given issuer.
If issuer is nil, the generated certificate is self-signed.
*/
func (key *PrivateKey) Certificate(template *x509.Certificate, issuer *Certificate) (*Certificate, error) {
	var issuerCert *x509.Certificate
	if issuer == nil {
		// Note - for self-signed certificates, we include the host's external IP address
		issuerCert = template
	} else {
		issuerCert = issuer.cert
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, issuerCert, &key.rsaKey.PublicKey, key.rsaKey)
	if err != nil {
		return nil, err
	}
	return bytesToCert(derBytes)
}

func LoadCertificateFromFile(filename string) (*Certificate, error) {
	if certificateData, err := ioutil.ReadFile(filename); err != nil {
		return nil, fmt.Errorf("Unable to read certificate file from disk: %s", err)
	} else {
		block, _ := pem.Decode(certificateData)
		if block == nil {
			return nil, fmt.Errorf("Unable to decode PEM encoded certificate")
		}
		return bytesToCert(block.Bytes)
	}
}

func bytesToCert(derBytes []byte) (*Certificate, error) {
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}
	return &Certificate{cert, derBytes}, nil
}

// X509 returns the x509 certificate underlying this Certificate
func (cert *Certificate) X509() *x509.Certificate {
	return cert.cert
}

// PEMEncoded encodes the Certificate in PEM
func (cert *Certificate) PEMEncoded() (pemBytes []byte) {
	return pem.EncodeToMemory(&pem.Block{Type: PEM_HEADER_CERTIFICATE, Bytes: cert.derBytes})
}

// WriteToFile writes the PEM-encoded Certificate to a file.
func (cert *Certificate) WriteToFile(filename string) (err error) {
	certOut, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("Failed to open %s for writing: %s", filename, err)
	}
	pem.Encode(certOut, &pem.Block{Type: PEM_HEADER_CERTIFICATE, Bytes: cert.derBytes})
	certOut.Close()
	return
}
