// Package trustgen generates credentials compatible with the trust package.
package trustgen

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"sync/atomic"
	"time"
)

var serial = new(atomic.Int64)

func NewRoot() (*x509.Certificate, crypto.Signer, error) {
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	template := x509.Certificate{
		NotBefore:             now,
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	crt, err := createCertificate(&template, &template, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}

	return crt, key, nil
}

func NewIntermediate(ca *x509.Certificate, signer crypto.Signer) (*x509.Certificate, crypto.Signer, error) {
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	template := x509.Certificate{
		NotBefore:             now,
		NotAfter:              now.AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	crt, err := createCertificate(&template, ca, key.Public(), signer)
	if err != nil {
		return nil, nil, err
	}

	return crt, key, nil
}

func NewLeaf(ca *x509.Certificate, signer crypto.Signer) (*x509.Certificate, crypto.Signer, error) {
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	template := x509.Certificate{
		NotBefore: now,
		NotAfter:  now.AddDate(1, 0, 0),
		KeyUsage:  x509.KeyUsageDigitalSignature,

		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},

		BasicConstraintsValid: true,
	}

	crt, err := createCertificate(&template, ca, key.Public(), signer)
	if err != nil {
		return nil, nil, err
	}

	return crt, key, nil
}

// PEMEncodeCertificates PEM-encodes the given certificates as CERTIFICATE blocks.
// Each block contains a complete certificate in ASN.1 DER form.
func PEMEncodeCertificates(certs ...*x509.Certificate) []byte {
	b := new(bytes.Buffer)

	for _, cert := range certs {
		err := pem.Encode(b, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})

		if err != nil {
			panic(err)
		}
	}

	return b.Bytes()
}

// PEMEncodePrivateKey PEM-encodes the given key as a PRIVATE KEY block.
// The block contains the key in PKCS #8, ASN.1 DER form.
func PEMEncodePrivateKey(key crypto.Signer) []byte {
	bytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: bytes,
	})
}

func createCertificate(template *x509.Certificate, parent *x509.Certificate, pub crypto.PublicKey, priv crypto.Signer) (*x509.Certificate, error) {
	template.SerialNumber = big.NewInt(serial.Add(1))
	der, err := x509.CreateCertificate(nil, template, parent, pub, priv)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(der)
}
