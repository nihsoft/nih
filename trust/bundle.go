// Package trust is concerned with secure communication between parts of the system.
package trust

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// Bundle collects the credentials required to communicate with the system.
type Bundle struct {
	cert  *tls.Certificate
	roots *x509.CertPool
}

// NewBundle validates and bundles a set of initial credentials.
func NewBundle(chain []*x509.Certificate, signer crypto.Signer, roots []*x509.Certificate) (*Bundle, error) {
	if len(chain) == 0 {
		return nil, errors.New("trust: empty chain")
	}

	if len(roots) == 0 {
		return nil, errors.New("trust: empty roots")
	}

	for i, c := range roots {
		if err := verifyRoot(c); err != nil {
			return nil, fmt.Errorf("trust: root[%d]: %w", i, err)
		}
	}

	rootPool := x509.NewCertPool()
	for _, c := range roots {
		rootPool.AddCert(c)
	}

	leaf, err := verifyChain(chain, rootPool)
	if err != nil {
		return nil, fmt.Errorf("trust: %w", err)
	}

	cert := tls.Certificate{
		PrivateKey: signer,
		Leaf:       leaf,
	}

	for _, c := range chain {
		cert.Certificate = append(cert.Certificate, c.Raw)
	}

	b := Bundle{
		cert:  &cert,
		roots: rootPool,
	}

	return &b, nil
}

// LoadPEM loads a set of initial credentials from the named PEM-encoded files.
// The cert file must contain a leaf CERTIFICATE block followed by any intermediates.
// The key file must only contain a PRIVATE KEY block.
// The ca file must contain one or more CERTIFICATE blocks.
func LoadPEM(certFile, keyFile, caFile string) (*Bundle, error) {
	chain, err := LoadCertificates(certFile)
	if err != nil {
		return nil, err
	}

	signer, err := LoadPrivateKey(keyFile)
	if err != nil {
		return nil, err
	}

	roots, err := LoadCertificates(caFile)
	if err != nil {
		return nil, err
	}

	return NewBundle(chain, signer, roots)
}

// LoadCertificates reads and parses the PEM-encoded contents of the named file.
// It returns a slice of certificates corresponding to the CERTIFICATE blocks in the file.
func LoadCertificates(name string) (certs []*x509.Certificate, err error) {
	contents, err := os.ReadFile(name)
	if err != nil {
		return
	}

	var blk *pem.Block
	var der []byte

	for {
		blk, contents = pem.Decode(contents)
		if blk == nil {
			break
		}

		if blk.Type != "CERTIFICATE" {
			continue
		}

		der = append(der, blk.Bytes...)
	}

	return x509.ParseCertificates(der)
}

// LoadPrivateKey reads and parses a PEM-encoded private key from the named file.
// The first thing in the file must be a PRIVATE KEY block containing the PKCS #8, ASN.1 DER form of the key.
func LoadPrivateKey(name string) (key crypto.Signer, err error) {
	contents, err := os.ReadFile(name)
	if err != nil {
		return
	}

	blk, _ := pem.Decode(contents)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("trust: load %s: no private key found", name)
	}

	anyKey, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return
	}

	key = anyKey.(crypto.Signer)
	return
}

// TLSConfig returns a TLS configuration backed by the bundle.
// The configuration can be used by a client or a server.
func (b *Bundle) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate:        b.getCertificate,
		GetClientCertificate:  b.getClientCertificate,
		VerifyPeerCertificate: b.verifyPeerCertificate,

		// validated by verifyPeerCertificate
		ClientAuth: tls.RequireAnyClientCert,

		// OK because verifyPeerCertificate is called
		InsecureSkipVerify: true,

		MinVersion: tls.VersionTLS13,
	}
}

func (b *Bundle) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return b.cert, nil
}

func (b *Bundle) getClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return b.cert, nil
}

func (b *Bundle) verifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	var chain []*x509.Certificate
	for _, raw := range rawCerts {
		crt, err := x509.ParseCertificate(raw)
		if err != nil {
			return err
		}
		chain = append(chain, crt)
	}

	if _, err := verifyChain(chain, b.roots); err != nil {
		return err
	}

	return nil
}

func verifyChain(chain []*x509.Certificate, roots *x509.CertPool) (leaf *x509.Certificate, err error) {
	if err := validateLeaf(chain[0]); err != nil {
		return nil, fmt.Errorf("chain[0]: %w", err)
	}

	var intermediates *x509.CertPool
	if len(chain) > 1 {
		intermediates = x509.NewCertPool()
		for i, c := range chain[1:] {
			if err := verifyIntermediate(c, roots); err != nil {
				return nil, fmt.Errorf("chain[%d]: %w", i+1, err)
			}
			intermediates.AddCert(c)
		}
	}

	_, err = chain[0].Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
	})

	if err != nil {
		return nil, err
	}

	return chain[0], nil
}

func verifyIntermediate(c *x509.Certificate, roots *x509.CertPool) error {
	if err := validateCertificate(c); err != nil {
		return err
	}

	if err := verifyCA(c, roots); err != nil {
		return err
	}

	return nil
}

func verifyRoot(c *x509.Certificate) error {
	if err := validateCertificate(c); err != nil {
		return err
	}

	self := x509.NewCertPool()
	self.AddCert(c)

	if err := verifyCA(c, self); err != nil {
		return err
	}

	return nil
}

func verifyCA(c *x509.Certificate, roots *x509.CertPool) error {
	if !c.IsCA {
		return errors.New("not a CA")
	}

	if c.KeyUsage != x509.KeyUsageCertSign {
		return errors.New("invalid key usage")
	}

	if len(c.ExtKeyUsage) != 0 {
		return errors.New("invalid extended key usage")
	}

	_, err := c.Verify(x509.VerifyOptions{
		Roots: roots,
	})

	return err
}

func validateLeaf(c *x509.Certificate) error {
	if err := validateCertificate(c); err != nil {
		return err
	}

	if c.IsCA {
		return errors.New("is a CA")
	}

	if c.KeyUsage != x509.KeyUsageDigitalSignature {
		return errors.New("invalid key usage")
	}

	var clientAuth, serverAuth bool
	for _, u := range c.ExtKeyUsage {
		switch u {
		case x509.ExtKeyUsageClientAuth:
			clientAuth = true

		case x509.ExtKeyUsageServerAuth:
			serverAuth = true
		}
	}

	if !(clientAuth && serverAuth) {
		return errors.New("invalid extended key usage")
	}

	return nil
}

func validateCertificate(c *x509.Certificate) error {
	if !c.BasicConstraintsValid {
		return errors.New("basic constraints invalid")
	}

	return nil
}
