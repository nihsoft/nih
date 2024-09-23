package trustgen_test

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"nih.software/trust"
	"nih.software/trust/trustgen"
)

func TestRoot(t *testing.T) {
	rootCert, rootKey, err := trustgen.NewRoot()
	if err != nil {
		t.Fatal(err)
	}

	intCert, intKey, err := trustgen.NewIntermediate(rootCert, rootKey)
	if err != nil {
		t.Fatal(err)
	}

	leafCert, leafKey, err := trustgen.NewLeaf(intCert, intKey)
	if err != nil {
		t.Fatal(err)
	}

	chain := []*x509.Certificate{leafCert, intCert}
	roots := []*x509.Certificate{rootCert}

	if _, err := trust.NewBundle(chain, leafKey, roots); err != nil {
		t.Fatal(err)
	}
}

func TestPEMEncode(t *testing.T) {
	rootCert, rootKey, err := trustgen.NewRoot()
	if err != nil {
		t.Fatal(err)
	}

	leafCert, leafKey, err := trustgen.NewLeaf(rootCert, rootKey)
	if err != nil {
		t.Fatal(err)
	}

	certPEM := trustgen.PEMEncodeCertificates(leafCert, rootCert)
	keyPEM := trustgen.PEMEncodePrivateKey(leafKey)

	blk, rest := pem.Decode(certPEM)
	crt0, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	blk, rest = pem.Decode(rest)
	crt1, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	if len(rest) != 0 {
		t.Fatal("leftover cert PEM")
	}

	if !crt0.Equal(leafCert) {
		t.Error("crt0 != leafCert")
	}

	if !crt1.Equal(rootCert) {
		t.Error("crt1 != rootCert")
	}

	blk, rest = pem.Decode(keyPEM)
	_, err = x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	if len(rest) != 0 {
		t.Fatal("leftover key PEM")
	}
}
