package trust_test

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"os"
	"testing"

	"nih.software/trust"
	"nih.software/trust/trustgen"
)

func TestNewBundle(t *testing.T) {
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

	t.Run("good", func(t *testing.T) {
		if _, err := trust.NewBundle(chain, leafKey, roots); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("tls", func(t *testing.T) {
		id, err := trust.NewBundle(chain, leafKey, roots)
		if err != nil {
			t.Fatal(err)
		}

		p0, p1 := net.Pipe()
		client := tls.Client(p0, id.TLSConfig())
		server := tls.Server(p1, id.TLSConfig())

		dataC := make(chan []byte)
		errC := make(chan error)

		go func() {
			data, err := io.ReadAll(server)
			if err != nil {
				errC <- err
				return
			}

			dataC <- data
		}()

		if _, err := client.Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}

		if err := client.Close(); err != nil {
			t.Fatal(err)
		}

		select {
		case err := <-errC:
			t.Fatal(err)

		case data := <-dataC:
			if string(data) != "hello" {
				t.Fatalf("data %q != %q", data, "hello")
			}
		}
	})

	t.Run("empty chain", func(t *testing.T) {
		if _, err := trust.NewBundle(nil, leafKey, roots); err == nil {
			t.Fatal("no error")
		}
	})

	t.Run("empty roots", func(t *testing.T) {
		if _, err := trust.NewBundle(chain, leafKey, nil); err == nil {
			t.Fatal("no error")
		}
	})

	t.Run("root is not a CA", func(t *testing.T) {
		root := *rootCert
		root.IsCA = false
		roots := []*x509.Certificate{&root}
		if _, err := trust.NewBundle(chain, leafKey, roots); err == nil {
			t.Fatal("no error")
		}
	})

	t.Run("root basic constraints invalid", func(t *testing.T) {
		root := *rootCert
		root.BasicConstraintsValid = false
		roots := []*x509.Certificate{&root}
		if _, err := trust.NewBundle(chain, leafKey, roots); err == nil {
			t.Fatal("no error")
		}
	})

	t.Run("root key usage", func(t *testing.T) {
		root := *rootCert
		root.KeyUsage = x509.KeyUsageDigitalSignature
		roots := []*x509.Certificate{&root}
		if _, err := trust.NewBundle(chain, leafKey, roots); err == nil {
			t.Fatal("no error")
		}
	})

	t.Run("root extended key usage", func(t *testing.T) {
		root := *rootCert
		root.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		roots := []*x509.Certificate{&root}
		if _, err := trust.NewBundle(chain, leafKey, roots); err == nil {
			t.Fatal("no error")
		}
	})

	t.Run("intermediate is not a CA", func(t *testing.T) {
		intermed := *intCert
		intermed.IsCA = false
		chain := []*x509.Certificate{leafCert, &intermed}
		if _, err := trust.NewBundle(chain, leafKey, roots); err == nil {
			t.Fatal("no error")
		}
	})

	t.Run("intermediate basic constraints invalid", func(t *testing.T) {
		intermed := *intCert
		intermed.BasicConstraintsValid = false
		chain := []*x509.Certificate{leafCert, &intermed}
		if _, err := trust.NewBundle(chain, leafKey, roots); err == nil {
			t.Fatal("no error")
		}
	})

	t.Run("leaf is a CA", func(t *testing.T) {
		leaf := *leafCert
		leaf.IsCA = true
		chain := []*x509.Certificate{&leaf, intCert}
		if _, err := trust.NewBundle(chain, leafKey, roots); err == nil {
			t.Fatal("no error")
		}
	})

	t.Run("leaf basic constraints invalid", func(t *testing.T) {
		leaf := *leafCert
		leaf.BasicConstraintsValid = false
		chain := []*x509.Certificate{&leaf, intCert}
		if _, err := trust.NewBundle(chain, leafKey, roots); err == nil {
			t.Fatal("no error")
		}
	})
}

func TestLoadBundle(t *testing.T) {
	dir := t.TempDir()
	certFile := dir + "/cert.pem"
	keyFile := dir + "/key.pem"
	caFile := dir + "/ca.pem"

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

	certPEM := trustgen.PEMEncodeCertificates(leafCert, intCert)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatal(err)
	}

	keyPEM := trustgen.PEMEncodePrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	caPEM := trustgen.PEMEncodeCertificates(rootCert)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := trust.LoadPEM(certFile, keyFile, caFile); err != nil {
		t.Fatal(err)
	}
}
