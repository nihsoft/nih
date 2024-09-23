//go:build (linux && (amd64 || arm64)) || (darwin && arm64)

// Preflight prepares the development environment by taking the following steps:
//
//  1. Generate a local certificate authority, certificate chain, and keypair.
//     These credentials are used to secure communication between nih instances.
//     The credentials are written to etc/trust/cert.pem, etc/trust/key.pem,
//     and etc/trust/ca.pem, which are all ignored by git.
package main

import (
	"fmt"
	"os"

	"golang.org/x/term"
	"nih.software/trust"
	"nih.software/trust/trustgen"
)

type step struct {
	Name string
	Do   func() error
	Test func() error
}

func main() {
	steps := []step{
		{"generate creds in etc/trust", doCreds, testCreds},
	}

	color := term.IsTerminal(int(os.Stdout.Fd()))
	ok := true

	for _, s := range steps {
		if err := s.Test(); err != nil {
			err = s.Do()

			// retest
			if err == nil {
				err = s.Test()
			}

			suffix := "OK"
			if color {
				suffix = fmt.Sprintf("\x1b[32m%s\x1b[0m", suffix)
			}

			if err != nil {
				ok = false
				suffix = fmt.Sprintf("ERROR: %v", err)
				if color {
					suffix = fmt.Sprintf("\x1b[31m%s\x1b[0m", suffix)
				}
			}

			fmt.Printf("%s: %s\n", s.Name, suffix)
		}
	}

	if !ok {
		os.Exit(1)
	}
}

func doCreds() error {
	if err := os.MkdirAll("etc/trust", 0700); err != nil {
		return err
	}

	rootCert, rootKey, err := trustgen.NewRoot()
	if err != nil {
		return err
	}

	intermediateCert, intermediateKey, err := trustgen.NewIntermediate(rootCert, rootKey)
	if err != nil {
		return err
	}

	leafCert, leafKey, err := trustgen.NewLeaf(intermediateCert, intermediateKey)
	if err != nil {
		return err
	}

	caPEM := trustgen.PEMEncodeCertificates(rootCert)
	if err := os.WriteFile("etc/trust/ca.pem", caPEM, 0600); err != nil {
		return err
	}

	certPEM := trustgen.PEMEncodeCertificates(leafCert, intermediateCert)
	if err := os.WriteFile("etc/trust/cert.pem", certPEM, 0600); err != nil {
		return err
	}

	keyPEM := trustgen.PEMEncodePrivateKey(leafKey)
	if err := os.WriteFile("etc/trust/key.pem", keyPEM, 0600); err != nil {
		return err
	}

	return nil
}

func testCreds() error {
	if _, err := trust.LoadPEM("etc/trust/cert.pem", "etc/trust/key.pem", "etc/trust/ca.pem"); err != nil {
		return err
	}

	return nil
}
