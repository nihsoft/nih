package main

import (
	"flag"
	"fmt"
	"os"

	"nih.software/cli"
	"nih.software/trust"
)

func main() {
	certFile := "etc/trust/cert.pem"
	flag.StringVar(&certFile, "cert", certFile, "initial TLS certificate chain file")

	keyFile := "etc/trust/key.pem"
	flag.StringVar(&keyFile, "key", keyFile, "initial TLS private key file")

	caFile := "etc/trust/ca.pem"
	flag.StringVar(&caFile, "ca", caFile, "initial TLS CA certificate file")

	// -h, -help
	flag.Usage = func() {
		cli.Help(nil)
	}

	// global
	flag.Parse()

	_, err := trust.LoadPEM(certFile, keyFile, caFile)
	if err != nil {
		panic(err)
	}

	args := flag.Args()
	if len(args) == 0 {
		args = append(args, "help")
	}

	cmd := args[0]
	args = args[1:]

	switch cmd {
	case "help":
		cli.Help(args)

	default:
		fmt.Fprintf(os.Stderr, "nih %s: unknown command\n", cmd)
		fmt.Fprintf(os.Stderr, "Run \"nih help\" for usage.\n")
		os.Exit(2)
	}
}
