package main

import (
	"flag"
	"fmt"
	"os"

	"nih.software/cli"
)

func main() {
	// global
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		args = append(args, "help")
	}

	cmd := args[0]
	args = args[1:]
	_ = args

	switch cmd {
	case "help":
		fmt.Println(cli.HelpText)

	default:
		fmt.Fprintf(os.Stderr, "nih %s: unknown command\n", cmd)
		fmt.Fprintf(os.Stderr, "Run 'nih help' for usage.\n")
		os.Exit(2)
	}
}
