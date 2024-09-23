package cli

import (
	"fmt"

	_ "embed"
)

//go:embed help.txt
var helpTxt string

// Help prints help text for the nih tool.
// If args[0] is the name of a known command,
// Help prints the help text for that command instead.
func Help(args []string) {
	var topic string
	if len(args) > 0 {
		topic = args[0]
	}

	switch topic {
	default:
		fmt.Println(helpTxt)
	}
}
