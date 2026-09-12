package main

import (
	"fmt"
	"os"

	"github.com/teemow/patty/cmd"
)

var version = "dev"

func main() {
	cmd.SetVersion(version)

	code, err := cmd.Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}
	os.Exit(code)
}
