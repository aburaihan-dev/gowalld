// Command gowalld is a devops helper CLI that manages firewalld and ufw
// through one consistent command set.
package main

import (
	"fmt"
	"os"

	"github.com/aburaihan-dev/gowalld/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
