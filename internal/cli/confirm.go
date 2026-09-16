package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/aburaihan-dev/gowalld/internal/service"
)

// stdinConfirmer implements service.Confirmer by prompting on the terminal.
type stdinConfirmer struct {
	in  io.Reader
	out io.Writer
}

func (c stdinConfirmer) Confirm(_ context.Context, level service.RiskLevel, message string) (bool, error) {
	icon := "?"
	if level == service.Destructive || level == service.LockoutRisk {
		icon = "!"
	}
	fmt.Fprintf(c.out, "%s %s\nProceed? [y/N]: ", icon, message)

	line, err := bufio.NewReader(c.in).ReadString('\n')
	if err != nil && err != io.EOF {
		return false, err
	}
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes", nil
}
