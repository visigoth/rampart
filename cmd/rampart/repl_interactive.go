package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/peterh/liner"
	"github.com/visigoth/rampart/internal/policy"
	"github.com/visigoth/rampart/internal/proxy"
)

// replCommands is the list of top-level REPL command names for tab completion.
var replCommands = []string{"read", "write", "exec", "http", "policy", "exit", "quit"}

// RunInteractiveREPL runs the REPL with liner for history and tab completion.
// Falls back to RunREPL when the output is not a TTY (e.g. in tests).
func RunInteractiveREPL(rp *policy.ResolvedPolicy, aclRules []proxy.ProxyACLRule, out io.Writer) error {
	li := liner.NewLiner()
	defer li.Close()

	li.SetCtrlCAborts(false) // Ctrl-C just clears the line
	li.SetCompleter(func(line string) []string {
		fields := strings.Fields(line)
		if len(fields) == 0 || (len(fields) == 1 && !strings.HasSuffix(line, " ")) {
			prefix := ""
			if len(fields) == 1 {
				prefix = fields[0]
			}
			var out []string
			for _, cmd := range replCommands {
				if strings.HasPrefix(cmd, prefix) {
					out = append(out, cmd)
				}
			}
			return out
		}
		return nil
	})

	for {
		input, err := li.Prompt("rampart> ")
		if err != nil {
			// EOF or Ctrl-D
			fmt.Fprintln(out)
			return nil
		}
		line := strings.TrimSpace(input)
		if line == "" {
			continue
		}
		li.AppendHistory(line)
		if exit := handleREPLLine(line, rp, aclRules, out); exit {
			return nil
		}
	}
}
