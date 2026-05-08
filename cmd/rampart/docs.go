package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

func docsCmd(root *cobra.Command) *cobra.Command {
	docs := &cobra.Command{
		Use:   "docs",
		Short: "Generate documentation artifacts (man pages, etc.)",
	}

	var outputDir string
	manCmd := &cobra.Command{
		Use:   "man",
		Short: "Generate man pages for all rampart subcommands",
		RunE: func(cmd *cobra.Command, args []string) error {
			// cobra/doc.GenManTree writes files but does not create the
			// output directory. Auto-create so callers (e.g. the install
			// Justfile recipe pointing at /tmp/rampart-man) don't have to
			// remember the prerequisite.
			if err := os.MkdirAll(outputDir, 0o755); err != nil {
				return fmt.Errorf("creating output dir %s: %w", outputDir, err)
			}
			header := &doc.GenManHeader{
				Title:   "RAMPART",
				Section: "1",
				Source:  "Rampart",
				Manual:  "Rampart Manual",
			}
			return doc.GenManTree(root, header, outputDir)
		},
	}
	manCmd.Flags().StringVar(&outputDir, "output-dir", ".", "Directory to write man pages into")
	docs.AddCommand(manCmd)
	return docs
}
