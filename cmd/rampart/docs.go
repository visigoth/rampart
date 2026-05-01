package main

import (
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
