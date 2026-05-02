package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/visigoth/rampart/internal/supervisor"
	"github.com/zclconf/go-cty/cty"
)

// errAlreadyPresent is returned by incorporateRecord when the pattern is already
// in the target HCL file (duplicate-rule guard).
var errAlreadyPresent = errors.New("already present in profile")

// reviewConfigFile is the JSON shape used for reading/writing config.json.
type reviewConfigFile struct {
	Approvals []supervisor.EscalationRecord `json:"approvals"`
}

// reviewProfileFileSchema is a minimal schema for reading profile list attributes.
type reviewProfileFileSchema struct {
	Profiles []reviewProfileBlockSchema `hcl:"profile,block"`
	Remain   hcl.Body                  `hcl:",remain"`
}

// reviewProfileBlockSchema captures only the list attributes we may modify.
type reviewProfileBlockSchema struct {
	Label  string   `hcl:",label"`
	Read   []string `hcl:"read,optional"`
	Write  []string `hcl:"write,optional"`
	Exec   []string `hcl:"exec,optional"`
	Remain hcl.Body `hcl:",remain"`
}

// RunReview reads escalation records from configPath, groups them by agent+profile,
// and interactively prompts [I]ncorporate / [D]iscard / [S]kip per entry.
// rampartDir is the path to the .rampart/ directory for HCL writes.
func RunReview(configPath, rampartDir string, in io.Reader, out io.Writer) error {
	records, err := loadEscalationRecords(configPath)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		fmt.Fprintln(out, "No pending escalations to review.")
		return nil
	}

	type groupKey struct{ agent, profile string }
	type indexed struct {
		idx int
		rec supervisor.EscalationRecord
	}

	var order []groupKey
	groups := make(map[groupKey][]indexed)
	seen := make(map[groupKey]bool)
	for i, rec := range records {
		k := groupKey{rec.AgentName, rec.ProfileName}
		if !seen[k] {
			order = append(order, k)
			seen[k] = true
		}
		groups[k] = append(groups[k], indexed{i, rec})
	}

	discardSet := make(map[int]bool)
	scanner := bufio.NewScanner(in)

	for _, key := range order {
		agentLabel := key.agent
		if agentLabel == "" {
			agentLabel = "(unknown)"
		}
		profileLabel := key.profile
		if profileLabel == "" {
			profileLabel = "(unknown)"
		}
		fmt.Fprintf(out, "\nAgent: %s  Profile: %s\n", agentLabel, profileLabel)

		for _, ir := range groups[key] {
			rec := ir.rec
			fmt.Fprintf(out, "  [%s] %s\n", rec.Operation, rec.Pattern)
			fmt.Fprintf(out, "  [I]ncorporate / [D]iscard / [S]kip: ")

			if !scanner.Scan() {
				break
			}
			choice := strings.ToLower(strings.TrimSpace(scanner.Text()))

			switch choice {
			case "i", "incorporate":
				err := incorporateRecord(rec, rampartDir)
				switch {
				case err == nil:
					fmt.Fprintln(out, "  Incorporated.")
				case errors.Is(err, errAlreadyPresent):
					fmt.Fprintln(out, "  Already present in profile (skipped).")
				default:
					fmt.Fprintf(out, "  ! %v\n", err)
				}
			case "d", "discard":
				discardSet[ir.idx] = true
				fmt.Fprintln(out, "  Discarded.")
			default:
				fmt.Fprintln(out, "  Skipped.")
			}
		}
	}

	if len(discardSet) > 0 {
		remaining := make([]supervisor.EscalationRecord, 0, len(records)-len(discardSet))
		for i, r := range records {
			if !discardSet[i] {
				remaining = append(remaining, r)
			}
		}
		return saveEscalationRecords(configPath, remaining)
	}
	return nil
}

// incorporateRecord adds rec.Pattern to the appropriate list attribute of the
// profile HCL file. Returns errAlreadyPresent if the pattern is already there.
func incorporateRecord(rec supervisor.EscalationRecord, rampartDir string) error {
	if rec.ProfileName == "" {
		return fmt.Errorf("no profile name recorded; cannot determine target HCL file")
	}
	attrName := operationToAttr(rec.Operation)
	if attrName == "" {
		return fmt.Errorf("unsupported operation %q", rec.Operation)
	}
	hclPath, profileLabel := profileHCLPath(rampartDir, rec.ProfileName)
	return appendToHCLList(hclPath, profileLabel, attrName, rec.Pattern)
}

// operationToAttr maps an EscalationRecord operation to its HCL attribute name.
func operationToAttr(op string) string {
	switch op {
	case "stat", "read":
		return "read"
	case "write":
		return "write"
	case "exec":
		return "exec"
	default:
		return ""
	}
}

// profileHCLPath returns the absolute path to the profile HCL file and the
// profile block label for a given rampartDir and profileName.
//
// Convention: ProfileName "project/default" → <rampartDir>/profiles/project/default.hcl
// with label "default". Single-segment "default" → <rampartDir>/profiles/default.hcl
// with label "default".
func profileHCLPath(rampartDir, profileName string) (string, string) {
	parts := strings.Split(profileName, "/")
	label := parts[len(parts)-1]
	relParts := append([]string{rampartDir, "profiles"}, parts...)
	relParts[len(relParts)-1] = label + ".hcl"
	return filepath.Join(relParts...), label
}

// appendToHCLList adds value to the named list attribute of the first profile
// block with the given label in hclPath. Preserves all other file formatting.
func appendToHCLList(hclPath, profileLabel, attrName, value string) error {
	src, err := os.ReadFile(hclPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", hclPath, err)
	}

	// Read existing values via hclsyntax for safe expression evaluation.
	existing, err := readProfileAttrValues(src, hclPath, profileLabel, attrName)
	if err != nil {
		return err
	}

	// Duplicate guard.
	for _, v := range existing {
		if v == value {
			return errAlreadyPresent
		}
	}

	// Parse with hclwrite for format-preserving modification.
	f, diags := hclwrite.ParseConfig(src, hclPath, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return fmt.Errorf("parsing %s: %s", hclPath, diags.Error())
	}

	var profileBody *hclwrite.Body
	for _, block := range f.Body().Blocks() {
		if block.Type() == "profile" && len(block.Labels()) > 0 && block.Labels()[0] == profileLabel {
			profileBody = block.Body()
			break
		}
	}
	if profileBody == nil {
		return fmt.Errorf("no profile %q block found in %s", profileLabel, hclPath)
	}

	newVals := append(existing, value)
	ctyVals := make([]cty.Value, len(newVals))
	for i, v := range newVals {
		ctyVals[i] = cty.StringVal(v)
	}
	profileBody.SetAttributeValue(attrName, cty.ListVal(ctyVals))

	tmpPath := hclPath + ".rampart.tmp"
	if err := os.WriteFile(tmpPath, f.Bytes(), 0o644); err != nil {
		return fmt.Errorf("writing temp file: %w", err)
	}
	return os.Rename(tmpPath, hclPath)
}

// readProfileAttrValues decodes a list attribute from the first profile block
// with the given label using hclsyntax for safe evaluation.
func readProfileAttrValues(src []byte, path, profileLabel, attrName string) ([]string, error) {
	file, diags := hclsyntax.ParseConfig(src, path, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return nil, fmt.Errorf("parsing %s: %s", path, diags.Error())
	}
	var schema reviewProfileFileSchema
	if diags = gohcl.DecodeBody(file.Body, nil, &schema); diags.HasErrors() {
		return nil, fmt.Errorf("decoding %s: %s", path, diags.Error())
	}
	for _, p := range schema.Profiles {
		if p.Label == profileLabel {
			switch attrName {
			case "read":
				return p.Read, nil
			case "write":
				return p.Write, nil
			case "exec":
				return p.Exec, nil
			}
		}
	}
	return nil, nil
}

// loadEscalationRecords reads records from configPath.
// Returns an empty slice (not an error) if the file doesn't exist.
func loadEscalationRecords(configPath string) ([]supervisor.EscalationRecord, error) {
	data, err := os.ReadFile(configPath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", configPath, err)
	}
	var cfg reviewConfigFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", configPath, err)
	}
	return cfg.Approvals, nil
}

// saveEscalationRecords writes records back to configPath atomically.
func saveEscalationRecords(configPath string, recs []supervisor.EscalationRecord) error {
	cfg := reviewConfigFile{Approvals: recs}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}
	tmpPath := configPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return fmt.Errorf("writing temp file: %w", err)
	}
	return os.Rename(tmpPath, configPath)
}
