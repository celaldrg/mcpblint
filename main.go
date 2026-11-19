// Command mcpblint lints MCP Bundles (.mcpb, formerly .dxt): the manifest,
// how mcp_config uses user_config, and the files that get packed.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

const version = "0.1.0"

const usage = `mcpblint: lint MCP Bundles (.mcpb / .dxt) before anyone installs them

usage:
  mcpblint [options] <bundle.mcpb | dir | manifest.json | ->...

  a .mcpb/.dxt file is checked as packed; a directory is checked the way
  "mcpb pack" would pack it (default excludes and .mcpbignore applied).
  With no arguments, the current directory is checked.

options:
  --json            machine-readable output
  --strict          exit 1 on warnings too
  --quiet           only show errors
  --ignore <rules>  comma-separated rule ids to skip
  --rules           list every rule and exit
  --no-color        disable colors (also NO_COLOR=1)
  --version         print the version

exit codes: 0 ok, 1 problems found, 2 usage or read error
`

type options struct {
	json, strict, quiet, color bool
	ignore                     map[string]bool
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	o := options{ignore: map[string]bool{}}
	o.color = isTTY(stdout) && os.Getenv("NO_COLOR") == ""
	if os.Getenv("FORCE_COLOR") != "" && os.Getenv("NO_COLOR") == "" {
		o.color = true
	}
	var targets []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--json":
			o.json = true
		case a == "--strict":
			o.strict = true
		case a == "--quiet" || a == "-q":
			o.quiet = true
		case a == "--no-color":
			o.color = false
		case a == "--version" || a == "-v":
			fmt.Fprintln(stdout, "mcpblint", version)
			return 0
		case a == "--help" || a == "-h":
			fmt.Fprint(stdout, usage)
			return 0
		case a == "--rules":
			for _, r := range Rules {
				fmt.Fprintf(stdout, "%-24s %-8s %s\n", r.ID, r.Sev, r.Desc)
			}
			return 0
		case a == "--ignore" || strings.HasPrefix(a, "--ignore="):
			v := strings.TrimPrefix(a, "--ignore=")
			if a == "--ignore" {
				if i+1 >= len(args) {
					fmt.Fprintln(stderr, "mcpblint: --ignore needs a list of rule ids")
					return 2
				}
				i++
				v = args[i]
			}
			for _, r := range strings.Split(v, ",") {
				if r = strings.TrimSpace(r); r != "" {
					o.ignore[r] = true
				}
			}
		case a == "--":
			targets = append(targets, args[i+1:]...)
			i = len(args)
		case strings.HasPrefix(a, "-") && a != "-":
			fmt.Fprintf(stderr, "mcpblint: unknown option %s\n\n%s", a, usage)
			return 2
		default:
			targets = append(targets, a)
		}
	}
	if len(targets) == 0 {
		targets = []string{"."}
	}
	var reports []Report
	readErr := false
	for _, t := range targets {
		b, err := Load(t)
		if err != nil {
			reports = append(reports, Report{Target: t, ReadErr: err.Error(), Findings: []Finding{}})
			readErr = true
			continue
		}
		r := Lint(b)
		b.Close()
		kept := []Finding{}
		for _, f := range r.Findings {
			if !o.ignore[f.Rule] {
				kept = append(kept, f)
			}
		}
		r.Findings = kept
		reports = append(reports, r)
	}
	fail := false
	for _, r := range reports {
		for _, f := range r.Findings {
			if f.Sev == Error || (o.strict && f.Sev == Warning) {
				fail = true
			}
		}
	}
	if o.json {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		enc.Encode(map[string]any{"version": version, "bundles": reports})
	} else {
		p := &printer{w: stdout, color: o.color, quiet: o.quiet}
		for _, r := range reports {
			p.report(r)
		}
		if len(reports) > 1 {
			p.total(reports)
		}
	}
	switch {
	case readErr:
		return 2
	case fail:
		return 1
	}
	return 0
}

func isTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
