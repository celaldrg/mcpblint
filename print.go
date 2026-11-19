package main

import (
	"fmt"
	"io"
	"strings"
)

type printer struct {
	w     io.Writer
	color bool
	quiet bool
}

func (p *printer) c(code, s string) string {
	if !p.color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func plural(n int, s string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, s)
	}
	return fmt.Sprintf("%d %ss", n, s)
}

func counts(fs []Finding) (e, w, n int) {
	for _, f := range fs {
		switch f.Sev {
		case Error:
			e++
		case Warning:
			w++
		default:
			n++
		}
	}
	return
}

func (p *printer) report(r Report) {
	if r.ReadErr != "" {
		fmt.Fprintf(p.w, "%s %s: %s\n\n", p.c("31;1", "error"), r.Target, r.ReadErr)
		return
	}
	var meta []string
	meta = append(meta, r.Kind)
	if r.Version != "" {
		meta = append(meta, "manifest "+r.Version)
	}
	if r.ServerType != "" {
		meta = append(meta, r.ServerType+" server")
	}
	if r.Kind != "manifest" {
		meta = append(meta, fmt.Sprintf("%s, %s", plural(r.Files, "file"), human(r.Bytes)))
	}
	meta = append(meta, plural(r.Tools, "tool"))
	if r.Options > 0 {
		meta = append(meta, plural(r.Options, "option"))
	}
	fmt.Fprintf(p.w, "%s  %s\n", p.c("1", r.Target), p.c("2", strings.Join(meta, " · ")))
	sec := ""
	for _, f := range r.Findings {
		if p.quiet && f.Sev != Error {
			continue
		}
		if f.Section != sec {
			sec = f.Section
			fmt.Fprintf(p.w, "  %s\n", p.c("36", sec))
		}
		pos := ""
		switch {
		case f.File == "manifest.json":
			pos = fmt.Sprintf("%d:%d", f.Line, f.Col)
		case f.Line > 0:
			pos = fmt.Sprintf("%s:%d", f.File, f.Line)
		default:
			pos = f.File
		}
		var sev string
		switch f.Sev {
		case Error:
			sev = p.c("31", fmt.Sprintf("%-7s", "error"))
		case Warning:
			sev = p.c("33", fmt.Sprintf("%-7s", "warning"))
		default:
			sev = p.c("34", fmt.Sprintf("%-7s", "note"))
		}
		if f.File == "manifest.json" {
			fmt.Fprintf(p.w, "  %7s  %s  %s  %s\n", pos, sev, f.Msg, p.c("2", f.Rule))
		} else {
			fmt.Fprintf(p.w, "    %s %s  %s  %s\n", sev, p.c("1", pos), f.Msg, p.c("2", f.Rule))
		}
	}
	e, w, n := counts(r.Findings)
	tail := fmt.Sprintf("%s, %s, %s", plural(e, "error"), plural(w, "warning"), plural(n, "note"))
	switch {
	case e > 0:
		fmt.Fprintf(p.w, "  %s %s\n\n", p.c("31;1", "✗ will not install cleanly:"), p.c("31", tail))
	case w > 0:
		fmt.Fprintf(p.w, "  %s %s\n\n", p.c("33;1", "! installs, with warnings:"), p.c("33", tail))
	default:
		fmt.Fprintf(p.w, "  %s %s\n\n", p.c("32;1", "✓ ready to ship:"), p.c("32", tail))
	}
}

func (p *printer) total(rs []Report) {
	bad, okN := 0, 0
	var e, w, n int
	for _, r := range rs {
		if r.ReadErr != "" {
			bad++
			continue
		}
		a, b, c := counts(r.Findings)
		e, w, n = e+a, w+b, n+c
		if a > 0 {
			bad++
		} else {
			okN++
		}
	}
	fmt.Fprintf(p.w, "%s: %d ok, %d failing · %s, %s, %s\n", plural(len(rs), "bundle"), okN, bad, plural(e, "error"), plural(w, "warning"), plural(n, "note"))
}
