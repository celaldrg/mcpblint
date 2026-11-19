package main

import (
	"fmt"
	"net/mail"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
)

type linter struct {
	b        *Bundle
	loc      *Locator
	root     *Node
	ver      int // minor version: 1..4, 0 when unknown
	verStr   string
	out      []Finding
	stype    string
	entry    string
	options  map[string]*Node
	optOrder []*Member
	refs     map[string]int
	hasMCP   bool
	tools    int
	cwdSet   bool
}

func (l *linter) add(sev Sev, rule, sec string, off int, format string, a ...any) {
	line, col := l.loc.Pos(off)
	l.out = append(l.out, Finding{Sev: sev, SevName: sev.String(), Rule: rule, Section: sec, File: "manifest.json", Line: line, Col: col, Msg: fmt.Sprintf(format, a...)})
}

func (l *linter) addFile(sev Sev, rule, file string, line int, format string, a ...any) {
	l.out = append(l.out, Finding{Sev: sev, SevName: sev.String(), Rule: rule, Section: SecFiles, File: file, Line: line, Msg: fmt.Sprintf(format, a...)})
}

// Report is the result for one target.
type Report struct {
	Target     string    `json:"target"`
	Kind       string    `json:"kind"`
	Version    string    `json:"manifest_version,omitempty"`
	ServerType string    `json:"server_type,omitempty"`
	Files      int       `json:"files"`
	Bytes      int64     `json:"bytes"`
	Tools      int       `json:"tools"`
	Options    int       `json:"user_config"`
	Findings   []Finding `json:"findings"`
	ReadErr    string    `json:"error,omitempty"`
}

func Lint(b *Bundle) Report {
	l := &linter{b: b, loc: NewLocator(b.Manifest), options: map[string]*Node{}, refs: map[string]int{}}
	r := Report{Target: b.Name, Kind: b.Kind}
	if b.HasFiles() {
		r.Files, r.Bytes = len(b.Files)+1, b.TotalSize()+int64(len(b.Manifest))
		if b.Has("manifest.json") {
			r.Files--
			r.Bytes -= int64(len(b.Manifest))
		}
	}
	root, dups, err := Parse(b.Manifest)
	if err != nil {
		off := 0
		if se, ok := err.(*SyntaxError); ok {
			off = se.Off
		}
		l.add(Error, "invalid-json", SecManifest, off, "%s", err.Error())
		r.Findings = l.out
		return r
	}
	for _, d := range dups {
		l.add(Warning, "duplicate-key", SecManifest, d.Off, "%q appears twice in this object; only the last value is used", d.Key)
	}
	l.root = root
	if !root.IsObj() {
		l.add(Error, "wrong-type", SecManifest, root.Off, "manifest.json must contain a JSON object")
		r.Findings = l.out
		return r
	}
	l.manifest()
	l.server()
	l.userConfig()
	l.capabilities()
	if b.HasFiles() {
		l.files()
	}
	sortFindings(l.out)
	r.Version, r.ServerType, r.Tools, r.Options, r.Findings = l.verStr, l.stype, l.tools, len(l.options), l.out
	return r
}

// ---- generic object checks -------------------------------------------------

type fspec struct {
	kind   string // string, bool, number, array, strarr, object, any
	req    bool
	minVer int
}

func kindName(k Kind) string {
	return [...]string{"null", "boolean", "number", "string", "array", "object"}[k]
}

func (l *linter) kindOK(n *Node, want string) bool {
	switch want {
	case "any":
		return true
	case "string":
		return n.Kind == KStr
	case "bool":
		return n.Kind == KBool
	case "number":
		return n.Kind == KNum
	case "object":
		return n.Kind == KObj
	case "array":
		return n.Kind == KArr
	case "strarr":
		if n.Kind != KArr {
			return false
		}
		for _, it := range n.Items {
			if it.Kind != KStr {
				l.add(Error, "wrong-type", SecManifest, it.Off, "array items must be strings, found %s", kindName(it.Kind))
			}
		}
		return true
	}
	return true
}

var wantName = map[string]string{"string": "a string", "bool": "true or false", "number": "a number", "object": "an object", "array": "an array", "strarr": "an array of strings"}

// object checks n against spec and reports unknown, missing and mistyped fields.
// It returns false when n is not an object at all.
func (l *linter) object(n *Node, where string, spec map[string]fspec, sec string) bool {
	if n == nil {
		return false
	}
	if n.Kind != KObj {
		l.add(Error, "wrong-type", sec, n.Off, "%s must be an object, found %s", where, kindName(n.Kind))
		return false
	}
	for _, m := range n.Members {
		fs, ok := spec[m.Key]
		if !ok {
			names := make([]string, 0, len(spec))
			for k := range spec {
				names = append(names, k)
			}
			hint := ""
			if s := suggest(m.Key, names); s != "" {
				hint = fmt.Sprintf(" (did you mean %q?)", s)
			}
			l.add(Error, "unknown-field", sec, m.KeyOff, "unknown field %q in %s%s; the schema is strict, so mcpb validate rejects it", m.Key, where, hint)
			continue
		}
		if fs.minVer > 0 && l.ver > 0 && l.ver < fs.minVer {
			l.add(Error, "field-needs-version", sec, m.KeyOff, "%q needs manifest_version 0.%d or later (this manifest declares %s)", m.Key, fs.minVer, l.verStr)
		}
		if !l.kindOK(m.Val, fs.kind) {
			l.add(Error, "wrong-type", sec, m.Val.Off, "%s.%s must be %s, found %s", where, m.Key, wantName[fs.kind], kindName(m.Val.Kind))
		}
	}
	var missing []string
	for k, fs := range spec {
		if !fs.req {
			continue
		}
		v := n.Get(k)
		if v == nil || (v.Kind == KStr && strings.TrimSpace(v.Str) == "") {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	for _, k := range missing {
		if v := n.Get(k); v != nil {
			l.add(Error, "missing-field", sec, v.Off, "%s.%s is empty", where, k)
		} else {
			l.add(Error, "missing-field", sec, n.Off, "%s is missing required field %q", where, k)
		}
	}
	return true
}

func str(n *Node, k string) (string, *Node) {
	v := n.Get(k)
	if v != nil && v.Kind == KStr {
		return v.Str, v
	}
	return "", nil
}

// ---- manifest metadata ------------------------------------------------------

var topSpec = map[string]fspec{
	"$schema": {kind: "string"}, "dxt_version": {kind: "string"}, "manifest_version": {kind: "string"},
	"name": {kind: "string", req: true}, "display_name": {kind: "string"}, "version": {kind: "string", req: true},
	"description": {kind: "string", req: true}, "long_description": {kind: "string"}, "author": {kind: "object", req: true},
	"repository": {kind: "object"}, "homepage": {kind: "string"}, "documentation": {kind: "string"}, "support": {kind: "string"},
	"icon": {kind: "string"}, "icons": {kind: "array", minVer: 3}, "screenshots": {kind: "strarr"},
	"localization": {kind: "object", minVer: 3}, "server": {kind: "object", req: true}, "tools": {kind: "array"},
	"tools_generated": {kind: "bool"}, "prompts": {kind: "array"}, "prompts_generated": {kind: "bool"},
	"keywords": {kind: "strarr"}, "license": {kind: "string"}, "privacy_policies": {kind: "strarr", minVer: 2},
	"compatibility": {kind: "object"}, "user_config": {kind: "object"}, "_meta": {kind: "object", minVer: 3},
}

var knownVersions = map[string]int{"0.1": 1, "0.2": 2, "0.3": 3, "0.4": 4}

var semverRe = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

func (l *linter) manifest() {
	r := l.root
	mv, mvn := str(r, "manifest_version")
	dv, dvn := str(r, "dxt_version")
	switch {
	case mvn == nil && dvn == nil:
		l.add(Error, "missing-version", SecManifest, r.Off, "manifest_version is missing (hosts use it to pick the schema)")
	case mvn != nil:
		l.verStr = mv
		if dvn != nil && dv != mv {
			l.add(Error, "version-conflict", SecManifest, dvn.Off, "dxt_version %q and manifest_version %q disagree", dv, mv)
		}
	default:
		l.verStr = dv
		l.add(Warning, "deprecated-dxt-version", SecManifest, r.Member("dxt_version").KeyOff, "dxt_version is deprecated; rename it to manifest_version")
	}
	if l.verStr != "" {
		if v, ok := knownVersions[l.verStr]; ok {
			l.ver = v
		} else {
			n := mvn
			if n == nil {
				n = dvn
			}
			l.add(Error, "unknown-version", SecManifest, n.Off, "manifest_version %q is not a published spec version (0.1, 0.2, 0.3, 0.4)", l.verStr)
		}
	}
	l.object(r, "manifest", topSpec, SecManifest)

	if v, n := str(r, "version"); n != nil && v != "" && !semverRe.MatchString(v) {
		l.add(Error, "invalid-semver", SecManifest, n.Off, "version %q is not semantic versioning (MAJOR.MINOR.PATCH)", v)
	}
	if v, n := str(r, "name"); n != nil && v != "" && !slugRe.MatchString(v) {
		l.add(Note, "name-style", SecManifest, n.Off, "name %q is the machine id; use %q and put the pretty name in display_name", v, slugify(v))
	}
	for _, k := range []string{"homepage", "documentation", "support"} {
		if v, n := str(r, k); n != nil {
			l.url(v, n, k)
		}
	}
	if pp := r.Get("privacy_policies"); pp != nil && pp.Kind == KArr {
		for _, it := range pp.Items {
			if it.Kind == KStr {
				l.url(it.Str, it, "privacy_policies entry")
			}
		}
	}
	if a := r.Get("author"); l.object(a, "author", map[string]fspec{"name": {kind: "string", req: true}, "email": {kind: "string"}, "url": {kind: "string"}}, SecManifest) {
		if v, n := str(a, "email"); n != nil {
			if _, err := mail.ParseAddress(v); err != nil || strings.ContainsAny(v, "<> ") {
				l.add(Error, "invalid-email", SecManifest, n.Off, "author.email %q is not an e-mail address", v)
			}
		}
		if v, n := str(a, "url"); n != nil {
			l.url(v, n, "author.url")
		}
	}
	if rp := r.Get("repository"); l.object(rp, "repository", map[string]fspec{"type": {kind: "string", req: true}, "url": {kind: "string", req: true}}, SecManifest) {
		if v, n := str(rp, "url"); n != nil && v != "" {
			l.url(v, n, "repository.url")
		}
	}
	l.icons()
	if lc := r.Get("localization"); l.object(lc, "localization", map[string]fspec{"resources": {kind: "string", req: true}, "default_locale": {kind: "string", req: true}}, SecManifest) {
		if v, n := str(lc, "resources"); n != nil && v != "" && !strings.Contains(strings.ToLower(v), "${locale}") {
			l.add(Error, "invalid-localization", SecManifest, n.Off, "localization.resources %q must contain the ${locale} placeholder", v)
		}
		if v, n := str(lc, "default_locale"); n != nil && v != "" && !regexp.MustCompile(`^[A-Za-z0-9]{2,8}(?:-[A-Za-z0-9]{1,8})*$`).MatchString(v) {
			l.add(Error, "invalid-localization", SecManifest, n.Off, "default_locale %q is not a BCP 47 tag (for example en-US)", v)
		}
	}
	if m := r.Get("_meta"); m != nil && m.Kind == KObj {
		for _, mm := range m.Members {
			if mm.Val.Kind != KObj {
				l.add(Error, "wrong-type", SecManifest, mm.Val.Off, "_meta.%s must be an object", mm.Key)
			}
		}
	}
	l.compatibility()
}

func (l *linter) url(v string, n *Node, what string) {
	u, err := url.Parse(v)
	if err != nil || u.Scheme == "" || u.Host == "" {
		l.add(Error, "invalid-url", SecManifest, n.Off, "%s %q is not an absolute URL", what, v)
	}
}

func slugify(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.TrimRight(b.String(), "-")
}

var iconSizeRe = regexp.MustCompile(`^\d+x\d+$`)

func (l *linter) icons() {
	if v, n := str(l.root, "icon"); n != nil {
		l.iconPath(v, n, "icon")
	}
	ic := l.root.Get("icons")
	if ic == nil || ic.Kind != KArr {
		return
	}
	for i, it := range ic.Items {
		where := fmt.Sprintf("icons[%d]", i)
		if !l.object(it, where, map[string]fspec{"src": {kind: "string", req: true}, "size": {kind: "string", req: true}, "theme": {kind: "string"}}, SecManifest) {
			continue
		}
		if v, n := str(it, "size"); n != nil && v != "" && !iconSizeRe.MatchString(v) {
			l.add(Error, "invalid-icon", SecManifest, n.Off, "%s.size %q must look like 128x128", where, v)
		}
		if v, n := str(it, "theme"); n != nil && v == "" {
			l.add(Error, "invalid-icon", SecManifest, n.Off, "%s.theme is empty; leave it out instead", where)
		}
		if v, n := str(it, "src"); n != nil && v != "" {
			l.iconPath(v, n, where+".src")
		}
	}
}

func (l *linter) iconPath(v string, n *Node, what string) {
	switch {
	case strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://"):
		l.add(Warning, "remote-icon", SecManifest, n.Off, "%s is a URL; Claude Desktop only shows icons packed in the bundle", what)
		return
	case strings.Contains(v, "${"):
		l.add(Error, "invalid-icon", SecManifest, n.Off, "%s %q uses a variable; icon paths are plain paths relative to the bundle root", what, v)
		return
	case isAbs(v):
		l.add(Error, "invalid-icon", SecManifest, n.Off, "%s %q is absolute; use a path relative to the bundle root", what, v)
		return
	}
	if !l.b.HasFiles() {
		return
	}
	f := l.b.Get(v)
	if f == nil {
		l.add(Error, "missing-file", SecManifest, n.Off, "%s %q is not in the bundle", what, v)
		return
	}
	if data, err := f.Read(); err == nil && !strings.HasPrefix(string(data), "\x89PNG\r\n\x1a\n") {
		l.add(Error, "invalid-icon", SecManifest, n.Off, "%s %q is not a PNG file", what, v)
	}
}

func isAbs(p string) bool {
	return strings.HasPrefix(p, "/") || strings.HasPrefix(p, "\\") || (len(p) > 2 && p[1] == ':' && (p[2] == '\\' || p[2] == '/'))
}

var rangeTokRe = regexp.MustCompile(`^(?:[<>]=?|=|\^|~)?v?(?:0|[1-9]\d*|x|X|\*)(?:\.(?:0|[1-9]\d*|x|X|\*)){0,2}(?:-[0-9A-Za-z.-]+)?$`)

func validRange(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || s == "*" {
		return s != ""
	}
	for _, alt := range strings.Split(s, "||") {
		alt = strings.TrimSpace(alt)
		// "1.0.0 - 2.0.0" hyphen ranges, and python-style comma lists ">=3.8,<4.0"
		alt = strings.ReplaceAll(alt, " - ", " ")
		alt = strings.ReplaceAll(alt, ",", " ")
		alt = regexp.MustCompile(`([<>=^~]+)\s+`).ReplaceAllString(alt, "$1")
		toks := strings.Fields(alt)
		if len(toks) == 0 {
			return false
		}
		for _, t := range toks {
			if !rangeTokRe.MatchString(t) {
				return false
			}
		}
	}
	return true
}

var platforms = map[string]bool{"darwin": true, "win32": true, "linux": true}
var platformAlias = map[string]string{"macos": "darwin", "mac": "darwin", "osx": "darwin", "windows": "win32", "win": "win32", "win64": "win32"}

func platformHint(p string) string {
	if a, ok := platformAlias[strings.ToLower(p)]; ok {
		return fmt.Sprintf(" (did you mean %q?)", a)
	}
	return ""
}

func (l *linter) compatibility() {
	c := l.root.Get("compatibility")
	if c == nil || c.Kind != KObj {
		return
	}
	for _, m := range c.Members {
		switch m.Key {
		case "platforms":
			if m.Val.Kind != KArr {
				l.add(Error, "wrong-type", SecManifest, m.Val.Off, "compatibility.platforms must be an array")
				continue
			}
			for _, it := range m.Val.Items {
				if it.Kind != KStr || !platforms[it.Str] {
					l.add(Error, "invalid-enum", SecManifest, it.Off, "platform %s is not one of darwin, win32, linux%s", literal(it), platformHint(it.Str))
				}
			}
		case "runtimes":
			if !l.object(m.Val, "compatibility.runtimes", map[string]fspec{"python": {kind: "string"}, "node": {kind: "string"}}, SecManifest) {
				continue
			}
			for _, rm := range m.Val.Members {
				if rm.Val.Kind == KStr && !validRange(rm.Val.Str) {
					l.add(Warning, "invalid-range", SecManifest, rm.Val.Off, "runtimes.%s %q is not a version range like \">=3.10\"", rm.Key, rm.Val.Str)
				}
			}
		case "claude_desktop":
			if m.Val.Kind != KStr {
				l.add(Error, "wrong-type", SecManifest, m.Val.Off, "compatibility.claude_desktop must be a string")
			} else if !validRange(m.Val.Str) {
				l.add(Warning, "invalid-range", SecManifest, m.Val.Off, "claude_desktop %q is not a semver range like \">=0.10.0\"", m.Val.Str)
			}
		default:
			if s := suggest(m.Key, []string{"platforms", "runtimes", "claude_desktop"}); s != "" {
				l.add(Error, "unknown-field", SecManifest, m.KeyOff, "unknown field %q in compatibility (did you mean %q?)", m.Key, s)
			} else {
				l.add(Warning, "unlisted-client", SecManifest, m.KeyOff, "compatibility.%s: the spec text allows other clients, but the published schema is strict and mcpb validate rejects it", m.Key)
			}
		}
	}
}

// ---- server / mcp_config ------------------------------------------------------

var serverTypes = map[string]int{"node": 1, "python": 1, "binary": 1, "uv": 4}

var cfgSpec = map[string]fspec{"command": {kind: "string"}, "args": {kind: "strarr"}, "env": {kind: "object"}, "platform_overrides": {kind: "object"}}
var overrideSpec = map[string]fspec{"command": {kind: "string"}, "args": {kind: "strarr"}, "env": {kind: "object"}}

func (l *linter) server() {
	s := l.root.Get("server")
	if s == nil || s.Kind != KObj {
		return
	}
	t, tn := str(s, "type")
	l.stype = t
	spec := map[string]fspec{"type": {kind: "string", req: true}, "entry_point": {kind: "string", req: true}, "mcp_config": {kind: "object", req: t != "uv"}}
	l.object(s, "server", spec, SecServer)
	if tn != nil && t != "" {
		if mv, ok := serverTypes[t]; !ok {
			l.add(Error, "invalid-enum", SecServer, tn.Off, "server.type %q is not one of node, python, binary, uv", t)
		} else if l.ver > 0 && l.ver < mv {
			l.add(Error, "field-needs-version", SecServer, tn.Off, "server.type \"uv\" needs manifest_version 0.4 (this manifest declares %s)", l.verStr)
		}
	}
	l.entry, _ = str(s, "entry_point")
	if rt := l.root.Get("compatibility").Get("runtimes"); rt.IsObj() && t != "" {
		for _, m := range rt.Members {
			want := map[string]string{"node": "node", "python": "python"}[t]
			if t == "uv" {
				want = "python"
			}
			if want != "" && m.Key != want {
				l.add(Warning, "runtime-mismatch", SecServer, m.KeyOff, "compatibility.runtimes.%s on a %s server; only declare the %s runtime", m.Key, t, want)
			} else if t == "binary" {
				l.add(Warning, "runtime-mismatch", SecServer, m.KeyOff, "compatibility.runtimes.%s on a binary server; binaries need no runtime", m.Key)
			}
		}
	}
	mc := s.Get("mcp_config")
	if mc == nil {
		if t == "uv" {
			return
		}
		return // reported as missing-field
	}
	if !l.object(mc, "server.mcp_config", cfgSpec, SecServer) {
		return
	}
	l.hasMCP = true
	cmd, cn := str(mc, "command")
	if cn == nil {
		l.add(Error, "mcp-config", SecServer, mc.Off, "server.mcp_config has no command; the host has nothing to run")
	} else if strings.TrimSpace(cmd) == "" {
		l.add(Error, "mcp-config", SecServer, cn.Off, "server.mcp_config.command is empty")
	}
	if po := mc.Get("platform_overrides"); po.IsObj() {
		for _, m := range po.Members {
			if !platforms[m.Key] {
				l.add(Warning, "unknown-platform", SecServer, m.KeyOff, "platform_overrides.%s never matches (hosts use darwin, win32, linux)%s", m.Key, platformHint(m.Key))
			}
			l.object(m.Val, "platform_overrides."+m.Key, overrideSpec, SecServer)
		}
	}
}

// configs returns the base mcp_config and every platform override.
func (l *linter) configs() []*Node {
	mc := l.root.Get("server").Get("mcp_config")
	if !mc.IsObj() {
		return nil
	}
	out := []*Node{mc}
	if po := mc.Get("platform_overrides"); po.IsObj() {
		for _, m := range po.Members {
			if m.Val.IsObj() {
				out = append(out, m.Val)
			}
		}
	}
	return out
}

var varRe = regexp.MustCompile(`\$\{([^}]*)\}`)
var secretKeyRe = regexp.MustCompile(`(?i)(api[_-]?key|apikey|access[_-]?key|token|secret|passw(or)?d|passwd|credential|private[_-]?key|auth|bearer)`)
var placeholderRe = regexp.MustCompile(`(?i)(your|<|xxx|changeme|replace|example|placeholder|todo|\.\.\.)`)
var absPathRe = regexp.MustCompile(`(?:^|[\s="':,])((?:/Users|/home)/[^/\s"']+|[A-Za-z]:[\\/](?:Users|Documents and Settings)[\\/][^\\/\s"']+)`)

func (l *linter) userConfig() {
	uc := l.root.Get("user_config")
	if uc != nil {
		if uc.Kind != KObj {
			l.add(Error, "wrong-type", SecOptions, uc.Off, "user_config must be an object of options")
		} else {
			for _, m := range uc.Members {
				l.options[m.Key] = m.Val
				l.optOrder = append(l.optOrder, m)
				l.option(m)
			}
		}
	}
	// Walk every string the host substitutes.
	for _, cfg := range l.configs() {
		if v, n := str(cfg, "command"); n != nil {
			l.value(v, n, "command", "")
		}
		if a := cfg.Get("args"); a != nil && a.Kind == KArr {
			l.cwdSet = setsCwd(a)
			for i, it := range a.Items {
				if it.Kind == KStr {
					l.value(it.Str, it, "args", fmt.Sprint(i))
				}
			}
		}
		if e := cfg.Get("env"); e.IsObj() {
			for _, m := range e.Members {
				if m.Val.Kind != KStr {
					l.add(Error, "wrong-type", SecServer, m.Val.Off, "env.%s must be a string (hosts pass environment values as strings)", m.Key)
					continue
				}
				l.value(m.Val.Str, m.Val, "env", m.Key)
			}
		}
	}
	l.commandChecks()
	if !l.hasMCP {
		return
	}
	for _, m := range l.optOrder {
		if l.refs[m.Key] == 0 {
			l.add(Warning, "unused-option", SecOptions, m.KeyOff, "option %q is asked for at install time but never passed to the server (no ${user_config.%s})", m.Key, m.Key)
			continue
		}
		o := m.Val
		if !o.IsObj() {
			continue
		}
		req := o.Get("required")
		typ, _ := str(o, "type")
		if (req == nil || !req.Bool) && o.Get("default") == nil && typ != "boolean" {
			l.add(Warning, "unset-option", SecOptions, m.KeyOff, "optional %q has no default; if never set, the reference code passes the literal \"${user_config.%s}\"", m.Key, m.Key)
		}
	}
}

var optSpec = map[string]fspec{
	"type": {kind: "string", req: true}, "title": {kind: "string", req: true}, "description": {kind: "string", req: true},
	"required": {kind: "bool"}, "default": {kind: "any"}, "multiple": {kind: "bool"}, "sensitive": {kind: "bool"},
	"min": {kind: "number"}, "max": {kind: "number"},
}
var optTypes = map[string]bool{"string": true, "number": true, "boolean": true, "directory": true, "file": true}

func num(n *Node) (float64, bool) {
	if n == nil || n.Kind != KNum {
		return 0, false
	}
	var f float64
	_, err := fmt.Sscan(n.Str, &f)
	return f, err == nil
}

func (l *linter) option(m *Member) {
	o := m.Val
	where := "user_config." + m.Key
	if !l.object(o, where, optSpec, SecOptions) {
		return
	}
	typ, tn := str(o, "type")
	if tn != nil && typ != "" && !optTypes[typ] {
		hint := ""
		if s := suggest(typ, []string{"string", "number", "boolean", "directory", "file"}); s != "" {
			hint = fmt.Sprintf(" (did you mean %q?)", s)
		} else if typ == "integer" || typ == "float" {
			hint = ` (use "number")`
		} else if typ == "bool" {
			hint = ` (use "boolean")`
		}
		l.add(Error, "invalid-enum", SecOptions, tn.Off, "%s.type %q is not one of string, number, boolean, directory, file%s", where, typ, hint)
	}
	flag := func(k string) *Node {
		v := o.Get(k)
		if v != nil && v.Kind == KBool && v.Bool {
			return v
		}
		return nil
	}
	if v := flag("sensitive"); v != nil && typ != "" && typ != "string" {
		l.add(Error, "option-schema", SecOptions, v.Off, "sensitive only applies to string options, %q is %s", m.Key, typ)
	}
	multi := flag("multiple")
	if multi != nil && typ != "" && typ != "directory" && typ != "file" {
		l.add(Error, "option-schema", SecOptions, multi.Off, "multiple only applies to directory and file options, %q is %s", m.Key, typ)
	}
	mn, hasMin := num(o.Get("min"))
	mx, hasMax := num(o.Get("max"))
	for _, k := range []string{"min", "max"} {
		if v := o.Get(k); v != nil && typ != "" && typ != "number" {
			l.add(Error, "option-schema", SecOptions, v.Off, "%s only applies to number options, %q is %s", k, m.Key, typ)
		}
	}
	if hasMin && hasMax && mn > mx {
		l.add(Error, "option-schema", SecOptions, o.Get("min").Off, "%s: min %v is greater than max %v", where, mn, mx)
	}
	if d := o.Get("default"); d != nil && typ != "" {
		ok := true
		switch typ {
		case "string":
			ok = d.Kind == KStr
		case "number":
			ok = d.Kind == KNum
			if f, isNum := num(d); isNum && ((hasMin && f < mn) || (hasMax && f > mx)) {
				l.add(Error, "option-schema", SecOptions, d.Off, "%s: default %v is outside min %v / max %v", where, f, mn, mx)
			}
		case "boolean":
			ok = d.Kind == KBool
		case "directory", "file":
			if multi != nil {
				ok = d.Kind == KArr
			} else {
				ok = d.Kind == KStr
			}
		}
		if !ok {
			want := map[string]string{"string": "a string", "number": "a number", "boolean": "true or false", "directory": "a path string", "file": "a path string"}[typ]
			if multi != nil {
				want = "an array of paths (multiple: true)"
			}
			l.add(Error, "option-schema", SecOptions, d.Off, "%s: default must be %s, found %s", where, want, kindName(d.Kind))
		}
		if d.Kind == KStr {
			for _, mm := range varRe.FindAllStringSubmatch(d.Str, -1) {
				switch mm[1] {
				case "HOME", "DESKTOP", "DOCUMENTS", "DOWNLOADS", "__dirname", "pathSeparator", "/":
				default:
					l.add(Error, "unknown-variable", SecOptions, d.Off, "%s: default uses ${%s}; defaults may use ${HOME}, ${DESKTOP}, ${DOCUMENTS}", where, mm[1])
				}
			}
		}
	}
	if typ == "string" && secretKeyRe.MatchString(m.Key) && flag("sensitive") == nil {
		l.add(Warning, "secret-not-sensitive", SecOptions, m.KeyOff, "option %q looks like a secret but is not \"sensitive\": true (shown and stored in clear text)", m.Key)
	}
}

// value checks one substituted string from mcp_config.
func (l *linter) value(v string, n *Node, field, key string) {
	where := field
	if field == "env" {
		where = "env." + key
	} else if field == "args" {
		where = "args[" + key + "]"
	}
	whole := strings.TrimSpace(v)
	for _, m := range varRe.FindAllStringSubmatch(v, -1) {
		name := m[1]
		switch {
		case name == "__dirname" || name == "pathSeparator" || name == "/":
		case name == "HOME" || name == "DESKTOP" || name == "DOCUMENTS" || name == "DOWNLOADS":
			l.add(Warning, "system-dir-variable", SecServer, n.Off, "${%s} in %s is documented, but mcpb validate rejects it (only ${__dirname}, ${/}, ${pathSeparator} and ${user_config.*}); pass it through a user_config default instead", name, where)
		case strings.HasPrefix(name, "user_config."):
			opt := strings.TrimPrefix(name, "user_config.")
			o, ok := l.options[opt]
			if !ok {
				names := make([]string, 0, len(l.options))
				for k := range l.options {
					names = append(names, k)
				}
				hint := ""
				if s := suggest(opt, names); s != "" {
					hint = fmt.Sprintf(" (did you mean %q?)", s)
				}
				l.add(Error, "undefined-option", SecServer, n.Off, "%s uses ${user_config.%s}, but there is no option %q%s", where, opt, opt, hint)
				continue
			}
			l.refs[opt]++
			if !o.IsObj() {
				continue
			}
			if mu := o.Get("multiple"); mu != nil && mu.Kind == KBool && mu.Bool && (field != "args" || whole != m[0]) {
				l.add(Error, "multiple-in-string", SecServer, n.Off, "%q has multiple values, which only expand as a whole args entry, not inside %s", opt, where)
			}
			sens := o.Get("sensitive")
			isSens := sens != nil && sens.Kind == KBool && sens.Bool
			if isSens && field == "args" {
				l.add(Warning, "secret-in-args", SecServer, n.Off, "sensitive option %q is passed in %s, where any local user can read it in the process list; pass it through env", opt, where)
			}
			if !isSens && field == "env" && secretKeyRe.MatchString(key) {
				if t, _ := str(o, "type"); t == "string" && !secretKeyRe.MatchString(opt) {
					l.add(Warning, "secret-not-sensitive", SecServer, n.Off, "env.%s carries a secret from option %q, which is not \"sensitive\": true", key, opt)
				}
			}
		default:
			l.add(Error, "unknown-variable", SecServer, n.Off, "${%s} in %s is not a variable hosts substitute (${__dirname}, ${/}, ${pathSeparator}, ${user_config.<key>})", name, where)
		}
	}
	// secrets
	if hit, kind := findSecret(v); hit != "" {
		l.add(Error, "hardcoded-secret", SecServer, n.Off, "%s holds %s (%s); use a sensitive user_config option instead", where, article(kind), mask(hit))
	} else if field == "env" && secretKeyRe.MatchString(key) && !strings.Contains(v, "${") && looksLikeValue(v) {
		if placeholderRe.MatchString(v) {
			l.add(Error, "hardcoded-secret", SecServer, n.Off, "env.%s is a placeholder (%q) users cannot change; use a sensitive user_config option", key, v)
		} else {
			l.add(Error, "hardcoded-secret", SecServer, n.Off, "env.%s is a literal secret (%s) shipped to every user; use a sensitive user_config option", key, mask(v))
		}
	}
	if m := absPathRe.FindStringSubmatch(v); m != nil {
		l.add(Error, "absolute-path", SecServer, n.Off, "%s contains %q, a path that only exists on the author's machine", where, m[1])
	}
	if field == "args" && !l.cwdSet && !strings.Contains(v, "${") && !strings.HasPrefix(v, "-") && !isAbs(v) && strings.Contains(v, "/") {
		rel := cleanRel(v)
		if (l.b.HasFiles() && (l.b.Has(rel) || l.b.HasDir(rel))) || (!l.b.HasFiles() && l.entry != "" && rel == cleanRel(l.entry)) {
			l.add(Warning, "relative-path", SecServer, n.Off, "%s %q is relative to the host's working directory; write \"${__dirname}/%s\"", where, v, rel)
		}
	}
	if l.b.HasFiles() {
		for _, p := range dirnamePaths(v) {
			if !l.b.Has(p) && !l.b.HasDir(p) && !(l.stype == "binary" && l.b.Has(p+".exe")) {
				l.add(Error, "missing-file", SecServer, n.Off, "%s points at %q, which is not in the bundle", where, p)
			}
		}
	}
}

// dirnamePaths returns the bundle-relative paths referenced as ${__dirname}/x.
func dirnamePaths(v string) []string {
	v = strings.ReplaceAll(v, "${/}", "/")
	v = strings.ReplaceAll(v, "${pathSeparator}", "/")
	var out []string
	for {
		i := strings.Index(v, "${__dirname}")
		if i < 0 {
			return out
		}
		v = v[i+len("${__dirname}"):]
		rest := strings.TrimLeft(v, "/\\")
		if len(rest) == len(v) {
			continue
		}
		end := strings.IndexAny(rest, " \"';,:=$")
		if end >= 0 {
			rest = rest[:end]
		}
		rest = strings.TrimRight(rest, "/\\")
		if rest != "" {
			out = append(out, cleanRel(rest))
		}
	}
}

func looksLikeValue(v string) bool {
	v = strings.TrimSpace(v)
	if len(v) < 6 {
		return false
	}
	lv := strings.ToLower(v)
	if lv == "true" || lv == "false" || lv == "none" || lv == "null" {
		return false
	}
	if _, err := fmt.Sscan(v, new(float64)); err == nil && !strings.ContainsAny(v, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		return false
	}
	if u, err := url.Parse(v); err == nil && u.Scheme != "" && u.Host != "" && u.User == nil {
		return false
	}
	return !strings.HasPrefix(v, "/") && !strings.HasPrefix(v, ".")
}

func mask(s string) string {
	r := []rune(s)
	if len(r) <= 8 {
		return strings.Repeat("•", len(r))
	}
	n := 6
	if len(r) > 20 {
		n = 10
	}
	return fmt.Sprintf("%s… %d chars", string(r[:n]), len(r))
}

var downloaders = map[string]string{"npx": "npm", "bunx": "npm", "pnpx": "npm", "uvx": "PyPI", "pipx": "PyPI", "docker": "a container registry", "podman": "a container registry", "deno": "the network"}

func cmdBase(c string) string {
	c = strings.ReplaceAll(c, "\\", "/")
	c = path.Base(c)
	c = strings.ToLower(strings.TrimSuffix(strings.ToLower(c), ".exe"))
	c = strings.TrimSuffix(c, ".cmd")
	return c
}

func (l *linter) commandChecks() {
	cfgs := l.configs()
	if len(cfgs) == 0 {
		return
	}
	entry := cleanRel(l.entry)
	mentions := false
	for _, cfg := range cfgs {
		cmd, cn := str(cfg, "command")
		if cn == nil || cmd == "" {
			if cfg != cfgs[0] {
				// overrides inherit the base command
			}
		} else {
			b := cmdBase(cmd)
			if src, ok := downloaders[b]; ok {
				l.add(Warning, "not-self-contained", SecServer, cn.Off, "command %q fetches the server from %s at run time; a bundle should ship its code (or use server.type \"uv\" for Python)", cmd, src)
			} else if l.stype != "" {
				bad := false
				switch l.stype {
				case "node":
					bad = b != "node" && !strings.Contains(cmd, "${")
				case "python":
					bad = !(b == "python" || b == "python3" || b == "py" || strings.HasPrefix(b, "python3.")) && !strings.Contains(cmd, "${")
				case "binary":
					bad = b == "node" || b == "python" || b == "python3"
				case "uv":
					bad = b != "uv" && !strings.Contains(cmd, "${")
				}
				if bad {
					l.add(Warning, "command-mismatch", SecServer, cn.Off, "command %q does not fit server.type %q", cmd, l.stype)
				}
			}
			if l.mentions(cmd, entry) {
				mentions = true
			}
		}
		if a := cfg.Get("args"); a != nil && a.Kind == KArr {
			for _, it := range a.Items {
				if it.Kind == KStr && l.mentions(it.Str, entry) {
					mentions = true
				}
			}
		}
	}
	if entry != "." && entry != "" && !mentions && l.stype != "uv" {
		if _, cn := str(cfgs[0], "command"); cn != nil {
			if _, ok := downloaders[cmdBase(cn.Str)]; ok {
				return
			}
		}
		_, en := str(l.root.Get("server"), "entry_point")
		l.add(Warning, "entry-point-unused", SecServer, en.Off, "mcp_config never runs entry_point %q (hosts start the server from mcp_config)", l.entry)
	}
}

func (l *linter) mentions(s, entry string) bool {
	s = strings.ReplaceAll(s, "${__dirname}", "")
	s = strings.ReplaceAll(s, "${/}", "/")
	s = strings.ReplaceAll(s, "${pathSeparator}", "/")
	s = strings.ReplaceAll(s, "\\", "/")
	s = strings.TrimLeft(s, "/")
	if s == "" {
		return false
	}
	c := cleanRel(s)
	e := strings.TrimSuffix(entry, ".exe")
	return c == entry || strings.TrimSuffix(c, ".exe") == e || strings.HasSuffix(s, "/"+entry)
}

// ---- tools and prompts ---------------------------------------------------------

var toolNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
var argRe = regexp.MustCompile(`\$\{arguments\.([^}]*)\}`)

func (l *linter) capabilities() {
	r := l.root
	seen := map[string]bool{}
	if t := r.Get("tools"); t != nil && t.Kind == KArr {
		for i, it := range t.Items {
			where := fmt.Sprintf("tools[%d]", i)
			if !l.object(it, where, map[string]fspec{"name": {kind: "string", req: true}, "description": {kind: "string"}}, SecManifest) {
				continue
			}
			l.tools++
			name, nn := str(it, "name")
			if nn == nil || name == "" {
				continue
			}
			if seen[name] {
				l.add(Error, "duplicate-tool", SecManifest, nn.Off, "tool %q is declared twice", name)
			}
			seen[name] = true
			if !toolNameRe.MatchString(name) {
				l.add(Warning, "tool-name", SecManifest, nn.Off, "tool name %q should be 1-128 characters of A-Z a-z 0-9 _ - .", name)
			}
			if d, _ := str(it, "description"); strings.TrimSpace(d) == "" {
				l.add(Note, "missing-description", SecManifest, it.Off, "tool %q has no description", name)
			}
		}
	}
	gen := r.Get("tools_generated")
	if l.tools == 0 && (gen == nil || !gen.Bool) {
		l.add(Note, "no-tools", SecManifest, r.Off, "no tools are declared and tools_generated is not true, so the install dialog lists nothing")
	}
	pseen := map[string]bool{}
	if p := r.Get("prompts"); p != nil && p.Kind == KArr {
		for i, it := range p.Items {
			where := fmt.Sprintf("prompts[%d]", i)
			if !l.object(it, where, map[string]fspec{"name": {kind: "string", req: true}, "description": {kind: "string"}, "arguments": {kind: "strarr"}, "text": {kind: "string", req: true}}, SecManifest) {
				continue
			}
			name, nn := str(it, "name")
			if nn != nil && name != "" {
				if pseen[name] {
					l.add(Error, "duplicate-tool", SecManifest, nn.Off, "prompt %q is declared twice", name)
				}
				pseen[name] = true
			}
			declared := map[string]*Node{}
			if a := it.Get("arguments"); a != nil && a.Kind == KArr {
				for _, an := range a.Items {
					if an.Kind == KStr {
						declared[an.Str] = an
					}
				}
			}
			text, tn := str(it, "text")
			used := map[string]bool{}
			for _, m := range argRe.FindAllStringSubmatch(text, -1) {
				used[m[1]] = true
				if declared[m[1]] == nil {
					l.add(Error, "prompt-argument", SecManifest, tn.Off, "prompt %q uses ${arguments.%s} but does not declare %q in arguments", name, m[1], m[1])
				}
			}
			for k, an := range declared {
				if !used[k] && tn != nil {
					l.add(Warning, "prompt-argument", SecManifest, an.Off, "prompt %q declares argument %q but its text never uses ${arguments.%s}", name, k, k)
				}
			}
		}
	}
	// privacy policies: a bundle that asks for an API key talks to a service.
	if l.ver == 0 || l.ver >= 2 {
		if pp := r.Get("privacy_policies"); pp == nil || (pp.Kind == KArr && len(pp.Items) == 0) {
			for _, m := range l.optOrder {
				s := m.Val.Get("sensitive")
				if (s != nil && s.Kind == KBool && s.Bool) || secretKeyRe.MatchString(m.Key) {
					l.add(Note, "privacy-policy", SecManifest, r.Off, "option %q implies an external service, but no privacy_policies are listed (the spec asks for them)", m.Key)
					break
				}
			}
		}
	}
}

// suggest returns the closest candidate to s, or "" when nothing is close.
func suggest(s string, cands []string) string {
	best, bd := "", 1<<30
	ls := strings.ToLower(s)
	for _, c := range cands {
		d := lev(ls, strings.ToLower(c))
		if d < bd || (d == bd && c < best) {
			best, bd = c, d
		}
	}
	lim := 2
	if len(s) > 8 {
		lim = 3
	}
	if bd <= lim && bd < len(s) {
		return best
	}
	for _, c := range cands {
		if strings.ReplaceAll(strings.ToLower(c), "_", "") == strings.ReplaceAll(strings.ReplaceAll(ls, "-", ""), "_", "") {
			return c
		}
	}
	return ""
}

func lev(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur := make([]int, len(rb)+1)
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			c := 1
			if ra[i-1] == rb[j-1] {
				c = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+c)
		}
		prev = cur
	}
	return prev[len(rb)]
}

func article(s string) string {
	if s != "" && strings.ContainsRune("AEIOUaeiou", rune(s[0])) {
		return "an " + s
	}
	return "a " + s
}

// setsCwd reports whether args point the launcher at the bundle directory,
// as in "uv run --directory ${__dirname} server.py", which makes relative paths safe.
func setsCwd(a *Node) bool {
	flags := map[string]bool{"--directory": true, "--cwd": true, "-C": true, "--project": true, "--prefix": true}
	for i, it := range a.Items {
		if it.Kind != KStr {
			continue
		}
		if k, v, ok := strings.Cut(it.Str, "="); ok && flags[k] && strings.HasPrefix(v, "${__dirname}") {
			return true
		}
		if flags[it.Str] && i+1 < len(a.Items) && strings.HasPrefix(a.Items[i+1].Str, "${__dirname}") {
			return true
		}
	}
	return false
}
