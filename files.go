package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

var secretPatterns = []struct {
	kind string
	re   *regexp.Regexp
}{
	{"private key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----`)},
	{"Anthropic API key", regexp.MustCompile(`sk-ant-[A-Za-z0-9_\-]{20,}`)},
	{"OpenAI API key", regexp.MustCompile(`\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,}`)},
	{"GitHub token", regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}`)},
	{"GitHub token", regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{50,}`)},
	{"AWS access key id", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"Slack token", regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}`)},
	{"Stripe live key", regexp.MustCompile(`\b[sr]k_live_[A-Za-z0-9]{20,}`)},
	{"Google API key", regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}`)},
	{"npm token", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`)},
	{"Hugging Face token", regexp.MustCompile(`\bhf_[A-Za-z0-9]{30,}\b`)},
}

func findSecret(s string) (string, string) {
	for _, p := range secretPatterns {
		if m := p.re.FindString(s); m != "" {
			if p.kind == "OpenAI API key" && strings.HasPrefix(m, "sk-ant-") {
				continue
			}
			return m, p.kind
		}
	}
	return "", ""
}

var sensitiveName = []struct {
	re   *regexp.Regexp
	what string
}{
	{regexp.MustCompile(`(^|/)\.env(\.[^/]+)?$`), "an environment file"},
	{regexp.MustCompile(`(^|/)(id_rsa|id_ed25519|id_ecdsa|id_dsa)$`), "an SSH private key"},
	{regexp.MustCompile(`(?i)\.(p12|pfx|jks|keystore)$`), "a key store"},
	{regexp.MustCompile(`(?i)(^|/)(credentials|token|service[-_]account)[^/]*\.json$`), "a credentials file"},
	{regexp.MustCompile(`(^|/)\.(npmrc|pypirc|netrc|git-credentials)$`), "a registry or git credentials file"},
	{regexp.MustCompile(`(^|/)\.(aws|ssh|gnupg)/`), "a credentials folder"},
}

var envTemplateRe = regexp.MustCompile(`(?i)\.env\.(example|sample|template|dist|defaults)$`)

// vendoredRe marks third-party code, which is skipped by the content scan.
var vendoredRe = regexp.MustCompile(`(^|/)(node_modules|site-packages|\.venv|venv|vendor)/|^(server/)?lib/`)

var junkRe = []struct {
	re   *regexp.Regexp
	what string
}{
	{regexp.MustCompile(`(^|/)__pycache__/|\.py[co]$`), "Python bytecode caches"},
	{regexp.MustCompile(`(^|/)\.DS_Store$|(^|/)Thumbs\.db$`), "Finder/Explorer metadata"},
	{regexp.MustCompile(`(^|/)\.git/`), "a .git folder"},
	{regexp.MustCompile(`(^|/)(\.pytest_cache|\.mypy_cache|\.ruff_cache|coverage|\.nyc_output)/`), "test and lint caches"},
}

func (l *linter) files() {
	b := l.b
	if b.Prefix != "" {
		l.addFile(Error, "manifest-not-at-root", b.Prefix+"manifest.json", 0, "manifest.json is inside %q; hosts read it from the archive root (zip the folder's contents)", b.Prefix)
	}
	l.entryFile()
	l.deps()
	for _, sc := range []string{"screenshots"} {
		if a := l.root.Get(sc); a != nil && a.Kind == KArr {
			for _, it := range a.Items {
				if it.Kind == KStr && !strings.HasPrefix(it.Str, "http") && !b.Has(it.Str) {
					l.add(Error, "missing-file", SecManifest, it.Off, "screenshot %q is not in the bundle", it.Str)
				}
			}
		}
	}
	junk := map[string][]string{}
	var junkOrder []string
	var total int64
	for _, p := range b.Paths() {
		f := b.Files[p]
		total += f.Size
		for _, s := range sensitiveName {
			if s.re.MatchString(p) && !envTemplateRe.MatchString(p) {
				l.addFile(Error, "sensitive-file", p, 0, "%s is packed; everyone who installs the bundle gets a copy", s.what)
				break
			}
		}
		for _, j := range junkRe {
			if j.re.MatchString(p) {
				if junk[j.what] == nil {
					junkOrder = append(junkOrder, j.what)
				}
				junk[j.what] = append(junk[j.what], p)
				break
			}
		}
		if f.Size > 25<<20 {
			l.addFile(Note, "large-bundle", p, 0, "file is %s; check it belongs in the bundle", human(f.Size))
		}
		l.scan(f)
	}
	for _, w := range junkOrder {
		ps := junk[w]
		l.addFile(Note, "junk-file", ps[0], 0, "%s packed (%d file%s); add them to .mcpbignore", w, len(ps), map[bool]string{true: "", false: "s"}[len(ps) == 1])
	}
	if total > 100<<20 {
		l.addFile(Note, "large-bundle", "", 0, "bundle content is %s; users download all of it", human(total))
	}
}

func (l *linter) scan(f *BFile) {
	p := f.Path
	if vendoredRe.MatchString(p) || f.Size > 2<<20 || p == "manifest.json" {
		return
	}
	data, err := f.Read()
	if err != nil {
		return
	}
	head := data
	if len(head) > 8000 {
		head = head[:8000]
	}
	if bytes.IndexByte(head, 0) >= 0 {
		return
	}
	for i, ln := range strings.Split(string(data), "\n") {
		if len(ln) > 4000 {
			ln = ln[:4000]
		}
		if hit, kind := findSecret(ln); hit != "" {
			sev := Error
			l.addFile(sev, "secret-in-file", p, i+1, "%s in packed source (%s)", kind, mask(hit))
		}
	}
}

func human(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

func (l *linter) entryFile() {
	_, en := str(l.root.Get("server"), "entry_point")
	if en == nil || en.Str == "" {
		return
	}
	e := en.Str
	b := l.b
	if isAbs(e) || strings.Contains(e, "${") {
		l.add(Error, "missing-file", SecServer, en.Off, "entry_point %q must be a plain path relative to the bundle root", e)
		return
	}
	f := b.Get(e)
	if f == nil && l.stype == "binary" {
		f = b.Get(e + ".exe")
	}
	if f == nil {
		l.add(Error, "missing-file", SecServer, en.Off, "entry_point %q is not in the bundle%s", e, l.didYouMeanFile(e))
		return
	}
	ext := strings.ToLower(path.Ext(e))
	switch l.stype {
	case "node":
		if ext != ".js" && ext != ".mjs" && ext != ".cjs" {
			hint := ""
			if ext == ".ts" || ext == ".mts" {
				hint = "; node servers need the compiled .js"
			}
			l.add(Warning, "entry-point-type", SecServer, en.Off, "entry_point %q is not .js, .mjs or .cjs%s", e, hint)
		}
	case "python", "uv":
		if ext != ".py" {
			l.add(Warning, "entry-point-type", SecServer, en.Off, "entry_point %q is not a .py file for a %s server", e, l.stype)
		}
	case "binary":
		if ext == ".js" || ext == ".mjs" || ext == ".cjs" || ext == ".py" {
			l.add(Warning, "entry-point-type", SecServer, en.Off, "entry_point %q is a script but server.type is binary; did you mean node or python?", e)
		}
		winOnly := strings.HasSuffix(strings.ToLower(f.Path), ".exe")
		if f.HasMode && !winOnly && f.Mode&0o111 == 0 && !(b.Kind == "directory" && runtime.GOOS == "windows") {
			l.add(Error, "not-executable", SecServer, en.Off, "binary entry_point %q is not executable; run chmod +x %s before packing", e, e)
		}
		claimsWin := true
		if pl := l.root.Get("compatibility").Get("platforms"); pl != nil && pl.Kind == KArr {
			claimsWin = false
			for _, it := range pl.Items {
				if it.Str == "win32" {
					claimsWin = true
				}
			}
		}
		if claimsWin && !winOnly && !b.Has(e+".exe") && l.root.Get("server").Get("mcp_config").Get("platform_overrides").Get("win32") == nil {
			l.add(Warning, "windows-binary", SecServer, en.Off, "the bundle claims win32 (or lists no platforms) but has no %s.exe; Windows hosts append .exe and find nothing", e)
		}
	}
}

func (l *linter) didYouMeanFile(e string) string {
	base := path.Base(e)
	var cands []string
	for _, p := range l.b.Paths() {
		if path.Base(p) == base || strings.TrimSuffix(path.Base(p), path.Ext(p)) == strings.TrimSuffix(base, path.Ext(base)) {
			cands = append(cands, p)
		}
	}
	if len(cands) == 0 || len(cands) > 3 {
		return ""
	}
	return fmt.Sprintf(" (found %s)", strings.Join(cands, ", "))
}

func (l *linter) deps() {
	b := l.b
	switch l.stype {
	case "node":
		f := b.Get("package.json")
		if f == nil {
			return
		}
		data, err := f.Read()
		if err != nil {
			return
		}
		var pkg struct {
			Deps    map[string]string `json:"dependencies"`
			DevDeps map[string]string `json:"devDependencies"`
		}
		if json.Unmarshal(data, &pkg) != nil {
			return
		}
		var missing, dev []string
		for d := range pkg.Deps {
			if !b.HasDir("node_modules/"+d) && !b.Has("node_modules/"+d+"/package.json") {
				missing = append(missing, d)
			}
		}
		for d := range pkg.DevDeps {
			if _, isDep := pkg.Deps[d]; !isDep && b.HasDir("node_modules/"+d) {
				dev = append(dev, d)
			}
		}
		sort.Strings(missing)
		sort.Strings(dev)
		if len(missing) > 0 {
			if l.bundledByTool() {
				return
			}
			l.addFile(Error, "deps-not-bundled", "package.json", 0, "%s missing from node_modules; bundles must ship their dependencies", listN(missing, 4))
		}
		if len(dev) > 0 {
			l.addFile(Warning, "dev-deps-bundled", "node_modules", 0, "devDependencies packed: %s; run npm prune --omit=dev (or mcpb clean) to shrink the bundle", listN(dev, 4))
		}
	case "python":
		deps := pythonDeps(b)
		if len(deps) == 0 {
			return
		}
		for _, d := range []string{"server/lib", "lib", "server/venv", "venv", ".venv", "server/.venv"} {
			if b.HasDir(d) {
				return
			}
		}
		l.addFile(Error, "deps-not-bundled", deps[0], 0, "Python deps declared, but no server/lib or server/venv is packed (pip install -t server/lib, or use \"uv\")")
	case "uv":
		if !b.Has("pyproject.toml") {
			l.addFile(Error, "uv-layout", "pyproject.toml", 0, "uv servers need pyproject.toml at the bundle root; the host installs dependencies from it")
		}
		for _, d := range []string{"server/lib", "server/venv"} {
			if b.HasDir(d) {
				l.addFile(Error, "uv-layout", d, 0, "uv bundles must not include %s; the host builds the environment", d)
			}
		}
	}
}

// bundledByTool reports whether the entry point looks like a single-file build
// (esbuild, ncc, rollup), in which case node_modules is not needed.
func (l *linter) bundledByTool() bool {
	f := l.b.Get(l.entry)
	if f == nil {
		return false
	}
	data, err := f.Read()
	if err != nil {
		return false
	}
	s := string(data)
	return len(data) > 200<<10 || strings.Contains(s, "__webpack_require__") || strings.Contains(s, "// node_modules/") || strings.Contains(s, "__commonJS(")
}

func listN(xs []string, n int) string {
	if len(xs) <= n {
		return strings.Join(xs, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(xs[:n], ", "), len(xs)-n)
}

var reqLineRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*`)

func pythonDeps(b *Bundle) []string {
	var out []string
	for _, p := range []string{"requirements.txt", "server/requirements.txt"} {
		if f := b.Get(p); f != nil {
			if data, err := f.Read(); err == nil {
				for _, ln := range strings.Split(string(data), "\n") {
					if reqLineRe.MatchString(strings.TrimSpace(ln)) {
						return append(out, p)
					}
				}
			}
		}
	}
	if f := b.Get("pyproject.toml"); f != nil {
		if data, err := f.Read(); err == nil {
			m := regexp.MustCompile(`(?s)\ndependencies\s*=\s*\[(.*?)\]`).FindStringSubmatch("\n" + string(data))
			if m != nil && strings.Contains(m[1], "\"") || m != nil && strings.Contains(m[1], "'") {
				return append(out, "pyproject.toml")
			}
		}
	}
	return out
}
