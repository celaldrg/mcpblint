package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func rulesOf(r Report) map[string]int {
	m := map[string]int{}
	for _, f := range r.Findings {
		m[f.Rule]++
	}
	return m
}

func lintPath(t *testing.T, p string) Report {
	t.Helper()
	b, err := Load(p)
	if err != nil {
		t.Fatalf("load %s: %v", p, err)
	}
	defer b.Close()
	return Lint(b)
}

func lintManifest(t *testing.T, manifest string, files map[string]string) Report {
	t.Helper()
	b := &Bundle{Kind: "directory", Name: "test", Manifest: []byte(manifest), Files: map[string]*BFile{}, Dirs: map[string]bool{}}
	if files == nil {
		b.Kind = "manifest"
	}
	for p, c := range files {
		c := c
		b.Files[p] = &BFile{Path: p, Size: int64(len(c)), Mode: 0o755, HasMode: true, read: func() ([]byte, error) { return []byte(c), nil }}
		b.addDirs(p)
	}
	return Lint(b)
}

func TestGoodExampleIsClean(t *testing.T) {
	r := lintPath(t, "examples/unit-converter")
	if len(r.Findings) != 0 {
		t.Fatalf("expected no findings, got %+v", r.Findings)
	}
	if r.Version != "0.3" || r.ServerType != "node" || r.Tools != 2 || r.Options != 1 {
		t.Fatalf("bad summary: %+v", r)
	}
}

func TestBrokenDirectory(t *testing.T) {
	r := lintPath(t, "examples/notes-search")
	got := rulesOf(r)
	for _, want := range []string{
		"invalid-semver", "invalid-email", "field-needs-version", "invalid-icon", "tool-name", "missing-description",
		"prompt-argument", "invalid-enum", "entry-point-unused", "entry-point-type", "relative-path", "hardcoded-secret",
		"multiple-in-string", "undefined-option", "absolute-path", "unknown-platform", "secret-not-sensitive",
		"unset-option", "unused-option", "option-schema", "secret-in-file", "deps-not-bundled", "sensitive-file",
		"name-style", "privacy-policy",
	} {
		if got[want] == 0 {
			t.Errorf("missing rule %s; got %v", want, got)
		}
	}
	for _, f := range r.Findings {
		if strings.Contains(f.Msg, "EXAMPLEdoNotUse") {
			t.Errorf("secret not masked: %s", f.Msg)
		}
	}
}

func TestBrokenArchive(t *testing.T) {
	r := lintPath(t, "examples/weather-py.mcpb")
	got := rulesOf(r)
	for _, want := range []string{"manifest-not-at-root", "deprecated-dxt-version", "secret-in-args", "missing-file", "sensitive-file", "deps-not-bundled", "junk-file"} {
		if got[want] == 0 {
			t.Errorf("missing rule %s; got %v", want, got)
		}
	}
	if r.Kind != "archive" {
		t.Fatalf("kind = %s", r.Kind)
	}
}

const base = `{
  "manifest_version": "0.3", "name": "x", "version": "1.0.0", "description": "d",
  "author": {"name": "a"},
  "tools": [{"name": "t", "description": "d"}],
  "server": {"type": "node", "entry_point": "server/index.js",
    "mcp_config": {"command": "node", "args": ["${__dirname}/server/index.js"]}}
}`

func TestBaseIsClean(t *testing.T) {
	r := lintManifest(t, base, map[string]string{"server/index.js": "x"})
	if len(r.Findings) != 0 {
		t.Fatalf("got %+v", r.Findings)
	}
}

func TestInvalidJSONPosition(t *testing.T) {
	r := lintManifest(t, "{\n  \"name\": \"x\",\n}", nil)
	if len(r.Findings) != 1 || r.Findings[0].Rule != "invalid-json" || r.Findings[0].Line != 3 {
		t.Fatalf("got %+v", r.Findings)
	}
}

func TestUnknownFieldSuggestion(t *testing.T) {
	m := strings.Replace(base, `"description": "d",`, `"description": "d", "user_confg": {},`, 1)
	r := lintManifest(t, m, nil)
	if !strings.Contains(r.Findings[0].Msg, `did you mean "user_config"`) {
		t.Fatalf("got %+v", r.Findings)
	}
}

func TestVersionGates(t *testing.T) {
	m := strings.Replace(base, `"0.3"`, `"0.3"`, 1)
	m = strings.Replace(m, `"type": "node"`, `"type": "uv"`, 1)
	r := lintManifest(t, m, nil)
	if rulesOf(r)["field-needs-version"] != 1 {
		t.Fatalf("uv on 0.3 should need 0.4: %+v", r.Findings)
	}
	m = strings.Replace(base, `"0.3"`, `"0.1"`, 1)
	m = strings.Replace(m, `"description": "d",`, `"description": "d", "privacy_policies": ["https://example.com/p"],`, 1)
	if rulesOf(lintManifest(t, m, nil))["field-needs-version"] != 1 {
		t.Fatal("privacy_policies on 0.1 should be flagged")
	}
	m = strings.Replace(base, `"0.3"`, `"0.9"`, 1)
	if rulesOf(lintManifest(t, m, nil))["unknown-version"] != 1 {
		t.Fatal("0.9 should be unknown")
	}
}

func TestVariables(t *testing.T) {
	m := strings.Replace(base, `"args": ["${__dirname}/server/index.js"]`,
		`"args": ["${__dirname}/server/index.js", "${HOME}/x", "${dirname}/y", "--d=${user_config.dirs}"], "env": {"TOKEN": "${user_config.tok}", "K": "${user_config.missing}"}`, 1)
	m = strings.Replace(m, `"description": "d",`, `"description": "d", "user_config": {
	  "dirs": {"type": "directory", "title": "D", "description": "d", "multiple": true, "required": true},
	  "tok": {"type": "string", "title": "T", "description": "t", "required": true}},`, 1)
	got := rulesOf(lintManifest(t, m, nil))
	for _, w := range []string{"system-dir-variable", "unknown-variable", "multiple-in-string", "undefined-option", "secret-not-sensitive"} {
		if got[w] == 0 {
			t.Errorf("missing %s in %v", w, got)
		}
	}
}

func TestHardcodedSecrets(t *testing.T) {
	key := "ghp_" + strings.Repeat("a1B2", 9)
	m := strings.Replace(base, `"args": ["${__dirname}/server/index.js"]`,
		`"args": ["${__dirname}/server/index.js"], "env": {"GH": "`+key+`", "API_KEY": "abc123def456", "MODE": "production", "DEBUG": "true", "AUTH_URL": "https://auth.example.com"}`, 1)
	r := lintManifest(t, m, nil)
	if n := rulesOf(r)["hardcoded-secret"]; n != 2 {
		t.Fatalf("want 2 hardcoded-secret, got %d: %+v", n, r.Findings)
	}
	for _, f := range r.Findings {
		if strings.Contains(f.Msg, key) || strings.Contains(f.Msg, "abc123def456") {
			t.Fatalf("secret leaked into message: %s", f.Msg)
		}
	}
}

func TestOptionSchema(t *testing.T) {
	m := strings.Replace(base, `"description": "d",`, `"description": "d", "user_config": {
	  "n": {"type": "number", "title": "N", "description": "n", "default": "5", "min": 10, "max": 1, "sensitive": true},
	  "b": {"type": "bool", "title": "B", "description": "b"},
	  "s": {"type": "string", "title": "S"}},`, 1)
	m = strings.Replace(m, `"args": ["${__dirname}/server/index.js"]`, `"args": ["${__dirname}/server/index.js", "${user_config.n}", "${user_config.b}", "${user_config.s}"]`, 1)
	r := lintManifest(t, m, nil)
	got := rulesOf(r)
	if got["option-schema"] < 3 || got["invalid-enum"] != 1 || got["missing-field"] != 1 {
		t.Fatalf("got %v", got)
	}
}

func TestFilesChecks(t *testing.T) {
	m := strings.Replace(base, `"type": "node", "entry_point": "server/index.js"`, `"type": "binary", "entry_point": "server/srv"`, 1)
	m = strings.Replace(m, `"command": "node", "args": ["${__dirname}/server/index.js"]`, `"command": "${__dirname}/server/srv"`, 1)
	b := &Bundle{Kind: "archive", Name: "t", Manifest: []byte(m), Files: map[string]*BFile{}, Dirs: map[string]bool{}}
	b.Files["server/srv"] = &BFile{Path: "server/srv", Size: 3, Mode: 0o644, HasMode: true, read: func() ([]byte, error) { return []byte("bin"), nil }}
	b.addDirs("server/srv")
	got := rulesOf(Lint(b))
	if got["not-executable"] != 1 || got["windows-binary"] != 1 {
		t.Fatalf("got %v", got)
	}
}

func TestCommandChecks(t *testing.T) {
	m := strings.Replace(base, `"command": "node", "args": ["${__dirname}/server/index.js"]`, `"command": "npx", "args": ["-y", "some-mcp-server@latest"]`, 1)
	got := rulesOf(lintManifest(t, m, map[string]string{"server/index.js": "x"}))
	if got["not-self-contained"] != 1 || got["entry-point-unused"] != 0 {
		t.Fatalf("got %v", got)
	}
	m = strings.Replace(base, `"command": "node"`, `"command": "python3"`, 1)
	if rulesOf(lintManifest(t, m, map[string]string{"server/index.js": "x"}))["command-mismatch"] != 1 {
		t.Fatal("python3 for node server should be flagged")
	}
}

func TestUVDirectoryMakesRelativeSafe(t *testing.T) {
	m := `{"manifest_version": "0.4", "name": "x", "version": "1.0.0", "description": "d", "author": {"name": "a"},
	  "tools_generated": true,
	  "server": {"type": "uv", "entry_point": "src/server.py",
	    "mcp_config": {"command": "uv", "args": ["run", "--directory", "${__dirname}", "src/server.py"]}}}`
	r := lintManifest(t, m, map[string]string{"src/server.py": "x", "pyproject.toml": "[project]\n"})
	if len(r.Findings) != 0 {
		t.Fatalf("got %+v", r.Findings)
	}
	r = lintManifest(t, m, map[string]string{"src/server.py": "x", "server/lib/x.py": "x"})
	if rulesOf(r)["uv-layout"] != 2 {
		t.Fatalf("got %+v", r.Findings)
	}
}

func TestNodeDeps(t *testing.T) {
	files := map[string]string{
		"server/index.js":                  "x",
		"package.json":                     `{"dependencies": {"zod": "^3"}, "devDependencies": {"typescript": "^5"}}`,
		"node_modules/typescript/index.js": "x",
	}
	got := rulesOf(lintManifest(t, base, files))
	if got["deps-not-bundled"] != 1 || got["dev-deps-bundled"] != 1 {
		t.Fatalf("got %v", got)
	}
	files["node_modules/zod/package.json"] = "{}"
	if rulesOf(lintManifest(t, base, files))["deps-not-bundled"] != 0 {
		t.Fatal("zod is bundled now")
	}
}

func TestSecretInFile(t *testing.T) {
	files := map[string]string{
		"server/index.js":             "const k = \"" + "sk-ant-" + "api03-" + strings.Repeat("x", 30) + "\";\n",
		"node_modules/dep/fixture.js": "sk-ant-" + strings.Repeat("y", 30),
		"server/certs/server.key":     "-----BEGIN " + "PRIVATE KEY-----\n",
	}
	r := lintManifest(t, base, files)
	n := 0
	for _, f := range r.Findings {
		if f.Rule == "secret-in-file" {
			n++
			if strings.HasPrefix(f.File, "node_modules") {
				t.Fatal("vendored code should not be scanned")
			}
		}
	}
	if n != 2 {
		t.Fatalf("want 2 secret-in-file, got %+v", r.Findings)
	}
}

func TestIgnorer(t *testing.T) {
	ig := newIgnorer(append(append([]string{}, defaultExcludes...), "tests/", "*.md", "!README.md", "/build"))
	cases := map[string]bool{
		".env": true, "config/.env.production": true, "node_modules/.cache": true, "src/a.js.map": true,
		"tests": true, "docs/guide.md": true, "README.md": false, "build": true, "src/build": false,
		"server/index.js": false, "package.json": false, "package-lock.json": true,
	}
	for p, want := range cases {
		if got := ig.ignored(p); got != want {
			t.Errorf("ignored(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestDirectoryHonorsMcpbignore(t *testing.T) {
	d := t.TempDir()
	write := func(p, c string) {
		full := filepath.Join(d, filepath.FromSlash(p))
		os.MkdirAll(filepath.Dir(full), 0o755)
		os.WriteFile(full, []byte(c), 0o644)
	}
	write("manifest.json", base)
	write("server/index.js", "x")
	write(".env", "TOKEN=abc")
	write("secrets/credentials.json", "{}")
	write(".mcpbignore", "secrets/\n")
	r := lintPath(t, d)
	if len(r.Findings) != 0 {
		t.Fatalf("ignored files should not be checked: %+v", r.Findings)
	}
	b, _ := Load(d)
	if b.Ignored < 3 {
		t.Fatalf("ignored = %d", b.Ignored)
	}
}

func TestZipWithUnixModes(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name, body string, mode os.FileMode) {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		h.SetMode(mode)
		w, _ := zw.CreateHeader(h)
		w.Write([]byte(body))
	}
	add("manifest.json", base, 0o644)
	add("server/index.js", "x", 0o644)
	zw.Close()
	p := filepath.Join(t.TempDir(), "x.mcpb")
	os.WriteFile(p, buf.Bytes(), 0o644)
	r := lintPath(t, p)
	if r.Kind != "archive" || len(r.Findings) != 0 || r.Files != 2 {
		t.Fatalf("got %+v", r)
	}
}

func TestRunExitCodesAndJSON(t *testing.T) {
	var out, errb bytes.Buffer
	if c := run([]string{"--no-color", "examples/unit-converter"}, &out, &errb); c != 0 {
		t.Fatalf("good exit %d: %s", c, out.String())
	}
	out.Reset()
	if c := run([]string{"--json", "examples/notes-search", "examples/unit-converter"}, &out, &errb); c != 1 {
		t.Fatalf("broken exit %d", c)
	}
	var doc struct {
		Bundles []Report `json:"bundles"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil || len(doc.Bundles) != 2 {
		t.Fatalf("json: %v %s", err, out.String())
	}
	if c := run([]string{"does/not/exist"}, &out, &errb); c != 2 {
		t.Fatalf("missing exit %d", c)
	}
	out.Reset()
	if c := run([]string{"--quiet", "--no-color", "examples/notes-search"}, &out, &errb); c != 1 || strings.Contains(out.String(), "warning ") {
		t.Fatalf("quiet output: %s", out.String())
	}
	if c := run([]string{"--strict", "--no-color", "examples/weather-py.mcpb", "--ignore", "manifest-not-at-root,secret-in-args,missing-file,sensitive-file,deps-not-bundled"}, &out, &errb); c != 1 {
		t.Fatalf("strict should fail on the remaining warning, got %d", c)
	}
}

func TestRulesCatalogue(t *testing.T) {
	ids := map[string]bool{}
	for _, r := range Rules {
		if ids[r.ID] {
			t.Fatalf("duplicate rule %s", r.ID)
		}
		ids[r.ID] = true
	}
	// every rule the code emits must be documented
	src := ""
	for _, f := range []string{"check.go", "files.go"} {
		b, _ := os.ReadFile(f)
		src += string(b)
	}
	var missing []string
	for _, r := range Rules {
		if !strings.Contains(src, "\""+r.ID+"\"") {
			missing = append(missing, r.ID)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("documented but never emitted: %v", missing)
	}
}

func TestSuggest(t *testing.T) {
	if s := suggest("manifest_verison", []string{"manifest_version", "name"}); s != "manifest_version" {
		t.Fatal(s)
	}
	if s := suggest("zzz", []string{"name"}); s != "" {
		t.Fatal(s)
	}
	if s := suggest("user-config", []string{"user_config"}); s != "user_config" {
		t.Fatal(s)
	}
}

func TestValidRange(t *testing.T) {
	for _, s := range []string{">=0.10.0", ">=3.8,<4.0", "^1.2.3", ">1.0.0 <2.0.0", "18.x", ">=16.0.0 || >=18"} {
		if !validRange(s) {
			t.Errorf("%q should be valid", s)
		}
	}
	for _, s := range []string{"latest", "node18", ""} {
		if validRange(s) {
			t.Errorf("%q should be invalid", s)
		}
	}
}
