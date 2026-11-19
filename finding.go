package main

import "sort"

type Sev int

const (
	Note Sev = iota
	Warning
	Error
)

func (s Sev) String() string {
	return [...]string{"note", "warning", "error"}[s]
}

// Section groups findings in the report.
const (
	SecManifest = "manifest"
	SecServer   = "server"
	SecOptions  = "user_config"
	SecFiles    = "files"
)

type Finding struct {
	Sev     Sev    `json:"-"`
	SevName string `json:"severity"`
	Rule    string `json:"rule"`
	Section string `json:"section"`
	File    string `json:"file"`
	Line    int    `json:"line,omitempty"`
	Col     int    `json:"column,omitempty"`
	Msg     string `json:"message"`
}

var sectionOrder = map[string]int{SecManifest: 0, SecServer: 1, SecOptions: 2, SecFiles: 3}

func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if sectionOrder[a.Section] != sectionOrder[b.Section] {
			return sectionOrder[a.Section] < sectionOrder[b.Section]
		}
		if (a.Rule == "manifest-not-at-root") != (b.Rule == "manifest-not-at-root") {
			return a.Rule == "manifest-not-at-root"
		}
		if a.File != b.File {
			if a.File == "manifest.json" {
				return true
			}
			if b.File == "manifest.json" {
				return false
			}
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Col < b.Col
	})
}

// Rules is the catalogue printed by --rules and used in the README.
var Rules = []struct{ ID, Sev, Desc string }{
	{"invalid-json", "error", "manifest.json is not valid JSON"},
	{"duplicate-key", "warning", "a key appears twice in one object; only the last one counts"},
	{"missing-version", "error", "neither manifest_version nor dxt_version is set"},
	{"unknown-version", "error", "manifest_version is not a published spec version (0.1 to 0.4)"},
	{"deprecated-dxt-version", "warning", "dxt_version is deprecated; use manifest_version"},
	{"version-conflict", "error", "dxt_version and manifest_version disagree"},
	{"missing-field", "error", "a required field is missing or empty"},
	{"wrong-type", "error", "a field has the wrong JSON type"},
	{"unknown-field", "error", "a field the spec version does not define (strict schema); typos get a suggestion"},
	{"field-needs-version", "error", "a field or value that only exists in a later manifest_version"},
	{"invalid-semver", "error", "version is not semantic versioning"},
	{"invalid-url", "error", "homepage, documentation, support, repository, author.url or privacy_policies is not a URL"},
	{"invalid-email", "error", "author.email is not an e-mail address"},
	{"name-style", "note", "name is meant to be machine-readable; display_name is for humans"},
	{"invalid-enum", "error", "server.type, compatibility.platforms or user_config type has a value the spec does not allow"},
	{"invalid-range", "warning", "a compatibility version constraint is not a semver range"},
	{"runtime-mismatch", "warning", "compatibility.runtimes does not match server.type"},
	{"unlisted-client", "warning", "a compatibility key other than claude_desktop, platforms, runtimes (rejected by mcpb validate)"},
	{"invalid-icon", "error", "icon or icons[] is absolute, uses ${__dirname}, is missing, not a PNG, or has a bad size"},
	{"remote-icon", "warning", "icon is a URL; Claude Desktop only shows icons packed in the bundle"},
	{"invalid-localization", "error", "localization.resources lacks ${locale} or default_locale is not BCP 47"},
	{"duplicate-tool", "error", "two tools or prompts share a name"},
	{"tool-name", "warning", "tool name has characters outside A-Z a-z 0-9 _ - . or is longer than 128"},
	{"missing-description", "note", "a tool or prompt has no description for the install dialog"},
	{"prompt-argument", "error", "prompt text uses ${arguments.x} that is not declared, or declares an argument it never uses"},
	{"no-tools", "note", "no tools declared and tools_generated is not true"},
	{"privacy-policy", "note", "the bundle takes an API key but lists no privacy_policies"},
	{"mcp-config", "error", "mcp_config is missing (only uv servers may omit it) or has no command"},
	{"unknown-variable", "error", "${...} that hosts do not substitute"},
	{"system-dir-variable", "warning", "${HOME}, ${DESKTOP}, ${DOCUMENTS} or ${DOWNLOADS} in mcp_config: documented, but rejected by mcpb validate"},
	{"undefined-option", "error", "${user_config.x} where x is not defined in user_config"},
	{"unused-option", "warning", "a user_config option that mcp_config never passes to the server"},
	{"unset-option", "warning", "an optional option with no default: if never set, the reference implementation passes the literal ${user_config.x}"},
	{"multiple-in-string", "error", "a multiple: true option inside a longer string or env value cannot be expanded"},
	{"hardcoded-secret", "error", "a literal API key or token in mcp_config env or args"},
	{"secret-not-sensitive", "warning", "an option that carries a secret is not marked sensitive: true"},
	{"secret-in-args", "warning", "a sensitive option passed as a command-line argument (visible in the process list)"},
	{"absolute-path", "error", "an absolute path from the author's machine (/Users/..., /home/..., C:\\Users\\...)"},
	{"relative-path", "warning", "a bundle path in args without ${__dirname}; it resolves against the host's working directory"},
	{"entry-point-unused", "warning", "mcp_config never runs server.entry_point"},
	{"command-mismatch", "warning", "mcp_config.command does not fit server.type"},
	{"not-self-contained", "warning", "npx, uvx, pipx, bunx or docker: the server is downloaded at run time instead of shipped"},
	{"unknown-platform", "warning", "a platform_overrides key that never matches (use darwin, win32, linux)"},
	{"option-schema", "error", "a user_config option has a bad default, min/max, or a flag that does not apply to its type"},
	{"missing-file", "error", "entry_point, an icon, a screenshot or a ${__dirname} path is not in the bundle"},
	{"entry-point-type", "warning", "entry_point extension does not match server.type"},
	{"not-executable", "error", "a binary entry_point without the executable bit"},
	{"windows-binary", "warning", "a binary server that claims win32 but ships no .exe"},
	{"deps-not-bundled", "error", "package.json dependencies missing from node_modules, or Python deps with no lib/venv"},
	{"dev-deps-bundled", "warning", "devDependencies are packed into node_modules"},
	{"uv-layout", "error", "uv server without pyproject.toml, or with server/lib or server/venv"},
	{"manifest-not-at-root", "error", "the archive has manifest.json inside a folder instead of at its root"},
	{"sensitive-file", "error", "a .env file, private key, keystore or credentials file is packed"},
	{"secret-in-file", "error", "a packed source file contains an API key, token or private key"},
	{"junk-file", "note", "__pycache__, .pyc, .DS_Store, .git or test caches are packed"},
	{"large-bundle", "note", "the bundle or one file in it is unusually large"},
}
