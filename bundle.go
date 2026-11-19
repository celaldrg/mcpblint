package main

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// BFile is one file that is (or would be) inside the bundle.
type BFile struct {
	Path    string // slash-separated, relative to the bundle root
	Size    int64
	Mode    fs.FileMode
	HasMode bool // false when the archive carries no Unix permissions
	read    func() ([]byte, error)
}

func (f *BFile) Read() ([]byte, error) { return f.read() }

// Bundle is a packed .mcpb archive, a source directory (seen the way
// `mcpb pack` would pack it) or a bare manifest with no files.
type Bundle struct {
	Kind     string // "archive", "directory" or "manifest"
	Name     string
	Manifest []byte
	Files    map[string]*BFile
	Dirs     map[string]bool
	Ignored  int
	Prefix   string // archive only: folder the manifest was found in, if not the root
	closer   io.Closer
}

func (b *Bundle) Close() {
	if b.closer != nil {
		b.closer.Close()
	}
}

func (b *Bundle) HasFiles() bool { return b.Kind != "manifest" }

func (b *Bundle) Has(p string) bool {
	_, ok := b.Files[cleanRel(p)]
	return ok
}

func (b *Bundle) HasDir(p string) bool { return b.Dirs[strings.TrimSuffix(cleanRel(p), "/")] }

func (b *Bundle) Get(p string) *BFile { return b.Files[cleanRel(p)] }

func (b *Bundle) Paths() []string {
	out := make([]string, 0, len(b.Files))
	for p := range b.Files {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func (b *Bundle) TotalSize() int64 {
	var n int64
	for _, f := range b.Files {
		n += f.Size
	}
	return n
}

func cleanRel(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.TrimPrefix(p, "./")
	return path.Clean(p)
}

func (b *Bundle) addDirs(p string) {
	for d := path.Dir(p); d != "." && d != "/"; d = path.Dir(d) {
		b.Dirs[d] = true
	}
}

// Load opens a target given on the command line.
func Load(arg string) (*Bundle, error) {
	if arg == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, err
		}
		return &Bundle{Kind: "manifest", Name: "<stdin>", Manifest: data}, nil
	}
	st, err := os.Stat(arg)
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return loadDir(arg, arg)
	}
	f, err := os.Open(arg)
	if err != nil {
		return nil, err
	}
	head := make([]byte, 4)
	n, _ := io.ReadFull(f, head)
	f.Close()
	if n == 4 && bytes.Equal(head, []byte("PK\x03\x04")) {
		return loadZip(arg)
	}
	ext := strings.ToLower(filepath.Ext(arg))
	if ext == ".mcpb" || ext == ".dxt" || ext == ".zip" {
		return nil, fmt.Errorf("not a zip archive (a .mcpb bundle is a zip file with manifest.json at its root)")
	}
	// A manifest file: lint it together with the folder it lives in.
	b, err := loadDir(filepath.Dir(arg), arg)
	if err != nil {
		return nil, err
	}
	if filepath.Base(arg) != "manifest.json" {
		data, err := os.ReadFile(arg)
		if err != nil {
			return nil, err
		}
		b.Manifest = data
	}
	return b, nil
}

func loadDir(dir, name string) (*Bundle, error) {
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("no manifest.json in %s", dir)
		}
		return nil, err
	}
	b := &Bundle{Kind: "directory", Name: name, Manifest: data, Files: map[string]*BFile{}, Dirs: map[string]bool{}}
	var extra []string
	if ig, err := os.ReadFile(filepath.Join(dir, ".mcpbignore")); err == nil {
		extra = strings.Split(strings.ReplaceAll(string(ig), "\r\n", "\n"), "\n")
	}
	ign := newIgnorer(append(append([]string{}, defaultExcludes...), extra...))
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if ign.ignored(rel) {
			b.Ignored++
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			b.Dirs[rel] = true
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		full := p
		b.Files[rel] = &BFile{Path: rel, Size: info.Size(), Mode: info.Mode(), HasMode: true,
			read: func() ([]byte, error) { return os.ReadFile(full) }}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return b, nil
}

func loadZip(name string) (*Bundle, error) {
	zr, err := zip.OpenReader(name)
	if err != nil {
		return nil, fmt.Errorf("cannot read archive: %v", err)
	}
	b := &Bundle{Kind: "archive", Name: name, Files: map[string]*BFile{}, Dirs: map[string]bool{}, closer: zr}
	var manifest *zip.File
	var nested []*zip.File
	for _, f := range zr.File {
		p := strings.ReplaceAll(f.Name, "\\", "/")
		if p == "manifest.json" {
			manifest = f
		} else if strings.Count(p, "/") == 1 && strings.HasSuffix(p, "/manifest.json") {
			nested = append(nested, f)
		}
	}
	if manifest == nil && len(nested) == 1 {
		manifest = nested[0]
		b.Prefix = strings.TrimSuffix(manifest.Name, "manifest.json")
	}
	if manifest == nil {
		zr.Close()
		return nil, fmt.Errorf("no manifest.json at the root of the archive")
	}
	rc, err := manifest.Open()
	if err != nil {
		zr.Close()
		return nil, err
	}
	b.Manifest, err = io.ReadAll(rc)
	rc.Close()
	if err != nil {
		zr.Close()
		return nil, err
	}
	for _, f := range zr.File {
		p := strings.ReplaceAll(f.Name, "\\", "/")
		if b.Prefix != "" {
			if !strings.HasPrefix(p, b.Prefix) {
				continue
			}
			p = strings.TrimPrefix(p, b.Prefix)
		}
		if p == "" {
			continue
		}
		if strings.HasSuffix(p, "/") {
			b.Dirs[strings.TrimSuffix(p, "/")] = true
			continue
		}
		zf := f
		bf := &BFile{Path: p, Size: int64(f.UncompressedSize64),
			read: func() ([]byte, error) {
				rc, err := zf.Open()
				if err != nil {
					return nil, err
				}
				defer rc.Close()
				return io.ReadAll(io.LimitReader(rc, 64<<20))
			}}
		// Unix permissions live in the high 16 bits when the zip was made on Unix.
		if f.CreatorVersion>>8 == 3 {
			bf.Mode = fs.FileMode(f.ExternalAttrs>>16) & fs.ModePerm
			bf.HasMode = true
		}
		b.Files[p] = bf
		b.addDirs(p)
	}
	return b, nil
}

// defaultExcludes is the list `mcpb pack` always leaves out of a bundle.
var defaultExcludes = []string{
	".DS_Store", "Thumbs.db", ".gitignore", ".git", ".mcpbignore", "*.log", ".env*", ".npm", ".npmrc",
	".yarnrc", ".yarn", ".eslintrc", ".editorconfig", ".prettierrc", ".prettierignore", ".eslintignore",
	".nycrc", ".babelrc", ".pnp.*", "node_modules/.cache", "node_modules/.bin", "*.map", ".env.local",
	".env.*.local", "npm-debug.log*", "yarn-debug.log*", "yarn-error.log*", "package-lock.json", "yarn.lock",
	"*.mcpb", "*.d.ts", "*.tsbuildinfo", "tsconfig.json",
}

type ignorePat struct {
	re      *regexp.Regexp
	neg     bool
	dirOnly bool
}

type ignorer []ignorePat

// newIgnorer understands the gitignore subset bundles use: globs with * ? **,
// leading / to anchor, trailing / for directories and ! to re-include.
func newIgnorer(lines []string) ignorer {
	var out ignorer
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		p := ignorePat{}
		if strings.HasPrefix(ln, "!") {
			p.neg = true
			ln = ln[1:]
		}
		if strings.HasSuffix(ln, "/") {
			p.dirOnly = true
			ln = strings.TrimSuffix(ln, "/")
		}
		anchored := strings.Contains(ln, "/")
		ln = strings.TrimPrefix(ln, "/")
		if strings.HasPrefix(ln, "**/") {
			ln = ln[3:]
			anchored = false
		}
		var re strings.Builder
		if anchored {
			re.WriteString("^")
		} else {
			re.WriteString("(^|/)")
		}
		for i := 0; i < len(ln); i++ {
			c := ln[i]
			switch {
			case c == '*' && i+1 < len(ln) && ln[i+1] == '*':
				re.WriteString(".*")
				i++
			case c == '*':
				re.WriteString("[^/]*")
			case c == '?':
				re.WriteString("[^/]")
			default:
				re.WriteString(regexp.QuoteMeta(string(c)))
			}
		}
		re.WriteString("(/.*)?$")
		r, err := regexp.Compile(re.String())
		if err != nil {
			continue
		}
		p.re = r
		out = append(out, p)
	}
	return out
}

func (ig ignorer) ignored(rel string) bool {
	hit := false
	for _, p := range ig {
		if p.re.MatchString(rel) {
			hit = !p.neg
		}
	}
	return hit
}
