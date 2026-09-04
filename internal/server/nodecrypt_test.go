package server_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// allowedSelectors names, per package, the only identifiers a file linked into the server
// may reach for. Everything else in these packages either opens a capsule or handles key
// material. An empty set means the package is off limits entirely.
var allowedSelectors = map[string]map[string]bool{
	// Parsing and holding the public half is the whole of the server's business with it.
	"github.com/Busness-app/ky-primitives/recoverykey": {"ParsePublicKey": true, "PublicKey": true},
	// Reading the unencrypted manifest and knowing how big a container may be.
	"github.com/Busness-app/ky-primitives/capsule": {"ReadUnverifiedManifest": true, "Manifest": true, "MaxContainerBytes": true},
	"github.com/Busness-app/ky-primitives/shamir":  {},
	"crypto/hpke": {},
}

// forbiddenImports are packages no file linked into the server may name directly. The
// binary still links them transitively — recoverykey and capsule use them, as does TLS —
// and this says nothing about that; it says the server's own code never reaches for them.
var forbiddenImports = []string{
	"github.com/Busness-app/ky-primitives/shamir",
	"crypto/hpke", "crypto/mlkem", "crypto/ecdh",
}

// kyrecovery is a blind store. Nothing linked into the server may be able to open a capsule
// or hold the recovery private key. cmd/ceremony-wasm is excluded because it runs in the
// operator's browser and never links into the server binary; test files are excluded
// because tests are where keys are allowed.
//
// The check is on the resolved import, not the spelling: `import rk ".../recoverykey"`
// followed by rk.Combine( is the same violation as recoverykey.Combine(.
func TestNothingInTheServerDecrypts(t *testing.T) {
	root, _ := filepath.Abs("../..")
	ceremony := filepath.Join(root, "cmd", "ceremony-wasm")
	if _, err := os.Stat(ceremony); err != nil {
		t.Fatalf("the excluded ceremony directory must exist, or this test excludes nothing: %v", err)
	}
	checked := 0
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Dot directories hold checkouts of this module (.claude/worktrees), which are
			// somebody else's copy of these rules to enforce.
			if p != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "node_modules" || p == ceremony) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		checked++
		checkFile(t, p)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 10 {
		t.Fatalf("only %d files scanned; the walk is not covering the module", checked)
	}
}

func checkFile(t *testing.T, file string) {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatalf("%s: %v", file, err)
	}

	// Bind every local name to the package it stands for, so an alias is followed rather
	// than believed.
	watched := map[string]string{} // identifier -> import path
	for _, spec := range f.Imports {
		p, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		for _, bad := range forbiddenImports {
			if p == bad {
				t.Errorf("%s imports %s directly; the server must not reach for key material", file, p)
			}
		}
		name := path.Base(p)
		if spec.Name != nil {
			name = spec.Name.Name
		}
		if name == "." && (strings.HasPrefix(p, "github.com/Busness-app/ky-primitives/") || p == "crypto/hpke") {
			// A dot import puts the package's whole surface in scope under no name at
			// all, which no amount of selector checking can follow.
			t.Errorf("%s dot-imports %s; that hides every call it makes", file, p)
		}
		if _, ok := allowedSelectors[p]; ok && name != "_" && name != "." {
			watched[name] = p
		}
	}
	if len(watched) == 0 {
		return
	}

	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		pkg, ok := watched[ident.Name]
		if !ok {
			return true
		}
		if !allowedSelectors[pkg][sel.Sel.Name] {
			t.Errorf("%s uses %s.%s; the server may only use %v from that package",
				file, pkg, sel.Sel.Name, keysOf(allowedSelectors[pkg]))
		}
		return true
	})
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
