package server_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// forbiddenCalls are the operations that open a capsule or handle key material.
var forbiddenCalls = []string{
	"recoverykey.Generate(", "recoverykey.Split(", "recoverykey.Combine(", "recoverykey.FromSeed(",
	"shamir.Split(", "shamir.Combine(",
	"capsule.Open(", "capsule.Seal(", "hpke.", "hpke.NewRecipient(",
}

// forbiddenImports are the packages nothing in the server may even link against. A blind
// store that cannot import them cannot grow a decrypt path by accident later.
var forbiddenImports = []string{
	"github.com/Busness-app/ky-primitives/shamir",
	"crypto/hpke", "crypto/mlkem", "crypto/ecdh",
}

// kyrecovery is a blind store. Nothing linked into the server may be able to open a capsule
// or hold the recovery private key. cmd/ceremony-wasm is excluded because it runs in the
// operator's browser and never links into the server binary; test files are excluded
// because tests are where keys are allowed.
func TestNothingInTheServerDecrypts(t *testing.T) {
	root, _ := filepath.Abs("../..")
	ceremony := filepath.Join(root, "cmd", "ceremony-wasm")
	if _, err := os.Stat(ceremony); err != nil {
		t.Fatalf("the excluded ceremony directory must exist, or this test excludes nothing: %v", err)
	}
	checked := 0
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "node_modules" || path == ceremony {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		checked++

		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, call := range forbiddenCalls {
			if strings.Contains(string(src), call) {
				t.Errorf("%s calls %s; the server must not be able to decrypt", path, call)
			}
		}

		// The grep above only sees the spellings it knows. The import list is the
		// complete answer: an aliased or renamed call still needs the package.
		f, err := parser.ParseFile(token.NewFileSet(), path, src, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, spec := range f.Imports {
			p, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			for _, bad := range forbiddenImports {
				if p == bad {
					t.Errorf("%s imports %s; the server must not link key material handling", path, p)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 10 {
		t.Fatalf("only %d files scanned; the walk is not covering the module", checked)
	}
}
