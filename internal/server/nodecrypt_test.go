package server_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// kyrecovery is a blind store. Nothing linked into the server may be able to open a capsule
// or hold the recovery private key. The WASM command is excluded because it never links
// into the server binary; test files are excluded because tests are where keys are allowed.
func TestNothingInTheServerDecrypts(t *testing.T) {
	forbidden := []string{"recoverykey.Generate(", "recoverykey.Split(", "recoverykey.Combine(", "recoverykey.FromSeed(", "capsule.Open(", "capsule.Seal(", "hpke.NewRecipient("}
	root, _ := filepath.Abs("../..")
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "node_modules" || path == filepath.Join(root, "cmd", "ceremony-wasm") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, f := range forbidden {
			if strings.Contains(string(src), f) {
				t.Errorf("%s calls %s; the server must not be able to decrypt", path, f)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
