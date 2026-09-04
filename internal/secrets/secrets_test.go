package secrets_test

import (
	"testing"

	"github.com/Busness-app/kyrecovery-server/internal/secrets"
)

// A value that is not a sealed envelope never comes back out of Open. Anyone who can write
// the database could otherwise plant a plaintext credential and have the server use it.
func TestOpenRefusesUnsealedValues(t *testing.T) {
	k, err := secrets.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := k.Seal("s3-secret")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := k.Open(sealed); err != nil || got != "s3-secret" {
		t.Fatalf("round trip: %q %v", got, err)
	}
	for _, bad := range []string{"s3-secret", "enc:v0:abc", "enc:v1", " enc:v1:abc"} {
		if got, err := k.Open(bad); err == nil {
			t.Errorf("Open(%q) returned %q; an unsealed value must be an error", bad, got)
		}
	}
	// Nothing stored is not a credential to refuse.
	if got, err := k.Open(""); err != nil || got != "" {
		t.Fatalf("Open(\"\") = %q %v", got, err)
	}
}
