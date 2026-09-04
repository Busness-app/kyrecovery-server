//go:build js && wasm

// ceremony-wasm is the only code in this repository that ever holds the suite recovery
// private key, and it runs in an operator's browser tab, never in the server. It exposes one
// function to the page: generate a keypair, split the seed, return the cards' contents and
// the public half. Nothing here can write to the network or to disk.
package main

import (
	"encoding/base64"
	"syscall/js"

	"github.com/Busness-app/ky-primitives/recoverykey"
)

func ceremony(_ js.Value, args []js.Value) any {
	if len(args) != 2 {
		return map[string]any{"error": "kyCeremony(threshold, total)"}
	}
	k, n := args[0].Int(), args[1].Int()
	priv, err := recoverykey.Generate()
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	shares, err := recoverykey.Split(priv, k, n)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	out := make([]any, len(shares))
	for i, s := range shares {
		out[i] = s.String()
	}
	pub := priv.Public()
	return map[string]any{
		"key_id":         pub.ID(),
		"public_key_b64": base64.StdEncoding.EncodeToString(pub.Bytes()),
		"threshold":      k,
		"total_shares":   n,
		"shares":         out,
	}
}

func main() {
	js.Global().Set("kyCeremony", js.FuncOf(ceremony))
	select {}
}
