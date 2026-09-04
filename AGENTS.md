# KyRecovery Server

KyRecovery Server is the self-hosted **blind store** for the KySecurity Suite (KySignOn, KyPassword, KyBookmarks, KyNotes, KyPost) and the Business.app ecosystem. Products seal their own `.kycap` containers with `ky-primitives/capsule` and deposit the ciphertext here. The server holds no recovery private key, no Shamir share and no plaintext, and no code path in it decrypts a capsule.

## Core Capabilities & Responsibilities

1. **Sealed-container deposit**: `POST /api/backup/deposit` takes an `application/octet-stream` body under a paired product's bearer token, reads `capsule.ReadUnverifiedManifest`, checks the manifest's recovery key ID against the pinned key and its service name against the token, hashes the bytes and stores them. `201` for a new capsule, `200` for a byte-identical re-send. The wire contract is `zero_code_pairing_handoff_spec.md`.
2. **Browser keypair ceremony**: `/admin/ceremony` (admin session) serves `ceremony.wasm`, a `GOOS=js GOARCH=wasm` build of `cmd/ceremony-wasm` compiled from this commit. It calls `recoverykey.Generate` and `recoverykey.Split` in the tab, prints custodian cards, and posts only `{public_key, threshold, total_shares}` to `POST /api/recovery-key`. The import is single-shot; a second one is `409`.
3. **Zero-code product pairing**: ephemeral six-digit codes (`/api/pairing/*`). `POST /api/pairing/claim` returns the API token plus `recovery_public_key`, `threshold` and `total_shares`, and is refused `409` before the ceremony has run, without consuming the code.
4. **Local admin bootstrap & KySignOn OIDC SSO**: local `admin` credentials on first start, PHC-format passwords via `ky-primitives/password`, SQLite session tokens, and an OIDC pairing portal with PKCE (`S256`). Every API route is authorized by `apiPolicy` in `internal/server/server.go` against `admin` > `operator` > `viewer`; SSO identities are verified against the issuer's JWKS before a session exists.
5. **Integrity attestation**: `GET /api/capsules/{id}/verify` re-hashes the stored blob and appends `capsule_verified` or `capsule_corrupt`, flagging the row; a sweep does the same for every capsule every 24 hours. `GET /api/capsules/{id}/download` returns the bytes with `X-Capsule-Digest` and `X-Capsule-Status`.
6. **Offsite replication (S3 / Cloudflare R2 / MinIO / local mounts)**: replicates stored containers to auto-sync targets with pure-Go SigV4 signing.
7. **Capsule diff & timeline inspector**: `internal/diff` computes drift across deposits from `capsules` rows — the recorded manifest fields — never by opening a container.
8. **Hash-chained audit ledger**: `ky-primitives/auditchain`, keyed from the keyring, with the anchor (count, last hash) kept outside the log. `POST /api/audit/verify` returns `{valid, count, last_hash}` and `append_disabled` + `error` when the ledger is poisoned. A poisoned ledger refuses deposits with `503` until an operator repairs the log and restarts.
9. **Privacy-safe structured logging**: `LOGGING.md` — structured JSON/logfmt to stdout/stderr, never secrets, keys or capsule contents.

## Package index

| Path | Holds |
| :--- | :--- |
| `cmd/kyrecovery` | The binary. `app.Run` dispatches `serve`, `audit`, `pair`, `help`. |
| `cmd/ceremony-wasm` | The `js/wasm` ceremony module. The only code in the repo that generates or splits a private key. It never links into the server binary. |
| `internal/server` | Routes, `apiPolicy`, deposit, recovery-key import, verify sweep, limits, embedded dashboard and ceremony page under `static/`. |
| `internal/auth` | Sessions, local admin, OIDC/PKCE, role ranking. |
| `internal/db` | SQLite schema and every query, including `capsules`, `recovery_key` and `paired_apps`. |
| `internal/audit` | The ledger over `auditchain`, its anchor and health latch. |
| `internal/pairing` | Pairing code generation and claim. |
| `internal/replication` | Offsite targets and the SigV4 S3 client. |
| `internal/secrets` | The keyring: master key from `KYRECOVERY_SECRET_KEY` or `<data-dir>/secret.key` via `ky-primitives/keyfile`. |
| `internal/crypto` | AES-256-GCM envelope used by the keyring, and nothing else. |
| `internal/diff` | The capsule diff and timeline inspector. |
| `pkg/client` | The product-side SDK: `ClaimPairing`, `Client.Deposit`. |
| `scripts` | `build-wasm.sh` rebuilds the committed module byte-for-byte; `test-wasm.mjs` runs it under Node. |

## Security Invariants

- **Nothing in the server decrypts.** `recoverykey.Generate/Split/Combine/FromSeed`, `capsule.Open`, `capsule.Seal` and `hpke.NewRecipient` may not appear in any non-test `.go` file outside `cmd/ceremony-wasm`. `TestNothingInTheServerDecrypts` walks the repo and fails if one does. Do not weaken it to land a feature.
- A deposit's manifest is displayed, never obeyed. The only decision taken from it is comparing `RecoveryKeyID` with the pinned key ID, a hash of a public key the server already holds.
- The server must never store plaintext master keys, passwords or third-party credentials. Replication secret keys and the SSO client secret are sealed with the keyring in `internal/secrets`.
- Every `/api/` route has an entry in `apiPolicy`; anything unlisted defaults to `admin`. New routes must be added to the table and to `TestRequiredRolePolicy`.
- An `/api/` path is rejected unless it equals `path.Clean` of itself, and both the capsule policy and the capsule handler read the URL through `parseCapsulePath`. Authorization and dispatch must never parse a URL twice.
- Credentials are never serialised by default. `PairedAppRecord.APIToken`, `PairedAppRecord.PairingCode`, `SessionRecord.ID` and `CapsuleRecord.FilePath` are `json:"-"`; the pairing code is returned only by `POST /api/pairing/generate` and the token only by `POST /api/pairing/claim`, each building its response explicitly.
- An OIDC identity is only trusted after `verifier.Verify` accepts the ID token's signature, issuer, audience and expiry, and the login nonce matches. A failed ID token is never retried against `userinfo`; unknown role claims become `viewer`.
- Outbound issuer requests use `auth.httpClient`, whose dialer refuses link-local destinations at connect time (covering redirects and DNS rebinding).
- A capsule ID becomes a filename, so it is held to `capsuleIDPattern` and published temp-file → fsync → row insert → rename. The database row is the mutual-exclusion primitive: racing deposits of one ID cannot both claim the path, and a row whose file is missing is marked corrupt rather than treated as a successful deposit.
- Every API request body is bounded (`bodyLimit`): 1 MiB, or `capsule.MaxContainerBytes` for the deposit. Deposits are rate limited per token and capped at 4 in flight.
- A deposit that cannot be recorded in the ledger is refused. The audit trail is most of a blind store's evidence that a deposit happened.
- Session cookies are `HttpOnly`, and `Secure` whenever the login arrived over TLS or `--cookie-secure=true` is set. Session tokens are never returned in a response body — `TestSessionTokenNeverAppearsInAResponseBody` checks the bodies, not just the handler that used to leak one. Changing a password ends every other session belonging to that user.
- SQLite transactions must be atomic and use WAL mode with foreign key constraints.
- Sensitive HTTP responses must enforce `Cache-Control: no-store` and standard security headers.
- Unauthenticated pairing claims are rate limited per source address and per code, and the claim's single-use and expiry guards live in the SQL `UPDATE`, not only in Go checks.
- The audit ledger records a resolved identity. `Server.actor` derives it from the session; a caller-supplied name goes in `details` under a `claimed_` key, never in `actor`.
- The dashboard escapes every value it interpolates into HTML — `esc` for markup, `escJs` for a value inside an inline handler's JS string — and every response carries a Content-Security-Policy. `/admin/ceremony` carries a stricter one with `wasm-unsafe-eval` and no inline script or style. `TestEmbeddedDashboardEscapesEveryInnerHTMLSink` reads the shipped asset and fails on a new unescaped sink.

# Ponytail, lazy senior dev mode

Use the smallest correct change.

1. Reuse what already exists.
2. Prefer stdlib and native platform APIs.
3. Add dependencies only when they remove meaningful code.
4. Fix shared root causes, not one caller.
5. If a shortcut has a limit, mark it with `ponytail:` and name the upgrade path.

Non-trivial logic must include one runnable check (unit test or minimal self-check).

# DOX framework

## Core Contract

- AGENTS.md files are binding contracts for their subtree.
- Read from root to nearest AGENTS.md before editing.
- The nearest AGENTS.md controls local details; parent docs keep global rules.

## Update After Editing

- Run a DOX pass for every meaningful change.
- Update nearest owning AGENTS.md when behavior, responsibilities, or verification changes.
## Verification

Run all unit and integration tests across the repository:
```bash
go test -race -count=1 ./...
```

Verify the binary builds and the CLI answers:
```bash
go build -o kyrecovery cmd/kyrecovery/main.go
./kyrecovery help
```

Rebuild the ceremony module and prove the committed artefact matches, then run it:
```bash
scripts/build-wasm.sh && git diff --exit-code -- internal/server/static/wasm
node scripts/test-wasm.mjs
```

## Child DOX Index
- `zero_code_pairing_handoff_spec.md`: the wire contract for pairing and deposit that this server exposes (`/api/pairing/generate`, `/api/pairing/claim`, `/api/backup/deposit`). A change here is breaking for every paired product; update their copies in the same change set.
