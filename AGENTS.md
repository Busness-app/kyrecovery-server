# KyRecovery Server

KyRecovery Server is the self-hosted recovery and restore-verification service for the KySecurity Suite of software (KySignOn, KyPassword, KyBookmarks, KyNotes, KyPost) and Business.app ecosystem. Supported service connectors operate through the unified, content-blind declarative recipe engine (`generic`, `kysignon`, `kypassword`, and dynamic pairing clients).

## Core Capabilities & Responsibilities

1. **Encrypted Recovery Capsules**: Generates and stores content-blind `.kycap` recovery archives containing service databases, signing keys, and configuration manifests.
2. **Zero-Code Product Pairing & Self-Declaring Ingest**: Generates ephemeral 6-digit pairing codes (`/api/pairing/*`). Any KySecurity or Business.app service pairs seamlessly and pushes self-declared backups (`/api/backup/push`) with custom files and verification recipes without KyRecovery server code modifications. The wire contract is `zero_code_pairing_handoff_spec.md`; changes to either side must keep `TestPublishedSpecClientCanPairAndPush` passing.
3. **Local Admin Bootstrap & KySignOn OIDC SSO Pairing**: Generates local administrator credentials on first startup, protects dashboard and API routes with Argon2id salted password authentication and SQLite session tokens, and provides an interactive KySignOn OIDC SSO pairing portal with PKCE (`S256`). Every API route is authorized by the `apiPolicy` table in `internal/server/server.go` against the `admin` > `operator` > `viewer` ordering; SSO identities are verified against the issuer's JWKS before a session exists.
4. **Interactive Custodian Quorum Ceremonies ($M$-of-$N$)**: Coordinates multi-party asynchronous Shamir share gathering via ephemeral in-memory sessions with automatic zeroing memory scrub upon execution.
5. **Offsite Remote Capsule Replication (S3 / Cloudflare R2 / Local Mounts)**: Automatically or manually replicates content-blind `.kycap` recovery archives to AWS S3, Cloudflare R2, MinIO, or offsite disk mounts using pure-Go SigV4 signing.
6. **Air-Gapped Terminal Disaster Console (`kyrecovery tui`)**: Provides an interactive keyboard-driven ANSI terminal interface for bare-metal offline disaster recovery environments without network access or web browsers.
7. **Capsule Version Diff & Snapshot Rollback Inspector**: Computes content-blind file, size, and dependency diffs across historical captures to detect drift and accelerate disaster rollback decisions.
8. **Automated Ephemeral Restore Drills**: Runs scheduled or on-demand restore drills in isolated scratch sandboxes, testing database integrity, token signing, and dependency manifests, followed by automatic cryptographic wiping.
9. **Keyed Hash-Chained Audit Ledger**: Records HMAC-SHA256 chained events for capture, approval, export, drill, and restore operations. The ledger key lives outside SQLite, so an attacker with database write access cannot rewrite an event and recompute the chain. It is not proof against an attacker holding the data directory.
10. **Emergency Recovery Kit Export**: Produces self-contained, human-readable offline disaster recovery runbooks (HTML & Markdown).
11. **Privacy-Safe Structured Logging**: Adheres strictly to `LOGGING.md` by emitting structured JSON/logfmt to stdout/stderr without logging secrets, keys, or capsule contents.

## Security Invariants

- Capsule data is encrypted at rest and in transit using AES-256-GCM / ChaCha20-Poly1305.
- The server must never store plaintext master keys, passwords, or third-party
  credentials in the database. Replication secret keys and the SSO client secret
  are sealed with the keyring in `internal/secrets`, whose key lives in
  `<data-dir>/secret.key` (0600) or `KYRECOVERY_SECRET_KEY`.
- Every `/api/` route has an entry in `apiPolicy`; anything unlisted defaults to
  `admin`. New routes must be added to the table and to `TestRequiredRolePolicy`.
- An OIDC identity is only trusted after `verifier.Verify` accepts the ID token's
  signature, issuer, audience and expiry, and the login nonce matches. A failed
  ID token is never retried against `userinfo`; unknown role claims become `viewer`.
- Outbound issuer requests use `auth.httpClient`, whose dialer refuses link-local
  destinations at connect time (covering redirects and DNS rebinding).
- Capsule IDs carry random entropy and capsules are published temp-file → fsync →
  rename → database insert, so a concurrent capture can never overwrite an
  existing recovery point.
- Every API request body is bounded (`bodyLimit`); self-declared pushes are
  additionally bounded by file count and decoded size, and rate limited per token.
- Session cookies are `HttpOnly`, and `Secure` whenever the login arrived over
  TLS or `--cookie-secure=true` is set. Session tokens are never returned in a
  response body.
- Drill scratch environments must be created with restricted permissions (`0700`) and securely scrubbed upon drill completion.
- SQLite database transactions must be atomic and use WAL mode with foreign key constraints.
- Sensitive HTTP responses must enforce `Cache-Control: no-store` and standard security headers.
- Unauthenticated pairing claims are rate limited per source address and per code, and the claim's single-use and expiry guards live in the SQL `UPDATE`, not only in Go checks.
- Capsule entries never resolve outside their restore directory: every extraction path goes through `capsule.SafeJoin`.

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
go test -v ./...
```

Verify binary build and CLI drill verification:
```bash
go build -o kyrecovery cmd/kyrecovery/main.go
./kyrecovery help
```

## Child DOX Index
- `zero_code_pairing_handoff_spec.md`: authoritative spec for the zero-code pairing and self-declaring backup ingest API this server exposes (`/api/pairing/generate`, `/api/pairing/claim`, `/api/backup/push`). A change here is breaking for every paired product; update their copies in the same change set.
