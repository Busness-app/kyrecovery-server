# KyRecovery

KyRecovery is a self-hosted recovery and restore-verification service for
KySecurity deployments.

Its purpose is to make recovery a tested capability instead of a collection of
backups that may or may not work when an administrator needs them.

## What it does

- Creates encrypted recovery capsules for KySecurity services.
- Stores recovery instructions, configuration, dependencies, and required
  secrets without exposing them to the KyRecovery server in plaintext.
- Supports offline recovery material and designated recovery custodians.
- Runs scheduled restore drills in an isolated environment.
- Reports missing files, expired credentials, failed dependencies, restore time,
  and the last successful verification.
- Records hash-chained, content-blind recovery events, authenticated with a
  server key held outside the database.
- Exports a human-readable recovery kit for emergency use.

## Example workflow

```text
Capture → encrypt → approve → verify restore → report readiness
```

An administrator should be able to answer:

1. What must be restored?
2. Which files, keys, and credentials are required?
3. Who can authorize emergency recovery?
4. When was the last successful restore test?
5. How long did recovery take?

## Recovery model

- Recovery material is encrypted before it is stored remotely or on disk.
- The KyRecovery service must not be able to read vaults, mail, notes, or
  private keys by itself.
- Recovery access is time-limited and audited.
- Custodian approval or a configurable quorum is required for sensitive
  capsules.
- A recovery drill uses disposable isolated state and deletes it after
  verification.
- Recovery does not promise to undo data that was already exposed or deleted.

## Initial scope

The first version should support one complete service adapter, preferably
KySignOn or KyPassword, including:

- encrypted capsule creation;
- offline export;
- isolated restore verification;
- missing-dependency reporting; and
- an audit record for capture, approval, drill, and restore.

Cross-service orchestration, custodian rotation, remote drill environments, and
automatic secret rotation are later work.

## Security model

- **Roles.** Every API route is authorized against `viewer` < `operator` <
  `admin`. Viewers read; operators run captures, drills and ceremonies; admins
  change pairing, replication targets and SSO. An unrecognised role claim from an
  identity provider is treated as `viewer`. API paths must be canonical, so a URL
  cannot mean one thing to the policy and another to the handler.
- **Credentials.** A product API token is shown once, to the product that claims
  the pairing code. A pairing code is shown once, to the administrator who
  generates it, and is valid for at most an hour. Neither appears in the paired
  products listing, and no response body contains a session token.
- **Server key.** `<data-dir>/secret.key` (0600, or `KYRECOVERY_SECRET_KEY`)
  seals replication credentials and the SSO client secret, and keys the audit
  ledger. Back it up with the database — without it those secrets are
  unrecoverable. It defends against a stolen database, not against an attacker
  who already has the data directory.
- **Transport.** Session cookies are `HttpOnly`, and `Secure` when the login
  arrived over TLS (directly or via `X-Forwarded-Proto`). Run KyRecovery behind
  TLS and set `--cookie-secure=true` to make that unconditional. Changing your
  password signs out every other session on the account.
- **Dashboard.** Values from the database are escaped before they are rendered,
  and every response carries a Content-Security-Policy that keeps injected markup
  from reaching anything off-origin.
- **Limits.** API bodies are capped at 1 MiB; self-declared backup pushes at
  `KYRECOVERY_MAX_BACKUP_BYTES` (64 MiB by default), 4096 files, 60 pushes per
  15 minutes per paired product, and 4 pushes in flight at once. KyRecovery does
  not yet reserve or enforce free disk space for the capsule volume — size that
  volume for your retention.
- **Drills.** A restore drill only reads what the capsule restored. Verification
  recipes come from the pushing product, so every path one names is resolved
  inside the drill sandbox; a recipe that reaches outside fails the drill.
- **Drill cleanup.** Restored files are overwritten before deletion. On SSDs,
  copy-on-write filesystems and virtualised storage that reduces exposure but
  cannot guarantee the original blocks are gone.
- **SSO.** The issuer must publish `/.well-known/openid-configuration`; endpoints
  and signing keys come from discovery, not from hardcoded paths.

## Repository status

The server is implemented and tested: capsule capture, zero-code pairing and
self-declaring ingest, custodian quorum ceremonies, restore drills, offsite
replication, the audit ledger, recovery kit export, and the air-gapped TUI. The
later work listed under Initial scope is still outstanding.

Verify with `go test ./...`.
