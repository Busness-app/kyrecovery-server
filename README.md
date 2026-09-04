# KyRecovery

KyRecovery is a self-hosted **blind store** for the KySecurity suite's encrypted
backups. Products seal their own `.kycap` containers and deposit the ciphertext
here. KyRecovery holds no recovery private key, no Shamir share and no plaintext,
and there is no code path in the server that decrypts a capsule — a test,
`TestNothingInTheServerDecrypts`, fails the build if one appears.

## What it holds

- kycap/3 containers exactly as deposited, plus the SHA-256 KyRecovery computed
  over each one at deposit.
- The manifest fields the container declares about itself: capsule ID, service
  name, app version, payload hash, threshold, total shares, recovery key ID and
  encapsulated key. They are recorded and displayed, never acted on — the one
  decision taken from a manifest is whether its recovery key ID is the one this
  store pins.
- A hash-chained audit ledger over deposits, verifications, pairings and the key
  import, keyed outside the database.
- The suite recovery **public** key and its ID, custodian names, paired-app API
  tokens, and the server keyring for its own secrets.

## Ceremony: creating the suite recovery keypair

The suite has one long-lived recovery keypair. It is generated once, in the
operator's browser, by a WebAssembly build of `ky-primitives/recoverykey` that is
compiled from this repository and served over an admin session.

1. Sign in as an admin and open `/admin/ceremony`.
2. Choose k (threshold) and n (cards) and generate. The private key is split into
   n printable custodian shares in the tab; **only** `{public_key, threshold,
   total_shares}` is posted to `POST /api/recovery-key`.
3. Print the cards, hand them to the custodians, confirm the import, close the tab.

Rules for the ceremony tab — the seed lives in the tab's memory from generate
until the tab closes and cannot be erased before that:

- A fresh private window, with no browser extensions.
- On a machine that will not hibernate during the ceremony.
- Close the tab once the cards are printed and the import is confirmed.

**Do a print-preview dry run first.** Run the page once with throwaway values
(k=2, n=2), open the print preview from *Print cards*, and confirm on the preview
that the text is black on white, that every share string is fully visible and
wrapped rather than cut off at the right edge, that a card is not split across a
page break, and that no buttons, form or import status appear on paper. Discard
that keypair — do not import it — then run the real ceremony.

The import is single-shot: a second `POST /api/recovery-key` is refused with 409
naming the key already stored. Rotation is a separate procedure that does not
exist yet.

## Pairing and deposit

`POST /api/pairing/generate` (admin) mints a six-digit code, valid for 15 minutes
by default and at most 60. The product calls `POST /api/pairing/claim` with the
code; the response carries the API token **and** the key to seal to:

```json
{
  "id": "pair-...", "status": "paired", "api_token": "kyrec_live_...",
  "service_name": "kynotes", "app_name": "KyNotes Primary", "paired_at": "...",
  "server_url": "recovery.internal:8095",
  "recovery_public_key": "<standard base64, 1216 bytes>",
  "threshold": 3, "total_shares": 5
}
```

If no recovery key has been imported the claim is refused with `409` and the
pairing code is **not** consumed: run the ceremony before pairing anything.

`POST /api/backup/deposit` takes the sealed container itself:
`Authorization: Bearer <api_token>`, `Content-Type: application/octet-stream`,
body = a kycap/3 container sealed to the pinned public key.

| Status | Meaning |
| :--- | :--- |
| `201 Created` | Stored. Body: `{capsule_id, digest, size_bytes, deposited_at}`. |
| `200 OK` | The same capsule ID with the same bytes was already stored; the original record is returned. Re-sending is safe. |
| `400 Bad Request` | Not a kycap/3 container, or its `capsule_id`/`service_name` is not a usable name. |
| `401 Unauthorized` | Missing, invalid or revoked bearer token. |
| `403 Forbidden` | The manifest names a service this token is not paired for. |
| `409 Conflict` | Sealed to a different recovery key (both IDs are named), or this capsule ID is stored with different bytes, or no key has been imported. |
| `413 Content Too Large` | Body over the container ceiling `capsule.MaxContainerBytes` (384 MiB). Larger data needs the streaming container, which does not exist yet. |
| `429 Too Many Requests` | More than 60 deposits from this product in 15 minutes. |
| `503 Service Unavailable` | The audit ledger cannot append, or all 4 deposit slots are busy and the client went away. |

`pkg/client` is the Go SDK for both halves: `ClaimPairing` and `Client.Deposit`.

A stored capsule is replicated to every auto-sync offsite target configured
under `/api/replication/targets`. The bytes are as opaque there as they are
here. Target types:

- `s3`: any S3-compatible bucket, signed with SigV4.
- `sftp`: an SSH server. The secret is a password or a PEM private key. The
  server's host key is pinned: Test Connection reports the SHA256 fingerprint
  of an unknown server, the operator confirms it against `ssh-keygen -lf` and
  saves it, and a later mismatch refuses to connect. No pin, no connection.
- `smb`: a Windows or Samba share over SMB 2 or 3, never SMB1. The user may be
  `DOMAIN\user`. The client requires message signing. Known limitation: the
  SMB library accepts a server that grants a *guest* session, unsigned, so a
  host impersonating the share can swallow uploads while the sync log records
  success and can observe the NTLMv2 exchange. Give the target a strong
  password, keep it on a trusted network, and check the share occasionally.
  An SMB share mounted on the host and used as a `local` target does not have
  this gap.
- `local`: a directory, typically an NFS or SMB mount managed by the host.

Credentials for every type are sealed with `secret.key` before they reach the
database.

## Integrity

- `GET /api/capsules/{id}/verify` (viewer) re-reads the blob, compares its
  SHA-256 with the stored digest, appends `capsule_verified` or
  `capsule_corrupt`, and flags the row on a mismatch. A missing file counts as
  corrupt.
- A sweep does the same for every capsule every 24 hours, as actor
  `integrity-sweep`.
- `GET /api/capsules/{id}/download` (operator) returns the bytes with
  `X-Capsule-Digest` and `X-Capsule-Status`. A capsule flagged corrupt still
  downloads, for forensics; the header is how you know.
- `GET /api/readiness` (viewer) reports `capsule_count`, `custodian_count` and
  `audit_append_disabled`. A blind store cannot open a capsule, so it never
  claims a verified restore.

## Audit ledger

Events are appended to `ky-primitives/auditchain`, with the anchor (count and
last hash) kept outside the log. `POST /api/audit/verify` (operator) returns
`{valid, count, last_hash}`, plus `append_disabled` and `error` when the ledger
is poisoned.

Two operational facts:

- A full verify holds the ledger lock, so deposits stall while a large log is
  being verified.
- If the log and the anchor disagree at startup the ledger refuses to append and
  every deposit gets `503` until an operator repairs the log and restarts. The
  latch is per-process; it is not cleared by anything short of a restart.

## Restore

KyRecovery is not in the restore path beyond the download. A fresh product
instance is restored by running the **product's** `restore` command against the
`.kycap` and typing k custodians' shares from their cards. `capsule.Open` proves
the bytes are the sealed ones and were sealed to the pinned key; comparing the
capsule ID and creation time against KyRecovery's deposit record is where
freshness comes from.

## CLI

```
kyrecovery serve      Start the dashboard and REST API
kyrecovery audit      Inspect or verify the audit chain
kyrecovery pair       generate | list | claim — paired products and 6-digit codes
kyrecovery help
```

`serve` flags: `--port` (8095), `--data-dir` (`./data`), `--sso-issuer`,
`--sso-client-id`, `--sso-client-secret`, `--sso-redirect-url`,
`--sso-admin-email`, `--cookie-secure`.

## Configuration

| Variable | Effect |
| :--- | :--- |
| `KYRECOVERY_SECRET_KEY` | The keyring master key, hex or base64. Falls back to `<data-dir>/secret.key` (0600), created on first start. |
| `KY_SSO_ISSUER`, `KY_SSO_CLIENT_ID`, `KY_SSO_CLIENT_SECRET`, `KY_SSO_REDIRECT_URL` | KySignOn OIDC defaults for the matching `serve` flags. SSO is enabled when an issuer is set. |
| `KY_ADMIN_EMAIL` | The SSO identity granted `admin`. |
| `KY_ADMIN_INITIAL_PASSWORD` | The local `admin` password on first start. Without it one is generated and printed once. |
| `KYRECOVERY_COOKIE_SECURE` | `true`, `false`, or empty to follow the request transport. |

The data directory holds `kyrecovery.db`, `secret.key` and `capsules/`. Back all
three up together: without `secret.key` the sealed replication credentials, the
SSO client secret and the audit chain key are unrecoverable. The `.kycap` files
are not readable with it — they need the custodians' shares.

## Security model

- **Roles.** Every `/api/` route is authorized against `viewer` < `operator` <
  `admin` by the `apiPolicy` table; anything unlisted defaults to `admin`.
  Viewers read; operators verify the chain, sync replication and download
  capsules; admins import the recovery key, pair products, and change
  replication and SSO. An unrecognised role claim from an identity provider is
  treated as `viewer`. An API path is rejected unless it equals `path.Clean` of
  itself, so a URL cannot mean one thing to the policy and another to the
  handler.
- **Credentials.** A product API token is shown once, to the product that claims
  the pairing code; a pairing code is shown once, to the administrator who
  generates it. Neither appears in the paired products listing, and no response
  body contains a session token.
- **Transport.** Session cookies are `HttpOnly`, and `Secure` when the login
  arrived over TLS (directly or via `X-Forwarded-Proto`). Run behind TLS and set
  `--cookie-secure=true` to make that unconditional. Changing a password signs
  out every other session on the account.
- **Dashboard.** Values from the database are escaped before they are rendered,
  and every response carries a Content-Security-Policy. `/admin/ceremony` gets a
  stricter one: it needs `wasm-unsafe-eval`, and in exchange carries no inline
  script or style at all.
- **Limits.** API bodies are capped at 1 MiB, deposits at 384 MiB, 60 deposits
  per 15 minutes per paired product, and 4 in flight at once. KyRecovery does not
  reserve or enforce free disk space for the capsule volume — size it for your
  retention.
- **SSO.** The issuer must publish `/.well-known/openid-configuration`; endpoints
  and signing keys come from discovery. Outbound issuer requests refuse
  link-local destinations at connect time.

## Upgrading from the previous KyRecovery

The previous version pushed plaintext to the server, packed and encrypted it
there, and returned the Shamir shares in the HTTP response. Nothing it produced
is readable now and nothing was in the wild: **delete `data/`** — the database,
`capsules/` and `secret.key` — and start fresh with a ceremony. There is no
migration.

## Verify

```bash
go test ./...
```
