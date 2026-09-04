# KyRecovery Server: Zero-Code Product Pairing & Sealed-Capsule Deposit Specification

**Document Version**: 2.0.0
**Target Audience**: KySecurity Suite Engineers, Business.app Ecosystem Developers, DevOps / Site Reliability Engineers
**Status**: This is the wire contract as of this commit. It has no deployments behind it and no compatibility guarantee yet; both sides move together.

---

## 1. Architecture Overview

Any KySecurity or Business.app service pairs with a KyRecovery server using an ephemeral
six-digit PIN and receives, in the same response, the **suite recovery public key** the
server pins. From then on the product seals its own backups into `.kycap` (kycap/3)
containers with `ky-primitives/capsule` and deposits the ciphertext.

KyRecovery is a blind store. It cannot open a container, it never sees a plaintext file or a
Shamir share, and it runs no restore drill. What it does is store the bytes, record what the
container says about itself, hash it, replicate it, attest that the hash still matches, and
chain every one of those events into an audit ledger.

```mermaid
sequenceDiagram
    autonumber
    actor Admin as KyRecovery Administrator
    participant RecUI as KyRecovery Dashboard / CLI
    actor ServiceAdmin as Product Admin (KyNotes / KyPost)
    participant Client as Client Application Server
    participant RecServer as KyRecovery API Server

    rect rgb(30, 26, 40)
    note over Admin,RecServer: Phase 0: Ceremony (once per suite, before any pairing)
    Admin->>RecUI: Open /admin/ceremony, choose k of n
    RecUI->>RecUI: recoverykey.Generate + Split, in the browser tab
    RecUI-->>Admin: n printed custodian cards
    RecUI->>RecServer: POST /api/recovery-key { public_key, threshold, total_shares }
    RecServer-->>RecUI: 201 { key_id, threshold, total_shares }
    end

    rect rgb(22, 28, 38)
    note over Admin,RecServer: Phase 1: Pairing
    Admin->>RecUI: Generate a pairing code for "kynotes"
    RecUI->>RecServer: POST /api/pairing/generate { service_name: "kynotes" }
    RecServer-->>RecUI: 6-digit PIN (TTL 15 min)
    Admin-->>ServiceAdmin: Provides the PIN out-of-band
    ServiceAdmin->>Client: Enters the PIN in product config
    Client->>RecServer: POST /api/pairing/claim { pairing_code, app_name }
    RecServer-->>Client: { api_token, recovery_public_key, threshold, total_shares }
    Client->>Client: Pins the public key; it is what every capsule is sealed to
    end

    rect rgb(18, 34, 30)
    note over Client,RecServer: Phase 2: Deposit
    Client->>Client: capsule.Seal(files, recovery_public_key) → kycap/3 container
    Client->>RecServer: POST /api/backup/deposit (Bearer + application/octet-stream)
    RecServer->>RecServer: ReadUnverifiedManifest, key-ID and service checks, SHA-256
    RecServer->>RecServer: Store, replicate offsite, append capsule_deposited
    RecServer-->>Client: 201 { capsule_id, digest, size_bytes, deposited_at }
    end
```

---

## 2. API Protocol & Endpoints Specification

### 2.1. Pairing Code Generation (Admin / Dashboard)

- **Endpoint**: `POST /api/pairing/generate`
- **Authentication**: KyRecovery admin session
- **Request Body**:
  ```json
  {
    "service_name": "kynotes",
    "ttl_minutes": 15
  }
  ```
- `ttl_minutes` defaults to 15 and may not exceed 60: a six-digit code is only as
  strong as the window in which it stays guessable. A larger value is rejected
  with `400 Bad Request`.
- **Response** (`200 OK`):
  ```json
  {
    "id": "pair-1787019014811345071",
    "service_name": "kynotes",
    "app_name": "Pending Service",
    "pairing_code": "849201",
    "status": "pending",
    "expires_at": "2026-08-18T02:25:14.811345071Z",
    "created_at": "2026-08-18T02:10:14.811345071Z"
  }
  ```
  This is the only response that carries the pairing code. It is not returned by
  `GET /api/pairing/list`, and the API token is not returned here — that belongs
  to whichever product claims the code.

---

### 2.2. Pairing Claim & Key Hand-off (Client Application)

- **Endpoint**: `POST /api/pairing/claim`
- **Authentication**: None (protected by the single-use six-digit PIN and rate limiting)
- **Request Body**:
  ```json
  {
    "pairing_code": "849201",
    "app_name": "KyNotes Production Cluster US-East",
    "service_name": "kynotes"
  }
  ```
  `service_name` defaults to `generic` and `app_name` to `App-<code>` if omitted.
- **Response** (`200 OK`):
  ```json
  {
    "id": "pair-1787019014811345071",
    "service_name": "kynotes",
    "app_name": "KyNotes Production Cluster US-East",
    "api_token": "kyrec_live_7a3d90e2f5b64c18a901ee45bc2990d1",
    "status": "paired",
    "paired_at": "2026-08-18T02:11:00Z",
    "server_url": "recovery.internal:8095",
    "recovery_public_key": "MIIE...",
    "threshold": 3,
    "total_shares": 5
  }
  ```
  - `recovery_public_key` is the suite recovery public key in **standard base64**,
    1216 bytes decoded. Every container this product later deposits must be sealed
    to it. Store it; the deposit is refused if it was sealed to anything else.
  - `threshold` and `total_shares` are the k-of-n the custodian cards were printed
    with. They are informational for the product, and are copied into the manifest
    of what it seals.
  - This is the only response that carries the API token. Store it; it cannot be
    read back from KyRecovery afterwards.
- **Error Codes**:
  - `400 Bad Request`: Invalid or expired pairing code.
  - `409 Conflict`: The pairing code was already claimed — **or** no recovery key has
    been imported yet, meaning the ceremony has not run. In the second case the code
    is *not* consumed and no rate-limit attempt is charged: run the ceremony and claim
    again with the same code.
  - `429 Too Many Requests`: More than 10 claim attempts from one source address, or 5
    for one code, within 15 minutes.

A client that receives no `recovery_public_key` must treat the pairing as failed;
`pkg/client.ClaimPairing` does exactly that.

---

### 2.3. Sealed-Capsule Deposit (Client Application)

- **Endpoint**: `POST /api/backup/deposit`
- **Authentication**: `Authorization: Bearer <api_token>`
- **Content-Type**: `application/octet-stream`
- **Request Body**: the raw kycap/3 container, as produced by
  `ky-primitives/capsule.Seal` against `recovery_public_key`. There is no JSON
  envelope, no file list and no verification recipe. The server does not choose
  what goes in the capsule and cannot see what did.

The server, in order: authenticates the token; charges the rate limit; takes one of
4 deposit slots; refuses if the audit ledger cannot append; reads the body under a
`capsule.MaxContainerBytes` cap; parses the container with
`capsule.ReadUnverifiedManifest`; compares `recovery_key_id` with the pinned key ID;
compares `service_name` with the token's paired service; SHA-256s the bytes; writes
temp-file → fsync → row insert → `capsule_deposited` appended → hard link; and kicks off
offsite replication.

- **Limits**:
  - The body is capped at `capsule.MaxContainerBytes` (384 MiB), the same bound
    `capsule.Open` enforces. There is no server setting for it. A product with more
    data than that needs the streaming container, which does not exist yet.
  - `service_name` and `capsule_id` in the manifest must match
    `[A-Za-z0-9][A-Za-z0-9_.-]{0,63}` and `{0,127}` respectively — the capsule ID
    becomes a filename.
  - At most 60 deposits per paired product per 15 minutes, and at most 4 deposits
    in flight at once across all products.

- **Response** (`201 Created`, or `200 OK` for an idempotent re-send):
  ```json
  {
    "capsule_id": "cap-kynotes-1787019014811345071",
    "digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "size_bytes": 1048576,
    "deposited_at": "2026-09-04T11:02:31.881Z"
  }
  ```
  `digest` is the SHA-256 KyRecovery computed over the bytes it received. Compare it
  with your own before considering the deposit durable.

- **Status Codes**:

| Status | Condition |
| :--- | :--- |
| `201 Created` | Stored. |
| `200 OK` | This capsule ID is already stored with byte-identical contents; the original record is returned. Re-sending the same container is safe. |
| `400 Bad Request` | The body is not a kycap/3 container, or its `capsule_id` / `service_name` is not a usable name. |
| `401 Unauthorized` | Missing, invalid or revoked bearer token. |
| `403 Forbidden` | The manifest names a service this token is not paired for. Both names are in the message. |
| `409 Conflict` | Sealed to a different recovery key (both key IDs are in the message); or this capsule ID is stored with different bytes; or its row exists but the file is missing (the row is flagged corrupt — retry with a new capsule ID); or no recovery key is imported. |
| `413 Content Too Large` | Body over `capsule.MaxContainerBytes`. |
| `429 Too Many Requests` | Deposit rate limit exceeded for this paired product. |
| `503 Service Unavailable` | The audit ledger is not writable — deposits are refused until an operator repairs the log and restarts — or the request was abandoned while waiting for a deposit slot. |

Nothing is written for any of the refusals above; a refused deposit leaves no row and
no file.

---

## 3. What KyRecovery Records From a Container

The container declares these in its manifest, which the server reads **without**
authenticating it — the bytes cannot be verified without the private key. They are
stored and displayed, never acted on. The single exception is `recovery_key_id`,
which is compared against the key the store pins.

| Field | Use |
| :--- | :--- |
| `capsule_id` | Primary key and filename. Refused if it is not a usable name; refused if it collides with different bytes. |
| `service_name` | Must equal the paired token's service, else `403`. |
| `app_version` | Recorded; shown in the dashboard and the timeline. |
| `created_at` | Recorded. Compared by the operator against the deposit time during a restore, which is where freshness comes from. |
| `payload_hash` | Recorded. The product's hash of its own plaintext; KyRecovery cannot check it. |
| `threshold`, `total_shares` | Recorded. How many custodian cards a restore will need. |
| `recovery_key_id` | The only field the server decides on: it must equal the pinned key's ID. |
| `encapsulated_key` | Recorded. Opaque to the server. |

KyRecovery adds `size_bytes`, `digest` (its own SHA-256) and `deposited_at`, which
are the only three values in a capsule record it did not take on faith.

---

## 4. Client Integration Examples

### 4.1. Go

The SDK in `pkg/client` covers both calls:

```go
import (
	"context"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/kyrecovery-server/pkg/client"
)

func pairAndDeposit(ctx context.Context, serverURL, pin string, container []byte) error {
	c, claim, err := client.ClaimPairing(ctx, serverURL, pin, "KyNotes Primary")
	if err != nil {
		return err
	}
	// Persist claim.APIToken and claim.RecoveryPublicKey. Seal every future backup to
	// that key with capsule.Seal; kyrecovery only stores what comes out.
	_ = claim
	_, err = c.Deposit(ctx, container)
	return err
}
```

`recoverykey.ParsePublicKey` on the decoded `recovery_public_key` gives the value
`capsule.Seal` takes. Products that already store it (`backup.StoreRecoveryKey` in
the server scaffold) refuse a claim response without one.

### 4.2. Any language

Two HTTP calls. Sealing is the part that is not HTTP: a non-Go product needs a
kycap/3 implementation before it can deposit anything, because KyRecovery will not
seal on its behalf.

```bash
# 1. Claim the pairing code; keep api_token and recovery_public_key
curl -s -X POST https://recovery.internal:8095/api/pairing/claim \
  -H "Content-Type: application/json" \
  -d '{"pairing_code":"849201","service_name":"kynotes","app_name":"KyNotes Node 1"}'

# 2. Deposit a container you sealed to that public key
curl -s -X POST https://recovery.internal:8095/api/backup/deposit \
  -H "Authorization: Bearer kyrec_live_7a3d90e2..." \
  -H "Content-Type: application/octet-stream" \
  --data-binary @backup.kycap
```

---

## 5. Security Invariants & Guarantees

1. **The store is blind.** No recovery private key, seed or Shamir share ever reaches
   the server: the ceremony runs in the operator's browser and posts only the public
   half, and the import handler decodes a struct with no field for a share. No
   non-test file in the repository calls `capsule.Open`, `capsule.Seal`,
   `recoverykey.Combine` or `recoverykey.FromSeed`; `TestNothingInTheServerDecrypts`
   enforces it.
2. **The pin is the contract.** A container sealed to any key but the pinned one is
   refused with `409` before anything is written, so a product that lost track of
   which suite it belongs to cannot quietly fill the store with unrecoverable bytes.
3. **Single-use ephemeral PINs.** Pairing codes expire after 15 minutes by default,
   60 at most, and are invalidated on first claim. The single-use and expiry guards
   live in the SQL `UPDATE`, so concurrent claims of one code cannot both mint a
   token. Attempts are capped per source address (10) and per code (5) per 15 minutes.
4. **Tamper-evident audit ledger.** Pairing, key import, deposit and verification
   events are appended to a keyed hash chain (`ky-primitives/auditchain`) whose anchor
   is kept outside the log. A deposit that cannot be recorded is refused rather than
   stored unrecorded.
5. **Attested at rest.** Every capsule is re-hashed on demand
   (`GET /api/capsules/{id}/verify`) and by a sweep every 24 hours; a mismatch flags
   the row and records `capsule_corrupt`. A flagged capsule still downloads, with
   `X-Capsule-Status: corrupt` and `X-Capsule-Digest` set.
6. **Zero-secret logging.** Per `LOGGING.md`, logs carry capsule IDs, sequence numbers
   and byte sizes — never API tokens, container contents or keys.
7. **Restore is not KyRecovery's.** A restore runs the product's own `restore` command
   against the downloaded `.kycap` and k custodian shares typed from their cards.
   KyRecovery has no part in it beyond serving the download.
