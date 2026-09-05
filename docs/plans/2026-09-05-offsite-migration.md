**Repo:** kyrecovery-server
**PR:** library dependency #14 — https://github.com/Busness-app/ky-primitives/pull/14 (merged; no consumer PR yet)
**Worktree:** /home/yoshi/busness.app/kyrecovery-server (main, 7071908)

# Offsite transport migration plan

Source: myslop post 294, folder `kyrecovery-offsite-adoption`. Source inspection on
2026-09-05 confirms the four transports remain in `internal/replication` and the
root ky-primitives dependency is v0.4.1. Implementation proceeds in `/home/yoshi/busness.app/kyrecovery-offsite`, branch `feature/offsite-adoption`.
The working tree contains the separate, tested tiered-retention implementation;
preserve it and keep the transport migration in its own change set.

## Implementation decisions

- v0.1.0 cannot represent absolute SFTP directories or the original virtual-host
  S3 endpoint rule. Preserve those records through explicit compatibility branches;
  remove them only after a released library supports the same destinations.
- Implement canonical SMB writes through the library and preserve a restricted,
  read-only legacy SMB adapter locally. This replaces the proposed library-release
  prerequisite below without relaxing the library's admitted object names. Legacy
  lookup accepts only capsule basenames, never caller-supplied arbitrary SMB names.
- Keep all credential, scheduling, logging and retention ownership in the product.
  The remaining compatibility code is deliberate; full transport-code deletion
  remains contingent on upstream support.

## Outcome and boundaries

Delegate opaque-byte transfer to `github.com/Busness-app/ky-primitives/offsite`.
KyRecovery continues to own target records, sealed credentials, scheduling,
retention, sync history and the audit ledger. Existing target records must resolve
to the same destinations. Historical replicas must remain discoverable.

No capsule decryption, automatic remote purge, root-module upgrade, target-table
rewrite, or remote object rename is part of this migration. The library currently
provides Put/Get/Test, not Delete. Local tiered retention remains independent.

## 1. Establish the compatibility baseline

- Re-read the folder's claim and current repository instructions before implementation.
  Separate or commit the retention changes before preparing the migration PR;
  do not stash, reset, or include them accidentally.
- Check the released nested-module tag and source against the local library checkout.
  Add `github.com/Busness-app/ky-primitives/offsite@v0.1.0`; its version is independent
  of the root module. Do not use `@offsite/v0.1.0` in go get.
- Add golden adapter fixtures before changing dispatch in `manager.go`. Assert exact
  endpoint, remote object location, credentials and pin, including these cases:

| Transport | Compatibility cases |
| --- | --- |
| S3 | Empty prefix, `capsules/`, `capsules`, leading slash, nested prefix; default/custom HTTPS endpoint, bucket, region, URL escaping. Existing code concatenates prefix and ID: `capsules` means `capsulescap-…`, not `capsules/cap-…`. |
| SFTP | Account-relative directories, user, password and PEM authentication, IPv6/explicit port, absent/correct/wrong host pin. Preserve actual join behavior. |
| SMB | Bare host, host:port, URL/UNC forms, separate share/prefix, domain user, mixed-case IDs and existing replica names. |
| Local | Absolute and relative stored endpoints, path characters needing URL escaping, existing symlink behavior and inaccessible directories. Resolve relative endpoints using the same process working directory. |

Do not silently normalize a record into a different destination. Identify records
rejected by the new library and provide an actionable validation error without
printing credentials. Safer library behavior, such as refusing symlink escapes or
HTTP S3 endpoints, needs explicit compatibility tests and operator documentation.

**Gate:** Fixtures describe every supported stored target shape and intentional
rejections. No old transport implementation has been deleted.

## 2. Resolve SMB names before switching SMB dispatch

The v0.1.0 SMB backend rejects uppercase object components. Existing IDs such as
`cap-KySignOn-*` therefore cannot pass straight through. It also refuses overwriting
an existing object. Lowercasing historical names is not a safe migration strategy.

Recommended direction:

1. Define a versioned canonical name for new SMB replicas, for example
   `kycap-v1-<lowercase SHA-256 of the exact capsule ID>.kycap`. Keep the original
   capsule ID in KyRecovery records and logs. Publish the mapping in recovery docs.
2. Golden-test distinct case variants, deterministic mapping, allowed name grammar,
   and coexistence with historical `<capsule-id>.kycap` objects.
3. Resolve historical lookup through a separately reviewed library capability that
   can read legacy names without opening ADS, traversal, short-name or write-alias
   bypasses. Test with actual mixed-case historical objects. The released API cannot
   perform this lookup for uppercase names today; this is a prerequisite, not an
   assumed capability. Use the new released nested-module version if required.
4. Define lookup order: canonical name first, exact historical name only on genuine
   absence. Authentication, network and permission failures must not trigger fallback.
   Verify returned bytes against the recorded digest before recognizing a replica.

If safe legacy access cannot be provided, retain existing SMB dispatch and mark the
SMB migration incomplete. A partial local/S3/SFTP PR may ship independently, but
must not claim all transports migrated. Do not move historical objects or weaken the
library's security constraints to close the task.

**Gate:** A reviewed naming/lookup contract and tests prove access to both historical
and new SMB replicas. Any library prerequisite is released before consumer adoption.

## 3. Implement the product adapter and dispatch

- Add one adapter in `internal/replication` from `ReplicationTargetRecord` and capsule
  metadata to `offsite.Config` plus object name. Use `net/url` construction, with
  credentials only in dedicated config fields. Keep database target IDs as identity.
- For S3, preserve the full historical key as the object name under a bucket-root
  configuration where possible; do not let prefix joining insert an extra slash.
- Use `offsite.Parse`, `Target.Put` and `Target.Test` in the manager. Use `Target.Get`
  for duplicate verification and the tested legacy lookup path. Close every reader.
- Preserve auto-sync selection, source-file lifetime, transfer budgets, target status,
  sync logs and ledger ownership. Handle file-stat errors before accessing Size.
- On `ErrObjectExists`, stream the existing object's SHA-256 and check its size against
  the capsule record. Matching bytes permit idempotent success; mismatch or failed
  verification is a failed sync, with no overwrite or false success event.
- Align server target validation and unknown-host-key responses with the library's
  `ParseSMBEndpoint` and `UnknownHostKeyError`. Preserve operator pin confirmation.
- Reuse library protocol tests; retain product-specific adapter, handler, audit and
  scheduling checks. Delete replaced transport files only after those checks pass.
  Run go mod tidy and remove direct dependencies only when no product imports remain.

**Gate:** The manager and handlers pass integration tests through the adapter, and
credential sealing, logging and target records keep their established contracts.

## 4. Verify failure behavior and retention coexistence

Run fixture round trips for local, HTTPS S3 and pinned SFTP, plus configured SMB:

- Interrupted writes leave no partial final replica and clean up staging objects.
- Wrong host pin fails before uploading; missing pin still yields the fingerprint
  confirmation flow. Credentials never appear in responses, URLs or log fixtures.
- Genuine absence remains distinguishable from denied/unavailable storage.
- Duplicate matching bytes succeed; different bytes at an existing SMB path fail.
- Historic locations remain unchanged, including S3 prefixes without trailing slash.
- A local retention purge racing replication cannot produce a false sync success.
  Offsite copies are not deleted by local retention. Audit and sync history remain.

Run the repository's required verification, plus vet:

```sh
go test -race -count=1 ./...
go vet ./...
go build -o kyrecovery cmd/kyrecovery/main.go
./kyrecovery help
scripts/build-wasm.sh && git diff --exit-code -- internal/server/static/wasm
node scripts/test-wasm.mjs
git diff --check
```

The current workspace has an unreadable runtime `data/` directory that prevents
`go test ./...` traversal. If it remains, run the complete suite from an isolated
copy of the exact source changes; preserve the decrypt guard and leave live data
permissions alone. Report that environment limitation and any skipped SMB tests.

**Gate:** Full tests, vet, build and WASM checks pass for the exact migration head.
No skipped live integration is described as compatibility evidence.

## 5. Prove existing-target compatibility and prepare review

- Update README and the owning AGENTS.md for transport ownership, name mapping,
  legacy lookup, rejection behavior and verification. Keep the pairing/deposit wire
  contract unchanged.
- Open a consumer PR focused on transport adoption, with exact commit, fixture
  evidence and explicit integration gaps. Drive CI and the autonomous reviewer to green.
- Before claiming live compatibility, arrange one operator-observed sync to an
  existing target, using a controlled capsule and the normal dashboard flow. Record
  target type, expected remote name, byte count and independently verified remote
  SHA-256; record no credentials. Include historical SMB lookup if SMB is migrating.
- Keep the prior binary available for rollback. For any new SMB name scheme, document
  that the old binary cannot discover canonical replicas automatically; retain the
  mapping/lookup tooling with the release. Never delete historical replicas as rollback.
- Mirror the final evidence and remaining work to the existing myslop folder.

**Completion:** Exact-head CI and reviewer are clear, old target mappings and new SMB
compatibility are proven, a live existing-target replica has a matching digest, and
Yoshi has the concrete PR and evidence for merge. Live credentials and operator
availability are later validation inputs; they do not block building the adapter/tests.
