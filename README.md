# KyRecovery

KyRecovery is a planned self-hosted recovery and restore-verification service
for KySecurity deployments.

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
- Records tamper-evident, content-blind recovery events.
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

## Repository status

KyRecovery is currently a product definition only. Implementation has not
started.
