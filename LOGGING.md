# Logging

KyRecovery must emit structured, privacy-safe application logs to standard
output and standard error. It must not build or require a KySecurity-specific
log database, log search system, or long-term retention service.

Operators may route container logs to an existing platform such as Loki,
OpenSearch, Elasticsearch, Graylog, or another OpenTelemetry-compatible
collector.

Log deposits, integrity verifications, downloads, pairings, the recovery key
import, replication results, failures, and administrative actions. Use request
IDs and coarse actor identifiers where useful.

Never log capsule bytes, the keyring master key, API tokens, pairing codes,
passwords, session tokens, or raw request bodies. A deposit event identifies the
capsule, its digest and its size, and nothing about what it contains — which is
all the server has anyway.

Do not add an embedded log database or product-specific log viewer. Operators
should use their existing logging platform for search, alerting, retention, and
access control.
