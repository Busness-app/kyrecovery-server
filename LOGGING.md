# Logging

KyRecovery must emit structured, privacy-safe application logs to standard
output and standard error. It must not build or require a KySecurity-specific
log database, log search system, or long-term retention service.

Operators may route container logs to an existing platform such as Loki,
OpenSearch, Elasticsearch, Graylog, or another OpenTelemetry-compatible
collector.

Log capsule creation, approval, export, drill start and completion, restore
results, missing dependencies, failures, and administrative actions. Use
request IDs and coarse actor identifiers where useful.

Never log capsule contents, recovery secrets, private keys, passwords, session
tokens, decrypted configuration, or raw request bodies. Recovery events should
identify the capsule and result without revealing its contents.

Do not add an embedded log database or product-specific log viewer. Operators
should use their existing logging platform for search, alerting, retention, and
access control.
