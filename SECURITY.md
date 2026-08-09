# Security policy and threat model

GESH is security-sensitive infrastructure. A design goal is that compromise of the sync server does not reveal plaintext application data because clients encrypt data before upload and GESH stores only opaque ciphertext.

That does **not** mean a compromised GESH server is harmless. It can still delete data, withhold events, replay old ciphertext, observe metadata, deny service, and potentially assist attacks against weak client implementations. Clients must therefore treat the server as an untrusted relay.

## Trust boundaries

### GESH trusts

- the local operating system and process boundary
- the configured secret registry
- the configured metadata/blob storage backends
- the administrator to provide TLS and secure host configuration when exposed beyond localhost

### GESH does not trust

- request paths, query parameters, headers, or bodies
- client-provided identifiers
- ciphertext contents
- client clocks
- network peers merely because they can reach the service

### Clients must not trust GESH with

- plaintext application records
- plaintext encryption keys
- recovery phrases or key-encryption secrets
- authoritative conflict resolution
- assumptions that server timestamps prove when user data was created

## Current protections

The Rust v2 foundation includes:

- strict identifier character/length validation before filesystem path construction
- bounded request bodies and bounded list page sizes
- bearer-secret authentication scoped by `(appId, rootId)`
- fixed-size SHA-256 digest comparison with constant-time equality
- immutable event IDs and atomic create-only blob writes
- SQLite-backed metadata instead of whole-file JSON rewrites
- generic external errors with detailed failures kept in server logs
- localhost-only default binding
- graceful process shutdown

## Known gaps before production readiness

The following are intentionally tracked as security work, not optional polish:

1. device enrollment, independent device credentials, and device revocation
2. root-secret rotation without requiring destructive re-pairing
3. cryptographic ciphertext hashes stored and verified by clients
4. anti-replay and protocol version rules
5. rate limiting, authentication backoff, per-root quotas, and abuse controls
6. TLS deployment guidance and hardened reverse-proxy examples
7. backup, restore, and disaster-recovery procedures
8. metadata/blob reconciliation after interrupted or damaged storage operations
9. security-focused integration and fuzz/property tests
10. dependency auditing in CI and a committed `Cargo.lock`
11. a documented retention/tombstone model rather than arbitrary event deletion
12. storage permissions and container hardening guidance

Until these items have been addressed and reviewed, GESH should be treated as development software.

## Reporting vulnerabilities

Do not publish exploitable vulnerability details in a public issue. Report them privately to the repository maintainers through GitHub's private vulnerability reporting feature when enabled, or another private channel established by the maintainers.
