# Security policy and threat model

GESH is security-sensitive infrastructure. A design goal is that compromise of the sync server does not reveal plaintext application data because clients encrypt data before upload and GESH stores only opaque ciphertext.

That does **not** mean a compromised GESH server is harmless. It can still delete data, withhold events, replay old ciphertext, observe metadata, deny service, and potentially assist attacks against weak client implementations. Clients must therefore treat the server as an untrusted relay.

## Trust boundaries

### GESH trusts

- the local operating system and process boundary
- the configured secret registry
- the configured metadata/blob storage backends
- the administrator to provide TLS and secure host configuration when exposed beyond localhost
- a forwarded-for header naming the real client, but only the header an administrator has named in `GESH_TRUSTED_FORWARDED_HEADER`, and only its last entry — unset, the peer address of the connection is the only identity throttling will believe

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
- per-device credentials issued by one-time enrollment codes, so a device can be revoked without disturbing any other
- a privilege boundary between the root secret, which enrolls and revokes, and device credentials, which only relay for the device they name
- enrollment codes and device secrets stored only as digests, and codes consumed in the same transaction that mints a credential
- authentication and media-type checks performed before a request body is read, so unauthenticated callers cannot make the server buffer an upload
- rate limiting and exponential backoff in front of enrollment, handle lookup, and the credential check, keyed by client address and applied before the body is read
- a per-root ceiling on enrollment attempts, so guessing a code does not scale with the number of source addresses an attacker holds
- fixed-size SHA-256 digest comparison with constant-time equality
- immutable event IDs, with ciphertext staged under a temporary name and published by atomic rename
- metadata rows as the sole record of event existence, so an upload interrupted before commit is retryable rather than permanently rejected
- SQLite-backed metadata instead of whole-file JSON rewrites
- generic external errors with detailed failures kept in server logs
- relay retention: ciphertext erased once every active peer has acknowledged it, and bounded by a TTL when nobody collects it
- tombstoned event identifiers, so already relayed ciphertext cannot be replayed back onto a root
- localhost-only default binding
- graceful process shutdown

## Known gaps before production readiness

The following are intentionally tracked as security work, not optional polish:

1. root-secret rotation without requiring destructive re-pairing, and moving the registry secret into the database
2. cryptographic ciphertext hashes stored and verified by clients
3. protocol version rules, and anti-replay beyond the tombstone window
4. per-root storage and upload quotas, and throttle state that survives a restart and is shared between processes: the current limiter is in-process, so a crash loop or a second replica forgets what a client was owed
5. TLS deployment guidance and hardened reverse-proxy examples
6. backup, restore, and disaster-recovery procedures
7. garbage collection of staging files and blobs left behind by interrupted uploads, and reconciliation of committed metadata whose ciphertext is missing or damaged
8. security-focused integration and fuzz/property tests
9. storage permissions and container hardening guidance

Until these items have been addressed and reviewed, GESH should be treated as development software.

## Reporting vulnerabilities

Do not publish exploitable vulnerability details in a public issue. Report them privately to the repository maintainers through GitHub's private vulnerability reporting feature when enabled, or another private channel established by the maintainers.
