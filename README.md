# Generic Encrypted Sync Hub (GESH)

GESH is a small, self-hostable, zero-knowledge synchronization relay for application state. Clients encrypt their own data and resolve their own domain conflicts; GESH authenticates sync roots, stores opaque immutable event blobs, and provides an incremental event feed for other devices.

> GESH is infrastructure, not a database-as-a-service. The server must never require plaintext application data.

## Status

GESH is under active development. The Rust service is the beginning of the v2 security foundation and is **not yet considered production-ready**.

## Architecture

```text
client domain state
      |
      v
serialize -> encrypt -> immutable sync event
                         |
                         v
                       GESH
                    /         \
             SQLite index   blob store
```

The current reference server uses:

- Rust + Axum for the HTTP service
- Tokio for async I/O
- SQLite via SQLx for durable event metadata and cursors
- the local filesystem for opaque encrypted blobs
- self-provisioned roots, with the authority and every device credential held in SQLite

The storage layer is intentionally simple today. S3-compatible blob storage is planned without changing the rule that GESH never receives plaintext application data.

## Security model

GESH assumes clients are responsible for encryption, key management, serialization, conflict resolution, and validation of decrypted application data.

The server is responsible for safely handling hostile network input and protecting stored ciphertext. The Rust implementation therefore starts with several non-negotiable properties:

- protocol identifiers are restricted before they can become filesystem path components
- secrets are compared through fixed-length SHA-256 digests using constant-time comparison
- each device holds its own credential, so one device can be revoked without re-pairing the rest
- a root is created by the app that will own it, so no secret is ever chosen by a person or written to a file
- the authority that enrolls and revokes is a separate credential from the one the owning app syncs with
- event IDs are immutable; uploading the same `(app, root, device, event)` twice returns `409 Conflict`
- ciphertext is staged under a temporary name and published by atomic rename, so a partially written blob is never readable
- an event exists only once its metadata row commits; an upload interrupted before that point can be retried under the same event ID
- requests are authenticated before their body is read
- enrollment, handle lookup, and the credential check are rate limited per client, and repeated failures earn a doubling lockout
- SQLite replaces rewrite-the-whole-JSON metadata indexes
- incremental listing uses a server cursor and bounded page size
- request bodies have a configurable hard size limit
- the server binds to localhost by default; public exposure should happen behind a properly configured TLS reverse proxy
- application errors do not expose internal filesystem or database details

This is only a foundation. See [SECURITY.md](SECURITY.md) for the threat model and work still required before a production declaration.

## Getting started

Install a current stable Rust toolchain and run the service:

```bash
cargo run
```

By default GESH listens on `127.0.0.1:3000`. There is nothing to configure and
no secret to write down — an app creates its own root the first time it runs.

> Deployments from before self-provisioning used a hand-written
> `data/secrets.json` registry mapping `appId` → `rootId` → secret. Those
> secrets still authenticate, so an existing install keeps working, but the file
> is no longer read if it is absent and nothing new should be added to it.

## Pairing devices

The person using the app should never see any of this. No file to edit, no
secret to copy, no identifier to type.

### The first device provisions itself

The app calls this once, on first launch, and stores what comes back:

```bash
curl -X POST $GESH/v1/roots \
     -H 'Content-Type: application/json' \
     -d '{"appId":"fattern","deviceId":"desktop"}'
# {
#   "app_id": "fattern",
#   "root_id": "root_7c5e1bb3-fca2-4e24-8c15-0fbb72e4f121",
#   "root_token":   "<the authority: enrolls and revokes>",
#   "device_token": "<this device's own sync credential>"
# }
```

That app is now the source of truth for the root. It is the only thing that can
add a device or take one away, and it is where the content key lives — GESH
never sees that key and cannot help anyone recover it.

**Two tokens, because the app plays two parts.** `root_token` is the authority.
`device_token` is what it relays its own events with, exactly like any other
device. Keeping them apart costs the app nothing and means the credential in
daily use cannot revoke anybody.

`handle` is optional in the request. A root is reachable by pairing code alone,
so only set a name if people are meant to type one.

### The second device scans

```bash
# the first device mints a one-time code, valid for ten minutes by default
curl -X POST $GESH/v1/admin/fattern/$ROOT_ID/enrollments \
     -H "Authorization: Bearer $ROOT_TOKEN"
# {"code":"79T54-26AJX","pairing_uri":"gesh://pair?s=...&c=79T54-26AJX",...}

# the new device redeems what it scanned — no handle, no root id
curl -X POST $GESH/v1/enroll \
     -H 'Content-Type: application/json' \
     -d '{"code":"79t5426ajx","deviceId":"phone"}'
# {"app_id":"fattern","root_id":"root_7c5e...","device_id":"phone","token":"..."}
```

`pairing_uri` is present once `GESH_PUBLIC_URL` is set, and is the string to put
in the QR code. It carries where to go and what to say, and nothing that
identifies the root — the code already does that.

**The app appends the content key as a fragment**, which is the second half of
pairing and the half GESH must never learn:

```text
gesh://pair?s=https%3A%2F%2Fsync.example.com&c=79T54-26AJX#k=<content key>
```

A URI fragment is never transmitted to a server, so one QR code can carry both
halves while the relay only ever receives one of them.

Codes are single-use, expire, are stored only as a hash, and are bound to the
root that minted them. Typed codes are normalized, so case and the grouping dash
do not matter — the alphabet drops `0`/`O` and `1`/`I` so a code can be read
aloud when there is no camera. Re-enrolling an existing `deviceId` replaces its
credential, which is how a reinstalled phone recovers without becoming a second
device.

Redemption is throttled and a wrong code costs a growing wait — see
[Rate limiting](#rate-limiting). A `429` means honour the `Retry-After` header;
minting a fresh code will not help, because the lockout is on the client.

### Revoking

Revoking one device leaves every other credential untouched, and takes the
device's claim on retained data with it:

```bash
curl $GESH/v1/admin/fattern/$ROOT_ID/devices -H "Authorization: Bearer $ROOT_TOKEN"
curl -X DELETE $GESH/v1/admin/fattern/$ROOT_ID/devices/phone \
     -H "Authorization: Bearer $ROOT_TOKEN"
```

The root's own credential is not in that list and cannot be named in a
revocation, so a root can never be left with no authority over itself.

## API

Sync endpoints accept either credential:

```http
Authorization: Bearer <root_token | device_token>
```

Admin endpoints under `/v1/admin` require the root token and answer `403` to a
device credential. Three routes are unauthenticated, because a device has to be
able to arrive holding nothing: `POST /v1/roots` creates a root, and `POST
/v1/enroll` and `POST /v1/roots/{handle}/enroll` trade a pairing code for a
credential. `GET /v1/roots/{handle}` resolves a typed name and reveals only
whether it exists.

### Provision a root

```http
POST /v1/roots
Content-Type: application/json

{ "appId": "fattern", "deviceId": "desktop", "handle": "madsen-home" }
```

`handle` is optional. Returns `201` with the root and its two credentials, which
are shown exactly once. Open by default; set `GESH_PROVISIONING_SECRET` to
require `Authorization: Bearer <secret>` here, and rate limited either way.

### Upload an immutable event

```http
PUT /v1/sync/{appId}/{rootId}/{deviceId}/{eventId}
Content-Type: application/octet-stream
Authorization: Bearer <root_token | device_token>
```

The request body is opaque ciphertext. A new event returns `201 Created`. Reusing an existing event ID returns `409 Conflict`; events cannot be overwritten.

### List events incrementally

```http
GET /v1/sync/{appId}/{rootId}?after=0&limit=100&deviceId={optionalDeviceId}
Authorization: Bearer <root_token | device_token>
```

`after` is an opaque server cursor from a previous response. `limit` must be between 1 and 500.

Example response:

```json
{
  "events": [
    {
      "cursor": 42,
      "app_id": "fattern",
      "root_id": "root_example",
      "device_id": "desktop_a",
      "event_id": "event_123",
      "created_at_ms": 1786270000000,
      "size": 4281
    }
  ],
  "next_cursor": 42
}
```

### Download an event

```http
GET /v1/sync/{appId}/{rootId}/{deviceId}/{eventId}
Authorization: Bearer <root_token | device_token>
```

Returns `application/octet-stream` or `404 Not Found`.

### Acknowledge consumed events

```http
PUT /v1/sync/{appId}/{rootId}/{deviceId}
Content-Type: application/json
Authorization: Bearer <root_token | device_token>

{ "ackCursor": 42 }
```

Reports that this device has consumed the feed up to and including that cursor,
and registers it as an active peer. Acknowledgements only move forward, so a
retried or out-of-order report cannot rewind a device's progress.

Once every active peer has acknowledged past an event, the relay has finished
its errand and the ciphertext is erased. A device is never required to
acknowledge its own uploads.

## Retention

GESH is a relay, not a record. Data is held only as long as it takes to hand it
to the other devices on a root:

- an event is erased once every active peer has acknowledged it
- an event nobody collects is erased when it reaches `GESH_EVENT_TTL_SECONDS`
- a device that has been silent for `GESH_DEVICE_TTL_SECONDS` stops counting as
  a peer, so a retired device cannot pin data forever
- an erased event leaves a tombstone for `GESH_TOMBSTONE_TTL_SECONDS`, which
  keeps its identifier reserved so already relayed ciphertext cannot be replayed
  back onto the root

Reclamation runs on a background sweep every `GESH_SWEEP_INTERVAL_SECONDS`, so
data ages out of a root even while no client is talking to it. Set the tombstone
window longer than the event window; once a tombstone is purged, its identifier
becomes reusable again.

## Rate limiting

Almost every credential here is 244 bits of CSPRNG output and not worth
guessing. Two things are: the enrollment code, which is short because a person
reads it aloud, and the bearer-token check, which anyone who can reach the port
may hammer. Both are throttled, before the request body is read:

- root creation is capped at `GESH_ROOTS_PER_MINUTE` per client, which is what
  stops an open server being turned into free storage
- handle lookups are capped at `GESH_HANDLE_LOOKUPS_PER_MINUTE` per client
- redemption attempts are capped at `GESH_ENROLL_ATTEMPTS_PER_MINUTE` per
  client, and separately at the same rate per root, so guessing a code does not
  scale with the number of addresses an attacker holds
- after `GESH_FAILURES_BEFORE_BACKOFF` consecutive bad codes or bad tokens, a
  client waits one second, then two, then four, up to `GESH_MAX_BACKOFF_SECONDS`

A throttled request gets `429 Too Many Requests` with a `Retry-After` header. A
successful redemption or a working credential clears that client's failures, so
a legitimate device that fumbles a code is not punished afterwards.

Clients are identified by connection address — a whole /64 for IPv6, since a
single host is normally handed one. **Behind a reverse proxy every request
arrives from the proxy, so all clients would share one bucket.** Set
`GESH_TRUSTED_FORWARDED_HEADER` (usually `x-forwarded-for`) to key on the real
client instead. It is unset by default on purpose: anyone can send that header,
and honouring it unconditionally would let one host claim a fresh identity on
every request. Only the last entry is used, since that is the one the proxy
appended, so set it only when your proxy is the sole route to the process.

Limiter state is in-process and bounded. A restart forgets it, which makes this
an abuse control rather than a durable lockout — the durable defence is that
codes are high-entropy, single-use, and expire in minutes.

### Health check

```http
GET /health
```

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `GESH_LISTEN_ADDR` | `127.0.0.1:3000` | Socket address to bind |
| `GESH_BLOB_BASE_DIR` | `data/blobs` | Encrypted blob storage |
| `GESH_DATABASE_URL` | `sqlite://data/gesh.db` | SQLite metadata database |
| `GESH_SECRET_REGISTRY_PATH` | `data/secrets.json` | Legacy root-secret registry, optional |
| `GESH_PROVISIONING_SECRET` | unset | Required to create a root, when set |
| `GESH_PUBLIC_URL` | unset | Address embedded in the pairing URI |
| `GESH_UPLOAD_LIMIT_BYTES` | `33554432` | Maximum event body size |
| `GESH_EVENT_TTL_SECONDS` | `604800` | Age at which an uncollected event is erased |
| `GESH_TOMBSTONE_TTL_SECONDS` | `2592000` | How long an erased event's ID stays reserved |
| `GESH_DEVICE_TTL_SECONDS` | `2592000` | Silence after which a device stops counting as a peer |
| `GESH_SWEEP_INTERVAL_SECONDS` | `60` | Delay between reclamation passes |
| `GESH_ENROLLMENT_CODE_TTL_SECONDS` | `600` | How long a pairing code stays redeemable |
| `GESH_ENROLL_ATTEMPTS_PER_MINUTE` | `10` | Redemption attempts per client, and per root |
| `GESH_ROOTS_PER_MINUTE` | `5` | Roots one client may create per minute |
| `GESH_HANDLE_LOOKUPS_PER_MINUTE` | `60` | Handle lookups per client |
| `GESH_FAILURES_BEFORE_BACKOFF` | `5` | Consecutive failures before lockouts begin |
| `GESH_MAX_BACKOFF_SECONDS` | `300` | Ceiling on the doubling lockout |
| `GESH_TRUSTED_FORWARDED_HEADER` | unset | Proxy header naming the real client address |
| `RUST_LOG` | `gesh_server=info` | Structured log filter |

## Direction

The next security milestones are root-secret rotation, ciphertext integrity metadata, per-root storage quotas and throttle state that survives a restart, protocol conformance tests, storage reconciliation, backup/restore documentation, and a reusable client SDK.

GESH should remain boring server-side. If the relay ever needs to understand invoices, notes, files, tasks, or whatever exciting new object a client invents, the protocol has gone in the wrong direction.
