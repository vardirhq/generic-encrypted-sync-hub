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
- a root-secret registry as the enrolling authority, with per-device credentials in SQLite

The storage layer is intentionally simple today. S3-compatible blob storage is planned without changing the rule that GESH never receives plaintext application data.

## Security model

GESH assumes clients are responsible for encryption, key management, serialization, conflict resolution, and validation of decrypted application data.

The server is responsible for safely handling hostile network input and protecting stored ciphertext. The Rust implementation therefore starts with several non-negotiable properties:

- protocol identifiers are restricted before they can become filesystem path components
- secrets are compared through fixed-length SHA-256 digests using constant-time comparison
- each device holds its own credential, so one device can be revoked without re-pairing the rest
- event IDs are immutable; uploading the same `(app, root, device, event)` twice returns `409 Conflict`
- ciphertext is staged under a temporary name and published by atomic rename, so a partially written blob is never readable
- an event exists only once its metadata row commits; an upload interrupted before that point can be retried under the same event ID
- requests are authenticated before their body is read
- SQLite replaces rewrite-the-whole-JSON metadata indexes
- incremental listing uses a server cursor and bounded page size
- request bodies have a configurable hard size limit
- the server binds to localhost by default; public exposure should happen behind a properly configured TLS reverse proxy
- application errors do not expose internal filesystem or database details

This is only a foundation. See [SECURITY.md](SECURITY.md) for the threat model and work still required before a production declaration.

## Getting started

Install a current stable Rust toolchain, then create the secret registry:

```bash
cp data/secrets.example.json data/secrets.json
```

The registry maps an `appId` and `rootId` to a root secret:

```json
{
  "fattern": {
    "root_7c5e1bb3-fca2-4e24-8c15-0fbb72e4f121": "replace-with-a-long-random-secret"
  }
}
```

Run the service:

```bash
cargo run
```

By default GESH listens on `127.0.0.1:3000`.

## Pairing a device

A root has two kinds of credential, and the difference is a privilege boundary.
The **root secret** from the registry is the authority: it names the root and
enrolls and revokes devices. A **device credential** is issued by enrollment and
speaks for one device only, so a compromised phone cannot enroll another device
or act as one.

Both are transport credentials. GESH never holds the key that decrypts an event,
so pairing always has two halves: the credential the server issues, and the
content key handed over out of band by the device that already has it. A QR code
shown by the desktop is the usual carrier for both; the enrollment code is short
and unambiguous so it can also just be read aloud and typed.

```bash
# 1. the desktop names the root, once
curl -X PUT $GESH/v1/admin/fattern/$ROOT_ID/handle \
     -H "Authorization: Bearer $ROOT_SECRET" \
     -H 'Content-Type: application/json' -d '{"handle":"madsen-home"}'

# 2. the desktop mints a one-time code, valid for ten minutes by default
curl -X POST $GESH/v1/admin/fattern/$ROOT_ID/enrollments \
     -H "Authorization: Bearer $ROOT_SECRET"
# {"code":"79T54-26AJX","expires_at_ms":...}

# 3. the phone finds the root by handle, then redeems the code for its own token
curl $GESH/v1/roots/madsen-home
curl -X POST $GESH/v1/roots/madsen-home/enroll \
     -H 'Content-Type: application/json' \
     -d '{"code":"79t5426ajx","deviceId":"phone"}'
# {"device_id":"phone","token":"<the phone's own bearer token>",...}
```

Codes are single-use, expire, are stored only as a hash, and are bound to the
root that minted them. Typed codes are normalized, so case and the grouping dash
do not matter. Re-enrolling an existing `deviceId` replaces its credential, which
is how a reinstalled phone recovers without becoming a second device.

Revoking one device leaves every other credential untouched, and takes the
device's claim on retained data with it:

```bash
curl $GESH/v1/admin/fattern/$ROOT_ID/devices -H "Authorization: Bearer $ROOT_SECRET"
curl -X DELETE $GESH/v1/admin/fattern/$ROOT_ID/devices/phone \
     -H "Authorization: Bearer $ROOT_SECRET"
```

## API

Sync endpoints accept either credential:

```http
Authorization: Bearer <root_secret | device_token>
```

Admin endpoints under `/v1/admin` require the root secret and answer `403`
to a device credential. `GET /v1/roots/{handle}` and `POST
/v1/roots/{handle}/enroll` are the only unauthenticated routes: a device being
paired has to find its root before it holds anything to prove with.

### Upload an immutable event

```http
PUT /v1/sync/{appId}/{rootId}/{deviceId}/{eventId}
Content-Type: application/octet-stream
Authorization: Bearer <root_secret>
```

The request body is opaque ciphertext. A new event returns `201 Created`. Reusing an existing event ID returns `409 Conflict`; events cannot be overwritten.

### List events incrementally

```http
GET /v1/sync/{appId}/{rootId}?after=0&limit=100&deviceId={optionalDeviceId}
Authorization: Bearer <root_secret>
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
Authorization: Bearer <root_secret>
```

Returns `application/octet-stream` or `404 Not Found`.

### Acknowledge consumed events

```http
PUT /v1/sync/{appId}/{rootId}/{deviceId}
Content-Type: application/json
Authorization: Bearer <root_secret>

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
| `GESH_SECRET_REGISTRY_PATH` | `data/secrets.json` | Root-secret registry |
| `GESH_UPLOAD_LIMIT_BYTES` | `33554432` | Maximum event body size |
| `GESH_EVENT_TTL_SECONDS` | `604800` | Age at which an uncollected event is erased |
| `GESH_TOMBSTONE_TTL_SECONDS` | `2592000` | How long an erased event's ID stays reserved |
| `GESH_DEVICE_TTL_SECONDS` | `2592000` | Silence after which a device stops counting as a peer |
| `GESH_SWEEP_INTERVAL_SECONDS` | `60` | Delay between reclamation passes |
| `GESH_ENROLLMENT_CODE_TTL_SECONDS` | `600` | How long a pairing code stays redeemable |
| `RUST_LOG` | `gesh_server=info` | Structured log filter |

## Direction

The next security milestones are rate limiting on enrollment and authentication, root-secret rotation, ciphertext integrity metadata, rate limiting and quotas, protocol conformance tests, storage reconciliation, backup/restore documentation, and a reusable client SDK.

GESH should remain boring server-side. If the relay ever needs to understand invoices, notes, files, tasks, or whatever exciting new object a client invents, the protocol has gone in the wrong direction.
