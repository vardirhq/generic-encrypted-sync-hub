# Integrating an application with GESH

This is the guide for someone writing an app that syncs through GESH. It goes in
the order you will actually hit things: provision, encrypt, upload, read,
acknowledge, pair a second device. The [README](../README.md) is the endpoint
reference; this is the walkthrough.

## What you are integrating with

GESH is a relay, not a database. It never sees your plaintext and cannot help
you recover a lost key. It holds opaque blobs just long enough to hand them to
your other devices, then erases them.

That means three jobs stay with you, permanently:

- **encryption and key management** — GESH stores whatever bytes you send
- **conflict resolution** — GESH orders events, it does not merge them
- **durability** — if you need a record, keep it on the device; GESH is transit

If you want a server that remembers your data, GESH is the wrong tool. If you
want two of your own devices to agree without a vendor reading your data, it is
the right one.

## Two conventions that will bite you first

**Requests are camelCase, responses are snake_case.** You send `appId`, you read
back `app_id`. Do not assume symmetry.

**Identifiers are restricted.** `appId`, `deviceId`, and `eventId` must be 1–128
characters of ASCII letters, digits, `-`, or `_`. A handle is narrower: 3–64
characters of lowercase letters, digits, or `-`. Anything else is a `400`. Pick
identifiers your app generates, not ones a user types.

## Step 1: first launch provisions a root

Do this once, ever, on the first device. Not on every start.

```bash
curl -X POST $GESH/v1/roots \
     -H 'Content-Type: application/json' \
     -d '{"appId":"fattern","deviceId":"desktop"}'
```

```json
{
  "app_id": "fattern",
  "root_id": "root_7c5e1bb3-fca2-4e24-8c15-0fbb72e4f121",
  "handle": null,
  "device_id": "desktop",
  "root_token": "<the authority: enrolls and revokes>",
  "device_token": "<this device's own sync credential>"
}
```

**This response is the only time either token exists in readable form.** There is
no endpoint that returns them again. Write them to your platform's secret store
(Keychain, Credential Manager, libsecret, encrypted app storage) before you do
anything else.

### Why two tokens

The app plays two parts, so it holds two credentials:

| Token | What it is for | Use it |
| --- | --- | --- |
| `root_token` | The authority. Enrolls and revokes devices. | Only when pairing or revoking |
| `device_token` | This device's own sync credential. | For every upload, list, download, ack |

Keeping them apart costs you nothing and means the credential in constant use
cannot revoke anybody. **Do not sync with the root token** just because it also
works.

### `handle` is optional

A root is reachable by pairing code alone. Only set a handle if you intend a
person to type a name. If you skip it here and want one later:

```http
PUT /v1/admin/{appId}/{rootId}/handle
Authorization: Bearer <root_token>

{ "handle": "madsen-home" }
```

## Step 2: generate a content key

This is the half of the system GESH is designed never to learn. Generate it on
the first device, at the same time as provisioning, and store it beside the
tokens.

```js
const contentKey = await crypto.subtle.generateKey(
  { name: "AES-GCM", length: 256 },
  true,                       // extractable: pairing has to export it
  ["encrypt", "decrypt"],
);
```

256-bit AES-GCM via WebCrypto is a reasonable default on every platform that has
WebCrypto; XChaCha20-Poly1305 is equally fine where you have a vetted
implementation. What matters more than the choice:

- **a fresh nonce per event**, never reused under the same key — 96 random bits
  for AES-GCM is fine at these volumes
- **the key never leaves the device except through pairing** (step 6)
- **no key material in logs, telemetry, or crash reports**

GESH cannot check any of this for you. If you get it wrong, the server will
faithfully relay your mistake.

## Step 3: upload an event

An event is an immutable blob of ciphertext with an ID you choose.

```js
const eventId = crypto.randomUUID();          // never reuse one
const iv = crypto.getRandomValues(new Uint8Array(12));
const ciphertext = await crypto.subtle.encrypt(
  { name: "AES-GCM", iv }, contentKey, serialize(change),
);

await fetch(`${gesh}/v1/sync/${appId}/${rootId}/${deviceId}/${eventId}`, {
  method: "PUT",
  headers: {
    "Content-Type": "application/octet-stream",
    Authorization: `Bearer ${deviceToken}`,
  },
  body: concat(iv, new Uint8Array(ciphertext)),   // nonce travels with the blob
});
```

`201 Created` means stored. Note the rules:

- **`Content-Type: application/octet-stream` is mandatory.** Anything else is a
  `400`, checked before your body is read.
- **`409 Conflict` means that event ID is already on this root.** On a retry
  after a network failure this is success, not an error — the previous attempt
  landed. Treat it as such rather than surfacing an error to the user.
- **`{deviceId}` in the path must be your own device.** A device token addressing
  another device's path is a `401`.
- Bodies above `GESH_UPLOAD_LIMIT_BYTES` (32 MiB by default) are `413`. Chunk
  large payloads into several events yourself.
- **Never reuse an event ID**, even for erased data. IDs stay reserved by a
  tombstone after erasure, specifically so already-relayed ciphertext cannot be
  replayed back onto the root.

## Step 4: read the feed

```bash
curl "$GESH/v1/sync/fattern/$ROOT_ID?after=$CURSOR&limit=100" \
     -H "Authorization: Bearer $DEVICE_TOKEN"
```

```json
{
  "events": [
    {
      "cursor": 42,
      "app_id": "fattern",
      "root_id": "root_7c5e…",
      "device_id": "desktop",
      "event_id": "event_123",
      "created_at_ms": 1786270000000,
      "size": 4281
    }
  ],
  "next_cursor": 42
}
```

- `after` is an **opaque server cursor**. Persist the `next_cursor` you were last
  given; do not compute, compare, or display it as a number.
- `next_cursor` is `null` when the page was empty — you are caught up.
- `limit` must be 1–500, and defaults to 100.
- `size` is the ciphertext length, not your plaintext length.
- `created_at_ms` is the **server's** clock. Do not present it as when the user
  made the change, and do not order your domain state by it. Put your own
  timestamp inside the encrypted payload.

Then fetch each blob:

```http
GET /v1/sync/{appId}/{rootId}/{deviceId}/{eventId}
Authorization: Bearer <device_token>
```

Decrypt, and **validate the result before trusting it.** A compromised relay can
withhold or reorder events, so treat the decrypted payload as input, not truth.

## Step 5: acknowledge what you consumed

```bash
curl -X PUT $GESH/v1/sync/fattern/$ROOT_ID/$DEVICE_ID \
     -H "Authorization: Bearer $DEVICE_TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"ackCursor":42}'
```

```json
{ "device_id": "phone", "ack_cursor": 42, "last_seen_ms": 1786270450000 }
```

**Acknowledging is destructive.** Once every active peer has acknowledged past an
event, GESH erases the ciphertext — that is the whole retention model. So:

> Acknowledge only after the decrypted change is durably applied on this device.
> Not after download. Not after decrypt. After commit.

Acknowledgements only move forward — the returned `ack_cursor` is the higher of
what the server had and what you sent — so a retried or out-of-order report is
harmless. Acking also registers you as an active peer, which is what keeps data
alive for you.

## Step 6: pair a second device

The first device mints a code:

```bash
curl -X POST $GESH/v1/admin/fattern/$ROOT_ID/enrollments \
     -H "Authorization: Bearer $ROOT_TOKEN"
```

```json
{
  "code": "79T54-26AJX",
  "expires_at_ms": 1786270600000,
  "pairing_uri": "gesh://pair?s=https%3A%2F%2Fsync.example.com&c=79T54-26AJX"
}
```

### GESH does not generate the QR code

It returns a **string**, and only when the operator has set `GESH_PUBLIC_URL`;
otherwise `pairing_uri` is `null`. Rendering the image is your job, and it has to
be, because the URI is only half of pairing. You append the other half:

```js
const uri = `${response.pairing_uri}#k=${base64url(exportedContentKey)}`;
render(<QRCode value={uri} />);
```

A URI fragment is never transmitted to a server. That is the property that lets
one QR code carry both the transport code and the content key while GESH only
ever receives the first. **If you put the key anywhere but the fragment — a query
parameter, a header, a request body — you have handed it to the relay and lost
the entire security model.**

The new device redeems what it scanned:

```bash
curl -X POST $GESH/v1/enroll \
     -H 'Content-Type: application/json' \
     -d '{"code":"79t5426ajx","deviceId":"phone"}'
```

```json
{
  "app_id": "fattern",
  "root_id": "root_7c5e…",
  "device_id": "phone",
  "token": "<this device's own sync credential>"
}
```

The code identifies its own root, so the scanning device needs no handle and no
root ID — it learns both here. It gets a device token only; there is no way to
obtain the root token by pairing, which is deliberate.

Codes are single-use, expire (ten minutes by default), and are stored only as a
hash. Typed codes normalize, so case and the grouping dash do not matter, and the
alphabet omits `0`/`O` and `1`/`I` so a code can be read aloud.

**Re-enrolling an existing `deviceId` replaces that device's credential.** This is
how a reinstalled phone recovers without becoming a second device — reuse the
same `deviceId` and the old token stops working.

## Step 7: revoking

```bash
curl $GESH/v1/admin/fattern/$ROOT_ID/devices -H "Authorization: Bearer $ROOT_TOKEN"
curl -X DELETE $GESH/v1/admin/fattern/$ROOT_ID/devices/phone \
     -H "Authorization: Bearer $ROOT_TOKEN"
```

Every other credential is untouched. The root's own credential is not in the list
and cannot be named, so a root can never be stripped of authority over itself.

Revocation stops the device talking to GESH. It does **not** rotate the content
key, and the revoked device still holds whatever it already decrypted. If the
device is genuinely hostile, you need a new key and a re-pair of everything else
— design for that before you need it.

## Retention: three timers your design must survive

GESH erases data on a schedule you do not control. All three of these are
operator-configured and your app has no say:

| Timer | Default | What it means for you |
| --- | --- | --- |
| `GESH_EVENT_TTL_SECONDS` | 7 days | An event nobody collects is erased |
| `GESH_DEVICE_TTL_SECONDS` | 30 days | A silent device stops counting as a peer |
| `GESH_TOMBSTONE_TTL_SECONDS` | 30 days | An erased event's ID stays reserved |

The consequence that catches people: **a device offline longer than the device
TTL stops holding data alive.** When it returns, events it never saw are gone —
permanently, with no error to distinguish "nothing new" from "you missed it".

So a returning device cannot rebuild state from the feed. If your app needs that,
it needs its own answer: a periodic full-state snapshot event, or a direct
device-to-device transfer. Do not design as though the feed is a log you can
replay from zero.

## Handling `429`

Enrollment, handle lookup, root creation, and the credential check are all
throttled, and repeated failures earn a doubling lockout. A throttled request
returns `429` with a `Retry-After` header.

Honour it. In particular, **minting a fresh pairing code will not help** — the
lockout is on the client, not the code. Show the user the wait rather than
retrying in a loop.

## Error shapes are not uniform

Failures GESH raises itself return `{"error": "<message>"}` — generic by design,
with the detail kept in the server log. But three statuses come from the
framework layer before any GESH handler runs, and those carry a **plain-text
body**:

- `413` — body above the upload limit
- `415` — a JSON endpoint called without `Content-Type: application/json`
- `422` — well-formed JSON missing a required field, or a field of the wrong type

So parse defensively. Branch on the status code, and treat the body as
best-effort context rather than assuming `response.json().error` exists. The
`415` in particular catches people who set `Content-Type` on uploads and forget
it on `POST /v1/enroll`.

## Checklist before you ship

- [ ] Both tokens stored in a platform secret store, never in plain files or logs
- [ ] Daily sync uses `device_token`, not `root_token`
- [ ] Content key generated with a CSPRNG and never sent to the server
- [ ] Key appears only in the `#k=` fragment during pairing
- [ ] Fresh nonce per event
- [ ] `409` on upload treated as success-on-retry
- [ ] Cursor persisted across restarts and treated as opaque
- [ ] Ack sent only after the change is durably applied
- [ ] Decrypted payloads validated before use
- [ ] Your own timestamps inside the payload; `created_at_ms` not used for ordering
- [ ] `Retry-After` honoured on `429`
- [ ] A story for a device that was offline past the device TTL

## Where this is going

A reusable client SDK is on the roadmap ([README, Direction](../README.md#direction)).
Until it exists, every application implements the above independently — so if you
build one, the parts worth factoring out are the cursor/ack state machine, the
`409`-is-success rule, and the pairing URI construction, in that order.
