# Kioku Cloud Capture API v2

This is the stable capture contract for the pure-Swift macOS and iOS clients.
Clients capture bounded audio or screenshots, attach authoritative device-time
and foreground/browser context, and upload them to the attested enclave. All
transcription, OCR, diarization, indexing, and summarization run in the cloud.
WeSpeaker profile learning and voice matching are offline evaluation capabilities,
not part of the serving capture pipeline.

The capture pipeline is a core product behavior. It is not controlled by a
Kioku feature flag. Apple recording, Screen Recording, and Automation
permissions still apply, and clients must present the platform recording
indicators and the product's cloud-processing disclosure.

The Mac may continue capture during an ordinary network outage in an
account-scoped AES-256-GCM local outbox. It deletes an outbox item only after
the enclave acknowledges it. The outbox is a delivery buffer, not a local
transcription or memory archive; all understanding remains in the cloud. Before
releasing queued media after reconnection, the client settles each rounded-up
offline minute through the content-free route below and obtains a new live
recording lease.

## Authentication and transport

- Production requests use HTTPS terminated inside the attested enclave.
- Send `Authorization: Bearer <token>` using either a Kioku access token or an
  accepted Google ID token. Apple login always yields an ordinary Kioku access token.
- Never put user IDs in a path, header, or manifest. The server derives the
  account from the verified token.
- All identifiers are 1–128 ASCII letters, digits, `-`, or `_`. UUIDv7 is the
  recommended client format.
- All times are RFC 3339/ISO 8601. Include the original IANA `timezone_id` and
  numeric UTC offset even when the timestamp is already expressed in UTC.

### Sign in with Apple routes

- `POST /oauth/apple/native` verifies an iPhone identity token, single-use authorization
  code, and raw nonce before issuing a Kioku access/refresh pair. The allow-listed legacy
  macOS audience remains accepted for forward compatibility, but directly distributed
  Developer ID builds use the browser flow below because their profiles cannot authorize
  Apple's native entitlement.
- `GET /oauth/apple/authorize` and Apple's exact `form_post`
  `POST /oauth/apple/callback` verify the web Services ID response, then continue through
  the same persisted consent, single-use authorization code, PKCE, and `/token` rotation
  used by the OAuth facade. Kioku's fixed native client additionally accepts only
  `http://127.0.0.1:<ephemeral-port>/oauth/callback`, enabling the Developer ID Mac app
  without placing a bearer or refresh token in the browser return URL.
- `GET /api/auth/session` returns canonical account metadata and linked providers.
  Authenticated native linking uses `POST /api/auth/apple/link`; browser linking begins at
  `POST /api/auth/apple/web-link` and returns only to the fixed `WEB_ORIGIN` callback.
- iPhone, Mac, and web use separate allow-listed Apple audiences. Provider subjects are
  never joined by email. Apple refresh authorization is retained per issuing client and
  all retained grants are revocation barriers for account deletion.

## Upload one capture event

`POST /api/v2/capture/events`

Content type: `multipart/form-data` with one or two parts:

1. `manifest`: UTF-8 JSON matching `CaptureEventManifest` below, maximum 128 KiB.
2. `media`: required for a canonical event and forbidden for a reference
   observation. For canonical events it contains the exact bytes described by
   `manifest.media`; set the part's content type to the same value as
   `manifest.media.mime_type`.

Supported media:

| Stream | MIME types | Maximum object size |
|---|---|---:|
| Audio | `audio/m4a`, `audio/mp4`, `audio/wav`, `audio/x-wav` | 20 MiB |
| Screenshot | `image/jpeg`, `image/png` | 5 MiB |

The server verifies the declared length, SHA-256, MIME type, and container
signature before encryption or storage. A capture event may span at most eight
hours; clients should normally use 5–30 second audio snippets and one event per
screenshot.

### Manifest example

```json
{
  "schema_version": 2,
  "event_id": "019fbab2-8413-7053-9117-eb249b72b15b",
  "device_id": "019fbab2-8413-7053-9117-eb249b72b15d",
  "install_id": "019fbab2-8413-7053-9117-eb249b72b15e",
  "capture_session_id": "019fbab2-8413-7053-9117-eb249b72b15f",
  "session_finished": false,
  "stream_id": "019fbab2-8413-7053-9117-eb249b72b160",
  "stream_kind": "system_audio",
  "sequence": 42,
  "source_wall_at": "2026-07-31T18:00:00.000Z",
  "source_monotonic_ns": 9000000000,
  "started_at": "2026-07-31T18:00:00.000Z",
  "ended_at": "2026-07-31T18:00:05.000Z",
  "timezone_id": "America/New_York",
  "utc_offset_minutes": -240,
  "clock_uncertainty_ms": 24,
  "media_disposition": "canonical",
  "media": {
    "asset_id": "019fbab2-8413-7053-9117-eb249b72b161",
    "mime_type": "audio/m4a",
    "codec": "aac",
    "byte_length": 137492,
    "sha256": "64 lowercase or uppercase hexadecimal characters",
    "sample_rate": 48000,
    "channels": 2,
    "frame_count": 240000,
    "width": null,
    "height": null,
    "scale": null,
    "orientation": null
  },
  "context": {
    "capture_status": "stable",
    "active_app": "Google Chrome",
    "primary_bundle_id": "com.google.Chrome",
    "primary_window_id": 876,
    "window_title": "Weekly planning",
    "display_id": 42,
    "active_url": "https://meet.google.com/abc-defg-hij?authuser=0",
    "active_url_title": "Weekly planning",
    "browser_permission_status": "granted",
    "browser_state_key": "019fbab2-8413-7053-9117-eb249b72b15d:browser-v2:<content_hash>",
    "browser_snapshot": {
      "state_key": "019fbab2-8413-7053-9117-eb249b72b15d:browser-v2:<content_hash>",
      "browser_bundle_id": "com.google.Chrome",
      "browser_name": "Google Chrome",
      "permission_status": "granted",
      "active_window_index": 1,
      "active_tab_index": 1,
      "reported_tab_count": 1,
      "truncated": false,
      "ambient_tab_collection_enabled": false,
      "content_hash": "64 lowercase hexadecimal characters over the browser-v2 commitment",
      "tabs": [
        {
          "window_index": 1,
          "tab_index": 1,
          "title": "Weekly planning",
          "url": "https://meet.google.com/abc-defg-hij?authuser=0",
          "url_scheme": "https",
          "is_active": true,
          "is_loading": false
        }
      ]
    },
    "visible_windows": [],
    "visible_windows_truncated": false
  },
  "audio_role": "remote_received",
  "audio_route": "system_output",
  "route_epoch": 3,
  "recording_retention": {
    "policy_revision": 7,
    "policy_epoch": "rpe_<64 lowercase hexadecimal characters>",
    "lease_id": "lease_<64 lowercase hexadecimal characters>",
    "authority_token": "rrl1.<signed opaque value>"
  }
}
```

Browser-v2 state is event-scoped and content-addressed. `state_key` is exactly
`<device_id>:browser-v2:<content_hash>`; the commitment covers the browser bundle,
permission result, active coordinates, reported/truncated counts, the explicit ambient-tab
consent bit, and every ordered tab field including `url_scheme`. Tab titles and URLs are
bounded by UTF-8 byte length. When ambient collection is false, a granted snapshot contains
only the active tab. Non-granted snapshots carry no tab or active-URL evidence. Older
browser-v1 manifests remain replay-compatible, but new clients always send the explicit v2
consent bit.

`session_finished` is optional (false by default) and valid only on audio. A client sets
it on its final durable, gracefully completed audio event. Acceptance atomically records
the exact capture session as ended; byte-identical replay remains idempotent. A separate
session-finish request may accelerate that fact but is not the durable boundary.

`recording_retention` is optional, audio-only, and strict. It contains exactly the four
server-issued fields shown above. The recording lease response also includes client-local
validity timestamps; clients use those to decide whether the complete source interval is
covered but never serialize them into this deny-unknown-fields object. The echo is not
authority by itself. Ingest verifies its signature, account, lease, policy epoch, and
interval, then rechecks the current durable retention preference under the account
lifecycle lock. Missing, stale, revoked, out-of-interval, or malformed authority falls
back to the ordinary 30-day processing path. Durable storage unavailability never becomes
a claimed durable acknowledgement.

`media_disposition` is `canonical` or `reference`; omission means `canonical`
for compatibility. Canonical events require `media`, forbid `reference`, and
create one encrypted media object plus one bounded processing job.

### Metadata-only screen references

A stable `mac_screen` capture attempt whose pixels meet deduplication version 1
may send a reference observation. It omits `media` and the multipart `media`
part while retaining all normal clocks, sequence fields, and complete current
context:

```json
{
  "schema_version": 2,
  "event_id": "019fbab2-8413-7053-9117-eb249b72b170",
  "device_id": "019fbab2-8413-7053-9117-eb249b72b15d",
  "install_id": "019fbab2-8413-7053-9117-eb249b72b15e",
  "capture_session_id": "019fbab2-8413-7053-9117-eb249b72b15f",
  "stream_id": "019fbab2-8413-7053-9117-eb249b72b169",
  "stream_kind": "mac_screen",
  "sequence": 43,
  "source_wall_at": "2026-07-31T18:00:02.000Z",
  "source_monotonic_ns": 11000000000,
  "started_at": "2026-07-31T18:00:02.000Z",
  "ended_at": "2026-07-31T18:00:04.000Z",
  "timezone_id": "America/New_York",
  "utc_offset_minutes": -240,
  "clock_uncertainty_ms": 24,
  "media_disposition": "reference",
  "reference": {
    "canonical_event_id": "019fbab2-8413-7053-9117-eb249b72b168",
    "canonical_asset_id": "019fbab2-8413-7053-9117-eb249b72b167",
    "canonical_media_sha256": "64 hexadecimal characters",
    "perceptual_hash": "0123456789abcdef",
    "hamming_distance": 2,
    "pixel_change_ratio": 0.004,
    "context_fingerprint": "64 hexadecimal characters",
    "dedupe_version": 1
  },
  "context": {
    "capture_status": "stable",
    "active_app": "Google Chrome",
    "primary_bundle_id": "com.google.Chrome",
    "primary_window_id": 876,
    "window_title": "Weekly planning",
    "display_id": 42,
    "active_url": "https://meet.google.com/abc-defg-hij?authuser=0",
    "active_url_title": "Weekly planning",
    "browser_permission_status": "granted",
    "visible_windows": [],
    "visible_windows_truncated": false
  }
}
```

Every version permits a reference only when the client compared against the
last canonical screen in that display stream, the before/after context was
stable, and the version's context fingerprint was unchanged. Ambiguous or
missing state must produce another canonical upload. Version bounds on the
pixel evidence:

- **Version 1**: 8×8 grayscale average-hash Hamming distance at most 3 and
  bounded downscaled pixel-change ratio at most 0.01.
- **Version 2**: Hamming distance at most 8 and pixel-change ratio at most
  0.03, wide enough to absorb clocks, notification badges, and cursor blinks
  on an otherwise unchanged screen; scrolling or content changes still exceed
  the ratio and require a canonical upload.

Clients must send `dedupe_version: 1` until a screen-reference batch receipt
advertises `max_screen_dedupe_version` of 2 or higher, then may use version 2
for subsequent decisions in that process run. The advertisement is
per-response, never persisted server-side, and an enclave accepts every
version up to the advertised maximum concurrently.

The context fingerprint is SHA-256 over compact UTF-8 JSON with recursively
lexicographically sorted keys. Version 1 covers exactly these nullable
fields: `active_app`, `active_url`, `active_url_title`,
`browser_permission_status`, `capture_status`, `display_id`,
`primary_bundle_id`, `primary_window_id`, `visible_windows`,
`visible_windows_truncated`, and `window_title`. Version 2 covers the same
fields **except** `visible_windows` and `visible_windows_truncated`: the
background window inventory's fractional intersection ratios and z-order
churn on every repaint, which made semantically identical screens fingerprint
differently under version 1. The inventory is still captured and retained on
the observation — it is only excluded from reference-identity. Ambient
browser-tab inventory is likewise retained on the observation but excluded
from every fingerprint version so an unchanged visible screen need not be
re-uploaded merely because a background tab changed.

The enclave recomputes the fingerprint, compares the literal visible context,
and requires the target to be an earlier canonical event for the same
authenticated account, device, install, session, stream, and display. It also
verifies the canonical asset and SHA-256. Missing/forward references, chains,
digest mismatches, and context transitions fail with HTTP 400 and the fixed,
content-free response `{"error":"screen_reference_rebase_required","reason":"..."}`.
The bounded `reason` is one of `canonical_unavailable`,
`context_fingerprint_mismatch`, `target_mismatch`,
`canonical_context_unavailable`, or `context_transition`. The client must retry
that same observation and stream sequence once as a canonical screenshot; this
screen-local recovery does not mean the audio upload path or recording lease
failed. A valid reference creates no media object and no Gemini job, but it
advances contiguous acknowledgement and remains in export and deletion
coverage.

iOS imported screenshots remain intentional canonical assets; clients must not
apply perceptual suppression to them.

### Batch metadata-only screen references

`POST /api/v2/capture/screen-reference-batches`

Content type: `application/json`. This route is available only to the Mac's encrypted
outbox delivery path and therefore requires
`Kioku-Delivery-Mode: encrypted-outbox-v1`. The body is capped at 1 MiB. Its JSON object
contains `schema_version: 1`, a `batch_id` of exactly 64 lowercase hexadecimal
characters, and an `events` array containing 1 to 64 complete
`CaptureEventManifest` reference objects.

Every `events` member is the complete metadata-only `mac_screen` reference manifest
described above. Members must have the same device, install, capture session, and stream;
their sequences must be ascending and contiguous; their event IDs must be unique; and no
member may contain media bytes. Each canonical dependency is validated independently, so
references in one stream may target different earlier canonical displays.

`batch_id` is SHA-256 over this exact byte preimage: UTF-8
`kioku.screen-reference-batch.v1`, one zero byte, a big-endian unsigned 32-bit event
count, then for each ordered event a big-endian unsigned 32-bit UTF-8 event-ID length,
the event-ID bytes, and a big-endian unsigned 64-bit sequence. The enclave separately
binds the receipt to its typed, normalized per-event manifest digests, so reusing a batch
ID with changed manifests returns HTTP `409` even if JSON encoding or key order differs.

A batch containing at least one new event returns HTTP `201`; an exact duplicate returns
HTTP `200`:

```json
{
  "batch_id": "64 lowercase hexadecimal characters",
  "stream_id": "019fbab2-8413-7053-9117-eb249b72b169",
  "first_sequence": 43,
  "last_sequence": 63,
  "new_count": 21,
  "duplicate_count": 0,
  "committed_through_sequence": 63,
  "max_screen_dedupe_version": 2
}
```

The enclave validates the whole batch, bulk-reserves the existing per-event delayed-
delivery authority, records every new reference/browser observation in one user
PostgreSQL transaction and advances the contiguous acknowledgement once. It returns success
only after commit. A failed or ambiguous commit retains
the per-event reservations for idempotent retry; it does not acknowledge volatile rows or
spend the same event twice. Every genuinely new reference still costs one event credit and
zero media bytes. The batch receipt is correlation state, not billing authority.

A canonical dependency failure rejects the whole batch with HTTP `400` and the same fixed
error and bounded reason as individual reference repair, plus only the failing zero-based
`index` and `sequence`:

```json
{
  "error": "screen_reference_rebase_required",
  "reason": "context_fingerprint_mismatch",
  "index": 7,
  "sequence": 50
}
```

The client must preserve every queued item, rebase only that exact observation as a
canonical event with the same event ID and sequence, and retry the remaining dependency-
ordered work. HTTP `401` requires credential refresh without retrying the stale bearer;
HTTP `429` and 5xx retain ciphertext and use bounded backoff. The client may fall back to
individual event upload only when an authenticated production server definitively returns
`404`, `405`, or `501` for this additive route.

`stream_kind` is one of `mic`, `system_audio`, `mac_screen`, `ios_mic`,
`ios_imported_screenshot`, or `ios_shared_page`.

Audio descriptors require `sample_rate`, `channels`, and `frame_count`. Image
descriptors require `width` and `height`; `scale` and `orientation` are
optional. Send all inapplicable optional fields as `null` or omit them.

`source_wall_at` and `source_monotonic_ns` describe the instant at which the
client committed the event metadata. `started_at` and `ended_at` describe the
media interval. Sequence numbers are zero-based and strictly identify the
ordering within one stream. A new app launch may create a new session and new
streams but must retain its stable `device_id` and `install_id`.

Browser URLs are exact evidence. Do not normalize, strip, complete, or rewrite
them. A complete snapshot may be omitted when unchanged; send its previous
`browser_state_key` and the server will link the observation when that state is
known. Permission denial is represented as metadata, not as a fabricated empty
browser state.

### Success and retry behavior

A new event returns HTTP `201`:

```json
{
  "event_id": "019fbab2-8413-7053-9117-eb249b72b15b",
  "asset_id": "019fbab2-8413-7053-9117-eb249b72b161",
  "media_disposition": "canonical",
  "processing_state": "queued",
  "committed_through_sequence": 42
}
```

An identical retry returns HTTP `200` with the same shape. Reusing an
`event_id`, `(device_id, stream_id, sequence)`, or asset identity with different
content returns HTTP `409`; the client must treat that as a local data-integrity
error and mint new IDs only for a genuinely new event.

A newly accepted reference returns `201` with
`media_disposition: "reference"`, the canonical `asset_id`, and
`processing_state: "ready"`; an identical retry returns `200`.

Clients durably spool a canonical manifest and media before upload, and spool a
reference manifest only after its canonical dependency is durable. Replay in
ascending stream sequence and never upload a reference until its canonical has
been acknowledged. Delete a local spool item only when its sequence is at or below
`committed_through_sequence`. Retry network failures and HTTP 5xx with bounded
exponential backoff plus jitter. Respect HTTP `429` and its `retry_after`
seconds. Do not retry malformed requests (HTTP 400) without correcting them;
the one defined exception is `screen_reference_rebase_required`, which is
corrected by a single canonical retry at the same stream sequence.

The Mac's encrypted outbox adds the fixed header
`Kioku-Delivery-Mode: encrypted-outbox-v1`. Each newly billed live minute and
each acknowledged offline tick grants a bounded delayed-delivery budget of 120
events and 256 MiB. Before persistence, the enclave atomically reserves one
event credit and the canonical media bytes by authenticated account/event ID.
Same-event retry spends nothing twice; a reference-to-canonical recovery spends
only its additional bytes. This delivery path remains usable after the original
live lease expires, so a stopped Mac can drain on reconnect without metering
network-transfer time. Requests without that header still require a current live
recording lease. Missing delivery credit returns the same retryable
`recording_lease_inactive` response and never persists the item.

## Reconcile offline recording time

`POST /api/billing/offline-recording-usage`

```json
{"request_id":"019fbab2-8413-45aa-8d2e-eb249b72b15b"}
```

Each request represents exactly one rounded-up 60-second offline recording
tick. `request_id` is UUIDv4 and is the sole accepted field. The enclave derives
the authenticated account and a domain-separated pseudonymous billing event;
no capture, device, stream, media, or timestamp identifier crosses the billing
boundary. An identical retry returns the admitted tick with `"duplicate":
true`. Success returns `200` with `duplicate` and the current provider-neutral
`billing` snapshot. Definite entitlement denial returns `402` with the same
bounded denial shape as recording-lease admission; dependency unavailability
returns `503`. Clients retain the usage request and queued media until the
request is acknowledged and settle ticks oldest-first. A running client then
acquires/reattaches a live lease for new online capture; a stopped client may
launch its signed helper in drain-only mode using the credits already granted
by the paid live/offline minutes.

## Resume a stream

`GET /api/v2/capture/streams/{stream_id}/ack`

```json
{
  "stream_id": "019fbab2-8413-7053-9117-eb249b72b160",
  "committed_through_sequence": 42
}
```

The acknowledgement advances only across a contiguous prefix. If sequences 42
and 44 arrived but 43 did not, the value remains 42. This makes recovery after
termination or background suspension deterministic. A well-formed stream ID that does
not belong to the authenticated account returns HTTP `404`.

## Check cloud processing

`GET /api/v2/capture/events/{event_id}`

```json
{
  "event_id": "019fbab2-8413-7053-9117-eb249b72b15b",
  "processing_state": "ready",
  "error_code": null,
  "attempt_count": 1
}
```

### Cloud aggregation and immutable provenance

The accepted event and its original clocks are immutable. The enclave plans
canonical media into deterministic bounded work units before calling Gemini:

- adjacent compatible audio events from one capture session and stream form a
  window of at most five minutes, 20 MiB, and a one-second inter-event gap;
- a screen storyboard spans at most 90 seconds, 12 canonical frames, 16 MiB,
  and 24 million input pixels; and
- reference observations have no media job, work-unit membership, output-token
  reservation, or model call.

Every work unit stores its ordered member events and exact window offsets.
Every diarized turn stores its intersections with the original source-event
intervals, including a turn that crosses an event boundary. Gemini offsets are
validated against the assembled window; source timestamps, URLs, and literal
device context always remain authoritative.

Gemini `speaker_local_id` values are request-local turn-grouping hints, not
durable speaker identities. The structured store therefore never exposes an unmatched
local ID such as `speaker_0`: it uses `Unidentified voice` instead. Within one
work unit, unresolved sibling turns may inherit a name or independent voice
profile label only when the same local ID has exactly one nonconflicting
resolution. The enclave abstains when different resolutions conflict, and it
never carries a Gemini local ID across work-unit boundaries. Schema migration
applies the same rule to historical exact local-ID fallbacks.

Storyboard inputs use each event ID as an opaque `frame_id`. A response is
rejected atomically if any expected ID is missing, duplicated, or replaced by
an unknown ID. Per-frame results are projected only to that exact source frame;
an active-speaker label is never smeared across the storyboard.

The persistent daily Vertex ceiling is divided into protected output-token
reservations: 50% audio, 25% screens, and 25% episode/finalization text. Screen
storyboards reserve at most 1,024 output tokens; audio windows reserve at most
4,096. Audio is scheduled before screen work for each user sweep, so screen
volume cannot consume or queue ahead of protected audio capacity. Retries reuse
the deterministic work-unit reservation. Encrypted per-user telemetry stores
only work class, opaque unit/version, reserved and actual token counts,
latency, attempt, and outcome—never captured content.

States are `queued`, `processing`, `retry_wait`, `ready`, `failed`, or
`pruned`. `pruned` means the bounded raw-media retention window elapsed; the
derived searchable records and timestamped evidence remain. A well-formed event ID
that does not belong to the authenticated account returns HTTP `404`.

## Check or finish one capture session

`GET /api/v2/capture/sessions/{capture_session_id}` returns only work and memories linked
to that exact authenticated session. Its stage is one of `received`, `processing`,
`organizing`, `preparing_recap`, `ready`, `needs_attention`, or `no_memory`; the body
also contains the accepted event count, optional end time, and zero or more linked
memory summaries. New in-flight work reports `processing`, and a formed memory reports
`ready`/`preparing_recap` even while other items sit in a terminal per-item failure or
its background retry; `needs_attention` is reserved for a session where terminal
failures remain and no memory materialized. Terminally failed jobs get a bounded
second-chance ladder (one resurrected attempt per hour, capped total attempts, recent
sessions only, never for media-integrity failures), and the summarizer holds its
forward-only cursor over otherwise-empty spans while their failures are inside the
ladder's first rounds, so a transiently failed session can still resolve to `ready` or
an honest `no_memory` without any client action. Recoveries after a memory already
formed, or after the hold rounds, enrich search but do not reopen summarization.

`POST /api/v2/capture/sessions/{capture_session_id}` is an idempotent completion
acceleration. Native clients retry it only after all durable events for that session are
accepted. Correctness and later finalization do not depend on this request because the
final accepted audio manifest carries `session_finished=true`.

## Screenshot evidence bytes

Cloud Capture v2 does not use the retired device-sync upload planner. Authenticated
`GET /api/screenshot-images/plan` and
`POST /api/screenshot-images` return
`410 {"error":"screenshot_upload_retired"}` before reading an upload body or
performing PostgreSQL, KMS, reservation, or object-provider work. Canonical capture
already uploaded the bounded image under its event receipt, and the native client
does not retain a second local source to upload later. New clients must not call the
retired plan or multipart routes.

`GET /api/screenshot-images/{cloud_image_id}/content` serves a complete JPEG to the
authenticated owner. A Cloud Capture v2 ID has the form `capture-v2:{asset_id}` and is
available only after the canonical screen result is ready. The enclave reads the exact
current-provider generation committed by capture ingest and verifies its owner-derived
object key, installed wrapped DEK, strict v2 authenticated context, plaintext length, and
SHA-256 before returning bytes. It never substitutes a newer generation. The only supported
namespace is `capture-v2:`; another well-formed identifier is absent and returns `404`.

A genuinely absent, non-ready, deleted, non-JPEG, or wrong-owner image returns `404`.
PostgreSQL, current-object-provider, or KMS transport unavailability returns
`503 {"error":"enclave_unavailable"}`. Malformed sealed identity, key mismatch,
authentication failure, or length/hash corruption returns `500` and no bytes.

## Browser evidence and episode deletion

Authenticated `GET /api/browser-snapshots/{source_key}` returns browser evidence only
while the exact Cloud Capture v2 event observation remains linked to
a live screenshot in a live episode. The v2 loader reauthenticates the event, observation,
state commitment, context status, canonical envelope and screenshot source association;
missing or mismatched required evidence is an authority failure, not a plausible empty
snapshot. True absence or wrong ownership returns `404`; PostgreSQL unavailability or corrupt
authoritative evidence returns `503 {"error":"enclave_unavailable"}`.

Authenticated `DELETE /api/episodes/{id}` returns the deleted utterance, screenshot, and
unreferenced audio-segment counts plus the utterance and screenshot local source keys. For a new
deletion, one tenant-qualified PostgreSQL transaction locks the episode, inventories its exact
member IDs, source keys, now-orphaned capture events, and live-media object names, freezes episode
finalization, and records an immutable pending plan and replayable response. Structured rows are
not physically removed before external media cleanup. Segments and capture events that still have
non-target references are excluded from the purge.

The route deletes and verifies every current and noncurrent GCS generation for each exact object
name in that PostgreSQL plan. Only after every object is absent does a second transaction lock and
revalidate the durable plan, delete the episode and its inventoried structured rows, and mark the
receipt complete. A successful request returns `200` with `{"deleted":true,...}`. Repeating a
completed request returns the persisted receipt without another provider call; a never-present
episode returns `404`.

Preparation failure returns `503 {"error":"enclave_unavailable"}`. Object cleanup or
transactional completion failure returns
`503 {"error":"media_delete_failed","deletion_pending":true}`—the episode API does not use
`202`. The durable plan remains pending, so another `DELETE` resumes the same idempotent work and a
restart-safe reconciler also scans immediately and every 30 seconds, processing at most 32 pending
plans per scan in durable update/account/episode order. No response claims completion while an
inventoried object generation or the transactional structured purge remains outstanding.

## Finalized-episode webhooks

Authenticated clients manage destinations with `GET`/`POST /api/webhooks`,
`DELETE /api/webhooks/{id}`, and `POST /api/webhooks/{id}/test`. Creation accepts
an HTTPS endpoint, a display name, and `include_content`; the one-time response
includes the signing secret. List responses and logs redact endpoint paths,
queries, and secrets. Events are Standard Webhooks-signed CloudEvents and omit
the final brief unless that destination explicitly enabled content.

Each list item includes a content-free `delivery_status` summary with `pending`,
`retry`, `sent`, `failed`, `ambiguous`, and `cancelled` counts. Its optional
`latest` object contains only a normalized outcome, bounded attempt count,
validated HTTP status, and validated update timestamp; it never returns a
provider error string, endpoint path, secret, signature, or body.
If PostgreSQL cannot answer that status read, the list
request returns `503 {"error":"enclave_unavailable"}` rather than a zeroed
status or a generic fault.

Only `w1_` event identities can reach a provider. Malformed rows and rows older than
24 hours are cancelled
without network I/O. Before the first provider call, the worker freezes one exact
bounded endpoint, signing secret, content decision, and canonical body, then
durably claims the complete delivery row behind an exact PostgreSQL disclosure
fence. Retries reuse those bytes and the same `webhook-id`; a lost or otherwise
ambiguous response is never resent. Definitive transient rejects use bounded
`Retry-After`/backoff up to ten attempts.

Every DNS lookup has a five-second deadline and at most 64 answers; all answers
must be public, the chosen address is pinned, environment proxies are disabled,
and redirects are disabled. A
subscription is strictly ordered, while another subscription can progress.
Delivery makes at most two provider calls per account per sweep, checks
that cap before creating a claim, and is
paced at 250 ms per worker. PostgreSQL claim ownership, lease expiry, and compare-and-set
settlement make the provider boundary safe across horizontal workers. Deletion first disables the
destination, exactly cancels its complete backlog in resumable one-row
transactions, exactly purges terminal delivery rows and their frozen endpoint,
signing secret, opted-in body, and claim evidence, then removes it. The
permanent logical purge record retains only fixed-size commitments. An in-flight
disclosure fence makes deletion conflict rather than allowing content to leave
after revocation. Finalization holds the same per-account lifecycle boundary
from its enabled-destination snapshot through the atomic PostgreSQL commit;
deletion holds it through disable, delivery drain, and account removal, so a
paused stale snapshot cannot enqueue after a successful `204`.

## Episode-ready email preference

Authenticated clients read and update the account-level preference at
`GET /api/preferences/episode-email` and `PUT /api/preferences/episode-email`.
The update body is `{"enabled":true,"include_content":false}`; the response
also returns the verified account email as `recipient_email` and whether the
provider is configured as `available`. Responses are `no-store`.

An initial completed memory creates one durable email delivery when the
preference is enabled; recap regeneration does not enqueue another. PostgreSQL freezes the
exact current recipient, rendered text and HTML,
content-consent decision, and `e1_` idempotency key before its first provider
call. Retries reuse those exact bytes. Preference disablement, content downgrade,
or account deletion cannot pass the durable pre-send disclosure fence; changing
the preference conflicts while an exact send is in flight.

Deliveries older than 24 hours and malformed, missing, exhausted, or
capacity-limited rows are cancelled without provider I/O. Known provider
rejections retry with bounded `Retry-After`/backoff up to ten attempts. A lost
or otherwise ambiguous response is never resent. Provider acceptance records
the provider's actual 2xx status and message ID. A worker sends at
most two emails per account per sweep, uses 250-ms process-local pacing, and
opens a process-local provider circuit for provider-wide failures. Durable PostgreSQL
claims, lease expiry, and compare-and-set settlement prevent two horizontal workers from
sending the same delivery.

## Apple ready-notification installation

Authenticated native clients opt in one device with
`PUT /api/push/installations/{installation_uuid}` and disable it with `DELETE` on the
same path. Registration accepts only the exact iOS/macOS app topic and matching
sandbox/production environment. A first successful initial memory finalization creates
one logical delivery for every installation active at that moment; recap regeneration
does not replay it.

The APNs alert is always `Kioku` / `Your memory is ready.` Its payload contains only a
schema version and a distinct 43-character URL-safe handoff handle. It contains no
memory ID, title, people, transcript, summary, action items, timestamps, account identity,
URL, or credential. Authenticated `GET /api/notifications/{handoff_handle}` resolves the
handle to the corresponding memory ID; missing, expired/deleted, and wrong-owner handles
are indistinguishable.

Only current `p1` rows bound to the current credential generation can reach APNs;
malformed or stale delivery rows are cancellation-only. Each delivery expires within
24 hours and is best-effort
at-most-once: Kioku retries only a provider response known to be a rejection,
and never resends after a lost or otherwise ambiguous response. A handoff for a
possibly delivered notification remains resolvable while its finalized memory
exists. A truly absent or wrong-owner handoff returns 404; temporary PostgreSQL
unavailability returns 503 so clients do not mistake unavailability
for absence.

Push pacing and provider-circuit state are process-local. PostgreSQL delivery claims,
expiry, and compare-and-set settlement provide the service-wide send fence for horizontal
workers; a lost or ambiguous provider response is terminal and is never resent. Production
still requires the clean, release-verified deployment source seal and ADR-0041's staged
zero-unavailable rollout with exact image/KMS/readiness readback.

## People learned automatically

`GET /api/v2/people?after_id=0&limit=50&q=john` returns identified people in
stable opaque-ID order. `limit` is 1–100, `after_id` is the prior page's
`next_cursor`, and optional `q` matches a display name or supported alias.
Unnamed/tentative voices are not returned:

```json
{
  "people": [{
    "id": 7,
    "display_name": "John Garcia",
    "voice_profile_count": 1,
    "fact_count": 2,
    "updated_at": "2026-07-31T18:04:12.000Z"
  }],
  "next_cursor": null
}
```

`GET /api/v2/people/{person_id}` returns supported aliases, human-readable
voice coverage, current and superseded temporal facts, identity evidence, and
up to 100 recent attributed statements with source event/time and episode
navigation. Each name/fact/evidence item includes its state, confidence,
observed time, literal evidence, and source event/turn. Raw embeddings and score
vectors never appear. Clients should present facts as learned observations,
not user-authored contact data. Existing REST search supports speaker filtering.

Large histories are available without growing the profile response:

- `GET /api/v2/people/{person_id}/evidence?limit=50&before_id=123` returns
  `{"evidence": [...], "next_cursor": 98}` newest first.
- `GET /api/v2/people/{person_id}/statements?limit=50&before_id=456` returns
  `{"statements": [...], "next_cursor": 407}` newest first, including source
  event and optional episode ID/title for navigation.

`limit` is 1–100. Omit `before_id` for the first page; pass the returned
positive `next_cursor` as the next `before_id`. A missing, unnamed, or tentative
person returns `404`. Unknown query fields return `400`.

### Recording retention setting (staged)

The cross-platform `recording_retention_v1` setting uses a two-step, revision-bound
contract:

- `GET /api/v2/settings/recording-retention` returns the capability, settled
  `processing_window_30d|until_deleted` policy, consent/revision/epoch/effective fields,
  active operation, and bounded recording/object/byte inventory.
- `POST /api/v2/settings/recording-retention/preview` accepts only
  `{target_policy,expected_revision,consent_version,promote_existing}` and returns a
  short-lived preview bound to that exact settled revision and inventory.
- `POST /api/v2/settings/recording-retention/changes` accepts the same decision plus
  `preview_id` and requires `Idempotency-Key`. A destructive downgrade additionally
  requires provider authentication no more than ten minutes old; it read-fences durable
  audio before asynchronous exact-generation deletion and recording-key erasure.
- `GET /api/v2/settings/recording-retention/changes/{operation_id}` returns the bounded
  operation status. IDs are opaque and owner scoped.

All responses are private/no-store. Enabling is prospective; `promote_existing=true` is
not currently advertised. The implementation is intentionally dark while schema epoch 2
is only known: source declares `HEAD=2`, `TARGET=1`, and `MINIMUM_SERVABLE=1`. During this
phase `capability.available` is false, an enable preview returns `412`, capture remains on
the existing processing bucket, and playback returns an owner-indistinguishable `404`.
Separate reviewed releases must first advance TARGET and then MINIMUM_SERVABLE.

### Person conversations and memory playback

`GET /api/episodes/{memory_id}/members` returns chronological evidence for the owner. An
utterance's `started_at` / `ended_at` use its stored speaker-observation times, falling back to
the source segment plus utterance offsets only when an observation is absent; rows in one source
segment therefore do not inherit one repeated timestamp. Source-backed owner speech is labeled
`Me`. Identified rows may add opaque `person_id`, `display_name`, and attribution kind without
using display text as identity.

`GET /api/v2/people/{person_id}/memories?limit=25&before_id=123` returns
person-ID-attributed memories newest first. Each row includes the attributed
utterance count, contributing recording count, truthful aggregate audio availability,
and optional `playback_start_ms` / `playback_utterance_id` deep-link coordinates.
`limit` is 1–100. The person must be identified; display-name equality is never used
as a join key.

`GET /api/v2/memories/{memory_id}/playback?at_ms=0` returns a version-1,
owner-only playback window. A window covers at most 15 minutes, 128 source segments,
1,000 utterances, and 4,000 ordered source spans. The response contains opaque
recording, track, and segment IDs; a memory-relative wall-clock timeline; separate
mic/system/iPhone tracks; transcript rows; source-span seek coordinates; availability;
and a positive `projection_revision`. It never exposes a provider object name,
generation, wrapped key, or media key. The revision is bounded to JavaScript's exact
integer range so browser clients can echo it without numeric rounding. Pass only one of
`at_ms` or the returned opaque
`cursor`; the cursor is account, memory, revision, offset, issue-time, and expiry bound.

`GET /api/v2/memories/{memory_id}/recordings/{recording_id}/segments/{segment_id}?projection_revision=7`
returns one complete bounded source M4A after reauthorizing the memory/recording/segment
chain and revalidating the exact provider generation, per-user envelope, object-bound
AAD, plaintext length, SHA-256, codec, and container. A stale revision returns `409`.
The endpoint intentionally does not advertise arbitrary byte ranges because current
segments are whole-object AES-GCM ciphertext.

All three surfaces require the ordinary authenticated owner, are rate limited, and set
`Cache-Control: private, no-store, max-age=0` plus `Pragma: no-cache`. Segment success
also sets canonical `Content-Type: audio/mp4` and `X-Content-Type-Options: nosniff`.
After epoch-2 activation, playback may cover source audio still present under the
processing-window policy as well as affirmatively retained durable audio. It does not
change either retention decision. Before activation the routes remain dark, and external
durable rollout additionally remains blocked on full media-byte export and complete
recording-audio deletion inventory required by ADR-0036.

## Owner metrics facade

The owner economics routes require an ordinary authenticated account whose stable enclave
UUID is present in the image-baked `ADMIN_USER_IDS`. This authorization check happens
before identity enumeration or any request to the isolated billing service. Non-owners
receive `403`; successful and error responses use `Cache-Control: no-store`.

`GET /api/admin/capabilities` is the navigation/capability probe. A successful response is:

```json
{
  "owner": true,
  "admin": true,
  "margin_report": true,
  "margin_kind": "estimated_contribution_margin",
  "storage_bytes": "current_logical_bytes"
}
```

`owner` is the canonical capability. `admin` remains a compatibility alias for older web
clients and has the same owner-only meaning; it does not grant a general administrator
role.

`GET /api/admin/margin?limit=50&after=<cursor>` returns the current UTC month's estimated
owner-economics page. `limit` is 1–100; `after` is the preceding opaque cursor. The facade
maps each billing row's random account pseudonym to `accounts[].email` inside the enclave,
removes the pseudonym, and adds enclave-local storage, email-delivery, and inference-
coverage drivers. The browser must follow `next_cursor` to completion before presenting
cross-account totals.

Each account row's `direct_vertex.by_operation.audio_understanding` object is:

```json
{
  "event_count": 18,
  "incomplete_event_count": 0,
  "estimated_known_uncached_input_audio_usd_micros": 12345,
  "uncached_input_audio_usd_micros": 12345,
  "complete": true
}
```

The known estimate is the sum of priceable observed components. The headline uncached
audio-input value is `null` unless bounded-recent producer coverage passes, the event page
is not truncated, and every audio component can be priced; `incomplete_event_count`
reports events whose audio component could not be priced. Unknown cost is never returned
as zero.

Every page includes a freshly read, page-independent population aggregate:

```json
{
  "account_metrics": {
    "retained_active_accounts": 42,
    "new_retained_active_accounts_mtd": 3,
    "period": "2026-08",
    "as_of": "2026-08-13T18:30:00.000Z"
  }
}
```

`retained_active_accounts` counts identities whose current status is active; “active” does
not mean recent recording, login, or payment activity. `new_retained_active_accounts_mtd`
counts only those active identities created during `period`. Beginning account deletion
removes an identity from both counts immediately, before its encrypted row is physically
purged, so the latter is not a durable signup/acquisition cohort. Counts are recomputed for
each page and can change between cursor requests; `as_of` is the local read time, and the
browser uses the final fetched page's aggregate. These aggregates never expose stable
enclave user IDs or account-level creation timestamps.

The owner dashboard may derive revenue and counterfactual cost cards from all completed
pages. It does not receive content, silence boundaries, VAD results, or timestamps through
these routes. Silence-removal percentages shown by the dashboard are planning scenarios
over complete rate-card-modeled uncached audio-input cost, not measured silence or realized
savings.

## Account-deletion status

`DELETE /api/account` begins or retries account deletion. It returns `202` until
physical deletion finishes and `200` only once it is complete. Each response has
the same opaque `operation_id` for that account deletion:

```json
{
  "deleted": false,
  "operation_id": "del_opaque",
  "status": "pending",
  "reason": "soft_delete_retention",
  "retry_after_seconds": 3600,
  "hard_delete_time": "2026-08-14T00:00:00.000Z"
}
```

`GET /api/account/deletion` returns `200` with the same shape for all states.
States are `pending`, `failed_retryable`, and `physical_complete`; `deleted` is
true only in `physical_complete`. The latter has no retry delay or provider
deadline. `Retry-After` is supplied when a retry delay is known.

The status surface uses the caller's ordinary account authentication and does not
introduce a separate polling credential. Deleting or deleted credentials are accepted
only for these deletion routes. PostgreSQL and provider retention/transient cleanup
failures remain pending or retryable for the bounded server-side reconciler; the API
never reports physical completion while structured rows or owned media generations remain.

## Processing and privacy semantics

- The enclave encrypts raw objects with a per-user KMS-wrapped DEK and binds
  each ciphertext to the authenticated user and exact object key with
  AES-256-GCM additional authenticated data.
- Gemini 3.5 Flash receives a bounded decrypted asset from inside the enclave
  for transcription/diarization or screenshot understanding. This is an
  explicit Vertex processing boundary, not enclave-only inference.
- Speaker names are opaque-person claims, never identity keys. Explicit audio
  self-identification binds its own turn; repeated exact active-speaker frames
  may bind only when exactly one non-overlapping system-audio turn spans them.
  Roster/context names and the bounded spelling vocabulary sent to Gemini are
  never proof of identity. Two people with the same normalized display name
  remain distinct. One-to-three-second samples are match-only; overlap, music,
  echo, silence, clipping, and low-purity samples quarantine. At least three
  seconds of clean speech is required for enrollment, and profiles use a
  versioned medoid/trimmed centroid with outlier rejection. The offline
  voice-evaluation path can use WeSpeaker embeddings to measure later-turn
  matching; serving does not currently execute that path. Gemini never receives
  voiceprints or acts as a biometric identifier. Gemini request-local speaker
  IDs may group turns only inside their source work unit; unmatched IDs are
  displayed as `Unidentified voice`, not persisted as apparent people.
- Profile reconciliation retains append-only revisions and sample-assignment
  history. A merge proposal is accepted only across the same embedding space,
  scorer, acoustic domain, and nonconflicting identity; a split is anonymous
  unless identity-aware correction has resolved it. Applied proposals replace
  the current derived labels without mutating source turns and are reversible
  only while doing so cannot orphan later samples. Superseded/split profiles
  are excluded from matching and People coverage. Similarity-driven proposal
  generation remains disabled until its versioned real-corpus gates pass.
- Facts may be learned from every confidently attributed turn, not only an
  introduction. Facts retain source event/turn, observed time, literal evidence,
  confidence, derivation version, and temporal supersession history.
- By default, raw encrypted media is retained for 30 days to support processing retries
  and voice-profile reconciliation, then deleted automatically. Once every ADR-0036
  activation gate is satisfied, an account may affirmatively retain original source audio
  until deletion in the separate encrypted recordings bucket; screenshots remain on the
  30-day policy. Account export
  includes profile proposals, revisions, and sample-assignment lineage. Account
  deletion removes raw objects, derived records, profiles, lineage, credentials,
  and all account-owned PostgreSQL rows. For every exact GCS object name, deletion lists,
  deletes, and verifies the absence of all live and noncurrent generations.
- Server logs may contain operational IDs, counts, states, and error classes,
  but never media, transcripts, URLs, names, facts, tokens, or key material.
