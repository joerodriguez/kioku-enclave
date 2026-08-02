# Kioku Cloud Capture API v2

This is the stable capture contract for the pure-Swift macOS and iOS clients.
Clients capture bounded audio or screenshots, attach authoritative device-time
and foreground/browser context, and upload them to the attested enclave. All
transcription, OCR, diarization, profile learning, voice matching, indexing,
and summarization run in the cloud.

The capture pipeline is a core product behavior. It is not controlled by a
Kioku feature flag. Apple recording, Screen Recording, and Automation
permissions still apply, and clients must present the platform recording
indicators and the product's cloud-processing disclosure.

## Authentication and transport

- Production requests use HTTPS terminated inside the attested enclave.
- Send `Authorization: Bearer <token>` using either a Kioku access token or an
  accepted Google ID token.
- Never put user IDs in a path, header, or manifest. The server derives the
  account from the verified token.
- All identifiers are 1–128 ASCII letters, digits, `-`, or `_`. UUIDv7 is the
  recommended client format.
- All times are RFC 3339/ISO 8601. Include the original IANA `timezone_id` and
  numeric UTC offset even when the timestamp is already expressed in UTC.

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
    "browser_state_key": "019fbab2-8413-7053-9117-eb249b72b162",
    "browser_snapshot": {
      "state_key": "019fbab2-8413-7053-9117-eb249b72b162",
      "browser_bundle_id": "com.google.Chrome",
      "browser_name": "Google Chrome",
      "permission_status": "granted",
      "active_window_index": 0,
      "active_tab_index": 1,
      "reported_tab_count": 2,
      "truncated": false,
      "content_hash": "64 hexadecimal characters over the canonical tab snapshot",
      "tabs": [
        {
          "window_index": 0,
          "tab_index": 1,
          "title": "Weekly planning",
          "url": "https://meet.google.com/abc-defg-hij?authuser=0",
          "is_active": true,
          "is_loading": false
        }
      ]
    },
    "visible_windows": [],
    "visible_windows_truncated": false
  }
}
```

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

Version 1 permits a reference only when the client compared against the last
canonical screen in that display stream, the before/after context was stable,
the context fingerprint was unchanged, the 8×8 grayscale average-hash Hamming
distance is at most 3, and the bounded downscaled pixel-change ratio is at most
0.01. Ambiguous or missing state must produce another canonical upload.

The context fingerprint is SHA-256 over compact UTF-8 JSON with recursively
lexicographically sorted keys for exactly these nullable fields:
`active_app`, `active_url`, `active_url_title`,
`browser_permission_status`, `capture_status`, `display_id`,
`primary_bundle_id`, `primary_window_id`, `visible_windows`,
`visible_windows_truncated`, and `window_title`. Ambient browser-tab inventory
is retained on the observation but excluded from this fingerprint so an
unchanged visible screen need not be re-uploaded merely because a background
tab changed.

The enclave recomputes the fingerprint, compares the literal visible context,
and requires the target to be an earlier canonical event for the same
authenticated account, device, install, session, stream, and display. It also
verifies the canonical asset and SHA-256. Missing/forward references, chains,
digest mismatches, and context transitions fail with HTTP 400. A valid
reference creates no media object and no Gemini job, but it advances contiguous
acknowledgement and remains in export and deletion coverage.

iOS imported screenshots remain intentional canonical assets; clients must not
apply perceptual suppression to them.

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
seconds. Do not retry malformed requests (HTTP 400) without correcting them.

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

States are `queued`, `processing`, `retry_wait`, `ready`, `failed`, or
`pruned`. `pruned` means the bounded raw-media retention window elapsed; the
derived searchable records and timestamped evidence remain. A well-formed event ID
that does not belong to the authenticated account returns HTTP `404`.

## People learned automatically

`GET /api/v2/people` returns up to 500 identified profiles:

```json
{
  "people": [{
    "id": 7,
    "display_name": "John Garcia",
    "voice_profile_count": 1,
    "fact_count": 2,
    "updated_at": "2026-07-31T18:04:12.000Z"
  }]
}
```

`GET /api/v2/people/{person_id}` returns the profile, its internal voice labels,
and evidence-backed durable facts. Evidence contains source `event_id`, turn or
screenshot identity, and the literal evidence used by the model. Clients should
present these facts as learned observations, not user-authored contact data.

## Processing and privacy semantics

- The enclave encrypts raw objects with a per-user KMS-wrapped DEK and binds
  each ciphertext to the authenticated user and exact object key with
  AES-256-GCM additional authenticated data.
- Gemini 3.5 Flash receives a bounded decrypted asset from inside the enclave
  for transcription/diarization or screenshot understanding. This is an
  explicit Vertex processing boundary, not enclave-only inference.
- Speaker names are accepted only from high-confidence complete-name evidence.
  Explicit audio self-identification binds its own turn. A screenshot name binds
  a system-audio turn only when the meeting UI visibly marks that exact label as
  the active speaker and exactly one non-overlapping turn spans the screenshot
  timestamp. Reconciliation works whether audio or screenshot processing finishes
  first. Independent WeSpeaker embeddings then match later turns; Gemini is never
  treated as a voice biometric identifier.
- Raw encrypted media is retained for 30 days to support processing retries and
  voice-profile reconciliation, then deleted automatically. Account deletion
  removes raw objects, derived records, profiles, credentials, and the encrypted
  user database.
- Server logs may contain operational IDs, counts, states, and error classes,
  but never media, transcripts, URLs, names, facts, tokens, or key material.
