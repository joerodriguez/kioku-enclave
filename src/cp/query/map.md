# map.md — `src/cp/query/`

Private ADR-0022 logical-operation children. The selected screenshot-upload
family remains inactive behind the Genesis `410 Gone` tombstone. The episode
delete prepare/completion family is active only through the authenticated
selected route in the production parent.

The active browser snapshot reader's browser-v2 arm follows a live episode member through the
screen result's `capture-v2-browser:<event_id>` reference, exact-matches the
capture context, observation, persisted state envelope, and recomputed
cross-language commitment, and fails closed on malformed evidence. The legacy
arm remains strict and likewise requires a live episode association. Archive
unavailability/corruption is 503; only authoritative absence is 404.

| File | Role |
|---|---|
| [`wal.rs`](wal/map.md) | Inactive selected-screenshot upload codecs plus the active selected episode-delete family. Preparation authenticates the immediate episode/member/screen/outbox cascade, tombstones plaintext, reserves the permanent receipt, and persists compact ordered event/voice/legacy selectors. Cleanup expands one selector at a time under shared evidence limits. Voice selectors reserve their exact 16,384-row legal maximum before identity paging, then atomically exchange it for exact cleanup usage; first-time current progress rows are globally charged before identity mutation and released exactly, while overwrites are charge-neutral. Other selectors exact-reserve at expansion before mutation. The family authenticates its full capture/voice/allocator mutation closure, applies scoped fixed-stamp lineage backfill for authenticated imported voice samples, protects canonical ancestors and NULL-linked audio sharing, advances affected identity work through rotating authenticated 128-episode revision pages, and advances exact provider identities durably. Stale completed identity work is queued again; one current progress row per affected episode is overwritten rather than retaining append-only page history and is removed at local expansion. A dedicated immediate/30-second worker advances a durable four-episode fair cursor before work, bounds/coalesces non-biased route wakeups, and backs off failed accounts without blocking ready neighbors; the summarizer is only a redundant wakeup. Completion is recorded only after the gap-free selector sequence and authenticated aggregate provider-inventory commitment are complete. Retained rows contain commitments, counts, local source keys, exact encrypted-object identities, and no transcript, OCR, browser URL/title/tab, endpoint/secret/body, or voice content. |
