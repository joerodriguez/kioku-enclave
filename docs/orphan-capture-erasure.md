# Scoped orphan-capture erasure

Status: backend implementation independently reviewed and locally verified. The synthetic PostgreSQL
two-session/three-stream path passes signed inspection, preparation, provider
acknowledgement, atomic finalization, complete-fenced Active, candidate rotation and
post-new-Active fence release, including late-failure rollback. The full local gate
passed 420 tests with zero failures, one existing ignored live-auth probe, and
all-target Clippy. The provider/operator delivery and signed release remain separate
unfinished stages. This verification does not install production schema or erase owner data.

## Problem and authority

An ended capture can contain a genuine missing sequence prefix after its native
outbox is no longer available. Waiting for model quota cannot recover those
coordinates. Neither sealing it nor inventing deletion-sequence evidence is valid.
The owner may instead explicitly authorize erasing the entire capture and its
associated orphan data, while preserving every existing memory and unrelated
capture. Such authorization is separate from permission to inspect diagnostic
counts.

The current episode DELETE route cannot perform this operation: an orphan capture
need not have an episode, and episode deletion intentionally retains session/stream
formation authority. Creating a synthetic episode to pass through that API would
misrepresent provenance. Directly cascading a session would lose both external
media inventory and the existing event-replay barrier.

## Deliberately bounded operation

The proposed operation accepts a small, explicit, account-qualified list of old
ended sessions. It is not an age-based sweep, account deletion, sequence repair,
general SQL runner, or change to activation gates. It refuses:

- any owned projection or intersection with an explicitly protected memory;
- a canonical/reference family, audio segment, speaker observation, media work
  unit, or other dependent record shared with a non-target capture or projection;
- ambiguous, missing, changed, or oversized scope;
- active upload intents, provider effects, summary/formation/finalization or
  reconciliation ownership, including residual ownership and ambiguous attempts;
- a changed signed activation generation, serving candidate, or schema contract.

The first bounded route also refuses any inferred person/profile lineage and any
intersection with prior episode-deletion receipts or deleted-sequence history.
It does not discard older replay barriers or rewrite previous deletion authority.

All scope evidence is metadata or a content-free commitment. No raw export,
transcript, OCR, summary, provider response, or media bytes leave their documented
boundary. Private identifiers needed to execute an exact erasure must not appear
in logs, PRs, public release assets, or monitoring messages.

## Compatibility and replay

The already signed activation catalog and event chain are immutable. In particular,
adding any trigger to a capture-formation table changes the frozen catalog even if
the trigger has a new name. No erasure implementation may hide such a change from
the verifier or broaden the existing reserved catalog.

A separately verified additive erasure contract must own durable session, stream,
event and asset tombstones independent of the deleted session's foreign-key
cascade. These are deletion identities, never accepted-sequence or seal evidence.
Database guards prevent erased identities and references from being accepted again.
Separately cataloged transcript/screenshot guards preserve that barrier even
after the original event FK namespace has disappeared.
The new serving image requires the erasure contract at startup/readiness and
capture admission, even for accounts without tombstones. Losing the entire
namespace must never be mistaken for a valid pre-install serving state. The
optional probe is solely the migrator's pre-install compatibility path.
Activation and erasure presence checks read the current-schema PostgreSQL catalogs
directly. A reused name-resolution query can report stale absence immediately after
waking from the release lock while another connection commits installation. The
catalog probe must observe that commit before selecting a legacy-safe path; a
wrong-kind relation remains corruption, not schema absence.
Normal capture admission must also check session identity before provider PUT, and
repeat the check atomically when reserving the upload.

The current serving predecessor cannot perform that session-aware reservation.
A temporary, account-qualified upload-admission fence is therefore required while
the exact cleanup and subsequent compatible serving rollout occur. The same guard
must fence recording-delivery credits and reference-batch reservation transactions
before they leave associated accounting state. Its database
lock must serialize against upload reservation without an account-row lock-upgrade
deadlock. It must not change account lifecycle/billing status or erase unrelated
data. Remove it only after independently verified homogeneous serving deployment
supports the new session-aware admission contract, the final new-image Active
generation is committed, and its protected-control canaries pass. Until removal, report capture
as paused; public process readiness alone is not proof that capture is available.

## Proposed transaction and provider ordering

Acquire the exclusive activation release lock, account lifecycle lock,
account reconciliation lock, retention lock, then the compatible account-row lock.
Every acquisition refuses contention rather than waiting for a blocked settler.
Revalidate the exact signed request, zero provider
authority, scope closure, and protected/unrelated commitments under those locks.

The proposed prepare transaction transfers the exact owned object metadata and
source coordinates into a durable erasure journal **before** deleting their original
rows. It also installs the replay barriers and temporary upload fence, removes only
the verified orphan projections and wholly contained work, then deletes the exact
session parents. Their normal cascades remove streams, events, formation receipts,
pages and seal history. An exception rolls back the entire transaction.

This differs intentionally from episode deletion's provider-first purge: the owner
has requested removal of these orphan captures, so structured content may become
unavailable immediately. The exact external-media deletion authority is transferred,
not discarded. A crash can leave a truthful pending erasure with its full provider
inventory; it cannot leave an untracked object or a false completed receipt. No
provider operation runs inside a PostgreSQL transaction, and no new GCS/KMS authority
is granted to the database migrator.

A separately reviewed operator deletes and independently verifies every current,
noncurrent, and provider-retained generation for each exact journaled object name,
using the existing authorized deployment identity. No bucket/prefix sweep or object
body read is permitted. An ambiguous result is reconciled by exact readback.
The PostgreSQL inventory holds one canonical object name and its original
source-authoritative generation, not a claim that it enumerates all provider
versions. A separate signed target-name root covers **both** `raw` and `recordings`
names for every canonical asset, including the alternate policy-selected location.
Each canonical event must have exactly one coherent media object and recording
authority; a missing row is never interpreted as an empty provider inventory.
Before any provider deletion, the operator privately journals exact-name
normal and soft-deleted version listings. Recovery relists those same exact names
and reconciles saved generations; completion requires empty listings of both kinds.
Provider retention and hard-purge capability must be established before prepare;
unsupported retention is a refusal, not an indefinite owner capture pause.
Before prepare and again before provider acknowledgement, metadata-only account
listings must classify every normal and soft-deleted name against the signed
whole-account current-canonical-asset allowlist (both locations). Unknown objects
are refused, never deleted. This catches an abandoned canonical PUT whose event
later committed as a reference after the upload intent was lost: that reference's
synthetic asset identifier cannot recover the original failed-upload asset.
Finalization verifies the bound provider receipt and unchanged journal, confirms
structured absence and the protected invariant, then records completion. Survivor
preservation is proved atomically during preparation, not frozen across provider cleanup.
It scrubs the now-unneeded object inventory and operational source coordinates,
retaining only minimal replay identities, receipt signatures/hashes and counts.
The inventory scrub and completion transition are one database transaction;
deferred database guards refuse either a completed row with residual inventory
or an incomplete row whose inventory has been discarded.
Activation must remain refused while any erasure is pending. A provider-verified
complete erasure with its temporary capture fence still held is not pending:
owner-prelaunch Active must allow that state or the release becomes circular.
The public/multi-user completion gate still requires all temporary fences released.

## Signed delivery and verification

The fixed migrator confirmation is `orphan-capture-erasure-v1`; install-only uses
the separately signed `install_schema` action. Its account/operation fields are
fixed neutral `schema`/`install` sentinels, not source selectors. It takes only the
nonwaiting exclusive release lock and binds the exact current signed Draining
generation, candidate and finalized base/activation chain before and after DDL.
Actual creation returns `installed`; a fresh verified replay returns
`already_installed`, a catalog-only result that never claims existing journals are
empty. Neither path creates a capture fence or erases data. Prepare requires the
already installed contract; serving itself never installs the prerequisite.

The new aggregate audit is v4, not a relabeling of historical v3 evidence. It
reads erasure catalog/state metadata in the same read-only repeatable-read
transaction as every unchanged prior gate. Pending or provider-verified operations,
residual inventory and coherence violations block both transitions. Schema absence
does not prevent first Draining (which authorizes install), but cannot authorize
Active or claim capture admission. Complete-fenced permits owner-prelaunch Active;
`capture_admission_unfenced` remains false until the signed new-runtime release.
Active independently requires the installed exact catalog and all erasures complete;
the migrator does not rely on an operator-side audit assertion alone.

Prepare, provider acknowledgement/finalization, and fence release require separate
strict, domain-separated, short-lived signed requests with exact operation/scope
commitments. Historical activation authorization is not erasure authorization.
Store request commitments and signatures, not redundant raw signed private JSON,
in the permanent database receipt. Abort rather than wait on a pre-existing upload
or provider claim under the exclusive activation lock: its settlement may need
the shared counterpart of the lock held by prepare.
Recovery reuses the exact saved operation and receipts; it never silently selects
new sessions or repeats a completed provider mutation.
New actions check database-time signature freshness both before work and immediately
before commit, with at least 60 seconds remaining. Deferred constraints finish before
the last check. Every transaction sets server-enforced 45-second transaction,
15-second statement/idle and 250-millisecond lock deadlines, forces synchronous
commit and requires fsync. These bounds protect against a stalled client or query;
they are not a hard deadline on WAL durability or critical server work. A positively
acknowledged commit uses synchronous local WAL durability. A missing acknowledgement
is ambiguous and requires exact replay/readback, never an assumed rollback or a new
request. Only a matching already-committed request may replay after expiry.

Required real PostgreSQL contracts cover zero and mixed scope, cross-account
isolation, protected records, upload races and lock ordering, old/new admission,
claim/late settlement exclusion, rollback after each prepare boundary, exact
survivor preservation, transferred object inventory, failure/restart/replay,
pending-erasure activation refusal, and compatibility with the unmodified v27
catalog and serving predecessor. Provider tests must cover exact names/generations,
retention, partial failures and lost-success recovery without reading object bytes.

Do not install the temporary capture fence before both cleanup and its eventual
removal path have passed full verification, independent review, normal PR merge,
signed release, and operator preparation. Completion requires actual provider and
database readback, restored capture admission, existing protected-text canaries,
normal activation evidence, and retirement of task-owned intermediate resources.
