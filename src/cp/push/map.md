# Push WAL children — active outbox owner

`wal/claim.rs` durably records the exact complete pre-send row and checked send
attempt before APNs. `wal/settlement.rs` consumes that exact claim and complete
predecessor for typed accepted, definitive-retry, failed, ambiguous,
provider-free cancel, and uncharged-defer transitions. Both families use
bounded permanent replay ledgers, exact full-row reread/CAS/adoption (including
nullable due/response/error fields), and fixed-size commitments for malformed
or oversized rows. `wal.rs` also retains the older definitive-200-only family;
the active owner uses the claim and general-settlement children.

The live owner in `push.rs` routes both selected and legacy scans, persists the
leased archive claim and a short Control send fence before provider I/O, and
releases all database locks before APNs. The Control fence binds the exact
user/installation/token-generation/archive-claim/lease tuple and durably
records typed provider outcomes until the archive settlement is durable.
Deletion or token rotation either wins before send or conflicts only with that
in-flight destination. Defensive claim/CAS checks leave a live lease untouched;
only bounded-expired claims recover as possibly delivered, and recovery replays
an exact typed Control receipt before it may synthesize ambiguity. Asymmetric
Control or archive save failures reconcile the known result on restart without
resend. These checks are not a distributed provider fence: production push is
supported only by the clean, release-verified deployment commit and exact
Terraform-root source seal whose reviewed source defines the single
VM/container; release binds that seal before network access and rechecks it at
roll, invokes only the exact tracked deployment owner, and passes the seal for
another recomputation inside its production-infrastructure lock before GCP
authority or mutation. Horizontal or overlapping runtimes are forbidden.

Pre-lift selected archives may contain bare installation UUID rows, but those
rows are cancellation-only and never reach APNs. After activation, only new
finalizations enqueue the versioned `p1:<installation UUID>:<token generation>`
binding. The Control generation is globally monotone across deletion,
deduplication, eviction, and restart, while inactive registry churn is hard
bounded. Bare rows,
generation mismatches, malformed/exhausted rows, and deliveries at least 24
hours old cancel before provider I/O. Provider calls are process-wide serialized
and paced—equivalent to production-service-wide only under the enforced
singleton deployment—each account sweep is capped, Retry-After is bounded, device-token
429s remain local, genuine provider-wide failures open a process-local circuit, and metrics expose only content-free depth, age,
outcome, cancellation, ambiguity, circuit, and settlement facts.
