# Webhook WAL child

`wal.rs` is the active ADR-0022 selected-archive webhook boundary. `claim.rs`
freezes one bounded endpoint, signing secret, content-scope decision, and
canonical CloudEvent body, then persists a random 90-second send claim before
provider I/O. `exact.rs` carries the complete due-row predecessor across that
I/O and exact-CASes or adopts typed cancel, defer, retry, sent, failed, and
ambiguous outcomes. Its distinct purge subtype authenticates and deletes one
exact terminal delivery plus its frozen endpoint, secret, body, and claim
subtree, leaving only fixed-size commitments in the permanent ledger. A live
claim blocks claimless cancellation and row/episode deletion; expired claims
become ambiguous without resend. Both children own
bounded permanent ledgers and cannot call Store, Control, DNS, HTTP, a runtime
launcher, or any provider.

The production owner keeps DNS/HTTP/signing and Control authority outside the
sealed children. It uses a short durable Control disclosure fence and typed
outcome receipt so either side can reconcile an asymmetric save. Legacy
archives retain their guarded snapshot path. The owner disables system proxies,
shares one singleton critical section between recovery and provider admission,
checks the per-account provider cap before claiming, and exposes only sanitized
delivery-status counts/latest outcomes.
