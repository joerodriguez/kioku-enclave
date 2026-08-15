# Webhook WAL child

`wal.rs` is an inactive, closed ADR-0022 domain that can only settle an exact
already-durable webhook outbox row after a definitive HTTP 2xx. It owns no
signing, transport, retry, subscription, Store, launcher, task, or
acknowledgement authority.
