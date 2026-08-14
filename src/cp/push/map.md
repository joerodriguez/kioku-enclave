# Push WAL child

`wal.rs` is an inactive, closed ADR-0022 domain that can only settle an exact
already-durable push outbox row after a definitive APNs acceptance. It owns no
transport, retry, installation, Store, launcher, task, or acknowledgement authority.
