# Reviewer WAL child

`wal.rs` is an inactive, closed ADR-0022 domain that can only insert or exactly
adopt the complete fixed synthetic reviewer archive after the reviewer account
has already been authenticated. It owns no authentication, Store/save, route,
launcher, task, or acknowledgement authority.
