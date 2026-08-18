# `src/archive_v3_extent_vfs/`

Inactive ADR-0022 SQLite Extent Virtual File System (VFS) and paging cache for the
Phase 3 shadow path. One installed instance serves exactly one main database; every
other file class (journals, WAL, temp, mmap, shm) fails closed so plaintext never
touches the host filesystem, and `xSync` settles commits at the witness-free
`ShadowSettled` ledger terminal only.

| File | Responsibility |
|---|---|
| `archive_v3_extent_vfs.rs` | Custom `sqlite3_vfs`: single-main-database open policy, authenticated root-based page reads with zero-fill beyond the settled root, staged multi-page writes with exact rollback, the durable shadow commit `xSync` flow (heal → begin → stage → candidate → `ShadowSettled`), install-time ledger reconciliation, and panic-isolated, bounded, runtime-flavor-safe execution lanes. |
| `cache.rs` | Bounded per-user 128 MiB zeroizing plaintext 4096-byte LRU page cache with exact 256-bit per-extent dirty masks (snapshot/exact-clean APIs), self-eviction under a 256 MiB process-global ceiling, and truncation purge that re-marks the trimmed boundary page dirty. |
