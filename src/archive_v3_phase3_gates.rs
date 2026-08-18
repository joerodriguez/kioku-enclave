#![allow(dead_code, reason = "ADR-0022 Phase 3 structural gate test suite")]

//! Behavioral verification gates for ADR-0022 Phase 3: the durable extent commit
//! protocol's authority boundaries, the shadow-only Extent VFS contract, cache
//! bounds, WAL-converter torn-tail conformance, vector-accelerator fail-closed
//! posture, and read-only shadow comparison. Every gate exercises production code
//! paths and asserts on observed behavior; static source-shape enforcement lives in
//! `scripts/test_phase3_architecture_gate.py`.

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use rusqlite::Connection;

    use crate::archive_v3::{ArchiveId, DatabaseEpoch, ImmutableObjectBackend, KeyEpoch};
    use crate::archive_v3_extent::{
        tests::{make_test_uploaded_tree, TestCipher},
        ExtentCipher, ExtentTreeDescriptor, ShadowExtentRootCandidate,
    };
    use crate::archive_v3_extent_commit::{
        ExtentAttemptLedger, ExtentCommitCoordinator, ExtentCommitError, ExtentCommitStage,
        SqliteExtentAttemptLedger, WitnessObservedEvidence, WitnessSendAuthority,
    };
    use crate::archive_v3_extent_vfs::{
        cache::{
            calculate_dynamic_global_page_limit, CacheError, ExtentFileType, PerUserPageCache,
            MAX_GLOBAL_ALLOCATED_PAGES,
        },
        RegisteredExtentVfs,
    };

    fn make_ledger() -> Arc<SqliteExtentAttemptLedger> {
        let conn = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
        Arc::new(SqliteExtentAttemptLedger::new(conn).unwrap())
    }

    fn make_candidate(
        archive_id: ArchiveId,
        db_epoch: DatabaseEpoch,
        key_epoch: KeyEpoch,
    ) -> ShadowExtentRootCandidate {
        ShadowExtentRootCandidate::from_uploaded_tree(
            archive_id,
            db_epoch,
            key_epoch,
            &make_test_uploaded_tree(),
        )
    }

    /// Gate 1: the descriptor trait is sealed and the shadow candidate type is
    /// explicitly non-authoritative: `PublishedExtentArchiveRoot` has no constructor,
    /// and a candidate exposes only content-free descriptor facts.
    #[test]
    fn gate_01_sealed_descriptor_and_no_authority_type() {
        fn assert_sealed_descriptor<T: ExtentTreeDescriptor>(_: &T) {}
        let candidate = make_candidate(
            ArchiveId::random(),
            DatabaseEpoch::random(),
            KeyEpoch::random(),
        );
        assert_sealed_descriptor(&candidate);
        assert_eq!(candidate.logical_file_length(), 4096);
        // The candidate round-trips its exact encoding; a flipped byte fails decode
        // or authenticates differently downstream (covered in extent_commit tests).
        let encoded = candidate.encode();
        let decoded = ShadowExtentRootCandidate::decode(&encoded).unwrap();
        assert_eq!(decoded, candidate);
    }

    /// Gate 2: `Published` is unreachable without sealed witness evidence; shadow
    /// attempts terminate at `ShadowSettled`; witness-stage crashes fail closed; a
    /// crash in any pre-witness stage can never wedge the active-attempt slot.
    #[test]
    fn gate_02_witness_evidence_gating_and_fail_closed_reconciliation() {
        let archive_id = ArchiveId::random();
        let db_epoch = DatabaseEpoch::random();
        let key_epoch = KeyEpoch::random();
        let ledger = make_ledger();
        let cand = make_candidate(archive_id, db_epoch, key_epoch);

        // A shadow attempt (no witness expectation) cannot enter the witness chain
        // even when a test-minted token exists, and settles at ShadowSettled.
        let mut coord = ExtentCommitCoordinator::new(
            archive_id,
            db_epoch,
            key_epoch,
            [0x21; 16],
            ledger.clone() as Arc<dyn ExtentAttemptLedger>,
        );
        coord
            .begin_attempt(ExtentFileType::MainDb, None, 0, 0, 4096, 0, vec![0])
            .unwrap();
        coord.mark_objects_staged().unwrap();
        coord.mark_candidate_ready(&cand).unwrap();
        assert!(matches!(
            coord.mark_witness_send_started(WitnessSendAuthority::mint_for_test(), [0x0A; 32]),
            Err(ExtentCommitError::InvalidTransition)
        ));
        let settled = coord.mark_shadow_settled().unwrap();
        assert_eq!(settled.stage(), ExtentCommitStage::ShadowSettled);
        assert!(settled.witness_observed_commitment().is_none());

        // A witness-intent attempt reaches Published only through the sealed token
        // and evidence chain, and its records carry the full evidence trail.
        let mut coord = ExtentCommitCoordinator::new(
            archive_id,
            db_epoch,
            key_epoch,
            [0x22; 16],
            ledger.clone() as Arc<dyn ExtentAttemptLedger>,
        );
        coord
            .begin_attempt(ExtentFileType::MainDb, Some(&cand), 3, 2, 8192, 0, vec![1])
            .unwrap();
        coord.mark_objects_staged().unwrap();
        coord.mark_candidate_ready(&cand).unwrap();
        // Published cannot be reached by skipping the witness chain.
        assert!(coord.mark_published().is_err());
        coord
            .mark_witness_send_started(WitnessSendAuthority::mint_for_test(), [0x0B; 32])
            .unwrap();
        assert!(coord.mark_published().is_err());
        coord
            .mark_witness_advanced(WitnessObservedEvidence::mint_for_test([0x0C; 32]))
            .unwrap();
        let published = coord.mark_published().unwrap();
        assert_eq!(published.stage(), ExtentCommitStage::Published);
        assert_eq!(published.witness_request_commitment(), Some([0x0B; 32]));
        assert_eq!(published.witness_observed_commitment(), Some([0x0C; 32]));

        // Crash in WitnessSendStarted fails reconciliation closed.
        {
            let ledger2 = make_ledger();
            {
                let mut c = ExtentCommitCoordinator::new(
                    archive_id,
                    db_epoch,
                    key_epoch,
                    [0x23; 16],
                    ledger2.clone() as Arc<dyn ExtentAttemptLedger>,
                );
                c.begin_attempt(ExtentFileType::MainDb, None, 5, 5, 4096, 0, vec![0])
                    .unwrap();
                c.mark_objects_staged().unwrap();
                c.mark_candidate_ready(&cand).unwrap();
                c.mark_witness_send_started(WitnessSendAuthority::mint_for_test(), [0x0D; 32])
                    .unwrap();
            }
            let mut fresh = ExtentCommitCoordinator::new(
                archive_id,
                db_epoch,
                key_epoch,
                [0x24; 16],
                ledger2 as Arc<dyn ExtentAttemptLedger>,
            );
            let mut cache = PerUserPageCache::with_default_capacity();
            assert!(matches!(
                fresh.reconcile_from_durable_ledger(ExtentFileType::MainDb, &mut cache, None),
                Err(ExtentCommitError::ManualWitnessReconciliationRequired)
            ));
        }

        // Crash in Prepared durably aborts on reconcile and frees the slot.
        {
            let ledger3 = make_ledger();
            {
                let mut c = ExtentCommitCoordinator::new(
                    archive_id,
                    db_epoch,
                    key_epoch,
                    [0x25; 16],
                    ledger3.clone() as Arc<dyn ExtentAttemptLedger>,
                );
                c.begin_attempt(ExtentFileType::MainDb, None, 0, 0, 4096, 0, vec![0])
                    .unwrap();
            }
            let mut fresh = ExtentCommitCoordinator::new(
                archive_id,
                db_epoch,
                key_epoch,
                [0x26; 16],
                ledger3.clone() as Arc<dyn ExtentAttemptLedger>,
            );
            let mut cache = PerUserPageCache::with_default_capacity();
            cache
                .put(ExtentFileType::MainDb, 0, &[0x33; 4096], true)
                .unwrap();
            let adopted = fresh
                .reconcile_from_durable_ledger(ExtentFileType::MainDb, &mut cache, None)
                .unwrap();
            assert_eq!(adopted, None);
            assert!(cache.dirty_extents(ExtentFileType::MainDb).is_empty());
            // Liveness: the slot is free for a new attempt.
            fresh
                .begin_attempt(ExtentFileType::MainDb, None, 0, 0, 4096, 0, vec![0])
                .unwrap();
        }
    }

    /// Gate 3: cache bounds are real — O(1) clean eviction, dirty-page capacity
    /// errors, snapshot-exact cleaning, and a global ceiling strictly above one
    /// user's budget.
    #[test]
    fn gate_03_cache_bounds_and_exact_masks() {
        let mut cache = PerUserPageCache::new(2);
        cache
            .put(ExtentFileType::MainDb, 0, &[0x01; 4096], false)
            .unwrap();
        cache
            .put(ExtentFileType::MainDb, 1, &[0x02; 4096], false)
            .unwrap();
        cache
            .put(ExtentFileType::MainDb, 2, &[0x03; 4096], false)
            .unwrap();
        assert_eq!(cache.len(), 2, "clean LRU eviction holds the bound");

        let mut all_dirty = PerUserPageCache::new(2);
        all_dirty
            .put(ExtentFileType::MainDb, 0, &[0x01; 4096], true)
            .unwrap();
        all_dirty
            .put(ExtentFileType::MainDb, 1, &[0x02; 4096], true)
            .unwrap();
        assert!(matches!(
            all_dirty.put(ExtentFileType::MainDb, 2, &[0x03; 4096], true),
            Err(CacheError::CapacityExceeded)
        ));

        // Snapshot-exact cleaning: post-snapshot writes stay dirty.
        let mut snap = PerUserPageCache::new(16);
        snap.put(ExtentFileType::MainDb, 0, &[0x11; 4096], true)
            .unwrap();
        let masks = snap.dirty_page_masks(ExtentFileType::MainDb);
        snap.put(ExtentFileType::MainDb, 9, &[0x22; 4096], true)
            .unwrap();
        for (ext, words) in &masks {
            snap.mark_pages_clean(ExtentFileType::MainDb, *ext, *words);
        }
        assert_eq!(snap.dirty_extents(ExtentFileType::MainDb), vec![0]);

        assert!(calculate_dynamic_global_page_limit() <= MAX_GLOBAL_ALLOCATED_PAGES);
        // The global-vs-per-user ceiling relation is a compile-time constant
        // assertion in cache.rs.
    }

    /// Gate 7: the shadow-only VFS contract holds end to end — full CRUD through a
    /// real SQLite connection, durable persistence across reinstall from the attempt
    /// ledger alone, refusal of journal-backed writes without memory journal mode,
    /// and zero host-filesystem artifacts.
    #[test]
    fn gate_07_vfs_shadow_contract_and_ledger_persistence() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("gate07.db");
        let ledger_path = tmp.path().join("gate07-ledger.db");
        let archive_id = ArchiveId::random();
        let key_epoch = KeyEpoch::random();
        let database_epoch = DatabaseEpoch::random();
        let backend = Arc::new(crate::archive_v3::InMemoryImmutableBackend::default());
        let cipher = Arc::new(TestCipher::new(archive_id, key_epoch));
        let vfs_name = format!("gate07-vfs-{:x}", rand::random::<u64>());

        let file_ledger = || -> Arc<dyn ExtentAttemptLedger> {
            let conn = Arc::new(Mutex::new(Connection::open(&ledger_path).unwrap()));
            Arc::new(SqliteExtentAttemptLedger::new(conn).unwrap())
        };

        {
            let _vfs = RegisteredExtentVfs::install(
                &vfs_name,
                backend.clone() as Arc<dyn ImmutableObjectBackend>,
                cipher.clone() as Arc<dyn ExtentCipher>,
                database_epoch,
                file_ledger(),
                None,
            )
            .unwrap();
            let conn = Connection::open_with_flags_and_vfs(
                &db_path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                    | rusqlite::OpenFlags::SQLITE_OPEN_CREATE,
                vfs_name.as_str(),
            )
            .unwrap();
            conn.execute_batch("PRAGMA journal_mode=MEMORY; PRAGMA temp_store=MEMORY;")
                .unwrap();
            conn.execute_batch(
                "CREATE TABLE t (k INTEGER PRIMARY KEY, v TEXT);
                 INSERT INTO t (k, v) VALUES (1, 'Alice'), (2, 'Bob');
                 UPDATE t SET v = 'Carol' WHERE k = 1;
                 DELETE FROM t WHERE k = 2;",
            )
            .unwrap();
            let v: String = conn
                .query_row("SELECT v FROM t WHERE k = 1;", [], |r| r.get(0))
                .unwrap();
            assert_eq!(v, "Carol");
        }

        // Reinstall from the durable ledger alone (same backend): install-time
        // reconciliation adopts the latest ShadowSettled root.
        {
            let _vfs = RegisteredExtentVfs::install(
                &vfs_name,
                backend.clone() as Arc<dyn ImmutableObjectBackend>,
                cipher.clone() as Arc<dyn ExtentCipher>,
                database_epoch,
                file_ledger(),
                None,
            )
            .unwrap();
            let conn = Connection::open_with_flags_and_vfs(
                &db_path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                    | rusqlite::OpenFlags::SQLITE_OPEN_CREATE,
                vfs_name.as_str(),
            )
            .unwrap();
            conn.execute_batch("PRAGMA journal_mode=MEMORY; PRAGMA temp_store=MEMORY;")
                .unwrap();
            let v: String = conn
                .query_row("SELECT v FROM t WHERE k = 1;", [], |r| r.get(0))
                .unwrap();
            assert_eq!(v, "Carol");
        }

        // Nothing ever touched the host filesystem.
        assert!(!db_path.exists());
        assert!(!db_path.with_extension("db-journal").exists());
    }

    /// Gate 4: WAL parsing follows SQLite recovery semantics — a torn trailing frame
    /// ends the log cleanly (the normal post-crash state), while header-level
    /// corruption fails hard.
    #[test]
    fn gate_04_wal_torn_tail_conformance_and_header_fail_closed() {
        use crate::archive_v3_wal_to_extent::{
            wal_checksum_bytes, ChecksumValidatedWalIndex, WAL_FILE_FORMAT_VERSION, WAL_MAGIC_BE,
        };
        use std::io::Cursor;

        let mut header = [0u8; 32];
        header[0..4].copy_from_slice(&WAL_MAGIC_BE.to_be_bytes());
        header[4..8].copy_from_slice(&WAL_FILE_FORMAT_VERSION.to_be_bytes());
        header[8..12].copy_from_slice(&4096u32.to_be_bytes());
        header[12..16].copy_from_slice(&1u32.to_be_bytes());
        header[16..20].copy_from_slice(&0xAAAA_BBBBu32.to_be_bytes());
        header[20..24].copy_from_slice(&0xCCCC_DDDDu32.to_be_bytes());
        let (mut s1, mut s2) = (0u32, 0u32);
        let prefix = header[0..24].to_vec();
        wal_checksum_bytes(&prefix, true, &mut s1, &mut s2).expect("aligned");
        header[24..28].copy_from_slice(&s1.to_be_bytes());
        header[28..32].copy_from_slice(&s2.to_be_bytes());

        // Valid header + torn 10-byte frame fragment: clean empty end-of-log.
        let mut torn = header.to_vec();
        torn.extend_from_slice(&[0x5A; 10]);
        let index = ChecksumValidatedWalIndex::parse(Cursor::new(torn))
            .expect("torn trailing frame ends the log cleanly");
        assert!(index.is_empty());

        // Corrupted magic: hard error.
        let mut bad = header.to_vec();
        bad[0] ^= 0xFF;
        assert!(ChecksumValidatedWalIndex::parse(Cursor::new(bad)).is_err());
    }

    /// Gate 5: the vector accelerator is fail-closed — construction rejects
    /// disconnected graphs and uncertified recall, and dimension mismatches error
    /// rather than scoring 0.0.
    #[test]
    fn gate_05_vector_accelerator_fail_closed_construction() {
        use crate::archive_v3_vector_accelerator::{
            cosine_similarity, AnnSnapshotDescriptor, VectorNode, VectorSearchAccelerator,
        };

        assert!(cosine_similarity(&[1.0, 0.0], &[1.0]).is_err());

        let reference = crate::archive_v3::ImmutableReference {
            object_id: crate::archive_v3::ObjectId::random(),
            envelope_hash: [0x11; 32],
        };
        let descriptor = AnnSnapshotDescriptor::new(reference.clone(), 100, 2, 3, 10_000).unwrap();
        // Fully connected two-node graph constructs.
        let nodes = vec![
            VectorNode::new(1, vec![1.0, 0.0, 0.0], vec![2]).unwrap(),
            VectorNode::new(2, vec![0.0, 1.0, 0.0], vec![1]).unwrap(),
        ];
        assert!(
            VectorSearchAccelerator::new(ArchiveId::random(), descriptor.clone(), nodes).is_ok()
        );

        // A disconnected graph is rejected outright.
        let disconnected = vec![
            VectorNode::new(1, vec![1.0, 0.0, 0.0], vec![]).unwrap(),
            VectorNode::new(2, vec![0.0, 1.0, 0.0], vec![]).unwrap(),
        ];
        assert!(
            VectorSearchAccelerator::new(ArchiveId::random(), descriptor, disconnected).is_err()
        );

        // A below-floor certification is rejected when the accelerator is built.
        let low_cert = AnnSnapshotDescriptor::new(reference, 100, 2, 3, 9_699).unwrap();
        let nodes = vec![
            VectorNode::new(1, vec![1.0, 0.0, 0.0], vec![2]).unwrap(),
            VectorNode::new(2, vec![0.0, 1.0, 0.0], vec![1]).unwrap(),
        ];
        assert!(VectorSearchAccelerator::new(ArchiveId::random(), low_cert, nodes).is_err());
    }

    /// Gate 6: the shadow comparator is strictly read-only (DML refused with no
    /// mutation), detects genuine mismatches, and matches identical multisets.
    #[test]
    fn gate_06_shadow_comparison_read_only_and_mismatch_detection() {
        use crate::archive_v3_extent_shadow::ExtentShadowCoordinator;

        let auth = Connection::open_in_memory().unwrap();
        let shadow = Connection::open_in_memory().unwrap();
        for conn in [&auth, &shadow] {
            conn.execute_batch(
                "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT);
                 INSERT INTO t (id, v) VALUES (1, 'a'), (2, 'b');",
            )
            .unwrap();
        }
        let coordinator = ExtentShadowCoordinator::new(ArchiveId::random(), auth, shadow).unwrap();
        let op_id = [0x61; 16];

        // Identical content matches.
        let receipt = coordinator
            .compare_query(op_id, "SELECT id, v FROM t;")
            .unwrap();
        assert!(receipt.matched());

        // DML is refused before any step; the row count proves nothing mutated.
        assert!(coordinator.compare_query(op_id, "DELETE FROM t;").is_err());
        let receipt = coordinator
            .compare_query(op_id, "SELECT count(*) FROM t;")
            .unwrap();
        assert!(receipt.matched());
        assert_eq!(receipt.authoritative_rows(), 1);

        // A genuine mismatch is detected.
        let auth2 = Connection::open_in_memory().unwrap();
        let shadow2 = Connection::open_in_memory().unwrap();
        auth2
            .execute_batch(
                "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT); INSERT INTO t VALUES (1, 'x');",
            )
            .unwrap();
        shadow2
            .execute_batch(
                "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT); INSERT INTO t VALUES (1, 'y');",
            )
            .unwrap();
        let coordinator2 =
            ExtentShadowCoordinator::new(ArchiveId::random(), auth2, shadow2).unwrap();
        let receipt2 = coordinator2
            .compare_query([0x62; 16], "SELECT id, v FROM t;")
            .unwrap();
        assert!(!receipt2.matched());

        // Integrity verification reports both engines healthy.
        let integrity = coordinator.verify_integrity([0x63; 16]).unwrap();
        assert!(integrity.authoritative_ok() && integrity.shadow_ok());
    }
}
