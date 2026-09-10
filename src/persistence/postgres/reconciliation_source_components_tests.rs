//! Disposable PostgreSQL-only source-graph regressions. All fixtures roll back.
use super::*;

pub(crate) async fn test_source_closed_components(persistence: &PostgresPersistence) -> Result<()> {
    const ACCOUNT: &str = "source-closed-components-test";
    let authority = ActiveReconciliationAuthority {
        generation: 2,
        producer_contract_sha256: vec![0x42; 32],
        reconciliation_model: "synthetic-model".into(),
        vertex_location: "us-central1".into(),
    };
    let mut tx = persistence.pool().begin().await?;
    sqlx::raw_sql(
        "INSERT INTO accounts(id,email,primary_provider,primary_subject)
         VALUES('source-closed-components-test','components@example.com','google','components');
         INSERT INTO episodes(account_id,id,started_at,ended_at,type,title,summary)
         SELECT 'source-closed-components-test',id,clock_timestamp()-age,
                clock_timestamp()-age+interval '1 minute','note','Synthetic','Synthetic'
           FROM (VALUES(1,interval '60 days'),(2,interval '59 days'),(3,interval '57 days')) f(id,age);
         INSERT INTO screenshots(account_id,id,captured_at)
         SELECT account_id,id,started_at FROM episodes WHERE account_id='source-closed-components-test';
         INSERT INTO episode_members(account_id,episode_id,record_type,record_id)
         SELECT account_id,id,'screenshot',id FROM episodes WHERE account_id='source-closed-components-test';
         INSERT INTO capture_sessions(account_id,id,device_id,install_id,started_at,last_event_at,schema_version,created_at)
         SELECT 'source-closed-components-test','bridge','device','install',min(started_at),max(ended_at),2,min(started_at)
           FROM episodes WHERE account_id='source-closed-components-test' AND id IN (1,2);"
    ).execute(&mut *tx).await?;
    let graph = source_closed_components(&mut tx, ACCOUNT).await?;
    assert_eq!(graph.components.len(), 2);
    assert_eq!(graph.components[0].draft_ids, [1, 2]);
    assert_eq!(graph.components[1].draft_ids, [3]);
    assert!(read_snapshot(&mut tx, ACCOUNT, &[1], 4000, &authority)
        .await?
        .is_none());
    assert!(
        !read_snapshot(&mut tx, ACCOUNT, &[1, 2], 4000, &authority)
            .await?
            .unwrap()
            .1
    );
    let later = select_source_settled_cohort(&mut tx, ACCOUNT, None, 32, 4000, &authority)
        .await?
        .expect("unrelated settled work remains reachable behind a held source component");
    assert_eq!(
        later
            .drafts
            .iter()
            .map(|draft| draft.id)
            .collect::<Vec<_>>(),
        [3]
    );
    for table in [
        "memory_reconciliation_jobs",
        "vertex_usage_events",
        "capture_formation_receipts",
    ] {
        let count: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT count(*) FROM {table} WHERE account_id=$1"
        )))
        .bind(ACCOUNT)
        .fetch_one(&mut *tx)
        .await?;
        assert_eq!(
            count, 0,
            "discovery must not invent source completion or provider work"
        );
    }

    // A real, exact empty-stream seal makes this previously held session
    // eligible on the next sweep; no process-local held cursor survives.
    sqlx::raw_sql(
        "UPDATE capture_sessions SET ended_at=last_event_at WHERE account_id='source-closed-components-test';
         INSERT INTO capture_streams(account_id,id,capture_session_id,device_id,stream_kind,
                                     committed_through_sequence,sealed_sequence)
         VALUES('source-closed-components-test','stream','bridge','device','mac_screen',-1,-1);
         INSERT INTO capture_formation_receipts(account_id,capture_session_id,source_revision,
             finish_requested_at,finish_request_provenance)
         VALUES('source-closed-components-test','bridge',1,clock_timestamp()-interval '59 days','finish_endpoint_v1');"
    ).execute(&mut *tx).await?;
    let fingerprint = capture_formation_source_fingerprint(&mut tx, ACCOUNT, "bridge", 1).await?;
    sqlx::query(
        "UPDATE capture_formation_receipts SET state='complete',completed_revision=1,
        completed_outcome='accounted',completed_claim_token='synthetic-completed-claim',
        completed_source_fingerprint=$2,completed_at=clock_timestamp()
        WHERE account_id=$1 AND capture_session_id='bridge'",
    )
    .bind(ACCOUNT)
    .bind(fingerprint)
    .execute(&mut *tx)
    .await?;
    let prompt = read_snapshot(&mut tx, ACCOUNT, &[1, 2], 4000, &authority)
        .await?
        .expect("current formation can organize before its seal exists");
    assert!(prompt.1);
    let mut preseal_sessions = load_source_sessions(
        &mut tx,
        ACCOUNT,
        prompt
            .0
            .atoms
            .iter()
            .map(|atom| timestamp(&atom.started_at, "test").unwrap())
            .min()
            .unwrap(),
        prompt
            .0
            .atoms
            .iter()
            .map(|atom| timestamp(&atom.ended_at, "test").unwrap())
            .max()
            .unwrap(),
    )
    .await?;
    verify_source_session_formation(&mut tx, ACCOUNT, &mut preseal_sessions).await?;
    assert!(source_sessions_are_organization_ready(&preseal_sessions));
    assert!(
        !source_sessions_are_settled(&preseal_sessions),
        "prompt memory organization must not grant brief readiness"
    );
    sqlx::raw_sql(
        "INSERT INTO capture_formation_seal_events(account_id,capture_session_id,seal_generation,
             source_revision,event_kind,stream_maxima_sha256,provenance)
         VALUES('source-closed-components-test','bridge',1,1,'seal',
             capture_formation_stream_maxima_sha256('source-closed-components-test','bridge'),'quiet_contiguous_v1');
         UPDATE capture_formation_receipts SET seal_generation=1,seal_finalized_at=clock_timestamp(),
             seal_finalization_provenance='quiet_contiguous_v1'
         WHERE account_id='source-closed-components-test' AND capture_session_id='bridge';"
    ).execute(&mut *tx).await?;
    let first = select_source_settled_cohort(&mut tx, ACCOUNT, None, 32, 4000, &authority)
        .await?
        .expect("a complete sealed long session must join both original header groups");
    assert_eq!(
        first
            .drafts
            .iter()
            .map(|draft| draft.id)
            .collect::<Vec<_>>(),
        [1, 2]
    );

    sqlx::query("SAVEPOINT fractional_edge")
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO screenshots(account_id,id,captured_at)
        SELECT $1,401,date_trunc('milliseconds',max(ended_at))+interval '0.0014 second'
        FROM episodes WHERE account_id=$1 AND id IN (1,2)",
    )
    .bind(ACCOUNT)
    .execute(&mut *tx)
    .await?;
    let fractional = read_snapshot(&mut tx, ACCOUNT, &[1, 2], 4000, &authority)
        .await?
        .expect("a fractional-millisecond unowned edge must remain in the complete snapshot")
        .0;
    assert!(fractional.atoms.iter().any(|atom| atom.record_id == 401));
    let component = oldest_source_component(&mut tx, ACCOUNT, None)
        .await?
        .unwrap();
    let keep_evidence = keep_evidence_closure(
        &mut tx,
        ACCOUNT,
        &[1, 2],
        component.started_ms,
        component.ended_ms,
    )
    .await?;
    assert_eq!(keep_evidence.count, 3);
    assert_eq!(
        keep_evidence.unowned_count, 1,
        "KEEP must account for the fractional-millisecond source before a no-memory decision"
    );
    sqlx::query("UPDATE episodes SET started_at=to_timestamp($2::double precision/1000)+interval '8 hours 0.0006 second',
        ended_at=to_timestamp($2::double precision/1000)+interval '8 hours 0.0006 second'
        WHERE account_id=$1 AND id=3")
        .bind(ACCOUNT).bind(component.ended_ms).execute(&mut *tx).await?;
    sqlx::query("UPDATE screenshots SET captured_at=to_timestamp($2::double precision/1000)+interval '8 hours 0.0006 second'
        WHERE account_id=$1 AND id=3")
        .bind(ACCOUNT).bind(component.ended_ms).execute(&mut *tx).await?;
    assert_eq!(
        source_closed_components(&mut tx, ACCOUNT)
            .await?
            .components
            .len(),
        2
    );
    let tight_next = select_source_settled_cohort(
        &mut tx,
        ACCOUNT,
        Some(component.ended_ms),
        32,
        4000,
        &authority,
    )
    .await?
    .expect("rounded full-component cursor must not add a second quiet horizon");
    assert_eq!(tight_next.drafts[0].id, 3);
    sqlx::query("ROLLBACK TO SAVEPOINT fractional_edge")
        .execute(&mut *tx)
        .await?;

    sqlx::query("SAVEPOINT changed_graph")
        .execute(&mut *tx)
        .await?;
    // Even an empty header is a temporal bridge, and must invalidate the old
    // exact predecessor set at claim/egress/publication revalidation.
    sqlx::query(
        "INSERT INTO episodes(account_id,id,started_at,ended_at,type,title,summary)
        SELECT $1,4,min(started_at),max(ended_at),'note','Empty bridge','Synthetic'
        FROM episodes WHERE account_id=$1 AND id IN (2,3)",
    )
    .bind(ACCOUNT)
    .execute(&mut *tx)
    .await?;
    let changed = source_closed_components(&mut tx, ACCOUNT).await?;
    assert_eq!(changed.components.len(), 1);
    assert_eq!(changed.components[0].draft_ids, [1, 2, 3, 4]);
    assert_eq!(changed.components[0].blocked_drafts, 1);
    assert!(read_snapshot(&mut tx, ACCOUNT, &[1, 2], 4000, &authority)
        .await?
        .is_none());
    assert!(
        select_source_settled_cohort(&mut tx, ACCOUNT, None, 32, 4000, &authority)
            .await?
            .is_none(),
        "a component with an empty predecessor cannot publish a valid CP partition"
    );
    assert!(
        select_source_settled_cohort(
            &mut tx,
            ACCOUNT,
            Some(graph.components[0].ended_ms),
            32,
            4000,
            &authority
        )
        .await?
        .is_none(),
        "a resume boundary may not expose a connected suffix"
    );
    sqlx::query("ROLLBACK TO SAVEPOINT changed_graph")
        .execute(&mut *tx)
        .await?;

    // A finalized memory does not schedule an organization pass by itself.
    sqlx::query(
        "UPDATE episodes SET finalized_at=clock_timestamp(),finalization_status='finalized'
        WHERE account_id=$1 AND id=3",
    )
    .bind(ACCOUNT)
    .execute(&mut *tx)
    .await?;
    assert_eq!(
        source_closed_components(&mut tx, ACCOUNT)
            .await?
            .components
            .len(),
        1
    );
    assert!(read_snapshot(&mut tx, ACCOUNT, &[3], 4000, &authority)
        .await?
        .is_none());
    // A late noon source is considered with the already-published 2 p.m.
    // memory, even though the new row arrives after that memory finalized.
    sqlx::raw_sql(
        "INSERT INTO episodes(account_id,id,started_at,ended_at,type,title,summary)
         SELECT account_id,10,started_at-interval '2 hours',started_at-interval '119 minutes',
                'meeting','Continuation','Synthetic' FROM episodes
         WHERE account_id='source-closed-components-test' AND id=3;
         INSERT INTO screenshots(account_id,id,captured_at)
         SELECT account_id,id,started_at FROM episodes
         WHERE account_id='source-closed-components-test' AND id=10;
         INSERT INTO episode_members(account_id,episode_id,record_type,record_id)
         VALUES('source-closed-components-test',10,'screenshot',10);",
    )
    .execute(&mut *tx)
    .await?;
    let continuation = read_snapshot(&mut tx, ACCOUNT, &[3, 10], 4000, &authority)
        .await?
        .expect("late evidence includes its following finalized memory");
    assert!(
        continuation.1,
        "source capture time, not the new row creation time, selects context"
    );
    assert_eq!(continuation.0.predecessor_episode_ids, [3, 10]);
    assert_eq!(continuation.0.atoms.len(), 2);
    sqlx::raw_sql(
        "UPDATE episodes new SET started_at=prior.started_at-interval '6 hours',
             ended_at=prior.started_at-interval '359 minutes' FROM episodes prior
         WHERE new.account_id='source-closed-components-test' AND new.id=10
           AND prior.account_id=new.account_id AND prior.id=3;
         UPDATE screenshots s SET captured_at=e.started_at FROM episodes e
         WHERE s.account_id='source-closed-components-test' AND s.id=10
           AND e.account_id=s.account_id AND e.id=10;",
    )
    .execute(&mut *tx)
    .await?;
    assert!(
        read_snapshot(&mut tx, ACCOUNT, &[3, 10], 4000, &authority)
            .await?
            .is_some(),
        "six-hour preceding activity remains inside the eight-hour candidate context"
    );
    sqlx::query("SAVEPOINT transitive_finalized_context")
        .execute(&mut *tx)
        .await?;
    sqlx::raw_sql(
        "INSERT INTO episodes(account_id,id,started_at,ended_at,type,title,summary,finalized_at,finalization_status)
         SELECT account_id,11,started_at+interval '7 hours',ended_at+interval '7 hours','meeting','Later continuation','Synthetic',clock_timestamp(),'complete'
           FROM episodes WHERE account_id='source-closed-components-test' AND id=3;
         INSERT INTO screenshots(account_id,id,captured_at) SELECT account_id,id,started_at FROM episodes
           WHERE account_id='source-closed-components-test' AND id=11;
         INSERT INTO episode_members(account_id,episode_id,record_type,record_id)
           VALUES('source-closed-components-test',11,'screenshot',11);
         INSERT INTO capture_sessions(account_id,id,device_id,install_id,started_at,last_event_at,schema_version,created_at)
         SELECT account_id,'transitive-finalized','device','install',started_at,ended_at,2,started_at FROM episodes
           WHERE account_id='source-closed-components-test' AND id=11;"
    ).execute(&mut *tx).await?;
    let transitive = source_closed_components(&mut tx, ACCOUNT).await?;
    assert!(
        transitive
            .components
            .iter()
            .any(|component| component.draft_ids == [3, 10, 11]),
        "full source closure includes finalized ownership beyond the direct seed window"
    );
    let candidate_counts: (i64, i64) = sqlx::query_as(concat!(
        include_str!("reconciliation_source_components.sql"),
        "SELECT drafts,fresh_drafts FROM candidate_components WHERE 10=ANY(draft_ids)"
    ))
    .bind(ACCOUNT)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(
        candidate_counts,
        (3, 1),
        "model bounds count all context owners while the v6 audit counts only fresh draft work"
    );
    assert!(
        read_snapshot(&mut tx, ACCOUNT, &[3, 10, 11], 4000, &authority)
            .await?
            .is_some(),
        "transitive ownership is a bounded readiness hold, not a permanent external-owner conflict"
    );
    sqlx::query("ROLLBACK TO SAVEPOINT transitive_finalized_context")
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE episodes SET structure_state='reconciled' WHERE account_id=$1 AND id=10")
        .bind(ACCOUNT)
        .execute(&mut *tx)
        .await?;
    assert!(
        read_snapshot(&mut tx, ACCOUNT, &[3, 10], 4000, &authority)
            .await?
            .is_none(),
        "unchanged published context must not repeatedly reconcile"
    );
    sqlx::query(
        "INSERT INTO capture_sessions(account_id,id,device_id,install_id,started_at,last_event_at,schema_version,created_at)
         SELECT $1,'dense-'||n,'device','install',e.started_at,e.ended_at,2,e.started_at
           FROM episodes e CROSS JOIN generate_series(1,257) n WHERE e.account_id=$1 AND e.id=3",
    ).bind(ACCOUNT).execute(&mut *tx).await?;
    let start = timestamp(&continuation.0.drafts[0].started_at, "test")?;
    let end = timestamp(&continuation.0.drafts[0].ended_at, "test")?;
    let dense = load_brief_source_sessions(&mut tx, ACCOUNT, start, end)
        .await?
        .unwrap();
    assert_eq!(
        dense.len(),
        257,
        "providerless brief verification pages beyond the model input bound"
    );
    assert!(
        !source_sessions_are_settled(&dense),
        "paging cannot manufacture missing seals"
    );
    tx.rollback().await?;

    let mut tx = persistence.pool().begin().await?;
    sqlx::raw_sql(
        "INSERT INTO accounts(id,email,primary_provider,primary_subject)
         VALUES('source-closed-components-test','components@example.com','google','components');
         INSERT INTO episodes(account_id,id,started_at,ended_at,type,title,summary)
         SELECT 'source-closed-components-test',id,clock_timestamp()-interval '100 days'+id*interval '2 days',
                clock_timestamp()-interval '100 days'+id*interval '2 days','note','Synthetic','Synthetic'
         FROM generate_series(1,9) id;
         INSERT INTO screenshots(account_id,id,captured_at)
         SELECT account_id,id,started_at FROM episodes WHERE account_id='source-closed-components-test';
         INSERT INTO episode_members(account_id,episode_id,record_type,record_id)
         SELECT account_id,id,'screenshot',id FROM episodes WHERE account_id='source-closed-components-test';
         INSERT INTO capture_sessions(account_id,id,device_id,install_id,started_at,last_event_at,schema_version,created_at)
         SELECT account_id,'held-'||id,'device','install',started_at,ended_at,2,started_at
         FROM episodes WHERE account_id='source-closed-components-test' AND id<=8;"
    ).execute(&mut *tx).await?;
    assert!(
        select_source_settled_cohort(&mut tx, ACCOUNT, None, 32, 4000, &authority)
            .await?
            .is_none(),
        "a sweep may inspect at most eight source components"
    );
    sqlx::query("DELETE FROM capture_sessions WHERE account_id=$1 AND id='held-8'")
        .bind(ACCOUNT)
        .execute(&mut *tx)
        .await?;
    let eighth = select_source_settled_cohort(&mut tx, ACCOUNT, None, 32, 4000, &authority)
        .await?
        .expect("seven held components leave the eighth reachable");
    assert_eq!(eighth.drafts[0].id, 8);
    sqlx::raw_sql(
        "INSERT INTO capture_streams(account_id,id,capture_session_id,device_id,stream_kind)
         VALUES('source-closed-components-test','root-stream','held-1','device','mac_screen'),
               ('source-closed-components-test','reference-stream','held-7','device','mac_screen');
         INSERT INTO capture_events(account_id,event_id,device_id,install_id,capture_session_id,
             stream_id,stream_kind,sequence,source_wall_at,source_monotonic_ns,started_at,ended_at,
             timezone_id,utc_offset_minutes,clock_uncertainty_ms,asset_id,manifest_digest,media_disposition)
         SELECT account_id,'canonical-root','device','install','held-1','root-stream','mac_screen',0,
             started_at,'0',started_at,ended_at,'UTC',0,0,'root-asset',repeat('a',64),'canonical'
         FROM episodes WHERE account_id='source-closed-components-test' AND id=1;
         INSERT INTO capture_events(account_id,event_id,device_id,install_id,capture_session_id,
             stream_id,stream_kind,sequence,source_wall_at,source_monotonic_ns,started_at,ended_at,
             timezone_id,utc_offset_minutes,clock_uncertainty_ms,asset_id,manifest_digest,media_disposition,
             canonical_event_id,canonical_asset_id,canonical_media_sha256,perceptual_hash,
             hamming_distance,pixel_change_ratio,context_fingerprint,dedupe_version)
         SELECT account_id,'canonical-reference','device','install','held-7','reference-stream','mac_screen',0,
             started_at,'0',started_at,ended_at,'UTC',0,0,'reference-asset',repeat('b',64),'reference',
             'canonical-root','root-asset',repeat('c',64),'0000000000000000',0,0,repeat('d',64),1
         FROM episodes WHERE account_id='source-closed-components-test' AND id=7;"
    ).execute(&mut *tx).await?;
    let canonical = source_closed_components(&mut tx, ACCOUNT).await?;
    assert_eq!(
        canonical.components[0].draft_ids,
        (1..=7).collect::<Vec<_>>(),
        "cross-session canonical references bridge whole source horizons"
    );
    sqlx::query("INSERT INTO visual_speaker_observations(account_id,id,event_id,screenshot_id,
        observed_at,platform,displayed_name,normalized_name,highlight_state,confidence)
        VALUES($1,1,'canonical-root',8,clock_timestamp(),'synthetic','Synthetic','synthetic','none',1)")
        .bind(ACCOUNT).execute(&mut *tx).await?;
    let indirect = source_closed_components(&mut tx, ACCOUNT).await?;
    assert_eq!(
        indirect.components[0].draft_ids,
        (1..=8).collect::<Vec<_>>(),
        "indirect visual projection ownership must extend the source family"
    );
    assert!(read_snapshot(&mut tx, ACCOUNT, &[8], 4000, &authority)
        .await?
        .is_none());
    let ninth = select_source_settled_cohort(&mut tx, ACCOUNT, None, 32, 4000, &authority)
        .await?
        .expect("only the still-independent ninth draft is eligible");
    assert_eq!(ninth.drafts[0].id, 9);
    tx.rollback().await?;
    Ok(())
}
