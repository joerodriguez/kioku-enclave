#![allow(dead_code, clippy::too_many_arguments)]

use rusqlite::{params, Connection, Result as SqlResult};
use serde::{Deserialize, Serialize};

use super::dlp::ProjectionDisposition;

pub const CURRENT_POLICY_VERSION: i32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectionJob {
    pub source_kind: String,
    pub source_id: String,
    pub source_revision: String,
    pub policy_version: i32,
    pub state: String,
    pub lease_owner: Option<String>,
    pub lease_expires_at: Option<String>,
}

/// Applies idempotent SQLite migrations for the durable projection work queue and safe schema.
pub fn init_projection_schema(conn: &Connection) -> SqlResult<()> {
    crate::store::init_vec_extension();
    conn.execute(
        "CREATE TABLE IF NOT EXISTS mcp_projection_jobs (
            source_kind TEXT NOT NULL,
            source_id TEXT NOT NULL,
            source_revision TEXT NOT NULL,
            policy_version INTEGER NOT NULL,
            state TEXT NOT NULL DEFAULT 'pending',
            lease_owner TEXT,
            lease_expires_at TIMESTAMP,
            attempt_count INTEGER NOT NULL DEFAULT 0,
            next_attempt_at TIMESTAMP,
            error_code TEXT,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (source_kind, source_id)
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS mcp_safe_utterances (
            id INTEGER PRIMARY KEY,
            source_revision TEXT NOT NULL,
            policy_version INTEGER NOT NULL,
            disposition TEXT NOT NULL,
            redaction_count INTEGER NOT NULL DEFAULT 0,
            sanitized_text TEXT NOT NULL,
            speaker_label TEXT,
            started_at TIMESTAMP NOT NULL,
            ended_at TIMESTAMP NOT NULL,
            projected_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS mcp_safe_screenshots (
            id INTEGER PRIMARY KEY,
            source_revision TEXT NOT NULL,
            policy_version INTEGER NOT NULL,
            disposition TEXT NOT NULL,
            redaction_count INTEGER NOT NULL DEFAULT 0,
            sanitized_ocr TEXT NOT NULL,
            app_name TEXT,
            window_title TEXT,
            captured_at TIMESTAMP NOT NULL,
            projected_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS mcp_safe_episodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            episode_ref TEXT NOT NULL UNIQUE,
            source_revision TEXT NOT NULL,
            policy_version INTEGER NOT NULL,
            disposition TEXT NOT NULL,
            redaction_count INTEGER NOT NULL DEFAULT 0,
            sanitized_title TEXT NOT NULL,
            sanitized_summary TEXT NOT NULL,
            participants_json TEXT NOT NULL,
            action_items_json TEXT NOT NULL,
            started_at TIMESTAMP NOT NULL,
            ended_at TIMESTAMP NOT NULL,
            projected_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    )?;

    conn.execute(
        "CREATE VIRTUAL TABLE IF NOT EXISTS mcp_utterances_fts USING fts5(
            sanitized_text,
            content='mcp_safe_utterances',
            content_rowid='id'
        )",
        [],
    )?;

    conn.execute(
        "CREATE TRIGGER IF NOT EXISTS mcp_utterances_insert_fts AFTER INSERT ON mcp_safe_utterances BEGIN
            INSERT INTO mcp_utterances_fts(rowid, sanitized_text) VALUES (new.id, new.sanitized_text);
        END;",
        [],
    )?;
    conn.execute(
        "CREATE TRIGGER IF NOT EXISTS mcp_utterances_delete_fts AFTER DELETE ON mcp_safe_utterances BEGIN
            INSERT INTO mcp_utterances_fts(mcp_utterances_fts, rowid, sanitized_text) VALUES ('delete', old.id, old.sanitized_text);
        END;",
        [],
    )?;
    conn.execute(
        "CREATE TRIGGER IF NOT EXISTS mcp_utterances_update_fts AFTER UPDATE OF sanitized_text ON mcp_safe_utterances BEGIN
            INSERT INTO mcp_utterances_fts(mcp_utterances_fts, rowid, sanitized_text) VALUES ('delete', old.id, old.sanitized_text);
            INSERT INTO mcp_utterances_fts(rowid, sanitized_text) VALUES (new.id, new.sanitized_text);
        END;",
        [],
    )?;
    conn.execute(
        "CREATE TRIGGER IF NOT EXISTS mcp_episodes_update_fts AFTER UPDATE OF sanitized_title, sanitized_summary ON mcp_safe_episodes BEGIN
            INSERT INTO mcp_episodes_fts(mcp_episodes_fts, rowid, sanitized_title, sanitized_summary) VALUES ('delete', old.id, old.sanitized_title, old.sanitized_summary);
            INSERT INTO mcp_episodes_fts(rowid, sanitized_title, sanitized_summary) VALUES (new.id, new.sanitized_title, new.sanitized_summary);
        END;",
        [],
    )?;

    // Clean up any stale whole-field '[REDACTED: restricted data]' strings left by older finalizers
    let _ = conn.execute_batch(
        "
        UPDATE episodes 
        SET finalization_status = 'regeneration_queued', finalized_at = NULL, finalization_version = 0 
        WHERE summary LIKE '%[REDACTED: restricted data]%';

        UPDATE episode_final_briefs 
        SET overview = replace(replace(overview, '[REDACTED: restricted data]', '[REDACTED]'), '[REDACTED FOR OPENAI]', '[REDACTED]')
        WHERE overview LIKE '%[REDACTED: restricted data]%' OR overview LIKE '%[REDACTED FOR OPENAI]%';

        DELETE FROM mcp_safe_episodes WHERE sanitized_summary LIKE '%[REDACTED: restricted data]%';
        ",
    );

    // Idempotently populate mcp_safe_utterances from raw utterances for un-projected items
    let _ = conn.execute_batch(
        "
        INSERT OR IGNORE INTO mcp_safe_utterances (id, source_revision, policy_version, disposition, redaction_count, sanitized_text, speaker_label, started_at, ended_at)
        SELECT 
            u.id, 
            COALESCE(u.source_key, CAST(u.id AS TEXT)), 
            1, 
            'projected', 
            0, 
            u.text, 
            u.speaker_label, 
            s.started_at, 
            s.ended_at
        FROM utterances u
        JOIN audio_segments s ON s.id = u.audio_segment_id;
        ",
    );

    // Run deterministic local redactions on un-redacted rows in mcp_safe_utterances using windowed segment context
    if let Ok(mut stmt) = conn.prepare(
        "SELECT m.id, m.sanitized_text, u.audio_segment_id 
         FROM mcp_safe_utterances m 
         JOIN utterances u ON u.id = m.id 
         WHERE m.redaction_count = 0 
         ORDER BY u.audio_segment_id ASC, m.id ASC 
         LIMIT 500",
    ) {
        let unredacted_rows: Vec<(i64, String, i64)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .map(|rows| rows.filter_map(|r| r.ok()).collect())
            .unwrap_or_default();

        let mut current_segment_id: Option<i64> = None;
        let mut current_batch: Vec<(i64, String)> = Vec::new();

        let process_batch = |conn: &Connection, batch: &[(i64, String)]| {
            if batch.is_empty() {
                return;
            }
            let redacted_results = super::dlp::redact_utterance_window(batch);
            for (id, red) in redacted_results {
                let disp = if red.redaction_count > 0 {
                    "sanitized"
                } else {
                    "projected"
                };
                let _ = conn.execute(
                    "UPDATE mcp_safe_utterances SET sanitized_text = ?1, disposition = ?2, redaction_count = ?3 WHERE id = ?4",
                    params![red.text, disp, red.redaction_count as i64, id],
                );
            }
        };

        for (id, text, seg_id) in unredacted_rows {
            if current_segment_id.is_some_and(|s| s != seg_id) {
                process_batch(conn, &current_batch);
                current_batch.clear();
            }
            current_segment_id = Some(seg_id);
            current_batch.push((id, text));
        }
        process_batch(conn, &current_batch);
    }

    conn.execute(
        "CREATE VIRTUAL TABLE IF NOT EXISTS mcp_screenshots_fts USING fts5(
            sanitized_ocr,
            content='mcp_safe_screenshots',
            content_rowid='id'
        )",
        [],
    )?;

    conn.execute(
        "CREATE TRIGGER IF NOT EXISTS mcp_screenshots_insert_fts AFTER INSERT ON mcp_safe_screenshots BEGIN
            INSERT INTO mcp_screenshots_fts(rowid, sanitized_ocr) VALUES (new.id, new.sanitized_ocr);
        END;",
        [],
    )?;
    conn.execute(
        "CREATE TRIGGER IF NOT EXISTS mcp_screenshots_delete_fts AFTER DELETE ON mcp_safe_screenshots BEGIN
            INSERT INTO mcp_screenshots_fts(mcp_screenshots_fts, rowid, sanitized_ocr) VALUES ('delete', old.id, old.sanitized_ocr);
        END;",
        [],
    )?;

    conn.execute(
        "CREATE VIRTUAL TABLE IF NOT EXISTS mcp_episodes_fts USING fts5(
            sanitized_title,
            sanitized_summary,
            content='mcp_safe_episodes',
            content_rowid='id'
        )",
        [],
    )?;

    conn.execute(
        "CREATE TRIGGER IF NOT EXISTS mcp_episodes_insert_fts AFTER INSERT ON mcp_safe_episodes BEGIN
            INSERT INTO mcp_episodes_fts(rowid, sanitized_title, sanitized_summary) VALUES (new.id, new.sanitized_title, new.sanitized_summary);
        END;",
        [],
    )?;

    Ok(())
}

/// Enqueues or updates a projection job for a raw source record.
pub fn enqueue_job(conn: &Connection, kind: &str, id: &str, revision: &str) -> SqlResult<()> {
    conn.execute(
        "
        INSERT INTO mcp_projection_jobs (source_kind, source_id, source_revision, policy_version, state, updated_at)
        VALUES (?1, ?2, ?3, ?4, 'pending', CURRENT_TIMESTAMP)
        ON CONFLICT(source_kind, source_id) DO UPDATE SET
            source_revision = excluded.source_revision,
            policy_version = excluded.policy_version,
            state = 'pending',
            lease_owner = NULL,
            lease_expires_at = NULL,
            attempt_count = 0,
            updated_at = CURRENT_TIMESTAMP
        ",
        params![kind, id, revision, CURRENT_POLICY_VERSION],
    )?;
    Ok(())
}

/// Claims pending or expired projection jobs atomically using RETURNING.
pub fn claim_jobs(
    conn: &Connection,
    worker_id: &str,
    limit: usize,
) -> SqlResult<Vec<ProjectionJob>> {
    let mut stmt = conn.prepare(
        "
        UPDATE mcp_projection_jobs
        SET state = 'processing',
            lease_owner = ?1,
            lease_expires_at = datetime('now', '+60 seconds'),
            updated_at = CURRENT_TIMESTAMP
        WHERE (source_kind, source_id) IN (
            SELECT source_kind, source_id FROM mcp_projection_jobs
            WHERE state = 'pending' OR (state = 'processing' AND lease_expires_at < CURRENT_TIMESTAMP)
            ORDER BY updated_at ASC LIMIT ?2
        )
        RETURNING source_kind, source_id, source_revision, policy_version, state, lease_owner, lease_expires_at;
        ",
    )?;

    let job_iter = stmt.query_map(params![worker_id, limit as i64], |row| {
        Ok(ProjectionJob {
            source_kind: row.get(0)?,
            source_id: row.get(1)?,
            source_revision: row.get(2)?,
            policy_version: row.get(3)?,
            state: row.get(4)?,
            lease_owner: row.get(5)?,
            lease_expires_at: row.get(6)?,
        })
    })?;

    let mut jobs = Vec::new();
    for job in job_iter {
        jobs.push(job?);
    }
    Ok(jobs)
}

/// CAS Compare-and-Swap commit for safe projection materialization.
pub fn commit_safe_utterance(
    conn: &Connection,
    job: &ProjectionJob,
    id: i64,
    disposition: &ProjectionDisposition,
    redaction_count: usize,
    sanitized_text: &str,
    speaker_label: Option<&str>,
    started_at: &str,
    ended_at: &str,
) -> SqlResult<bool> {
    let tx = conn.unchecked_transaction()?;

    let disp_str = match disposition {
        ProjectionDisposition::Safe => "safe",
        ProjectionDisposition::Sanitized => "sanitized",
        ProjectionDisposition::Blocked => "blocked",
    };

    tx.execute(
        "
        INSERT INTO mcp_safe_utterances (id, source_revision, policy_version, disposition, redaction_count, sanitized_text, speaker_label, started_at, ended_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        ON CONFLICT(id) DO UPDATE SET
            source_revision = excluded.source_revision,
            policy_version = excluded.policy_version,
            disposition = excluded.disposition,
            redaction_count = excluded.redaction_count,
            sanitized_text = excluded.sanitized_text,
            speaker_label = excluded.speaker_label,
            started_at = excluded.started_at,
            ended_at = excluded.ended_at,
            projected_at = CURRENT_TIMESTAMP
        ",
        params![
            id,
            job.source_revision,
            job.policy_version,
            disp_str,
            redaction_count as i64,
            sanitized_text,
            speaker_label,
            started_at,
            ended_at
        ],
    )?;

    // CAS check on job revision & policy version
    let updated = tx.execute(
        "
        UPDATE mcp_projection_jobs
        SET state = 'ready', lease_owner = NULL, lease_expires_at = NULL, updated_at = CURRENT_TIMESTAMP
        WHERE source_kind = ?1 AND source_id = ?2 AND source_revision = ?3 AND policy_version = ?4 AND lease_owner = ?5
        ",
        params![job.source_kind, job.source_id, job.source_revision, job.policy_version, job.lease_owner],
    )?;

    if updated == 1 {
        tx.commit()?;
        Ok(true)
    } else {
        tx.rollback()?;
        Ok(false)
    }
}

/// Complete episode dependency enqueuing helper.
pub fn enqueue_episode_dependencies(conn: &Connection, episode_id: &str) -> SqlResult<()> {
    let rev = format!("ep_rev_{}", episode_id);
    enqueue_job(conn, "episode", episode_id, &rev)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_init_and_job_lifecycle() {
        let conn = Connection::open_in_memory().unwrap();
        init_projection_schema(&conn).unwrap();

        enqueue_job(&conn, "utterance", "101", "rev_a").unwrap();
        let jobs = claim_jobs(&conn, "worker_1", 10).unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].source_id, "101");
        assert_eq!(jobs[0].state, "processing");

        let committed = commit_safe_utterance(
            &conn,
            &jobs[0],
            101,
            &ProjectionDisposition::Safe,
            0,
            "Hello world",
            Some("Lynn"),
            "2026-07-26T12:00:00Z",
            "2026-07-26T12:00:05Z",
        )
        .unwrap();

        assert!(committed);

        // Verify episode dependency enqueuing
        enqueue_episode_dependencies(&conn, "ep_123").unwrap();
        let ep_jobs = claim_jobs(&conn, "worker_2", 10).unwrap();
        assert_eq!(ep_jobs[0].source_kind, "episode");
        assert_eq!(ep_jobs[0].source_id, "ep_123");

        // Verify FTS entry
        let mut stmt = conn
            .prepare("SELECT count(*) FROM mcp_utterances_fts WHERE sanitized_text MATCH 'Hello'")
            .unwrap();
        let count: i64 = stmt.query_row([], |r| r.get(0)).unwrap();
        assert_eq!(count, 1);
    }
}
