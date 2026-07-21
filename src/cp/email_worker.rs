use crate::cp::{isotime, CpState};
use crate::error::Result;
use rusqlite::OptionalExtension;
use serde::Deserialize;
use serde_json::json;
use tracing::{info, warn};

#[derive(Debug)]
struct OutboxRow {
    episode_id: i64,
    delivery_version: i32,
    attempt_count: i32,
}

#[derive(Debug, Deserialize)]
struct GmailTokenRefreshResp {
    access_token: String,
}

#[derive(Debug, Clone)]
struct BriefDetails {
    title: String,
    started_at: String,
    ended_at: String,
    participants: Vec<String>,
    #[allow(dead_code)]
    episode_type: Option<String>,
    overview: String,
    decisions: Vec<DecisionDetail>,
    action_items: Vec<ActionItemDetail>,
    important_links: Vec<LinkDetail>,
    open_questions: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct DecisionDetail {
    text: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ActionItemDetail {
    text: String,
    owner: String,
    due_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct LinkDetail {
    url: String,
    label: String,
    why_it_matters: String,
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn format_mime_message(
    self_email: &str,
    subject: &str,
    plain_body: &str,
    html_body: &str,
    episode_id: i64,
) -> String {
    let boundary = "----=_Part_Kioku_Alternative_Boundary_1029384756";
    let message_id = format!(
        "<ep-{}-{}@kiokuu.com>",
        episode_id,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    );

    let mut mime = String::new();
    mime.push_str(&format!("From: {}\r\n", self_email));
    mime.push_str(&format!("To: {}\r\n", self_email));
    mime.push_str(&format!("Subject: {}\r\n", subject));
    mime.push_str(&format!("Message-ID: {}\r\n", message_id));
    mime.push_str(&format!("X-Kioku-Episode-ID: {}\r\n", episode_id));
    mime.push_str("MIME-Version: 1.0\r\n");
    mime.push_str(&format!(
        "Content-Type: multipart/alternative; boundary=\"{}\"\r\n\r\n",
        boundary
    ));

    use base64::Engine as _;

    // Plain text section
    mime.push_str(&format!("--{}\r\n", boundary));
    mime.push_str("Content-Type: text/plain; charset=UTF-8\r\n");
    mime.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
    mime.push_str(&base64::engine::general_purpose::STANDARD.encode(plain_body.as_bytes()));
    mime.push_str("\r\n\r\n");

    // HTML section
    mime.push_str(&format!("--{}\r\n", boundary));
    mime.push_str("Content-Type: text/html; charset=UTF-8\r\n");
    mime.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
    mime.push_str(&base64::engine::general_purpose::STANDARD.encode(html_body.as_bytes()));
    mime.push_str("\r\n\r\n");

    mime.push_str(&format!("--{}--\r\n", boundary));

    mime
}

/// Sweep pending outbox rows and deliver them to Gmail.
pub async fn deliver_user_emails(state: &CpState, user_id: &str) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    let now_iso = isotime::format_epoch_millis(now);

    let user = user_id.to_string();
    let pending_delivery: Option<OutboxRow> = state
        .store
        .with_user(&user, move |conn| {
            let row = conn
                .query_row(
                    "SELECT episode_id, delivery_version, attempt_count
             FROM episode_deliveries
             WHERE state IN ('pending', 'retry')
               AND (next_attempt_at IS NULL OR next_attempt_at <= ?1)
             LIMIT 1",
                    [&now_iso],
                    |r| {
                        Ok(OutboxRow {
                            episode_id: r.get(0)?,
                            delivery_version: r.get(1)?,
                            attempt_count: r.get(2)?,
                        })
                    },
                )
                .optional()?;
            Ok(row)
        })
        .await?;

    let Some(outbox) = pending_delivery else {
        return Ok(());
    };

    info!(user_id = %user_id, episode_id = outbox.episode_id, "processing pending email delivery");

    // Fetch user Gmail config
    let gmail_config = state.control.get_gmail_config(user_id).await?;
    let Some(config) = gmail_config else {
        warn!(user_id = %user_id, "Gmail configuration not found during delivery sweep");
        return Ok(());
    };

    if !config.enabled || config.refresh_token.is_none() {
        // Cancel delivery if disabled or not configured
        let user_cloned = user.clone();
        let ep_id = outbox.episode_id;
        let v = outbox.delivery_version;
        let _ = state.store.with_user(&user_cloned, move |conn| {
            conn.execute(
                "UPDATE episode_deliveries SET state = 'cancelled', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
                 WHERE episode_id = ?1 AND delivery_version = ?2",
                rusqlite::params![ep_id, v]
            )?;
            Ok(())
        }).await;
        let _ = state.store.save_user(&user).await;
        return Ok(());
    }

    // Refresh Gmail access token
    let refresh_token = config.refresh_token.as_ref().unwrap();
    let http = reqwest::Client::new();
    let token_body = serde_urlencoded::to_string([
        ("client_id", state.config.google_web_client_id.as_str()),
        (
            "client_secret",
            state.config.google_web_client_secret.as_str(),
        ),
        ("refresh_token", refresh_token.as_str()),
        ("grant_type", "refresh_token"),
    ])
    .unwrap();

    let refresh_resp = http
        .post("https://oauth2.googleapis.com/token")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(token_body)
        .send()
        .await;

    let access_token = match refresh_resp {
        Ok(resp) if resp.status().is_success() => {
            match resp.json::<GmailTokenRefreshResp>().await {
                Ok(r) => r.access_token,
                Err(_) => {
                    return handle_delivery_failure(
                        state,
                        &user,
                        &outbox,
                        "Google token refresh response parse failed",
                        false,
                    )
                    .await;
                }
            }
        }
        Ok(resp) => {
            let status = resp.status();
            let err_text = resp.text().await.unwrap_or_default();
            warn!(user_id = %user_id, status = %status, error = %err_text, "failed to refresh Gmail access token");
            // If invalid_grant, trigger reconnect
            let is_permanent = err_text.contains("invalid_grant")
                || status.as_u16() == 400
                || status.as_u16() == 401;
            return handle_delivery_failure(
                state,
                &user,
                &outbox,
                &format!("Token refresh failed: {}", err_text),
                is_permanent,
            )
            .await;
        }
        Err(e) => {
            warn!(user_id = %user_id, error = %e, "network error refreshing access token");
            return handle_delivery_failure(
                state,
                &user,
                &outbox,
                &format!("Network error refreshing token: {}", e),
                false,
            )
            .await;
        }
    };

    // Load episode final brief details
    let user_cloned = user.clone();
    let ep_id = outbox.episode_id;
    let brief_data: Option<BriefDetails> = state
        .store
        .with_user(&user_cloned, move |conn| {
            let ep_row = conn
                .query_row(
                    "SELECT title, started_at, ended_at, participants, type
             FROM episodes WHERE id = ?1",
                    [ep_id],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, String>(2)?,
                            r.get::<_, Option<String>>(3)?,
                            r.get::<_, Option<String>>(4)?,
                        ))
                    },
                )
                .optional()?;

            let Some((title, started_at, ended_at, part_raw, ep_type)) = ep_row else {
                return Ok(None);
            };

            let brief_row = conn
                .query_row(
                    "SELECT overview, decisions, action_items, important_links, open_questions
             FROM episode_final_briefs WHERE episode_id = ?1",
                    [ep_id],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, String>(2)?,
                            r.get::<_, String>(3)?,
                            r.get::<_, String>(4)?,
                        ))
                    },
                )
                .optional()?;

            let Some((overview, decisions_raw, actions_raw, links_raw, questions_raw)) = brief_row
            else {
                return Ok(None);
            };

            let parse_json_list = |raw: Option<String>| -> Vec<String> {
                raw.and_then(|r| serde_json::from_str::<Vec<String>>(&r).ok())
                    .unwrap_or_default()
            };

            let participants = parse_json_list(part_raw);
            let open_questions = parse_json_list(Some(questions_raw));
            let decisions: Vec<DecisionDetail> =
                serde_json::from_str(&decisions_raw).unwrap_or_default();
            let action_items: Vec<ActionItemDetail> =
                serde_json::from_str(&actions_raw).unwrap_or_default();
            let important_links: Vec<LinkDetail> =
                serde_json::from_str(&links_raw).unwrap_or_default();

            Ok(Some(BriefDetails {
                title,
                started_at,
                ended_at,
                participants,
                episode_type: ep_type,
                overview,
                decisions,
                action_items,
                important_links,
                open_questions,
            }))
        })
        .await?;

    let Some(brief) = brief_data else {
        warn!(
            episode_id = outbox.episode_id,
            "final brief or episode metadata not found in DB during delivery"
        );
        return handle_delivery_failure(state, &user, &outbox, "Brief data missing in DB", true)
            .await;
    };

    // Format plain text body
    let mut plain = String::new();
    plain.push_str(&format!("{}\n", brief.title));
    plain.push_str(&format!(
        "Time: {} - {}\n",
        brief.started_at, brief.ended_at
    ));
    if !brief.participants.is_empty() {
        plain.push_str(&format!(
            "Participants: {}\n",
            brief.participants.join(", ")
        ));
    }
    plain.push('\n');

    plain.push_str("■ Do next\n");
    if brief.action_items.is_empty() {
        plain.push_str("- None\n");
    } else {
        for a in &brief.action_items {
            let due = a
                .due_at
                .as_ref()
                .map(|d| format!(" (Due: {})", d))
                .unwrap_or_default();
            plain.push_str(&format!("[ ] {} — Owner: {}{}\n", a.text, a.owner, due));
        }
    }
    plain.push('\n');

    plain.push_str("■ Important links\n");
    if brief.important_links.is_empty() {
        plain.push_str("- None\n");
    } else {
        for l in &brief.important_links {
            plain.push_str(&format!(
                "- {}: {}\n  Why it matters: {}\n",
                l.label, l.url, l.why_it_matters
            ));
        }
    }
    plain.push('\n');

    plain.push_str("■ Decisions and key facts\n");
    if brief.decisions.is_empty() {
        plain.push_str("- None\n");
    } else {
        for d in &brief.decisions {
            plain.push_str(&format!("- {}\n", d.text));
        }
    }
    plain.push('\n');

    plain.push_str("■ Open questions / follow-ups\n");
    if brief.open_questions.is_empty() {
        plain.push_str("- None\n");
    } else {
        for q in &brief.open_questions {
            plain.push_str(&format!("- {}\n", q));
        }
    }
    plain.push('\n');

    plain.push_str("■ Overview\n");
    plain.push_str(&brief.overview);
    plain.push_str("\n\n");
    plain.push_str(&format!(
        "View details in Kioku: {}/app#episodes/{}\n",
        state.config.web_origin, outbox.episode_id
    ));
    plain.push_str(&format!(
        "Turn off these emails: {}/app#settings\n",
        state.config.web_origin
    ));

    // Format HTML body
    let mut html = String::new();
    html.push_str("<!DOCTYPE html><html><head><meta charset=\"UTF-8\"></head><body style=\"font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f8f9fa; color: #212529; margin: 0; padding: 20px;\">");
    html.push_str("<div style=\"max-width: 600px; margin: 0 auto; background-color: #ffffff; border: 1px solid #e9ecef; border-radius: 8px; padding: 24px; box-shadow: 0 4px 6px rgba(0,0,0,0.05);\">");

    // Header
    html.push_str(&format!("<h1 style=\"font-size: 20px; font-weight: 700; color: #1a73e8; margin-top: 0; margin-bottom: 8px;\">{}</h1>", html_escape(&brief.title)));
    html.push_str(&format!("<p style=\"font-size: 14px; color: #5f6368; margin-top: 0; margin-bottom: 16px;\">{} &bull; {}</p>", html_escape(&brief.started_at), html_escape(&brief.ended_at)));
    if !brief.participants.is_empty() {
        html.push_str(&format!("<p style=\"font-size: 14px; color: #5f6368; margin-top: 0; margin-bottom: 24px;\"><strong>Participants:</strong> {}</p>", html_escape(&brief.participants.join(", "))));
    }

    // Do Next
    html.push_str("<h2 style=\"font-size: 16px; font-weight: 600; color: #202124; border-bottom: 1px solid #f1f3f4; padding-bottom: 8px; margin-top: 24px; margin-bottom: 12px;\">Do Next</h2>");
    if brief.action_items.is_empty() {
        html.push_str("<p style=\"font-size: 14px; color: #5f6368; font-style: italic;\">None</p>");
    } else {
        html.push_str("<ul style=\"list-style: none; padding-left: 0; margin-top: 0;\">");
        for a in &brief.action_items {
            let due = a.due_at.as_ref().map(|d| format!(" <span style=\"font-size: 12px; color: #d93025; background-color: #fce8e6; padding: 2px 6px; border-radius: 4px; margin-left: 8px;\">Due: {}</span>", html_escape(d))).unwrap_or_default();
            html.push_str(&format!(
                "<li style=\"font-size: 14px; margin-bottom: 8px; display: flex; align-items: flex-start;\">
                    <span style=\"color: #1a73e8; margin-right: 8px; font-weight: bold;\">[ ]</span>
                    <span><strong>{}</strong> &mdash; {} {}</span>
                 </li>",
                html_escape(&a.text),
                html_escape(&a.owner),
                due
            ));
        }
        html.push_str("</ul>");
    }

    // Important Links
    html.push_str("<h2 style=\"font-size: 16px; font-weight: 600; color: #202124; border-bottom: 1px solid #f1f3f4; padding-bottom: 8px; margin-top: 24px; margin-bottom: 12px;\">Important Links</h2>");
    if brief.important_links.is_empty() {
        html.push_str("<p style=\"font-size: 14px; color: #5f6368; font-style: italic;\">None</p>");
    } else {
        for l in &brief.important_links {
            html.push_str(&format!(
                "<div style=\"margin-bottom: 12px;\">
                    <a href=\"{}\" target=\"_blank\" style=\"font-size: 14px; color: #1a73e8; font-weight: 600; text-decoration: none;\">{}</a>
                    <p style=\"font-size: 13px; color: #5f6368; margin-top: 4px; margin-bottom: 0;\">{}</p>
                 </div>",
                html_escape(&l.url),
                html_escape(&l.label),
                html_escape(&l.why_it_matters)
            ));
        }
    }

    // Decisions
    html.push_str("<h2 style=\"font-size: 16px; font-weight: 600; color: #202124; border-bottom: 1px solid #f1f3f4; padding-bottom: 8px; margin-top: 24px; margin-bottom: 12px;\">Decisions and Key Facts</h2>");
    if brief.decisions.is_empty() {
        html.push_str("<p style=\"font-size: 14px; color: #5f6368; font-style: italic;\">None</p>");
    } else {
        html.push_str("<ul style=\"padding-left: 20px; margin-top: 0; margin-bottom: 0;\">");
        for d in &brief.decisions {
            html.push_str(&format!(
                "<li style=\"font-size: 14px; color: #202124; margin-bottom: 6px;\">{}</li>",
                html_escape(&d.text)
            ));
        }
        html.push_str("</ul>");
    }

    // Open Questions
    html.push_str("<h2 style=\"font-size: 16px; font-weight: 600; color: #202124; border-bottom: 1px solid #f1f3f4; padding-bottom: 8px; margin-top: 24px; margin-bottom: 12px;\">Open Questions & Follow-ups</h2>");
    if brief.open_questions.is_empty() {
        html.push_str("<p style=\"font-size: 14px; color: #5f6368; font-style: italic;\">None</p>");
    } else {
        html.push_str("<ul style=\"padding-left: 20px; margin-top: 0; margin-bottom: 0;\">");
        for q in &brief.open_questions {
            html.push_str(&format!(
                "<li style=\"font-size: 14px; color: #202124; margin-bottom: 6px;\">{}</li>",
                html_escape(q)
            ));
        }
        html.push_str("</ul>");
    }

    // Overview
    html.push_str("<h2 style=\"font-size: 16px; font-weight: 600; color: #202124; border-bottom: 1px solid #f1f3f4; padding-bottom: 8px; margin-top: 24px; margin-bottom: 12px;\">Overview</h2>");
    html.push_str(&format!(
        "<p style=\"font-size: 14px; color: #3c4043; line-height: 1.5; margin-top: 0;\">{}</p>",
        html_escape(&brief.overview)
    ));

    // Footer links
    html.push_str("<div style=\"border-top: 1px solid #f1f3f4; padding-top: 16px; margin-top: 32px; font-size: 12px; color: #70757a;\">");
    html.push_str(&format!("<p style=\"margin-top: 0; margin-bottom: 4px;\">Sent from your Attested Kioku Enclave. <a href=\"{}/app#episodes/{}\" target=\"_blank\" style=\"color: #1a73e8; text-decoration: none;\">View evidence-backed details</a>.</p>", state.config.web_origin, outbox.episode_id));
    html.push_str(&format!("<p style=\"margin-top: 0; margin-bottom: 0;\">To turn off these emails, update your <a href=\"{}/app#settings\" target=\"_blank\" style=\"color: #1a73e8; text-decoration: none;\">Kioku Settings</a>.</p>", state.config.web_origin));
    html.push_str("</div>");

    html.push_str("</div></body></html>");

    let subject = format!(
        "[Kioku] Actions from {} — {}",
        brief.title,
        brief.started_at.split('T').next().unwrap_or("")
    );
    let self_recipient = config.gmail_email.as_ref().unwrap();

    let mime_msg = format_mime_message(self_recipient, &subject, &plain, &html, outbox.episode_id);

    use base64::Engine as _;
    let encoded_raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mime_msg.as_bytes());

    let send_body = json!({
        "raw": encoded_raw
    });

    let send_resp = http
        .post("https://gmail.googleapis.com/gmail/v1/users/me/messages/send")
        .bearer_auth(&access_token)
        .json(&send_body)
        .send()
        .await;

    match send_resp {
        Ok(resp) if resp.status().is_success() => {
            #[derive(Deserialize)]
            struct GmailSendResp {
                id: String,
            }
            let gmail_id = match resp.json::<GmailSendResp>().await {
                Ok(r) => Some(r.id),
                Err(_) => None,
            };

            info!(episode_id = outbox.episode_id, gmail_message_id = ?gmail_id, "email successfully sent via Gmail");

            // Mark as sent in DB
            let user_cloned = user.clone();
            let ep_id = outbox.episode_id;
            let v = outbox.delivery_version;
            let db_res = state.store.with_user(&user_cloned, move |conn| {
                conn.execute(
                    "UPDATE episode_deliveries
                     SET state = 'sent', gmail_message_id = ?1, error_message = NULL, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
                     WHERE episode_id = ?2 AND delivery_version = ?3",
                    rusqlite::params![gmail_id, ep_id, v]
                )?;
                Ok(())
            }).await;
            if let Err(e) = db_res {
                warn!(episode_id = ep_id, error = %e, "failed to update outbox to sent state");
            } else {
                let _ = state.store.save_user(&user).await;
            }
        }
        Ok(resp) => {
            let status = resp.status();
            let err_text = resp.text().await.unwrap_or_default();
            warn!(episode_id = outbox.episode_id, status = %status, error = %err_text, "Gmail API returned error status");
            let is_permanent =
                status.as_u16() == 400 || status.as_u16() == 401 || status.as_u16() == 403;
            handle_delivery_failure(
                state,
                &user,
                &outbox,
                &format!("Gmail API send error ({}): {}", status, err_text),
                is_permanent,
            )
            .await?;
        }
        Err(e) => {
            warn!(episode_id = outbox.episode_id, error = %e, "network error sending email via Gmail");
            handle_delivery_failure(
                state,
                &user,
                &outbox,
                &format!("Network error during send: {}", e),
                false,
            )
            .await?;
        }
    }

    Ok(())
}

async fn handle_delivery_failure(
    state: &CpState,
    user_id: &str,
    outbox: &OutboxRow,
    err_msg: &str,
    is_permanent: bool,
) -> Result<()> {
    if is_permanent {
        info!(user_id = %user_id, episode_id = outbox.episode_id, "permanent OAuth/Gmail error encountered; disabling Gmail connection");
        // Disable preference and mark reconnect required in control store
        let gmail_config = state.control.get_gmail_config(user_id).await?;
        if let Some(mut config) = gmail_config {
            config.enabled = false;
            config.reconnect_required = true;
            config.refresh_token = None; // Purge expired/invalid token
            let _ = state.control.upsert_gmail_config(config).await;
        }

        // Set state = reconnect_required in user content DB
        let user_cloned = user_id.to_string();
        let ep_id = outbox.episode_id;
        let v = outbox.delivery_version;
        let msg = err_msg.to_string();
        let _ = state.store.with_user(&user_cloned, move |conn| {
            conn.execute(
                "UPDATE episode_deliveries
                 SET state = 'reconnect_required', error_message = ?1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
                 WHERE episode_id = ?2 AND delivery_version = ?3",
                rusqlite::params![msg, ep_id, v]
            )?;
            Ok(())
        }).await;
        let _ = state.store.save_user(user_id).await;
    } else {
        // Transient error: retry with exponential backoff
        let next_attempt_count = outbox.attempt_count + 1;
        // 1.5^attempt_count * 10 seconds (cap at 4 hours)
        let backoff_secs = (1.5f64.powi(next_attempt_count) * 10.0).min(14400.0) as i64;
        let next_run_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64
            + (backoff_secs * 1000);
        let next_run_iso = isotime::format_epoch_millis(next_run_ms);

        info!(episode_id = outbox.episode_id, attempt = next_attempt_count, next_attempt = %next_run_iso, "scheduling delivery retry");

        let user_cloned = user_id.to_string();
        let ep_id = outbox.episode_id;
        let v = outbox.delivery_version;
        let msg = err_msg.to_string();
        let _ = state.store.with_user(&user_cloned, move |conn| {
            conn.execute(
                "UPDATE episode_deliveries
                 SET state = 'retry', attempt_count = ?1, next_attempt_at = ?2, error_message = ?3, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
                 WHERE episode_id = ?4 AND delivery_version = ?5",
                rusqlite::params![next_attempt_count, next_run_iso, msg, ep_id, v]
            )?;
            Ok(())
        }).await;
        let _ = state.store.save_user(user_id).await;
    }

    Ok(())
}
