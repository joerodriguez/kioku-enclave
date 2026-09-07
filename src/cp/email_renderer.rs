//! Pure subject, plain-text, and HTML rendering for native memory emails.
//!
//! The email speaks the same language as the Kioku apps. A finalized *memory*
//! has a *Final brief* made of an overview plus Decisions, Action items,
//! Important links, and Open questions — the section names and order of the
//! iPhone and web Brief pages — and the content-free subject matches the
//! iPhone push alert ("Your memory is ready.").
//!
//! Enforces exact isolation between notification-only (default) and full-content
//! modes, strict HTML escaping of user content, safe link attribute validation,
//! and deterministic capping/truncation.

use crate::cp::delivery::FinalizedEpisode;
use crate::cp::isotime;

const MAX_RENDERED_BYTES: usize = 102_400; // 100 KiB cap

const READY_SUBJECT: &str = "Your memory is ready";
const READY_LEAD: &str = "Its final brief is waiting in Kioku.";
const OPEN_IN_KIOKU: &str = "Open in Kioku";

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

pub fn escape_html(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

pub fn is_safe_href(url: &str) -> bool {
    let lower = url.trim().to_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

/// `Jul 30, 2026` for a UTC civil date.
fn human_date(y: i64, mo: i64, d: i64) -> String {
    let month = MONTHS
        .get((mo - 1).clamp(0, 11) as usize)
        .copied()
        .unwrap_or("Jan");
    format!("{month} {d}, {y}")
}

/// Human-readable UTC instant, e.g. `Jul 30, 2026, 10:31 UTC`. The enclave
/// holds no per-account time zone, so the zone is stated instead of guessed.
/// Unparseable input is returned unchanged rather than dropped.
pub fn human_utc(timestamp: &str) -> String {
    match isotime::parse_epoch_millis(timestamp) {
        Some(ms) => {
            let (y, mo, d, h, mi, _) = isotime::civil_utc(ms);
            format!("{}, {h:02}:{mi:02} UTC", human_date(y, mo, d))
        }
        None => timestamp.to_string(),
    }
}

/// Human-readable UTC range, e.g. `Jul 30, 2026, 10:00–10:30 UTC`, or with a
/// second date when the memory crosses midnight.
pub fn human_utc_range(start: &str, end: &str) -> String {
    match (
        isotime::parse_epoch_millis(start),
        isotime::parse_epoch_millis(end),
    ) {
        (Some(start_ms), Some(end_ms)) => {
            let (sy, smo, sd, sh, smi, _) = isotime::civil_utc(start_ms);
            let (ey, emo, ed, eh, emi, _) = isotime::civil_utc(end_ms);
            if (sy, smo, sd) == (ey, emo, ed) {
                format!(
                    "{}, {sh:02}:{smi:02}–{eh:02}:{emi:02} UTC",
                    human_date(sy, smo, sd)
                )
            } else {
                format!(
                    "{}, {sh:02}:{smi:02} – {}, {eh:02}:{emi:02} UTC",
                    human_date(sy, smo, sd),
                    human_date(ey, emo, ed)
                )
            }
        }
        _ => {
            if end.trim().is_empty() {
                human_utc(start)
            } else {
                format!("{} – {}", human_utc(start), human_utc(end))
            }
        }
    }
}

pub fn render_email_subject(episode: &FinalizedEpisode, include_content: bool) -> String {
    if !include_content {
        READY_SUBJECT.to_string()
    } else {
        let title = episode.title.trim();
        if title.is_empty() {
            READY_SUBJECT.to_string()
        } else {
            format!("Final brief: {}", title)
        }
    }
}

const STYLE: &str = r#"
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f4f5f7; color: #172b4d; margin: 0; padding: 24px; }
  .container { max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 8px; border: 1px solid #e2e8f0; padding: 32px; }
  .h1 { font-size: 22px; font-weight: 600; color: #091e42; margin-top: 0; margin-bottom: 6px; }
  .lead { font-size: 15px; line-height: 1.5; color: #172b4d; margin: 0 0 8px; }
  .meta { font-size: 13px; color: #5e6c84; margin-bottom: 20px; }
  .section-title { font-size: 14px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; color: #42526e; margin-top: 24px; margin-bottom: 10px; border-bottom: 1px solid #ebecf0; padding-bottom: 4px; }
  .group-title { font-size: 14px; font-weight: 600; color: #172b4d; margin-top: 18px; margin-bottom: 8px; }
  .overview { font-size: 15px; line-height: 1.5; color: #172b4d; }
  ul { margin: 0; padding-left: 20px; }
  li { margin-bottom: 8px; font-size: 14px; line-height: 1.4; }
  .badge { background: #dfe1e6; color: #42526e; font-size: 12px; font-weight: 500; padding: 2px 6px; border-radius: 3px; margin-left: 4px; }
  .cta { margin-top: 28px; padding-top: 16px; border-top: 1px solid #ebecf0; }
  .button { display: inline-block; background-color: #0052cc; color: #ffffff !important; text-decoration: none; font-size: 14px; font-weight: 500; padding: 10px 20px; border-radius: 6px; }
"#;

fn html_document(title: &str, body: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{}</title>
<style>{}</style>
</head>
<body>
  <div class="container">
{}
  </div>
</body>
</html>"#,
        escape_html(title),
        STYLE,
        body
    )
}

fn cta_html(app_url: &str) -> String {
    format!(
        r#"<div class="cta"><a href="{}" class="button" target="_blank" rel="noopener noreferrer">{}</a></div>"#,
        escape_html(app_url),
        OPEN_IN_KIOKU
    )
}

pub fn render_email_body(
    episode: &FinalizedEpisode,
    include_content: bool,
    app_base_url: &str,
) -> (String, String) {
    let app_url = format!(
        "{}/app#memory/{}",
        app_base_url.trim_end_matches('/'),
        episode.episode_id
    );
    let finalized = human_utc(&episode.finalized_at);

    if !include_content {
        let finalized_line = if finalized.trim().is_empty() {
            String::new()
        } else {
            format!("Finalized {finalized}.\n")
        };
        let text = format!(
            "{READY_SUBJECT}.\n\n{READY_LEAD}\n{finalized_line}\n{OPEN_IN_KIOKU}: {app_url}\n"
        );
        let finalized_html = if finalized.trim().is_empty() {
            String::new()
        } else {
            format!(
                r#"<div class="meta">Finalized {}</div>"#,
                escape_html(&finalized)
            )
        };
        let body = format!(
            r#"    <div class="h1">{READY_SUBJECT}</div>
    <p class="lead">{READY_LEAD}</p>
    {}
    {}"#,
            finalized_html,
            cta_html(&app_url)
        );
        return (
            truncate_bytes(text, MAX_RENDERED_BYTES),
            truncate_bytes(html_document(READY_SUBJECT, &body), MAX_RENDERED_BYTES),
        );
    }

    // Full content: the memory title, when it happened and with whom, then the
    // Final brief exactly as the Brief page shows it.
    let title = if episode.title.trim().is_empty() {
        "Memory".to_string()
    } else {
        episode.title.trim().to_string()
    };
    let when = human_utc_range(&episode.started_at, &episode.ended_at);

    let mut text_parts = Vec::new();
    text_parts.push(format!("Final brief: {title}"));
    text_parts.push(when.clone());
    if !episode.participants.is_empty() {
        text_parts.push(format!("Participants: {}", episode.participants.join(", ")));
    }

    let has_brief = !episode.overview.is_empty()
        || !episode.decisions.is_empty()
        || !episode.action_items.is_empty()
        || !episode.important_links.is_empty()
        || !episode.open_questions.is_empty();
    if has_brief {
        text_parts.push("\nFinal brief".to_string());
    }
    if !episode.overview.is_empty() {
        text_parts.push(episode.overview.clone());
    }

    if !episode.decisions.is_empty() {
        text_parts.push("\nDecisions".to_string());
        for d in &episode.decisions {
            text_parts.push(format!("• {}", d.text));
        }
    }

    if !episode.action_items.is_empty() {
        text_parts.push("\nAction items".to_string());
        for a in &episode.action_items {
            let mut meta = Vec::new();
            if !a.owner.is_empty() {
                meta.push(a.owner.clone());
            }
            if let Some(due) = a.due_at.as_deref() {
                meta.push(due.to_string());
            }
            if meta.is_empty() {
                text_parts.push(format!("• {}", a.text));
            } else {
                text_parts.push(format!("• {} — {}", a.text, meta.join(" · ")));
            }
        }
    }

    if !episode.important_links.is_empty() {
        text_parts.push("\nImportant links".to_string());
        for l in &episode.important_links {
            text_parts.push(format!("• {} — {} ({})", l.label, l.url, l.why_it_matters));
        }
    }

    if !episode.open_questions.is_empty() {
        text_parts.push("\nOpen questions".to_string());
        for q in &episode.open_questions {
            text_parts.push(format!("• {}", q));
        }
    }

    text_parts.push(format!("\n{OPEN_IN_KIOKU}: {app_url}"));
    let text = text_parts.join("\n");

    let mut body = String::new();
    body.push_str(&format!(
        r#"    <div class="h1">{}</div>
    <div class="meta">{}"#,
        escape_html(&title),
        escape_html(&when),
    ));
    if !episode.participants.is_empty() {
        let participants_escaped: Vec<String> = episode
            .participants
            .iter()
            .map(|p| escape_html(p))
            .collect();
        body.push_str(&format!(
            r#" &bull; Participants: {}"#,
            participants_escaped.join(", ")
        ));
    }
    body.push_str("</div>\n");

    if has_brief {
        body.push_str(r#"<div class="section-title">Final brief</div>"#);
    }
    if !episode.overview.is_empty() {
        body.push_str(&format!(
            r#"<div class="overview">{}</div>"#,
            escape_html(&episode.overview)
        ));
    }

    if !episode.decisions.is_empty() {
        body.push_str(r#"<div class="group-title">Decisions</div><ul>"#);
        for d in &episode.decisions {
            body.push_str(&format!("<li>{}</li>", escape_html(&d.text)));
        }
        body.push_str("</ul>");
    }

    if !episode.action_items.is_empty() {
        body.push_str(r#"<div class="group-title">Action items</div><ul>"#);
        for a in &episode.action_items {
            let owner = if !a.owner.is_empty() {
                format!(r#"<span class="badge">{}</span>"#, escape_html(&a.owner))
            } else {
                String::new()
            };
            let due = if let Some(ref d) = a.due_at {
                format!(r#" <span class="badge">Due {}</span>"#, escape_html(d))
            } else {
                String::new()
            };
            body.push_str(&format!(
                "<li>{}{}{}</li>",
                escape_html(&a.text),
                owner,
                due
            ));
        }
        body.push_str("</ul>");
    }

    if !episode.important_links.is_empty() {
        body.push_str(r#"<div class="group-title">Important links</div><ul>"#);
        for l in &episode.important_links {
            let link_html = if is_safe_href(&l.url) {
                format!(
                    r#"<a href="{}" target="_blank" rel="noopener noreferrer">{}</a>"#,
                    escape_html(&l.url),
                    escape_html(&l.label)
                )
            } else {
                escape_html(&l.label)
            };
            body.push_str(&format!(
                "<li>{} &ndash; {}</li>",
                link_html,
                escape_html(&l.why_it_matters)
            ));
        }
        body.push_str("</ul>");
    }

    if !episode.open_questions.is_empty() {
        body.push_str(r#"<div class="group-title">Open questions</div><ul>"#);
        for q in &episode.open_questions {
            body.push_str(&format!("<li>{}</li>", escape_html(q)));
        }
        body.push_str("</ul>");
    }

    body.push_str(&cta_html(&app_url));

    (
        truncate_bytes(text, MAX_RENDERED_BYTES),
        truncate_bytes(html_document(&title, &body), MAX_RENDERED_BYTES),
    )
}

fn truncate_bytes(s: String, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        s
    } else {
        let mut end = max_bytes;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        s[..end].to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cp::delivery::{ActionItemDetail, DecisionDetail, LinkDetail};

    fn sample_episode() -> FinalizedEpisode {
        FinalizedEpisode {
            episode_id: 101,
            title: "Project Alpha Launch Plan".into(),
            started_at: "2026-07-30T10:00:00Z".into(),
            ended_at: "2026-07-30T10:30:00Z".into(),
            finalized_at: "2026-07-30T10:31:00Z".into(),
            episode_type: Some("meeting".into()),
            participants: vec!["Alice".into(), "Bob <script>alert(1)</script>".into()],
            overview: "Discussed launch timelines & deployment steps.".into(),
            decisions: vec![DecisionDetail {
                text: "Ship v1 on Monday & Friday".into(),
            }],
            action_items: vec![ActionItemDetail {
                text: "Update docs".into(),
                owner: "Alice".into(),
                due_at: Some("2026-08-01".into()),
            }],
            important_links: vec![
                LinkDetail {
                    label: "Launch Doc".into(),
                    url: "https://example.com/doc".into(),
                    why_it_matters: "Contains spec".into(),
                },
                LinkDetail {
                    label: "Evil Script".into(),
                    url: "javascript:alert(1)".into(),
                    why_it_matters: "Should not link".into(),
                },
            ],
            open_questions: vec!["Who handles support?".into()],
        }
    }

    #[test]
    fn notification_only_never_contains_episode_content() {
        let ep = sample_episode();
        let subject = render_email_subject(&ep, false);
        let (text, html) = render_email_body(&ep, false, "https://api.kiokuu.com");

        // Same words as the iPhone push alert.
        assert_eq!(subject, "Your memory is ready");
        assert!(!subject.contains("Project Alpha"));
        assert!(text.starts_with("Your memory is ready."));
        assert!(text.contains("Its final brief is waiting in Kioku."));
        assert!(text.contains("Finalized Jul 30, 2026, 10:31 UTC."));
        assert!(!text.contains("Project Alpha"));
        assert!(!text.contains("Alice"));
        assert!(!text.contains("Discussed launch timelines"));
        assert!(html.contains(r#"<div class="h1">Your memory is ready</div>"#));
        assert!(html.contains("Finalized Jul 30, 2026, 10:31 UTC"));
        assert!(!html.contains("Project Alpha"));
        assert!(!html.contains("Alice"));
        assert!(!html.contains("Discussed launch timelines"));
        assert!(html.contains("https://api.kiokuu.com/app#memory/101"));
        assert!(html.contains(">Open in Kioku</a>"));
    }

    #[test]
    fn full_content_uses_the_brief_page_sections_and_sanitizes() {
        let ep = sample_episode();
        let subject = render_email_subject(&ep, true);
        let (text, html) = render_email_body(&ep, true, "https://api.kiokuu.com");

        assert_eq!(subject, "Final brief: Project Alpha Launch Plan");
        assert!(text.starts_with("Final brief: Project Alpha Launch Plan\n"));
        assert!(text.contains("Jul 30, 2026, 10:00–10:30 UTC"));
        assert!(text.contains("Alice, Bob <script>alert(1)</script>"));
        // Section names match the iPhone and web Brief page, in its order.
        for heading in [
            "\nFinal brief\n",
            "\nDecisions\n",
            "\nAction items\n",
            "\nImportant links\n",
            "\nOpen questions\n",
        ] {
            assert!(text.contains(heading), "missing {heading:?} in {text}");
        }
        assert!(text.contains("• Update docs — Alice · 2026-08-01"));
        let order: Vec<usize> = [
            "Final brief",
            "Decisions",
            "Action items",
            "Important links",
            "Open questions",
        ]
        .iter()
        .map(|h| html.find(&format!(">{h}</div>")).expect(h))
        .collect();
        assert!(
            order.windows(2).all(|w| w[0] < w[1]),
            "sections out of order"
        );
        assert!(html.contains(r#"<div class="section-title">Final brief</div>"#));
        assert!(html.contains("Jul 30, 2026, 10:00–10:30 UTC"));
        assert!(!html.contains("Action Items"));
        assert!(!html.contains("Open Questions"));
        assert!(!html.contains("Kioku brief"));

        // Check HTML escaping
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("Bob &lt;script&gt;alert(1)&lt;/script&gt;"));

        // Check link safety
        assert!(html.contains(r#"href="https://example.com/doc""#));
        assert!(!html.contains(r#"href="javascript:alert(1)""#));
        assert!(html.contains("Evil Script"));
    }

    #[test]
    fn empty_title_falls_back_without_leaking_content_into_the_subject() {
        let mut ep = sample_episode();
        ep.title = "   ".into();
        assert_eq!(render_email_subject(&ep, true), "Your memory is ready");
        let (_, html) = render_email_body(&ep, true, "https://api.kiokuu.com");
        assert!(html.contains(r#"<div class="h1">Memory</div>"#));
    }

    #[test]
    fn empty_brief_and_missing_finalized_time_render_nothing_misleading() {
        let mut ep = sample_episode();
        ep.overview.clear();
        ep.decisions.clear();
        ep.action_items.clear();
        ep.important_links.clear();
        ep.open_questions.clear();
        ep.finalized_at.clear();
        let (text, html) = render_email_body(&ep, true, "https://api.kiokuu.com");
        assert!(!text.contains("Final brief\n"));
        assert!(!html.contains("Final brief</div>"));
        assert!(html.contains("Project Alpha Launch Plan"));
        let (text, html) = render_email_body(&ep, false, "https://api.kiokuu.com");
        assert!(!text.contains("Finalized"));
        assert!(!html.contains("Finalized"));
        assert!(html.contains("Your memory is ready"));
    }

    #[test]
    fn human_dates_are_readable_utc_and_never_invent_a_zone() {
        assert_eq!(human_utc("2026-07-30T10:31:00Z"), "Jul 30, 2026, 10:31 UTC");
        assert_eq!(
            human_utc("2026-07-30T06:31:00-04:00"),
            "Jul 30, 2026, 10:31 UTC"
        );
        assert_eq!(
            human_utc_range("2026-07-30T10:00:00Z", "2026-07-30T10:30:00Z"),
            "Jul 30, 2026, 10:00–10:30 UTC"
        );
        assert_eq!(
            human_utc_range("2026-12-31T23:50:00Z", "2027-01-01T00:20:00Z"),
            "Dec 31, 2026, 23:50 – Jan 1, 2027, 00:20 UTC"
        );
        // Unparseable input is shown as-is rather than dropped.
        assert_eq!(human_utc("not-a-timestamp"), "not-a-timestamp");
        assert_eq!(human_utc_range("not-a-timestamp", ""), "not-a-timestamp");
        assert_eq!(
            human_utc_range("2026-07-30T10:00:00Z", "later"),
            "Jul 30, 2026, 10:00 UTC – later"
        );
    }

    #[test]
    fn link_href_safety_check() {
        assert!(is_safe_href("https://example.com"));
        assert!(is_safe_href("http://example.com"));
        assert!(!is_safe_href("javascript:alert(1)"));
        assert!(!is_safe_href("file:///etc/passwd"));
        assert!(!is_safe_href("data:text/html,test"));
    }
}
