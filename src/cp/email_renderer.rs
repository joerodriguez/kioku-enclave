//! Pure subject, plain-text, and HTML rendering for native episode emails.
//!
//! Enforces exact isolation between notification-only (default) and full-content
//! modes, strict HTML escaping of user content, safe link attribute validation,
//! and deterministic capping/truncation.

use crate::cp::delivery::FinalizedEpisode;

const MAX_RENDERED_BYTES: usize = 102_400; // 100 KiB cap

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

pub fn render_email_subject(episode: &FinalizedEpisode, include_content: bool) -> String {
    if !include_content {
        "Your Kioku brief is ready".to_string()
    } else {
        let title = episode.title.trim();
        if title.is_empty() {
            "Your Kioku brief is ready".to_string()
        } else {
            format!("Kioku brief: {}", title)
        }
    }
}

pub fn render_email_body(
    episode: &FinalizedEpisode,
    include_content: bool,
    app_base_url: &str,
) -> (String, String) {
    let app_url = format!(
        "{}/app#episodes/{}",
        app_base_url.trim_end_matches('/'),
        episode.episode_id
    );

    if !include_content {
        let text = format!(
            "Your Kioku brief is ready.\n\nFinalized at: {}\n\nOpen Kioku: {}\n",
            episode.finalized_at, app_url
        );

        let html = format!(
            r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Your Kioku brief is ready</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f4f5f7; color: #172b4d; margin: 0; padding: 24px; }}
  .container {{ max-width: 560px; margin: 0 auto; background: #ffffff; border-radius: 8px; border: 1px solid #e2e8f0; padding: 32px; }}
  .h1 {{ font-size: 20px; font-weight: 600; color: #091e42; margin-top: 0; margin-bottom: 8px; }}
  .meta {{ font-size: 14px; color: #5e6c84; margin-bottom: 24px; }}
  .button {{ display: inline-block; background-color: #0052cc; color: #ffffff !important; text-decoration: none; font-size: 14px; font-weight: 500; padding: 10px 20px; border-radius: 6px; }}
</style>
</head>
<body>
  <div class="container">
    <div class="h1">Your Kioku brief is ready</div>
    <div class="meta">Finalized at {}</div>
    <div>
      <a href="{}" class="button" target="_blank" rel="noopener noreferrer">Open in Kioku</a>
    </div>
  </div>
</body>
</html>"#,
            escape_html(&episode.finalized_at),
            escape_html(&app_url)
        );

        return (
            truncate_bytes(text, MAX_RENDERED_BYTES),
            truncate_bytes(html, MAX_RENDERED_BYTES),
        );
    }

    // Full-content rendering
    let mut text_parts = Vec::new();
    text_parts.push(format!("Kioku Brief: {}", episode.title));
    text_parts.push(format!(
        "Time: {} - {}",
        episode.started_at, episode.ended_at
    ));

    if !episode.participants.is_empty() {
        text_parts.push(format!("Participants: {}", episode.participants.join(", ")));
    }

    if !episode.overview.is_empty() {
        text_parts.push(format!("\nOverview:\n{}", episode.overview));
    }

    if !episode.decisions.is_empty() {
        text_parts.push("\nDecisions:".to_string());
        for d in &episode.decisions {
            text_parts.push(format!("• {}", d.text));
        }
    }

    if !episode.action_items.is_empty() {
        text_parts.push("\nAction Items:".to_string());
        for a in &episode.action_items {
            let due = a
                .due_at
                .as_deref()
                .map(|d| format!(" (Due: {})", d))
                .unwrap_or_default();
            let owner = if a.owner.is_empty() {
                String::new()
            } else {
                format!(" [{}]", a.owner)
            };
            text_parts.push(format!("• {}{}{}", a.text, owner, due));
        }
    }

    if !episode.important_links.is_empty() {
        text_parts.push("\nImportant Links:".to_string());
        for l in &episode.important_links {
            text_parts.push(format!("• {} - {} ({})", l.label, l.url, l.why_it_matters));
        }
    }

    if !episode.open_questions.is_empty() {
        text_parts.push("\nOpen Questions:".to_string());
        for q in &episode.open_questions {
            text_parts.push(format!("• {}", q));
        }
    }

    text_parts.push(format!("\nOpen in Kioku: {}", app_url));
    let text = text_parts.join("\n");

    // HTML Full Content
    let mut html_body = String::new();
    html_body.push_str(&format!(
        r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f4f5f7; color: #172b4d; margin: 0; padding: 24px; }}
  .container {{ max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 8px; border: 1px solid #e2e8f0; padding: 32px; }}
  .h1 {{ font-size: 22px; font-weight: 600; color: #091e42; margin-top: 0; margin-bottom: 6px; }}
  .meta {{ font-size: 13px; color: #5e6c84; margin-bottom: 20px; }}
  .section-title {{ font-size: 14px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; color: #42526e; margin-top: 24px; margin-bottom: 10px; border-bottom: 1px solid #ebecf0; padding-bottom: 4px; }}
  .overview {{ font-size: 15px; line-height: 1.5; color: #172b4d; }}
  ul {{ margin: 0; padding-left: 20px; }}
  li {{ margin-bottom: 8px; font-size: 14px; line-height: 1.4; }}
  .badge {{ background: #dfe1e6; color: #42526e; font-size: 12px; font-weight: 500; padding: 2px 6px; border-radius: 3px; margin-left: 4px; }}
  .cta {{ margin-top: 28px; padding-top: 16px; border-top: 1px solid #ebecf0; }}
  .button {{ display: inline-block; background-color: #0052cc; color: #ffffff !important; text-decoration: none; font-size: 14px; font-weight: 500; padding: 10px 20px; border-radius: 6px; }}
</style>
</head>
<body>
  <div class="container">
    <div class="h1">{}</div>
    <div class="meta">Time: {} – {}"#,
        escape_html(&episode.title),
        escape_html(&episode.title),
        escape_html(&episode.started_at),
        escape_html(&episode.ended_at),
    ));

    if !episode.participants.is_empty() {
        let participants_escaped: Vec<String> = episode
            .participants
            .iter()
            .map(|p| escape_html(p))
            .collect();
        html_body.push_str(&format!(
            r#" &bull; Participants: {}"#,
            participants_escaped.join(", ")
        ));
    }
    html_body.push_str("</div>\n");

    if !episode.overview.is_empty() {
        html_body.push_str(&format!(
            r#"<div class="section-title">Overview</div><div class="overview">{}</div>"#,
            escape_html(&episode.overview)
        ));
    }

    if !episode.decisions.is_empty() {
        html_body.push_str(r#"<div class="section-title">Decisions</div><ul>"#);
        for d in &episode.decisions {
            html_body.push_str(&format!("<li>{}</li>", escape_html(&d.text)));
        }
        html_body.push_str("</ul>");
    }

    if !episode.action_items.is_empty() {
        html_body.push_str(r#"<div class="section-title">Action Items</div><ul>"#);
        for a in &episode.action_items {
            let owner = if !a.owner.is_empty() {
                format!(r#"<span class="badge">{}</span>"#, escape_html(&a.owner))
            } else {
                String::new()
            };
            let due = if let Some(ref d) = a.due_at {
                format!(r#" <span class="badge">Due: {}</span>"#, escape_html(d))
            } else {
                String::new()
            };
            html_body.push_str(&format!(
                "<li>{}{}{}</li>",
                escape_html(&a.text),
                owner,
                due
            ));
        }
        html_body.push_str("</ul>");
    }

    if !episode.important_links.is_empty() {
        html_body.push_str(r#"<div class="section-title">Important Links</div><ul>"#);
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
            html_body.push_str(&format!(
                "<li>{} &ndash; {}</li>",
                link_html,
                escape_html(&l.why_it_matters)
            ));
        }
        html_body.push_str("</ul>");
    }

    if !episode.open_questions.is_empty() {
        html_body.push_str(r#"<div class="section-title">Open Questions</div><ul>"#);
        for q in &episode.open_questions {
            html_body.push_str(&format!("<li>{}</li>", escape_html(q)));
        }
        html_body.push_str("</ul>");
    }

    html_body.push_str(&format!(
        r#"<div class="cta"><a href="{}" class="button" target="_blank" rel="noopener noreferrer">Open in Kioku</a></div>
  </div>
</body>
</html>"#,
        escape_html(&app_url)
    ));

    (
        truncate_bytes(text, MAX_RENDERED_BYTES),
        truncate_bytes(html_body, MAX_RENDERED_BYTES),
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

        assert_eq!(subject, "Your Kioku brief is ready");
        assert!(!subject.contains("Project Alpha"));
        assert!(!text.contains("Project Alpha"));
        assert!(!text.contains("Alice"));
        assert!(!text.contains("Discussed launch timelines"));
        assert!(!html.contains("Project Alpha"));
        assert!(!html.contains("Alice"));
        assert!(!html.contains("Discussed launch timelines"));
        assert!(html.contains("https://api.kiokuu.com/app#episodes/101"));
    }

    #[test]
    fn full_content_escapes_html_and_sanitizes_links() {
        let ep = sample_episode();
        let subject = render_email_subject(&ep, true);
        let (text, html) = render_email_body(&ep, true, "https://api.kiokuu.com");

        assert_eq!(subject, "Kioku brief: Project Alpha Launch Plan");
        assert!(text.contains("Project Alpha Launch Plan"));
        assert!(text.contains("Alice, Bob <script>alert(1)</script>"));

        // Check HTML escaping
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("Bob &lt;script&gt;alert(1)&lt;/script&gt;"));

        // Check link safety
        assert!(html.contains(r#"href="https://example.com/doc""#));
        assert!(!html.contains(r#"href="javascript:alert(1)""#));
        assert!(html.contains("Evil Script"));
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
