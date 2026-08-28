//! MCP-only restricted-data boundary.
//!
//! Kioku keeps the user's archive unchanged. Before assistant-facing content
//! leaves the enclave, this module refuses searches aimed at prohibited data
//! and replaces any matching content in the projected MCP response. The REST
//! and debugger surfaces are intentionally unaffected.

use std::sync::OnceLock;

use regex::Regex;
use serde_json::{json, Value};

pub(crate) const DEFAULT_MINIMIZED_PAGE_SIZE: usize = 10;
pub(crate) const MAX_MINIMIZED_PAGE_SIZE: usize = 20;

const REDACTED: &str = "[REDACTED: restricted data]";
const MAX_MCP_STRING_BYTES: usize = 64 * 1024;

fn credential_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(
            r"(?ix)
            \b(?:
                password|passwd|passcode|api[\s_-]?key|client[\s_-]?secret|
                access[\s_-]?token|refresh[\s_-]?token|auth(?:entication|orization)?[\s_-]?token|
                bearer|private[\s_-]?key|seed[\s_-]?phrase|recovery[\s_-]?(?:code|phrase)|
                mfa|otp|one[\s_-]?time[\s_-]?(?:code|password)
            )\b
            |
            \b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b
            |
            \bAKIA[0-9A-Z]{16}\b
            |
            \bAIza[0-9A-Za-z_-]{30,}\b
            |
            \bxox[baprs]-[0-9A-Za-z-]{10,}\b
            |
            \beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b
            |
            -----BEGIN\x20(?:RSA\x20|EC\x20|OPENSSH\x20)?PRIVATE\x20KEY-----
            ",
        )
        .expect("credential pattern")
    })
}

fn payment_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(
            r"(?ix)\b(?:
                credit[\s_-]?card|debit[\s_-]?card|card[\s_-]?number|
                cardholder|cvv|cvc|security[\s_-]?code|payment[\s_-]?card
            )\b",
        )
        .expect("payment pattern")
    })
}

fn government_id_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(
            r"(?ix)
            \b(?:social[\s_-]?security|ssn|passport|driver'?s?[\s_-]?licen[cs]e|
                national[\s_-]?id|government[\s_-]?id|taxpayer[\s_-]?(?:id|number)|itin)\b
            |
            \b\d{3}-\d{2}-\d{4}\b
            ",
        )
        .expect("government identifier pattern")
    })
}

fn health_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(
            r"(?ix)\b(?:
                protected[\s_-]?health|medical[\s_-]?(?:record|history|condition|diagnosis)|
                health[\s_-]?(?:record|history|condition|diagnosis)|
                patient|diagnos(?:is|ed)|prescription|medication|dosage|
                hospital|clinic|physician|therapist|psychiatr(?:y|ic)|
                hiv|aids|cancer|diabetes|blood[\s_-]?pressure|pregnan(?:cy|t)|
                insurance[\s_-]?(?:member|policy)[\s_-]?(?:id|number)
            )\b",
        )
        .expect("health-information pattern")
    })
}

fn card_candidate_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"\b(?:\d[ -]?){12,18}\d\b").expect("payment-card candidate pattern")
    })
}

fn contains_luhn_card(text: &str) -> bool {
    card_candidate_pattern().find_iter(text).any(|candidate| {
        let digits: Vec<u32> = candidate
            .as_str()
            .chars()
            .filter_map(|ch| ch.to_digit(10))
            .collect();
        if !(13..=19).contains(&digits.len()) {
            return false;
        }
        let parity = digits.len() % 2;
        let sum: u32 = digits
            .iter()
            .enumerate()
            .map(|(index, digit)| {
                let mut value = *digit;
                if index % 2 == parity {
                    value *= 2;
                    if value > 9 {
                        value -= 9;
                    }
                }
                value
            })
            .sum();
        sum.is_multiple_of(10)
    })
}

fn contains_restricted_data(text: &str) -> bool {
    text.len() > MAX_MCP_STRING_BYTES
        || credential_pattern().is_match(text)
        || payment_pattern().is_match(text)
        || government_id_pattern().is_match(text)
        || health_pattern().is_match(text)
        || contains_luhn_card(text)
}

fn sanitize_url(raw: &str) -> String {
    let Ok(mut url) = reqwest::Url::parse(raw) else {
        return REDACTED.to_string();
    };
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return REDACTED.to_string();
    }
    if !url.username().is_empty() || url.password().is_some() {
        return REDACTED.to_string();
    }
    // Query strings and fragments commonly carry session, reset, tracking, or
    // identity values. They are never necessary for assistant grounding.
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

fn sanitize_value(value: &mut Value, field_name: Option<&str>) {
    match value {
        Value::String(text) => {
            if text.len() > MAX_MCP_STRING_BYTES {
                *text = REDACTED.to_string();
            } else if field_name.is_some_and(|field| {
                field.eq_ignore_ascii_case("url") || field.to_ascii_lowercase().ends_with("_url")
            }) {
                *text = sanitize_url(text);
            } else {
                let red = crate::cp::dlp::local_deterministic_redact(text);
                *text = red.text;
            }
        }
        Value::Array(items) => {
            for item in items {
                sanitize_value(item, field_name);
            }
        }
        Value::Object(fields) => {
            for (name, child) in fields {
                sanitize_value(child, Some(name));
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

pub(crate) fn sanitize_result(mut result: Value) -> Value {
    sanitize_value(&mut result, None);
    result
}

pub(crate) fn refusal_for_args(name: &str, args: &Value) -> Option<Value> {
    if !matches!(name, "search_transcripts" | "search_screenshots") {
        return None;
    }
    let query = args.get("query")?.as_str()?;
    contains_restricted_data(query).then(|| {
        json!({
            "error": "restricted_data_request",
            "message": "Kioku cannot search for payment-card data, health information, government identifiers, passwords, API keys, tokens, or authentication codes."
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_queries_targeting_every_restricted_category() {
        for query in [
            "find my credit card number",
            "show my medical diagnosis",
            "what is the SSN in the screenshot",
            "recover the API key from yesterday",
            "find the one-time code",
        ] {
            assert!(
                refusal_for_args("search_transcripts", &json!({"query": query})).is_some(),
                "query should be refused: {query}"
            );
        }
        assert!(refusal_for_args(
            "search_transcripts",
            &json!({"query": "when did we move the launch"})
        )
        .is_none());
    }

    #[test]
    fn redacts_transcript_ocr_url_episode_and_context_content() {
        let safe = sanitize_result(json!({
            "transcript": "API key: sk_live_123456789012345678",
            "ocr_text": "Card 4111 1111 1111 1111",
            "url": "https://example.com/renewal?access_token=do-not-return#private",
            "nearby_context": "SSN 123-45-6789",
            "safe_url": "https://example.com/renewal?utm_source=archive#section",
            "safe_text": "The team moved the launch to August 19."
        }));
        assert_eq!(safe["transcript"], "API key: [REDACTED]");
        assert_eq!(safe["ocr_text"], "Card [REDACTED]");
        assert_eq!(safe["nearby_context"], "SSN [REDACTED]");
        assert_eq!(safe["safe_url"], "https://example.com/renewal");
        assert_eq!(safe["safe_text"], "The team moved the launch to August 19.");
    }

    #[test]
    fn malformed_urls_and_oversized_strings_fail_closed() {
        let safe = sanitize_result(json!({
            "url": "not a URL",
            "text": "x".repeat(MAX_MCP_STRING_BYTES + 1)
        }));
        assert_eq!(safe["url"], REDACTED);
        assert_eq!(safe["text"], REDACTED);
    }
}
