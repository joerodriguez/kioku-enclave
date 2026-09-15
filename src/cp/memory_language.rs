//! ADR-0049: the language every authored memory field is written in.
//!
//! Resolution order is the newest recording that carries a companion-stamped
//! `locale_id`, else English. The result governs only text the enclave
//! authors (titles, summary bullets, timeline gists, brief sections, screen
//! descriptions). Transcript turns, the evidence-level `languages` field,
//! names, URLs, on-screen text, and verbatim quotations are never translated.
//! The summarizer and finalizer append [`output_language_rule`] to their
//! system prompts; the reconciler carries the same rule in its committed
//! producer contract and receives the tag as the `memory_language` input
//! field so the request body stays a function of its durable attempt.
use super::CpState;
use crate::error::Result;

/// Authored when no recording has stamped a language: the only language the
/// product copy speaks today.
pub(crate) const DEFAULT_MEMORY_LANGUAGE: &str = "en";

/// RFC 5646 recommends that implementations accept tags of at least 35 bytes.
pub(crate) const MAX_LOCALE_ID_BYTES: usize = 35;

/// BCP-47 syntax accepted from a companion manifest: a 2–8 letter primary
/// language subtag followed by optional 1–8 character alphanumeric subtags.
/// Mirrors the `capture_events_locale_id_bcp47` check in migration 0035.
pub(crate) fn is_bcp47_language_tag(tag: &str) -> bool {
    if tag.is_empty() || tag.len() > MAX_LOCALE_ID_BYTES {
        return false;
    }
    let mut subtags = tag.split('-');
    let primary = subtags.next().unwrap_or_default();
    if !(2..=8).contains(&primary.len()) || !primary.bytes().all(|b| b.is_ascii_alphabetic()) {
        return false;
    }
    subtags.all(|subtag| {
        (1..=8).contains(&subtag.len()) && subtag.bytes().all(|b| b.is_ascii_alphanumeric())
    })
}

/// The tag the authoring prompts receive, from the newest stamped locale.
/// A stored value that fails the syntax check (impossible under the v35 check
/// constraint, kept for defense) falls back to English rather than reaching a
/// prompt.
pub(crate) fn memory_language_from_locale(locale: Option<String>) -> String {
    locale
        .filter(|locale| is_bcp47_language_tag(locale))
        .unwrap_or_else(|| DEFAULT_MEMORY_LANGUAGE.to_string())
}

/// The BCP-47 tag the authoring prompts receive for this account.
pub(crate) async fn resolve_memory_language(state: &CpState, account_id: &str) -> Result<String> {
    Ok(memory_language_from_locale(
        state
            .repositories
            .captures()
            .newest_recording_locale(account_id)
            .await?,
    ))
}

/// System-prompt rule appended by the summarizer and finalizer. `language` is
/// a validated BCP-47 tag; the wording deliberately restates the evidence
/// boundary so translation cannot become a second place for facts to drift.
pub(crate) fn output_language_rule(language: &str) -> String {
    format!(
        "OUTPUT LANGUAGE RULE: the device owner reads memories in the language with BCP-47 tag \"{language}\". \
Write every field you author — title, summary, gists, headings, section items, action items, and descriptions — in that language, \
regardless of the language spoken or shown in the evidence. Report languages as the BCP-47 codes actually heard, never the output language. \
Keep personal names, organization and product names, URLs, and captured on-screen text in their original form. \
Render instructions and requirements directed at the owner in the output language; when the exact original wording of a phrase matters, \
quote it in the original language and add a gloss. Never translate or rewrite the transcript itself."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_bcp47_shapes_the_companions_send() {
        for tag in [
            "en",
            "fr",
            "en-US",
            "fr-CA",
            "pt-BR",
            "zh-Hant-TW",
            "sr-Latn-RS",
            "es-419",
        ] {
            assert!(is_bcp47_language_tag(tag), "{tag}");
        }
    }

    #[test]
    /// Syntax only: "English" is a well-formed eight-letter-or-shorter primary
    /// subtag, so registry membership is deliberately not checked here.
    fn refuses_non_tags() {
        for tag in [
            "",
            "e",
            "en_US",
            "en-",
            "-en",
            "en--US",
            "en US",
            "123",
            "abcdefghi",
            "en-abcdefghi",
            "en\0",
            "en-US-x-private-use-subtags-longer-than-limit",
        ] {
            assert!(!is_bcp47_language_tag(tag), "{tag:?}");
        }
    }

    #[test]
    fn resolution_defaults_to_english_and_keeps_a_stamped_tag() {
        assert_eq!(memory_language_from_locale(None), "en");
        assert_eq!(memory_language_from_locale(Some("fr-CA".into())), "fr-CA");
        assert_eq!(memory_language_from_locale(Some("not a tag".into())), "en");
    }

    #[test]
    fn rule_names_the_tag_and_the_carve_outs() {
        let rule = output_language_rule("fr-CA");
        assert!(rule.starts_with("OUTPUT LANGUAGE RULE:"));
        assert!(rule.contains("BCP-47 tag \"fr-CA\""));
        for carve_out in [
            "codes actually heard",
            "personal names",
            "URLs",
            "on-screen text",
            "quote it in the original language",
            "Never translate or rewrite the transcript",
        ] {
            assert!(rule.contains(carve_out), "{carve_out}");
        }
    }
}
