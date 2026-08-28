pub const REDACTION_MARKER: &str = "[REDACTED]";

/// Result of running the redaction pipeline over a text string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionResult {
    pub text: String,
}

/// Luhn algorithm check for credit card numbers.
pub fn luhn_check(number: &str) -> bool {
    let digits: Vec<u32> = number.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let mut sum = 0;
    let mut double = false;
    for &digit in digits.iter().rev() {
        if double {
            let mut val = digit * 2;
            if val > 9 {
                val -= 9;
            }
            sum += val;
        } else {
            sum += digit;
        }
        double = !double;
    }
    sum % 10 == 0
}

fn replace_span_smart(text: &mut String, start: usize, end: usize) {
    let needs_prefix_space = start > 0
        && text[..start]
            .chars()
            .last()
            .is_some_and(|c| c.is_alphanumeric());
    let needs_suffix_space = end < text.len()
        && text[end..]
            .chars()
            .next()
            .is_some_and(|c| c.is_alphanumeric());

    let mut replacement = String::new();
    if needs_prefix_space {
        replacement.push(' ');
    }
    replacement.push_str(REDACTION_MARKER);
    if needs_suffix_space {
        replacement.push(' ');
    }
    text.replace_range(start..end, &replacement);
}

/// Deterministic local redaction pass.
pub fn local_deterministic_redact(input: &str) -> RedactionResult {
    let mut text = input.to_string();

    // 1. Credit card numbers with Luhn verification
    let card_regex = regex::Regex::new(r"\b(?:\d[ -]*?){13,19}\b").unwrap();
    let mut replacements = Vec::new();
    for mat in card_regex.find_iter(&text) {
        let matched_str = mat.as_str();
        if luhn_check(matched_str) {
            replacements.push((mat.start(), mat.end()));
        }
    }
    for (start, end) in replacements.into_iter().rev() {
        replace_span_smart(&mut text, start, end);
    }

    // 2. High-confidence credential and key shapes (Bearer tokens, API keys, JWTs, CVV/CVC/CVB)
    let jwt_regex =
        regex::Regex::new(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
            .unwrap();
    let api_key_regex = regex::Regex::new(
        r"(?i)\b(?:sk|pk|api|key)[_-](?:live|test|prod)?[_-]?[A-Za-z0-9_-]{10,}\b",
    )
    .unwrap();
    let bearer_regex = regex::Regex::new(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*\b").unwrap();
    let ssn_regex = regex::Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap();
    let cvv_regex = regex::Regex::new(
        r"(?i)\b(?:cvv2?|cvc2?|cvb|security\s*code|security\s*number|card\s*code|csc)\s*[:=]?\s*\d{3,4}\b",
    )
    .unwrap();
    let spaced_digits_regex = regex::Regex::new(
        r"(?i)\b(?:numbers?|code|claim|billing|id|ssn|card|passport|pin|zip|cvv|cvc|cvb)?\s*[:=]?\s*(?:\d[\s,.-]*){3,16}\b",
    )
    .unwrap();

    let standalone_spaced_digits_regex =
        regex::Regex::new(r"\b\d(?:\s*[\s,.-]\s*\d){2,15}\b").unwrap();
    let health_narrative_regex = regex::Regex::new(
        r"(?i)\b(?:growth|tumor|lesion|biopsy|surgery|knee|elbow|ankle|shoulder|spine|wound|injury|injured|diagnosis|prescription|medication|treatment)\b(?:\s+(?:on|in|of|to|for|with|at|had|was|were|get|removed|my|the|a|an)\s+[a-z]+)*",
    )
    .unwrap();

    for re in &[
        &jwt_regex,
        &api_key_regex,
        &bearer_regex,
        &ssn_regex,
        &cvv_regex,
        &standalone_spaced_digits_regex,
    ] {
        let mut spans = Vec::new();
        for mat in re.find_iter(&text) {
            spans.push((mat.start(), mat.end()));
        }
        for (start, end) in spans.into_iter().rev() {
            replace_span_smart(&mut text, start, end);
        }
    }

    // Spaced numbers/code sequences with context
    let lower = text.to_lowercase();
    if lower.contains("billing")
        || lower.contains("code")
        || lower.contains("number")
        || lower.contains("claim")
        || lower.contains("passport")
        || lower.contains("card")
        || lower.contains("ssn")
        || lower.contains("pin")
        || lower.contains("cvv")
        || lower.contains("cvc")
        || lower.contains("cvb")
        || lower.contains("security")
        || lower.contains("zip")
    {
        let mut digit_spans = Vec::new();
        for mat in spaced_digits_regex.find_iter(&text) {
            digit_spans.push((mat.start(), mat.end()));
        }
        for (start, end) in digit_spans.into_iter().rev() {
            replace_span_smart(&mut text, start, end);
        }
    }

    // Health narrative redaction when medical condition terms are present with identifying/claim context
    let has_health_term = lower.contains("growth")
        || lower.contains("knee")
        || lower.contains("surgery")
        || lower.contains("tumor")
        || lower.contains("biopsy")
        || lower.contains("injury")
        || lower.contains("injured")
        || lower.contains("diagnosis")
        || lower.contains("prescription")
        || lower.contains("medication")
        || lower.contains("treatment")
        || lower.contains("hospital")
        || lower.contains("clinic")
        || lower.contains("doctor");

    let has_health_context = lower.contains("insurance")
        || lower.contains("claim")
        || lower.contains("billing")
        || lower.contains("patient")
        || lower.contains("removed")
        || lower.contains("pay")
        || lower.contains("my ");

    if has_health_term && has_health_context {
        let mut health_spans = Vec::new();
        for mat in health_narrative_regex.find_iter(&text) {
            health_spans.push((mat.start(), mat.end()));
        }
        for (start, end) in health_spans.into_iter().rev() {
            replace_span_smart(&mut text, start, end);
        }
    }

    // 3. Sensitive URL credentials and query parameters
    let url_creds_regex = regex::Regex::new(r"https?://[^:\s]+:[^@\s]+@").unwrap();
    let mut url_spans = Vec::new();
    for mat in url_creds_regex.find_iter(&text) {
        url_spans.push((mat.start(), mat.end()));
    }
    for (start, end) in url_spans.into_iter().rev() {
        replace_span_smart(&mut text, start, end);
    }

    RedactionResult { text }
}

/// Redacts a window/sequence of utterances belonging to an audio segment or time window.
///
/// Concatenates the utterances using newline separators, runs deterministic local redaction
/// over the full window text (allowing cross-utterance context evaluation), and re-slices
/// the sanitized text back into individual utterance outputs.
pub fn redact_utterance_window(utterances: &[(i64, String)]) -> Vec<(i64, RedactionResult)> {
    if utterances.is_empty() {
        return Vec::new();
    }

    let joined_text = utterances
        .iter()
        .map(|(_, text)| text.as_str())
        .collect::<Vec<_>>()
        .join("\n");

    let window_red = local_deterministic_redact(&joined_text);
    let sanitized_lines: Vec<&str> = window_red.text.split('\n').collect();

    utterances
        .iter()
        .enumerate()
        .map(|(idx, (id, orig_text))| {
            let sanitized_text = if idx < sanitized_lines.len() {
                sanitized_lines[idx].trim_end_matches('\r').to_string()
            } else {
                orig_text.clone()
            };

            (
                *id,
                RedactionResult {
                    text: sanitized_text,
                },
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_luhn_check() {
        assert!(luhn_check("4532015112830366"));
        assert!(!luhn_check("4532015112830367"));
    }

    #[test]
    fn test_local_deterministic_redact_card() {
        let input = "Paid with card 4532-0151-1283-0366 today.";
        let res = local_deterministic_redact(input);
        assert!(res.text.contains(REDACTION_MARKER));
        assert!(!res.text.contains("4532"));
    }

    #[test]
    fn test_local_deterministic_redact_bearer_token() {
        let input = "Header: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sSflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5";
        let res = local_deterministic_redact(input);
        assert!(res.text.contains(REDACTION_MARKER));
    }

    #[test]
    fn test_redact_cvv_and_cvb() {
        let input1 = "so I can say something like my credit card number is 918743299419188 and the cvb for that is 145";
        let res1 = local_deterministic_redact(input1);
        assert!(
            !res1.text.contains("145"),
            "CVB 3-digit code 145 must be redacted"
        );
        assert!(res1.text.contains(REDACTION_MARKER));

        let input2 = "with CVV 892, billing zip code 90210";
        let res2 = local_deterministic_redact(input2);
        assert!(
            !res2.text.contains("892"),
            "CVV 3-digit code 892 must be redacted"
        );
    }

    #[test]
    fn test_redact_spaced_claim_digits() {
        let input = "growth on my knee had to get removed and insurance is saying they're not going to pay for it my claim 5 7 8 9.";
        let res = local_deterministic_redact(input);
        assert!(
            !res.text.contains("5 7 8 9"),
            "Spaced claim number 5 7 8 9 must be redacted"
        );
        assert!(res.text.contains(REDACTION_MARKER));
    }

    #[test]
    fn test_redaction_marker_spacing() {
        let input = "my credit card number is 4532-0151-1283-0366 and my zip is 90210";
        let res = local_deterministic_redact(input);
        assert!(
            !res.text.contains("is[REDACTED"),
            "Redaction marker must have space separation from preceding words: got '{}'",
            res.text
        );
        assert!(
            !res.text.contains("OPENAI]and"),
            "Redaction marker must have space separation from succeeding words: got '{}'",
            res.text
        );
    }

    #[test]
    fn test_redact_standalone_spaced_digits() {
        let input1 = "4 4 1 2";
        let res1 = local_deterministic_redact(input1);
        assert_eq!(
            res1.text, REDACTION_MARKER,
            "Standalone spaced 4-digit fragment '4 4 1 2' must be redacted"
        );

        let input2 = "code was 5 7 8 9.";
        let res2 = local_deterministic_redact(input2);
        assert!(
            !res2.text.contains("5 7 8 9"),
            "Spaced 4-digit fragment '5 7 8 9' must be redacted: got '{}'",
            res2.text
        );
    }

    #[test]
    fn test_redact_health_narrative() {
        let input = "growth on my knee had to get removed and insurance is saying they're not going to pay for it my claim";
        let res = local_deterministic_redact(input);
        assert!(
            !res.text.contains("growth on my knee"),
            "Descriptive health condition 'growth on my knee' must be redacted: got '{}'",
            res.text
        );
        assert!(res.text.contains(REDACTION_MARKER));
    }

    #[test]
    fn test_windowed_utterance_redaction_cross_boundary_context() {
        let utterances = vec![
            (
                1i64,
                "so I can say something like my credit card number is".to_string(),
            ),
            (2i64, "9 1 8 7 4 3 2 9 9 4 1 9 1 8 8".to_string()),
            (3i64, "and the CVV for that is".to_string()),
            (4i64, "1 4 5".to_string()),
        ];

        let results = redact_utterance_window(&utterances);
        assert_eq!(results.len(), 4);
        assert_eq!(results[0].0, 1);
        assert_eq!(results[1].0, 2);
        assert_eq!(results[2].0, 3);
        assert_eq!(results[3].0, 4);

        assert!(
            !results[1].1.text.contains("9 1 8 7 4 3"),
            "Card digits in utterance 2 must be redacted via window context: got '{}'",
            results[1].1.text
        );
        assert!(
            results[1].1.text.contains(REDACTION_MARKER),
            "Utterance 2 must contain REDACTION_MARKER"
        );

        assert!(
            !results[3].1.text.contains("1 4 5"),
            "CVV in utterance 4 must be redacted via window context: got '{}'",
            results[3].1.text
        );
        assert!(
            results[3].1.text.contains(REDACTION_MARKER),
            "Utterance 4 must contain REDACTION_MARKER"
        );
    }
}
