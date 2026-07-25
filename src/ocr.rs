//! OCR projections used by summarization and the web UI.
//!
//! `ocr_text` remains lossless and searchable. `salient_ocr_text` is a bounded,
//! deterministic projection that removes common full-screen chrome and keeps
//! title-like content. The fallback here gives historical rows the improved
//! behavior without rewriting or re-syncing their raw evidence.

use std::collections::HashSet;

const MAX_SALIENT_LINES: usize = 24;
const MAX_SALIENT_CHARS: usize = 1_500;
const MAX_FACTS: usize = 8;

const GENERIC_CHROME: &[&str] = &[
    "apple",
    "file",
    "edit",
    "view",
    "history",
    "bookmarks",
    "develop",
    "window",
    "help",
    "search",
    "home",
    "library",
    "store",
    "account",
    "actions",
    "controls",
    "recently added",
    "family sharing",
    "genres",
    "playlist",
    "movies",
    "tv shows",
    "downloaded",
    "formula 1",
    "mls",
    "sign out",
];

const TITLE_CHROME: &[&str] = &[
    "top results",
    "recently added",
    "family sharing",
    "apple tv",
    "tv shows",
    "movie collection",
    "key screens",
    "raw transcript",
    "kioku cloud dashboard",
];

pub(crate) fn contains_plural_deictic(text: &str) -> bool {
    let value = text.to_lowercase();
    value.contains("these are the two")
        || value.contains("these two")
        || value.contains("both of these")
        || value.contains("the two shown")
        || (value.contains("two movies") && value.contains("these"))
        || value.contains("ces deux")
        || value.contains("voici les deux")
}

pub(crate) fn contains_singular_deictic(text: &str) -> bool {
    let value = text.to_lowercase();
    value.contains("this one") || value.contains("celui-ci") || value.contains("celle-ci")
}

fn compact(line: &str) -> String {
    line.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn words_lower(line: &str) -> Vec<String> {
    line.split(|c: char| !c.is_alphanumeric() && c != '\'' && c != '&')
        .filter(|word| !word.is_empty())
        .map(str::to_lowercase)
        .collect()
}

fn is_boilerplate(line: &str) -> bool {
    let normalized = line.to_lowercase();
    if GENERIC_CHROME.contains(&normalized.as_str()) {
        return true;
    }
    if normalized == "me"
        || normalized
            .strip_prefix("speaker ")
            .is_some_and(|suffix| suffix.chars().all(|c| c.is_ascii_digit()))
    {
        return true;
    }
    let words = words_lower(line);
    if words.is_empty() {
        return true;
    }
    let chrome_count = words
        .iter()
        .filter(|word| GENERIC_CHROME.contains(&word.as_str()))
        .count();
    let chrome_phrase_count = GENERIC_CHROME
        .iter()
        .filter(|phrase| normalized.contains(*phrase))
        .count();
    (words.len() >= 4 && chrome_count * 2 >= words.len())
        || (words.len() >= 6 && chrome_phrase_count >= 4)
}

fn title_score(line: &str) -> i32 {
    let chars: Vec<char> = line.chars().collect();
    let letters: Vec<char> = chars
        .iter()
        .copied()
        .filter(|c| c.is_alphabetic())
        .collect();
    let words = words_lower(line);
    let uppercase = !letters.is_empty() && letters.iter().all(|c| c.is_uppercase());
    let title_case = words.len() >= 2
        && line
            .split_whitespace()
            .filter_map(|word| word.chars().find(|c| c.is_alphabetic()))
            .filter(|c| c.is_uppercase())
            .count()
            >= 2;
    let mut score = 0;
    if uppercase && (2..=10).contains(&words.len()) {
        score += 8;
    }
    if title_case && (2..=10).contains(&words.len()) {
        score += 3;
    }
    if line.contains("Movie") || line.contains("Film") || line.contains("Document") {
        score += 2;
    }
    if line.len() <= 90 {
        score += 1;
    }
    score
}

/// Prefer the device-generated projection and deterministically derive one for
/// historical/older-client rows. The returned text is bounded and never
/// replaces the raw OCR column.
pub(crate) fn select_salient_ocr(raw: Option<&str>, provided: Option<&str>) -> Option<String> {
    if let Some(value) = provided.map(str::trim).filter(|value| !value.is_empty()) {
        return Some(value.chars().take(4_000).collect());
    }
    salient_ocr_from_raw(raw?)
}

pub(crate) fn salient_ocr_from_raw(raw: &str) -> Option<String> {
    #[derive(Debug)]
    struct Candidate {
        index: usize,
        text: String,
        score: i32,
    }

    let mut seen = HashSet::new();
    let mut candidates = Vec::new();
    for (index, raw_line) in raw.lines().enumerate() {
        let line = compact(raw_line);
        let normalized = line.to_lowercase();
        if line.chars().count() < 2 || is_boilerplate(&line) || !seen.insert(normalized) {
            continue;
        }
        let information = line.chars().filter(|c| c.is_alphanumeric()).count();
        if information < 2 {
            continue;
        }
        candidates.push(Candidate {
            index,
            score: title_score(&line),
            text: line,
        });
    }

    candidates.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.index.cmp(&right.index))
    });
    candidates.truncate(MAX_SALIENT_LINES);
    candidates.sort_by_key(|candidate| candidate.index);

    let mut output = Vec::new();
    let mut chars = 0;
    for candidate in candidates {
        let separator = usize::from(!output.is_empty());
        if chars + separator >= MAX_SALIENT_CHARS {
            break;
        }
        let remaining = MAX_SALIENT_CHARS - chars - separator;
        let line: String = candidate.text.chars().take(remaining).collect();
        if line.is_empty() {
            continue;
        }
        chars += separator + line.chars().count();
        output.push(line);
    }
    (!output.is_empty()).then(|| output.join("\n"))
}

fn clean_fact(line: &str) -> Option<String> {
    let mut value = compact(line)
        .trim_matches(|c: char| !c.is_alphanumeric() && c != '\'' && c != '&')
        .to_string();
    for prefix in ["Top Results ", "Recently Added "] {
        if value.to_lowercase().starts_with(&prefix.to_lowercase()) {
            value = value[prefix.len()..].to_string();
        }
    }
    if let Some(index) = value.find(" Movie") {
        value.truncate(index);
    }
    let normalized = value.to_lowercase();
    if value.chars().count() < 3
        || value.chars().count() > 90
        || TITLE_CHROME.iter().any(|chrome| normalized == *chrome)
        || is_boilerplate(&value)
    {
        return None;
    }
    Some(value)
}

/// Extract conservative, display-ready entity/title candidates. These are
/// evidence labels, not inferred facts: callers must never treat them as proof
/// of anything beyond what appeared literally on screen.
pub(crate) fn extract_screen_facts(text: &str) -> Vec<String> {
    let mut facts = Vec::new();
    let mut seen = HashSet::new();
    let lines: Vec<&str> = text.lines().collect();

    for (index, line) in lines.iter().enumerate() {
        let compacted = compact(line);
        let next_is_media_metadata = lines
            .get(index + 1)
            .map(|next| {
                let value = compact(next).to_lowercase();
                value.starts_with("movie ")
                    || value.starts_with("film ")
                    || value.contains("• movie")
            })
            .unwrap_or(false);
        if title_score(&compacted) < 7 && !next_is_media_metadata {
            continue;
        }
        let Some(fact) = clean_fact(&compacted) else {
            continue;
        };
        let normalized = fact.to_lowercase();
        if seen.insert(normalized) {
            facts.push(fact);
        }
        if facts.len() == MAX_FACTS {
            break;
        }
    }
    facts
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPISODE_312_OCR: &str = "TV File Edit Actions View Controls Account Window Help
Home Apple TV Formula 1 MLS Store Library Recently Added Movies TV Shows 4K HDR Downloaded Family Sharing Genres Playlist
Search
MARY POPPINS
Movie • Comedy - Kids & Family
1964 • 2 hr 19 min
Recently Added
MARY POPPINS RETURNS
Movie • Musical - Adventure
2018 • 2 hr 10 min";

    #[test]
    fn salient_fallback_preserves_titles_and_removes_menu_bar() {
        let salient = salient_ocr_from_raw(EPISODE_312_OCR).unwrap();
        assert!(salient.contains("MARY POPPINS"));
        assert!(salient.contains("MARY POPPINS RETURNS"));
        assert!(!salient.contains("File Edit Actions"));
        assert!(!salient.contains("Family Sharing"));
        assert!(!salient.lines().any(|line| line == "Search"));
    }

    #[test]
    fn extracts_two_mary_poppins_screen_facts() {
        let salient = salient_ocr_from_raw(EPISODE_312_OCR).unwrap();
        let facts = extract_screen_facts(&salient);
        assert_eq!(facts, vec!["MARY POPPINS", "MARY POPPINS RETURNS"]);
    }

    #[test]
    fn provided_salient_text_wins_without_mutating_raw() {
        assert_eq!(
            select_salient_ocr(Some("raw boilerplate"), Some("Useful title")).as_deref(),
            Some("Useful title")
        );
    }
}
