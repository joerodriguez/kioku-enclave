//! Immutable authoring labels and simultaneous presentation-only substitution.
//! Graph resolution belongs to the account-qualified PostgreSQL adapter. This
//! module never infers identity from a name or modifies authored/source bytes.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub(crate) enum LabelTarget {
    Profile(i64),
    Cluster(i64),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct AuthoredLabel {
    pub label: String,
    pub target: LabelTarget,
    /// The reserved anonymous label, used if all retained anchors disappear.
    pub fallback_label: String,
    /// Retained turn anchors let a map follow current assignment after a merge
    /// or split without treating a retired profile ID as current authority.
    pub utterance_ids: Vec<i64>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct AuthoredLabelMap {
    pub labels: Vec<AuthoredLabel>,
}

impl AuthoredLabelMap {
    pub(crate) fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }

    pub(crate) fn from_labels(labels: impl IntoIterator<Item = AuthoredLabel>) -> Self {
        let mut combined = BTreeMap::<(String, LabelTarget), AuthoredLabel>::new();
        for label in labels {
            let key = (label.label.clone(), label.target.clone());
            if let Some(existing) = combined.get_mut(&key) {
                existing.utterance_ids.extend(label.utterance_ids);
                existing.utterance_ids.sort_unstable();
                existing.utterance_ids.dedup();
            } else {
                combined.insert(key, label);
            }
        }
        Self {
            labels: combined.into_values().collect(),
        }
    }
}

/// Participant meaning excludes acoustic bookkeeping and reserved slot text.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct SpeakerMeaning {
    pub owner: bool,
    pub person_id: Option<i64>,
    pub name: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct UtteranceIdentity {
    pub utterance_id: i64,
    pub meaning: SpeakerMeaning,
}

/// Source additions initialize their own attribution. They are not upgrades of
/// an existing participant. Withdrawal matters when its participant disappears
/// from the surviving memory; unknown source removal is identity-neutral.
pub(crate) fn participant_meaning_changed(
    previous: &[UtteranceIdentity],
    current: &[UtteranceIdentity],
) -> bool {
    let current_by_id = current
        .iter()
        .map(|entry| (entry.utterance_id, &entry.meaning))
        .collect::<BTreeMap<_, _>>();
    previous
        .iter()
        .any(|before| match current_by_id.get(&before.utterance_id) {
            Some(after) => before.meaning != **after,
            None => {
                (before.meaning.owner || before.meaning.person_id.is_some())
                    && !current.iter().any(|after| after.meaning == before.meaning)
            }
        })
}

#[derive(Clone, Debug, Default)]
pub(crate) struct LabelProjection {
    replacements: Vec<(String, String)>,
}

impl LabelProjection {
    pub(crate) fn new(
        authored: &AuthoredLabelMap,
        current: &BTreeMap<LabelTarget, String>,
    ) -> Self {
        let mut candidates = BTreeMap::<String, BTreeSet<String>>::new();
        for entry in &authored.labels {
            if entry.label.trim().is_empty() {
                continue;
            }
            let fallback = if is_slot_label(&entry.fallback_label) {
                entry.fallback_label.as_str()
            } else {
                "Speaker"
            };
            // A label→voice map cannot distinguish a speaker's name from a
            // mention of someone else with that name. Only reserved graph
            // tokens have enough provenance for automatic text substitution.
            let replacement = if entry.label == "Me"
                || (entry.label != "Speaker" && is_slot_label(&entry.label))
            {
                current
                    .get(&entry.target)
                    .filter(|label| !label.trim().is_empty())
                    .map(String::as_str)
                    .unwrap_or(fallback)
            } else {
                // Retain as a no-op token so a complete ordinary name can
                // shield any shorter reserved token it happens to contain.
                entry.label.as_str()
            };
            candidates
                .entry(entry.label.clone())
                .or_default()
                .insert(replacement.to_owned());
        }
        let mut replacements = candidates
            .into_iter()
            .map(|(label, candidates)| {
                // No-op and ambiguous tokens still consume their whole span:
                // a shorter name must not rewrite part of an unchanged name.
                let replacement = if candidates.len() == 1 {
                    candidates.into_iter().next().unwrap()
                } else {
                    // One authored name can refer to several voices. If their
                    // current labels disagree, keep the presentation anonymous.
                    "Speaker".to_owned()
                };
                (label, replacement)
            })
            .collect::<Vec<_>>();
        // Longest exact token wins. Replacement bytes are never scanned again.
        replacements.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then(a.0.cmp(&b.0)));
        Self { replacements }
    }

    /// Unmapped historical prose cannot borrow another memory's slot namespace
    /// in a new provider request. Neutralize only reserved tokens in that copied
    /// context, preserving the same literal quote/URL protection as presentation.
    pub(crate) fn unmapped_context(authored: &Value) -> Self {
        static TOKENS: std::sync::LazyLock<regex::Regex> =
            std::sync::LazyLock::new(|| regex::Regex::new(r"Me|Speaker [A-Z]+").unwrap());
        let serialized = authored.to_string();
        let mut replacements = TOKENS
            .find_iter(&serialized)
            .map(|token| token.as_str().to_owned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|token| (token, "Speaker".to_owned()))
            .collect::<Vec<_>>();
        replacements.sort_by(|left, right| {
            right
                .0
                .len()
                .cmp(&left.0.len())
                .then_with(|| left.0.cmp(&right.0))
        });
        Self { replacements }
    }

    pub(crate) fn text(&self, authored: &str) -> String {
        if self.replacements.is_empty() {
            return authored.to_owned();
        }
        let protected = protected_text_ranges(authored);
        let mut output = String::with_capacity(authored.len());
        let mut offset = 0;
        while offset < authored.len() {
            let replacement = self.replacements.iter().find(|(token, _)| {
                authored[offset..].starts_with(token)
                    && token_boundary(authored, offset, offset + token.len())
                    && !protected[offset..offset + token.len()].iter().any(|p| *p)
            });
            if let Some((token, replacement)) = replacement {
                output.push_str(replacement);
                offset += token.len();
            } else {
                let character = authored[offset..].chars().next().unwrap();
                output.push(character);
                offset += character.len_utf8();
            }
        }
        output
    }

    /// Call only for authored brief/timeline fields. Unknown keys, evidence,
    /// quotations, URLs, IDs and timestamps are copied without traversal.
    pub(crate) fn human_json(&self, authored: &Value) -> Value {
        match authored {
            Value::String(text) => Value::String(self.text(text)),
            Value::Array(items) => {
                Value::Array(items.iter().map(|item| self.human_json(item)).collect())
            }
            Value::Object(object) => {
                let mut output = object.clone();
                for (key, value) in object {
                    let projected = match key.as_str() {
                        "text" | "heading" | "gist" | "owner" | "title" | "summary"
                        | "overview" | "task" | "question" | "decision" | "label"
                        | "why_it_matters"
                            if value.is_string() =>
                        {
                            Some(self.human_json(value))
                        }
                        "items" | "sections" | "action_items" | "decisions" | "open_questions"
                        | "minute_summaries" | "important_links"
                            if value.is_array() =>
                        {
                            Some(self.human_json(value))
                        }
                        _ => None,
                    };
                    if let Some(projected) = projected {
                        output.insert(key.clone(), projected);
                    }
                }
                Value::Object(output)
            }
            other => other.clone(),
        }
    }
}

/// Each authored block keeps its own frozen namespace. In particular, a new
/// brief must not reinterpret minute buckets retained from earlier authoring.
#[derive(Clone, Debug, Default)]
pub(crate) struct EpisodeLabelProjection {
    pub timeline: LabelProjection,
    pub minutes: BTreeMap<String, LabelProjection>,
    pub actions: LabelProjection,
    pub brief: LabelProjection,
}

impl EpisodeLabelProjection {
    /// Project only the documented human fields on a copied memory envelope.
    pub(crate) fn episode_json(&self, episode: &mut Value) {
        for field in ["title", "summary"] {
            if let Some(text) = episode.get(field).and_then(Value::as_str) {
                episode[field] = Value::String(self.timeline.text(text));
            }
        }
        if let Some(actions) = episode.get("action_items") {
            episode["action_items"] = self.actions.human_json(actions);
        }
        if let Some(brief) = episode.get("final_brief") {
            episode["final_brief"] = self.brief.human_json(brief);
        }
        if let Some(minutes) = episode.get("minute_summaries").cloned() {
            if let Some(text) = episode.get("minutes_text").and_then(Value::as_str) {
                episode["minutes_text"] = Value::String(self.minutes_text(text, &minutes));
            }
            episode["minute_summaries"] = self.minute_summaries(&minutes);
        }
    }

    pub(crate) fn minute_summaries(&self, authored: &Value) -> Value {
        let Some(minutes) = authored.as_array() else {
            return authored.clone();
        };
        Value::Array(
            minutes
                .iter()
                .map(|minute| {
                    minute
                        .get("start")
                        .and_then(Value::as_str)
                        .and_then(|start| self.minutes.get(start))
                        .map_or_else(
                            || minute.clone(),
                            |projection| projection.human_json(minute),
                        )
                })
                .collect(),
        )
    }

    pub(crate) fn minutes_text(&self, authored: &str, minutes: &Value) -> String {
        // Only reconstruct the established plain-text mirror; retain any
        // independently authored historical representation unchanged.
        if let Some(minutes) = minutes.as_array() {
            let raw = minutes
                .iter()
                .map(|minute| minute.get("gist").and_then(Value::as_str))
                .collect::<Option<Vec<_>>>();
            if let Some(gists) = raw {
                // Formation stores newline mirrors; the existing full
                // finalizer stores space mirrors. Preserve either exact form.
                for separator in ["\n", " "] {
                    if gists.join(separator) == authored {
                        return self
                            .minute_summaries(&Value::Array(minutes.clone()))
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|minute| minute["gist"].as_str().unwrap())
                            .collect::<Vec<_>>()
                            .join(separator);
                    }
                }
            }
        }
        authored.to_owned()
    }
}

fn is_slot_label(label: &str) -> bool {
    label == "Speaker"
        || label.strip_prefix("Speaker ").is_some_and(|suffix| {
            !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_uppercase())
        })
}

fn word_character(character: char) -> bool {
    static WORD: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"\w").unwrap());
    WORD.is_match(character.encode_utf8(&mut [0; 4]))
}

fn token_boundary(text: &str, start: usize, end: usize) -> bool {
    !text[..start]
        .chars()
        .next_back()
        .is_some_and(word_character)
        && !text[end..].chars().next().is_some_and(word_character)
}

fn quoted_span_end(text: &str, closing: char) -> usize {
    let mut offset = text.chars().next().unwrap().len_utf8();
    while offset < text.len() {
        let character = text[offset..].chars().next().unwrap();
        if character == '\\' {
            offset += character.len_utf8();
            if let Some(escaped) = text[offset..].chars().next() {
                offset += escaped.len_utf8();
            }
            continue;
        }
        let end = offset + character.len_utf8();
        let apostrophe_inside_word = matches!(closing, '\'' | '’')
            && text[..offset]
                .chars()
                .next_back()
                .is_some_and(word_character)
            && text[end..].chars().next().is_some_and(word_character);
        if character == closing && !apostrophe_inside_word {
            return end;
        }
        offset = end;
    }
    text.len()
}

fn starts_url(text: &str) -> bool {
    static URL: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"(?i)^(?:[a-z][a-z0-9+.-]*://|(?:mailto|tel|urn|data):|www\.)").unwrap()
    });
    URL.is_match(text)
}

/// Conservative protection for quoted/source-like spans in otherwise human
/// text. Structured evidence and link destinations are also excluded above.
fn protected_text_ranges(text: &str) -> Vec<bool> {
    let mut protected = vec![false; text.len()];
    let mut line_start = 0;
    for line in text.split_inclusive('\n') {
        if line.trim_start().starts_with('>') {
            protected[line_start..line_start + line.len()].fill(true);
        }
        line_start += line.len();
    }
    let mut offset = 0;
    while offset < text.len() {
        let rest = &text[offset..];
        let character = rest.chars().next().unwrap();
        let quote_end = match character {
            '"' => Some('"'),
            '“' => Some('”'),
            '‘' => Some('’'),
            '\'' if !text[..offset]
                .chars()
                .next_back()
                .is_some_and(word_character) =>
            {
                Some('\'')
            }
            _ => None,
        };
        let protected_end = if character == '`' {
            let count = rest.bytes().take_while(|byte| *byte == b'`').count();
            let delimiter = &rest[..count];
            Some(
                rest[count..]
                    .find(delimiter)
                    .map_or(text.len(), |end| offset + count + end + count),
            )
        } else if let Some(close) = quote_end {
            Some(offset + quoted_span_end(rest, close))
        } else if let Some(link_target) = rest.strip_prefix("](") {
            let mut depth = 1;
            let mut end = None;
            for (index, character) in link_target.char_indices() {
                match character {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            end = Some(offset + 2 + index + 1);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            Some(end.unwrap_or(text.len()))
        } else if starts_url(rest) {
            Some(
                offset
                    + rest
                        .find(|c: char| c.is_whitespace() || matches!(c, '<' | '>' | '"'))
                        .unwrap_or(rest.len()),
            )
        } else {
            None
        };
        if let Some(end) = protected_end {
            protected[offset..end].fill(true);
            offset = end;
        } else {
            offset += character.len_utf8();
        }
    }
    protected
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn projection(pairs: &[(&str, &str)]) -> LabelProjection {
        let mut current = BTreeMap::new();
        let authored = AuthoredLabelMap {
            labels: pairs
                .iter()
                .enumerate()
                .map(|(index, (from, to))| {
                    let target = LabelTarget::Profile(index as i64 + 1);
                    current.insert(target.clone(), (*to).to_owned());
                    AuthoredLabel {
                        label: (*from).to_owned(),
                        target,
                        fallback_label: "Speaker".into(),
                        utterance_ids: vec![index as i64 + 1],
                    }
                })
                .collect(),
        };
        LabelProjection::new(&authored, &current)
    }

    #[test]
    fn substitution_is_exact_simultaneous_and_preserves_authored_bytes() {
        let authored =
            "Speaker A, Speaker AA, Speaker ABC, Speaker A's plan; Speaker A_1 and xSpeaker A.";
        let original = authored.to_owned();
        let projected =
            projection(&[("Speaker A", "Speaker AA"), ("Speaker AA", "Ana")]).text(authored);
        assert_eq!(
            projected,
            "Speaker AA, Ana, Speaker ABC, Speaker AA's plan; Speaker A_1 and xSpeaker A.",
            "label replacement must be simultaneous and respect complete tokens"
        );
        assert_eq!(
            authored, original,
            "presentation must preserve the raw authored text"
        );
    }

    #[test]
    fn quotations_urls_code_and_structured_sources_are_never_relabelled() {
        let render = projection(&[("Speaker A", "Ana"), ("Me", "Alex")]);
        let text = "Speaker A said \"Speaker A agrees\" and ‘Me agrees’. Me's plan uses `Me` at https://example.test/Me.\n> Speaker A said yes\n[Me](https://example.test/Me)";
        assert_eq!(render.text(text), "Ana said \"Speaker A agrees\" and ‘Me agrees’. Alex's plan uses `Me` at https://example.test/Me.\n> Speaker A said yes\n[Alex](https://example.test/Me)", "literal quotations, URLs and code must remain byte-identical");
        let raw = json!({"heading":"Speaker A's next steps","items":[{"text":"Me will help Speaker A","owner":"Me","due_at":"Me","evidence":[{"quote":"Speaker A","id":"Me"}]}],"url":"https://example.test/Me","unknown":{"text":"Me"}});
        let result = render.human_json(&raw);
        assert_eq!(result["heading"], "Ana's next steps");
        assert_eq!(result["items"][0]["owner"], "Alex");
        for key in ["due_at", "evidence"] {
            assert_eq!(
                result["items"][0][key], raw["items"][0][key],
                "structured source fields must never undergo name substitution"
            );
        }
        assert_eq!(result["url"], raw["url"]);
        assert_eq!(result["unknown"], raw["unknown"]);
    }

    #[test]
    fn minute_projection_preserves_each_authored_namespace_and_actual_mirror_format() {
        let presentation = EpisodeLabelProjection {
            minutes: BTreeMap::from([
                ("first".into(), projection(&[("Speaker A", "Ana")])),
                ("second".into(), projection(&[("Speaker A", "Bao")])),
            ]),
            ..Default::default()
        };
        let minutes = json!([
            {"start":"first","gist":"Speaker A planned work"},
            {"start":"second","gist":"Speaker A agreed"}
        ]);
        let source = minutes.clone();
        for separator in ["\n", " "] {
            let raw = ["Speaker A planned work", "Speaker A agreed"].join(separator);
            assert_eq!(presentation.minutes_text(&raw, &minutes),
                ["Ana planned work", "Bao agreed"].join(separator),
                "minute text must project both formation newline and finalizer space mirrors without mixing namespaces");
        }
        assert_eq!(
            presentation.minute_summaries(&minutes)[1]["gist"],
            "Bao agreed"
        );
        assert_eq!(
            presentation.minutes_text("Independent Speaker A prose", &minutes),
            "Independent Speaker A prose"
        );
        assert_eq!(
            minutes, source,
            "minute presentation must preserve original authored bytes"
        );
    }

    #[test]
    fn conflicting_authored_slots_abstain_and_missing_targets_use_reserved_slots() {
        let mut map = AuthoredLabelMap {
            labels: vec![AuthoredLabel {
                label: "Speaker C".into(),
                target: LabelTarget::Profile(1),
                fallback_label: "Speaker A".into(),
                utterance_ids: vec![1],
            }],
        };
        assert_eq!(
            LabelProjection::new(&map, &BTreeMap::new()).text("Speaker C spoke"),
            "Speaker A spoke",
            "a missing graph target must not invent an attribution"
        );
        map.labels.push(AuthoredLabel {
            label: "Speaker C".into(),
            target: LabelTarget::Profile(2),
            fallback_label: "Speaker B".into(),
            utterance_ids: vec![2],
        });
        assert_eq!(
            LabelProjection::new(&map, &BTreeMap::new()).text("Speaker C spoke"),
            "Speaker spoke",
            "ambiguous erased targets must not select an arbitrary reserved slot"
        );
        let current = BTreeMap::from([
            (LabelTarget::Profile(1), "Ana".into()),
            (LabelTarget::Profile(2), "Bao".into()),
        ]);
        assert_eq!(
            LabelProjection::new(&map, &current).text("Speaker C spoke"),
            "Speaker spoke",
            "an ambiguous authored token must not be assigned to either voice"
        );
        assert_eq!(
            projection(&[("Speaker A", "Zoë 林")]).text("Speaker A's plan"),
            "Zoë 林's plan"
        );
        assert_eq!(
            projection(&[("Speaker A", "Speaker A Speaker AA")]).text("Speaker A"),
            "Speaker A Speaker AA",
            "replacement text must never be substituted recursively"
        );
    }
    #[test]
    fn ordinary_names_and_unmapped_generic_speakers_remain_authored_history() {
        let render = projection(&[("Sarah", "Sofia"), ("Speaker B", "Ana"), ("Speaker", "Bao")]);
        assert_eq!(
            render.text("Sarah asked Speaker B to call Sarah from accounting. Speaker replied."),
            "Sarah asked Ana to call Sarah from accounting. Speaker replied.",
            "an authored label map must never relabel a third-party name or generic Speaker"
        );
        let render = projection(&[("Speaker A", "Alex"), ("Speaker A Lee", "Ana")]);
        assert_eq!(
            render.text("Speaker A Lee spoke to Speaker A"),
            "Speaker A Lee spoke to Alex",
            "a complete ordinary name must shield a shorter reserved token"
        );
        assert_eq!(
            projection(&[("Me", "Alex")]).text("Me\u{301} and Me"),
            "Me\u{301} and Alex",
            "combining marks must remain part of a Unicode word boundary"
        );
    }
    #[test]
    fn escaped_quotations_and_case_insensitive_urls_preserve_literal_spans() {
        let render = projection(&[("Me", "Alex")]);
        let quotes = r#"'Me's friend Me' and "hello \"Me\"" and Me"#;
        assert_eq!(
            render.text(quotes),
            r#"'Me's friend Me' and "hello \"Me\"" and Alex"#,
            "an apostrophe or escaped quote must not expose the rest of a literal quotation"
        );
        let urls = "HTTPS://example.test/Me ftp://example.test/Me MAILTO:Me@example.test www.example.test/Me and Me";
        assert_eq!(render.text(urls), "HTTPS://example.test/Me ftp://example.test/Me MAILTO:Me@example.test www.example.test/Me and Alex",
            "URL schemes and host prefixes must remain protected regardless of case");
    }
    #[test]
    fn revisions_follow_existing_participant_meaning_without_source_or_slot_churn() {
        let unknown = SpeakerMeaning::default();
        let named = SpeakerMeaning {
            owner: false,
            person_id: Some(4),
            name: Some("Sam Lee".into()),
        };
        let turn = |id, meaning| UtteranceIdentity {
            utterance_id: id,
            meaning,
        };
        let before = vec![turn(1, unknown.clone()), turn(2, named.clone())];
        let mut current = before.clone();
        current.push(turn(3, named.clone()));
        assert!(
            !participant_meaning_changed(&before, &current),
            "adding a source or acoustic sample must not manufacture an identity upgrade"
        );
        current[0].meaning = SpeakerMeaning {
            owner: true,
            person_id: None,
            name: None,
        };
        assert!(
            participant_meaning_changed(&before, &current),
            "owner attachment to an existing utterance must advance identity"
        );
        current = before.clone();
        current[1].meaning.name = Some("Sam Smith".into());
        assert!(
            participant_meaning_changed(&before, &current),
            "renaming an existing participant must advance identity"
        );
        current[1].meaning = SpeakerMeaning {
            owner: false,
            person_id: Some(5),
            name: Some("Sam Lee".into()),
        };
        assert!(
            participant_meaning_changed(&before, &current),
            "equal names on different opaque people must remain distinct identity changes"
        );
        current[1].meaning = SpeakerMeaning {
            owner: false,
            person_id: Some(4),
            name: None,
        };
        assert!(
            participant_meaning_changed(&before, &current),
            "withdrawing an accepted name must advance identity"
        );
        assert!(
            !participant_meaning_changed(&before, &[turn(2, named.clone())]),
            "erasing an unknown source does not remove a participant"
        );
        assert!(
            !participant_meaning_changed(
                &[turn(1, named.clone()), turn(2, named.clone())],
                &[turn(2, named)]
            ),
            "removing one of several supports must not withdraw a surviving participant"
        );
        assert!(
            participant_meaning_changed(&before, &[turn(1, unknown)]),
            "erasing the last source for a public participant must advance identity"
        );
    }
}
