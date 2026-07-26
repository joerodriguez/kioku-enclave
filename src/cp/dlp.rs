#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::warn;

use crate::error::Result;

pub const REDACTION_MARKER: &str = "[REDACTED FOR OPENAI]";

/// Verification disposition for a projected text field or record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionDisposition {
    Safe,
    Sanitized,
    Blocked,
}

/// Result of running the redaction pipeline over a text string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionResult {
    pub text: String,
    pub disposition: ProjectionDisposition,
    pub redaction_count: usize,
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

/// Deterministic local redaction pass.
pub fn local_deterministic_redact(input: &str) -> RedactionResult {
    let mut text = input.to_string();
    let mut redaction_count = 0;

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
        text.replace_range(start..end, REDACTION_MARKER);
        redaction_count += 1;
    }

    // 2. High-confidence credential and key shapes (Bearer tokens, API keys, JWTs)
    let jwt_regex =
        regex::Regex::new(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
            .unwrap();
    let api_key_regex =
        regex::Regex::new(r"\b(?:sk|pk|api|key)_[live|test|prod]_[A-Za-z0-9]{16,}\b").unwrap();
    let bearer_regex = regex::Regex::new(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*\b").unwrap();
    let ssn_regex = regex::Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap();

    for re in &[&jwt_regex, &api_key_regex, &bearer_regex, &ssn_regex] {
        let mut spans = Vec::new();
        for mat in re.find_iter(&text) {
            spans.push((mat.start(), mat.end()));
        }
        for (start, end) in spans.into_iter().rev() {
            text.replace_range(start..end, REDACTION_MARKER);
            redaction_count += 1;
        }
    }

    // 3. Sensitive URL credentials and query parameters
    let url_creds_regex = regex::Regex::new(r"https?://[^:\s]+:[^@\s]+@").unwrap();
    let mut url_spans = Vec::new();
    for mat in url_creds_regex.find_iter(&text) {
        url_spans.push((mat.start(), mat.end()));
    }
    for (start, end) in url_spans.into_iter().rev() {
        text.replace_range(start..end, REDACTION_MARKER);
        redaction_count += 1;
    }

    let disposition = if redaction_count > 0 {
        ProjectionDisposition::Sanitized
    } else {
        ProjectionDisposition::Safe
    };

    RedactionResult {
        text,
        disposition,
        redaction_count,
    }
}

/// Google DLP API Client for content.deidentify and content.inspect.
#[derive(Clone)]
pub struct DlpClient {
    http: reqwest::Client,
    project_id: String,
    location: String,
    base_url_override: Option<String>,
    token_override: Option<String>,
}

impl DlpClient {
    pub fn new(project_id: impl Into<String>, location: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap(),
            project_id: project_id.into(),
            location: location.into(),
            base_url_override: None,
            token_override: None,
        }
    }

    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url_override = Some(base_url.into());
        self
    }

    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token_override = Some(token.into());
        self
    }

    fn base_url(&self) -> String {
        self.base_url_override
            .clone()
            .unwrap_or_else(|| "https://dlp.googleapis.com".to_string())
    }

    async fn get_auth_token(&self) -> Result<String> {
        if let Some(ref tok) = self.token_override {
            return Ok(tok.clone());
        }
        // Metadata server token pattern
        let res = self
            .http
            .get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
            .header("Metadata-Flavor", "Google")
            .send()
            .await?;
        if res.status().is_success() {
            let json: Value = res.json().await?;
            if let Some(tok) = json.get("access_token").and_then(|v| v.as_str()) {
                return Ok(tok.to_string());
            }
        }
        Ok("mock_token".to_string())
    }

    /// Calls GCP DLP `projects.locations.content.deidentify`.
    pub async fn deidentify(&self, text: &str) -> Result<RedactionResult> {
        if text.trim().is_empty() {
            return Ok(RedactionResult {
                text: text.to_string(),
                disposition: ProjectionDisposition::Safe,
                redaction_count: 0,
            });
        }

        // Check 0.5 MB size limit
        if text.len() > 500_000 {
            warn!("Payload exceeds 0.5 MB DLP limit — failing closed as Blocked");
            return Ok(RedactionResult {
                text: REDACTION_MARKER.to_string(),
                disposition: ProjectionDisposition::Blocked,
                redaction_count: 1,
            });
        }

        let token = self.get_auth_token().await?;
        let url = format!(
            "{}/v2/projects/{}/locations/{}/content:deidentify",
            self.base_url(),
            self.project_id,
            self.location
        );

        let body = json!({
            "item": {
                "value": text
            },
            "deidentifyConfig": {
                "infoTypeTransformations": {
                    "transformations": [
                        {
                            "primitiveTransformation": {
                                "replaceWithInfoTypeConfig": {}
                            }
                        }
                    ]
                }
            },
            "inspectConfig": {
                "infoTypes": [
                    { "name": "CREDIT_CARD_NUMBER" },
                    { "name": "US_SOCIAL_SECURITY_NUMBER" },
                    { "name": "EMAIL_ADDRESS" },
                    { "name": "PHONE_NUMBER" },
                    { "name": "PASSPORT" }
                ]
            }
        });

        let res = self
            .http
            .post(&url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .await?;

        if !res.status().is_success() {
            warn!(
                "DLP deidentify returned status {} — failing closed",
                res.status()
            );
            return Ok(RedactionResult {
                text: REDACTION_MARKER.to_string(),
                disposition: ProjectionDisposition::Blocked,
                redaction_count: 1,
            });
        }

        let resp_json: Value = res.json().await?;
        let item_text = resp_json
            .pointer("/item/value")
            .and_then(|v| v.as_str())
            .unwrap_or(text);

        let redaction_count = item_text.matches(REDACTION_MARKER).count()
            + item_text.matches("[CREDIT_CARD_NUMBER]").count()
            + item_text.matches("[EMAIL_ADDRESS]").count()
            + item_text.matches("[PHONE_NUMBER]").count();

        let final_text = item_text
            .replace("[CREDIT_CARD_NUMBER]", REDACTION_MARKER)
            .replace("[EMAIL_ADDRESS]", REDACTION_MARKER)
            .replace("[PHONE_NUMBER]", REDACTION_MARKER)
            .replace("[PASSPORT]", REDACTION_MARKER)
            .replace("[US_SOCIAL_SECURITY_NUMBER]", REDACTION_MARKER);

        let disposition = if redaction_count > 0 {
            ProjectionDisposition::Sanitized
        } else {
            ProjectionDisposition::Safe
        };

        Ok(RedactionResult {
            text: final_text,
            disposition,
            redaction_count,
        })
    }

    /// Calls GCP DLP `projects.locations.content.inspect` to evaluate HIPAA Safe Harbor health findings.
    pub async fn inspect(&self, text: &str) -> Result<Vec<String>> {
        if text.trim().is_empty() {
            return Ok(Vec::new());
        }

        let token = self.get_auth_token().await?;
        let url = format!(
            "{}/v2/projects/{}/locations/{}/content:inspect",
            self.base_url(),
            self.project_id,
            self.location
        );

        let body = json!({
            "item": {
                "value": text
            },
            "inspectConfig": {
                "infoTypes": [
                    { "name": "DOCUMENT_TYPE/CONTEXT/HEALTH" },
                    { "name": "MEDICAL_RECORD_NUMBER" },
                    { "name": "HEALTHCARE_NPI" }
                ],
                "minLikelihood": "LIKELY"
            }
        });

        let res = self
            .http
            .post(&url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .await?;

        if !res.status().is_success() {
            warn!(
                "DLP inspect returned status {} — failing closed",
                res.status()
            );
            return Ok(vec!["INSPECT_FAILED_CLOSED".to_string()]);
        }

        let resp_json: Value = res.json().await?;
        let mut findings = Vec::new();
        if let Some(findings_array) = resp_json
            .pointer("/result/findings")
            .and_then(|v| v.as_array())
        {
            for f in findings_array {
                if let Some(name) = f.pointer("/infoType/name").and_then(|v| v.as_str()) {
                    findings.push(name.to_string());
                }
            }
        }

        Ok(findings)
    }
}

/// Evaluates full pipeline (Deterministic + DLP Deidentify + DLP Inspect Safe Harbor Gating).
pub async fn run_full_pipeline(client: &DlpClient, input: &str) -> Result<RedactionResult> {
    // Step 1: Local deterministic pass
    let det_res = local_deterministic_redact(input);

    // Step 2: Google DLP deidentify
    let dlp_res = client.deidentify(&det_res.text).await?;
    let mut combined_count = det_res.redaction_count + dlp_res.redaction_count;
    let mut current_text = dlp_res.text;

    // Step 3: Google DLP inspect for health findings & HIPAA Safe Harbor gating
    let health_findings = client.inspect(&current_text).await?;
    let has_health = !health_findings.is_empty();

    let disposition = if has_health {
        // HIPAA Safe Harbor gating: If health context findings exist, check for identifiable context
        let lower = current_text.to_lowercase();
        let has_identifying = lower.contains("claim")
            || lower.contains("patient")
            || lower.contains("member")
            || lower.contains("dr.")
            || lower.contains("hospital")
            || lower.contains("clinic");

        if has_identifying {
            // Replace with generic safe action
            current_text = "Follow up on a billing issue".to_string();
            combined_count += 1;
            ProjectionDisposition::Sanitized
        } else {
            ProjectionDisposition::Blocked
        }
    } else if combined_count > 0 {
        ProjectionDisposition::Sanitized
    } else {
        ProjectionDisposition::Safe
    };

    Ok(RedactionResult {
        text: current_text,
        disposition,
        redaction_count: combined_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::post, Json, Router};
    use tokio::net::TcpListener;

    #[test]
    fn test_luhn_check() {
        assert!(luhn_check("4532015112830366"));
        assert!(!luhn_check("4532015112830367"));
    }

    #[test]
    fn test_local_deterministic_redact_card() {
        let input = "Paid with card 4532-0151-1283-0366 today.";
        let res = local_deterministic_redact(input);
        assert_eq!(res.disposition, ProjectionDisposition::Sanitized);
        assert!(res.text.contains(REDACTION_MARKER));
        assert!(!res.text.contains("4532"));
    }

    #[test]
    fn test_local_deterministic_redact_bearer_token() {
        let input = "Header: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sSflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5";
        let res = local_deterministic_redact(input);
        assert_eq!(res.disposition, ProjectionDisposition::Sanitized);
        assert!(res.text.contains(REDACTION_MARKER));
    }

    #[tokio::test]
    async fn test_http_mock_server_dlp_pipeline() {
        // Axum HTTP test server pattern to mock Google DLP API
        let app = Router::new()
            .route(
                "/v2/projects/test-proj/locations/us/content:deidentify",
                post(|Json(req): Json<Value>| async move {
                    let val = req
                        .pointer("/item/value")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let replaced = val.replace("John Doe", "[REDACTED FOR OPENAI]");
                    Json(json!({
                        "item": {
                            "value": replaced
                        }
                    }))
                }),
            )
            .route(
                "/v2/projects/test-proj/locations/us/content:inspect",
                post(|Json(_req): Json<Value>| async move {
                    Json(json!({
                        "result": {
                            "findings": [
                                { "infoType": { "name": "DOCUMENT_TYPE/CONTEXT/HEALTH" } }
                            ]
                        }
                    }))
                }),
            );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let base_url = format!("http://{}", addr);
        let client = DlpClient::new("test-proj", "us")
            .with_base_url(base_url)
            .with_token("test-token");

        let res = run_full_pipeline(&client, "Billing discussed for patient John Doe at clinic")
            .await
            .unwrap();
        assert_eq!(res.text, "Follow up on a billing issue");
        assert_eq!(res.disposition, ProjectionDisposition::Sanitized);
    }
}
