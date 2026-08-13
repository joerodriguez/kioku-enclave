#![allow(
    dead_code,
    reason = "inactive ADR-0022 Firestore HTTP transport is compiled and tested before runtime authority wiring"
)]

//! Concrete but inactive Firestore REST transport for the ADR-0022 witness.
//!
//! The transport has no environment constructor, credential acquisition, or
//! connection to the live Store/VFS/routes. Callers supply an already opaque
//! bearer token through the adapter boundary. It can issue exactly three RPCs
//! against one named database: `beginTransaction`, one-document `batchGet`,
//! and one-document `commit`.

use crate::archive_v3_firestore_probe::{FirestoreProbeRecord, PROBE_RECORD_BYTES};
use crate::archive_v3_firestore_witness::{
    firestore_timestamp_not_after, parse_exact_batch_get_stream,
    parse_exact_probe_batch_get_stream, valid_firestore_precondition_timestamp, FirestoreProbeRead,
    FirestoreProbeTransport, FirestoreTransaction, FirestoreWitnessNamespace, FirestoreWitnessRead,
    FirestoreWitnessTransport, FirestoreWitnessTransportError, MAX_BATCH_GET_RESPONSE_BYTES,
};
use crate::archive_v3_witness::WITNESS_RECORD_BYTES;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
#[cfg(test)]
use std::net::IpAddr;
use std::{fmt, time::Duration};
use zeroize::Zeroize;

const FIRESTORE_ORIGIN: &str = "https://firestore.googleapis.com/v1";
const MAX_REQUEST_BYTES: usize = 8 * 1024;
const MAX_BEGIN_RESPONSE_BYTES: usize = 2 * 1024;
const MAX_COMMIT_RESPONSE_BYTES: usize = 2 * 1024;
const MAX_ERROR_RESPONSE_BYTES: usize = 4 * 1024;
const MAX_ERROR_MESSAGE_BYTES: usize = 1_024;
const MAX_ERROR_STATUS_BYTES: usize = 128;
const MAX_TRANSACTION_BYTES: usize = 1_024;
const MAX_WITNESS_RECORD_BYTES: usize = WITNESS_RECORD_BYTES;
const MAX_WITNESS_RECORD_BASE64_BYTES: usize = 4 * MAX_WITNESS_RECORD_BYTES.div_ceil(3);
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const HTTP_BODY_TIMEOUT: Duration = Duration::from_secs(15);

/// Fixed-origin REST transport. Its only construction is intentionally
/// provider-neutral and inactive; a later explicitly reviewed runtime slice
/// must supply the namespace and token source.
pub(crate) struct FirestoreWitnessRestTransport {
    http: reqwest::Client,
    origin: String,
    namespace: FirestoreWitnessNamespace,
}

impl FirestoreWitnessRestTransport {
    /// Creates a production-origin transport. This does not perform I/O,
    /// inspect environment variables, acquire a token, or enable authority.
    pub(crate) fn new(
        namespace: FirestoreWitnessNamespace,
    ) -> std::result::Result<Self, FirestoreWitnessTransportError> {
        Self::new_at_origin(FIRESTORE_ORIGIN, namespace)
    }

    fn new_at_origin(
        origin: &str,
        namespace: FirestoreWitnessNamespace,
    ) -> std::result::Result<Self, FirestoreWitnessTransportError> {
        if !valid_production_origin(origin) {
            #[cfg(not(test))]
            return Err(FirestoreWitnessTransportError::Protocol);
            #[cfg(test)]
            if !valid_test_origin(origin) {
                return Err(FirestoreWitnessTransportError::Protocol);
            }
        }
        let http = reqwest::Client::builder()
            .use_rustls_tls()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(HTTP_CONNECT_TIMEOUT)
            .timeout(HTTP_REQUEST_TIMEOUT)
            .build()
            .map_err(|_| FirestoreWitnessTransportError::Unavailable)?;
        Ok(Self {
            http,
            origin: origin.trim_end_matches('/').to_owned(),
            namespace,
        })
    }

    /// Loopback injection exists only for real local HTTP tests. Production
    /// code cannot select a different origin.
    #[cfg(test)]
    fn new_with_test_origin(
        origin: &str,
        namespace: FirestoreWitnessNamespace,
    ) -> std::result::Result<Self, FirestoreWitnessTransportError> {
        Self::new_at_origin(origin, namespace)
    }

    fn rpc_url(&self, rpc: &str) -> String {
        format!(
            "{}/{}/documents:{rpc}",
            self.origin,
            self.namespace.database_resource()
        )
    }

    fn validate_begin_request(request: &Value) -> bool {
        request == &json!({"options": {"readWrite": {}}})
    }

    fn validate_batch_get_request(
        &self,
        request: &Value,
        transaction: Option<&FirestoreTransaction>,
    ) -> bool {
        let Some(object) = request.as_object() else {
            return false;
        };
        let expected_keys = if transaction.is_some() { 2 } else { 1 };
        if object.len() != expected_keys {
            return false;
        }
        let Some(documents) = object.get("documents").and_then(Value::as_array) else {
            return false;
        };
        if documents.len() != 1
            || !documents[0]
                .as_str()
                .is_some_and(|document| self.namespace.is_canonical_document(document))
        {
            return false;
        }
        match (transaction, object.get("transaction")) {
            (None, None) => true,
            (Some(transaction), Some(Value::String(encoded))) => {
                canonical_base64_decodes_to(encoded, transaction.bytes())
            }
            _ => false,
        }
    }

    fn validate_commit_request(&self, request: &Value, transaction: &FirestoreTransaction) -> bool {
        let Some(object) = request.as_object() else {
            return false;
        };
        if object.len() != 2
            || !object
                .get("transaction")
                .and_then(Value::as_str)
                .is_some_and(|encoded| canonical_base64_decodes_to(encoded, transaction.bytes()))
        {
            return false;
        }
        let Some(writes) = object.get("writes").and_then(Value::as_array) else {
            return false;
        };
        if writes.len() != 1 {
            return false;
        }
        let Some(write) = writes[0].as_object() else {
            return false;
        };
        if write.len() != 2 {
            return false;
        }
        let Some(update) = write.get("update").and_then(Value::as_object) else {
            return false;
        };
        if update.len() != 2
            || !update
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|document| self.namespace.is_canonical_document(document))
        {
            return false;
        }
        let Some(fields) = update.get("fields").and_then(Value::as_object) else {
            return false;
        };
        if fields.len() != 1 {
            return false;
        }
        let Some(encoded) = fields
            .get("r")
            .and_then(Value::as_object)
            .filter(|field| field.len() == 1)
            .and_then(|field| field.get("bytesValue"))
            .and_then(Value::as_str)
        else {
            return false;
        };
        if !canonical_fixed_record_base64(encoded) {
            return false;
        }
        let Some(precondition) = write.get("currentDocument").and_then(Value::as_object) else {
            return false;
        };
        match (
            precondition.get("exists"),
            precondition.get("updateTime"),
            precondition.len(),
        ) {
            (Some(Value::Bool(false)), None, 1) => true,
            (None, Some(Value::String(timestamp)), 1) => {
                valid_firestore_precondition_timestamp(timestamp)
            }
            _ => false,
        }
    }

    fn validate_probe_batch_get_request(
        &self,
        request: &Value,
        transaction: Option<&FirestoreTransaction>,
    ) -> bool {
        let Some(object) = request.as_object() else {
            return false;
        };
        if object.len() != usize::from(transaction.is_some()) + 1 {
            return false;
        }
        let exact_document = object
            .get("documents")
            .and_then(Value::as_array)
            .filter(|documents| documents.len() == 1)
            .and_then(|documents| documents[0].as_str())
            .is_some_and(|document| self.namespace.is_probe_document(document));
        exact_document
            && match (transaction, object.get("transaction")) {
                (None, None) => true,
                (Some(transaction), Some(Value::String(encoded))) => {
                    canonical_base64_decodes_to(encoded, transaction.bytes())
                }
                _ => false,
            }
    }

    fn validate_probe_commit_request(
        &self,
        request: &Value,
        transaction: &FirestoreTransaction,
    ) -> bool {
        let Some(object) = request.as_object() else {
            return false;
        };
        if object.len() != 2
            || !object
                .get("transaction")
                .and_then(Value::as_str)
                .is_some_and(|value| canonical_base64_decodes_to(value, transaction.bytes()))
        {
            return false;
        }
        let Some(write) = object
            .get("writes")
            .and_then(Value::as_array)
            .filter(|writes| writes.len() == 1)
            .and_then(|writes| writes[0].as_object())
            .filter(|write| write.len() == 2)
        else {
            return false;
        };
        let Some(update) = write
            .get("update")
            .and_then(Value::as_object)
            .filter(|update| update.len() == 2)
        else {
            return false;
        };
        if !update
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|name| self.namespace.is_probe_document(name))
        {
            return false;
        }
        let valid_record = update
            .get("fields")
            .and_then(Value::as_object)
            .filter(|fields| fields.len() == 1)
            .and_then(|fields| fields.get("r"))
            .and_then(Value::as_object)
            .filter(|field| field.len() == 1)
            .and_then(|field| field.get("bytesValue"))
            .and_then(Value::as_str)
            .is_some_and(canonical_probe_record_base64);
        if !valid_record {
            return false;
        }
        let Some(precondition) = write.get("currentDocument").and_then(Value::as_object) else {
            return false;
        };
        matches!(
            (
                precondition.get("exists"),
                precondition.get("updateTime"),
                precondition.len()
            ),
            (Some(Value::Bool(false)), None, 1)
        ) || matches!(
            (precondition.get("exists"), precondition.get("updateTime"), precondition.len()),
            (None, Some(Value::String(timestamp)), 1)
                if valid_firestore_precondition_timestamp(timestamp)
        )
    }

    async fn post_json(
        &self,
        rpc: &str,
        bearer_token: &str,
        request: Value,
    ) -> std::result::Result<reqwest::Response, FirestoreWitnessTransportError> {
        if !valid_bearer_token(bearer_token.as_bytes()) {
            return Err(FirestoreWitnessTransportError::Protocol);
        }
        let body =
            serde_json::to_vec(&request).map_err(|_| FirestoreWitnessTransportError::Protocol)?;
        if body.len() > MAX_REQUEST_BYTES {
            return Err(FirestoreWitnessTransportError::TooLarge);
        }
        self.http
            .post(self.rpc_url(rpc))
            .header(reqwest::header::ACCEPT, "application/json")
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .bearer_auth(bearer_token)
            .body(body)
            .send()
            .await
            .map_err(|_| FirestoreWitnessTransportError::Unavailable)
    }

    async fn post_commit_json(
        &self,
        bearer_token: &str,
        request: Value,
    ) -> std::result::Result<reqwest::Response, FirestoreWitnessTransportError> {
        if !valid_bearer_token(bearer_token.as_bytes()) {
            return Err(FirestoreWitnessTransportError::Protocol);
        }
        let body =
            serde_json::to_vec(&request).map_err(|_| FirestoreWitnessTransportError::Protocol)?;
        if body.len() > MAX_REQUEST_BYTES {
            return Err(FirestoreWitnessTransportError::TooLarge);
        }
        let request = self
            .http
            .post(self.rpc_url("commit"))
            .header(reqwest::header::ACCEPT, "application/json")
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .bearer_auth(bearer_token)
            .body(body)
            // A request-build failure happens before any bytes can leave the
            // process, so it is a definite availability failure rather than
            // an ambiguous commit outcome.
            .build()
            .map_err(|_| FirestoreWitnessTransportError::Unavailable)?;
        self.http
            .execute(request)
            .await
            // Once commit bytes were offered to the network, no transport
            // failure may be represented as a definite non-commit.
            .map_err(|error| {
                if error.is_connect() {
                    FirestoreWitnessTransportError::Unavailable
                } else {
                    FirestoreWitnessTransportError::OutcomeUnknown
                }
            })
    }
}

#[async_trait::async_trait]
impl FirestoreWitnessTransport for FirestoreWitnessRestTransport {
    async fn begin_read_write(
        &self,
        bearer_token: &str,
        request_json: Value,
    ) -> std::result::Result<FirestoreTransaction, FirestoreWitnessTransportError> {
        if !Self::validate_begin_request(&request_json) {
            return Err(FirestoreWitnessTransportError::Protocol);
        }
        let response = self
            .post_json("beginTransaction", bearer_token, request_json)
            .await?;
        if !response.status().is_success() {
            return Err(read_error_response(response).await?);
        }
        let body = bounded_body(response, MAX_BEGIN_RESPONSE_BYTES).await?;
        parse_begin_response(&body)
    }

    async fn batch_get_exact(
        &self,
        bearer_token: &str,
        transaction: &FirestoreTransaction,
        request_json: Value,
    ) -> std::result::Result<FirestoreWitnessRead, FirestoreWitnessTransportError> {
        if !self.validate_batch_get_request(&request_json, Some(transaction)) {
            return Err(FirestoreWitnessTransportError::Protocol);
        }
        let document = request_json["documents"][0]
            .as_str()
            .expect("validated request")
            .to_owned();
        let response = self
            .post_json("batchGet", bearer_token, request_json)
            .await?;
        if !response.status().is_success() {
            return Err(read_error_response(response).await?);
        }
        let body = bounded_body(response, MAX_BATCH_GET_RESPONSE_BYTES).await?;
        parse_batch_get_response_array(&body, &document)
    }

    async fn read_exact(
        &self,
        bearer_token: &str,
        request_json: Value,
    ) -> std::result::Result<FirestoreWitnessRead, FirestoreWitnessTransportError> {
        if !self.validate_batch_get_request(&request_json, None) {
            return Err(FirestoreWitnessTransportError::Protocol);
        }
        let document = request_json["documents"][0]
            .as_str()
            .expect("validated request")
            .to_owned();
        let response = self
            .post_json("batchGet", bearer_token, request_json)
            .await?;
        if !response.status().is_success() {
            return Err(read_error_response(response).await?);
        }
        let body = bounded_body(response, MAX_BATCH_GET_RESPONSE_BYTES).await?;
        parse_batch_get_response_array(&body, &document)
    }

    async fn commit_full_record(
        &self,
        bearer_token: &str,
        transaction: &FirestoreTransaction,
        request_json: Value,
    ) -> std::result::Result<(), FirestoreWitnessTransportError> {
        if !self.validate_commit_request(&request_json, transaction) {
            return Err(FirestoreWitnessTransportError::Protocol);
        }
        let response = self.post_commit_json(bearer_token, request_json).await?;
        if !response.status().is_success() {
            return commit_error_response(response).await;
        }
        let body = bounded_body(response, MAX_COMMIT_RESPONSE_BYTES)
            .await
            .map_err(|_| FirestoreWitnessTransportError::OutcomeUnknown)?;
        parse_commit_response(&body).map_err(|_| FirestoreWitnessTransportError::OutcomeUnknown)
    }
}

#[async_trait::async_trait]
impl FirestoreProbeTransport for FirestoreWitnessRestTransport {
    async fn begin_probe_transaction(
        &self,
        bearer_token: &str,
        request_json: Value,
    ) -> std::result::Result<FirestoreTransaction, FirestoreWitnessTransportError> {
        self.begin_read_write(bearer_token, request_json).await
    }

    async fn batch_get_probe(
        &self,
        bearer_token: &str,
        transaction: &FirestoreTransaction,
        request_json: Value,
    ) -> std::result::Result<FirestoreProbeRead, FirestoreWitnessTransportError> {
        if !self.validate_probe_batch_get_request(&request_json, Some(transaction)) {
            return Err(FirestoreWitnessTransportError::Protocol);
        }
        let document = request_json["documents"][0]
            .as_str()
            .expect("validated request")
            .to_owned();
        let response = self
            .post_json("batchGet", bearer_token, request_json)
            .await?;
        if !response.status().is_success() {
            return Err(read_error_response(response).await?);
        }
        let body = bounded_body(response, MAX_BATCH_GET_RESPONSE_BYTES).await?;
        parse_probe_batch_get_response_array(&body, &document)
    }

    async fn read_probe(
        &self,
        bearer_token: &str,
        request_json: Value,
    ) -> std::result::Result<FirestoreProbeRead, FirestoreWitnessTransportError> {
        if !self.validate_probe_batch_get_request(&request_json, None) {
            return Err(FirestoreWitnessTransportError::Protocol);
        }
        let document = request_json["documents"][0]
            .as_str()
            .expect("validated request")
            .to_owned();
        let response = self
            .post_json("batchGet", bearer_token, request_json)
            .await?;
        if !response.status().is_success() {
            return Err(read_error_response(response).await?);
        }
        let body = bounded_body(response, MAX_BATCH_GET_RESPONSE_BYTES).await?;
        parse_probe_batch_get_response_array(&body, &document)
    }

    async fn commit_probe_record(
        &self,
        bearer_token: &str,
        transaction: &FirestoreTransaction,
        request_json: Value,
    ) -> std::result::Result<(), FirestoreWitnessTransportError> {
        if !self.validate_probe_commit_request(&request_json, transaction) {
            return Err(FirestoreWitnessTransportError::Protocol);
        }
        let response = self.post_commit_json(bearer_token, request_json).await?;
        if !response.status().is_success() {
            return commit_error_response(response).await;
        }
        let body = bounded_body(response, MAX_COMMIT_RESPONSE_BYTES)
            .await
            .map_err(|_| FirestoreWitnessTransportError::OutcomeUnknown)?;
        parse_commit_response(&body).map_err(|_| FirestoreWitnessTransportError::OutcomeUnknown)
    }
}

fn valid_production_origin(origin: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(origin) else {
        return false;
    };
    url.scheme() == "https"
        && url.host_str() == Some("firestore.googleapis.com")
        && url.port().is_none()
        && url.path() == "/v1"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none()
}

#[cfg(test)]
fn valid_test_origin(origin: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(origin) else {
        return false;
    };
    url.scheme() == "http"
        && url.port().is_some()
        && url.path() == "/v1"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none()
        && url
            .host_str()
            .and_then(|host| host.parse::<IpAddr>().ok())
            .is_some_and(|address| address.is_loopback())
}

fn valid_bearer_token(token: &[u8]) -> bool {
    !token.is_empty()
        && token.len() <= 16_384
        && token
            .iter()
            .all(|byte| byte.is_ascii_graphic() && !matches!(*byte, b'"' | b'\\'))
}

fn canonical_base64_decodes_to(encoded: &str, expected: &[u8]) -> bool {
    STANDARD.encode(expected) == encoded
}

fn canonical_fixed_record_base64(encoded: &str) -> bool {
    if encoded.len() != MAX_WITNESS_RECORD_BASE64_BYTES {
        return false;
    }
    let Ok(decoded) = STANDARD.decode(encoded) else {
        return false;
    };
    decoded.len() == MAX_WITNESS_RECORD_BYTES && STANDARD.encode(decoded) == encoded
}

fn canonical_probe_record_base64(encoded: &str) -> bool {
    let Ok(decoded) = STANDARD.decode(encoded) else {
        return false;
    };
    decoded.len() == PROBE_RECORD_BYTES
        && STANDARD.encode(&decoded) == encoded
        && FirestoreProbeRecord::decode(&decoded).is_some()
}

async fn bounded_body(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> std::result::Result<Vec<u8>, FirestoreWitnessTransportError> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(FirestoreWitnessTransportError::TooLarge);
    }
    let capacity = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or(0)
        .min(max_bytes);
    let mut body = Vec::with_capacity(capacity);
    loop {
        let next = tokio::time::timeout(HTTP_BODY_TIMEOUT, response.chunk())
            .await
            .map_err(|_| FirestoreWitnessTransportError::Unavailable)?
            .map_err(|_| FirestoreWitnessTransportError::Unavailable)?;
        let Some(chunk) = next else {
            break;
        };
        let total = body
            .len()
            .checked_add(chunk.len())
            .ok_or(FirestoreWitnessTransportError::TooLarge)?;
        if total > max_bytes {
            return Err(FirestoreWitnessTransportError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Firestore's REST transcoder returns `batchGet` as a JSON array. Require the
/// entire bounded response to be exactly one object and pass only that object
/// through the shared strict witness parser.
fn parse_batch_get_response_array(
    body: &[u8],
    expected_document: &str,
) -> std::result::Result<FirestoreWitnessRead, FirestoreWitnessTransportError> {
    let value: Value =
        serde_json::from_slice(body).map_err(|_| FirestoreWitnessTransportError::Protocol)?;
    let responses = value
        .as_array()
        .ok_or(FirestoreWitnessTransportError::Protocol)?;
    if responses.len() != 1 || !responses[0].is_object() {
        return Err(FirestoreWitnessTransportError::Protocol);
    }
    let response =
        serde_json::to_vec(&responses[0]).map_err(|_| FirestoreWitnessTransportError::Protocol)?;
    parse_exact_batch_get_stream([response.as_slice()], expected_document)
}

fn parse_probe_batch_get_response_array(
    body: &[u8],
    expected_document: &str,
) -> std::result::Result<FirestoreProbeRead, FirestoreWitnessTransportError> {
    let value: Value =
        serde_json::from_slice(body).map_err(|_| FirestoreWitnessTransportError::Protocol)?;
    let responses = value
        .as_array()
        .filter(|responses| responses.len() == 1 && responses[0].is_object())
        .ok_or(FirestoreWitnessTransportError::Protocol)?;
    let response =
        serde_json::to_vec(&responses[0]).map_err(|_| FirestoreWitnessTransportError::Protocol)?;
    parse_exact_probe_batch_get_stream([response.as_slice()], expected_document)
}

fn parse_begin_response(
    body: &[u8],
) -> std::result::Result<FirestoreTransaction, FirestoreWitnessTransportError> {
    let value: Value =
        serde_json::from_slice(body).map_err(|_| FirestoreWitnessTransportError::Protocol)?;
    let Some(object) = value.as_object() else {
        return Err(FirestoreWitnessTransportError::Protocol);
    };
    if object.len() != 1 {
        return Err(FirestoreWitnessTransportError::Protocol);
    }
    let encoded = object
        .get("transaction")
        .and_then(Value::as_str)
        .ok_or(FirestoreWitnessTransportError::Protocol)?;
    let mut decoded = STANDARD
        .decode(encoded)
        .map_err(|_| FirestoreWitnessTransportError::Protocol)?;
    if decoded.is_empty()
        || decoded.len() > MAX_TRANSACTION_BYTES
        || STANDARD.encode(&decoded) != encoded
    {
        return Err(FirestoreWitnessTransportError::Protocol);
    }
    let transaction = FirestoreTransaction::new(&decoded);
    decoded.zeroize();
    transaction
}

fn parse_commit_response(body: &[u8]) -> std::result::Result<(), FirestoreWitnessTransportError> {
    let value: Value =
        serde_json::from_slice(body).map_err(|_| FirestoreWitnessTransportError::Protocol)?;
    let Some(object) = value.as_object() else {
        return Err(FirestoreWitnessTransportError::Protocol);
    };
    if object.len() != 2 {
        return Err(FirestoreWitnessTransportError::Protocol);
    }
    let Some(results) = object.get("writeResults").and_then(Value::as_array) else {
        return Err(FirestoreWitnessTransportError::Protocol);
    };
    if results.len() != 1 {
        return Err(FirestoreWitnessTransportError::Protocol);
    }
    let Some(result) = results[0].as_object() else {
        return Err(FirestoreWitnessTransportError::Protocol);
    };
    let Some(update_time) = result.get("updateTime").and_then(Value::as_str) else {
        return Err(FirestoreWitnessTransportError::Protocol);
    };
    let Some(commit_time) = object.get("commitTime").and_then(Value::as_str) else {
        return Err(FirestoreWitnessTransportError::Protocol);
    };
    let valid_transform_results = match result.get("transformResults") {
        None => result.len() == 1,
        Some(Value::Array(results)) => result.len() == 2 && results.is_empty(),
        _ => false,
    };
    if !valid_transform_results || !firestore_timestamp_not_after(update_time, commit_time) {
        return Err(FirestoreWitnessTransportError::Protocol);
    }
    Ok(())
}

struct GoogleError {
    status: String,
}

fn parse_google_error(
    body: &[u8],
    http_status: reqwest::StatusCode,
) -> std::result::Result<GoogleError, FirestoreWitnessTransportError> {
    let value: Value =
        serde_json::from_slice(body).map_err(|_| FirestoreWitnessTransportError::Protocol)?;
    let envelope = match &value {
        Value::Object(_) => &value,
        Value::Array(values) if values.len() == 1 && values[0].is_object() => &values[0],
        _ => return Err(FirestoreWitnessTransportError::Protocol),
    };
    let Some(top) = envelope.as_object() else {
        return Err(FirestoreWitnessTransportError::Protocol);
    };
    if top.len() != 1 {
        return Err(FirestoreWitnessTransportError::Protocol);
    }
    let Some(error) = top.get("error").and_then(Value::as_object) else {
        return Err(FirestoreWitnessTransportError::Protocol);
    };
    let valid_details = match error.get("details") {
        None => error.len() == 3,
        Some(Value::Array(_)) => error.len() == 4,
        _ => false,
    };
    if !valid_details
        || error.get("code").and_then(Value::as_u64) != Some(u64::from(http_status.as_u16()))
    {
        return Err(FirestoreWitnessTransportError::Protocol);
    }
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .ok_or(FirestoreWitnessTransportError::Protocol)?;
    let status = error
        .get("status")
        .and_then(Value::as_str)
        .ok_or(FirestoreWitnessTransportError::Protocol)?;
    if message.is_empty()
        || message.len() > MAX_ERROR_MESSAGE_BYTES
        || status.is_empty()
        || status.len() > MAX_ERROR_STATUS_BYTES
        || !status
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte == b'_')
    {
        return Err(FirestoreWitnessTransportError::Protocol);
    }
    Ok(GoogleError {
        status: status.to_owned(),
    })
}

async fn read_error_response(
    response: reqwest::Response,
) -> std::result::Result<FirestoreWitnessTransportError, FirestoreWitnessTransportError> {
    let status = response.status();
    let body = bounded_body(response, MAX_ERROR_RESPONSE_BYTES).await?;
    let _error = parse_google_error(&body, status)?;
    Ok(read_error_status(status))
}

fn read_error_status(status: reqwest::StatusCode) -> FirestoreWitnessTransportError {
    if status == reqwest::StatusCode::NOT_FOUND {
        FirestoreWitnessTransportError::EndpointNotFound
    } else if status.is_server_error()
        || matches!(
            status,
            reqwest::StatusCode::TOO_MANY_REQUESTS
                | reqwest::StatusCode::REQUEST_TIMEOUT
                | reqwest::StatusCode::UNAUTHORIZED
                | reqwest::StatusCode::FORBIDDEN
        )
    {
        FirestoreWitnessTransportError::Unavailable
    } else {
        FirestoreWitnessTransportError::Protocol
    }
}

async fn commit_error_response(
    response: reqwest::Response,
) -> std::result::Result<(), FirestoreWitnessTransportError> {
    let status = response.status();
    let body = bounded_body(response, MAX_ERROR_RESPONSE_BYTES).await;
    if status.is_server_error()
        || matches!(
            status,
            reqwest::StatusCode::TOO_MANY_REQUESTS | reqwest::StatusCode::REQUEST_TIMEOUT
        )
    {
        // The status itself signals uncertainty even if an intermediary
        // truncated an otherwise canonical Google error envelope.
        return Err(FirestoreWitnessTransportError::OutcomeUnknown);
    }
    let body = body?;
    let error = parse_google_error(&body, status)?;
    if status == reqwest::StatusCode::NOT_FOUND {
        Err(FirestoreWitnessTransportError::EndpointNotFound)
    } else if status == reqwest::StatusCode::CONFLICT && error.status == "ABORTED" {
        Err(FirestoreWitnessTransportError::Aborted)
    } else if status == reqwest::StatusCode::BAD_REQUEST && error.status == "FAILED_PRECONDITION" {
        Err(FirestoreWitnessTransportError::PreconditionFailed)
    } else if matches!(
        status,
        reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
    ) {
        Err(FirestoreWitnessTransportError::Unavailable)
    } else {
        Err(FirestoreWitnessTransportError::Protocol)
    }
}

impl fmt::Debug for FirestoreWitnessRestTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FirestoreWitnessRestTransport(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive_v3_witness::WITNESS_RECORD_BYTES;
    use std::sync::{Arc, Mutex};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::JoinHandle,
    };

    const PROJECT: &str = "project-1";
    const DATABASE: &str = "witness-db";
    const TIME: &str = "2026-01-02T03:04:05.123Z";

    struct Reply {
        status: &'static str,
        body: Vec<u8>,
        fragments: Vec<usize>,
        close: bool,
    }
    #[derive(Debug)]
    struct Request {
        method: String,
        target: String,
        headers: String,
        body: Vec<u8>,
    }
    struct Server {
        origin: String,
        requests: Arc<Mutex<Vec<Request>>>,
        task: JoinHandle<()>,
    }
    impl Server {
        async fn new(replies: Vec<Reply>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin = format!("http://{}", listener.local_addr().unwrap());
            let requests = Arc::new(Mutex::new(Vec::new()));
            let recorded = Arc::clone(&requests);
            let task = tokio::spawn(async move {
                for reply in replies {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let request = read_request(&mut stream).await;
                    recorded.lock().unwrap().push(request);
                    if reply.close {
                        continue;
                    }
                    let head = format!(
                        "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        reply.status,
                        reply.body.len()
                    );
                    stream.write_all(head.as_bytes()).await.unwrap();
                    let mut offset = 0;
                    for length in reply.fragments {
                        let end = (offset + length).min(reply.body.len());
                        stream.write_all(&reply.body[offset..end]).await.unwrap();
                        offset = end;
                    }
                    stream.write_all(&reply.body[offset..]).await.unwrap();
                }
            });
            Self {
                origin,
                requests,
                task,
            }
        }
        async fn finish(self) -> Vec<Request> {
            self.task.await.unwrap();
            Arc::try_unwrap(self.requests)
                .unwrap()
                .into_inner()
                .unwrap()
        }
    }
    async fn read_request(stream: &mut tokio::net::TcpStream) -> Request {
        let mut bytes = Vec::new();
        let mut chunk = [0; 1024];
        let header_end = loop {
            let count = stream.read(&mut chunk).await.unwrap();
            assert_ne!(count, 0);
            bytes.extend_from_slice(&chunk[..count]);
            if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                break index + 4;
            }
        };
        let headers = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.strip_prefix("content-length: ")
                    .or_else(|| line.strip_prefix("Content-Length: "))
            })
            .unwrap_or("0")
            .parse::<usize>()
            .unwrap();
        while bytes.len() - header_end < content_length {
            let count = stream.read(&mut chunk).await.unwrap();
            assert_ne!(count, 0);
            bytes.extend_from_slice(&chunk[..count]);
        }
        let mut parts = headers.lines().next().unwrap().split_whitespace();
        Request {
            method: parts.next().unwrap().to_owned(),
            target: parts.next().unwrap().to_owned(),
            headers,
            body: bytes[header_end..header_end + content_length].to_vec(),
        }
    }
    fn reply(status: &'static str, body: &str) -> Reply {
        Reply {
            status,
            body: body.as_bytes().to_vec(),
            fragments: Vec::new(),
            close: false,
        }
    }
    fn fragmented(status: &'static str, body: &str, fragments: &[usize]) -> Reply {
        Reply {
            status,
            body: body.as_bytes().to_vec(),
            fragments: fragments.to_vec(),
            close: false,
        }
    }
    fn error(code: u16, status: &str) -> String {
        format!(r#"{{"error":{{"code":{code},"message":"provider error","status":"{status}"}}}}"#)
    }
    fn transport(server: &Server) -> FirestoreWitnessRestTransport {
        FirestoreWitnessRestTransport::new_with_test_origin(
            &format!("{}/v1", server.origin),
            FirestoreWitnessNamespace::new(PROJECT, DATABASE).unwrap(),
        )
        .unwrap()
    }
    async fn refused_loopback_transport() -> FirestoreWitnessRestTransport {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        FirestoreWitnessRestTransport::new_with_test_origin(
            &format!("{origin}/v1"),
            FirestoreWitnessNamespace::new(PROJECT, DATABASE).unwrap(),
        )
        .unwrap()
    }
    fn document() -> String {
        format!(
            "projects/{PROJECT}/databases/{DATABASE}/documents/archive_witness_v3/{}",
            "01".repeat(16)
        )
    }
    fn transaction() -> FirestoreTransaction {
        FirestoreTransaction::new(b"transaction").unwrap()
    }
    fn batch_request(with_transaction: bool) -> Value {
        let mut value = json!({"documents": [document()]});
        if with_transaction {
            value["transaction"] = Value::String(STANDARD.encode(transaction().bytes()));
        }
        value
    }
    fn record() -> [u8; WITNESS_RECORD_BYTES] {
        [7; WITNESS_RECORD_BYTES]
    }
    fn commit_request() -> Value {
        json!({"transaction": STANDARD.encode(transaction().bytes()), "writes": [{"update": {"name": document(), "fields": {"r": {"bytesValue": STANDARD.encode(record())}}}, "currentDocument": {"updateTime": TIME}}]})
    }
    fn probe_document() -> String {
        format!(
            "projects/{PROJECT}/databases/{DATABASE}/documents/archive_witness_transport_probe_v1/singleton"
        )
    }
    fn probe_record() -> [u8; PROBE_RECORD_BYTES] {
        let mut bytes = [0; PROBE_RECORD_BYTES];
        bytes[..16].copy_from_slice(b"KIOKU-WIT-PROBE\0");
        bytes[16..20].copy_from_slice(&1u32.to_be_bytes());
        bytes[24..32].copy_from_slice(&1u64.to_be_bytes());
        bytes[32..].fill(7);
        bytes
    }
    fn probe_commit_request() -> Value {
        json!({"transaction": STANDARD.encode(transaction().bytes()), "writes": [{"update": {"name": probe_document(), "fields": {"r": {"bytesValue": STANDARD.encode(probe_record())}}}, "currentDocument": {"exists": false}}]})
    }
    fn batch_body() -> String {
        format!(r#"{{"missing":"{}","readTime":"{}"}}"#, document(), TIME)
    }

    fn batch_array_body() -> String {
        format!("[{}]", batch_body())
    }

    #[tokio::test]
    async fn exact_rpc_paths_bodies_auth_and_fragmented_batch_stream() {
        let server = Server::new(vec![
            reply("200 OK", r#"{"transaction":"dHJhbnNhY3Rpb24="}"#),
            fragmented("200 OK", &batch_array_body(), &[1, 2, 5, 11]),
            reply("200 OK", r#"{"writeResults":[{"updateTime":"2026-01-02T03:04:05.123Z","transformResults":[]}],"commitTime":"2026-01-02T03:04:05.124Z"}"#),
        ]).await;
        let transport = transport(&server);
        let tx = transport
            .begin_read_write("token", json!({"options": {"readWrite": {}}}))
            .await
            .unwrap();
        transport
            .batch_get_exact("token", &tx, batch_request(true))
            .await
            .unwrap();
        transport
            .commit_full_record("token", &tx, commit_request())
            .await
            .unwrap();
        let requests = server.finish().await;
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].method, "POST");
        assert_eq!(
            requests[0].target,
            "/v1/projects/project-1/databases/witness-db/documents:beginTransaction"
        );
        assert_eq!(
            requests[1].target,
            "/v1/projects/project-1/databases/witness-db/documents:batchGet"
        );
        assert_eq!(
            requests[2].target,
            "/v1/projects/project-1/databases/witness-db/documents:commit"
        );
        assert!(requests.iter().all(|request| request
            .headers
            .to_ascii_lowercase()
            .contains("authorization: bearer token")));
        assert_eq!(
            serde_json::from_slice::<Value>(&requests[0].body).unwrap(),
            json!({"options":{"readWrite":{}}})
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&requests[1].body).unwrap(),
            batch_request(true)
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&requests[2].body).unwrap(),
            commit_request()
        );
    }

    #[test]
    fn batch_json_array_requires_exactly_one_response_object() {
        let object = batch_body();
        assert!(parse_batch_get_response_array(batch_array_body().as_bytes(), &document()).is_ok());
        for body in [
            String::new(),
            object.clone(),
            "[]".to_owned(),
            format!("[{object},{object}]"),
            format!("[[{object}]]"),
            format!("[{object}] {{}}"),
            "[null]".to_owned(),
        ] {
            assert_eq!(
                parse_batch_get_response_array(body.as_bytes(), &document()),
                Err(FirestoreWitnessTransportError::Protocol),
                "accepted {body}"
            );
        }
    }

    #[tokio::test]
    async fn exact_error_and_commit_ambiguity_matrix() {
        let cases = [
            (
                "404 Not Found",
                error(404, "NOT_FOUND"),
                FirestoreWitnessTransportError::EndpointNotFound,
            ),
            (
                "409 Conflict",
                error(409, "ABORTED"),
                FirestoreWitnessTransportError::Aborted,
            ),
            (
                "400 Bad Request",
                error(400, "FAILED_PRECONDITION"),
                FirestoreWitnessTransportError::PreconditionFailed,
            ),
            (
                "400 Bad Request",
                error(400, "ABORTED"),
                FirestoreWitnessTransportError::Protocol,
            ),
            (
                "409 Conflict",
                error(409, "FAILED_PRECONDITION"),
                FirestoreWitnessTransportError::Protocol,
            ),
            (
                "429 Too Many Requests",
                error(429, "RESOURCE_EXHAUSTED"),
                FirestoreWitnessTransportError::OutcomeUnknown,
            ),
            (
                "500 Internal Server Error",
                error(500, "INTERNAL"),
                FirestoreWitnessTransportError::OutcomeUnknown,
            ),
        ];
        for (status, body, expected) in cases {
            let server = Server::new(vec![reply(status, &body)]).await;
            let transport = transport(&server);
            assert_eq!(
                transport
                    .commit_full_record("token", &transaction(), commit_request())
                    .await,
                Err(expected)
            );
            let _ = server.finish().await;
        }
        let server = Server::new(vec![reply("200 OK", "{")]).await;
        let client = transport(&server);
        assert_eq!(
            client
                .commit_full_record("token", &transaction(), commit_request())
                .await,
            Err(FirestoreWitnessTransportError::OutcomeUnknown)
        );
        let _ = server.finish().await;

        let client = refused_loopback_transport().await;
        assert_eq!(
            client
                .commit_full_record("token", &transaction(), commit_request())
                .await,
            Err(FirestoreWitnessTransportError::Unavailable)
        );

        let server = Server::new(vec![Reply {
            status: "",
            body: Vec::new(),
            fragments: Vec::new(),
            close: true,
        }])
        .await;
        let client = transport(&server);
        assert_eq!(
            client
                .commit_full_record("token", &transaction(), commit_request())
                .await,
            Err(FirestoreWitnessTransportError::OutcomeUnknown)
        );
        let _ = server.finish().await;
    }

    #[tokio::test]
    async fn response_limits_fail_closed_and_commit_success_ambiguity_is_preserved() {
        let oversized_begin = "x".repeat(MAX_BEGIN_RESPONSE_BYTES + 1);
        let server = Server::new(vec![reply("200 OK", &oversized_begin)]).await;
        let client = transport(&server);
        assert!(matches!(
            client
                .begin_read_write("token", json!({"options": {"readWrite": {}}}))
                .await,
            Err(FirestoreWitnessTransportError::TooLarge)
        ));
        let _ = server.finish().await;

        let oversized_batch = "x".repeat(MAX_BATCH_GET_RESPONSE_BYTES + 1);
        let server = Server::new(vec![reply("200 OK", &oversized_batch)]).await;
        let client = transport(&server);
        assert_eq!(
            client.read_exact("token", batch_request(false)).await,
            Err(FirestoreWitnessTransportError::TooLarge)
        );
        let _ = server.finish().await;

        let oversized_commit = "x".repeat(MAX_COMMIT_RESPONSE_BYTES + 1);
        let server = Server::new(vec![reply("200 OK", &oversized_commit)]).await;
        let client = transport(&server);
        assert_eq!(
            client
                .commit_full_record("token", &transaction(), commit_request())
                .await,
            Err(FirestoreWitnessTransportError::OutcomeUnknown)
        );
        let _ = server.finish().await;
    }

    #[test]
    fn accepts_empty_write_transform_results_and_google_status_details() {
        assert!(parse_commit_response(br#"{"writeResults":[{"updateTime":"2026-01-02T03:04:05.123Z","transformResults":[]}],"commitTime":"2026-01-02T03:04:05.124Z"}"#).is_ok());
        assert!(parse_commit_response(br#"{"writeResults":[{"updateTime":"2026-01-02T03:04:05.123Z","transformResults":[{}]}],"commitTime":"2026-01-02T03:04:05.124Z"}"#).is_err());
        assert!(parse_google_error(
            br#"{"error":{"code":409,"message":"line\nunicode: \u2603","status":"ABORTED","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo"}]}}"#,
            reqwest::StatusCode::CONFLICT,
        )
        .is_ok());
        let bare = error(409, "ABORTED");
        assert!(parse_google_error(bare.as_bytes(), reqwest::StatusCode::CONFLICT).is_ok());
        let array = format!("[{bare}]");
        assert!(parse_google_error(array.as_bytes(), reqwest::StatusCode::CONFLICT).is_ok());
        for rejected in [
            "[]".to_owned(),
            format!("[{bare},{bare}]"),
            format!("[[{bare}]]"),
            format!("[{bare}] {{}}"),
        ] {
            assert_eq!(
                parse_google_error(rejected.as_bytes(), reqwest::StatusCode::CONFLICT).map(|_| ()),
                Err(FirestoreWitnessTransportError::Protocol),
                "accepted {rejected}"
            );
        }
    }

    #[tokio::test]
    async fn read_errors_never_treat_http_404_as_missing_document() {
        let server = Server::new(vec![reply("404 Not Found", &error(404, "NOT_FOUND"))]).await;
        let transport = transport(&server);
        assert_eq!(
            transport.read_exact("token", batch_request(false)).await,
            Err(FirestoreWitnessTransportError::EndpointNotFound)
        );
        let _ = server.finish().await;
    }

    #[test]
    fn constructor_and_request_validation_are_narrow() {
        let namespace = FirestoreWitnessNamespace::new(PROJECT, DATABASE).unwrap();
        assert!(FirestoreWitnessRestTransport::new(namespace.clone()).is_ok());
        assert!(!valid_production_origin(
            "https://firestore.googleapis.com/v1/extra"
        ));
        assert!(!valid_bearer_token(b"token\r\nnext"));
        let transport = FirestoreWitnessRestTransport::new(namespace).unwrap();
        assert!(!transport.validate_batch_get_request(&json!({"documents": ["projects/project-1/databases/witness-db/documents/archive_witness_v3/01010101010101010101010101010101"], "structuredQuery": {}}), None));
        let mut invalid = commit_request();
        invalid["writes"][0]["update"]["fields"]["extra"] = json!({"bytesValue": "x"});
        assert!(!transport.validate_commit_request(&invalid, &transaction()));
        let mut unaligned = commit_request();
        unaligned["writes"][0]["currentDocument"]["updateTime"] =
            json!("2026-01-02T03:04:05.123456789Z");
        assert!(!transport.validate_commit_request(&unaligned, &transaction()));
        let mut aligned = commit_request();
        aligned["writes"][0]["currentDocument"]["updateTime"] =
            json!("2026-01-02T03:04:05.123456000Z");
        assert!(transport.validate_commit_request(&aligned, &transaction()));

        assert!(transport
            .validate_probe_batch_get_request(&json!({"documents": [probe_document()]}), None));
        assert!(transport.validate_probe_commit_request(&probe_commit_request(), &transaction()));
        let mut arbitrary = probe_commit_request();
        arbitrary["writes"][0]["update"]["name"] = json!(format!(
            "projects/{PROJECT}/databases/{DATABASE}/documents/archive_witness_transport_probe_v1/other"
        ));
        assert!(!transport.validate_probe_commit_request(&arbitrary, &transaction()));
        let mut malformed = probe_commit_request();
        malformed["writes"][0]["update"]["fields"]["r"]["bytesValue"] =
            json!(STANDARD.encode([0; PROBE_RECORD_BYTES]));
        assert!(!transport.validate_probe_commit_request(&malformed, &transaction()));
    }
}
