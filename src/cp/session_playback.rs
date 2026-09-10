//! Exact-session playback before memory formation. Uses the same source-byte
//! authorization, retention, encrypted-object verification and bounded manifest
//! projection as memory playback, without inventing an episode ID.

use super::*;

pub(super) fn router() -> Router<Arc<CpState>> {
    Router::new()
        .route(
            "/api/v2/capture/sessions/{capture_session_id}/playback",
            get(manifest),
        )
        .route(
            "/api/v2/capture/sessions/{capture_session_id}/recordings/{recording_id}/segments/{segment_id}",
            get(segment),
        )
}

fn valid_session(value: &str) -> bool {
    super::super::media::validate_id("capture_session_id", value).is_ok()
}

async fn manifest(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Path(session_id): Path<String>,
    Query(query): Query<PlaybackQuery>,
) -> Response {
    if !playback_capability_available(&state) || !valid_session(&session_id) {
        return not_found();
    }
    if query.at_ms.is_some_and(|at| at < 0) || (query.at_ms.is_some() && query.cursor.is_some()) {
        return bad_request("invalid playback window");
    }
    if !manifest_limiter()
        .consume_scoped(&state.repositories, "playback-manifest", &user.0)
        .await
    {
        return too_many_requests();
    }
    let durable_read = match current_durable_read_fence(&state, &user.0).await {
        Ok(value) => value,
        Err(error) => return super::super::routed_read_unavailable("api.session_playback", &error),
    };
    match state
        .repositories
        .playback()
        .session_dataset(&user.0, &session_id, durable_read.as_ref())
        .await
    {
        Ok(Some(dataset)) => match playback_window_start(&dataset, &query)
            .and_then(|start| project_manifest(&dataset, start))
        {
            Ok(value) => no_store_json(value),
            Err(EnclaveError::InvalidRequest(_)) => bad_request("invalid playback cursor"),
            Err(error) => super::super::routed_read_unavailable("api.session_playback", &error),
        },
        Ok(None) => not_found(),
        Err(error) => super::super::routed_read_unavailable("api.session_playback", &error),
    }
}

async fn segment(
    State(state): State<Arc<CpState>>,
    Extension(user): Extension<AuthUser>,
    Path((session_id, recording_id, segment_id)): Path<(String, String, String)>,
    Query(query): Query<SegmentQuery>,
) -> Response {
    if !playback_capability_available(&state)
        || !valid_session(&session_id)
        || query.projection_revision <= 0
        || !valid_public_id(&recording_id, "rec_")
        || !valid_public_id(&segment_id, "seg_")
    {
        return not_found();
    }
    if !segment_limiter()
        .consume_scoped(&state.repositories, "playback-segment", &user.0)
        .await
    {
        return too_many_requests();
    }
    let durable_read = match current_durable_read_fence(&state, &user.0).await {
        Ok(value) => value,
        Err(error) => return super::super::routed_read_unavailable("api.session_playback", &error),
    };
    let dataset = match state
        .repositories
        .playback()
        .session_dataset(&user.0, &session_id, durable_read.as_ref())
        .await
    {
        Ok(Some(dataset)) => dataset,
        Ok(None) => return not_found(),
        Err(error) => return super::super::routed_read_unavailable("api.session_playback", &error),
    };
    if dataset.projection_revision != query.projection_revision {
        return revision_changed();
    }
    let Some(authority) = dataset.segments.into_iter().find(|source| {
        source.capture_session_id == session_id
            && source.recording_id == recording_id
            && source.segment_id == segment_id
            && source.readable()
    }) else {
        return not_found();
    };
    let wrapped_dek = if authority.retention_decision == "processing_window_30d" {
        match state
            .repositories
            .captures()
            .media_dek_wrapped(&user.0)
            .await
        {
            Ok(value) => value,
            Err(error) => {
                return super::super::routed_read_unavailable("api.session_playback", &error)
            }
        }
    } else {
        None
    };
    let response = serve_authorized_segment(&state, &user.0, authority, wrapped_dek).await;
    if !response.status().is_success() {
        return response;
    }
    // Revalidate after provider I/O. A pending episode/account deletion or a
    // retention change cannot be bypassed by using the enclosing session route.
    let durable_read = match current_durable_read_fence(&state, &user.0).await {
        Ok(value) => value,
        Err(error) => return super::super::routed_read_unavailable("api.session_playback", &error),
    };
    match state
        .repositories
        .playback()
        .session_dataset(&user.0, &session_id, durable_read.as_ref())
        .await
    {
        Ok(Some(dataset))
            if dataset.projection_revision == query.projection_revision
                && dataset.segments.iter().any(|source| {
                    source.segment_id == segment_id
                        && source.recording_id == recording_id
                        && source.readable()
                }) =>
        {
            response
        }
        Ok(Some(_)) => revision_changed(),
        Ok(None) => not_found(),
        Err(error) => super::super::routed_read_unavailable("api.session_playback", &error),
    }
}

fn revision_changed() -> Response {
    no_store_error(
        StatusCode::CONFLICT,
        json!({"error": "playback_revision_changed"}),
    )
}
