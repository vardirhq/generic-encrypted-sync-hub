mod auth;
mod config;
mod credentials;
mod ids;
mod store;

use std::{sync::Arc, time::Duration};

use anyhow::Result;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, FromRequestParts, Path, Query, RawPathParams, State},
    http::{StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::{
    auth::{Identity, SecretRegistry, authenticate, load_secret_registry},
    config::{Config, Retention},
    credentials::EnrollmentCode,
    ids::{is_valid_handle, is_valid_id},
    store::{
        DeviceState, EnrolledDevice, EnrolledDeviceSummary, EventMetadata, RootRef, Store,
        StoreError,
    },
};

#[derive(Clone)]
struct AppState {
    secrets: Arc<SecretRegistry>,
    store: Store,
    enrollment_code_ttl: Duration,
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    #[serde(default)]
    after: i64,
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(rename = "deviceId")]
    device_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct HandleRequest {
    handle: String,
}

#[derive(Debug, Deserialize)]
struct RedeemRequest {
    code: String,
    #[serde(rename = "deviceId")]
    device_id: String,
}

#[derive(Debug, Serialize)]
struct EnrollmentResponse {
    code: String,
    expires_at_ms: i64,
}

#[derive(Debug, Deserialize)]
struct AckRequest {
    #[serde(rename = "ackCursor")]
    ack_cursor: i64,
}

#[derive(Debug, Serialize)]
struct ListResponse {
    events: Vec<EventMetadata>,
    next_cursor: Option<i64>,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    ok: bool,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: &'static str,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: &'static str,
}

impl ApiError {
    fn bad_request(message: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message,
        }
    }

    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: "unauthorized",
        }
    }

    fn conflict() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: "event already exists",
        }
    }

    fn forbidden() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: "the root secret is required for this operation",
        }
    }

    fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: "event not found",
        }
    }

    fn handle_taken() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: "handle is already in use",
        }
    }

    fn unknown_device() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: "unknown device",
        }
    }

    fn unknown_root() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: "unknown root",
        }
    }

    fn invalid_code() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: "enrollment code is invalid or expired",
        }
    }

    fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "internal server error",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}

/// The authenticated caller on a root, before any per-plane rule is applied.
struct Caller {
    app_id: String,
    root_id: String,
    device_id: Option<String>,
    identity: Identity,
}

/// Validates every path identifier and resolves the credential behind the
/// request, using only the request head.
///
/// Authenticating here rather than in the handler body is what keeps an
/// anonymous caller from making the server buffer a full upload before it is
/// told it is unauthorized.
async fn resolve_caller(parts: &mut Parts, state: &AppState) -> Result<Caller, ApiError> {
    let params = RawPathParams::from_request_parts(parts, state)
        .await
        .map_err(|_| ApiError::bad_request("invalid identifier"))?;

    let mut app_id = None;
    let mut root_id = None;
    let mut device_id = None;

    for (key, value) in &params {
        if !is_valid_id(value) {
            return Err(ApiError::bad_request("invalid identifier"));
        }

        match key {
            "app_id" => app_id = Some(value.to_owned()),
            "root_id" => root_id = Some(value.to_owned()),
            "device_id" => device_id = Some(value.to_owned()),
            _ => {}
        }
    }

    let (Some(app_id), Some(root_id)) = (app_id, root_id) else {
        error!("route is missing app_id or root_id path parameters");
        return Err(ApiError::internal());
    };

    let identity = authenticate(
        &state.secrets,
        &state.store,
        &parts.headers,
        &app_id,
        &root_id,
    )
    .await
    .map_err(|err| {
        error!(error = %err, "failed to resolve credential");
        ApiError::internal()
    })?
    .ok_or_else(ApiError::unauthorized)?;

    Ok(Caller {
        app_id,
        root_id,
        device_id,
        identity,
    })
}

/// A caller cleared to relay events on a root.
struct SyncScope;

impl FromRequestParts<AppState> for SyncScope {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let caller = resolve_caller(parts, state).await?;

        // On the sync plane the device in the path is the device acting, and a
        // device credential speaks only for itself. Without this, any paired
        // device could write events under another device's name, or acknowledge
        // on its behalf and cause data it never received to be erased.
        if let (Identity::Device(authenticated), Some(addressed)) =
            (&caller.identity, &caller.device_id)
            && authenticated != addressed
        {
            return Err(ApiError::unauthorized());
        }

        Ok(Self)
    }
}

/// A caller holding the root secret, which is the authority that enrolls and
/// revokes devices.
///
/// The sync plane's device rule deliberately does not apply here: on the admin
/// plane a device in the path is the subject of the operation, not its author.
struct RootScope {
    app_id: String,
    root_id: String,
}

impl FromRequestParts<AppState> for RootScope {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let caller = resolve_caller(parts, state).await?;

        if caller.identity != Identity::Root {
            return Err(ApiError::forbidden());
        }

        Ok(Self {
            app_id: caller.app_id,
            root_id: caller.root_id,
        })
    }
}

/// Rejects the wrong media type before the body is read, for the same reason
/// [`SyncScope`] authorizes there.
struct OctetStreamBody;

impl<S: Send + Sync> FromRequestParts<S> for OctetStreamBody {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let content_type = parts
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok());

        if content_type == Some("application/octet-stream") {
            Ok(Self)
        } else {
            Err(ApiError::bad_request(
                "content-type must be application/octet-stream",
            ))
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let config = Config::from_env()?;
    let secrets = Arc::new(load_secret_registry(&config.secret_registry_path).await?);
    let store = Store::open(&config).await?;
    let state = AppState {
        secrets,
        store: store.clone(),
        enrollment_code_ttl: config.enrollment_code_ttl,
    };

    tokio::spawn(sweep_loop(store.clone(), config.retention.clone()));

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/roots/{handle}", get(resolve_handle))
        .route("/v1/roots/{handle}/enroll", post(redeem_enrollment))
        .route("/v1/admin/{app_id}/{root_id}/handle", put(set_handle))
        .route(
            "/v1/admin/{app_id}/{root_id}/enrollments",
            post(create_enrollment),
        )
        .route("/v1/admin/{app_id}/{root_id}/devices", get(list_devices))
        .route(
            "/v1/admin/{app_id}/{root_id}/devices/{device_id}",
            delete(revoke_device),
        )
        .route("/v1/sync/{app_id}/{root_id}", get(list_events))
        .route("/v1/sync/{app_id}/{root_id}/{device_id}", put(acknowledge))
        .route(
            "/v1/sync/{app_id}/{root_id}/{device_id}/{event_id}",
            put(put_event).get(get_event),
        )
        .layer(DefaultBodyLimit::max(config.upload_limit_bytes))
        .with_state(state);

    let listener = TcpListener::bind(config.listen_addr).await?;
    info!(address = %config.listen_addr, "GESH listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { ok: true })
}

async fn put_event(
    State(state): State<AppState>,
    Path((app_id, root_id, device_id, event_id)): Path<(String, String, String, String)>,
    _scope: SyncScope,
    _content_type: OctetStreamBody,
    body: Bytes,
) -> Result<impl IntoResponse, ApiError> {
    match state
        .store
        .put_event(&app_id, &root_id, &device_id, &event_id, body)
        .await
    {
        Ok(metadata) => Ok((StatusCode::CREATED, Json(metadata))),
        Err(StoreError::Conflict) => Err(ApiError::conflict()),
        Err(err) => {
            error!(error = %err, "failed to store event");
            Err(ApiError::internal())
        }
    }
}

async fn get_event(
    State(state): State<AppState>,
    Path((app_id, root_id, device_id, event_id)): Path<(String, String, String, String)>,
    _scope: SyncScope,
) -> Result<Response, ApiError> {
    match state
        .store
        .get_event(&app_id, &root_id, &device_id, &event_id)
        .await
    {
        Ok(bytes) => {
            Ok(([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response())
        }
        Err(StoreError::NotFound) => Err(ApiError::not_found()),
        Err(err) => {
            error!(error = %err, "failed to read event");
            Err(ApiError::internal())
        }
    }
}

/// Resolves the name a person types into the root it refers to.
///
/// This is deliberately the only unauthenticated sync-plane route: a device
/// being paired has to find its root before it holds anything to prove with.
/// It reveals that a handle exists and nothing further.
async fn resolve_handle(
    State(state): State<AppState>,
    Path(handle): Path<String>,
) -> Result<Json<RootRef>, ApiError> {
    if !is_valid_handle(&handle) {
        return Err(ApiError::bad_request("invalid handle"));
    }

    match state.store.resolve_handle(&handle).await {
        Ok(root) => Ok(Json(root)),
        Err(StoreError::NotFound) => Err(ApiError::unknown_root()),
        Err(err) => {
            error!(error = %err, "failed to resolve handle");
            Err(ApiError::internal())
        }
    }
}

/// Names a root so devices can find it.
async fn set_handle(
    State(state): State<AppState>,
    scope: RootScope,
    Json(request): Json<HandleRequest>,
) -> Result<StatusCode, ApiError> {
    if !is_valid_handle(&request.handle) {
        return Err(ApiError::bad_request("invalid handle"));
    }

    match state
        .store
        .set_handle(&scope.app_id, &scope.root_id, &request.handle)
        .await
    {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(StoreError::Conflict) => Err(ApiError::handle_taken()),
        Err(err) => {
            error!(error = %err, "failed to set handle");
            Err(ApiError::internal())
        }
    }
}

/// Mints a one-time code for pairing a new device.
///
/// The code authorizes transport only. Whatever carries it to the new device —
/// a QR code on the desktop, or the code read aloud — must also carry the
/// content key, which this server never sees and cannot supply.
async fn create_enrollment(
    State(state): State<AppState>,
    scope: RootScope,
) -> Result<(StatusCode, Json<EnrollmentResponse>), ApiError> {
    let code = EnrollmentCode::mint();

    let expires_at_ms = state
        .store
        .create_enrollment_code(
            &scope.app_id,
            &scope.root_id,
            &code,
            state.enrollment_code_ttl,
        )
        .await
        .map_err(|err| {
            error!(error = %err, "failed to create enrollment code");
            ApiError::internal()
        })?;

    Ok((
        StatusCode::CREATED,
        Json(EnrollmentResponse {
            code: code.code,
            expires_at_ms,
        }),
    ))
}

/// Exchanges a pairing code for the device's own credential.
async fn redeem_enrollment(
    State(state): State<AppState>,
    Path(handle): Path<String>,
    Json(request): Json<RedeemRequest>,
) -> Result<(StatusCode, Json<EnrolledDevice>), ApiError> {
    if !is_valid_handle(&handle) {
        return Err(ApiError::bad_request("invalid handle"));
    }
    if !is_valid_id(&request.device_id) {
        return Err(ApiError::bad_request("invalid identifier"));
    }

    let root = match state.store.resolve_handle(&handle).await {
        Ok(root) => root,
        Err(StoreError::NotFound) => return Err(ApiError::unknown_root()),
        Err(err) => {
            error!(error = %err, "failed to resolve handle");
            return Err(ApiError::internal());
        }
    };

    let enrolled = match state
        .store
        .redeem_enrollment_code(&request.code, &request.device_id)
        .await
    {
        Ok(enrolled) => enrolled,
        Err(StoreError::NotFound) => return Err(ApiError::invalid_code()),
        Err(err) => {
            error!(error = %err, "failed to redeem enrollment code");
            return Err(ApiError::internal());
        }
    };

    // A code is bound to the root that minted it, so one presented against a
    // different handle is refused rather than silently enrolling elsewhere.
    if enrolled.app_id != root.app_id || enrolled.root_id != root.root_id {
        return Err(ApiError::invalid_code());
    }

    info!(
        app_id = %enrolled.app_id,
        root_id = %enrolled.root_id,
        device_id = %enrolled.device_id,
        "enrolled device"
    );

    Ok((StatusCode::CREATED, Json(enrolled)))
}

async fn list_devices(
    State(state): State<AppState>,
    scope: RootScope,
) -> Result<Json<Vec<EnrolledDeviceSummary>>, ApiError> {
    state
        .store
        .list_devices(&scope.app_id, &scope.root_id)
        .await
        .map(Json)
        .map_err(|err| {
            error!(error = %err, "failed to list devices");
            ApiError::internal()
        })
}

/// Withdraws one device's access without disturbing any other.
async fn revoke_device(
    State(state): State<AppState>,
    Path((app_id, root_id, device_id)): Path<(String, String, String)>,
    _scope: RootScope,
) -> Result<StatusCode, ApiError> {
    match state
        .store
        .revoke_device(&app_id, &root_id, &device_id)
        .await
    {
        Ok(()) => {
            info!(%app_id, %root_id, %device_id, "revoked device");
            Ok(StatusCode::NO_CONTENT)
        }
        Err(StoreError::NotFound) => Err(ApiError::unknown_device()),
        Err(err) => {
            error!(error = %err, "failed to revoke device");
            Err(ApiError::internal())
        }
    }
}

/// Reports how far a device has consumed the feed, releasing everything its
/// peers have also collected.
async fn acknowledge(
    State(state): State<AppState>,
    Path((app_id, root_id, device_id)): Path<(String, String, String)>,
    _scope: SyncScope,
    Json(request): Json<AckRequest>,
) -> Result<Json<DeviceState>, ApiError> {
    if request.ack_cursor < 0 {
        return Err(ApiError::bad_request("ackCursor must be zero or greater"));
    }

    state
        .store
        .acknowledge(&app_id, &root_id, &device_id, request.ack_cursor)
        .await
        .map(Json)
        .map_err(|err| {
            error!(error = %err, "failed to record acknowledgement");
            ApiError::internal()
        })
}

async fn list_events(
    State(state): State<AppState>,
    Path((app_id, root_id)): Path<(String, String)>,
    Query(query): Query<ListQuery>,
    _scope: SyncScope,
) -> Result<Json<ListResponse>, ApiError> {
    if query.after < 0 {
        return Err(ApiError::bad_request("after must be zero or greater"));
    }
    if !(1..=500).contains(&query.limit) {
        return Err(ApiError::bad_request("limit must be between 1 and 500"));
    }
    if let Some(device_id) = query.device_id.as_deref() {
        validate_ids(&[device_id])?;
    }

    let events = state
        .store
        .list_events(
            &app_id,
            &root_id,
            query.after,
            query.limit,
            query.device_id.as_deref(),
        )
        .await
        .map_err(|err| {
            error!(error = %err, "failed to list events");
            ApiError::internal()
        })?;

    let next_cursor = events.last().map(|event| event.cursor);
    Ok(Json(ListResponse {
        events,
        next_cursor,
    }))
}

/// Reclaims relayed and expired data for as long as the process runs.
///
/// Retention is enforced here rather than on the request path so that data
/// still ages out of a root nothing is currently talking to.
async fn sweep_loop(store: Store, retention: Retention) {
    let mut ticker = tokio::time::interval(retention.sweep_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        ticker.tick().await;

        match store.sweep(&retention).await {
            Ok(report) if report.is_empty() => {}
            Ok(report) => info!(
                delivered = report.delivered,
                expired = report.expired,
                blobs_removed = report.blobs_removed,
                tombstones_purged = report.tombstones_purged,
                devices_forgotten = report.devices_forgotten,
                codes_expired = report.codes_expired,
                "reclaimed relayed data"
            ),
            Err(err) => error!(error = %err, "retention sweep failed"),
        }
    }
}

/// Path identifiers are validated by [`SyncScope`]; this covers the ones that
/// arrive as query parameters instead.
fn validate_ids(ids: &[&str]) -> Result<(), ApiError> {
    if ids.iter().all(|id| is_valid_id(id)) {
        Ok(())
    } else {
        Err(ApiError::bad_request("invalid identifier"))
    }
}

fn default_limit() -> i64 {
    100
}

fn init_tracing() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("gesh_server=info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
        signal(SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!(
        timeout_seconds = Duration::from_secs(10).as_secs(),
        "shutdown requested"
    );
}
