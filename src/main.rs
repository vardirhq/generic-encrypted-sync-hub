mod auth;
mod config;
mod credentials;
mod ids;
mod ratelimit;
mod store;

use std::{
    convert::Infallible,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::Result;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, FromRequestParts, Path, Query, RawPathParams, State},
    http::{HeaderName, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::{
    auth::{Identity, SecretRegistry, authenticate, load_secret_registry},
    config::{Config, Limits, Retention},
    credentials::EnrollmentCode,
    ids::{is_valid_handle, is_valid_id},
    ratelimit::{Backoff, Quota, RateLimiter},
    store::{
        DeviceState, EnrolledDevice, EnrolledDeviceSummary, EventMetadata, RootRef, Store,
        StoreError,
    },
};

/// Base wait once a client has failed past the threshold. Each further failure
/// doubles it, up to the configured ceiling.
const BACKOFF_BASE: Duration = Duration::from_secs(1);

#[derive(Clone)]
struct AppState {
    secrets: Arc<SecretRegistry>,
    store: Store,
    enrollment_code_ttl: Duration,
    throttles: Arc<Throttles>,
    trusted_forwarded_header: Option<HeaderName>,
}

/// The abuse controls in front of the routes a stranger can reach.
///
/// Rate limits and backoff answer different questions and both are needed here.
/// A limit caps how fast anyone may knock and recovers continuously, so the
/// worst it does to a legitimate client is make it wait a moment. Backoff
/// punishes only repeated failure and grows, which is what turns guessing from
/// slow into pointless.
struct Throttles {
    /// Per client: how fast anyone may try to redeem a code.
    enroll: RateLimiter,
    /// Per root: how fast codes may be tried against one root, whoever is
    /// trying. Without this a distributed attempt would face no ceiling at all.
    /// It is a bucket rather than a lockout on purpose: an attacker hammering
    /// someone's root delays their pairing by seconds instead of blocking it.
    enroll_root: RateLimiter,
    /// Per client: a growing lockout after repeated bad codes.
    enroll_failures: Backoff,
    /// Per client: a growing lockout after repeated bad bearer tokens.
    auth_failures: Backoff,
    /// Per client: handle lookups, the one route that confirms a root exists.
    handle_lookups: RateLimiter,
}

impl Throttles {
    fn new(limits: &Limits) -> Self {
        Self {
            enroll: RateLimiter::new(Quota::per_minute(limits.enroll_attempts_per_minute)),
            enroll_root: RateLimiter::new(Quota::per_minute(limits.enroll_attempts_per_minute)),
            enroll_failures: Backoff::new(
                limits.failures_before_backoff,
                BACKOFF_BASE,
                limits.max_backoff,
            ),
            auth_failures: Backoff::new(
                limits.failures_before_backoff,
                BACKOFF_BASE,
                limits.max_backoff,
            ),
            handle_lookups: RateLimiter::new(Quota::per_minute(limits.handle_lookups_per_minute)),
        }
    }
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
    retry_after: Option<Duration>,
}

impl ApiError {
    fn new(status: StatusCode, message: &'static str) -> Self {
        Self {
            status,
            message,
            retry_after: None,
        }
    }

    fn bad_request(message: &'static str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized")
    }

    /// Tells a throttled caller to come back later rather than leaving it to
    /// guess, so an honest client backs off without a retry storm.
    fn too_many_requests(retry_after: Duration) -> Self {
        Self {
            retry_after: Some(retry_after),
            ..Self::new(StatusCode::TOO_MANY_REQUESTS, "too many requests")
        }
    }

    fn conflict() -> Self {
        Self::new(StatusCode::CONFLICT, "event already exists")
    }

    fn forbidden() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "the root secret is required for this operation",
        )
    }

    fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "event not found")
    }

    fn handle_taken() -> Self {
        Self::new(StatusCode::CONFLICT, "handle is already in use")
    }

    fn unknown_device() -> Self {
        Self::new(StatusCode::NOT_FOUND, "unknown device")
    }

    fn unknown_root() -> Self {
        Self::new(StatusCode::NOT_FOUND, "unknown root")
    }

    fn invalid_code() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "enrollment code is invalid or expired",
        )
    }

    fn internal() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response();

        if let Some(retry_after) = self.retry_after {
            // Rounded up, and never zero: a `Retry-After: 0` invites the retry
            // storm the header exists to prevent.
            let seconds = retry_after.as_secs_f64().ceil().max(1.0) as u64;

            if let Ok(value) = seconds.to_string().parse() {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
        }

        response
    }
}

/// The key a request is throttled under.
///
/// Throttling is only as good as its notion of "who", and the only thing a
/// stranger cannot trivially change is the address the packets came from.
struct ClientKey(String);

impl FromRequestParts<AppState> for ClientKey {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(client_key(parts, state)))
    }
}

fn client_key(parts: &Parts, state: &AppState) -> String {
    if let Some(address) = forwarded_client(parts, state) {
        return ratelimit::client_key(address);
    }

    parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(address)| ratelimit::client_key(address.ip()))
        // Only reachable if the service is served without connection info, in
        // which case every caller shares one bucket. That is the safe way to
        // be wrong: it throttles too much rather than not at all.
        .unwrap_or_else(|| "unknown".to_owned())
}

/// Reads the client address from the proxy header the administrator declared
/// trustworthy, if any.
///
/// The *last* entry is used, not the first. A conforming proxy appends the peer
/// it actually saw, so anything a client puts in the header ends up to the left
/// of that entry and cannot displace it.
fn forwarded_client(parts: &Parts, state: &AppState) -> Option<IpAddr> {
    let name = state.trusted_forwarded_header.as_ref()?;
    let value = parts.headers.get(name)?.to_str().ok()?;
    let last = value.rsplit(',').next()?.trim();

    last.parse::<IpAddr>()
        .ok()
        // Some proxies write `host:port`; the port is not part of the identity.
        .or_else(|| last.parse::<SocketAddr>().ok().map(|address| address.ip()))
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
/// told it is unauthorized. The lockout below sits in front of the credential
/// check for the same reason.
async fn resolve_caller(parts: &mut Parts, state: &AppState) -> Result<Caller, ApiError> {
    let client = client_key(parts, state);

    if let Err(retry_after) = state.throttles.auth_failures.check(&client) {
        return Err(ApiError::too_many_requests(retry_after));
    }

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
    })?;

    let Some(identity) = identity else {
        state.throttles.auth_failures.record_failure(&client);
        return Err(ApiError::unauthorized());
    };

    // A working credential clears the history, so a device that presented a
    // revoked token before re-pairing is not left serving out a lockout.
    state.throttles.auth_failures.record_success(&client);

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

/// A knock on the enrollment door, already throttled.
///
/// This is an extractor rather than a check inside the handler so that a caller
/// which is over its limit is turned away before the server parses anything it
/// sent.
struct EnrollmentAttempt {
    client: String,
    handle: String,
}

impl FromRequestParts<AppState> for EnrollmentAttempt {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let Path(handle) = Path::<String>::from_request_parts(parts, state)
            .await
            .map_err(|_| ApiError::bad_request("invalid handle"))?;

        if !is_valid_handle(&handle) {
            return Err(ApiError::bad_request("invalid handle"));
        }

        let client = client_key(parts, state);
        let throttles = &state.throttles;

        // The client's own record is consulted first, so a caller already
        // serving a lockout cannot spend a stranger's root allowance on the way
        // to being refused.
        throttles
            .enroll_failures
            .check(&client)
            .map_err(ApiError::too_many_requests)?;
        throttles
            .enroll
            .check(&client)
            .map_err(ApiError::too_many_requests)?;
        throttles
            .enroll_root
            .check(&handle)
            .map_err(ApiError::too_many_requests)?;

        Ok(Self { client, handle })
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
        throttles: Arc::new(Throttles::new(&config.limits)),
        trusted_forwarded_header: config.limits.trusted_forwarded_header.clone(),
    };

    if let Some(header) = &state.trusted_forwarded_header {
        info!(header = %header, "trusting a proxy header for the client address");
    }

    tokio::spawn(sweep_loop(store.clone(), config.retention.clone()));

    let app = router(state, config.upload_limit_bytes);

    let listener = TcpListener::bind(config.listen_addr).await?;
    info!(address = %config.listen_addr, "GESH listening");

    // Connection info is what the throttles key on, so it is served rather
    // than a plain service.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    Ok(())
}

fn router(state: AppState, upload_limit_bytes: usize) -> Router {
    Router::new()
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
        .layer(DefaultBodyLimit::max(upload_limit_bytes))
        .with_state(state)
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
    ClientKey(client): ClientKey,
    Path(handle): Path<String>,
) -> Result<Json<RootRef>, ApiError> {
    // Charged before the handle is validated, so sweeping a namespace with
    // malformed names is not a way to look for roots for free.
    state
        .throttles
        .handle_lookups
        .check(&client)
        .map_err(ApiError::too_many_requests)?;

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
///
/// This is the one credential on the server a person types, so it is the one
/// worth guessing. Every rejection here costs the caller a growing wait; see
/// [`EnrollmentAttempt`], which has already throttled the request by the time
/// this runs.
async fn redeem_enrollment(
    State(state): State<AppState>,
    attempt: EnrollmentAttempt,
    Json(request): Json<RedeemRequest>,
) -> Result<(StatusCode, Json<EnrolledDevice>), ApiError> {
    if !is_valid_id(&request.device_id) {
        return Err(ApiError::bad_request("invalid identifier"));
    }

    let failed = || {
        state
            .throttles
            .enroll_failures
            .record_failure(&attempt.client);
        warn!(client = %attempt.client, handle = %attempt.handle, "rejected enrollment attempt");
    };

    let root = match state.store.resolve_handle(&attempt.handle).await {
        Ok(root) => root,
        Err(StoreError::NotFound) => {
            failed();
            return Err(ApiError::unknown_root());
        }
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
        Err(StoreError::NotFound) => {
            failed();
            return Err(ApiError::invalid_code());
        }
        Err(err) => {
            error!(error = %err, "failed to redeem enrollment code");
            return Err(ApiError::internal());
        }
    };

    // A code is bound to the root that minted it, so one presented against a
    // different handle is refused rather than silently enrolling elsewhere.
    if enrolled.app_id != root.app_id || enrolled.root_id != root.root_id {
        failed();
        return Err(ApiError::invalid_code());
    }

    state
        .throttles
        .enroll_failures
        .record_success(&attempt.client);

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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use axum::{body::Body, http::Request, response::Response};
    use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode};
    use tempfile::TempDir;
    use tower::ServiceExt;

    use crate::config::Retention;

    use super::*;

    const ROOT_SECRET: &str = "a-long-random-root-secret";

    fn limits() -> Limits {
        Limits {
            enroll_attempts_per_minute: 60,
            handle_lookups_per_minute: 60,
            failures_before_backoff: 3,
            max_backoff: Duration::from_secs(300),
            trusted_forwarded_header: None,
        }
    }

    async fn test_state(limits: Limits) -> (AppState, TempDir) {
        let dir = TempDir::new().expect("temp dir");
        let config = Config {
            listen_addr: "127.0.0.1:0".parse().expect("socket address"),
            blob_base_dir: dir.path().join("blobs"),
            secret_registry_path: dir.path().join("secrets.json"),
            database_options: SqliteConnectOptions::new()
                .filename(dir.path().join("gesh.db"))
                .create_if_missing(true)
                .journal_mode(SqliteJournalMode::Wal),
            upload_limit_bytes: 1024,
            retention: Retention {
                event_ttl: Duration::from_secs(3600),
                tombstone_ttl: Duration::from_secs(3600),
                device_ttl: Duration::from_secs(3600),
                sweep_interval: Duration::from_secs(60),
            },
            enrollment_code_ttl: Duration::from_secs(600),
            limits,
        };

        let store = Store::open(&config).await.expect("store opens");
        store
            .set_handle("app", "root", "madsen-home")
            .await
            .expect("handle is set");

        let secrets = SecretRegistry::from([(
            "app".to_owned(),
            HashMap::from([("root".to_owned(), ROOT_SECRET.to_owned())]),
        )]);

        let state = AppState {
            secrets: Arc::new(secrets),
            store,
            enrollment_code_ttl: config.enrollment_code_ttl,
            throttles: Arc::new(Throttles::new(&config.limits)),
            trusted_forwarded_header: config.limits.trusted_forwarded_header.clone(),
        };

        (state, dir)
    }

    async fn send(state: &AppState, request: Request<Body>) -> Response {
        router(state.clone(), 1024)
            .oneshot(request)
            .await
            .expect("the router answers")
    }

    fn from(peer: &str) -> Request<Body> {
        let mut request = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .expect("request builds");

        request.extensions_mut().insert(ConnectInfo(
            peer.parse::<SocketAddr>().expect("peer address"),
        ));

        request
    }

    /// A redemption attempt from `peer`, carrying a code that will not work.
    fn bad_code(peer: &str) -> Request<Body> {
        let mut request = from(peer);
        *request.method_mut() = http::Method::POST;
        *request.uri_mut() = "/v1/roots/madsen-home/enroll".parse().expect("uri");
        request.headers_mut().insert(
            header::CONTENT_TYPE,
            "application/json".parse().expect("header value"),
        );
        *request.body_mut() = Body::from(r#"{"code":"AAAAA-BBBBB","deviceId":"phone"}"#);

        request
    }

    fn listing(peer: &str, token: &str) -> Request<Body> {
        let mut request = from(peer);
        *request.uri_mut() = "/v1/sync/app/root?after=0&limit=10".parse().expect("uri");
        request.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().expect("header value"),
        );

        request
    }

    #[tokio::test]
    async fn repeated_bad_codes_lock_a_client_out() {
        let (state, _dir) = test_state(limits()).await;

        for _ in 0..3 {
            let response = send(&state, bad_code("203.0.113.5:44000")).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        // Keyed by address, so opening a new connection does not reset it.
        let response = send(&state, bad_code("203.0.113.5:51000")).await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response
                .headers()
                .get(header::RETRY_AFTER)
                .expect("a throttled caller is told when to return"),
            "1"
        );

        // And it is that client that is locked out, not the root.
        let response = send(&state, bad_code("198.51.100.9:44000")).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn enrollment_attempts_are_capped_even_before_any_failure() {
        let (state, _dir) = test_state(Limits {
            enroll_attempts_per_minute: 2,
            failures_before_backoff: 100,
            ..limits()
        })
        .await;

        for _ in 0..2 {
            let response = send(&state, bad_code("203.0.113.5:44000")).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        let response = send(&state, bad_code("203.0.113.5:44000")).await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

        // The root's own allowance is spent too, so a distributed attempt on
        // one root does not simply scale with the number of source addresses.
        let response = send(&state, bad_code("198.51.100.9:44000")).await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn repeated_bad_tokens_lock_a_client_out() {
        let (state, _dir) = test_state(limits()).await;

        for _ in 0..3 {
            let response = send(&state, listing("203.0.113.5:44000", "guessed")).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        // The lockout is in front of the credential check, so even the real
        // secret waits it out from that address.
        let response = send(&state, listing("203.0.113.5:44000", ROOT_SECRET)).await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

        let response = send(&state, listing("198.51.100.9:44000", ROOT_SECRET)).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_working_credential_clears_the_failures_before_it() {
        let (state, _dir) = test_state(limits()).await;

        for _ in 0..2 {
            let response = send(&state, listing("203.0.113.5:44000", "guessed")).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        let response = send(&state, listing("203.0.113.5:44000", ROOT_SECRET)).await;
        assert_eq!(response.status(), StatusCode::OK);

        // Two more failures would have crossed the threshold had the success
        // not reset the count.
        for _ in 0..2 {
            let response = send(&state, listing("203.0.113.5:44000", "guessed")).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn an_untrusted_forwarding_header_cannot_buy_a_new_identity() {
        let (state, _dir) = test_state(limits()).await;

        for attempt in 0..3 {
            let mut request = listing("203.0.113.5:44000", "guessed");
            request.headers_mut().insert(
                "x-forwarded-for",
                format!("10.0.0.{attempt}").parse().expect("header value"),
            );

            let response = send(&state, request).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        let mut request = listing("203.0.113.5:44000", "guessed");
        request.headers_mut().insert(
            "x-forwarded-for",
            "10.0.0.99".parse().expect("header value"),
        );

        assert_eq!(
            send(&state, request).await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn a_trusted_forwarding_header_separates_clients_behind_one_proxy() {
        let (state, _dir) = test_state(Limits {
            trusted_forwarded_header: Some(HeaderName::from_static("x-forwarded-for")),
            ..limits()
        })
        .await;

        // Every request arrives from the proxy's own address.
        for _ in 0..3 {
            let mut request = listing("127.0.0.1:44000", "guessed");
            request.headers_mut().insert(
                "x-forwarded-for",
                // Only the last entry was written by the proxy; the rest is
                // whatever the client claimed on the way in.
                "10.0.0.99, 203.0.113.5".parse().expect("header value"),
            );

            assert_eq!(
                send(&state, request).await.status(),
                StatusCode::UNAUTHORIZED
            );
        }

        let mut locked = listing("127.0.0.1:44000", "guessed");
        locked.headers_mut().insert(
            "x-forwarded-for",
            "203.0.113.5".parse().expect("header value"),
        );
        assert_eq!(
            send(&state, locked).await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );

        // The neighbour behind the same proxy is untouched.
        let mut neighbour = listing("127.0.0.1:44000", ROOT_SECRET);
        neighbour.headers_mut().insert(
            "x-forwarded-for",
            "198.51.100.9".parse().expect("header value"),
        );
        assert_eq!(send(&state, neighbour).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn handle_lookups_are_capped() {
        let (state, _dir) = test_state(Limits {
            handle_lookups_per_minute: 2,
            ..limits()
        })
        .await;

        for _ in 0..2 {
            let mut request = from("203.0.113.5:44000");
            *request.uri_mut() = "/v1/roots/madsen-home".parse().expect("uri");
            assert_eq!(send(&state, request).await.status(), StatusCode::OK);
        }

        // Including lookups for names that do not exist, which is what makes
        // sweeping a namespace expensive.
        let mut request = from("203.0.113.5:44000");
        *request.uri_mut() = "/v1/roots/nobody-home".parse().expect("uri");
        assert_eq!(
            send(&state, request).await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }
}
