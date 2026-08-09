mod auth;
mod config;
mod ids;
mod store;

use std::{sync::Arc, time::Duration};

use anyhow::Result;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, put},
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::{
    auth::{SecretRegistry, is_authorized, load_secret_registry},
    config::Config,
    ids::is_valid_id,
    store::{EventMetadata, Store, StoreError},
};

#[derive(Clone)]
struct AppState {
    secrets: Arc<SecretRegistry>,
    store: Store,
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

    fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: "event not found",
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
        (self.status, Json(ErrorBody { error: self.message })).into_response()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let config = Config::from_env()?;
    let secrets = Arc::new(load_secret_registry(&config.secret_registry_path).await?);
    let store = Store::open(&config).await?;
    let state = AppState { secrets, store };

    let app = Router::new()
        .route("/health", get(health))
        .route(
            "/v1/sync/{app_id}/{root_id}",
            get(list_events),
        )
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
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, ApiError> {
    validate_ids(&[&app_id, &root_id, &device_id, &event_id])?;
    authorize(&state, &headers, &app_id, &root_id)?;

    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some("application/octet-stream")
    {
        return Err(ApiError::bad_request(
            "content-type must be application/octet-stream",
        ));
    }

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
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    validate_ids(&[&app_id, &root_id, &device_id, &event_id])?;
    authorize(&state, &headers, &app_id, &root_id)?;

    match state
        .store
        .get_event(&app_id, &root_id, &device_id, &event_id)
        .await
    {
        Ok(bytes) => Ok(([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response()),
        Err(StoreError::NotFound) => Err(ApiError::not_found()),
        Err(err) => {
            error!(error = %err, "failed to read event");
            Err(ApiError::internal())
        }
    }
}

async fn list_events(
    State(state): State<AppState>,
    Path((app_id, root_id)): Path<(String, String)>,
    Query(query): Query<ListQuery>,
    headers: HeaderMap,
) -> Result<Json<ListResponse>, ApiError> {
    validate_ids(&[&app_id, &root_id])?;
    authorize(&state, &headers, &app_id, &root_id)?;

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

fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    app_id: &str,
    root_id: &str,
) -> Result<(), ApiError> {
    if is_authorized(&state.secrets, headers, app_id, root_id) {
        Ok(())
    } else {
        Err(ApiError::unauthorized())
    }
}

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
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("gesh_server=info"));
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

    info!(timeout_seconds = Duration::from_secs(10).as_secs(), "shutdown requested");
}
