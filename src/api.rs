use axum::{
    extract::{Path, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tower_http::timeout::TimeoutLayer;
use tracing::{debug, instrument, Instrument};

use crate::auth::validate_bearer_token;
use crate::config::Config;
use crate::db::DbService;
use crate::error::AppError;
use crate::models::{GroupCreate, GroupUpdate, UserCreate, UserResponse, UserUpdate};
use crate::tls;
use uuid::Uuid;

/// Middleware to add request ID to all requests
async fn add_request_id(mut request: Request, next: Next) -> Response {
    let request_id = Uuid::new_v4();
    request.extensions_mut().insert(request_id);

    let span = tracing::info_span!(
        "request",
        request_id = %request_id,
        method = %request.method(),
        uri = %request.uri()
    );

    let response = async move { next.run(request).await }
        .instrument(span)
        .await;

    response
}

pub type AppState = Arc<dyn DbService>;

// Response types
#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

#[derive(Serialize)]
struct HealthStatus {
    status: String, // "healthy", "degraded", "unhealthy"
    redis: bool,
    timestamp: String,
}

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    fn error(message: String) -> ApiResponse<()> {
        ApiResponse {
            success: false,
            data: None,
            error: Some(message),
        }
    }
}

// Convert AppError to HTTP response
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            AppError::AlreadyExists(msg) => (StatusCode::CONFLICT, msg),
            AppError::InvalidInput(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::AuthenticationFailed => (
                StatusCode::UNAUTHORIZED,
                "Authentication failed".to_string(),
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
        };

        (status, Json(ApiResponse::<()>::error(message))).into_response()
    }
}

// User endpoints
#[instrument(skip(db), fields(org = %user.organization, username = %user.username))]
async fn create_user(
    State(db): State<AppState>,
    Json(user): Json<UserCreate>,
) -> Result<impl IntoResponse, AppError> {
    debug!("Creating new user");
    let created_user = db.create_user(user).await?;
    let response: UserResponse = created_user.into();
    debug!("User created successfully");
    Ok((StatusCode::CREATED, Json(ApiResponse::success(response))))
}

async fn get_user(
    State(db): State<AppState>,
    Path((org, username)): Path<(String, String)>,
) -> Result<impl IntoResponse, AppError> {
    let user = db.get_user(&org, &username).await?;
    let response: UserResponse = user.into();
    Ok(Json(ApiResponse::success(response)))
}

async fn update_user(
    State(db): State<AppState>,
    Path((org, username)): Path<(String, String)>,
    Json(update): Json<UserUpdate>,
) -> Result<impl IntoResponse, AppError> {
    let user = db.update_user(&org, &username, update).await?;
    let response: UserResponse = user.into();
    Ok(Json(ApiResponse::success(response)))
}

#[instrument(skip(db))]
async fn delete_user(
    State(db): State<AppState>,
    Path((org, username)): Path<(String, String)>,
) -> Result<impl IntoResponse, AppError> {
    debug!("Deleting user");
    db.delete_user(&org, &username).await?;
    debug!("User deleted successfully");
    Ok((StatusCode::NO_CONTENT, ()))
}

async fn list_users(
    State(db): State<AppState>,
    Path(org): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let users = db.list_users(&org).await?;
    let responses: Vec<UserResponse> = users.into_iter().map(|u| u.into()).collect();
    Ok(Json(ApiResponse::success(responses)))
}

// Group endpoints
#[instrument(skip(db), fields(org = %group.organization, group_name = %group.name))]
async fn create_group(
    State(db): State<AppState>,
    Json(group): Json<GroupCreate>,
) -> Result<impl IntoResponse, AppError> {
    debug!("Creating new group");
    let created_group = db.create_group(group).await?;
    debug!("Group created successfully");
    Ok((
        StatusCode::CREATED,
        Json(ApiResponse::success(created_group)),
    ))
}

async fn get_group(
    State(db): State<AppState>,
    Path((org, name)): Path<(String, String)>,
) -> Result<impl IntoResponse, AppError> {
    let group = db.get_group(&org, &name).await?;
    Ok(Json(ApiResponse::success(group)))
}

async fn update_group(
    State(db): State<AppState>,
    Path((org, name)): Path<(String, String)>,
    Json(update): Json<GroupUpdate>,
) -> Result<impl IntoResponse, AppError> {
    let group = db.update_group(&org, &name, update).await?;
    Ok(Json(ApiResponse::success(group)))
}

async fn delete_group(
    State(db): State<AppState>,
    Path((org, name)): Path<(String, String)>,
) -> Result<impl IntoResponse, AppError> {
    db.delete_group(&org, &name).await?;
    Ok((StatusCode::NO_CONTENT, ()))
}

async fn list_groups(
    State(db): State<AppState>,
    Path(org): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let groups = db.list_groups(&org).await?;
    Ok(Json(ApiResponse::success(groups)))
}

#[derive(Deserialize)]
struct AddMemberRequest {
    username: String,
}

async fn add_member_to_group(
    State(db): State<AppState>,
    Path((org, name)): Path<(String, String)>,
    Json(req): Json<AddMemberRequest>,
) -> Result<impl IntoResponse, AppError> {
    let group = db.add_user_to_group(&org, &name, &req.username).await?;
    Ok(Json(ApiResponse::success(group)))
}

async fn remove_member_from_group(
    State(db): State<AppState>,
    Path((org, name, username)): Path<(String, String, String)>,
) -> Result<impl IntoResponse, AppError> {
    let group = db.remove_user_from_group(&org, &name, &username).await?;
    Ok(Json(ApiResponse::success(group)))
}

async fn get_user_groups(
    State(db): State<AppState>,
    Path((org, username)): Path<(String, String)>,
) -> Result<impl IntoResponse, AppError> {
    let groups = db.get_user_groups(&org, &username).await?;
    Ok(Json(ApiResponse::success(groups)))
}

// Health check
async fn health_check(State(db): State<AppState>) -> Result<impl IntoResponse, AppError> {
    let redis_healthy = db.health_check().await.unwrap_or(false);

    let status = if redis_healthy {
        "healthy"
    } else {
        "unhealthy"
    };

    let health = HealthStatus {
        status: status.to_string(),
        redis: redis_healthy,
        timestamp: Utc::now().to_rfc3339(),
    };

    let http_status = if redis_healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    Ok((http_status, Json(ApiResponse::success(health))))
}

/// Get CA certificate endpoint
/// Returns the CA certificate in PEM format if TLS is enabled
async fn get_ca_certificate() -> Result<impl IntoResponse, AppError> {
    let config = Config::from_env();

    if !config.enable_tls {
        return Err(AppError::InvalidInput(
            "TLS is not enabled on this server".to_string(),
        ));
    }

    let cert_path = config
        .tls_cert_path
        .ok_or_else(|| AppError::Internal("TLS_CERT_PATH not configured".to_string()))?;

    let ca_cert = tls::extract_ca_certificate(&cert_path)?;

    Ok((
        StatusCode::OK,
        [("content-type", "application/x-pem-file")],
        ca_cert,
    ))
}

/// Create the API router with bearer token authentication
pub fn create_router(db: Arc<dyn DbService>) -> Router {
    // Protected routes that require authentication
    let protected_routes = Router::new()
        // User routes
        .route("/api/users", post(create_user))
        .route("/api/users/{org}", get(list_users))
        .route("/api/users/{org}/{username}", get(get_user))
        .route("/api/users/{org}/{username}", put(update_user))
        .route("/api/users/{org}/{username}", delete(delete_user))
        .route("/api/users/{org}/{username}/groups", get(get_user_groups))
        // Group routes
        .route("/api/groups", post(create_group))
        .route("/api/groups/{org}", get(list_groups))
        .route("/api/groups/{org}/{name}", get(get_group))
        .route("/api/groups/{org}/{name}", put(update_group))
        .route("/api/groups/{org}/{name}", delete(delete_group))
        .route(
            "/api/groups/{org}/{name}/members",
            post(add_member_to_group),
        )
        .route(
            "/api/groups/{org}/{name}/members/{username}",
            delete(remove_member_from_group),
        )
        .layer(middleware::from_fn(validate_bearer_token));

    // Build router with metrics, timeout, and request ID
    let (prometheus_layer, prometheus_handle) = crate::metrics::get_prometheus_layer();
    Router::new()
        .route("/health", get(health_check))
        .route("/api/v1/ca-certificate", get(get_ca_certificate))
        .route(
            "/metrics",
            get(move || async move { prometheus_handle.render() }),
        )
        .merge(protected_routes)
        .layer(middleware::from_fn(add_request_id))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(30),
        ))
        .layer(prometheus_layer)
        .with_state(db)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::mock::MockDbService;

    #[tokio::test]
    async fn test_health_check_mock() {
        let mut mock_db = MockDbService::new();
        mock_db.expect_health_check().returning(|| Ok(true));

        let _app = create_router(Arc::new(mock_db));

        // Just verify the router can be created with a mock
        // Full integration testing is done in integration tests
    }
}
