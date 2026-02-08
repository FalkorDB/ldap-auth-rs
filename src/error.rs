use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Already exists: {0}")]
    AlreadyExists(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),

    #[error("Connection pool error: {0}")]
    Pool(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl From<deadpool_redis::PoolError> for AppError {
    fn from(err: deadpool_redis::PoolError) -> Self {
        AppError::Pool(format!("Connection pool error: {}", err))
    }
}

impl From<deadpool_redis::redis::RedisError> for AppError {
    fn from(err: deadpool_redis::redis::RedisError) -> Self {
        AppError::Database(format!("Redis error: {}", err))
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
