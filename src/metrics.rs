use axum_prometheus::{metrics_exporter_prometheus::PrometheusHandle, PrometheusMetricLayer};
use once_cell::sync::Lazy;

/// Global Prometheus metrics layer and handle
/// Initialized once on first use to avoid registry conflicts in tests
static METRICS: Lazy<(PrometheusMetricLayer<'static>, PrometheusHandle)> =
    Lazy::new(PrometheusMetricLayer::pair);

/// Get the global Prometheus metrics layer and handle
/// This ensures only one registry is created, allowing tests to run without conflicts
pub fn get_prometheus_layer() -> (PrometheusMetricLayer<'static>, PrometheusHandle) {
    let (layer, handle) = &*METRICS;
    (layer.clone(), handle.clone())
}

/// Custom metrics for application-specific tracking
pub mod custom {
    use once_cell::sync::Lazy;
    use prometheus::{register_counter_vec, register_histogram_vec, CounterVec, HistogramVec};

    /// Authentication attempts counter (success/failure)
    pub static AUTH_ATTEMPTS: Lazy<CounterVec> = Lazy::new(|| {
        register_counter_vec!(
            "ldap_auth_attempts_total",
            "Total number of authentication attempts",
            &["organization", "result"]
        )
        .expect("Failed to register auth_attempts counter")
    });

    /// LDAP bind operations counter
    pub static LDAP_BINDS: Lazy<CounterVec> = Lazy::new(|| {
        register_counter_vec!(
            "ldap_bind_operations_total",
            "Total number of LDAP bind operations",
            &["organization", "result"]
        )
        .expect("Failed to register ldap_binds counter")
    });

    /// Redis operation latency histogram
    pub static REDIS_OPERATION_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
        register_histogram_vec!(
            "redis_operation_duration_seconds",
            "Duration of Redis operations in seconds",
            &["operation", "result"],
            vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
        )
        .expect("Failed to register redis_operation_duration histogram")
    });

    /// User operations counter (create, update, delete)
    pub static USER_OPERATIONS: Lazy<CounterVec> = Lazy::new(|| {
        register_counter_vec!(
            "user_operations_total",
            "Total number of user operations",
            &["organization", "operation", "result"]
        )
        .expect("Failed to register user_operations counter")
    });

    /// Group operations counter (create, update, delete, membership changes)
    pub static GROUP_OPERATIONS: Lazy<CounterVec> = Lazy::new(|| {
        register_counter_vec!(
            "group_operations_total",
            "Total number of group operations",
            &["organization", "operation", "result"]
        )
        .expect("Failed to register group_operations counter")
    });
}

/// Helper function to record authentication attempts
pub fn record_auth_attempt(org: &str, success: bool) {
    let result = if success { "success" } else { "failure" };
    custom::AUTH_ATTEMPTS
        .with_label_values(&[org, result])
        .inc();
}

/// Helper function to record LDAP bind operations
pub fn record_ldap_bind(org: &str, success: bool) {
    let result = if success { "success" } else { "failure" };
    custom::LDAP_BINDS.with_label_values(&[org, result]).inc();
}

/// Helper function to record user operations
pub fn record_user_operation(org: &str, operation: &str, success: bool) {
    let result = if success { "success" } else { "failure" };
    custom::USER_OPERATIONS
        .with_label_values(&[org, operation, result])
        .inc();
}

/// Helper function to record group operations
pub fn record_group_operation(org: &str, operation: &str, success: bool) {
    let result = if success { "success" } else { "failure" };
    custom::GROUP_OPERATIONS
        .with_label_values(&[org, operation, result])
        .inc();
}
