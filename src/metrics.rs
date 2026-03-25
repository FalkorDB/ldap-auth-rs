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
    use prometheus::{
        register_counter_vec, register_histogram_vec, register_int_gauge, register_int_gauge_vec,
        CounterVec, HistogramVec, IntGauge, IntGaugeVec,
    };

    /// Authentication attempts counter (success/failure)
    #[allow(dead_code)]
    pub static AUTH_ATTEMPTS: Lazy<CounterVec> = Lazy::new(|| {
        register_counter_vec!(
            "ldap_auth_attempts_total",
            "Total number of authentication attempts",
            &["organization", "result"]
        )
        .expect("Failed to register auth_attempts counter")
    });

    /// LDAP bind operations counter
    #[allow(dead_code)]
    pub static LDAP_BINDS: Lazy<CounterVec> = Lazy::new(|| {
        register_counter_vec!(
            "ldap_bind_operations_total",
            "Total number of LDAP bind operations",
            &["organization", "result"]
        )
        .expect("Failed to register ldap_binds counter")
    });

    /// Redis operation latency histogram
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    pub static USER_OPERATIONS: Lazy<CounterVec> = Lazy::new(|| {
        register_counter_vec!(
            "ldap_user_operations_total",
            "Total number of user operations",
            &["organization", "operation", "result"]
        )
        .expect("Failed to register user_operations counter")
    });

    /// Group operations counter (create, update, delete, membership changes)
    #[allow(dead_code)]
    pub static GROUP_OPERATIONS: Lazy<CounterVec> = Lazy::new(|| {
        register_counter_vec!(
            "ldap_group_operations_total",
            "Total number of group operations",
            &["organization", "operation", "result"]
        )
        .expect("Failed to register group_operations counter")
    });

    /// Total number of organizations tracked by the service
    #[allow(dead_code)]
    pub static ORGANIZATIONS_COUNT: Lazy<IntGauge> = Lazy::new(|| {
        register_int_gauge!(
            "ldap_organizations_count",
            "Current total number of organizations"
        )
        .expect("Failed to register organizations_count gauge")
    });

    /// Total number of users per organization
    #[allow(dead_code)]
    pub static USERS_COUNT: Lazy<IntGaugeVec> = Lazy::new(|| {
        register_int_gauge_vec!(
            "ldap_users_count",
            "Current total number of users per organization",
            &["organization"]
        )
        .expect("Failed to register users_count gauge")
    });

    /// Total number of groups per organization
    #[allow(dead_code)]
    pub static GROUPS_COUNT: Lazy<IntGaugeVec> = Lazy::new(|| {
        register_int_gauge_vec!(
            "ldap_groups_count",
            "Current total number of groups per organization",
            &["organization"]
        )
        .expect("Failed to register groups_count gauge")
    });
}

/// Helper function to record authentication attempts
#[allow(dead_code)]
pub fn record_auth_attempt(org: &str, success: bool) {
    let result = if success { "success" } else { "failure" };
    custom::AUTH_ATTEMPTS
        .with_label_values(&[org, result])
        .inc();
}

/// Helper function to record LDAP bind operations
#[allow(dead_code)]
pub fn record_ldap_bind(org: &str, success: bool) {
    let result = if success { "success" } else { "failure" };
    custom::LDAP_BINDS.with_label_values(&[org, result]).inc();
}

/// Helper function to record user operations
#[allow(dead_code)]
pub fn record_user_operation(org: &str, operation: &str, success: bool) {
    let result = if success { "success" } else { "failure" };
    custom::USER_OPERATIONS
        .with_label_values(&[org, operation, result])
        .inc();
}

/// Helper function to record group operations
#[allow(dead_code)]
pub fn record_group_operation(org: &str, operation: &str, success: bool) {
    let result = if success { "success" } else { "failure" };
    custom::GROUP_OPERATIONS
        .with_label_values(&[org, operation, result])
        .inc();
}

/// Helper function to set organization count
#[allow(dead_code)]
pub fn set_organizations_count(count: i64) {
    custom::ORGANIZATIONS_COUNT.set(count);
}

/// Helper function to set user count per organization
#[allow(dead_code)]
pub fn set_users_count(org: &str, count: i64) {
    custom::USERS_COUNT.with_label_values(&[org]).set(count);
}

/// Helper function to set group count per organization
#[allow(dead_code)]
pub fn set_groups_count(org: &str, count: i64) {
    custom::GROUPS_COUNT.with_label_values(&[org]).set(count);
}
