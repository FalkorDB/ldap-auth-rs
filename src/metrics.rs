use axum_prometheus::{PrometheusMetricLayer, metrics_exporter_prometheus::PrometheusHandle};
use once_cell::sync::Lazy;
use prometheus::{Encoder, TextEncoder};

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

/// Render a merged metrics payload that includes both axum-prometheus recorder
/// metrics and metrics registered in the default Prometheus registry.
pub fn render_combined_metrics(prometheus_handle: &PrometheusHandle) -> String {
    let mut merged = prometheus_handle.render();

    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();
    if encoder.encode(&prometheus::gather(), &mut buffer).is_ok() {
        if !merged.ends_with('\n') {
            merged.push('\n');
        }
        if let Ok(default_registry_text) = String::from_utf8(buffer) {
            merged.push_str(&default_registry_text);
        }
    }

    merged
}

/// Custom metrics for application-specific tracking
pub mod custom {
    use once_cell::sync::Lazy;
    use prometheus::{
        CounterVec, HistogramVec, IntGauge, IntGaugeVec, register_counter_vec,
        register_histogram_vec, register_int_gauge, register_int_gauge_vec,
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

    /// User operations gauge (total from DB)
    #[allow(dead_code)]
    pub static USER_OPERATIONS: Lazy<IntGaugeVec> = Lazy::new(|| {
        register_int_gauge_vec!(
            "ldap_user_operations_total",
            "Total number of user operations",
            &["organization", "operation"]
        )
        .expect("Failed to register user_operations gauge")
    });

    /// Group operations gauge (total from DB)
    #[allow(dead_code)]
    pub static GROUP_OPERATIONS: Lazy<IntGaugeVec> = Lazy::new(|| {
        register_int_gauge_vec!(
            "ldap_group_operations_total",
            "Total number of group operations",
            &["organization", "operation"]
        )
        .expect("Failed to register group_operations gauge")
    });

    /// Legacy group operations counter (kept for backward compatibility)
    #[allow(dead_code)]
    pub static GROUP_OPERATIONS_LEGACY: Lazy<CounterVec> = Lazy::new(|| {
        register_counter_vec!(
            "group_operations_total",
            "Total number of group operations",
            &["organization", "operation", "result"]
        )
        .expect("Failed to register legacy group_operations counter")
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

/// Helper function to record user operations (sets gauge value which is eventually synced)
#[allow(dead_code)]
pub fn record_user_operation(org: &str, operation: &str, count: i64) {
    let safe = if count < 0 { 0 } else { count };
    custom::USER_OPERATIONS
        .with_label_values(&[org, operation])
        .set(safe);
}

/// Helper function to record group operations (sets gauge value which is eventually synced)
#[allow(dead_code)]
pub fn record_group_operation(org: &str, operation: &str, count: i64) {
    let safe = if count < 0 { 0 } else { count };
    custom::GROUP_OPERATIONS
        .with_label_values(&[org, operation])
        .set(safe);
}

/// Helper function to set organization count
#[allow(dead_code)]
pub fn set_organizations_count(count: i64) {
    let safe = if count < 0 { 0 } else { count };
    custom::ORGANIZATIONS_COUNT.set(safe);
}

/// Helper function to set user count per organization
#[allow(dead_code)]
pub fn set_users_count(org: &str, count: i64) {
    let safe = if count < 0 { 0 } else { count };
    custom::USERS_COUNT.with_label_values(&[org]).set(safe);
}

/// Helper function to set group count per organization
#[allow(dead_code)]
pub fn set_groups_count(org: &str, count: i64) {
    let safe = if count < 0 { 0 } else { count };
    custom::GROUPS_COUNT.with_label_values(&[org]).set(safe);
}
