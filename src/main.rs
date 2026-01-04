mod api;
mod auth;
mod config;
mod db;
mod error;
mod ldap;
mod metrics;
mod models;
mod password;
mod redis_db;
mod tls;

use std::sync::Arc;
use tokio::signal;
use tracing::{info, Level};
use tracing_subscriber;

use config::Config;
use redis_db::RedisDbService;

/// Signal handler for graceful shutdown
async fn shutdown_signal() -> anyhow::Result<()> {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to install Ctrl+C handler: {}", e))
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
                Ok(())
            }
            Err(e) => Err(anyhow::anyhow!("Failed to install SIGTERM handler: {}", e)),
        }
    };

    #[cfg(not(unix))]
    let terminate = async { Ok::<(), anyhow::Error>(()) };

    tokio::select! {
        result = ctrl_c => result?,
        result = terminate => result?,
    }

    info!("Received shutdown signal, shutting down gracefully...");
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    info!("Starting LDAP Auth RS");

    // Load configuration
    let config = Config::from_env();
    info!("Configuration loaded: TLS={}", config.enable_tls);

    // Validate configuration
    config.validate()?;
    info!("Configuration validated successfully");

    // Initialize database
    let redis_url = config.redis_url();
    let db = Arc::new(RedisDbService::new(&redis_url).await?) as Arc<dyn db::DbService>;
    info!(
        "Connected to Redis at {}:{}",
        config.redis_host, config.redis_port
    );

    // Start API server with optional TLS
    let api_db = db.clone();
    let api_addr = config.api_address();
    let api_config = config.clone();
    let _api_handle = tokio::spawn(async move {
        let app = api::create_router(api_db);

        if api_config.enable_tls {
            if let (Some(cert_path), Some(key_path)) =
                (&api_config.tls_cert_path, &api_config.tls_key_path)
            {
                info!("Starting API server with TLS on {}", api_addr);
                match axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path)
                    .await
                {
                    Ok(tls_config) => {
                        let addr = api_addr.parse().map_err(|e| {
                            anyhow::anyhow!("Invalid API address {}: {}", api_addr, e)
                        })?;
                        axum_server::bind_rustls(addr, tls_config)
                            .serve(app.into_make_service())
                            .await
                            .map_err(|e| anyhow::anyhow!("API server error: {}", e))?;
                    }
                    Err(e) => {
                        return Err(anyhow::anyhow!("Failed to load TLS config for API: {}", e));
                    }
                }
            } else {
                return Err(anyhow::anyhow!(
                    "TLS enabled but certificate paths not provided"
                ));
            }
        } else {
            info!("Starting API server (no TLS) on {}", api_addr);
            let listener = tokio::net::TcpListener::bind(&api_addr)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to bind API server on {}: {}", api_addr, e))?;
            axum::serve(listener, app)
                .await
                .map_err(|e| anyhow::anyhow!("API server error: {}", e))?;
        }
        Ok(())
    });

    // Start LDAP server with optional TLS
    let ldap_db = db.clone();
    let ldap_addr = config.ldap_address();
    let base_dn = config.ldap_base_dn.clone();
    let ldap_config = config.clone();
    let _ldap_handle = tokio::spawn(async move {
        let ldap_server = ldap::LdapServer::new(ldap_db, base_dn);

        if ldap_config.enable_tls {
            if let (Some(cert_path), Some(key_path)) =
                (&ldap_config.tls_cert_path, &ldap_config.tls_key_path)
            {
                info!("Starting LDAP server with TLS on {}", ldap_addr);
                let tls_config = tls::load_tls_config(cert_path, key_path)
                    .map_err(|e| anyhow::anyhow!("Failed to load TLS config for LDAP: {}", e))?;
                ldap_server
                    .run_with_tls(&ldap_addr, tls_config)
                    .await
                    .map_err(|e| anyhow::anyhow!("LDAP server error: {}", e))?;
            } else {
                return Err(anyhow::anyhow!(
                    "TLS enabled but certificate paths not provided"
                ));
            }
        } else {
            info!("Starting LDAP server (no TLS) on {}", ldap_addr);
            ldap_server
                .run(&ldap_addr)
                .await
                .map_err(|e| anyhow::anyhow!("LDAP server error: {}", e))?;
        }
        Ok(())
    });

    info!("All services started successfully");

    // Wait for shutdown signal
    shutdown_signal().await?;

    info!("Shutdown complete");
    Ok(())
}
