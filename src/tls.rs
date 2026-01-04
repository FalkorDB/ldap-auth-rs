use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use crate::error::{AppError, Result};

/// Load TLS configuration from certificate and key files
pub fn load_tls_config(cert_path: &str, key_path: &str) -> Result<Arc<ServerConfig>> {
    // Load certificates
    let cert_file = File::open(cert_path)
        .map_err(|e| AppError::Internal(format!("Failed to open certificate file: {}", e)))?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<Certificate> = certs(&mut cert_reader)
        .map_err(|e| AppError::Internal(format!("Failed to parse certificates: {}", e)))?
        .into_iter()
        .map(Certificate)
        .collect();

    if certs.is_empty() {
        return Err(AppError::Internal(
            "No certificates found in file".to_string(),
        ));
    }

    // Load private key
    let key_file = File::open(key_path)
        .map_err(|e| AppError::Internal(format!("Failed to open key file: {}", e)))?;
    let mut key_reader = BufReader::new(key_file);
    let mut keys: Vec<PrivateKey> = pkcs8_private_keys(&mut key_reader)
        .map_err(|e| AppError::Internal(format!("Failed to parse private keys: {}", e)))?
        .into_iter()
        .map(PrivateKey)
        .collect();

    if keys.is_empty() {
        return Err(AppError::Internal(
            "No private keys found in file".to_string(),
        ));
    }

    let key = keys.remove(0);

    // Build TLS config
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| AppError::Internal(format!("Failed to build TLS config: {}", e)))?;

    Ok(Arc::new(config))
}

/// Generate self-signed certificates for testing
#[allow(dead_code)]
pub fn generate_test_certs() -> Result<(String, String)> {
    use std::io::Write;
    use std::process::Command;

    let temp_dir = std::env::temp_dir();

    // Generate unique filenames using timestamp and random number to avoid conflicts between tests
    let unique_id = format!(
        "{}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("System clock is set before UNIX epoch - this should never happen")
            .as_nanos(),
        rand::random::<u32>()
    );
    let cert_path = temp_dir.join(format!("test-cert-{}.pem", unique_id));
    let key_path = temp_dir.join(format!("test-key-{}.pem", unique_id));

    // Generate self-signed certificate using openssl with X.509 v3 extensions for rustls compatibility
    let key_path_str = key_path
        .to_str()
        .ok_or_else(|| AppError::Internal("Invalid UTF-8 in key path".to_string()))?;
    let cert_path_str = cert_path
        .to_str()
        .ok_or_else(|| AppError::Internal("Invalid UTF-8 in cert path".to_string()))?;

    let output = Command::new("openssl")
        .args(&[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            key_path_str,
            "-out",
            cert_path_str,
            "- days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
            "-addext",
            "basicConstraints=CA:FALSE",
        ])
        .output();

    match output {
        Ok(result) if result.status.success() => {
            Ok((cert_path_str.to_string(), key_path_str.to_string()))
        }
        Ok(result) => Err(AppError::Internal(format!(
            "Failed to generate test certificates: {}",
            String::from_utf8_lossy(&result.stderr)
        ))),
        Err(e) => Err(AppError::Internal(format!(
            "Failed to execute openssl: {}. Note: openssl must be installed for TLS tests",
            e
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_test_certs() {
        // This test requires openssl to be installed
        let result = generate_test_certs();

        if result.is_err() {
            eprintln!(
                "Warning: Failed to generate test certificates. OpenSSL may not be installed."
            );
            eprintln!("Error: {:?}", result.err());
            return;
        }

        let (cert_path, key_path) = result.unwrap();

        // Verify files exist
        assert!(std::path::Path::new(&cert_path).exists());
        assert!(std::path::Path::new(&key_path).exists());

        // Try to load the config
        let config_result = load_tls_config(&cert_path, &key_path);
        assert!(config_result.is_ok());

        // Cleanup
        std::fs::remove_file(cert_path).ok();
        std::fs::remove_file(key_path).ok();
    }

    #[test]
    fn test_load_tls_config_missing_files() {
        let result = load_tls_config("/nonexistent/cert.pem", "/nonexistent/key.pem");
        assert!(result.is_err());
    }
}
