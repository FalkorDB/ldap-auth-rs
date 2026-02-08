use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use std::fs::File;
use std::io::{BufReader, Read};
use std::sync::Arc;

use crate::error::{AppError, Result};

/// Load TLS configuration from certificate and key files
pub fn load_tls_config(cert_path: &str, key_path: &str) -> Result<Arc<ServerConfig>> {
    // Load certificates
    let cert_file = File::open(cert_path)
        .map_err(|e| AppError::Internal(format!("Failed to open certificate file: {}", e)))?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> = certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| AppError::Internal(format!("Failed to parse certificates: {}", e)))?;

    if certs.is_empty() {
        return Err(AppError::Internal(
            "No certificates found in file".to_string(),
        ));
    }

    // Load private key
    // cert-manager commonly emits RSA keys in PKCS#1 (tls.key) when `privateKey.encoding=PKCS1`.
    // rustls supports PKCS#1 and PKCS#8, so we accept either.
    let mut pkcs8_keys = {
        let key_file = File::open(key_path)
            .map_err(|e| AppError::Internal(format!("Failed to open key file: {}", e)))?;
        let mut key_reader = BufReader::new(key_file);
        pkcs8_private_keys(&mut key_reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| AppError::Internal(format!("Failed to parse private keys: {}", e)))?
    };

    let key = if let Some(key) = pkcs8_keys.pop() {
        PrivateKeyDer::Pkcs8(key)
    } else {
        let mut rsa_keys = {
            let key_file = File::open(key_path)
                .map_err(|e| AppError::Internal(format!("Failed to open key file: {}", e)))?;
            let mut key_reader = BufReader::new(key_file);
            rsa_private_keys(&mut key_reader)
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| AppError::Internal(format!("Failed to parse private keys: {}", e)))?
        };

        if rsa_keys.is_empty() {
            return Err(AppError::Internal(
                "No private keys found in file (expected PKCS#8 or PKCS#1 PEM)".to_string(),
            ));
        }

        PrivateKeyDer::Pkcs1(rsa_keys.remove(0))
    };

    // Build TLS config
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| AppError::Internal(format!("Failed to build TLS config: {}", e)))?;

    Ok(Arc::new(config))
}

/// Extract CA certificate from certificate chain file
/// Returns the last certificate in the chain (the CA/root certificate) in PEM format
/// For self-signed certificates, returns the certificate itself
pub fn extract_ca_certificate(cert_path: &str) -> Result<String> {
    // Read the entire certificate file
    let mut cert_file = File::open(cert_path)
        .map_err(|e| AppError::Internal(format!("Failed to open certificate file: {}", e)))?;

    let mut contents = String::new();
    cert_file
        .read_to_string(&mut contents)
        .map_err(|e| AppError::Internal(format!("Failed to read certificate file: {}", e)))?;

    // Parse all certificates
    let cert_reader = std::io::Cursor::new(contents.as_bytes());
    let mut cert_buf_reader = BufReader::new(cert_reader);
    let parsed_certs: Vec<CertificateDer<'static>> = certs(&mut cert_buf_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| AppError::Internal(format!("Failed to parse certificates: {}", e)))?;

    if parsed_certs.is_empty() {
        return Err(AppError::Internal(
            "No certificates found in file".to_string(),
        ));
    }

    // Split the file into individual PEM blocks
    let pem_blocks: Vec<&str> = contents
        .split("-----BEGIN CERTIFICATE-----")
        .filter(|s| !s.trim().is_empty())
        .collect();

    if pem_blocks.is_empty() {
        return Err(AppError::Internal("No PEM certificates found".to_string()));
    }

    // The CA certificate is the last one in the chain
    // For self-signed certs, there's only one certificate
    let ca_cert = if pem_blocks.len() == 1 {
        // Self-signed certificate
        format!("-----BEGIN CERTIFICATE-----{}", pem_blocks[0])
    } else {
        // Certificate chain - return the last one (root CA)
        format!(
            "-----BEGIN CERTIFICATE-----{}",
            pem_blocks[pem_blocks.len() - 1]
        )
    };

    Ok(ca_cert)
}

/// Generate self-signed certificates for testing
#[allow(dead_code)]
pub fn generate_test_certs() -> Result<(String, String)> {
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
        .args([
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
    use std::process::Command;

    #[test]
    fn test_generate_test_certs() {
        // Install default crypto provider for rustls
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

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

    #[test]
    fn test_load_tls_config_with_pkcs1_key() {
        // Install default crypto provider for rustls
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        // This test requires openssl to be installed.
        // It mimics cert-manager when `privateKey.encoding=PKCS1` (RSA PRIVATE KEY).
        let temp_dir = std::env::temp_dir();
        let unique_id = format!(
            "{}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("System clock is set before UNIX epoch - this should never happen")
                .as_nanos(),
            rand::random::<u32>()
        );

        let key_path = temp_dir.join(format!("test-pkcs1-key-{}.pem", unique_id));
        let cert_path = temp_dir.join(format!("test-pkcs1-cert-{}.pem", unique_id));

        let key_path_str = key_path
            .to_str()
            .expect("Invalid UTF-8 in generated key path")
            .to_string();
        let cert_path_str = cert_path
            .to_str()
            .expect("Invalid UTF-8 in generated cert path")
            .to_string();

        // Generate a PKCS#1 RSA private key.
        let key_out = Command::new("openssl")
            .args(["genrsa", "-out", &key_path_str, "2048"])
            .output();

        match key_out {
            Ok(result) if result.status.success() => {}
            Ok(result) => {
                eprintln!(
                    "Warning: openssl genrsa failed: {}",
                    String::from_utf8_lossy(&result.stderr)
                );
                return;
            }
            Err(e) => {
                eprintln!("Warning: openssl not available: {}", e);
                return;
            }
        }

        // Generate a self-signed cert using that key.
        let cert_out = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-new",
                "-key",
                &key_path_str,
                "-out",
                &cert_path_str,
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost",
                "-addext",
                "basicConstraints=CA:FALSE",
            ])
            .output();

        match cert_out {
            Ok(result) if result.status.success() => {}
            Ok(result) => {
                eprintln!(
                    "Warning: openssl req failed: {}",
                    String::from_utf8_lossy(&result.stderr)
                );
                let _ = std::fs::remove_file(&key_path_str);
                return;
            }
            Err(e) => {
                eprintln!("Warning: openssl not available: {}", e);
                let _ = std::fs::remove_file(&key_path_str);
                return;
            }
        }

        let config_result = load_tls_config(&cert_path_str, &key_path_str);
        assert!(
            config_result.is_ok(),
            "Expected PKCS#1 key to be accepted, got: {:?}",
            config_result.err()
        );

        // Cleanup
        std::fs::remove_file(cert_path_str).ok();
        std::fs::remove_file(key_path_str).ok();
    }

    #[test]
    fn test_extract_ca_certificate_self_signed() {
        // Test extracting CA from a self-signed certificate
        use std::process::Command;

        let temp_dir = std::env::temp_dir();
        let unique_id = format!(
            "{}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("System clock is set before UNIX epoch")
                .as_nanos(),
            rand::random::<u32>()
        );

        let cert_path = temp_dir.join(format!("test-self-signed-{}.pem", unique_id));
        let cert_path_str = cert_path
            .to_str()
            .expect("Invalid UTF-8 in generated cert path")
            .to_string();

        // Generate self-signed certificate
        let output = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                "/dev/null",
                "-out",
                &cert_path_str,
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=test.example.com",
            ])
            .output();

        match output {
            Ok(result) if result.status.success() => {}
            Ok(result) => {
                eprintln!(
                    "Warning: openssl failed: {}",
                    String::from_utf8_lossy(&result.stderr)
                );
                return;
            }
            Err(e) => {
                eprintln!("Warning: openssl not available: {}", e);
                return;
            }
        }

        // Extract CA certificate
        let ca_cert = extract_ca_certificate(&cert_path_str);
        assert!(
            ca_cert.is_ok(),
            "Failed to extract CA certificate: {:?}",
            ca_cert.err()
        );

        let ca_pem = ca_cert.unwrap();
        assert!(ca_pem.contains("-----BEGIN CERTIFICATE-----"));
        assert!(ca_pem.contains("-----END CERTIFICATE-----"));

        // Cleanup
        std::fs::remove_file(cert_path_str).ok();
    }

    #[test]
    fn test_extract_ca_certificate_chain() {
        // Test extracting CA from a certificate chain
        use std::process::Command;

        let temp_dir = std::env::temp_dir();
        let unique_id = format!(
            "{}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("System clock is set before UNIX epoch")
                .as_nanos(),
            rand::random::<u32>()
        );

        // Create CA cert
        let ca_key_path = temp_dir.join(format!("test-ca-key-{}.pem", unique_id));
        let ca_cert_path = temp_dir.join(format!("test-ca-cert-{}.pem", unique_id));

        let ca_key_str = ca_key_path.to_str().expect("Invalid UTF-8");
        let ca_cert_str = ca_cert_path.to_str().expect("Invalid UTF-8");

        // Generate CA key and certificate
        let ca_result = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                ca_key_str,
                "-out",
                ca_cert_str,
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=Test CA",
            ])
            .output();

        match ca_result {
            Ok(result) if result.status.success() => {}
            Ok(result) => {
                eprintln!(
                    "Warning: CA generation failed: {}",
                    String::from_utf8_lossy(&result.stderr)
                );
                return;
            }
            Err(e) => {
                eprintln!("Warning: openssl not available: {}", e);
                return;
            }
        }

        // Create server key
        let server_key_path = temp_dir.join(format!("test-server-key-{}.pem", unique_id));
        let server_key_str = server_key_path.to_str().expect("Invalid UTF-8");

        let key_result = Command::new("openssl")
            .args(["genrsa", "-out", server_key_str, "2048"])
            .output();

        if !matches!(key_result, Ok(ref result) if result.status.success()) {
            std::fs::remove_file(ca_key_str).ok();
            std::fs::remove_file(ca_cert_str).ok();
            return;
        }

        // Create server CSR
        let server_csr_path = temp_dir.join(format!("test-server-csr-{}.pem", unique_id));
        let server_csr_str = server_csr_path.to_str().expect("Invalid UTF-8");

        let csr_result = Command::new("openssl")
            .args([
                "req",
                "-new",
                "-key",
                server_key_str,
                "-out",
                server_csr_str,
                "-subj",
                "/CN=server.example.com",
            ])
            .output();

        if !matches!(csr_result, Ok(ref result) if result.status.success()) {
            std::fs::remove_file(ca_key_str).ok();
            std::fs::remove_file(ca_cert_str).ok();
            std::fs::remove_file(server_key_str).ok();
            return;
        }

        // Sign server cert with CA
        let server_cert_path = temp_dir.join(format!("test-server-cert-{}.pem", unique_id));
        let server_cert_str = server_cert_path.to_str().expect("Invalid UTF-8");

        let sign_result = Command::new("openssl")
            .args([
                "x509",
                "-req",
                "-in",
                server_csr_str,
                "-CA",
                ca_cert_str,
                "-CAkey",
                ca_key_str,
                "-CAcreateserial",
                "-out",
                server_cert_str,
                "-days",
                "1",
            ])
            .output();

        if !matches!(sign_result, Ok(ref result) if result.status.success()) {
            std::fs::remove_file(ca_key_str).ok();
            std::fs::remove_file(ca_cert_str).ok();
            std::fs::remove_file(server_key_str).ok();
            std::fs::remove_file(server_csr_str).ok();
            return;
        }

        // Create certificate chain (server cert + CA cert)
        let chain_path = temp_dir.join(format!("test-chain-{}.pem", unique_id));
        let chain_str = chain_path.to_str().expect("Invalid UTF-8");

        let server_cert_content =
            std::fs::read_to_string(server_cert_str).expect("Failed to read server cert");
        let ca_cert_content = std::fs::read_to_string(ca_cert_str).expect("Failed to read CA cert");
        let chain_content = format!("{}\n{}", server_cert_content, ca_cert_content);
        std::fs::write(chain_str, chain_content).expect("Failed to write chain");

        // Extract CA certificate from chain
        let ca_cert = extract_ca_certificate(chain_str);
        assert!(
            ca_cert.is_ok(),
            "Failed to extract CA certificate from chain: {:?}",
            ca_cert.err()
        );

        let ca_pem = ca_cert.unwrap();
        assert!(ca_pem.contains("-----BEGIN CERTIFICATE-----"));
        assert!(ca_pem.contains("-----END CERTIFICATE-----"));

        // Verify it's the CA cert by checking the subject
        let verify_result = Command::new("openssl")
            .args(["x509", "-noout", "-subject"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                child.stdin.as_mut().unwrap().write_all(ca_pem.as_bytes())?;
                child.wait_with_output()
            });

        if let Ok(output) = verify_result {
            let subject = String::from_utf8_lossy(&output.stdout);
            assert!(
                subject.contains("Test CA"),
                "Expected CA subject, got: {}",
                subject
            );
        }

        // Cleanup
        std::fs::remove_file(ca_key_str).ok();
        std::fs::remove_file(ca_cert_str).ok();
        std::fs::remove_file(server_key_str).ok();
        std::fs::remove_file(server_csr_str).ok();
        std::fs::remove_file(server_cert_str).ok();
        std::fs::remove_file(chain_str).ok();
    }
}
