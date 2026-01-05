use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "ldap-auth-cli")]
#[command(about = "CLI tool for interacting with the LDAP Auth Service API", long_about = None)]
struct Cli {
    /// API base URL (defaults to http://localhost:8080)
    #[arg(
        short,
        long,
        env = "LDAP_AUTH_URL",
        default_value = "http://localhost:8080"
    )]
    url: String,

    /// Bearer token for authentication
    #[arg(short, long, env = "LDAP_AUTH_TOKEN")]
    token: Option<String>,

    /// Allow insecure TLS connections (skip certificate verification)
    #[arg(long, env = "LDAP_AUTH_INSECURE")]
    insecure: bool,

    /// Path to CA certificate file for TLS verification
    #[arg(long, env = "LDAP_AUTH_CA_CERT")]
    ca_cert: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Health check
    Health,

    /// User management
    #[command(subcommand)]
    User(UserCommands),

    /// Group management
    #[command(subcommand)]
    Group(GroupCommands),
}

#[derive(Subcommand)]
enum UserCommands {
    /// Create a new user
    Create {
        /// Organization
        #[arg(short, long)]
        org: String,
        /// Username
        #[arg(short, long)]
        username: String,
        /// Password
        #[arg(short, long)]
        password: String,
        /// Email
        #[arg(short, long)]
        email: String,
        /// Full name
        #[arg(short, long)]
        name: String,
    },
    /// Get a user
    Get {
        /// Organization
        #[arg(short, long)]
        org: String,
        /// Username
        #[arg(short, long)]
        username: String,
    },
    /// List users in an organization
    List {
        /// Organization
        #[arg(short, long)]
        org: String,
    },
    /// Update a user
    Update {
        /// Organization
        #[arg(short, long)]
        org: String,
        /// Username
        #[arg(short, long)]
        username: String,
        /// New email
        #[arg(long)]
        email: Option<String>,
        /// New full name
        #[arg(long)]
        name: Option<String>,
        /// New password
        #[arg(long)]
        password: Option<String>,
    },
    /// Delete a user
    Delete {
        /// Organization
        #[arg(short, long)]
        org: String,
        /// Username
        #[arg(short, long)]
        username: String,
    },
    /// Get user's groups
    Groups {
        /// Organization
        #[arg(short, long)]
        org: String,
        /// Username
        #[arg(short, long)]
        username: String,
    },
}

#[derive(Subcommand)]
enum GroupCommands {
    /// Create a new group
    Create {
        /// Organization
        #[arg(short, long)]
        org: String,
        /// Group name
        #[arg(short, long)]
        name: String,
        /// Description
        #[arg(short, long)]
        description: String,
    },
    /// Get a group
    Get {
        /// Organization
        #[arg(short, long)]
        org: String,
        /// Group name
        #[arg(short, long)]
        name: String,
    },
    /// List groups in an organization
    List {
        /// Organization
        #[arg(short, long)]
        org: String,
    },
    /// Update a group
    Update {
        /// Organization
        #[arg(short, long)]
        org: String,
        /// Group name
        #[arg(short, long)]
        name: String,
        /// New description
        #[arg(short, long)]
        description: String,
    },
    /// Delete a group
    Delete {
        /// Organization
        #[arg(short, long)]
        org: String,
        /// Group name
        #[arg(short, long)]
        name: String,
    },
    /// Add a member to a group
    AddMember {
        /// Organization
        #[arg(short, long)]
        org: String,
        /// Group name
        #[arg(short, long)]
        name: String,
        /// Username to add
        #[arg(short, long)]
        username: String,
    },
    /// Remove a member from a group
    RemoveMember {
        /// Organization
        #[arg(short, long)]
        org: String,
        /// Group name
        #[arg(short, long)]
        name: String,
        /// Username to remove
        #[arg(short, long)]
        username: String,
    },
}

#[derive(Serialize)]
struct UserCreate {
    organization: String,
    username: String,
    password: String,
    email: String,
    full_name: String,
}

#[derive(Serialize)]
struct UserUpdate {
    email: Option<String>,
    full_name: Option<String>,
    password: Option<String>,
}

#[derive(Serialize)]
struct GroupCreate {
    organization: String,
    name: String,
    description: String,
}

#[derive(Serialize)]
struct GroupUpdate {
    description: String,
}

#[derive(Serialize)]
struct AddMemberRequest {
    username: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

async fn make_request(
    client: &Client,
    method: reqwest::Method,
    url: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> Result<Value> {
    let mut req = client.request(method, url);

    if let Some(token) = token {
        req = req.header("Authorization", format!("Bearer {}", token));
    }

    if let Some(body) = body {
        req = req.json(&body);
    }

    let response = req.send().await.context("Failed to send request")?;
    let status = response.status();
    let text = response.text().await.context("Failed to read response")?;

    if !status.is_success() {
        anyhow::bail!("Request failed with status {}: {}", status, text);
    }

    let value: Value = serde_json::from_str(&text).context("Failed to parse response as JSON")?;

    Ok(value)
}

fn print_response(response: Value) {
    if let Some(obj) = response.as_object() {
        if let Some(success) = obj.get("success").and_then(|v| v.as_bool()) {
            if success {
                if let Some(data) = obj.get("data") {
                    println!("{}", serde_json::to_string_pretty(data).unwrap());
                } else {
                    println!("✓ Success");
                }
            } else if let Some(error) = obj.get("error").and_then(|v| v.as_str()) {
                eprintln!("✗ Error: {}", error);
            }
        } else {
            println!("{}", serde_json::to_string_pretty(&response).unwrap());
        }
    } else {
        println!("{}", serde_json::to_string_pretty(&response).unwrap());
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Build HTTP client with TLS configuration
    let mut client_builder = Client::builder();

    if cli.insecure {
        client_builder = client_builder.danger_accept_invalid_certs(true);
    }

    if let Some(ca_cert_path) = &cli.ca_cert {
        let ca_cert_contents = std::fs::read(ca_cert_path)
            .with_context(|| format!("Failed to read CA certificate from {:?}", ca_cert_path))?;
        let ca_cert = reqwest::Certificate::from_pem(&ca_cert_contents)
            .context("Failed to parse CA certificate")?;
        client_builder = client_builder.add_root_certificate(ca_cert);
    }

    let client = client_builder
        .build()
        .context("Failed to build HTTP client")?;

    match cli.command {
        Commands::Health => {
            let url = format!("{}/health", cli.url);
            let response = make_request(&client, reqwest::Method::GET, &url, None, None).await?;
            print_response(response);
        }

        Commands::User(cmd) => match cmd {
            UserCommands::Create {
                org,
                username,
                password,
                email,
                name,
            } => {
                let token = cli
                    .token
                    .as_deref()
                    .context("Token required for this operation")?;
                let url = format!("{}/api/users", cli.url);
                let user = UserCreate {
                    organization: org,
                    username,
                    password,
                    email,
                    full_name: name,
                };
                let response = make_request(
                    &client,
                    reqwest::Method::POST,
                    &url,
                    Some(token),
                    Some(serde_json::to_value(user)?),
                )
                .await?;
                print_response(response);
            }

            UserCommands::Get { org, username } => {
                let token = cli
                    .token
                    .as_deref()
                    .context("Token required for this operation")?;
                let url = format!("{}/api/users/{}/{}", cli.url, org, username);
                let response =
                    make_request(&client, reqwest::Method::GET, &url, Some(token), None).await?;
                print_response(response);
            }

            UserCommands::List { org } => {
                let token = cli
                    .token
                    .as_deref()
                    .context("Token required for this operation")?;
                let url = format!("{}/api/users/{}", cli.url, org);
                let response =
                    make_request(&client, reqwest::Method::GET, &url, Some(token), None).await?;
                print_response(response);
            }

            UserCommands::Update {
                org,
                username,
                email,
                name,
                password,
            } => {
                let token = cli
                    .token
                    .as_deref()
                    .context("Token required for this operation")?;
                let url = format!("{}/api/users/{}/{}", cli.url, org, username);
                let update = UserUpdate {
                    email,
                    full_name: name,
                    password,
                };
                let response = make_request(
                    &client,
                    reqwest::Method::PUT,
                    &url,
                    Some(token),
                    Some(serde_json::to_value(update)?),
                )
                .await?;
                print_response(response);
            }

            UserCommands::Delete { org, username } => {
                let token = cli
                    .token
                    .as_deref()
                    .context("Token required for this operation")?;
                let url = format!("{}/api/users/{}/{}", cli.url, org, username);
                let response =
                    make_request(&client, reqwest::Method::DELETE, &url, Some(token), None).await?;
                print_response(response);
            }

            UserCommands::Groups { org, username } => {
                let token = cli
                    .token
                    .as_deref()
                    .context("Token required for this operation")?;
                let url = format!("{}/api/users/{}/{}/groups", cli.url, org, username);
                let response =
                    make_request(&client, reqwest::Method::GET, &url, Some(token), None).await?;
                print_response(response);
            }
        },

        Commands::Group(cmd) => match cmd {
            GroupCommands::Create {
                org,
                name,
                description,
            } => {
                let token = cli
                    .token
                    .as_deref()
                    .context("Token required for this operation")?;
                let url = format!("{}/api/groups", cli.url);
                let group = GroupCreate {
                    organization: org,
                    name,
                    description,
                };
                let response = make_request(
                    &client,
                    reqwest::Method::POST,
                    &url,
                    Some(token),
                    Some(serde_json::to_value(group)?),
                )
                .await?;
                print_response(response);
            }

            GroupCommands::Get { org, name } => {
                let token = cli
                    .token
                    .as_deref()
                    .context("Token required for this operation")?;
                let url = format!("{}/api/groups/{}/{}", cli.url, org, name);
                let response =
                    make_request(&client, reqwest::Method::GET, &url, Some(token), None).await?;
                print_response(response);
            }

            GroupCommands::List { org } => {
                let token = cli
                    .token
                    .as_deref()
                    .context("Token required for this operation")?;
                let url = format!("{}/api/groups/{}", cli.url, org);
                let response =
                    make_request(&client, reqwest::Method::GET, &url, Some(token), None).await?;
                print_response(response);
            }

            GroupCommands::Update {
                org,
                name,
                description,
            } => {
                let token = cli
                    .token
                    .as_deref()
                    .context("Token required for this operation")?;
                let url = format!("{}/api/groups/{}/{}", cli.url, org, name);
                let update = GroupUpdate { description };
                let response = make_request(
                    &client,
                    reqwest::Method::PUT,
                    &url,
                    Some(token),
                    Some(serde_json::to_value(update)?),
                )
                .await?;
                print_response(response);
            }

            GroupCommands::Delete { org, name } => {
                let token = cli
                    .token
                    .as_deref()
                    .context("Token required for this operation")?;
                let url = format!("{}/api/groups/{}/{}", cli.url, org, name);
                let response =
                    make_request(&client, reqwest::Method::DELETE, &url, Some(token), None).await?;
                print_response(response);
            }

            GroupCommands::AddMember {
                org,
                name,
                username,
            } => {
                let token = cli
                    .token
                    .as_deref()
                    .context("Token required for this operation")?;
                let url = format!("{}/api/groups/{}/{}/members", cli.url, org, name);
                let req = AddMemberRequest { username };
                let response = make_request(
                    &client,
                    reqwest::Method::POST,
                    &url,
                    Some(token),
                    Some(serde_json::to_value(req)?),
                )
                .await?;
                print_response(response);
            }

            GroupCommands::RemoveMember {
                org,
                name,
                username,
            } => {
                let token = cli
                    .token
                    .as_deref()
                    .context("Token required for this operation")?;
                let url = format!(
                    "{}/api/groups/{}/{}/members/{}",
                    cli.url, org, name, username
                );
                let response =
                    make_request(&client, reqwest::Method::DELETE, &url, Some(token), None).await?;
                print_response(response);
            }
        },
    }

    Ok(())
}
