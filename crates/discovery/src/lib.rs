use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub scanned_at: String,
    pub clients: Vec<ClientFinding>,
    pub summary: Summary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientFinding {
    pub client: String,
    pub config_path: String,
    pub servers: Vec<ServerFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerFinding {
    pub name: String,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub env_keys: Vec<String>,
    pub url: Option<String>,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub kind: FindingKind,
    pub message: String,
    pub evidence: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    HardcodedSecret,
    UnpinnedVersion,
    MissingLock,
    InsecureTransport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Summary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub total_servers: usize,
}

pub fn scan(project_dir: Option<&Path>) -> Result<ScanReport, DiscoveryError> {
    let mut clients = Vec::new();
    let cwd = project_dir
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());

    let lock_exists = cwd.join("4madeus.lock").exists();

    for (client, path) in config_paths(&cwd) {
        if !path.exists() {
            continue;
        }
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(content.trim_start_matches('\u{FEFF}')) else {
            continue;
        };

        let mut servers = parse_servers(&value, client, lock_exists);

        if client == "claude-code" && path.ends_with(".claude.json") {
            if let Some(projects) = value.get("projects").and_then(|p| p.as_object()) {
                for (proj_path, proj_cfg) in projects {
                    let mut proj_servers = parse_servers(proj_cfg, client, lock_exists);
                    for s in &mut proj_servers {
                        s.name = format!("{} [{}]", s.name, proj_path);
                    }
                    servers.extend(proj_servers);
                }
            }
        }

        if !servers.is_empty() {
            clients.push(ClientFinding {
                client: client.to_string(),
                config_path: path.display().to_string(),
                servers,
            });
        }
    }

    let summary = compute_summary(&clients);
    Ok(ScanReport {
        scanned_at: chrono::Utc::now().to_rfc3339(),
        clients,
        summary,
    })
}

fn config_paths(cwd: &Path) -> Vec<(&'static str, PathBuf)> {
    let home = dirs::home_dir().unwrap_or_default();
    let mut paths = Vec::new();

    paths.push(("claude-desktop", home.join("Library/Application Support/Claude/claude_desktop_config.json")));
    if let Ok(appdata) = std::env::var("APPDATA") {
        paths.push(("claude-desktop", PathBuf::from(&appdata).join("Claude/claude_desktop_config.json")));
        paths.push(("vscode", PathBuf::from(&appdata).join("Code/User/mcp.json")));
        paths.push(("windsurf", PathBuf::from(&appdata).join("devin/mcp_config.json")));
    }
    if let Ok(localappdata) = std::env::var("LOCALAPPDATA") {
        paths.push(("claude-desktop", PathBuf::from(localappdata).join("Packages/Claude_pzs8sxrjxfjjc/LocalCache/Roaming/Claude/claude_desktop_config.json")));
    }
    paths.push(("claude-desktop", home.join(".config/Claude/claude_desktop_config.json")));
    paths.push(("cursor", home.join(".cursor/mcp.json")));
    paths.push(("cursor", cwd.join(".cursor/mcp.json")));
    paths.push(("claude-code", home.join(".claude.json")));
    paths.push(("portable-mcp", cwd.join(".mcp.json")));
    paths.push(("vscode", home.join("Library/Application Support/Code/User/mcp.json")));
    paths.push(("vscode", home.join(".config/Code/User/mcp.json")));
    paths.push(("vscode", cwd.join(".vscode/mcp.json")));
    paths.push(("windsurf", home.join(".codeium/windsurf/mcp_config.json")));
    paths.push(("windsurf", home.join(".config/devin/mcp_config.json")));

    paths
}

fn parse_servers(value: &serde_json::Value, client: &str, lock_exists: bool) -> Vec<ServerFinding> {
    let key = if client == "vscode" { "servers" } else { "mcpServers" };
    let Some(obj) = value.get(key).and_then(|v| v.as_object()) else {
        return Vec::new();
    };

    obj.iter()
        .map(|(name, cfg)| {
            let command = cfg.get("command").and_then(|v| v.as_str()).map(String::from);
            let args: Vec<String> = cfg
                .get("args")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default();
            let raw_env: HashMap<String, String> = cfg
                .get("env")
                .and_then(|v| v.as_object())
                .map(|m| {
                    m.iter()
                        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                        .collect()
                })
                .unwrap_or_default();
            let url = cfg
                .get("url")
                .or_else(|| cfg.get("serverUrl"))
                .and_then(|v| v.as_str())
                .map(String::from);

            let findings = detect_findings(&command, &args, &raw_env, &url, lock_exists);
            let mut env_keys: Vec<String> = raw_env.keys().cloned().collect();
            env_keys.sort();

            ServerFinding {
                name: name.clone(),
                command,
                args,
                env_keys,
                url,
                findings,
            }
        })
        .collect()
}

fn detect_findings(
    command: &Option<String>,
    args: &[String],
    env: &HashMap<String, String>,
    url: &Option<String>,
    lock_exists: bool,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (key, value) in env {
        if is_secret_key(key) && looks_like_secret_value(value) {
            findings.push(Finding {
                severity: Severity::Critical,
                kind: FindingKind::HardcodedSecret,
                message: format!("Hardcoded secret in env: {}", key),
                evidence: Some(mask_secret(value)),
            });
        }
    }

    for arg in args {
        if is_sensitive_path(arg) {
            findings.push(Finding {
                severity: Severity::Critical,
                kind: FindingKind::HardcodedSecret,
                message: format!("Sensitive path in args: {}", arg),
                evidence: Some(arg.clone()),
            });
        }
    }

    if let Some(u) = url {
        if u.starts_with("http://") && !u.contains("localhost") && !u.contains("127.0.0.1") {
            findings.push(Finding {
                severity: Severity::High,
                kind: FindingKind::InsecureTransport,
                message: format!("Unencrypted remote MCP endpoint: {}", u),
                evidence: Some(u.clone()),
            });
        }
    }

    if let Some(cmd) = command {
        if cmd == "npx" || cmd == "uvx" {
            for arg in args {
                if arg.starts_with('-') {
                    continue;
                }
                let without_scope = arg.strip_prefix('@').unwrap_or(arg);
                let has_pinned_version = if let Some((_, ver)) = without_scope.split_once('@') {
                    ver != "latest" && !ver.is_empty()
                } else {
                    arg.contains("==")
                };

                if !has_pinned_version {
                    findings.push(Finding {
                        severity: Severity::High,
                        kind: FindingKind::UnpinnedVersion,
                        message: format!("Unpinned package version: {}", arg),
                        evidence: Some(arg.clone()),
                    });
                }
                break;
            }
        }
    }

    if !lock_exists {
        findings.push(Finding {
            severity: Severity::Medium,
            kind: FindingKind::MissingLock,
            message: "Server tools not pinned in 4madeus.lock".to_string(),
            evidence: None,
        });
    }

    findings
}

fn is_secret_key(key: &str) -> bool {
    let k = key.to_uppercase();
    k.contains("TOKEN")
        || k.contains("SECRET")
        || k.contains("PASSWORD")
        || k.contains("API_KEY")
        || k.contains("ACCESS_KEY")
        || k.contains("PRIVATE_KEY")
        || k.contains("AUTH")
}

fn looks_like_secret_value(value: &str) -> bool {
    if value.len() < 12 || value.starts_with("${") || value.starts_with('$') {
        return false;
    }
    value.starts_with("sk-")
        || value.starts_with("ghp_")
        || value.starts_with("gho_")
        || value.starts_with("github_pat_")
        || value.starts_with("AKIA")
        || value.starts_with("xoxb-")
        || value.starts_with("xoxp-")
        || value.starts_with("-----BEGIN")
        || (value.len() > 24
            && value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
}

fn is_sensitive_path(path: &str) -> bool {
    let p = path.to_lowercase();
    p.contains(".ssh/")
        || p.contains(".ssh\\")
        || p.contains("id_rsa")
        || p.contains("id_ed25519")
        || p.ends_with(".env")
        || p.contains(".aws/credentials")
        || p.contains(".aws\\credentials")
}

fn mask_secret(value: &str) -> String {
    if value.len() <= 8 {
        return "****".to_string();
    }
    format!("{}…{}", &value[..4], &value[value.len() - 4..])
}

fn compute_summary(clients: &[ClientFinding]) -> Summary {
    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut total_servers = 0;

    for client in clients {
        for server in &client.servers {
            total_servers += 1;
            for f in &server.findings {
                match f.severity {
                    Severity::Critical => critical += 1,
                    Severity::High => high += 1,
                    Severity::Medium => medium += 1,
                    Severity::Info => {}
                }
            }
        }
    }

    Summary {
        critical,
        high,
        medium,
        total_servers,
    }
}
