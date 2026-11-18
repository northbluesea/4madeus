use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::*;
use fourmadeus_core::{LockedServer, Lockfile};
use fourmadeus_discovery::{scan, Severity};
use fourmadeus_proxy::{run_stdio_proxy, ProxyConfig};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "4madeus", about = "Zero-noise security & deterministic lockfile for MCP servers")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Discover Shadow MCP servers and exposed secrets across local AI clients
    Scan {
        #[arg(long)]
        json: bool,
    },
    /// Initialize 4madeus.lock and wrap local MCP configurations
    Init {
        /// Wrap found client configs so traffic routes through 4madeus proxy
        #[arg(long)]
        wrap: bool,
    },
    /// Run an MCP server wrapped inside the 4madeus real-time security proxy
    Run {
        #[arg(long)]
        id: String,
        #[arg(long, default_value_t = false)]
        observe: bool,
        #[arg(trailing_var_arg = true, required = true)]
        cmd: Vec<String>,
    },
    /// Restore original MCP client configs from .bak backups
    Unwrap,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { json } => {
            let report = scan(None)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
                return Ok(());
            }

            println!("\n{}\n", "4madeus scan".bold());
            println!("{}\n", "Scanning MCP configurations...".dimmed());

            for client in &report.clients {
                for server in &client.servers {
                    for finding in &server.findings {
                        let (badge, symbol) = match finding.severity {
                            Severity::Critical => ("CRITICAL".red().bold(), "✗".red().bold()),
                            Severity::High => ("HIGH".yellow().bold(), "!".yellow().bold()),
                            Severity::Medium => ("MEDIUM".cyan().bold(), "·".cyan().bold()),
                            Severity::Info => ("INFO".dimmed(), "·".dimmed()),
                        };

                        println!("{}", badge);
                        println!(
                            "  {} {}  {}",
                            symbol,
                            server.name.bold(),
                            format!("({})", client.client).dimmed()
                        );
                        println!("      {}", finding.message);
                        println!("      {}\n", format!("Path: {}", client.config_path).dimmed());
                    }
                }
            }

            println!("{}", "Summary".bold());
            println!(
                "  {}  ·  {}  ·  {}  ·  {} servers total\n",
                format!("{} critical", report.summary.critical).red().bold(),
                format!("{} high", report.summary.high).yellow().bold(),
                format!("{} medium", report.summary.medium).cyan(),
                report.summary.total_servers
            );

            println!("{}", "Next steps".bold());
            println!("  {}          → create 4madeus.lock and pin all tools", "4madeus init".green());
            println!("  {}   → wrap local MCP configs automatically", "4madeus init --wrap".green());
            println!("  {}  → output JSON for CI/CD or team dashboard\n", "4madeus scan --json".green());
        }

        Commands::Init { wrap } => {
            let report = scan(None)?;
            let lock_path = PathBuf::from("4madeus.lock");
            let mut lockfile = Lockfile::load(&lock_path).unwrap_or_else(|_| Lockfile::new());

            for client in &report.clients {
                for server in &client.servers {
                    if let Some(cmd) = &server.command {
                        lockfile
                            .servers
                            .entry(server.name.clone())
                            .or_insert_with(|| LockedServer {
                                command: cmd.clone(),
                                args: server.args.clone(),
                                tools: BTreeMap::new(),
                            });
                    }
                }

                if wrap {
                    wrap_config_file(&client.config_path)?;
                }
            }

            lockfile.save(&lock_path)?;
            println!(
                "\n{} Created {} with {} server(s) registered.",
                "✓".green().bold(),
                "4madeus.lock".bold(),
                lockfile.servers.len()
            );
            if wrap {
                println!(
                    "{} Wrapped client configurations (backups saved as .bak). Run {} to revert.\n",
                    "✓".green().bold(),
                    "4madeus unwrap".cyan()
                );
            } else {
                println!(
                    "Tip: Run {} to automatically route your editors through the proxy.\n",
                    "4madeus init --wrap".cyan()
                );
            }
        }

        Commands::Run { id, observe, cmd } => {
            let exe = &cmd[0];
            let args = &cmd[1..];
            let cfg = ProxyConfig {
                server_id: id,
                lock_path: PathBuf::from("4madeus.lock"),
                enforce: !observe,
            };
            let code = run_stdio_proxy(exe, args, cfg).await?;
            std::process::exit(code);
        }

        Commands::Unwrap => {
            let report = scan(None)?;
            let mut restored = 0;
            for client in &report.clients {
                let bak = format!("{}.bak", client.config_path);
                if PathBuf::from(&bak).exists() {
                    fs::copy(&bak, &client.config_path)?;
                    fs::remove_file(&bak)?;
                    println!("{} Restored {}", "✓".green().bold(), client.config_path);
                    restored += 1;
                }
            }
            if restored == 0 {
                println!("No .bak backup files found to restore.");
            }
        }
    }

    Ok(())
}

fn wrap_config_file(path: &str) -> Result<()> {
    let content = fs::read_to_string(path)?;
    let bak_path = format!("{}.bak", path);
    if !PathBuf::from(&bak_path).exists() {
        fs::write(&bak_path, &content)?;
    }

    let mut json: serde_json::Value = serde_json::from_str(content.trim_start_matches('\u{FEFF}'))?;
    let root_key = if json.get("servers").is_some() {
        "servers"
    } else {
        "mcpServers"
    };

    if let Some(servers) = json.get_mut(root_key).and_then(|v| v.as_object_mut()) {
        for (name, cfg) in servers.iter_mut() {
            let Some(cmd) = cfg.get("command").and_then(|v| v.as_str()).map(String::from) else {
                continue;
            };
            if cmd == "4madeus" || cmd.ends_with("4madeus.exe") {
                continue; // Ya está envuelto (idempotente)
            }

            let mut old_args: Vec<String> = cfg
                .get("args")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default();

            let mut new_args = vec!["run".to_string(), "--id".to_string(), name.clone(), "--".to_string(), cmd];
            new_args.append(&mut old_args);

            cfg["command"] = serde_json::Value::String("4madeus".to_string());
            cfg["args"] = serde_json::to_value(new_args)?;
        }
    }

    fs::write(path, serde_json::to_string_pretty(&json)?)?;
    Ok(())
}
