use anyhow::Result;
use fourmadeus_core::{canonical_tool_hash, LockedTool, Lockfile};
use memchr::memmem;
use serde_json::Value;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

pub struct ProxyConfig {
    pub server_id: String,
    pub lock_path: PathBuf,
    pub enforce: bool,
}

enum Verdict {
    Allow,
    Block { id: Value, reason: String },
}

pub async fn run_stdio_proxy(cmd: &str, args: &[String], cfg: ProxyConfig) -> Result<i32> {
    // En Windows, comandos como npx o uvx son scripts .cmd
    let resolved_cmd = if cfg!(windows) && (cmd == "npx" || cmd == "uvx" || cmd == "npm") {
        format!("{}.cmd", cmd)
    } else {
        cmd.to_string()
    };

    let mut child = Command::new(&resolved_cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()?;

    let mut child_in = child.stdin.take().unwrap();
    let child_out = child.stdout.take().unwrap();

    let state = Arc::new(Mutex::new(cfg));
    let (tx, mut rx) = mpsc::channel::<String>(256);

    // Escritor único hacia stdout del editor (evita mezcla de bytes)
    let writer = tokio::spawn(async move {
        let mut out = tokio::io::stdout();
        while let Some(line) = rx.recv().await {
            out.write_all(line.as_bytes()).await?;
            out.write_all(b"\n").await?;
            out.flush().await?;
        }
        anyhow::Ok(())
    });

    // Flujo Cliente (Cursor/Claude) -> Servidor MCP
    let (state_up, tx_up) = (state.clone(), tx.clone());
    let up = tokio::spawn(async move {
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        while let Some(line) = lines.next_line().await? {
            match inspect_request(&line, &state_up) {
                Verdict::Allow => {
                    child_in.write_all(line.as_bytes()).await?;
                    child_in.write_all(b"\n").await?;
                }
                Verdict::Block { id, reason } => {
                    let err = serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32001,
                            "message": reason
                        }
                    });
                    tx_up.send(err.to_string()).await?;
                }
            }
        }
        anyhow::Ok(())
    });

    // Flujo Servidor MCP -> Cliente (Cursor/Claude)
    let state_down = state.clone();
    let down = tokio::spawn(async move {
        let mut lines = BufReader::new(child_out).lines();
        while let Some(line) = lines.next_line().await? {
            let processed = inspect_response(line, &state_down);
            tx.send(processed).await?;
        }
        anyhow::Ok(())
    });

    let status = child.wait().await?;
    up.abort();
    let _ = down.await;
    drop(writer);
    Ok(status.code().unwrap_or(1))
}

fn inspect_request(line: &str, state: &Arc<Mutex<ProxyConfig>>) -> Verdict {
    // Fast-path: 99% del tráfico sale sin parsear JSON (< 5 microsegundos)
    if memmem::find(line.as_bytes(), b"\"tools/call\"").is_none() {
        return Verdict::Allow;
    }

    let Ok(req) = serde_json::from_str::<Value>(line) else {
        return Verdict::Allow;
    };

    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let args_str = req
        .pointer("/params/arguments")
        .map(|v| v.to_string().to_lowercase())
        .unwrap_or_default();

    // Reglas de alta confianza contra exfiltración de rutas sensibles
    let blocked_patterns = [".ssh/", ".ssh\\", "id_rsa", "id_ed25519", ".aws/credentials", ".env"];
    for pattern in blocked_patterns {
        if args_str.contains(pattern) {
            let cfg = state.lock().unwrap();
            eprintln!("[4madeus] ALERT: Sensitive path access detected ({})", pattern);
            if cfg.enforce {
                return Verdict::Block {
                    id,
                    reason: format!(
                        "[4madeus] Blocked sensitive path access '{}'. Run with --observe to allow.",
                        pattern
                    ),
                };
            }
        }
    }

    Verdict::Allow
}

fn inspect_response(line: String, state: &Arc<Mutex<ProxyConfig>>) -> String {
    // Fast-path: solo inspeccionamos respuestas que contienen definición de herramientas
    if memmem::find(line.as_bytes(), b"\"tools\":[").is_none() {
        return line;
    }

    let Ok(mut res) = serde_json::from_str::<Value>(&line) else {
        return line;
    };

    let cfg = state.lock().unwrap();
    let Ok(mut lockfile) = Lockfile::load(&cfg.lock_path) else {
        return line;
    };

    let mut lock_dirty = false;

    if let Some(tools) = res.pointer_mut("/result/tools").and_then(|t| t.as_array_mut()) {
        if let Some(server_entry) = lockfile.servers.get_mut(&cfg.server_id) {
            tools.retain(|tool| {
                let name = tool.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let desc = tool.get("description").and_then(|v| v.as_str()).unwrap_or("");
                let schema = tool.get("inputSchema").unwrap_or(&Value::Null);
                let current_hash = canonical_tool_hash(name, desc, schema);

                match server_entry.tools.get(name) {
                    Some(pinned) => {
                        if pinned.sha256 != current_hash {
                            eprintln!(
                                "[4madeus] RUG-PULL DETECTED on tool '{}' in server '{}'!",
                                name, cfg.server_id
                            );
                            if cfg.enforce {
                                // Cuarentena granular: ocultamos solo la herramienta alterada
                                return false;
                            }
                        }
                        true
                    }
                    None => {
                        // Primera vez que vemos esta herramienta: la fijamos automáticamente
                        server_entry.tools.insert(
                            name.to_string(),
                            LockedTool {
                                sha256: current_hash,
                                pinned_at: chrono::Utc::now().to_rfc3339(),
                                status: "pinned".to_string(),
                            },
                        );
                        lock_dirty = true;
                        true
                    }
                }
            });
        }
    }

    if lock_dirty {
        let _ = lockfile.save(&cfg.lock_path);
    }

    res.to_string()
}
