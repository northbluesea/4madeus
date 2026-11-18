use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lockfile {
    pub version: u32,
    pub generated_at: String,
    pub servers: BTreeMap<String, LockedServer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockedServer {
    pub command: String,
    pub args: Vec<String>,
    #[serde(default)]
    pub tools: BTreeMap<String, LockedTool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockedTool {
    pub sha256: String,
    pub pinned_at: String,
    pub status: String, // "pinned" | "quarantined"
}

impl Lockfile {
    pub fn new() -> Self {
        Self {
            version: 1,
            generated_at: chrono::Utc::now().to_rfc3339(),
            servers: BTreeMap::new(),
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&content)?)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }
}

pub fn canonical_tool_hash(name: &str, description: &str, input_schema: &Value) -> String {
    let mut map = serde_json::Map::new();
    map.insert("name".to_string(), Value::String(name.to_string()));
    map.insert("description".to_string(), Value::String(description.to_string()));
    map.insert("inputSchema".to_string(), canonicalize_value(input_schema));

    let canonical = Value::Object(map);
    let bytes = serde_json::to_vec(&canonical).expect("canonical value is always serializable");
    hex::encode(Sha256::digest(&bytes))
}

fn canonicalize_value(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut sorted: Vec<_> = map.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(b.0));
            let mut new_map = serde_json::Map::new();
            for (k, val) in sorted {
                new_map.insert(k.clone(), canonicalize_value(val));
            }
            Value::Object(new_map)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(canonicalize_value).collect()),
        _ => v.clone(),
    }
}
