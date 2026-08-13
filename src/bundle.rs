//! Evidence-bundle reading and parsing — Pylae Evidence Format Spec §9.
//!
//! Reads a `pylae chain export` directory into typed rows. Only the fields the
//! verifier needs are deserialized; the exporter's other columns are ignored.
//! All I/O and parsing is fallible — nothing here panics on malformed input.
#![allow(dead_code)]

use serde::Deserialize;
use serde_json::Value;
use std::path::{Path, PathBuf};

use crate::canonical::sha256_hex;

// ── MANIFEST.json ───────────────────────────────────────────────────────────
#[derive(Debug, Deserialize)]
pub struct Manifest {
    pub files: Vec<ManifestEntry>,
}

#[derive(Debug, Deserialize)]
pub struct ManifestEntry {
    pub name: String,
    pub sha256: String,
    pub bytes: u64,
}

// ── identity.json ───────────────────────────────────────────────────────────
#[derive(Debug, Deserialize)]
pub struct Identity {
    pub stored_seed_fingerprint: Option<String>,
    pub instance_id: Option<String>,
    #[serde(default)]
    pub last_sealed_version: i64,
    #[serde(default)]
    pub tool_version: String,
}

// ── Leaf rows ───────────────────────────────────────────────────────────────
#[derive(Debug, Deserialize)]
pub struct ActionRow {
    pub id: String,
    pub chain_version: i64,
    pub agent_id: String,
    pub method: String,
    #[serde(default)]
    pub tool_name: Option<String>,
    #[serde(default)]
    pub request_params: Option<Value>,
    /// The hash of the params as they arrived, before the producer applied any
    /// truncation — the value the leaf committed (spec §9, precedence rule 1).
    /// Absent on rows written before the producer recorded it.
    #[serde(default)]
    pub request_params_raw_hash: Option<String>,
    pub decision: String,
    #[serde(default)]
    pub decision_source: Option<String>,
    #[serde(default)]
    pub policy_id: Option<String>,
    pub server_id: String,
    pub timestamp: String,
    /// Present once the exporter includes it (spec §9 / snapshot gap). Absent
    /// rows verify with the empty-sentinel snapshot the stamp path uses.
    #[serde(default)]
    pub snapshot_hash: Option<String>,
    #[serde(default)]
    pub request_params_truncated: Option<bool>,
    #[serde(default)]
    pub request_params_original_size: Option<i64>,
    /// Set on an erased action; drives tombstone resolution (spec §6).
    #[serde(default)]
    pub redacted_marker_hash: Option<String>,
    pub chain_hash: String,
    // Response-leaf fields (spec §5.4); all absent when no response was captured.
    #[serde(default)]
    pub response_chain_version: Option<i64>,
    #[serde(default)]
    pub response_raw_hash: Option<String>,
    #[serde(default)]
    pub response_truncated: Option<bool>,
    #[serde(default)]
    pub response_original_size: Option<i64>,
    #[serde(default)]
    pub response_chain_timestamp: Option<String>,
    #[serde(default)]
    pub response_chain_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ErasureRow {
    pub id: String,
    pub target_action_id: String,
    pub actor: String,
    pub reason: String,
    pub timestamp: String,
    pub chain_version: i64,
    pub tombstone_hash: String,
    pub original_params_hash: String,
    pub chain_hash: String,
}

#[derive(Debug, Deserialize)]
pub struct EventRow {
    pub id: String,
    pub event_type: String,
    pub timestamp: String,
    pub details: Value,
    pub chain_version: i64,
    pub chain_hash: String,
    pub event_uid: String,
}

#[derive(Debug, Deserialize)]
pub struct BlockRow {
    pub block_number: i64,
    pub merkle_root: String,
    pub prev_block_merkle: Option<String>,
    pub actions_count: u64,
    pub first_chain_version: i64,
    pub last_chain_version: i64,
    pub last_chain_hash: String,
}

#[derive(Debug, Deserialize)]
pub struct ConfigRow {
    pub content_hash: String,
    pub kind: String,
    pub content: String,
}

// ── The bundle ──────────────────────────────────────────────────────────────
pub struct Bundle {
    pub dir: PathBuf,
    pub manifest: Manifest,
    pub identity: Identity,
    pub actions: Vec<ActionRow>,
    pub erasures: Vec<ErasureRow>,
    pub events: Vec<EventRow>,
    pub blocks: Vec<BlockRow>,
    pub configs: Vec<ConfigRow>,
}

fn read_file(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))
}

fn read_json<T: for<'de> Deserialize<'de>>(dir: &Path, name: &str) -> Result<T, String> {
    let path = dir.join(name);
    let bytes = read_file(&path)?;
    serde_json::from_slice(&bytes).map_err(|e| format!("parse {name}: {e}"))
}

/// Read a JSONL file into typed rows. A missing file is treated as empty
/// (the exporter always writes the file, possibly zero-length).
fn read_jsonl<T: for<'de> Deserialize<'de>>(dir: &Path, name: &str) -> Result<Vec<T>, String> {
    let path = dir.join(name);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = read_file(&path)?;
    let text = String::from_utf8(bytes).map_err(|e| format!("{name}: not UTF-8: {e}"))?;
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let row = serde_json::from_str(line)
            .map_err(|e| format!("{name} line {}: {e}", i + 1))?;
        out.push(row);
    }
    Ok(out)
}

impl Bundle {
    /// Load and parse a bundle directory. Fails on any read or parse error.
    pub fn load(dir: &Path) -> Result<Self, String> {
        if !dir.is_dir() {
            return Err(format!("not a directory: {}", dir.display()));
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            manifest: read_json(dir, "MANIFEST.json")?,
            identity: read_json(dir, "identity.json")?,
            actions: read_jsonl(dir, "actions.jsonl")?,
            erasures: read_jsonl(dir, "erasures.jsonl")?,
            events: read_jsonl(dir, "events.jsonl")?,
            blocks: read_jsonl(dir, "blocks.jsonl")?,
            configs: read_jsonl(dir, "config_archive.jsonl")?,
        })
    }

    /// Verify every file listed in `MANIFEST.json` against its recorded
    /// SHA-256 and byte length (spec §9.1). `MANIFEST.json` itself is written
    /// last and is not among its own entries. Returns the list of mismatches.
    pub fn verify_manifest(&self) -> Vec<String> {
        let mut problems = Vec::new();
        for e in &self.manifest.files {
            if e.name == "MANIFEST.json" {
                continue;
            }
            let path = self.dir.join(&e.name);
            match read_file(&path) {
                Ok(bytes) => {
                    if bytes.len() as u64 != e.bytes {
                        problems.push(format!(
                            "{}: size {} != manifest {}",
                            e.name,
                            bytes.len(),
                            e.bytes
                        ));
                    }
                    let got = sha256_hex(&bytes);
                    if got != e.sha256 {
                        problems.push(format!("{}: sha256 mismatch", e.name));
                    }
                }
                Err(err) => problems.push(err),
            }
        }
        problems
    }
}
