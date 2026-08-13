//! End-to-end verification against a real `pylae chain export` bundle.
//!
//! The fixture `valid-bundle` is a genuine export from a Pylae instance (demo
//! data — synthetic agents/actions, no real PII): 82 leaves (50 actions, 13
//! erasures, 19 events) across 3 sealed blocks.
//!
//! The tamper test does not ship a second bundle. It copies the valid one into
//! a temp directory, alters one action's `decision`, and re-fixes the MANIFEST
//! to match — modelling an attacker who edited a file and covered the file
//! digest. The chain must still catch it via leaf recomputation.

use std::path::{Path, PathBuf};

use pylae_verify::bundle::Bundle;
use pylae_verify::verify;

const VALID: &str = "tests/fixtures/valid-bundle";

/// A second, small fixture carrying the three shapes the demo export does
/// not: a truncated request payload, a captured response leaf, and a
/// non-empty snapshot hash. Regenerate with the in-tree generator:
/// `PYLAE_FIXTURE_OUT=<dir> cargo test --bin pylae emit_conformance_fixture
/// -- --ignored` in the core repo.
const TRUNCATED: &str = "tests/fixtures/truncated-bundle";

#[test]
fn truncated_bundle_verifies_via_the_raw_commitment() {
    let b = Bundle::load(Path::new(TRUNCATED)).expect("load truncated bundle");

    // Premise guards: this fixture exists solely to exercise shapes the
    // demo bundle lacks. If it stops carrying them, the test below proves
    // nothing and must fail loudly rather than pass vacuously.
    let truncated = b
        .actions
        .iter()
        .find(|a| a.request_params_truncated == Some(true))
        .expect("fixture must contain a truncated action");
    assert!(
        truncated.request_params_raw_hash.is_some(),
        "a truncated action must carry the pre-truncation commitment"
    );
    assert!(
        b.actions.iter().any(|a| a.response_chain_version.is_some()),
        "fixture must contain a captured response leaf"
    );
    assert!(
        b.actions
            .iter()
            .any(|a| a.snapshot_hash.as_deref().map_or(false, |s| !s.is_empty())),
        "fixture must contain a non-empty snapshot hash"
    );

    let r = verify::verify(&b);
    assert!(
        r.structural_passed(),
        "truncated bundle must pass; leaf_mismatches={:?}, blocks={:?}, gaps={:?}, manifest={:?}",
        r.leaf_mismatches,
        r.block_problems,
        r.linkage_gaps,
        r.manifest_problems
    );
}

#[test]
fn stripping_the_raw_commitment_breaks_the_truncated_leaf() {
    // Proves the §9 precedence is load-bearing here rather than
    // incidentally satisfied. With the commitment removed, the only value
    // left for the truncated action is its `{"truncated":…}` marker, which
    // cannot reproduce the leaf the producer stamped.
    let dir = TempBundle::from_dir(TRUNCATED, "strip");
    let actions = dir.path().join("actions.jsonl");
    let original = std::fs::read(&actions).expect("read actions.jsonl");
    let stripped = strip_raw_hash(&original);
    assert_ne!(
        original, stripped,
        "fixture must contain a raw commitment to strip"
    );
    std::fs::write(&actions, &stripped).expect("write stripped actions");
    refix_manifest(dir.path(), "actions.jsonl", &stripped);

    let b = Bundle::load(dir.path()).expect("load stripped bundle");
    let r = verify::verify(&b);

    assert!(
        !r.structural_passed(),
        "a truncated leaf without its commitment must not verify"
    );
    assert!(
        !r.leaf_mismatches.is_empty(),
        "the failure must be a leaf recompute mismatch, not a manifest problem"
    );
}

/// Null out `request_params_raw_hash` on every action row. Harmless for an
/// untruncated action — its stored payload still re-hashes to the committed
/// value — so only the truncated leaf loses its only usable source.
fn strip_raw_hash(content: &[u8]) -> Vec<u8> {
    let text = String::from_utf8(content.to_vec()).expect("actions.jsonl is utf-8");
    let mut out = String::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let mut v: serde_json::Value = serde_json::from_str(line).expect("action row json");
        v["request_params_raw_hash"] = serde_json::Value::Null;
        out.push_str(&v.to_string());
        out.push('\n');
    }
    out.into_bytes()
}

#[test]
fn valid_bundle_verifies() {
    let b = Bundle::load(Path::new(VALID)).expect("load valid bundle");
    let r = verify::verify(&b);

    assert!(
        r.structural_passed(),
        "valid bundle must pass; leaf_mismatches={:?}, blocks={:?}, gaps={:?}, manifest={:?}",
        r.leaf_mismatches, r.block_problems, r.linkage_gaps, r.manifest_problems
    );
    assert_eq!(r.leaf_count, 82, "expected 82 leaves");
    assert_eq!(r.block_count, 3, "expected 3 blocks");
    assert!(r.tombstone_problems.is_empty(), "tombstones must be consistent");
    assert!(r.config_problems.is_empty(), "no config anchor should fail to re-hash");
    assert_eq!(r.config_resolved, 2, "effective_rules + cve_feed should resolve");
}

#[test]
fn tampered_bundle_is_rejected() {
    let dir = TempBundle::from_valid();

    // Attacker edits one action's decision …
    let actions = dir.path().join("actions.jsonl");
    let original = std::fs::read(&actions).expect("read actions.jsonl");
    let tampered = replace_once(&original, b"\"decision\":\"allow\"", b"\"decision\":\"block\"");
    assert_ne!(original, tampered, "fixture must contain an allow decision to flip");
    std::fs::write(&actions, &tampered).expect("write tampered actions");

    // … and re-fixes the MANIFEST so the file-digest check passes.
    refix_manifest(dir.path(), "actions.jsonl", &tampered);

    let b = Bundle::load(dir.path()).expect("load tampered bundle");
    let r = verify::verify(&b);

    assert!(!r.structural_passed(), "tampered bundle must be rejected");
    assert!(
        r.manifest_problems.is_empty(),
        "manifest was re-fixed, so the file-digest check should pass: {:?}",
        r.manifest_problems
    );
    assert!(
        !r.leaf_mismatches.is_empty(),
        "the chain must catch the altered field via leaf recomputation"
    );
}

// ── helpers ─────────────────────────────────────────────────────────────────

fn replace_once(haystack: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    match haystack.windows(from.len()).position(|w| w == from) {
        Some(i) => {
            let mut out = Vec::with_capacity(haystack.len());
            out.extend_from_slice(&haystack[..i]);
            out.extend_from_slice(to);
            out.extend_from_slice(&haystack[i + from.len()..]);
            out
        }
        None => haystack.to_vec(),
    }
}

/// Rewrite MANIFEST.json so `name`'s sha256+bytes match `content`. Uses only
/// string surgery on the two entry fields — no JSON dependency beyond what the
/// crate already pulls in via the library.
fn refix_manifest(dir: &Path, name: &str, content: &[u8]) {
    use pylae_verify::canonical::sha256_hex;
    let path = dir.join("MANIFEST.json");
    let text = std::fs::read_to_string(&path).expect("read MANIFEST.json");
    let mut manifest: serde_json::Value = serde_json::from_str(&text).expect("parse MANIFEST.json");
    let files = manifest
        .get_mut("files")
        .and_then(|f| f.as_array_mut())
        .expect("MANIFEST.files array");
    let entry = files
        .iter_mut()
        .find(|e| e.get("name").and_then(|n| n.as_str()) == Some(name))
        .expect("manifest entry for file");
    entry["sha256"] = serde_json::Value::String(sha256_hex(content));
    entry["bytes"] = serde_json::Value::Number((content.len() as u64).into());
    std::fs::write(&path, manifest.to_string()).expect("write MANIFEST.json");
}

/// A throwaway copy of the valid bundle in a unique temp directory, removed on
/// drop. Avoids any external temp-dir crate.
struct TempBundle {
    dir: PathBuf,
}

impl TempBundle {
    fn from_valid() -> Self {
        Self::from_dir(VALID, "tamper")
    }

    fn from_dir(src: &str, tag: &str) -> Self {
        let mut dir = std::env::temp_dir();
        // Unique per test binary + this test name; no rng needed.
        dir.push(format!("pylae-verify-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp bundle dir");
        for entry in std::fs::read_dir(src).expect("read source fixture") {
            let entry = entry.expect("dir entry");
            if entry.file_type().expect("file type").is_file() {
                let dest = dir.join(entry.file_name());
                std::fs::copy(entry.path(), dest).expect("copy fixture file");
            }
        }
        Self { dir }
    }
    fn path(&self) -> &Path {
        &self.dir
    }
}

impl Drop for TempBundle {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
