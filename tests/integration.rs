//! End-to-end verification against real `pylae chain export` bundles.
//!
//! Two fixtures, both regenerable from the producer's own tree rather than
//! shipped as opaque blobs:
//!
//! * `demo-bundle` — breadth. A demo-scale export: 50 action leaves, 13
//!   erasures, a signed event leaf, sealed Merkle blocks. Regenerate with
//!   `PYLAE_FIXTURE_OUT=<dir> cargo test --bin pylae emit_demo_fixture --
//!   --ignored` in the core repo.
//! * `conformance-bundle` — depth. Small, and carries the shapes a demo run
//!   does not produce: a truncated request payload, a captured response leaf,
//!   a non-empty snapshot hash with its inputs in `snapshots.jsonl`, and all
//!   four content-addressed config referents including **both** manifest
//!   branches of spec §9.2. Regenerate with `emit_conformance_fixture`.
//!
//! The tamper tests ship no third bundle. They copy a fixture into a temp
//! directory, alter one value, and re-fix `MANIFEST.json` to match — modelling
//! an attacker who edited a file and covered the file digest. Every one of
//! them names the check that is supposed to catch it, and asserts that the
//! other checks stay clean, so a test cannot pass on the strength of an
//! unrelated failure.

use std::path::{Path, PathBuf};

use pylae_verify::bundle::Bundle;
use pylae_verify::verify;

const DEMO: &str = "tests/fixtures/demo-bundle";
const CONFORMANCE: &str = "tests/fixtures/conformance-bundle";

// ── The two fixtures verify ─────────────────────────────────────────────────

#[test]
fn the_demo_bundle_verifies() {
    let b = Bundle::load(Path::new(DEMO)).expect("load demo bundle");
    let r = verify::verify(&b);

    assert!(
        r.structural_passed(),
        "demo bundle must pass; leaves={:?}, blocks={:?}, gaps={:?}, tombstones={:?}, \
         snapshots={:?}, config={:?}, manifest={:?}",
        r.leaf_mismatches,
        r.block_problems,
        r.linkage_gaps,
        r.tombstone_problems,
        r.snapshot_problems,
        r.config_problems,
        r.manifest_problems
    );
    assert_eq!(r.leaf_count, 64, "expected 64 leaves");
    assert_eq!(r.block_count, 2, "expected 2 sealed blocks");
    assert_eq!(r.tombstone_count, 13, "expected 13 erasure tombstones");
    assert!(
        !b.events.is_empty(),
        "premise: the breadth fixture must carry a signed event leaf, or §5.3 is exercised \
         only by the small one"
    );
    assert_eq!(
        r.config_resolved, 4,
        "all four anchored referents must re-derive: {:?} / {:?}",
        r.config_problems, r.config_unresolved
    );
}

#[test]
fn the_conformance_bundle_verifies() {
    let b = Bundle::load(Path::new(CONFORMANCE)).expect("load conformance bundle");

    // Premise guards. This fixture exists solely to exercise shapes the demo
    // export does not produce; if it stops carrying them the tests below
    // prove nothing and must fail loudly rather than pass vacuously.
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
            .any(|a| a.snapshot_hash.as_deref().is_some_and(|s| !s.is_empty())),
        "fixture must contain a non-empty snapshot hash"
    );
    assert!(
        !b.snapshots.is_empty(),
        "fixture must ship the snapshot inputs, or the §2.2 recompute has nothing to run on"
    );

    let r = verify::verify(&b);
    assert!(
        r.structural_passed(),
        "conformance bundle must pass; leaves={:?}, blocks={:?}, gaps={:?}, snapshots={:?}, \
         config={:?}, manifest={:?}",
        r.leaf_mismatches,
        r.block_problems,
        r.linkage_gaps,
        r.snapshot_problems,
        r.config_problems,
        r.manifest_problems
    );
    assert_eq!(
        r.snapshot_count,
        b.actions
            .iter()
            .filter(|a| a.snapshot_hash.as_deref().is_some_and(|s| !s.is_empty()))
            .count(),
        "spec §9: a snapshot row exists if and only if the action carried one"
    );
}

/// **Promise:** both manifest branches of spec §9.2 re-derive, against a real
/// bundle rather than a synthetic vector.
///
/// The parenthesis in §9.2 — *"confirmed against real bundles"* — used to
/// certify three bullets that no fixture contained and that this verifier did
/// not implement: every `manifest` row was reported unresolved with the note
/// *"JWS derivation not implemented"*, which was never true. The derivation is
/// keyless and belongs to Level 1.
///
/// The two branches are genuinely different code paths — one parses the body,
/// the other base64url-decodes a segment of it first — so a bundle carrying
/// only one of them confirms half the bullet.
#[test]
fn both_manifest_branches_resolve_against_the_real_bundle() {
    let b = Bundle::load(Path::new(CONFORMANCE)).expect("load conformance bundle");

    let manifests: Vec<&_> = b.configs.iter().filter(|c| c.kind == "manifest").collect();
    assert_eq!(
        manifests.len(),
        2,
        "premise: the fixture must carry both branches, or this confirms half of §9.2"
    );
    assert!(
        manifests.iter().any(|c| c.content.starts_with('{')),
        "premise: one row must be an embedded canonical payload"
    );
    assert!(
        manifests
            .iter()
            .any(|c| !c.content.starts_with('{') && c.content.matches('.').count() >= 2),
        "premise: one row must be a compact JWS"
    );

    let r = verify::verify(&b);
    assert!(
        r.config_problems.is_empty() && r.config_unresolved.is_empty(),
        "every anchored referent must resolve: problems={:?}, unresolved={:?}",
        r.config_problems,
        r.config_unresolved
    );
    assert_eq!(r.config_resolved, b.configs.len());
}

// ── Tamper: each one names the check that catches it ────────────────────────

#[test]
fn tampering_an_action_is_caught_by_leaf_recomputation() {
    let dir = TempBundle::from_dir(DEMO, "tamper");

    // Attacker edits one action's decision …
    let actions = dir.path().join("actions.jsonl");
    let original = std::fs::read(&actions).expect("read actions.jsonl");
    let tampered = replace_once(
        &original,
        b"\"decision\":\"allow\"",
        b"\"decision\":\"block\"",
    );
    assert_ne!(
        original, tampered,
        "fixture must contain an allow decision to flip"
    );
    std::fs::write(&actions, &tampered).expect("write tampered actions");

    // … and re-fixes the MANIFEST so the file-digest check passes.
    refix_manifest(dir.path(), "actions.jsonl", &tampered);

    let r = verify::verify(&Bundle::load(dir.path()).expect("load tampered bundle"));

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

#[test]
fn stripping_the_raw_commitment_breaks_the_truncated_leaf() {
    // Proves the §9 precedence is load-bearing here rather than incidentally
    // satisfied. With the commitment removed, the only value left for the
    // truncated action is its `{"truncated":…}` marker, which cannot reproduce
    // the leaf the producer stamped.
    let dir = TempBundle::from_dir(CONFORMANCE, "strip");
    let actions = dir.path().join("actions.jsonl");
    let original = std::fs::read(&actions).expect("read actions.jsonl");
    let stripped = rewrite_rows(&original, |v| {
        v["request_params_raw_hash"] = serde_json::Value::Null;
    });
    assert_ne!(
        original, stripped,
        "fixture must contain a raw commitment to strip"
    );
    std::fs::write(&actions, &stripped).expect("write stripped actions");
    refix_manifest(dir.path(), "actions.jsonl", &stripped);

    let r = verify::verify(&Bundle::load(dir.path()).expect("load stripped bundle"));

    assert!(
        !r.structural_passed(),
        "a truncated leaf without its commitment must not verify"
    );
    assert!(
        !r.leaf_mismatches.is_empty(),
        "the failure must be a leaf recompute mismatch, not a manifest problem"
    );
}

/// **Promise:** a forensic snapshot edited after the fact is caught, and this
/// is the only check that catches it.
///
/// The action leaf commits to `snapshot_hash`, never to the values behind it.
/// Edit an input and leave the recorded hash alone, and the leaf still
/// recomputes, the linkage holds, every block root reproduces and the tombstone
/// rule is untouched — the bundle reads as intact on the strength of a
/// commitment nobody checked. §2.2 makes recomputing from `snapshots.jsonl`
/// mandatory for exactly this reason, and the assertions below insist that the
/// *other* sections stay clean so the test cannot pass on a failure elsewhere.
#[test]
fn editing_a_snapshot_input_is_caught_only_by_the_snapshot_recompute() {
    let dir = TempBundle::from_dir(CONFORMANCE, "snapedit");
    let path = dir.path().join("snapshots.jsonl");
    let original = std::fs::read(&path).expect("read snapshots.jsonl");
    let edited = rewrite_rows(&original, |v| {
        // One input, changed in place; `snapshot_hash` is left as recorded.
        v["damage_estimate"]["amount_microcents"] = serde_json::json!(999_999);
    });
    assert_ne!(original, edited, "fixture must carry a snapshot to edit");
    std::fs::write(&path, &edited).expect("write edited snapshots");
    refix_manifest(dir.path(), "snapshots.jsonl", &edited);

    let r = verify::verify(&Bundle::load(dir.path()).expect("load edited bundle"));

    assert!(
        r.leaf_mismatches.is_empty()
            && r.linkage_gaps.is_empty()
            && r.block_problems.is_empty()
            && r.tombstone_problems.is_empty()
            && r.manifest_problems.is_empty()
            && r.config_problems.is_empty(),
        "every other Level 1 check must stay clean — that is what makes this check the only \
         witness: leaves={:?}, gaps={:?}, blocks={:?}, tombstones={:?}, manifest={:?}, \
         config={:?}",
        r.leaf_mismatches,
        r.linkage_gaps,
        r.block_problems,
        r.tombstone_problems,
        r.manifest_problems,
        r.config_problems
    );
    assert!(
        !r.snapshot_problems.is_empty(),
        "the snapshot recompute must catch an edited input"
    );
    assert!(
        !r.structural_passed(),
        "and a bundle whose snapshot inputs do not reproduce their hash is not intact"
    );
}

/// **Promise:** a bundle that commits to a snapshot and ships no inputs is
/// reported, rather than read as an action that never had one.
///
/// §9 states the invariant as an "if and only if", and this is the half that
/// matters: treating the absent file as "no snapshot" would let a producer
/// publish a commitment whose preimage the recipient does not hold, and the
/// recipient would never know a check had been skipped.
#[test]
fn a_committed_snapshot_with_no_row_is_reported() {
    let dir = TempBundle::from_dir(CONFORMANCE, "nosnap");
    let path = dir.path().join("snapshots.jsonl");
    std::fs::write(&path, b"").expect("empty the snapshots file");
    refix_manifest(dir.path(), "snapshots.jsonl", b"");

    let b = Bundle::load(dir.path()).expect("load bundle without snapshots");
    assert!(b.snapshots.is_empty(), "premise: the file is now empty");
    let committed = b
        .actions
        .iter()
        .filter(|a| a.snapshot_hash.as_deref().is_some_and(|s| !s.is_empty()))
        .count();
    assert!(
        committed > 0,
        "premise: the bundle must still commit to at least one snapshot"
    );

    let r = verify::verify(&b);
    assert_eq!(
        r.snapshot_problems.len(),
        committed,
        "every committed snapshot with no row must be reported: {:?}",
        r.snapshot_problems
    );
    assert!(!r.structural_passed());
}

/// **Promise:** a manifest body swapped after the chain anchored its key is a
/// failure, not a footnote.
///
/// This is the row the old verifier never checked. It reported every manifest
/// anchor as "unresolved — JWS derivation not implemented" and let the bundle
/// pass, so the one configuration artifact an operator could rewrite without
/// touching a leaf was the one artifact outside Level 1.
#[test]
fn swapping_a_manifest_body_is_a_failure() {
    let dir = TempBundle::from_dir(CONFORMANCE, "manifest");
    let path = dir.path().join("config_archive.jsonl");
    let original = std::fs::read(&path).expect("read config_archive.jsonl");
    let mut swapped_any = false;
    let swapped = rewrite_rows(&original, |v| {
        if v["kind"] == serde_json::json!("manifest")
            && v["content"].as_str().is_some_and(|c| c.starts_with('{'))
        {
            // A body that is still valid canonical JSON, so nothing but the
            // content-addressing catches it.
            let mut payload: serde_json::Value =
                serde_json::from_str(v["content"].as_str().expect("content")).expect("payload");
            payload["fallback_ttl_seconds"] = serde_json::json!(1);
            v["content"] = serde_json::Value::String(payload.to_string());
            swapped_any = true;
        }
    });
    assert!(
        swapped_any,
        "premise: the fixture must carry an embedded manifest row to swap"
    );
    std::fs::write(&path, &swapped).expect("write swapped config archive");
    refix_manifest(dir.path(), "config_archive.jsonl", &swapped);

    let r = verify::verify(&Bundle::load(dir.path()).expect("load swapped bundle"));

    assert_address_mismatch(&r.config_problems, &r.config_unresolved);
    assert!(
        r.leaf_mismatches.is_empty() && r.manifest_problems.is_empty(),
        "and nothing else sees it — that is why it has to be checked here"
    );
    assert!(!r.structural_passed());
}

/// The same for the JWS branch. Decoding the payload segment is a different
/// path from parsing an embedded body, so a swap that only the embedded branch
/// catches leaves every fetched manifest unguarded — which is the shape a real
/// deployment archives.
#[test]
fn swapping_a_jws_manifest_payload_is_a_failure() {
    let dir = TempBundle::from_dir(CONFORMANCE, "jws");
    let path = dir.path().join("config_archive.jsonl");
    let original = std::fs::read(&path).expect("read config_archive.jsonl");
    let mut swapped_any = false;
    let swapped = rewrite_rows(&original, |v| {
        let is_jws = v["kind"] == serde_json::json!("manifest")
            && v["content"].as_str().is_some_and(|c| !c.starts_with('{'));
        if !is_jws {
            return;
        }
        let jws = v["content"].as_str().expect("content").to_string();
        let mut parts = jws.split('.');
        let header = parts.next().expect("header");
        let payload = parts.next().expect("payload");
        let signature = parts.next().unwrap_or("");
        let raw = b64url_decode(payload);
        let mut doc: serde_json::Value = serde_json::from_slice(&raw).expect("payload json");
        doc["fallback_ttl_seconds"] = serde_json::json!(1);
        let reencoded = b64url_encode(doc.to_string().as_bytes());
        v["content"] = serde_json::Value::String(format!("{header}.{reencoded}.{signature}"));
        swapped_any = true;
    });
    assert!(
        swapped_any,
        "premise: the fixture must carry a JWS manifest row to swap"
    );
    std::fs::write(&path, &swapped).expect("write swapped config archive");
    refix_manifest(dir.path(), "config_archive.jsonl", &swapped);

    let r = verify::verify(&Bundle::load(dir.path()).expect("load swapped bundle"));
    assert_address_mismatch(&r.config_problems, &r.config_unresolved);
    assert!(!r.structural_passed());
}

/// Assert the verifier reported a **content-addressing** failure and not
/// some other way of failing.
///
/// Without this the two swap tests above cannot tell a detected tamper
/// from a broken test helper: corrupt the re-encoder in
/// `swapping_a_jws_manifest_payload_is_a_failure` so the payload does not
/// even decode, and `config_problems` is still non-empty — the test goes
/// green over a bundle it never tampered with. It was, until this helper
/// existed; the probe is one character appended to the re-encoded segment.
fn assert_address_mismatch(problems: &[String], unresolved: &[String]) {
    assert!(
        problems
            .iter()
            .any(|p| p.contains("does not re-hash to its address")),
        "the failure must be the content-addressing check, not a decode or parse error \
         — problems={problems:?}, unresolved={unresolved:?}"
    );
}

/// **Promise:** the `if and only if` of spec §9 holds in both directions.
///
/// The half nobody reaches by accident: a snapshot row whose action's leaf
/// commits the empty hash. The producer cannot emit it — the export writes
/// one row per snapshotted action — so it only arrives by someone adding
/// it, and a verifier that ignored the extra row would let a bundle carry
/// forensic state attached to an action that never committed to any.
#[test]
fn a_snapshot_row_for_an_action_that_committed_none_is_reported() {
    let dir = TempBundle::from_dir(DEMO, "orphansnap");
    let b = Bundle::load(dir.path()).expect("load demo bundle");
    assert!(
        b.snapshots.is_empty()
            && b.actions
                .iter()
                .all(|a| a.snapshot_hash.as_deref().unwrap_or("").is_empty()),
        "premise: the demo bundle commits to no snapshot at all"
    );
    let target = b.actions[0].id.clone();
    drop(b);

    let row = format!(
        r#"{{"action_id":"{target}","chain_version":1,"security_posture":{{"level":"NORMAL"}},"cost_ceiling":{{"enabled":false}},"agent_profile_id":null,"active_policy_ids":[],"active_contract_id":null,"damage_estimate":{{"amount_microcents":0}},"snapshot_hash":"00","created_at":"2026-01-01T00:00:00Z"}}
"#
    );
    let path = dir.path().join("snapshots.jsonl");
    std::fs::write(&path, row.as_bytes()).expect("write snapshot row");
    refix_manifest(dir.path(), "snapshots.jsonl", row.as_bytes());

    let r = verify::verify(&Bundle::load(dir.path()).expect("reload"));
    assert_eq!(
        r.snapshot_problems.len(),
        1,
        "exactly the added row must be reported: {:?}",
        r.snapshot_problems
    );
    assert!(!r.structural_passed());
}

/// **Promise:** two rows claiming one action is reported rather than
/// resolved by arrival order.
///
/// A map keyed by `action_id` silently keeps the last writer. If the two
/// rows disagree, which one the verifier recomputed against is then a
/// property of line order in a file — so a producer could ship the real
/// snapshot and a forged one and have the verdict depend on which it
/// wrote second.
#[test]
fn two_snapshot_rows_for_one_action_are_reported() {
    let dir = TempBundle::from_dir(CONFORMANCE, "dupsnap");
    let path = dir.path().join("snapshots.jsonl");
    let original = std::fs::read(&path).expect("read snapshots.jsonl");
    let text = String::from_utf8(original).expect("utf-8");
    let first = text.lines().find(|l| !l.trim().is_empty()).expect("a row");
    let doubled = format!("{text}{first}\n");
    std::fs::write(&path, doubled.as_bytes()).expect("write doubled snapshots");
    refix_manifest(dir.path(), "snapshots.jsonl", doubled.as_bytes());

    let r = verify::verify(&Bundle::load(dir.path()).expect("reload"));
    assert!(
        r.snapshot_problems
            .iter()
            .any(|p| p.contains("claim the same action")),
        "the duplicate must be named as such: {:?}",
        r.snapshot_problems
    );
    assert!(!r.structural_passed());
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

/// Parse every line of a JSONL file, hand it to `f`, and re-serialize. Keeps
/// the tamper tests operating on values rather than on byte patterns that
/// happen to appear elsewhere in the row.
fn rewrite_rows(content: &[u8], mut f: impl FnMut(&mut serde_json::Value)) -> Vec<u8> {
    let text = String::from_utf8(content.to_vec()).expect("jsonl is utf-8");
    let mut out = String::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let mut v: serde_json::Value = serde_json::from_str(line).expect("row json");
        f(&mut v);
        out.push_str(&v.to_string());
        out.push('\n');
    }
    out.into_bytes()
}

const B64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64url_encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let mut acc = 0u32;
        for (i, &b) in chunk.iter().enumerate() {
            acc |= u32::from(b) << (16 - 8 * i);
        }
        let chars = chunk.len() + 1;
        for i in 0..chars {
            out.push(B64URL[((acc >> (18 - 6 * i)) & 0x3f) as usize] as char);
        }
    }
    out
}

fn b64url_decode(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in s.as_bytes().chunks(4) {
        let mut acc = 0u32;
        for &c in chunk {
            let v = B64URL.iter().position(|&x| x == c).expect("base64url byte") as u32;
            acc = (acc << 6) | v;
        }
        let bits = chunk.len() * 6;
        acc <<= 24 - bits;
        for i in 0..bits / 8 {
            out.push(((acc >> (16 - 8 * i)) & 0xff) as u8);
        }
    }
    out
}

/// Rewrite `MANIFEST.json` so `name`'s sha256+bytes match `content`, modelling
/// an attacker who covered the file digest after editing the file.
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

/// A throwaway copy of a fixture in a unique temp directory, removed on drop.
/// Avoids any external temp-dir crate.
struct TempBundle {
    dir: PathBuf,
}

impl TempBundle {
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
