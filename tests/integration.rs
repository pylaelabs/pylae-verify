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
    assert_eq!(r.leaf_count, 65, "expected 65 leaves");
    assert_eq!(r.block_count, 2, "expected 2 sealed blocks");
    assert_eq!(r.tombstone_count, 13, "expected 13 erasure tombstones");
    assert!(
        !b.events.is_empty(),
        "premise: the breadth fixture must carry a signed event leaf, or §5.3 is exercised \
         only by the small one"
    );
    assert_eq!(
        r.config_resolved, 4,
        "all four archived referents must re-derive: {:?} / {:?}",
        r.config_problems, r.config_unresolved
    );
    assert_eq!(
        (r.config_anchors, r.config_unresolved.len()),
        (2, 0),
        "and the two hashes the chain anchors must both be in the archive: {:?}",
        r.config_unresolved
    );
}

/// **Promise:** the anchors come from the chain, not from the archive.
///
/// `config_archive.jsonl` cannot say what is missing from it. Checking only
/// the rows present means checking the producer's choice of what to hand
/// over — an operator who drops a row drops the evidence that it should
/// have been there. The `compliance.config_active` leaf is what states the
/// anchors, and it is a chain leaf so that dropping one is not a silent
/// edit: this test reads them back out of `events.jsonl`, confirms the
/// verifier found the same ones, and confirms the archive holds them.
///
/// **Kill mutation:** stop reading the anchor leaf — `config_anchors`
/// drops to zero.
#[test]
fn the_anchors_are_read_from_the_chain_not_from_the_archive() {
    let b = Bundle::load(Path::new(CONFORMANCE)).expect("load conformance bundle");

    let anchor = b
        .events
        .iter()
        .filter(|e| e.event_type == "compliance.config_active")
        .max_by_key(|e| e.chain_version)
        .expect("premise: the fixture must carry a config anchor leaf");
    let manifest_hash = anchor.details["manifest"]["manifest_hash"]
        .as_str()
        .expect("premise: the anchor names a manifest hash")
        .to_string();
    let rules_fp = anchor.details["rules_fingerprint"]
        .as_str()
        .expect("premise: the anchor names a rules fingerprint")
        .to_string();
    assert_ne!(
        manifest_hash, rules_fp,
        "premise: two distinct anchors, or this counts one twice"
    );
    assert!(
        anchor.signature.is_some(),
        "premise: the anchor leaf is signed — that is what puts it beyond an operator's edit"
    );

    let r = verify::verify(&b);
    assert_eq!(
        r.config_anchors, 2,
        "the verifier must find exactly the anchors the leaf names: {:?}",
        r.config_unresolved
    );
    assert!(
        r.config_unresolved.is_empty(),
        "and this bundle archives both of them: {:?}",
        r.config_unresolved
    );
}

/// **Promise:** an anchored hash with no row is reported, and is not a
/// verdict.
///
/// Spec §9.2 draws the line here and it is the whole point of the section:
/// a row that contradicts its own address is a **failure**, because
/// content-addressing makes the disagreement mean the body was replaced.
/// An anchor with no row is **informative** — a database predating the
/// archive has nothing to offer. Collapsing the two in either direction
/// breaks something: treat the absence as failure and every older
/// deployment is permanently not-intact; treat it as silence and dropping
/// a row becomes free.
///
/// **Kill mutations:** stop reading the anchor leaf (nothing is reported);
/// or push the absence into `config_problems` (the verdict below flips).
#[test]
fn an_anchored_hash_with_no_row_is_reported_and_is_not_a_verdict() {
    let dir = TempBundle::from_dir(CONFORMANCE, "anchor");
    let path = dir.path().join("config_archive.jsonl");
    let original = std::fs::read(&path).expect("read config_archive.jsonl");

    // Drop the embedded manifest row — the one the anchor names — and
    // leave every other row untouched, so what remains is self-consistent
    // and only the comparison against the chain sees the loss.
    let b = Bundle::load(dir.path()).expect("load");
    let anchor_hash = b
        .events
        .iter()
        .filter(|e| e.event_type == "compliance.config_active")
        .max_by_key(|e| e.chain_version)
        .and_then(|e| e.details["manifest"]["manifest_hash"].as_str())
        .expect("premise: an anchored manifest hash")
        .to_string();
    drop(b);

    let text = String::from_utf8(original).expect("utf-8");
    let kept: String = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter(|l| !l.contains(&format!("\"content_hash\":\"{anchor_hash}\"")))
        .map(|l| format!("{l}\n"))
        .collect();
    assert_ne!(
        kept.lines().count(),
        text.lines().filter(|l| !l.trim().is_empty()).count(),
        "premise: a row must actually have been removed"
    );
    std::fs::write(&path, kept.as_bytes()).expect("write");
    refix_manifest(dir.path(), "config_archive.jsonl", kept.as_bytes());

    let r = verify::verify(&Bundle::load(dir.path()).expect("reload"));

    assert!(
        r.config_unresolved
            .iter()
            .any(|u| u.contains("anchored by the chain") && u.contains(&anchor_hash[..12])),
        "the missing row must be named: {:?}",
        r.config_unresolved
    );
    assert!(
        r.config_problems.is_empty(),
        "and it is not a content-addressing failure — nothing contradicts its address: {:?}",
        r.config_problems
    );
    assert!(
        r.structural_passed(),
        "§9.2: an anchored hash with no row is informative, never a verdict — {:?}",
        r.config_unresolved
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

// ── Every [ok] the report prints is true ────────────────────────────────────

#[test]
fn a_leaf_after_a_gap_is_reported_as_not_recomputed() {
    // Remove event 64 and edit event 65's details without touching its
    // stored hash. The walk has no predecessor for 65, so it cannot
    // recompute it, and the edit is invisible to every other check (the
    // event sits above the last sealed block). The report must say 65 was
    // not checked rather than count it under "all leaves re-hash".
    let dir = TempBundle::from_dir(DEMO, "gap-leaf");
    let events = dir.path().join("events.jsonl");
    let original = std::fs::read_to_string(&events).expect("read events.jsonl");
    let mut kept = String::new();
    for line in original.lines().filter(|l| !l.trim().is_empty()) {
        let mut v: serde_json::Value = serde_json::from_str(line).expect("row");
        match v["chain_version"].as_i64() {
            Some(64) => continue,
            Some(65) => v["details"]["edited_after_export"] = serde_json::Value::Bool(true),
            _ => {}
        }
        kept.push_str(&v.to_string());
        kept.push('\n');
    }
    std::fs::write(&events, &kept).expect("write events.jsonl");
    refix_manifest(dir.path(), "events.jsonl", kept.as_bytes());

    let r = verify::verify(&Bundle::load(dir.path()).expect("load"));

    assert!(!r.structural_passed());
    assert!(
        r.leaves_not_recomputed
            .iter()
            .any(|l| l.starts_with("chain_version 65 ")),
        "leaf 65 has no predecessor and must be named as not recomputed: {:?}",
        r.leaves_not_recomputed
    );
    assert!(
        r.leaf_mismatches.is_empty(),
        "nothing was recomputed and found wrong: {:?}",
        r.leaf_mismatches
    );
}

#[test]
fn a_required_file_absent_from_the_manifest_is_reported() {
    // Delete events.jsonl and its manifest entry. Every remaining entry
    // still matches, a missing file reads as an empty one, and the tail
    // events sit above the last sealed block, so nothing else notices.
    let dir = TempBundle::from_dir(DEMO, "manifest-complete");
    std::fs::remove_file(dir.path().join("events.jsonl")).expect("remove events.jsonl");
    let path = dir.path().join("MANIFEST.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("parse");
    manifest["files"]
        .as_array_mut()
        .expect("files")
        .retain(|e| e["name"] != "events.jsonl");
    std::fs::write(&path, manifest.to_string()).expect("write MANIFEST.json");

    let r = verify::verify(&Bundle::load(dir.path()).expect("load"));

    assert!(!r.structural_passed());
    assert!(
        r.manifest_problems
            .iter()
            .any(|p| p.starts_with("events.jsonl: required")),
        "{:?}",
        r.manifest_problems
    );
}

#[test]
fn a_snapshot_row_naming_no_action_is_reported() {
    let dir = TempBundle::from_dir(CONFORMANCE, "orphan-snapshot");
    let snaps = dir.path().join("snapshots.jsonl");
    let original = std::fs::read_to_string(&snaps).expect("read snapshots.jsonl");
    let mut orphan: serde_json::Value =
        serde_json::from_str(original.lines().next().expect("one row")).expect("row");
    orphan["action_id"] = serde_json::Value::String("00000000-0000-0000-0000-00000000dead".into());
    let tampered = format!("{original}{orphan}\n");
    std::fs::write(&snaps, &tampered).expect("write");
    refix_manifest(dir.path(), "snapshots.jsonl", tampered.as_bytes());

    let r = verify::verify(&Bundle::load(dir.path()).expect("load"));

    assert!(!r.structural_passed());
    assert!(
        r.snapshot_problems
            .iter()
            .any(|p| p.contains("00000000-0000-0000-0000-00000000dead")),
        "{:?}",
        r.snapshot_problems
    );
}

#[test]
fn two_action_rows_sharing_an_id_are_reported() {
    let dir = TempBundle::from_dir(DEMO, "dup-id");
    let actions = dir.path().join("actions.jsonl");
    let original = std::fs::read(&actions).expect("read");
    let mut first_id: Option<String> = None;
    let tampered = rewrite_rows(&original, |v| {
        let id = v["id"].as_str().expect("id").to_string();
        match &first_id {
            None => first_id = Some(id),
            Some(f) if v["chain_version"] == 2 => v["id"] = serde_json::Value::String(f.clone()),
            _ => {}
        }
    });
    std::fs::write(&actions, &tampered).expect("write");
    refix_manifest(dir.path(), "actions.jsonl", &tampered);

    let r = verify::verify(&Bundle::load(dir.path()).expect("load"));

    let id = first_id.expect("fixture has actions");
    assert!(!r.structural_passed());
    assert!(
        r.leaf_mismatches
            .iter()
            .any(|m| m == &format!("action {id}: two rows in actions.jsonl share this id")),
        "{:?}",
        r.leaf_mismatches
    );
}

// ── Spec §10, Sealing: a block with an unfilled slot is not intact ─────────

#[test]
fn an_empty_slot_inside_a_block_is_reported_even_when_its_root_recomputes() {
    // Remove action 30 and re-seal block 2 over the leaves that remain, as a
    // producer would have if slot 30 was already empty at sealing time. The
    // root then recomputes; only the empty slot says the block is not intact.
    let dir = TempBundle::from_dir(DEMO, "empty-slot");
    let actions = dir.path().join("actions.jsonl");
    let original = std::fs::read_to_string(&actions).expect("read");
    let kept: String = original
        .lines()
        .filter(|l| !l.contains("\"chain_version\":30,"))
        .map(|l| format!("{l}\n"))
        .collect();
    assert_ne!(kept.len(), original.len(), "fixture must hold slot 30");
    std::fs::write(&actions, &kept).expect("write");
    refix_manifest(dir.path(), "actions.jsonl", kept.as_bytes());
    reseal_block(dir.path(), 2, None);

    let r = verify::verify(&Bundle::load(dir.path()).expect("load"));

    assert!(
        !r.block_problems.iter().any(|p| p.contains("root mismatch")),
        "the re-sealed root must recompute, or this test proves nothing: {:?}",
        r.block_problems
    );
    assert!(
        r.block_problems
            .iter()
            .any(|p| p == "block 2: slot(s) 30 in its range hold no leaf"),
        "{:?}",
        r.block_problems
    );
}

#[test]
fn an_empty_slot_at_the_tail_of_the_last_block_is_reported() {
    // Extend the conformance bundle's only block to slot 6, one past the
    // last leaf, and re-seal it. No leaf sits above slot 6, so there is no
    // linkage gap: without the slot check this bundle verifies clean.
    let dir = TempBundle::from_dir(CONFORMANCE, "tail-slot");
    reseal_block(dir.path(), 1, Some(6));

    let r = verify::verify(&Bundle::load(dir.path()).expect("load"));

    assert!(
        r.linkage_gaps.is_empty(),
        "no leaf above slot 6, so no linkage gap: {:?}",
        r.linkage_gaps
    );
    assert!(!r.block_problems.iter().any(|p| p.contains("root mismatch")));
    assert!(!r.structural_passed());
    assert!(
        r.block_problems
            .iter()
            .any(|p| p == "block 1: slot(s) 6 in its range hold no leaf"),
        "{:?}",
        r.block_problems
    );
}

#[test]
fn a_snapshots_file_on_disk_that_the_manifest_does_not_list_is_reported() {
    // `snapshots.jsonl` may be absent from an older export, but when it is
    // on disk it is consumed, so the manifest must cover it.
    let dir = TempBundle::from_dir(CONFORMANCE, "manifest-optional");
    let path = dir.path().join("MANIFEST.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("parse");
    manifest["files"]
        .as_array_mut()
        .expect("files")
        .retain(|e| e["name"] != "snapshots.jsonl");
    std::fs::write(&path, manifest.to_string()).expect("write MANIFEST.json");

    let r = verify::verify(&Bundle::load(dir.path()).expect("load"));

    assert!(!r.structural_passed());
    assert!(
        r.manifest_problems
            .iter()
            .any(|p| p == "snapshots.jsonl: present but not listed in MANIFEST.json"),
        "{:?}",
        r.manifest_problems
    );
}

#[test]
fn without_a_genesis_hash_the_first_leaf_is_named_as_not_recomputed() {
    // A 4-byte fingerprint derives no genesis hash (spec §8 fixes it at 32
    // bytes), so the first leaf has nothing to be recomputed against.
    let dir = TempBundle::from_dir(DEMO, "no-genesis");
    let path = dir.path().join("identity.json");
    let mut identity: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("parse");
    identity["stored_seed_fingerprint"] = "338eae5e".into();
    let edited = identity.to_string();
    std::fs::write(&path, &edited).expect("write identity.json");
    refix_manifest(dir.path(), "identity.json", edited.as_bytes());

    let r = verify::verify(&Bundle::load(dir.path()).expect("load"));

    assert!(r.genesis_error.is_some());
    assert!(
        r.leaves_not_recomputed
            .iter()
            .any(|l| l.starts_with("chain_version 1 ") && l.ends_with("no genesis hash")),
        "{:?}",
        r.leaves_not_recomputed
    );
}

// ── What a leaf commits, and what it does not ──────────────────────────────

/// An edit to one column of an action row.
type Edit = fn(&mut serde_json::Value);

/// Which action row an edit lands on.
type Row = fn(&serde_json::Value) -> bool;

/// Neither truncated nor erased: every field §5.1 folds is committed as
/// stored (spec §9, rule 3).
fn ordinary(v: &serde_json::Value) -> bool {
    v["request_params_truncated"] != true && v["redacted_marker_hash"].is_null()
}

/// An ordinary row that also carries the raw commitment, which rule 3 must
/// not serve in place of the stored payload.
fn ordinary_with_raw_hash(v: &serde_json::Value) -> bool {
    ordinary(v) && !v["request_params_raw_hash"].is_null()
}

#[test]
fn a_committed_field_edited_under_a_rewritten_manifest_fails() {
    // Every action-row field the leaf folds (spec §5.1), and the stored leaf
    // hash. `request_params` enters through its params hash. Each edit is
    // made alone, under a manifest re-fixed to match, and the leaf walk must
    // name the edited row.
    let cases: [(&str, &str, Row, Edit); 15] = [
        (DEMO, "agent_id", ordinary, flip_last_char),
        (DEMO, "method", ordinary, append_edited),
        (DEMO, "tool_name", ordinary, append_edited),
        (DEMO, "request_params", ordinary, |v| {
            v["edited_after_export"] = true.into()
        }),
        (CONFORMANCE, "request_params", ordinary_with_raw_hash, |v| {
            v["edited_after_export"] = true.into()
        }),
        (DEMO, "decision", ordinary, |v| {
            *v = if v == "allow" { "block" } else { "allow" }.into()
        }),
        (DEMO, "decision_source", ordinary, append_edited),
        (DEMO, "policy_id", ordinary, flip_last_char),
        (DEMO, "server_id", ordinary, flip_last_char),
        (DEMO, "timestamp", ordinary, |v| {
            *v = v
                .as_str()
                .expect("timestamp")
                .replacen("2026", "2025", 1)
                .into()
        }),
        (CONFORMANCE, "snapshot_hash", ordinary, flip_last_char),
        (CONFORMANCE, "request_params_truncated", ordinary, |v| {
            *v = (!v.as_bool().expect("bool")).into()
        }),
        (CONFORMANCE, "request_params_original_size", ordinary, |v| {
            *v = (v.as_i64().expect("size") + 1).into()
        }),
        (DEMO, "chain_hash", ordinary, flip_last_char),
        (DEMO, "chain_version", ordinary, |v| {
            *v = (v.as_i64().expect("slot") + 1000).into()
        }),
    ];
    let mut missed = Vec::new();
    for (n, (src, column, row, edit)) in cases.into_iter().enumerate() {
        let (r, cv) = edit_first_action(src, &format!("committed-{n}"), column, row, edit);
        let named = if column == "chain_version" {
            // The slot itself moved: the walk finds a hole where it was.
            r.linkage_gaps
                .iter()
                .any(|g| g == &format!("chain_version {}: no predecessor at {cv}", cv + 1))
        } else {
            r.leaf_mismatches
                .iter()
                .any(|m| m.starts_with(&format!("chain_version {cv} ")))
        };
        if !named || r.structural_passed() {
            missed.push(format!(
                "{column} (chain_version {cv}): leaves={:?} gaps={:?}",
                r.leaf_mismatches, r.linkage_gaps
            ));
        }
    }
    assert!(
        missed.is_empty(),
        "edits the leaf walk did not name: {missed:#?}"
    );
}

#[test]
fn an_operational_column_edited_under_a_rewritten_manifest_verifies_clean() {
    // The README names these as columns no leaf commits. Each edit, made
    // alone under a re-fixed manifest, verifies clean, and the README keeps
    // naming every one of them.
    let readme = std::fs::read_to_string("README.md").expect("read README.md");
    let cases: [(&str, &str, Edit); 5] = [
        (DEMO, "resource_uri", append_edited),
        (DEMO, "session_id", flip_last_char),
        (DEMO, "model_id", append_edited),
        (DEMO, "evaluation_trace", |v| {
            v["edited_after_export"] = true.into()
        }),
        (CONFORMANCE, "latency_us", |v| {
            *v = (v.as_i64().expect("latency") + 1).into()
        }),
    ];
    for (src, column, edit) in cases {
        assert!(
            readme.contains(&format!("`{column}`")),
            "README.md no longer names `{column}`"
        );
        let tag = format!("operational-{column}");
        let (r, cv) = edit_first_action(src, &tag, column, ordinary, edit);
        assert!(
            r.structural_passed(),
            "{column} (chain_version {cv}) is committed after all: leaves={:?} gaps={:?} \
             manifest={:?}",
            r.leaf_mismatches,
            r.linkage_gaps,
            r.manifest_problems
        );
    }
}

/// Copy `src`, apply `edit` to `column` of the first action row that `row`
/// accepts and where `column` is not null, re-fix the manifest, and verify.
/// Returns the report and the edited row's `chain_version` as it was before
/// the edit.
fn edit_first_action(
    src: &str,
    tag: &str,
    column: &str,
    row: Row,
    edit: Edit,
) -> (verify::Report, i64) {
    let dir = TempBundle::from_dir(src, tag);
    let path = dir.path().join("actions.jsonl");
    let original = std::fs::read(&path).expect("read actions.jsonl");
    let mut edited: Option<i64> = None;
    let tampered = rewrite_rows(&original, |v| {
        if edited.is_none() && row(v) && !v[column].is_null() {
            edited = v["chain_version"].as_i64();
            edit(&mut v[column]);
        }
    });
    let cv = edited.unwrap_or_else(|| panic!("no action row in {src} carries `{column}`"));
    std::fs::write(&path, &tampered).expect("write actions.jsonl");
    refix_manifest(dir.path(), "actions.jsonl", &tampered);
    let r = verify::verify(&Bundle::load(dir.path()).expect("load"));
    (r, cv)
}

fn append_edited(v: &mut serde_json::Value) {
    *v = format!("{}-edited", v.as_str().expect("string column")).into();
}

/// Changes the last character of a hex or UUID string, keeping its shape.
fn flip_last_char(v: &mut serde_json::Value) {
    let s = v.as_str().expect("string column");
    let flipped = match s.chars().last() {
        Some('0') => '1',
        Some(_) => '0',
        None => '0',
    };
    *v = format!("{}{flipped}", &s[..s.len().saturating_sub(1)]).into();
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

/// Stored leaf hash by chain slot, from every row kind that carries one.
fn stored_hashes(dir: &Path) -> std::collections::BTreeMap<i64, String> {
    let b = Bundle::load(dir).expect("load");
    let mut m = std::collections::BTreeMap::new();
    for a in &b.actions {
        m.insert(a.chain_version, a.chain_hash.clone());
        if let (Some(v), Some(h)) = (a.response_chain_version, &a.response_chain_hash) {
            m.insert(v, h.clone());
        }
    }
    for e in &b.erasures {
        m.insert(e.chain_version, e.chain_hash.clone());
    }
    for e in &b.events {
        m.insert(e.chain_version, e.chain_hash.clone());
    }
    m
}

/// Re-seal block `number` over the leaves its range now holds, as a producer
/// would: root and `actions_count` from the present leaves, optionally with a
/// new `last_chain_version`. The next block's `prev_block_merkle` follows, so
/// block linkage stays clean, and the manifest is re-fixed.
fn reseal_block(dir: &Path, number: i64, new_last: Option<i64>) {
    let hashes = stored_hashes(dir);
    let path = dir.join("blocks.jsonl");
    let original = std::fs::read(&path).expect("read blocks.jsonl");
    let mut new_root = None;
    let pass1 = rewrite_rows(&original, |v| {
        if v["block_number"] == number {
            if let Some(last) = new_last {
                v["last_chain_version"] = last.into();
            }
            let first = v["first_chain_version"].as_i64().expect("first");
            let last = v["last_chain_version"].as_i64().expect("last");
            let leaves: Vec<&str> = hashes
                .range(first..=last)
                .map(|(_, h)| h.as_str())
                .collect();
            let root = pylae_verify::chain::block_root(&leaves, leaves.len() as u64).expect("root");
            v["actions_count"] = (leaves.len() as u64).into();
            v["merkle_root"] = root.clone().into();
            new_root = Some(root);
        }
    });
    let root = new_root.expect("block exists");
    let resealed = rewrite_rows(&pass1, |v| {
        if v["block_number"] == number + 1 {
            v["prev_block_merkle"] = root.clone().into();
        }
    });
    std::fs::write(&path, &resealed).expect("write blocks.jsonl");
    refix_manifest(dir, "blocks.jsonl", &resealed);
}
