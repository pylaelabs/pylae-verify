//! Verification driver — Pylae Evidence Format Specification §10.
//!
//! Level 1 (STRUCTURAL, keyless): recompute every leaf, check the hash-linked
//! chain back to genesis, recompute every Merkle block root, enforce tombstone
//! consistency, resolve content-addressed config anchors, and verify the
//! bundle manifest. Level 2 (ATTRIBUTION) is seed-keyed and out of scope — it
//! is always reported as skipped.
//!
//! Fail-closed: any linkage gap, leaf/Merkle/tombstone/manifest mismatch, or
//! config resolution failure marks structural verification as NOT passed.

use std::collections::BTreeMap;
use std::collections::HashMap;

use crate::bundle::{ActionRow, Bundle, ErasureRow, EventRow};
use crate::canonical::{canonical_params_hash, canonical_value_hash, sha256_hex};
use crate::chain::{
    block_root, genesis_hash, normalize_timestamp, tombstone_hash, ActionLeaf, ErasureLeaf,
    EventLeaf, ResponseLeaf,
};

#[derive(Default)]
pub struct Report {
    pub genesis_error: Option<String>,
    pub manifest_problems: Vec<String>,
    pub leaf_count: usize,
    pub leaf_mismatches: Vec<String>,
    pub linkage_gaps: Vec<String>,
    pub block_count: usize,
    pub block_problems: Vec<String>,
    pub tombstone_count: usize,
    pub tombstone_problems: Vec<String>,
    pub config_resolved: usize,
    pub config_unresolved: Vec<String>, // report-only limitations (e.g. manifest kind)
    pub config_problems: Vec<String>,   // genuine resolution failures (tamper)
}

impl Report {
    /// Structural verification passes only if every keyless check holds.
    /// Config *unresolved* items are report-only (spec §9.2) and do not gate;
    /// config *problems* (a rules/cve blob that no longer re-hashes) do.
    #[must_use]
    pub fn structural_passed(&self) -> bool {
        self.genesis_error.is_none()
            && self.manifest_problems.is_empty()
            && self.leaf_mismatches.is_empty()
            && self.linkage_gaps.is_empty()
            && self.block_problems.is_empty()
            && self.tombstone_problems.is_empty()
            && self.config_problems.is_empty()
    }
}

/// A chain leaf, borrowing its source row.
enum Leaf<'b> {
    Action(&'b ActionRow),
    Erasure(&'b ErasureRow),
    Event(&'b EventRow),
    Response(&'b ActionRow),
}

impl<'b> Leaf<'b> {
    fn stored_hash(&self) -> Option<&'b str> {
        match self {
            Leaf::Action(a) => Some(&a.chain_hash),
            Leaf::Erasure(e) => Some(&e.chain_hash),
            Leaf::Event(e) => Some(&e.chain_hash),
            Leaf::Response(a) => a.response_chain_hash.as_deref(),
        }
    }
    fn kind(&self) -> &'static str {
        match self {
            Leaf::Action(_) => "action",
            Leaf::Erasure(_) => "erasure",
            Leaf::Event(_) => "event",
            Leaf::Response(_) => "response",
        }
    }
}

pub fn verify(b: &Bundle) -> Report {
    let mut r = Report::default();

    // ── MANIFEST integrity (spec §9.1) ─────────────────────────────────────
    r.manifest_problems = b.verify_manifest();

    // ── Genesis (spec §4) ──────────────────────────────────────────────────
    let genesis = match b.identity.stored_seed_fingerprint.as_deref() {
        Some(fp) => match genesis_hash(fp) {
            Ok(g) => Some(g),
            Err(e) => {
                r.genesis_error = Some(e);
                None
            }
        },
        None => {
            r.genesis_error = Some("identity.json has no stored_seed_fingerprint".into());
            None
        }
    };

    // ── Index leaves by chain_version; detect collisions ───────────────────
    let mut index: BTreeMap<i64, Leaf> = BTreeMap::new();

    for a in &b.actions {
        if index.insert(a.chain_version, Leaf::Action(a)).is_some() {
            r.leaf_mismatches
                .push(format!("chain_version {}: duplicate leaf", a.chain_version));
        }
        if let Some(rcv) = a.response_chain_version {
            if index.insert(rcv, Leaf::Response(a)).is_some() {
                r.leaf_mismatches
                    .push(format!("chain_version {rcv}: duplicate response leaf"));
            }
        }
    }
    for e in &b.erasures {
        if index.insert(e.chain_version, Leaf::Erasure(e)).is_some() {
            r.leaf_mismatches
                .push(format!("chain_version {}: duplicate leaf", e.chain_version));
        }
    }
    for e in &b.events {
        if index.insert(e.chain_version, Leaf::Event(e)).is_some() {
            r.leaf_mismatches
                .push(format!("chain_version {}: duplicate leaf", e.chain_version));
        }
    }
    r.leaf_count = index.len();

    // Stored hash by version, for O(1) predecessor lookup during the walk.
    let stored_by_cv: HashMap<i64, &str> = index
        .iter()
        .filter_map(|(cv, l)| l.stored_hash().map(|h| (*cv, h)))
        .collect();

    // Erasure lookup by the action it targets (tombstone resolution, spec §6).
    let era_by_target: HashMap<&str, &ErasureRow> = b
        .erasures
        .iter()
        .map(|e| (e.target_action_id.as_str(), e))
        .collect();

    // ── Chain walk: recompute every leaf and check linkage (spec §5, §10) ──
    for (&cv, leaf) in &index {
        let stored = match leaf.stored_hash() {
            Some(h) => h,
            None => {
                r.leaf_mismatches
                    .push(format!("chain_version {cv} ({}): missing chain_hash", leaf.kind()));
                continue;
            }
        };
        let prev: &str = if cv == 1 {
            match genesis.as_deref() {
                Some(g) => g,
                None => continue, // genesis error already recorded
            }
        } else {
            match stored_by_cv.get(&(cv - 1)) {
                Some(h) => h,
                None => {
                    r.linkage_gaps
                        .push(format!("chain_version {cv}: no predecessor at {}", cv - 1));
                    continue;
                }
            }
        };

        let recomputed = recompute_leaf(leaf, prev, &era_by_target, &mut r);
        if recomputed != stored {
            r.leaf_mismatches
                .push(format!("chain_version {cv} ({}): recomputed hash != stored", leaf.kind()));
        }
    }

    // ── Tombstone consistency (spec §6) ────────────────────────────────────
    r.tombstone_count = b.erasures.len();
    let action_by_id: HashMap<&str, &ActionRow> =
        b.actions.iter().map(|a| (a.id.as_str(), a)).collect();
    for e in &b.erasures {
        let recomputed = tombstone_hash(
            &e.target_action_id,
            &normalize_timestamp(&e.timestamp),
            &e.actor,
            &e.reason,
            &e.original_params_hash,
        );
        if recomputed != e.tombstone_hash {
            r.tombstone_problems.push(format!(
                "erasure of {}: tombstone_hash does not recompute",
                e.target_action_id
            ));
        }
        match action_by_id.get(e.target_action_id.as_str()) {
            Some(a) => match a.redacted_marker_hash.as_deref() {
                Some(m) if m == recomputed => {}
                Some(_) => r.tombstone_problems.push(format!(
                    "action {}: redacted_marker_hash != recomputed tombstone",
                    e.target_action_id
                )),
                None => r.tombstone_problems.push(format!(
                    "action {}: erased but carries no redacted_marker_hash",
                    e.target_action_id
                )),
            },
            None => { /* target action outside the exported window: acceptable */ }
        }
    }

    // ── Merkle blocks (spec §7) ────────────────────────────────────────────
    r.block_count = b.blocks.len();
    let mut blocks: Vec<&_> = b.blocks.iter().collect();
    blocks.sort_by_key(|bl| bl.block_number);
    let mut prev_merkle: Option<&str> = None;
    for bl in &blocks {
        let leaves: Vec<&str> = (bl.first_chain_version..=bl.last_chain_version)
            .filter_map(|cv| stored_by_cv.get(&cv).copied())
            .collect();
        match block_root(&leaves, bl.actions_count) {
            Some(root) if root == bl.merkle_root => {}
            Some(_) => r
                .block_problems
                .push(format!("block {}: Merkle/block root mismatch", bl.block_number)),
            None => r
                .block_problems
                .push(format!("block {}: empty or zero-count leaf set", bl.block_number)),
        }
        if let Some(h) = stored_by_cv.get(&bl.last_chain_version) {
            if *h != bl.last_chain_hash {
                r.block_problems
                    .push(format!("block {}: last_chain_hash != leaf at last version", bl.block_number));
            }
        }
        // Sealed-block linkage: each block commits its predecessor's root.
        if bl.prev_block_merkle.as_deref() != prev_merkle {
            r.block_problems
                .push(format!("block {}: prev_block_merkle breaks block linkage", bl.block_number));
        }
        prev_merkle = Some(&bl.merkle_root);
    }

    // ── Config anchors (spec §9.2, report-only) ────────────────────────────
    for c in &b.configs {
        let resolved = match c.kind.as_str() {
            "effective_rules" => sha256_hex(c.content.as_bytes()) == c.content_hash,
            "cve_feed" => match serde_json::from_str::<serde_json::Value>(&c.content) {
                Ok(v) => canonical_value_hash(&v) == c.content_hash,
                Err(_) => false,
            },
            "manifest" => {
                // Manifest anchors use a JWS-derived hash not reconstructible
                // from the bundle in v0.1. Reported, never failed.
                r.config_unresolved
                    .push(format!("manifest {} (JWS derivation not implemented)", &c.content_hash[..12.min(c.content_hash.len())]));
                continue;
            }
            other => {
                r.config_unresolved.push(format!("unknown config kind '{other}'"));
                continue;
            }
        };
        if resolved {
            r.config_resolved += 1;
        } else {
            r.config_problems
                .push(format!("config {} ({}): content does not re-hash to its address", c.kind, &c.content_hash[..12.min(c.content_hash.len())]));
        }
    }

    r
}

/// Recompute a leaf's chain_hash from the bundle row. `prev` is the
/// predecessor leaf's stored hash (or genesis for chain_version 1).
fn recompute_leaf(
    leaf: &Leaf<'_>,
    prev: &str,
    era_by_target: &HashMap<&str, &ErasureRow>,
    r: &mut Report,
) -> String {
    match leaf {
        Leaf::Action(a) => {
            let ts = normalize_timestamp(&a.timestamp);
            let snapshot_hash = a.snapshot_hash.as_deref().unwrap_or("");
            let params_hash = resolve_params_hash(a, era_by_target, r);
            ActionLeaf {
                prev_hash: prev,
                chain_version: a.chain_version,
                agent_id: &a.agent_id,
                method: &a.method,
                tool_name: a.tool_name.as_deref(),
                params_hash: &params_hash,
                decision: &a.decision,
                decision_source: a.decision_source.as_deref(),
                policy_id: a.policy_id.as_deref(),
                server_id: &a.server_id,
                timestamp: &ts,
                snapshot_hash,
                request_params_truncated: a.request_params_truncated.unwrap_or(false),
                request_params_original_size: a.request_params_original_size.unwrap_or(0),
            }
            .hash()
        }
        Leaf::Erasure(e) => {
            let ts = normalize_timestamp(&e.timestamp);
            ErasureLeaf {
                prev_hash: prev,
                chain_version: e.chain_version,
                target_action_id: &e.target_action_id,
                actor: &e.actor,
                reason: &e.reason,
                timestamp: &ts,
                tombstone_hash: &e.tombstone_hash,
            }
            .hash()
        }
        Leaf::Event(e) => {
            let ts = normalize_timestamp(&e.timestamp);
            let dch = canonical_value_hash(&e.details);
            EventLeaf {
                prev_hash: prev,
                chain_version: e.chain_version,
                event_uid: &e.event_uid,
                event_type: &e.event_type,
                timestamp: &ts,
                details_canonical_hash: &dch,
            }
            .hash()
        }
        Leaf::Response(a) => {
            let ts = a
                .response_chain_timestamp
                .as_deref()
                .map(normalize_timestamp)
                .unwrap_or_default();
            ResponseLeaf {
                prev_hash: prev,
                chain_version: a.response_chain_version.unwrap_or_default(),
                action_id: &a.id,
                response_raw_hash: a.response_raw_hash.as_deref().unwrap_or(""),
                response_truncated: a.response_truncated.unwrap_or(false),
                response_original_size: a.response_original_size.unwrap_or(0),
                timestamp: &ts,
            }
            .hash()
        }
    }
}

/// Resolve an action's params_hash, by the normative rule of spec §9:
///
///  1. `request_params_truncated` → `request_params_raw_hash`, the pre-truncation
///     commitment the leaf carries. Past the producer's threshold `request_params`
///     holds a `{"truncated": true, "size": N}` marker, so re-hashing it cannot
///     reproduce the leaf.
///  2. erased with a tombstone that verifies against both stored copies (spec §6)
///     → the raw commitment if present, else the tombstone's `original_params_hash`.
///     The raw one is more faithful: a truncated action's tombstone commits the
///     marker's hash.
///  3. otherwise hash the current params.
///
/// Case 3 is deliberately not served from the commitment column. Re-hashing the
/// stored payload is what catches an out-of-band rewrite of `request_params`;
/// preferring the column unconditionally would accept a forged payload under a
/// leaf that still verifies.
///
/// Selection is independent of the tombstone verdict: that verdict is an integrity
/// signal about the erasure record, reported by the erasure pass (spec §6).
fn resolve_params_hash(
    a: &ActionRow,
    era_by_target: &HashMap<&str, &ErasureRow>,
    _r: &mut Report,
) -> String {
    if a.request_params_truncated.unwrap_or(false) {
        if let Some(raw) = a.request_params_raw_hash.as_deref() {
            return raw.to_string();
        }
    }
    if let (Some(marker), Some(e)) = (a.redacted_marker_hash.as_deref(), era_by_target.get(a.id.as_str())) {
        let th = tombstone_hash(
            &e.target_action_id,
            &normalize_timestamp(&e.timestamp),
            &e.actor,
            &e.reason,
            &e.original_params_hash,
        );
        if th == e.tombstone_hash && th == marker {
            return a
                .request_params_raw_hash
                .clone()
                .unwrap_or_else(|| e.original_params_hash.clone());
        }
    }
    canonical_params_hash(a.request_params.as_ref())
}
