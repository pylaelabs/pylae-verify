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

use crate::bundle::{ActionRow, Bundle, ErasureRow, EventRow, SnapshotRow};
use crate::canonical::{canonical_json, canonical_params_hash, canonical_value_hash, sha256_hex};
use crate::chain::{
    block_root, genesis_hash, normalize_timestamp, tombstone_hash, ActionLeaf, ErasureLeaf,
    EventLeaf, ResponseLeaf, SnapshotInputs,
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
    pub snapshot_count: usize,
    pub snapshot_problems: Vec<String>,
    pub config_resolved: usize,
    pub config_unresolved: Vec<String>, // report-only limitations (e.g. manifest kind)
    pub config_problems: Vec<String>,   // genuine resolution failures (tamper)
}

impl Report {
    /// Structural verification passes only if every keyless check holds.
    /// Config *unresolved* items are report-only (spec §9.2) and do not gate;
    /// config *problems* (a row that no longer re-hashes to its own address) do.
    ///
    /// Snapshot problems gate for the reason §2.2 gives: the action leaf
    /// commits to the snapshot *hash*, so a producer-side change to one of
    /// its inputs recomputes clean at every other level. This is the only
    /// check that sees it.
    #[must_use]
    pub fn structural_passed(&self) -> bool {
        self.genesis_error.is_none()
            && self.manifest_problems.is_empty()
            && self.leaf_mismatches.is_empty()
            && self.linkage_gaps.is_empty()
            && self.block_problems.is_empty()
            && self.tombstone_problems.is_empty()
            && self.snapshot_problems.is_empty()
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
    // ── MANIFEST integrity (spec §9.1) ─────────────────────────────────────
    let mut r = Report {
        manifest_problems: b.verify_manifest(),
        ..Default::default()
    };

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
                r.leaf_mismatches.push(format!(
                    "chain_version {cv} ({}): missing chain_hash",
                    leaf.kind()
                ));
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
            r.leaf_mismatches.push(format!(
                "chain_version {cv} ({}): recomputed hash != stored",
                leaf.kind()
            ));
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

    // ── Snapshots (spec §2.2 + §9) ─────────────────────────────────────────
    //
    // The action leaf commits to `snapshot_hash`, never to the values behind
    // it, so every other Level 1 check passes over a snapshot whose inputs
    // were edited to keep the same recorded hash. Recomputing from
    // `snapshots.jsonl` is what sees it — and the file has to be there for
    // the recomputation to exist at all, which is why §9 makes a committed
    // hash with no row an invariant violation rather than an absent
    // snapshot.
    r.snapshot_count = b.snapshots.len();
    let mut snapshot_by_action: HashMap<&str, &SnapshotRow> = HashMap::new();
    for s in &b.snapshots {
        if snapshot_by_action.insert(s.action_id.as_str(), s).is_some() {
            r.snapshot_problems.push(format!(
                "action {}: two rows in snapshots.jsonl claim the same action",
                s.action_id
            ));
        }
    }
    for a in &b.actions {
        let committed = a.snapshot_hash.as_deref().unwrap_or("");
        match (committed.is_empty(), snapshot_by_action.get(a.id.as_str())) {
            // The ordinary case: no snapshot was bound, the leaf carries
            // the empty sentinel, and no row exists.
            (true, None) => {}
            (true, Some(_)) => r.snapshot_problems.push(format!(
                "action {}: ships a snapshot row but its leaf commits the empty hash \
                 (spec §9: a row appears if and only if the action carried a snapshot)",
                a.id
            )),
            (false, None) => r.snapshot_problems.push(format!(
                "action {}: commits snapshot {} and ships no row — the producer published \
                 a commitment whose inputs the recipient does not hold",
                a.id,
                short(committed)
            )),
            (false, Some(s)) => {
                let recomputed = SnapshotInputs {
                    security_posture: &s.security_posture,
                    cost_ceiling: &s.cost_ceiling,
                    agent_profile_id: s.agent_profile_id.as_deref(),
                    active_policy_ids: &s.active_policy_ids,
                    active_contract_id: s.active_contract_id.as_deref(),
                    damage_estimate: &s.damage_estimate,
                }
                .hash();
                if recomputed != committed {
                    r.snapshot_problems.push(format!(
                        "action {}: snapshot inputs recompute to {} but the leaf commits {}",
                        a.id,
                        short(&recomputed),
                        short(committed)
                    ));
                } else if s.snapshot_hash != committed {
                    // The row's own hash column contradicts the leaf even
                    // though the inputs reproduce the leaf. Reported
                    // separately: nothing is forged, but the bundle carries
                    // two answers and a reader could believe either.
                    r.snapshot_problems.push(format!(
                        "action {}: snapshots.jsonl records {} where the leaf commits {}",
                        a.id,
                        short(&s.snapshot_hash),
                        short(committed)
                    ));
                }
            }
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
            Some(_) => r.block_problems.push(format!(
                "block {}: Merkle/block root mismatch",
                bl.block_number
            )),
            None => r.block_problems.push(format!(
                "block {}: empty or zero-count leaf set",
                bl.block_number
            )),
        }
        if let Some(h) = stored_by_cv.get(&bl.last_chain_version) {
            if *h != bl.last_chain_hash {
                r.block_problems.push(format!(
                    "block {}: last_chain_hash != leaf at last version",
                    bl.block_number
                ));
            }
        }
        // Sealed-block linkage: each block commits its predecessor's root.
        if bl.prev_block_merkle.as_deref() != prev_merkle {
            r.block_problems.push(format!(
                "block {}: prev_block_merkle breaks block linkage",
                bl.block_number
            ));
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
            // Spec §9.2. This derivation is **keyless** and always has
            // been: the manifest hash is SHA-256 of the canonical JSON of
            // the payload, and the payload is obtainable from the archived
            // content without any signature. Earlier text here declared it
            // "not reconstructible from the bundle alone" and reported
            // every manifest row unresolved, so the one row an attacker
            // could swap was the one row nobody checked.
            "manifest" => match manifest_payload(&c.content) {
                Ok(payload) => match canonical_json(&payload) {
                    Ok(cj) => sha256_hex(cj.as_bytes()) == c.content_hash,
                    // The §2.2 bound: a form this spec does not define.
                    // Unresolved, not failed — guessing one would mint an
                    // address the publisher never computed.
                    Err(why) => {
                        r.config_unresolved
                            .push(format!("manifest {}: {why}", short(&c.content_hash)));
                        continue;
                    }
                },
                Err(why) => {
                    r.config_problems
                        .push(format!("manifest {}: {why}", short(&c.content_hash)));
                    continue;
                }
            },
            other => {
                r.config_unresolved
                    .push(format!("unknown config kind '{other}'"));
                continue;
            }
        };
        if resolved {
            r.config_resolved += 1;
        } else {
            r.config_problems.push(format!(
                "config {} ({}): content does not re-hash to its address",
                c.kind,
                short(&c.content_hash)
            ));
        }
    }

    r
}

/// First 12 characters of a hash, for report lines.
fn short(hash: &str) -> &str {
    &hash[..12.min(hash.len())]
}

/// Obtain a manifest payload from an archived `config_archive` body, by the
/// rule of spec §9.2.
///
/// `content` starting with `{` is the canonical payload JSON itself — an
/// embedded snapshot, which has no publisher envelope. Otherwise it is a
/// compact JWS and the payload is its middle segment, base64url without
/// padding. **The signature is not needed and MUST NOT be required**: the
/// derivation is keyless and belongs to Level 1.
///
/// The discriminator is structural rather than a `.` scan: `{` is not in the
/// base64url alphabet, while canonical JSON contains dots inside float
/// values.
///
/// # Errors
/// Returns `Err` when the body is neither parseable JSON nor a compact JWS
/// whose payload segment decodes to JSON. That is a failure and not a
/// limitation: the row is content-addressed, so a body that cannot even
/// produce a payload cannot re-derive its own key.
fn manifest_payload(content: &str) -> Result<serde_json::Value, String> {
    if content.starts_with('{') {
        return serde_json::from_str(content)
            .map_err(|e| format!("embedded payload is not valid JSON: {e}"));
    }
    let mut segments = content.split('.');
    let (_header, payload) = match (segments.next(), segments.next()) {
        (Some(h), Some(p)) if !h.is_empty() && !p.is_empty() => (h, p),
        _ => return Err("content is neither an embedded payload nor a compact JWS".into()),
    };
    let raw = base64url_decode(payload)
        .map_err(|e| format!("JWS payload segment does not decode: {e}"))?;
    serde_json::from_slice(&raw).map_err(|e| format!("JWS payload is not valid JSON: {e}"))
}

/// base64url decode without padding (RFC 4648 §5), hand-rolled to keep this
/// crate's dependency surface at the cryptography it cannot reimplement.
///
/// Rejects padding, non-alphabet bytes, and a trailing group of one
/// character — which encodes no byte and is how a truncated segment shows up.
fn base64url_decode(s: &str) -> Result<Vec<u8>, String> {
    fn sextet(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    if bytes.len() % 4 == 1 {
        return Err("truncated base64url group".into());
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut acc: u32 = 0;
        for &c in chunk {
            let v = sextet(c).ok_or_else(|| format!("byte {c:#04x} is not base64url"))?;
            acc = (acc << 6) | v;
        }
        // A short final chunk carries 6 bits per character; shift the
        // accumulator up so the bytes land in the high end of the group.
        let bits = chunk.len() * 6;
        acc <<= 24 - bits;
        let produced = bits / 8;
        for i in 0..produced {
            out.push(((acc >> (16 - 8 * i)) & 0xff) as u8);
        }
    }
    Ok(out)
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
    if let (Some(marker), Some(e)) = (
        a.redacted_marker_hash.as_deref(),
        era_by_target.get(a.id.as_str()),
    ) {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4648 §10 vectors, which cover the three final-group shapes the
    /// decoder has to get right. A JWS payload segment lands on whichever
    /// of them its length implies, and the fixture only ever exercises
    /// one — so a bug in the other two ships invisibly behind a bundle
    /// that happens to verify.
    #[test]
    fn base64url_decodes_every_final_group_shape() {
        for (enc, dec) in [
            ("", ""),
            ("Zg", "f"),
            ("Zm8", "fo"),
            ("Zm9v", "foo"),
            ("Zm9vYg", "foob"),
            ("Zm9vYmE", "fooba"),
            ("Zm9vYmFy", "foobar"),
        ] {
            assert_eq!(
                base64url_decode(enc).expect("valid base64url"),
                dec.as_bytes(),
                "{enc} did not decode to {dec}"
            );
        }
    }

    /// The URL-safe alphabet is the whole reason this is not plain
    /// base64: sextets 62 and 63 are `-` and `_` here and `+` and `/`
    /// there. A decoder built on the standard table rejects a real JWS
    /// segment, or worse, silently accepts one carrying `+` or `/`.
    #[test]
    fn the_alphabet_is_url_safe_and_only_url_safe() {
        assert_eq!(base64url_decode("____").unwrap(), vec![0xff, 0xff, 0xff]);
        assert_eq!(base64url_decode("----").unwrap(), vec![0xfb, 0xef, 0xbe]);
        assert!(base64url_decode("++++").is_err());
        assert!(base64url_decode("////").is_err());
    }

    /// Padding is not part of the compact serialization, and a trailing
    /// group of one character encodes no byte at all — it is what a
    /// truncated segment looks like. Both are refused rather than
    /// silently producing a shorter payload, because a payload that
    /// decodes to *something* will be parsed, hashed, and reported as an
    /// address mismatch: a tamper verdict on what is actually a
    /// malformed row.
    #[test]
    fn padding_and_a_truncated_group_are_refused() {
        assert!(base64url_decode("Zg==").is_err());
        assert!(base64url_decode("Zm9vYg==").is_err());
        assert!(base64url_decode("Z").is_err());
        assert!(base64url_decode("Zm9vYg#").is_err());
        assert!(base64url_decode("Zm9v\u{e9}").is_err());
    }

    /// The §9.2 discriminator, both ways round. `{` is not in the
    /// base64url alphabet and canonical JSON contains dots inside float
    /// values, which is why the rule is structural rather than a scan
    /// for `.`.
    #[test]
    fn the_manifest_body_discriminator_is_structural() {
        let embedded = manifest_payload(r#"{"a":1.5}"#).expect("embedded payload");
        assert_eq!(embedded["a"], serde_json::json!(1.5));

        // A canonical payload carrying a float: dots, and still not a JWS.
        let with_dots = manifest_payload(r#"{"x":1.0,"y":2.0}"#).expect("still embedded");
        assert_eq!(with_dots["y"], serde_json::json!(2.0));

        // A body that is neither.
        assert!(manifest_payload("not-a-jws").is_err());
        assert!(manifest_payload("").is_err());
    }
}
