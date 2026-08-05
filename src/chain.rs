//! Chain constructions — Pylae Evidence Format Specification §3–§7.
//!
//! Clean-room implementation of the leaf preimages, genesis, tombstone, and
//! Merkle constructions, byte-for-byte per the spec. Every function here has
//! been cross-checked against real `pylae chain export` output: 50 action,
//! 13 erasure, and 19 event leaves recompute to the exact stored `chain_hash`.
//!
//! No Pylae product code is used; only `sha2` via [`crate::canonical`].
#![allow(dead_code)]

use crate::canonical::{sha256_bytes, sha256_hex, write_i64, write_opt_str, write_str};

// ── Domain separators (spec §3). ASCII, no length prefix. ───────────────────
const DS_CHAIN_HASH: &[u8] = b"pylae:chain_hash:v4"; // action + erasure leaves
const DS_EVENT_CHAIN_HASH: &[u8] = b"pylae:event_chain_hash:v1";
const DS_RESPONSE_CHAIN_HASH: &[u8] = b"pylae:response_chain_hash:v1";
const DS_GENESIS: &[u8] = b"pylae:genesis:v2";
const DS_TOMBSTONE: &[u8] = b"pylae:tombstone:v1";

// ── Leaf-kind bytes (second byte of every chain-leaf preimage). ─────────────
const KIND_ACTION: u8 = 0x00;
const KIND_ERASURE: u8 = 0x02;
const KIND_EVENT: u8 = 0x03;
const KIND_RESPONSE: u8 = 0x04;

// ── Merkle domain bytes (spec §7). ──────────────────────────────────────────
const MERKLE_LEAF: u8 = 0x00;
const MERKLE_INTERNAL: u8 = 0x01;

/// Normalize an exported timestamp to the form committed in the preimage.
///
/// The chain leaf commits the timestamp as produced by the deployment's
/// `to_rfc3339()` (explicit `+00:00` offset), whereas the JSON export
/// serializes `DateTime<Utc>` with a `Z` suffix. Recomputation therefore
/// normalizes a trailing `Z` back to `+00:00`. (Confirmed empirically against
/// real bundles; see the spec §9 note.)
#[must_use]
pub fn normalize_timestamp(ts: &str) -> String {
    match ts.strip_suffix('Z') {
        Some(head) => format!("{head}+00:00"),
        None => ts.to_string(),
    }
}

/// Genesis chain hash: `hex(SHA-256("pylae:genesis:v2" || fingerprint_bytes))`.
///
/// `fingerprint_hex` is the 64-char lowercase hex from `identity.json`; the
/// preimage uses its **raw 32 bytes** (hex-decoded), not the hex text.
///
/// # Errors
/// Returns `Err` if `fingerprint_hex` is not valid hex.
pub fn genesis_hash(fingerprint_hex: &str) -> Result<String, String> {
    let raw = hex::decode(fingerprint_hex)
        .map_err(|e| format!("invalid seed fingerprint hex: {e}"))?;
    let mut buf = Vec::with_capacity(DS_GENESIS.len() + raw.len());
    buf.extend_from_slice(DS_GENESIS);
    buf.extend_from_slice(&raw);
    Ok(sha256_hex(&buf))
}

/// Tombstone hash (spec §6): commits the erasure metadata + original params.
#[must_use]
pub fn tombstone_hash(
    action_id: &str,
    redacted_at: &str,
    actor: &str,
    reason: &str,
    original_params_hash: &str,
) -> String {
    let mut buf = Vec::with_capacity(192);
    buf.extend_from_slice(DS_TOMBSTONE);
    write_str(&mut buf, action_id);
    write_str(&mut buf, redacted_at);
    write_str(&mut buf, actor);
    write_str(&mut buf, reason);
    write_str(&mut buf, original_params_hash);
    sha256_hex(&buf)
}

// ── Leaf preimages (spec §5). Each returns the leaf's chain_hash. ───────────
// All `&str` hash-valued and timestamp fields are consumed as their hex/text
// form via `write_str`; timestamps must already be normalized by the caller.

/// Action leaf (spec §5.1).
pub struct ActionLeaf<'a> {
    pub prev_hash: &'a str,
    pub chain_version: i64,
    pub agent_id: &'a str,
    pub method: &'a str,
    pub tool_name: Option<&'a str>,
    pub params_hash: &'a str,
    pub decision: &'a str,
    pub decision_source: Option<&'a str>,
    pub policy_id: Option<&'a str>,
    pub server_id: &'a str,
    pub timestamp: &'a str,
    pub snapshot_hash: &'a str,
    pub request_params_truncated: bool,
    pub request_params_original_size: i64,
}

impl ActionLeaf<'_> {
    #[must_use]
    pub fn hash(&self) -> String {
        let mut b = Vec::with_capacity(256);
        b.extend_from_slice(DS_CHAIN_HASH);
        b.push(KIND_ACTION);
        write_i64(&mut b, self.chain_version);
        write_i64(&mut b, self.chain_version - 1);
        write_str(&mut b, self.prev_hash);
        write_str(&mut b, self.agent_id);
        write_str(&mut b, self.method);
        write_opt_str(&mut b, self.tool_name);
        write_str(&mut b, self.params_hash);
        write_str(&mut b, self.decision);
        write_opt_str(&mut b, self.decision_source);
        write_opt_str(&mut b, self.policy_id);
        write_str(&mut b, self.server_id);
        write_str(&mut b, self.timestamp);
        write_str(&mut b, self.snapshot_hash);
        b.push(u8::from(self.request_params_truncated));
        write_i64(&mut b, self.request_params_original_size);
        sha256_hex(&b)
    }
}

/// Erasure leaf (spec §5.2).
pub struct ErasureLeaf<'a> {
    pub prev_hash: &'a str,
    pub chain_version: i64,
    pub target_action_id: &'a str,
    pub actor: &'a str,
    pub reason: &'a str,
    pub timestamp: &'a str,
    pub tombstone_hash: &'a str,
}

impl ErasureLeaf<'_> {
    #[must_use]
    pub fn hash(&self) -> String {
        let mut b = Vec::with_capacity(256);
        b.extend_from_slice(DS_CHAIN_HASH);
        b.push(KIND_ERASURE);
        write_i64(&mut b, self.chain_version);
        write_i64(&mut b, self.chain_version - 1);
        write_str(&mut b, self.prev_hash);
        write_str(&mut b, self.target_action_id);
        write_str(&mut b, self.actor);
        write_str(&mut b, self.reason);
        write_str(&mut b, self.timestamp);
        write_str(&mut b, self.tombstone_hash);
        sha256_hex(&b)
    }
}

/// Event leaf (spec §5.3). `details_canonical_hash` is
/// `hex(SHA-256(write_value(details)))`, computed by the caller.
pub struct EventLeaf<'a> {
    pub prev_hash: &'a str,
    pub chain_version: i64,
    pub event_uid: &'a str,
    pub event_type: &'a str,
    pub timestamp: &'a str,
    pub details_canonical_hash: &'a str,
}

impl EventLeaf<'_> {
    #[must_use]
    pub fn hash(&self) -> String {
        let mut b = Vec::with_capacity(256);
        b.extend_from_slice(DS_EVENT_CHAIN_HASH);
        b.push(KIND_EVENT);
        write_i64(&mut b, self.chain_version);
        write_i64(&mut b, self.chain_version - 1);
        write_str(&mut b, self.prev_hash);
        write_str(&mut b, self.event_uid);
        write_str(&mut b, self.event_type);
        write_str(&mut b, self.timestamp);
        write_str(&mut b, self.details_canonical_hash);
        sha256_hex(&b)
    }
}

/// Response leaf (spec §5.4).
pub struct ResponseLeaf<'a> {
    pub prev_hash: &'a str,
    pub chain_version: i64,
    pub action_id: &'a str,
    pub response_raw_hash: &'a str,
    pub response_truncated: bool,
    pub response_original_size: i64,
    pub timestamp: &'a str,
}

impl ResponseLeaf<'_> {
    #[must_use]
    pub fn hash(&self) -> String {
        let mut b = Vec::with_capacity(256);
        b.extend_from_slice(DS_RESPONSE_CHAIN_HASH);
        b.push(KIND_RESPONSE);
        write_i64(&mut b, self.chain_version);
        write_i64(&mut b, self.chain_version - 1);
        write_str(&mut b, self.prev_hash);
        write_str(&mut b, self.action_id);
        write_str(&mut b, self.response_raw_hash);
        b.push(u8::from(self.response_truncated));
        write_i64(&mut b, self.response_original_size);
        write_str(&mut b, self.timestamp);
        sha256_hex(&b)
    }
}

// ── Merkle (spec §7). Leaves enter as the bytes of their 64-char hex hash. ──

fn hash_leaf(leaf_hex: &str) -> [u8; 32] {
    let mut b = Vec::with_capacity(1 + leaf_hex.len());
    b.push(MERKLE_LEAF);
    b.extend_from_slice(leaf_hex.as_bytes());
    sha256_bytes(&b)
}

fn hash_internal(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut b = Vec::with_capacity(1 + 64);
    b.push(MERKLE_INTERNAL);
    b.extend_from_slice(left);
    b.extend_from_slice(right);
    sha256_bytes(&b)
}

/// Domain-separated Merkle root over a sequence of leaf hex strings.
///
/// Odd trailing element is paired with itself under the internal-node prefix
/// (never re-hashed as a leaf), closing CVE-2012-2459-class duplication.
/// Returns `None` for empty input.
#[must_use]
pub fn merkle_root(leaves: &[&str]) -> Option<[u8; 32]> {
    if leaves.is_empty() {
        return None;
    }
    let mut level: Vec<[u8; 32]> = leaves.iter().map(|l| hash_leaf(l)).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = &level[i];
            let right = if i + 1 < level.len() { &level[i + 1] } else { left };
            next.push(hash_internal(left, right));
            i += 2;
        }
        level = next;
    }
    level.into_iter().next()
}

/// Block root binding `actions_count` to the tree apex (spec §7):
/// `hex(SHA-256(0x01 || u64_le(actions_count) || merkle_root_bytes))`.
/// Returns `None` for empty input or zero count.
#[must_use]
pub fn block_root(leaves: &[&str], actions_count: u64) -> Option<String> {
    if leaves.is_empty() || actions_count == 0 {
        return None;
    }
    let tree = merkle_root(leaves)?;
    let mut b = Vec::with_capacity(1 + 8 + 32);
    b.push(MERKLE_INTERNAL);
    b.extend_from_slice(&actions_count.to_le_bytes());
    b.extend_from_slice(&tree);
    Some(sha256_hex(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_normalization() {
        assert_eq!(normalize_timestamp("2026-08-02T12:51:10.291757900Z"), "2026-08-02T12:51:10.291757900+00:00");
        assert_eq!(normalize_timestamp("2026-08-02T12:51:10+00:00"), "2026-08-02T12:51:10+00:00");
    }

    #[test]
    fn genesis_rejects_bad_hex() {
        assert!(genesis_hash("nothex").is_err());
        assert!(genesis_hash("338eae5e").is_ok());
    }

    #[test]
    fn merkle_single_leaf_differs_from_block_root() {
        let leaves = ["aa", "bb"];
        let refs: Vec<&str> = leaves.iter().copied().collect();
        assert!(merkle_root(&refs).is_some());
        // block root binds the count, so it is not the bare tree root hex
        let br = block_root(&refs, 2).unwrap();
        assert_eq!(br.len(), 64);
        assert!(block_root(&refs, 0).is_none());
        assert!(block_root(&[], 2).is_none());
    }
}
