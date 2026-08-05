//! Canonical encoding and hashing — Pylae Evidence Format Specification §1–§2.
//!
//! Clean-room implementation from the published spec. No Pylae product code is
//! used here; only standard cryptography (`sha2`) and JSON parsing (`serde_json`).
#![allow(dead_code)]

use serde_json::Value;
use sha2::{Digest, Sha256};

// Tag bytes for the canonical JSON-value encoding (spec §2.1).
const TAG_NULL: u8 = 0x60;
const TAG_FALSE: u8 = 0x50;
const TAG_TRUE: u8 = 0x51;
const TAG_STRING: u8 = 0x30;
const TAG_INT_I64: u8 = 0x41;
const TAG_INT_U64: u8 = 0x42;
const TAG_FLOAT: u8 = 0x43;
const TAG_ARRAY: u8 = 0x20;
const TAG_OBJECT: u8 = 0x10;

// Optional-field tags (spec §2).
const OPT_TAG_NONE: u8 = 0x00;
const OPT_TAG_SOME: u8 = 0x01;

/// SHA-256 of `bytes`, lowercase hex (spec §1).
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// SHA-256 raw 32 bytes.
pub fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

pub fn write_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}
pub fn write_i64(buf: &mut Vec<u8>, v: i64) {
    buf.extend_from_slice(&v.to_le_bytes());
}
pub fn write_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

/// Length-prefixed UTF-8 string: `u32_le(len) || bytes` (spec §2).
pub fn write_str(buf: &mut Vec<u8>, s: &str) {
    write_u32(buf, s.len() as u32);
    buf.extend_from_slice(s.as_bytes());
}

/// Optional length-prefixed string: `None` => `0x00`;
/// `Some(s)` => `0x01 || write_str(s)` (spec §2).
pub fn write_opt_str(buf: &mut Vec<u8>, s: Option<&str>) {
    match s {
        None => buf.push(OPT_TAG_NONE),
        Some(v) => {
            buf.push(OPT_TAG_SOME);
            write_str(buf, v);
        }
    }
}

/// Canonical byte encoding of a JSON value (spec §2.1).
///
/// Object keys are sorted ascending by Unicode code point (Rust `str` Ord).
/// Numbers are typed `i64` → `u64` → `f64` so the encoding is independent of
/// any serializer's number formatting.
pub fn write_value(buf: &mut Vec<u8>, v: &Value) {
    match v {
        Value::Null => buf.push(TAG_NULL),
        Value::Bool(false) => buf.push(TAG_FALSE),
        Value::Bool(true) => buf.push(TAG_TRUE),
        Value::String(s) => {
            buf.push(TAG_STRING);
            write_str(buf, s);
        }
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                buf.push(TAG_INT_I64);
                write_i64(buf, i);
            } else if let Some(u) = n.as_u64() {
                buf.push(TAG_INT_U64);
                write_u64(buf, u);
            } else if let Some(f) = n.as_f64() {
                buf.push(TAG_FLOAT);
                buf.extend_from_slice(&f.to_le_bytes());
            } else {
                // Unreachable for valid serde_json numbers; conservative fallback.
                buf.push(TAG_NULL);
            }
        }
        Value::Array(arr) => {
            buf.push(TAG_ARRAY);
            write_u32(buf, arr.len() as u32);
            for item in arr {
                write_value(buf, item);
            }
        }
        Value::Object(obj) => {
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort();
            buf.push(TAG_OBJECT);
            write_u32(buf, keys.len() as u32);
            for k in keys {
                write_str(buf, k);
                write_value(buf, obj.get(k).expect("key from obj.keys()"));
            }
        }
    }
}

/// `hex(SHA-256(write_value(v)))` (spec §2.2).
pub fn canonical_value_hash(v: &Value) -> String {
    let mut buf = Vec::with_capacity(64);
    write_value(&mut buf, v);
    sha256_hex(&buf)
}

/// `params_hash`: empty string when absent, else `canonical_value_hash` (spec §2.2).
pub fn canonical_params_hash(params: Option<&Value>) -> String {
    match params {
        None => String::new(),
        Some(v) => canonical_value_hash(v),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn opt_str_distinguishes_none_from_empty() {
        let mut a = Vec::new();
        write_opt_str(&mut a, None);
        let mut b = Vec::new();
        write_opt_str(&mut b, Some(""));
        assert_ne!(a, b);
        assert_eq!(a, vec![0x00]);
        assert_eq!(b, vec![0x01, 0, 0, 0, 0]); // SOME || u32_le(0)
    }

    #[test]
    fn object_key_order_is_canonical() {
        // Same object, different key insertion order → identical hash.
        let x = json!({"b": 1, "a": 2});
        let y = json!({"a": 2, "b": 1});
        assert_eq!(canonical_value_hash(&x), canonical_value_hash(&y));
    }

    #[test]
    fn string_is_length_prefixed() {
        let mut buf = Vec::new();
        write_str(&mut buf, "hi");
        assert_eq!(buf, vec![2, 0, 0, 0, b'h', b'i']);
    }
}
