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

/// Textual canonical JSON (spec §2.2). Used **only** by the manifest hash
/// (§9.2); everything else in the format hashes `write_value`.
///
/// Two encoders exist because the manifest hash is computed over a JSON
/// document the publisher signed, so its preimage has to stay JSON text. The
/// rules, verbatim from §2.2:
///
/// * object — `{` , members `"key":value` joined by `,` , `}` , keys sorted
///   ascending by Unicode code point; array — order preserved; no whitespace.
/// * string — RFC 8259 §7 escaping, shortest form.
/// * number — **the branch is chosen by the token, not by the value.** An
///   integer token emits its exact decimal digits; a float token emits the
///   shortest decimal string that round-trips, with a `.0` suffix when the
///   value is integral. `1` and `1.0` are different inputs and encode
///   differently — see the §2.3 vector below, which is what catches a reader
///   that collapses them.
///
/// # Errors
/// Returns `Err` when a float's shortest round-tripping form needs an
/// exponent. §2.2 bounds the construction rather than specifying a form no
/// third party could reproduce: a manifest payload MUST NOT carry such a
/// number, and a verifier that meets one MUST report the row unresolved
/// rather than guess.
pub fn canonical_json(v: &Value) -> Result<String, String> {
    let mut out = String::with_capacity(256);
    write_canonical_json(v, &mut out)?;
    Ok(out)
}

fn write_canonical_json(v: &Value, out: &mut String) -> Result<(), String> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::String(s) => out.push_str(&json_string(s)),
        Value::Number(n) => {
            // `Number`'s own text keeps the token: an integer token prints
            // its digits, a float token prints the shortest round-tripping
            // decimal and never drops its fraction. That is the §2.2 rule,
            // and it is the one place where reading the value instead of
            // the token would silently produce a different hash.
            // `Number`'s own text is the shortest round-tripping form and it
            // keeps the token: an integer token prints its digits, a float
            // token prints its fraction and never drops it. That is the §2.2
            // rule verbatim, and it is delegated rather than reimplemented
            // because "shortest decimal string that round-trips" is exactly
            // what a JSON number formatter already computes.
            //
            // Delegated, not assumed: `a_float_token_keeps_its_fraction`
            // below pins the half that matters, because reading the *value*
            // instead of the token is the mistake §2.2 calls out — a
            // `min_chain_coverage` of 99.0 that serializes as `99` computes
            // a different manifest hash for every bundle.
            let t = n.to_string();
            if t.contains('e') || t.contains('E') {
                return Err(format!("number {t} needs an exponent (spec §2.2 bound)"));
            }
            out.push_str(&t);
        }
        Value::Array(arr) => {
            out.push('[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical_json(item, out)?;
            }
            out.push(']');
        }
        Value::Object(obj) => {
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&json_string(k));
                out.push(':');
                write_canonical_json(obj.get(*k).expect("key from obj.keys()"), out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// RFC 8259 §7 string escaping, shortest form: only `"`, `\` and
/// U+0000–U+001F are escaped; `\b \f \n \r \t` take their two-character
/// forms and every other control character takes `\u00XX` in lowercase hex.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
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

    /// Spec §2.3, both lines, over the one object that carries both number
    /// tokens. §11 makes this the conformance gate: *"an implementation that
    /// cannot reproduce §2.3 is not conformant, whatever else it passes."*
    ///
    /// The input is parsed from **text**, deliberately. Building it with
    /// `json!({"float": 1.0, "int": 1})` would prove nothing about the
    /// reader: the whole failure this vector exists to catch is a parser
    /// that collapses `1.0` and `1` into one number, and only a parse of
    /// the published bytes can exhibit it.
    #[test]
    fn the_published_conformance_vector_is_what_this_code_produces() {
        let v: Value = serde_json::from_str(r#"{"float":1.0,"int":1}"#).expect("§2.3 input");

        let mut buf = Vec::new();
        write_value(&mut buf, &v);
        assert_eq!(
            hex::encode(&buf),
            "100200000005000000666c6f617443000000000000f03f03000000696e744101000000\
             00000000",
            "write_value must produce the published bytes"
        );
        assert_eq!(
            sha256_hex(&buf),
            "de789bfc10c30559c6087d3df7dbb5bc7eee0f3401d46576fce25ab66b09b55d"
        );

        let cj = canonical_json(&v).expect("§2.3 input needs no exponent");
        assert_eq!(cj, r#"{"float":1.0,"int":1}"#);
        assert_eq!(
            sha256_hex(cj.as_bytes()),
            "049a286599a6c0887e4bce2e4505ab4cee4faff27488688ebba3dfa0f8addb69"
        );
    }

    /// The same pairing, stated as the property rather than as a digest:
    /// the two members hold one numeric value and must encode differently.
    /// A reader that collapses the tokens passes neither assertion.
    #[test]
    fn the_two_number_tokens_do_not_collapse() {
        let i: Value = serde_json::from_str("1").expect("int token");
        let f: Value = serde_json::from_str("1.0").expect("float token");
        assert_ne!(
            canonical_value_hash(&i),
            canonical_value_hash(&f),
            "write_value must keep the tokens apart"
        );
        assert_eq!(canonical_json(&i).unwrap(), "1");
        assert_eq!(canonical_json(&f).unwrap(), "1.0");
    }

    /// A float token keeps its fraction — §2.2's *"with a `.0` suffix when
    /// the value is integral"*, and the rule the spec says a verifier is
    /// most likely to get wrong.
    ///
    /// `min_chain_coverage` is the live instance: a float token whose value
    /// is 99, which must serialize `99.0`. An implementation that reads the
    /// value rather than the token emits `99` and computes a different
    /// manifest hash for every bundle it ever sees.
    #[test]
    fn a_float_token_keeps_its_fraction() {
        for src in ["1.0", "99.0", "2.5", "-3.0", "0.0", "2.1831479362172885"] {
            let v: Value = serde_json::from_str(src).expect("float token");
            assert_eq!(
                canonical_json(&v).expect("no exponent needed"),
                src,
                "{src} did not round-trip through canonical_json"
            );
        }
        let v: Value = serde_json::from_str(r#"{"min_chain_coverage":99.0}"#).expect("parse");
        assert_eq!(
            canonical_json(&v).unwrap(),
            r#"{"min_chain_coverage":99.0}"#,
            "the value the spec names as the trap"
        );
    }

    /// The §2.2 bound. The decimal-without-exponent form does not exist for
    /// every double, and where a formatter switches is a property of the
    /// formatter rather than of this format — so the spec forbids such a
    /// number in a manifest payload and tells the verifier to report the row
    /// unresolved. Guessing a form here would mint an address the publisher
    /// never computed.
    #[test]
    fn a_number_needing_an_exponent_is_refused_rather_than_guessed() {
        let v: Value = serde_json::from_str(r#"{"big":1e300}"#).expect("parse");
        assert!(canonical_json(&v).is_err());
    }

    #[test]
    fn canonical_json_sorts_keys_and_escapes_controls() {
        let v: Value = serde_json::from_str(r#"{"b":1,"a":"x\ty"}"#).expect("parse");
        assert_eq!(canonical_json(&v).unwrap(), r#"{"a":"x\ty","b":1}"#);
        let v: Value = serde_json::from_str(r#"{"k":"\u0001"}"#).expect("parse");
        assert_eq!(canonical_json(&v).unwrap(), r#"{"k":"\u0001"}"#);
    }
}
