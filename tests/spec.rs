//! The vendored specification and this implementation agree.
//!
//! `docs/EVIDENCE-FORMAT.md` is the contract this verifier claims to implement.
//! These tests read it from disk rather than restating it, so editing the
//! document without the code (or the code without the document) fails here.

use pylae_verify::canonical::{canonical_json, sha256_hex, write_value};
use pylae_verify::SPEC_VERSION;
use serde_json::Value;

fn spec() -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/docs/EVIDENCE-FORMAT.md");
    std::fs::read_to_string(path)
        .expect("docs/EVIDENCE-FORMAT.md is vendored in the repo")
        // A Windows checkout may carry CRLF; the vector blocks are parsed by line.
        .replace("\r\n", "\n")
}

/// The fenced block that follows `heading`, one `(label, value)` per line.
fn vector(spec: &str, heading: &str) -> Vec<(String, String)> {
    let after = &spec[spec.find(heading).expect("section heading present")..];
    let open = after.find("```\n").expect("vector block opens") + 4;
    let body = &after[open..];
    let body = &body[..body.find("```").expect("vector block closes")];
    body.lines()
        .filter_map(|l| {
            let l = l.trim();
            let (k, v) = l.split_once(char::is_whitespace)?;
            Some((k.to_string(), v.trim().to_string()))
        })
        .collect()
}

#[test]
fn the_header_names_the_version_this_build_implements() {
    let spec = spec();
    let first = spec
        .lines()
        .find(|l| l.starts_with("*Version "))
        .expect("version line");
    assert!(
        first.starts_with(&format!("*Version {SPEC_VERSION} ")),
        "SPEC_VERSION is {SPEC_VERSION} but the vendored spec says: {first}"
    );
}

/// §2.3 as printed in the document, not as copied into a unit test. Lines
/// are, in order: input, write_value, its hash, canonical_json, its hash.
#[test]
fn the_vendored_section_2_3_vector_is_what_this_code_produces() {
    let spec = spec();
    let lines = vector(&spec, "### 2.3 Conformance vector");
    let get = |i: usize, label: &str| {
        let (k, v) = &lines[i];
        assert_eq!(k, label, "§2.3 line {i} changed shape");
        v.clone()
    };

    let input: Value = serde_json::from_str(&get(0, "input")).expect("§2.3 input parses");
    let mut buf = Vec::new();
    write_value(&mut buf, &input);
    assert_eq!(hex::encode(&buf), get(1, "write_value"));
    assert_eq!(sha256_hex(&buf), get(2, "hex(H(...))"));

    let cj = canonical_json(&input).expect("§2.3 input needs no exponent");
    assert_eq!(cj, get(3, "canonical_json"));
    assert_eq!(sha256_hex(cj.as_bytes()), get(4, "hex(H(...))"));
}
