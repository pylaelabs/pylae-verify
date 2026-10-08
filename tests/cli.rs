//! What the binary prints — the report an auditor reads.
//!
//! `tests/integration.rs` checks the library's `Report`. The lines a reader
//! sees are composed in `main.rs`, and a correct `Report` rendered as `[ok]`
//! is still a false statement. These tests run the built binary.

use std::path::{Path, PathBuf};
use std::process::Command;

const DEMO: &str = "tests/fixtures/demo-bundle";

fn run(dir: &Path) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_pylae-verify"))
        .arg(dir)
        .output()
        .expect("run pylae-verify");
    (
        out.status.code().expect("exit code"),
        String::from_utf8(out.stdout).expect("utf-8 report"),
    )
}

/// The line under `title`, e.g. `  [FAIL] leaf recomputation …`.
fn line<'a>(report: &'a str, title: &str) -> &'a str {
    report
        .lines()
        .find(|l| l.contains(title))
        .unwrap_or_else(|| panic!("no line containing {title:?} in:\n{report}"))
}

#[test]
fn a_leaf_that_was_not_recomputed_is_not_reported_under_ok() {
    let dir = Copy::of(DEMO, "cli-gap");
    let events = dir.0.join("events.jsonl");
    let kept: String = std::fs::read_to_string(&events)
        .expect("read events.jsonl")
        .lines()
        .filter(|l| {
            let v: serde_json::Value = serde_json::from_str(l).expect("row");
            v["chain_version"] != 64
        })
        .map(|l| format!("{l}\n"))
        .collect();
    std::fs::write(&events, &kept).expect("write events.jsonl");
    dir.refix_manifest("events.jsonl");

    let (code, report) = run(&dir.0);

    assert_eq!(code, 1, "{report}");
    assert!(
        line(&report, "leaf recomputation").contains("[FAIL]"),
        "{report}"
    );
    assert!(
        report.contains("chain_version 65 (event): no predecessor at 64: not recomputed"),
        "{report}"
    );
}

#[test]
fn an_anchor_without_its_row_is_a_note_not_an_ok() {
    // Drop the archived row for the active effective rules, which the chain
    // anchors. The anchor count must not be printed under [ok].
    let dir = Copy::of(DEMO, "cli-anchor");
    let archive = dir.0.join("config_archive.jsonl");
    let kept: String = std::fs::read_to_string(&archive)
        .expect("read config_archive.jsonl")
        .lines()
        .filter(|l| !l.contains("\"kind\":\"effective_rules\""))
        .map(|l| format!("{l}\n"))
        .collect();
    std::fs::write(&archive, &kept).expect("write config_archive.jsonl");
    dir.refix_manifest("config_archive.jsonl");

    let (_, report) = run(&dir.0);

    let anchors = line(&report, "config anchors named by the chain");
    assert!(anchors.contains("[note]"), "{report}");
    assert!(!anchors.contains("[ok]"), "{report}");
    assert!(anchors.contains("1 without a row"), "{report}");
}

// ── The README shows what the binary prints ────────────────────────────────

#[test]
fn the_readme_try_it_output_is_what_the_binary_prints() {
    let shown = readme_output_after("./target/release/pylae-verify tests/fixtures/demo-bundle");

    let (code, report) = run(Path::new(DEMO));

    assert_eq!(code, 0, "{report}");
    let printed: Vec<&str> = report.lines().collect();
    assert_eq!(
        shown, printed,
        "README.md's Try it block is not what the binary prints"
    );
}

#[test]
fn the_readme_tamper_output_is_what_the_binary_prints() {
    // The README's edit: the first `"timestamp":"2026-` in actions.jsonl, the
    // first action's, becomes 2025, and the manifest is left as it was.
    let (from, to) = (r#""timestamp":"2026-"#, r#""timestamp":"2025-"#);
    let dir = Copy::of(DEMO, "cli-readme-tamper");
    let actions = dir.0.join("actions.jsonl");
    let text = std::fs::read_to_string(&actions).expect("read actions.jsonl");
    assert!(text.contains(from), "the README's edit needs {from}");
    std::fs::write(&actions, text.replacen(from, to, 1)).expect("write actions.jsonl");
    let shown = readme_output_after("./target/release/pylae-verify tampered; echo \"exit=$?\"");

    let (code, report) = run(&dir.0);

    // The block elides with `...` and ends with the shell's `exit=N`; every
    // other line it shows must be printed, in the order shown.
    let (exit, lines) = shown.split_last().expect("a non-empty block");
    assert_eq!(*exit, format!("exit={code}"), "{report}");
    let mut printed = report.lines();
    for want in lines.iter().filter(|l| l.trim() != "...") {
        assert!(
            printed.any(|got| got == *want),
            "README line {want:?} is not printed, or not in this order:\n{report}"
        );
    }
}

/// The lines of the first plain fenced block after the README line `command`:
/// the output the README shows for that command.
fn readme_output_after(command: &str) -> Vec<String> {
    let readme = std::fs::read_to_string("README.md").expect("read README.md");
    let mut lines = readme.lines().skip_while(|l| *l != command);
    assert!(
        lines.next().is_some(),
        "README.md no longer shows {command:?}"
    );
    let block: Vec<String> = lines
        .skip_while(|l| *l != "```")
        .skip(1)
        .skip_while(|l| *l != "```")
        .skip(1)
        .take_while(|l| *l != "```")
        .map(str::to_string)
        .collect();
    assert!(!block.is_empty(), "no output block after {command:?}");
    block
}

/// A fixture copy in a temp directory, removed on drop.
struct Copy(PathBuf);

impl Copy {
    fn of(src: &str, tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("pylae-verify-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        for e in std::fs::read_dir(src).expect("read fixture") {
            let e = e.expect("entry");
            std::fs::copy(e.path(), dir.join(e.file_name())).expect("copy");
        }
        Self(dir)
    }

    fn refix_manifest(&self, name: &str) {
        let bytes = std::fs::read(self.0.join(name)).expect("read edited file");
        let path = self.0.join("MANIFEST.json");
        let mut m: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("parse");
        let entry = m["files"]
            .as_array_mut()
            .expect("files")
            .iter_mut()
            .find(|e| e["name"] == name)
            .expect("entry");
        entry["sha256"] = pylae_verify::canonical::sha256_hex(&bytes).into();
        entry["bytes"] = (bytes.len() as u64).into();
        std::fs::write(&path, m.to_string()).expect("write MANIFEST.json");
    }
}

impl Drop for Copy {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
