//! pylae-verify — independent verifier for Pylae audit-evidence bundles.
//!
//! Re-checks a `pylae chain export` bundle using only the published Pylae
//! Evidence Format Specification and standard cryptography — no Pylae source,
//! no private keys. Implements the STRUCTURAL (keyless) verification level;
//! the ATTRIBUTION level is seed-keyed and out of scope by design (spec §8, §10).
//!
//! Exit codes: 0 = structural verification passed; 1 = a discrepancy was found;
//! 2 = usage error or the bundle could not be read.

use std::path::Path;
use std::process::ExitCode;

use pylae_verify::bundle::Bundle;
use pylae_verify::verify::{self, Report};
use pylae_verify::SPEC_VERSION;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let dir = match args.get(1).map(String::as_str) {
        Some("-h" | "--help") | None => {
            usage();
            return ExitCode::from(2);
        }
        Some("--version") => {
            println!(
                "pylae-verify {} (evidence format spec {SPEC_VERSION})",
                env!("CARGO_PKG_VERSION")
            );
            return ExitCode::SUCCESS;
        }
        Some(p) => p,
    };

    let bundle = match Bundle::load(Path::new(dir)) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };

    let report = verify::verify(&bundle);
    print_report(&bundle, &report);

    if report.structural_passed() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn usage() {
    eprintln!("pylae-verify {}", env!("CARGO_PKG_VERSION"));
    eprintln!("Independent structural verifier for Pylae evidence bundles.\n");
    eprintln!("Usage:");
    eprintln!("  pylae-verify <bundle-dir>     verify an exported evidence bundle");
    eprintln!("  pylae-verify --version");
    eprintln!("  pylae-verify --help");
}

fn section(title: &str, problems: &[String]) {
    if problems.is_empty() {
        println!("  [ok]   {title}");
    } else {
        println!("  [FAIL] {title}");
        for p in problems {
            println!("           - {p}");
        }
    }
}

fn print_report(b: &Bundle, r: &Report) {
    println!(
        "pylae-verify {} — structural verification (evidence format spec {SPEC_VERSION})",
        env!("CARGO_PKG_VERSION")
    );
    println!("bundle: {}", b.dir.display());
    if !b.identity.tool_version.is_empty() {
        println!("exported by Pylae {}", b.identity.tool_version);
    }
    println!(
        "leaves: {} (actions {}, erasures {}, events {}) · blocks: {} · snapshots: {} · \
         config artifacts: {}",
        r.leaf_count,
        b.actions.len(),
        b.erasures.len(),
        b.events.len(),
        r.block_count,
        r.snapshot_count,
        b.configs.len(),
    );
    println!("\nLevel 1 — structural (keyless):");

    match &r.genesis_error {
        Some(e) => section("genesis", std::slice::from_ref(e)),
        None => section("genesis", &[]),
    }
    section(
        "bundle manifest (SHA-256 of every file)",
        &r.manifest_problems,
    );
    section("chain linkage (no gaps)", &r.linkage_gaps);
    section(
        "leaf recomputation (all leaves re-hash)",
        &r.leaf_mismatches,
    );
    section(
        "Merkle blocks (roots + actions_count binding)",
        &r.block_problems,
    );
    section(
        "tombstone consistency (GDPR erasure)",
        &r.tombstone_problems,
    );
    section(
        "forensic snapshots (inputs recompute their hash)",
        &r.snapshot_problems,
    );
    section("config anchors (content-addressed)", &r.config_problems);

    if r.config_anchors > 0 {
        println!(
            "  [ok]   config anchors named by the chain: {} (spec §9.2)",
            r.config_anchors
        );
    }
    if !r.config_unresolved.is_empty() {
        println!(
            "  [note] {} config anchor(s) not resolvable (report-only, spec §9.2):",
            r.config_unresolved.len()
        );
        for u in &r.config_unresolved {
            println!("           - {u}");
        }
    }

    println!("\nLevel 2 — attribution (authorship / anti-operator tamper):");
    println!(
        "  [skip] requires the per-deployment seed; not verifiable by a third party (spec §8, §10)"
    );

    println!();
    if r.structural_passed() {
        println!(
            "RESULT: OK — structural integrity verified ({} leaves, {} blocks).",
            r.leaf_count, r.block_count
        );
    } else {
        let issues = r.manifest_problems.len()
            + r.linkage_gaps.len()
            + r.leaf_mismatches.len()
            + r.block_problems.len()
            + r.tombstone_problems.len()
            + r.snapshot_problems.len()
            + r.config_problems.len()
            + usize::from(r.genesis_error.is_some());
        println!("RESULT: FAILED — {issues} discrepancy(ies) found. This bundle is not intact.");
    }
}
