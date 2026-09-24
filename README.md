# pylae-verify

**Check a [Pylae](https://pylae.net) evidence bundle yourself, without a Pylae account, key
or binary.**

Pylae is a closed-source governance proxy for MCP/AI agents. Its audit evidence is exported
as a bundle (`pylae chain export`). `pylae-verify` re-checks that bundle using the published
[evidence format specification](./docs/EVIDENCE-FORMAT.md) and SHA-256, and tells you what
it could and could not establish. It is written for auditors, DPOs and security reviewers,
and is Apache-2.0.

## Try it

```bash
cargo build --release
./target/release/pylae-verify tests/fixtures/demo-bundle
```

```
pylae-verify 0.1.0 — structural verification (evidence format spec 0.1)
bundle: tests/fixtures/demo-bundle
exported by Pylae 0.2.0
leaves: 65 (actions 50, erasures 13, events 2) · blocks: 2 · snapshots: 0 · config artifacts: 4

Level 1 — structural (keyless):
  [ok]   genesis
  [ok]   bundle manifest (SHA-256 of every file)
  [ok]   chain linkage (no gaps)
  [ok]   leaf recomputation (all leaves re-hash)
  [ok]   Merkle blocks (roots + actions_count binding)
  [ok]   tombstone consistency (GDPR erasure)
  [ok]   forensic snapshots (inputs recompute their hash)
  [ok]   config anchors (content-addressed)
  [ok]   config anchors named by the chain: 2 (spec §9.2)

Level 2 — attribution (authorship / anti-operator tamper):
  [skip] requires the per-deployment seed; not verifiable by a third party (spec §8, §10)

RESULT: OK — structural integrity verified (65 leaves, 2 blocks).
```

Now change one byte. The first action read `file:///data/report_8.csv`, and this edit
makes it `report_9.csv`:

```bash
cp -r tests/fixtures/demo-bundle tampered
sed -i '0,/report_8\.csv/s//report_9.csv/' tampered/actions.jsonl   # macOS: use gsed
./target/release/pylae-verify tampered; echo "exit=$?"
```

```
Level 1 — structural (keyless):
  [ok]   genesis
  [FAIL] bundle manifest (SHA-256 of every file)
           - actions.jsonl: sha256 mismatch
  [ok]   chain linkage (no gaps)
  [FAIL] leaf recomputation (all leaves re-hash)
           - chain_version 1 (action): recomputed hash != stored
  [ok]   Merkle blocks (roots + actions_count binding)
  ...
RESULT: FAILED — 2 discrepancy(ies) found. This bundle is not intact.
exit=1
```

Two checks fail, and each does so on its own:

- **Manifest.** The file no longer matches the SHA-256 that `MANIFEST.json` lists for it.
- **Leaf recomputation.** The action's leaf hash is recomputed from its contents and no
  longer matches the stored `chain_hash`.

Someone who edits a row usually rewrites `MANIFEST.json` too. When they do, the leaf check
still fails. The test `tampering_an_action_is_caught_by_leaf_recomputation` in
[`tests/integration.rs`](./tests/integration.rs) does exactly that. The Merkle blocks stay
`[ok]` because blocks fold the stored leaf hashes (spec §7), and this edit changed the row,
not its stored hash.

## What each check establishes, and what it does not

Everything below is **Level 1, structural**: it needs no key, so any reader of the bundle
can run it (spec §10).

| Check | Establishes | Does not establish |
|---|---|---|
| **Bundle manifest** (§9.1) | every file matches the SHA-256 and size in `MANIFEST.json` | anything, if the editor also rewrote the manifest. The manifest is not signed. |
| **Genesis** (§4) | the chain starts at the genesis hash of the deployment fingerprint in `identity.json` | that `identity.json` names the deployment you think it does |
| **Chain linkage** (§5) | each leaf's predecessor is the leaf before it, back to genesis, with no missing slot | that the whole chain was not rebuilt from scratch. Every hash here is keyless, so anyone who can rewrite the rows can recompute all of them. |
| **Leaf recomputation** (§5) | every action, erasure, event and response leaf re-hashes from its row | the truth of what a row records. A leaf commits to the row as written. |
| **Merkle blocks** (§7) | each sealed block's root recomputes from its leaves and is bound to `actions_count`; blocks link to each other | that the blocks match any copy you received earlier. This tool does not compare against one. |
| **Tombstones** (§6) | each GDPR erasure's `tombstone_hash` recomputes and matches the `redacted_marker_hash` on the action it erased; an erased action without that marker is reported | the erased content. It is gone by design, and only its hash commitment remains. The check runs from each erasure to its action, not the other way round. |
| **Forensic snapshots** (§2.2, §9) | each `snapshot_hash` recomputes from the six inputs the bundle ships | that the inputs were right when they were captured. The action leaf commits to the snapshot's *hash*, so an edited input is invisible to the leaf check. The test `editing_a_snapshot_input_is_caught_only_by_the_snapshot_recompute` shows that this check catches it. |
| **Config anchors** (§9.2) | every archived config (effective rules, CVE feed, rule manifest as payload or JWS) re-hashes to its own address, and the anchors come from a signed `compliance.config_active` leaf in the chain, so a dropped archive row is reported | completeness. An anchored hash with no row is reported as a note, not a failure (spec §9.2). Tool pins are not exported, so their anchors cannot be checked at all. |

## What it does not do

- **Level 2, attribution: skipped.** Authorship and protection against tampering by the
  operator are keyed to a per-deployment seed (spec §8). A keyless verifier reports this
  level as skipped and never as passed (spec §10). On the Free tier the seed can be derived
  from the `instance_id` in the bundle itself, so even with the seed, this layer
  establishes integrity, not authenticity (spec §8).
- **It does not re-derive decisions.** An action row records its `decision` and a
  `policy_id`, but the bundle does not archive policy content: the `config_archive` kinds
  are `effective_rules`, `cve_feed` and `manifest` (spec §9.2). This tool can confirm that
  the recorded decision was not altered after the fact. It cannot confirm the decision was
  the right one under the policy in force.
- **It does not judge the bundle as a whole** beyond the checks above. `REPORT.md` inside
  a bundle is the producer's statement. This tool verifies its bytes against the manifest
  but does not read its claims.

## Install

From source, with a recent Rust toolchain:

```bash
cargo install --path .
```

### Verify a release binary

Release archives are built and signed by [`.github/workflows/release.yml`](./.github/workflows/release.yml)
with [cosign](https://docs.sigstore.dev/) keyless signing. **No release has been tagged
yet.** Until one is, build from source.

Each archive ships with a `.sigstore.json` bundle. To check one:

```bash
cosign verify-blob \
  --bundle pylae-verify-v0.1.0-x86_64-unknown-linux-musl.tar.gz.sigstore.json \
  --certificate-identity "https://github.com/pylaelabs/pylae-verify/.github/workflows/release.yml@refs/tags/v0.1.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  pylae-verify-v0.1.0-x86_64-unknown-linux-musl.tar.gz
```

This establishes that the archive was produced by that workflow file, run from that tag of
this repository. It does not establish that the workflow is correct. For that, read it, or
build from source at the same tag.

## Usage

```bash
pylae chain export ./evidence     # on the Pylae host
pylae-verify ./evidence           # anywhere
```

| Exit code | Meaning |
|---|---|
| `0` | structural verification passed |
| `1` | a discrepancy was found; the report names it |
| `2` | usage error, or the bundle could not be read |

Scripts should read the exit code. The report text is not a stable interface.

## Specification and versioning

[`docs/EVIDENCE-FORMAT.md`](./docs/EVIDENCE-FORMAT.md) is the contract. It is currently
**version 0.1, draft**. `pylae-verify --version` prints the spec version this build
implements. [`tests/spec.rs`](./tests/spec.rs) fails if that version differs from the
document's header, and it recomputes the §2.3 conformance vector from the document text.
Spec §11 states that an implementation which cannot reproduce §2.3 is not conformant.

How the spec, the constructions and this tool are versioned, and what this build does with
input from a newer format, is in [`VERSIONING.md`](./VERSIONING.md).

The spec is meant for anyone who wants to write another verifier. This one depends on
`sha2`, `serde`, `serde_json` and `hex` ([`Cargo.toml`](./Cargo.toml)) and on no Pylae crate.

## Test fixtures

Both bundles under `tests/fixtures/` are real exports, regenerated from the producer's tree:

```bash
# in the Pylae core repo
PYLAE_FIXTURE_OUT=<empty-dir> cargo test --bin pylae emit_demo_fixture        -- --ignored
PYLAE_FIXTURE_OUT=<empty-dir> cargo test --bin pylae emit_conformance_fixture -- --ignored
```

`demo-bundle` covers breadth: 50 action leaves, 13 erasures, a signed event leaf and sealed
blocks. `conformance-bundle` covers the shapes a demo run never produces: a truncated request
payload, a captured response leaf, a forensic snapshot with its inputs, and all four
content-addressed referents. Each generator asserts the shapes it exists to provide, so a
fixture that stops carrying one fails when it is generated instead of silently making a
test vacuous.

## License

Apache License 2.0. See [`LICENSE`](./LICENSE). The Pylae product is proprietary and
licensed separately. The verifier and the evidence format are open.
