# pylae-verify

**Independent, open-source verifier for [Pylae](https://pylae.net) audit-evidence bundles.**

Pylae is a self-hosted, closed-source governance proxy for MCP/AI agents. Its value is
*verifiable* compliance evidence — and this is the tool that verifies it. `pylae-verify`
re-checks a Pylae evidence bundle using **only cryptography and a published specification**:
no Pylae source code, no running Pylae binary, and no private keys.

If you can run this and it prints `OK`, you don't have to take Pylae's word for the integrity
of its audit chain — you've checked it yourself.

> **Status: v0.1 — working.** The structural verification pipeline is implemented and tested
> end to end against real `pylae chain export` bundles: a genuine 82-leaf / 3-block bundle
> verifies, and a tampered copy is rejected (the chain catches an altered field even after its
> MANIFEST is re-fixed). Signed release binaries are not published yet — build from source below.

---

## What it verifies

`pylae-verify` implements the **structural** verification level — everything that is checkable
**without any secret key**, from a standalone `pylae chain export` bundle:

- **Bundle integrity** — recomputes the SHA-256 of every file against `MANIFEST.json`.
- **Hash-linked chain** — recomputes each leaf hash (action, erasure, event, response) from its
  canonical preimage and checks that every `prev_hash` links to its predecessor, back to the
  deployment genesis.
- **Merkle blocks** — recomputes each sealed block's Merkle root and the `actions_count`-bound
  block root.
- **Content-addressed config** — confirms every configuration the chain anchors re-hashes to its
  own address.
- **Tombstone consistency** — confirms GDPR erasures keep the chain recomputable and flags
  out-of-band deletions or forged tombstones.

## What it does NOT do (by design)

Proving *authorship* / anti-operator tamper is keyed to a per-deployment secret and **cannot** be
done by a third party without that secret. `pylae-verify` verifies **structural integrity** and
reports the **attribution** level as *skipped* — it never claims a guarantee it cannot make. See
the specification, §8 and §10.

## How it works

`pylae-verify` is a **clean-room implementation of the published Pylae Evidence Format
Specification** — it shares no source with the Pylae product and depends only on widely-audited,
standard cryptography. The specification is the contract; anyone can re-implement a verifier from
it. That is the point: trust rests on open cryptography and an open format, not on this binary
either.

- Specification: [`EVIDENCE-FORMAT.md`](https://github.com/pylaelabs/pylae/blob/main/docs/EVIDENCE-FORMAT.md)
- Cryptography: SHA-256 (`sha2`), plus `serde_json` for reading the bundle. That's it.

## Install

```bash
# From source (requires a recent Rust toolchain):
cargo install --path .
# or
cargo build --release   # → target/release/pylae-verify
```

Signed release binaries will be published on the [releases page](https://github.com/pylaelabs/pylae-verify/releases).

## Usage

```bash
# 1. Export an evidence bundle from your Pylae instance:
pylae chain export ./evidence

# 2. Verify it — no keys, no Pylae binary needed:
pylae-verify ./evidence
```

A successful structural verification exits `0`; any linkage, leaf, Merkle, block-count,
tombstone, or manifest mismatch exits non-zero and names the discrepancy.

## License

Apache License 2.0. See [`LICENSE`](./LICENSE).

The Pylae product binary is proprietary and licensed separately; `pylae-verify` and the evidence
format are open so the *evidence* can be trusted independently of the product.
