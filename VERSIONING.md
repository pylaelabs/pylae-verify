# Versioning

Three things carry a version, and they move independently.

| What | Where it is written | Current |
|---|---|---|
| The evidence format specification | header of [`docs/EVIDENCE-FORMAT.md`](./docs/EVIDENCE-FORMAT.md) | 0.1 (draft) |
| Each cryptographic construction | its domain separator, spec §3 (`pylae:chain_hash:v4`, `pylae:genesis:v2`, …) | per construction |
| This tool | `Cargo.toml`, printed by `pylae-verify --version` | 0.1.0 |

`pylae-verify --version` prints the tool version and the spec version it implements. A
test (`tests/spec.rs`) reads the header of the vendored spec and fails if the two disagree,
and reproduces the §2.3 conformance vector from the document text rather than from a copy.

## What a bundle does and does not say about its format

A bundle carries **no format-version field**. `identity.json` and `MANIFEST.json` carry
`tool_version`, which is the version of the Pylae product that exported it, not the version
of this specification. Per spec §11, a verifier selects each construction by the persisted
version or kind, never by guessing.

What this build does with input it was not written for:

| Input | Behaviour | Source |
|---|---|---|
| A field it does not know, on any line | ignored | spec §9 |
| An `event_type` whose payload it does not interpret | hashed as part of the leaf, not interpreted | spec §9, `events.jsonl` |
| A `config_archive.jsonl` row of unknown `kind` | reported as a note (`unknown config kind`), not a failure | `src/verify.rs` |
| A leaf produced under a domain separator other than the one in §3 | leaf recomputation fails; the bundle is reported **not intact** | spec §11 |

The last row is a limit of the current format: this verifier cannot tell a leaf built with a
newer construction from a tampered one. Both fail.

## The policy

**Specification.** `MAJOR.MINOR`.

- While the major version is `0` the document is a draft (its header says so) and any
  release may change anything.
- From `1.0`:
  - **Minor** — a change that alters no preimage, no domain separator and no canonical
    encoding, and that a verifier of the same major version can meet without misreporting.
    This covers clarifications of which stored value feeds an unchanged construction (spec
    §9, the `params_hash` rule, is an example), new event types, new optional fields, and new
    `config_archive` kinds (an older verifier reports them as notes; see the table above).
  - **Major** — any change to a preimage, a domain separator, the canonical encodings (§2),
    the Merkle construction (§7), or a field becoming required. Spec §11 already requires
    the affected separator to be bumped in the same change.
- The conformance vectors (§2.3, §11.1) are normative. A change that alters them is a
  change to the construction.

**Tool.** Semantic versioning over these interfaces:

- the exit codes: `0` structural verification passed, `1` a discrepancy was found, `2`
  usage error or unreadable bundle;
- the spec versions it implements.

The human-readable report text is **not** a stable interface; scripts should read the exit
code.

- **Patch** — fixes that change no verdict on a conformant bundle.
- **Minor** — support for a new minor spec version, or new checks that report notes only.
- **Major** — dropping support for any spec version or construction version, or a change to
  the exit codes.

**Old evidence.** Once a release verifies a construction version, later releases of the
same tool major version keep verifying it. Evidence exported years ago must still be
checkable with a current binary.

## Where the spec comes from

`docs/EVIDENCE-FORMAT.md` is published here, next to the code that implements it.
The Pylae product team writes it. A change to it lands in this repository as its own commit,
together with the code and tests that implement the change, so the spec version and the
verifier version move in the same commit.
