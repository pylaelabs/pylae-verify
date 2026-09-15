# Pylae audit-chain evidence bundle

## Contents

- Sealed blocks: 1
- Action leaves: 2
- Forensic snapshots (the inputs of snapshot_hash, §2.2): 2
- Event leaves: 2
- Erasure leaves: 0
- Archived configuration artifacts: 4
- Last sealed chain version: 4
- Stamped-but-unsealed leaves (included, flagged): 1

Erased actions appear as their tombstones; original payloads are not part of this bundle and cannot be reconstructed from it.
If a daemon was running during the export, the bundle reflects the committed snapshot the reader observed and may lag the live head by in-flight writes.

## Level 1 — Structural verification (keyless)

SHA-256 linkage recomputed across the exported window.

- Verifiable: true
- Recomputation passed: true
- Gaps: 0
- Coverage: 100.00%

## Level 2 — Signature attribution

NOT VERIFIED HERE: the signing seed is not derivable in this environment (the deployment's host_secret is required and was not readable). The structural level above still guarantees linkage integrity; signature attribution can be performed in the deployment environment or by a party holding the deployment's key material.

## Config resolution

Every anchored configuration hash (active manifest, effective rules, pin fingerprints) resolves to archived content that re-derives its own address.
