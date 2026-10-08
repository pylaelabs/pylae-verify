# Pylae audit-chain evidence bundle

## Contents

- Sealed blocks: 2
- Action leaves: 50
- Forensic snapshots (the inputs of snapshot_hash, §2.2): 0
- Event leaves: 2
- Erasure leaves: 13
- Archived configuration artifacts: 4
- Last sealed chain version: 50
- Stamped-but-unsealed leaves (included, flagged): 15
- Records outside the chain (in this database, not in this bundle): events 0, responses 0. They hold no chain slot — events written while the chain could not stamp them, responses recorded without a response leaf — so neither level below checks them, and deleting one leaves no trace: this is a lower bound.

Erased actions appear as their tombstones; original payloads are not part of this bundle and cannot be reconstructed from it.
If a daemon was running during the export, the bundle reflects the committed snapshot the reader observed and may lag the live head by in-flight writes.

## Level 1 — Structural verification (keyless)

SHA-256 linkage recomputed across the exported window, every sealed block's Merkle root recomputed from its leaves, and the tombstone rule applied.

- Verifiable: true
- Recomputation passed: true
- Gaps: 0
- Coverage: 100.00%
- Block roots recomputed and matching: 2
- Blocks whose root does not match: none
- Blocks whose root matches but which report a slot without a leaf or a duplicate: none
- Blocks that could not be read to recompute: none
- Tombstone rule: held

## Level 2 — Signature attribution

NOT VERIFIED HERE: the signing seed is not derivable in this environment (the deployment's host_secret is required and was not readable). The structural level above still guarantees linkage integrity; signature attribution can be performed in the deployment environment or by a party holding the deployment's key material.

## Config resolution

The following anchored hashes resolve to no row. This does not invalidate the chain; it limits configuration reproducibility for the affected window.

- pin rules_version test-rules-v1: anchored hash test-rules-v1 does not resolve in config_archive (expected on databases predating the archive; re-publish or reboot archives the current configuration)
