# Pylae audit-chain evidence bundle

## Contents

- Sealed blocks: 3
- Action leaves: 50
- Event leaves: 19
- Erasure leaves: 13
- Archived configuration artifacts: 3
- Last sealed chain version: 82
- Stamped-but-unsealed leaves (included, flagged): 0

Erased actions appear as their tombstones; original payloads are not part of this bundle and cannot be reconstructed from it.
If a daemon was running during the export, the bundle reflects the committed snapshot the reader observed and may lag the live head by in-flight writes.

## Level 1 — Structural verification (keyless)

SHA-256 linkage recomputed across the exported window.

- Verifiable: true
- Recomputation passed: true
- Gaps: 0
- Coverage: 100.00%

## Level 2 — Signature attribution

Signing seed derivable in this environment; leaves verified under the deployment's identity regime(s).

- Attributed fingerprint: de1c89c66e197d0e21810e6ce7a9cb58a893f226af4da7a56c7f3a16ca448ff2
- Chain intact: true
- Invalid signatures: 0
- Gaps: 0

## Config resolution (report-only)

The following anchored hashes did not resolve to archived content. This does not invalidate the chain; it limits configuration reproducibility for the affected window.

- active manifest: archived manifest payload does not re-hash to its key (expected b8b7a3b6f99d3add4a2190443ee06d8df34f0d7c4271b2ac76a3e31f4c832299, got 39420b7cacab17a40b51f7600c911f140de3b4933cfcbcc1f4809f8cd6b01a7d)
- pin rules_version test-rules-v1: anchored hash test-rules-v1 does not resolve in config_archive (expected on databases predating the archive; re-publish or reboot archives the current configuration)
