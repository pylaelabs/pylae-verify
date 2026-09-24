# Pylae Evidence Format Specification

*Version 0.1 (draft) · derived from the reference implementation at product version 0.2.0 · status: DRAFT, subject to change before the `pylae-verify` public release.*

This document specifies the on-disk format and cryptographic construction of a Pylae
**evidence bundle** — the output of `pylae chain export` — in enough detail for an
independent implementation (`pylae-verify`, Apache-2.0) to re-check it **without access to
the Pylae source code and without any secret key**.

It is the contract that makes Pylae's "closed core, open verification" model real: trust in
the evidence rests on the public constructions below, not on the closed binary.

> **Scope of independent verification.** Everything a third party can verify **keyless** is
> specified normatively in §2–§7 (the *structural* layer). The *attribution* layer (§8) is
> keyed to a per-deployment secret and is **not** independently verifiable by a third party;
> it is described but not offered as a third-party guarantee. See §8 and §10.

---

## 1. Primitives and notation

- **Hash:** SHA-256. `H(x)` denotes the 32-byte SHA-256 digest of byte string `x`.
- **Hex:** lowercase, unpadded. A "hash string" is the 64-character lowercase hex of a
  32-byte digest. `hex(b)` = lowercase hex of bytes `b`; `unhex(s)` its inverse.
- **Integers in preimages:** fixed-width **little-endian**. `u32le(n)`, `i64le(n)`,
  `u64le(n)` denote the 4- or 8-byte little-endian encodings. `bool` encodes as a single
  byte `0x00` / `0x01`.
- **`||`** is byte concatenation. **ASCII string literals** in preimages (e.g.
  `"pylae:chain_hash:v4"`) are their raw UTF-8 bytes with **no** length prefix and **no**
  terminator.
- All timestamps are RFC 3339 / ISO 8601 UTC strings and enter preimages as strings (§2).

---

## 2. Canonical encoding

Every variable-length value that enters a preimage is encoded with a single length-prefixed
binary scheme (never via a JSON serializer's text form). Two helpers:

```
write_str(s)      := u32le(len(utf8(s))) || utf8(s)
write_opt_str(o)  := 0x00                      if o is None
                     0x01 || write_str(s)       if o is Some(s)
```

`write_opt_str` distinguishes `None` (`0x00`) from `Some("")` (`0x01 || u32le(0)`).

### 2.1 Canonical JSON-value encoding — `write_value`

Used for structured fields (request params, security posture, cost ceiling, damage
estimate, config archive content). Recursively:

| Value | Encoding |
|---|---|
| null | `0x60` |
| false | `0x50` |
| true | `0x51` |
| string `s` | `0x30 \|\| write_str(s)` |
| number, **integer token**, fits `i64` | `0x41 \|\| i64le(n)` |
| number, **integer token**, fits `u64` (not `i64`) | `0x42 \|\| u64le(n)` |
| number, anything else | `0x43 \|\| f64le(n)` (IEEE-754 little-endian) |
| array `[v0..]` | `0x20 \|\| u32le(count) \|\| write_value(v0) \|\| …` |
| object | `0x10 \|\| u32le(count) \|\| (write_str(key) \|\| write_value(val))*` with **keys sorted** ascending by Unicode code point |

**The tag follows the JSON token, not the value**, and this is the single portability trap
in this section. `1` and `1.0` are different numbers here: the first encodes
`0x41 || i64le(1)`, the second `0x43 || f64le(1.0)`, and they hash differently. A number
written with a fraction or an exponent is a float token whatever its value — `1.0` is a
float token, not an integer that happens to have a fraction.

The three rows are tried **in order**, and the third is a genuine fallback rather than "the
float case": an *integer* token too large for `u64` does not fit either of the first two and
so takes `0x43` as well, encoded as the nearest double.

| token in the document | tag |
|---|---|
| `1` | `0x41` |
| `18446744073709551615` (fits `u64`, not `i64`) | `0x42` |
| `99999999999999999999` (integer token, exceeds `u64`) | `0x43` |
| `1.0` | `0x43` |

A verifier therefore MUST read the bundle with a parser that keeps integer and float
tokens apart, or take the token from the text itself. Several common ones do not: JavaScript's
`JSON.parse` and Go's `encoding/json` into `interface{}` both collapse `1` and `1.0` to one
double. §2.3 publishes a vector that fails immediately on such a reader rather than at a
customer's bundle, and §11 makes it a conformance requirement.

Object keys are always sorted; arrays preserve order.

### 2.2 Derived hashes

- **`canonical_value_hash(v)`** := `hex(H(write_value(v)))`.
- **`canonical_json(v)`** — a *textual* canonical form, used only by the manifest hash
  (§9.2). It is **not** `write_value`: that one is binary and type-tagged, this one is JSON
  text. Both exist because the manifest hash is computed over a JSON document the publisher
  signed, and its preimage has to stay JSON.

  ```
  object  → "{" || ( canonical_json_string(key) || ":" || canonical_json(val) ) joined by ","  || "}"
              with keys sorted ascending by Unicode code point
  array   → "[" || canonical_json(v0) || "," || ... || "]"          order preserved
  string  → canonical_json_string(s)   — RFC 8259 §7 escaping, shortest form:
              only `"` `\` and U+0000–U+001F are escaped; `\b \f \n \r \t` use their
              two-character forms, every other control character uses `\u00XX` lowercase hex
  bool    → "true" | "false"
  null    → "null"
  number  → integer token → its exact decimal digits, no sign for zero, no fraction,
              no exponent;
            float token   → the **shortest decimal string that round-trips** to the same
              IEEE-754 double, **with a `.0` suffix when the value is integral**,
              and no exponent — see the bound below
  ```

  No whitespace anywhere. The branch is chosen by the token, exactly as in §2.1 — an
  integral float is a **float token**, so it keeps its fraction. **This is the rule a
  verifier is most likely to get wrong**: `min_chain_coverage` is a float token whose value
  is 99, and it serializes `99.0`, not `99`. A JavaScript verifier using `String(n)`
  produces `99` and will compute a different manifest hash for every bundle; Python's `repr`
  happens to agree. §2.3 publishes the vector.

  **Bound (normative).** The decimal-without-exponent form does not exist for every double:
  past a magnitude the shortest round-tripping form switches to exponential notation, and
  where it switches is a property of the producer's formatter rather than of this format. So
  the rule above is not extended to cover it. Instead: **a manifest payload MUST NOT carry a
  number whose shortest round-tripping form requires an exponent.** Every float the payload
  carries today is a small ratio or percentage (`min_chain_coverage`, the rubric bands), and
  a verifier that encounters an exponent in a canonical form MUST report the row unresolved
  rather than guess a form. This bounds the construction instead of specifying something a
  third party could not reproduce; `canonical_json` is used only here (§9.2), so the bound
  costs nothing elsewhere.
- **`params_hash(params)`** := `""` (the empty string) when `params` is absent; otherwise
  `canonical_value_hash(params)`. The empty-string sentinel is unambiguous because
  `params_hash` is itself length-prefixed wherever it is consumed.
- **`snapshot_hash`** commits the contemporaneous forensic snapshot. Preimage (fixed field
  order — reordering re-keys every leaf):
  ```
  "pylae:snapshot_hash:v1"
    || write_value(security_posture)
    || write_value(cost_ceiling)
    || write_opt_str(agent_profile_id)
    || u32le(count(active_policy_ids)) || write_str(id)*     // in stored order
    || write_opt_str(active_contract_id)
    || write_value(damage_estimate)
  ```
  `snapshot_hash` := `hex(H(preimage))`.

  **The inputs travel in the bundle (`snapshots.jsonl`, §9), and a verifier MUST recompute
  from them.** Comparing the result against the `snapshot_hash` in `actions.jsonl` is the
  only check that sees a snapshot altered after the fact: the action leaf commits to the
  *hash*, so a producer-side change to an input that leaves the hash alone recomputes clean
  at every other level. A verifier that carries the file and never recomputes it reports a
  bundle as intact on the strength of a commitment it did not check — a mismatch here is a
  Level 1 failure, like any other recomputation that does not reproduce.

### 2.3 Conformance vector — canonical encoding

Both encoders over one object carrying both number tokens. **These values are normative.**

```
input            {"float":1.0,"int":1}

write_value      100200000005000000666c6f617443000000000000f03f03000000696e74410100000000000000
  hex(H(...))    de789bfc10c30559c6087d3df7dbb5bc7eee0f3401d46576fce25ab66b09b55d

canonical_json   {"float":1.0,"int":1}
  hex(H(...))    049a286599a6c0887e4bce2e4505ab4cee4faff27488688ebba3dfa0f8addb69
```

Read the binary form against §2.1: `10` opens the object, `02000000` counts its two
members, and the keys appear **sorted** (`float` before `int`). Then `float` takes
`43` + `000000000000f03f` — the IEEE-754 bytes of 1.0 — while `int` takes `41` +
`0100000000000000`. **The two members hold the same numeric value and encode differently.**

An implementation whose JSON reader collapses the two tokens cannot produce either line: it
sees one object with two equal numbers, and emits either two `41`s or two `43`s. That is the
point of pairing them — the failure lands here, on a published vector, instead of on a
bundle whose agent happened to send `1.0`.

---

## 3. Domain separators

All ASCII, raw bytes, no length prefix. Changing any string re-keys every artifact under it.

| Constant | Value |
|---|---|
| Action/erasure leaf | `pylae:chain_hash:v4` |
| Genesis | `pylae:genesis:v2` |
| Tombstone | `pylae:tombstone:v1` |
| Event leaf | `pylae:event_chain_hash:v1` |
| Response leaf | `pylae:response_chain_hash:v1` |
| Snapshot | `pylae:snapshot_hash:v1` |
| Event HMAC key (HKDF info) — *attribution* | `pylae:event_hmac:v1` |
| Event HMAC preimage — *attribution* | `pylae:event_preimage:v1` |
| Event UID — *attribution* | `pylae:event_uid:v1` |
| Deployment Ed25519 key (HKDF info) — *attribution* | `pylae:deployment_sign:v1` |
| Seed (HKDF **salt**, not info) — *attribution* | `pylae:seed:v1` |
| WAL-intent row MAC — *attribution* | `pylae:wal_intent:v1` |

**Leaf-kind bytes** (second byte of every chain-leaf preimage):

| Kind | Byte |
|---|---|
| Action | `0x00` |
| Erasure | `0x02` |
| Event | `0x03` |
| Response | `0x04` |

**Merkle domain bytes:** leaf `0x00`, internal `0x01`.

---

## 4. Genesis

The chain's first predecessor hash binds it to the deployment fingerprint:

```
genesis      := H( "pylae:genesis:v2" || fingerprint_bytes )
genesis_hash := hex(genesis)
```

`fingerprint_bytes` are the deployment fingerprint's raw bytes (derived from `instance_id`
and, on Pro, the host secret). The bundle records the fingerprint in `identity.json`
(`stored_seed_fingerprint`). A chain whose first leaf's `prev_hash` is not this deployment's
`genesis_hash` is from a different deployment and MUST NOT validate here.

---

## 5. Chain leaves

Each recorded row is a **leaf** with a `chain_version` (monotonic position), a `prev_version`
(by construction `chain_version - 1`), and a `prev_hash` (the predecessor leaf's hash string,
or `genesis_hash` for the first). `prev_hash`, `params_hash`, `snapshot_hash`, and all other
hash-valued fields enter preimages as their **hex strings** via `write_str`.

Every leaf hash := `hex(H(preimage))`. The four preimages:

### 5.1 Action leaf (`0x00`)
```
"pylae:chain_hash:v4" || 0x00
  || i64le(chain_version) || i64le(prev_version) || write_str(prev_hash)
  || write_str(agent_id) || write_str(method) || write_opt_str(tool_name)
  || write_str(params_hash) || write_str(decision) || write_opt_str(decision_source)
  || write_opt_str(policy_id) || write_str(server_id) || write_str(timestamp)
  || write_str(snapshot_hash)
  || bool(request_params_truncated) || i64le(request_params_original_size)
```

`params_hash` here always commits the params **as they arrived**, before the producer
applied any truncation — `request_params_truncated` and `request_params_original_size`
record that truncation happened without changing what was committed. §9 gives the
normative rule for recovering that value from a bundle.

### 5.2 Erasure leaf (`0x02`)
```
"pylae:chain_hash:v4" || 0x02
  || i64le(chain_version) || i64le(prev_version) || write_str(prev_hash)
  || write_str(target_action_id) || write_str(actor) || write_str(reason)
  || write_str(timestamp) || write_str(tombstone_hash)
```

### 5.3 Event leaf (`0x03`)
```
"pylae:event_chain_hash:v1" || 0x03
  || i64le(chain_version) || i64le(prev_version) || write_str(prev_hash)
  || write_str(event_uid) || write_str(event_type) || write_str(timestamp)
  || write_str(details_canonical_hash)
```
`details_canonical_hash` = `hex(H(write_value(details)))`. `event_uid` is defined in §8; a
keyless verifier treats it as an opaque string it reads off the row (the leaf hash still
binds it structurally).

### 5.4 Response leaf (`0x04`)
```
"pylae:response_chain_hash:v1" || 0x04
  || i64le(chain_version) || i64le(prev_version) || write_str(prev_hash)
  || write_str(action_id) || write_str(response_raw_hash)
  || bool(response_truncated) || i64le(response_original_size) || write_str(timestamp)
```

The verifier selects the preimage by the leaf's **persisted kind**, never by heuristic. The
distinct domain separator + kind byte make a forged payload of one kind unable to collide
with another.

---

## 6. Tombstones (GDPR erasure)

Erasure redacts an action's params in place while keeping the chain recomputable. The
redaction is closed by a tombstone:

```
tombstone_hash := hex(H(
    "pylae:tombstone:v1"
      || write_str(action_id) || write_str(redacted_at) || write_str(actor)
      || write_str(reason) || write_str(original_params_hash) ))
```

`tombstone_hash` is stored in **two** places: the action row (`redacted_marker_hash`) and
the matching erasure event (`tombstone_hash`), and is folded into the erasure leaf (§5.2).

**What the redaction clears, and what it cannot (normative).** The redaction nulls
`request_params`, `response_summary`, `evaluation_trace`, `pii_detected`, `metadata`,
`resource_uri`, `prompt_name` and `security_flags`, and sets the four `redacted_*` marker
fields in the same transaction. A row carrying one set without the other is a partial
erasure and MUST be surfaced.

The boundary is not a policy choice: **a field committed by the action leaf preimage (§5.1)
cannot be cleared without making that leaf unrecomputable.** Every field §5.1 folds is
therefore retained by construction, and a conforming producer MUST NOT null one. The list
is §5.1's and is not repeated here: an enumeration copied into this section is an
enumeration that can fall behind the preimage, and a verifier reading a short copy would
report a committed field as one the redaction merely chose to keep. Of what §5.1 folds,
`params_hash` is derived (§9) and `prev_hash`, `prev_version` and `snapshot_hash` are not
columns of the action row; the rest — `chain_version`, `agent_id`, `method`, `tool_name`,
`decision`, `decision_source`, `policy_id`, `server_id`, `timestamp`,
`request_params_truncated` and `request_params_original_size` — are the columns an erasure
cannot touch. A deployment that needs one of those fields to be erasable has to stop
committing it in the preimage — a domain-separator version bump under §11, not an erasure
change. Producers MUST NOT write a value into a committed field that they also expose in an
erasable one: the erasable copy is cleared, the committed copy is not, and the tombstone
then attests a destruction that did not happen.

**How an erased row reads (normative).** The columns §5.1 commits are kept by construction;
every other column the row still carries is kept only because the redaction does not name
it, and a verifier MUST NOT report the two alike. What the redaction destroys is the evaluation's
inputs and its trace — the columns listed above — and not the coarse grounds of the call:
`decision_source` names which control decided (a policy, a contract, the cost ceiling, the
blast-radius scorer, the security posture), `policy_id` names the rule that matched when one
did, and the bundle ships no rule catalogue, so that identifier names a rule without
disclosing it. An erased action that carried a forensic snapshot still ships it in
`snapshots.jsonl` (§9), `damage_estimate` included. A verifier that renders an erased action
MUST mark it as erased — the row carries `redacted_marker_hash` (§9) and its tombstone
resolves under the rule below — and MUST NOT present what the row still carries as content
the erasure left standing: it is the fact of a decision and the coarse grounds of it, not a
finding about the subject, and a verifier's report that presents it as the latter overstates
what the evidence holds.

**Resolution rule (normative).** When recomputing an *erased* action's leaf, the verifier
recomputes `tombstone_hash` from the erasure event's own fields and:

- **Verified** — recompute equals BOTH stored copies. The erasure is legitimate.
- **Inconsistent** — recompute disagrees with either copy. MUST be surfaced.
- **NotErased** — no marker / no matching event → ordinary path.

The verdict is an integrity signal about the erasure record itself and MUST be reported on
its own terms. Which stored value supplies the action's `params_hash` is a **separate**
decision, governed by §9. A verifier that has the raw commitment therefore still recomputes
an erased leaf correctly while reporting `Inconsistent`; the two signals are independent,
and conflating them would report a tampered tombstone as generic chain damage.

This is how an out-of-band SQL wipe or a hand-forged tombstone is caught rather than
silently accepted.

---

## 7. Merkle blocks

Sealed blocks commit ranges of leaves. Leaves enter the tree as the **bytes of their
64-char hex hash string**.

```
hash_leaf(leaf_hex)      := H( 0x00 || utf8(leaf_hex) )            // 32 bytes
hash_internal(l, r)      := H( 0x01 || l || r )                    // l,r,result: 32 raw bytes
```

`merkle_root(leaves)`: build levels bottom-up; at each level pair `(level[i], level[i+1])`;
for an **odd** trailing element, pair it with **itself** under `hash_internal` (never
re-hashed as a leaf). Empty input has no root.

**Block root** binds the leaf count:
```
block_root := hex(H( 0x01 || u64le(actions_count) || merkle_root_bytes ))
```
where `merkle_root_bytes` are the 32 raw bytes of `merkle_root(leaves)`. A block whose stored
`actions_count` does not match its leaf set fails — this closes CVE-2012-2459-class odd-leaf
duplication. Each block row also carries `prev_block_merkle`, `first_chain_version` and
`last_chain_version`.

**Membership (normative).** A leaf belongs to a block **if and only if its own chain slot
falls in `[first_chain_version, last_chain_version]`**. The slot of the Response leaf (§5.4)
is `response_chain_version`, **not** the `chain_version` of the action row that carries it —
one row holds two leaves in two unrelated slots, and a block that contains one need not
contain the other. A call sealed in the last slot of block N whose response is stamped into
block N+1 contributes its Action leaf to N and its Response leaf to N+1; a verifier that
harvests the response off the rows it loaded by `chain_version` gets both blocks wrong, and
its two failures look sound: a leaf too many in N (`actions_count` binds the root, so the
root mismatches) and a slot with no leaf in N+1.

---

## 8. Attribution layer (seed-keyed — NOT third-party verifiable)

This layer proves *authorship / anti-operator tamper* and is **keyed to a per-deployment
secret** — the seed, derived as `HKDF(instance_id || host_secret)`. It is documented for
completeness; it is **not** part of the keyless guarantee.

> **This layer is qualified by tier, and the qualification is load-bearing.**
> The host secret exists only on Pro. On Free the seed is derived from the `instance_id`
> alone — and §9 records the `instance_id` inside `identity.json`, in the bundle itself. So
> on Free the seed is reconstructible by anyone holding a bundle, and with it every key
> below: the event HMAC key, the `event_uid` construction, and the Ed25519 deployment key.
>
> The consequence, stated without softening: **on Free this layer establishes integrity,
> not authenticity.** A recipient can confirm the chain is internally consistent; they
> cannot distinguish it from one a third party minted, because they can mint one too. A
> party without the seed cannot forge it — but on Free, holding the bundle *is* holding the
> seed. Only on Pro does "without the seed" describe a bundle recipient.
>
> The keyless guarantees of §§1–7 are unaffected: they depend on hash linkage and Merkle
> recomputation, not on the seed.

- **Key ladder (normative).** Every key in this layer descends from the seed by a fixed
  path, and the two HKDF steps are **different constructions**. Using one where the other
  belongs yields a different key and every tag below then fails.

  ```
  seed  := HKDF-SHA256(salt = "pylae:seed:v1",                     // extract-then-expand
                       ikm  = instance_id_bytes(16) || host_secret(32, Pro only),
                       info = "", L = 32)
  k_evt := HKDF-Expand-SHA256(prk = seed, info = "pylae:event_hmac:v1",      L = 32)
  k_sig := HKDF-Expand-SHA256(prk = seed, info = "pylae:deployment_sign:v1", L = 32)
  ```

  The seed step is full HKDF, and the separator is the **salt** — `info` is empty. The
  `ikm` is the UUID's 16 raw bytes (not its text form) followed, on Pro only, by the
  32 host-secret bytes. The subkey steps are **HKDF-Expand only**: the seed is the PRK
  and there is no extract. `fingerprint` := `hex(SHA-256(seed))`, which is the value
  `identity.json` carries as `stored_seed_fingerprint`.
- **Signed events.** `system_events` used as chain-gap / erasure justifications are signed
  with HMAC-SHA256 under `k_evt`, over this preimage:

  ```
  event_preimage := "pylae:event_preimage:v1"
                      || u32le(len(event_type)) || utf8(event_type)
                      || u32le(len(timestamp))  || utf8(timestamp)
                      || fingerprint_raw                       // 32 bytes, NO length prefix
                      || u32le(len(details_canonical_bytes)) || details_canonical_bytes
  ```

  Three things here are easy to get wrong, and each one produces a tag that does not
  validate against a correct implementation:

  1. **The fingerprint enters raw and unprefixed.** §2 length-prefixes every
     *variable*-width value; this one is fixed-width at 32 bytes and carries no prefix.
  2. **`details_canonical_bytes` is `write_value(details)` — the canonical *bytes*, not a
     hash.** It is **not** `details_canonical_hash` (§5.3), which is the hex SHA-256 of
     those same bytes. The two names are one word apart, their contents are unrelated, and
     the name used here is the producer's own so the two sides can be grepped against each
     other.
  3. **The `v1:` prefix is not part of the tag.** The `signature` column is the literal
     ASCII `v1:` followed by `hex(HMAC-SHA256(k_evt, event_preimage))`. A verifier strips
     the prefix, rejects an unknown one rather than guessing, and compares the tag bytes
     in constant time.

  `timestamp` is the deployment's `to_rfc3339()` form with an explicit `+00:00` offset —
  the same normalization §9 pins for leaves, and `events.jsonl` serializes it with a `Z`
  that a verifier MUST map back before rebuilding this preimage. `k_evt` lives in memory
  only, zeroized on drop, never persisted and never exported.
- **`event_uid`** := the first 32 characters of
  `hex(SHA-256("pylae:event_uid:v1" || k_evt || event_preimage))` — the same preimage
  bytes, with the key **inside the hash** rather than used as an HMAC key. Opaque without
  the key, and no substitute for the signature: it is an identifier, not a proof.
- **Gap attribution.** A slot whose leaf was stamped but whose destination row never landed
  is attributed by a signed chain-gap event carrying the orphaned `stamp_hash`, which lets a
  verifier re-anchor linkage across the gap instead of stopping. What that record proves is
  qualified by tier, and the qualification is the same one this section opens with.
  **On Pro it establishes that the attribution came from the deployment holding the host
  secret. On Free it establishes nothing about who wrote it.**
  On Free the record does the job it exists for: it distinguishes an *honest* gap — a crash,
  a terminally failed INSERT, a disk that filled — from an unexplained hole, and it carries
  the hash that keeps linkage verifiable across the slot. It does **not** survive an
  adversary holding the bundle. That adversary holds the seed, and can mint the same record
  for a slot they emptied themselves. A conforming verifier reading a Free bundle MUST
  report an attributed gap as *attributed, origin not authenticated* — never as *verified*,
  and never as evidence that the slot was lost rather than removed.
  This record lives in this layer, not in §§1–7: the keyless guarantees are unaffected by
  it, and a verifier that ignores the attribution entirely still reports the gap.
- **Producer rule for gap attribution (normative).** A producer MUST NOT emit an attributed
  gap record carrying a `stamp_hash` it did not itself compute. Where the hash is recovered
  after a crash from a local write-ahead record rather than held in memory, that record MUST
  be authenticated as the producer's own before its hash is copied into signed evidence
  — the signature otherwise certifies only that the deployment repeated a value, not that
  the value is the hash of a leaf the deployment ever stamped. A producer that cannot
  authenticate the record MUST leave the slot unexplained, which is the honest verdict and
  the one a verifier already knows how to report. Pylae authenticates the record with an
  HMAC over its four columns plus the deployment fingerprint, under the same key that signs
  the events (domain-separated as `pylae:wal_intent:v1`); the tier qualification above
  applies unchanged, since a tag is worth exactly what the seed behind it is worth.
  **A tag alone establishes origin, not freshness.** A producer that mints one per
  write-ahead record and deletes the record when the write lands leaves each record
  replayable for as long as an adversary can observe it, so an adversary who can both
  read and write the producer's store can re-present a captured record for a leaf they
  later remove. Closing it needs a freshness binding an adversary holding the store
  cannot reproduce. **This format does not specify one, and a verifier cannot check
  freshness from a bundle** — so the rule stands regardless of producer: a verifier MUST
  NOT read an attributed gap as proof that the slot was lost rather than removed.
  Pylae's producer binds freshness outside the store: a slot is explained only if the
  deployment listed it as outstanding in an authenticated record kept beside the key,
  never in the database, and populated only from what the running process opened
  first-hand. What that leaves is a slot settled after the last checkpoint of a run that
  then dies uncleanly, and the standing fact that whoever holds the producer's
  filesystem holds its key.
- **Insurability report (Ed25519).** The one artifact designed for asymmetric third-party
  checking. It is **not part of the evidence bundle** — `pylae chain export` does not write
  it — and it is specified here because §8 is where every seed-keyed construction lives.
  Signed with `k_sig` used directly as the Ed25519 secret-scalar seed, so the keypair is
  deterministic per deployment and a broker re-fetching a report sees a stable key. The
  preimage is `write_value` (§2.1) over this object, and because `write_value` **sorts
  object keys**, what is load-bearing is the field *set and names*, not the order they
  appear in below:

  ```
  { "scheme": "ed25519-v1", "generated_at": <rfc3339>, "pylae_version": <string>,
    "fingerprint": <hex(SHA-256(seed))>,
    "deployment_overview": …, "governance_controls": …, "security_posture": …,
    "cost_controls": …, "compliance_status": …, "audit_chain": …,
    "safety_infrastructure": …, "incident_history": …, "health_score": … }
  ```

  `signature` and `signing_pubkey` are base64 of the raw 64- and 32-byte values.

  **`signing_pubkey` is not in the preimage, and that bounds what the signature proves.**
  A verifier checking the report against the key the report itself carries learns that
  those bytes were signed by *some* key — not by this deployment's. Establishing origin
  requires knowing the deployment's public key beforehand, or checking `fingerprint`
  against a bundle from the same deployment; `fingerprint` **is** covered. This format
  does not anchor the public key to the chain, and a reader should not treat the report
  as self-authenticating.

**Roadmap (out of scope for v0.1):** signing block roots with the Ed25519 deployment key
and/or anchoring roots to an RFC 3161 timestamp or transparency log would extend
independent verification to anti-operator tamper. Until then, do not claim a third party can
prove the operator did not recompute their own chain.

---

## 9. The evidence bundle

`pylae chain export` writes a directory (refuses a non-empty one) containing:

| File | Contents |
|---|---|
| `blocks.jsonl` | one sealed block per line |
| `actions.jsonl` | action leaves, ordered by `chain_version` ascending |
| `events.jsonl` | signed event leaves |
| `snapshots.jsonl` | the forensic snapshot behind every non-empty `snapshot_hash` |
| `erasures.jsonl` | erasure leaves (an erased action's cleared content appears nowhere; the row itself still ships in `actions.jsonl`, emptied) |
| `config_archive.jsonl` | content-addressed referents (see §9.2) |
| `identity.json` | `{ stored_seed_fingerprint, instance_id, last_sealed_version, exported_at, tool_version }` |
| `REPORT.md` | human-readable summary + which verification level was achieved |
| `MANIFEST.json` | written **last**; `{ created_at, tool_version, files: [{name, sha256, bytes}] }` covering every other file |

Each `*.jsonl` line is one JSON object. A leaf's `prev_hash` and `prev_version` are **not**
stored in the row — they are derived from the walk (the predecessor leaf's `chain_hash`, or
the genesis hash for `chain_version == 1`). The following field mapping is **confirmed against
real `pylae chain export` output**; the reference implementation is `pylae-verify`'s
`bundle.rs`.

**What a bullet lists.** Each bullet names every field a verifier **consumes** — nothing
required to recompute or to report is omitted. A line MAY carry more than the bullet
lists (`actions.jsonl` in particular serializes the whole action row, operational columns
included), and a verifier MUST ignore fields it does not know rather than reject the line.
An unknown field is not a conformance failure; a **missing** listed field is.

- **`actions.jsonl`:** `id`, `chain_version`, `agent_id`, `method`, `tool_name` (nullable),
  `request_params` (nullable object), `request_params_raw_hash` (nullable), `decision`,
  `decision_source` (nullable), `policy_id` (nullable), `server_id`, `timestamp`,
  `request_params_truncated` (nullable → `false`), `request_params_original_size`
  (nullable → `0`), `redacted_marker_hash` (set on erased actions), `chain_hash`, plus
  response-leaf fields `response_chain_version`, `response_raw_hash`, `response_truncated`,
  `response_original_size`, `response_chain_timestamp`, `response_chain_hash`.
  - `params_hash` (§5.1) is **derived**, by this rule (normative):
    1. when `request_params_truncated` is true → `request_params_raw_hash`. Past the
       producer's truncation threshold `request_params` holds a `{"truncated": true,
       "size": N}` marker and not the payload, so re-hashing it cannot reproduce the leaf.
    2. otherwise, when the action is erased and its tombstone verifies (§6) →
       `request_params_raw_hash` if present, else the tombstone's `original_params_hash`.
       The raw commitment is the more faithful of the two, because the tombstone of a
       truncated action commits the marker's hash rather than the payload's.
    3. otherwise → `canonical_params_hash(request_params)`.

    Case 3 is the common one, and it is deliberately **not** served from
    `request_params_raw_hash`. Re-hashing the stored payload is what detects an out-of-band
    rewrite of `request_params`; a verifier that preferred the commitment column
    unconditionally would accept a forged payload under a leaf that still verifies. The
    commitment is consulted only where the stored payload cannot serve — truncated away, or
    erased.

    **This rule changes no preimage and no domain separator.** It states which stored value
    feeds an unchanged construction, so evidence produced before this clarification stays
    valid under it.
  - `snapshot_hash` (§5.1) is the empty string `""` when the action carried no forensic
    snapshot (the stamp-path sentinel). When it carried one, the value MUST be emitted here
    and the snapshot itself MUST appear in `snapshots.jsonl`; a bundle that omits the hash
    cannot recompute those action leaves, and one that omits the snapshot publishes a
    commitment whose inputs the recipient does not hold.
- **`snapshots.jsonl`:** `action_id`, `chain_version`, `security_posture` (object),
  `cost_ceiling` (object), `agent_profile_id` (nullable), `active_policy_ids` (array of
  UUID strings, **in stored order**), `active_contract_id` (nullable), `damage_estimate`
  (object), `snapshot_hash`, `created_at`.

  These are the six inputs of `snapshot_hash` (§2.2) plus the hash they produce, so the
  construction is recomputable from the bundle alone. **A row appears here if and only if
  the action carried a snapshot.** An action whose `actions.jsonl` `snapshot_hash` is the
  empty string has no row here and that is the ordinary case; an action with a **non-empty**
  `snapshot_hash` and no row here is an invariant violation, and a verifier MUST report it
  rather than treat the snapshot as absent — the producer committed to a snapshot it did not
  ship.

  `damage_estimate` is carried as the object `write_value` consumes; a verifier feeds it
  straight into the preimage without reshaping it.
- **`erasures.jsonl`:** `target_action_id`, `actor`, `reason`, `timestamp`, `chain_version`,
  `tombstone_hash`, `original_params_hash`, `chain_hash`.
- **`events.jsonl`:** `id`, `event_uid`, `event_type`, `timestamp`, `details` (object),
  `signature` (nullable), `chain_version`, `chain_hash`.
  `details_canonical_hash` (§5.3) = `canonical_value_hash(details)`, and `signature` is the
  `v1:`-prefixed tag §8 specifies — the column Level 2 verifies, without which an
  attributed gap cannot be checked at all.
  - `details` is opaque to the leaf hash — it is fed to `write_value` whole — but it is **not**
    opaque to verification. Three event types carry payloads that §9.2 and §10 tell a verifier
    to read; **§9.3 gives their shape**. Every other event type's `details` is informational and
    a verifier hashes it without interpreting it.
- **`blocks.jsonl`:** `block_number`, `merkle_root` (this **is** the `actions_count`-bound
  block root of §7), `prev_block_merkle` (nullable), `actions_count`, `first_chain_version`,
  `last_chain_version`, `last_chain_hash`. `first_chain_version` and `last_chain_version` are
  **normative**: together they are the block's slot range, and §7 Membership decides from them
  alone which leaves the verifier folds into the root.

**Timestamp normalization.** The chain leaf commits the timestamp in the deployment's
`to_rfc3339()` form (explicit `+00:00` offset); the JSON export serializes `DateTime<Utc>`
with a `Z` suffix. A verifier MUST map a trailing `Z` to `+00:00` before recomputing. (An
exporter MAY instead emit the `+00:00` form directly; this spec pins the preimage form.)

### 9.1 Integrity of the bundle itself
Recompute `sha256` and `bytes` for every entry in `MANIFEST.json`; any mismatch means the
bundle was altered after export. `MANIFEST.json` is written last and lists all other files.

### 9.2 Config resolution
Each `config_archive.jsonl` row carries at least `{ content_hash, kind, content }` — the
three fields resolution consumes — where `content` is the archived configuration serialized
as a JSON string. Its `content_hash` re-derives from
`content` by `kind` (confirmed against real bundles):

- `kind == "effective_rules"` → `hex(SHA-256(content_bytes))` — the SHA-256 of the exact
  serialized string.
- `kind == "cve_feed"` → `canonical_value_hash(parse(content))`.
- `kind == "manifest"` → `hex(SHA-256(canonical_json(payload)))`, where `payload` is the
  manifest payload obtained from `content` as follows:
  - `content` starting with `{` is the canonical payload JSON itself (an embedded snapshot,
    which has no publisher envelope). Parse it.
  - otherwise `content` is a compact JWS. Take its **payload** segment, base64url-decode it
    (no padding) and parse that. The signature is **not** needed and MUST NOT be required:
    this derivation is keyless and belongs to Level 1.

  The discriminator is structural rather than a `.` scan: `{` is not in the base64url
  alphabet, while canonical JSON contains dots inside float values.

  Note the re-canonicalisation. The hash is **not** SHA-256 of the literal bytes the
  publisher signed — those are re-serialized through `canonical_json` first. A verifier that
  hashes the decoded bytes verbatim computes a different value for every fetched manifest.

  **And `payload` here is the parsed JSON document, not a model of it.** A verifier in a
  typed language will be tempted to deserialize the payload into its own struct and
  canonicalize that. It must not: any field the struct does not declare is dropped and any
  field it defaults is filled back in, so the hash lands on a document the publisher never
  signed. Two payloads differing only in fields one implementation defaults would then
  share an address. Canonicalize the parsed JSON, whatever it contains.

  This bullet previously declared the manifest hash *"**not** reconstructible from the bundle
  alone"* and told a keyless verifier to report it unresolved. That was false: the derivation
  above is keyless and has been in the core throughout. A verifier written against the old
  text reported every manifest row as unresolved and therefore never checked it.

**Where the anchored hashes come from.** The rows in `config_archive.jsonl` are the
*archive*; the *anchors* — which hashes a complete archive would have to contain — are
carried by a chain leaf, so that removing an anchor is not a silent edit. They are read from
the `compliance.config_active` event in `events.jsonl` (§9.3) with the **highest
`chain_version`** — the chain's own order, so two verifiers pick the same one — taking its
`details.manifest.manifest_hash` and its `details.rules_fingerprint`. Because that event is a
chain leaf, altering either value breaks the leaf's `details_canonical_hash` and deleting the
event leaves a slot with no leaf; a verifier therefore holds the anchor list on the same
footing as any other leaf content.

**What is not in the bundle, and must not be assumed.** A deployment also anchors the
`rules_version_at_pin` of each tool pin. Tool pins are **not** exported, so a bundle carries
no record of which pin fingerprints exist, and a verifier MUST NOT report the archive as
complete on the strength of resolving the two anchors above. A producer's `REPORT.md` may
list pin anchors it resolved from its own database; that is the producer's statement, not a
checkable one, and nothing in this format makes it so.

Resolution distinguishes two outcomes, and only one of them is a verdict. An anchored hash
with **no row** is informative: a database predating the archive has nothing to offer, and
the absence says so. A row whose `content` does not re-derive its own `content_hash` is a
**failure** — the row is content-addressed, so the two disagreeing means the body was
replaced after the chain anchored the key, and no signature covers that.

### 9.3 Event payloads a verifier consumes

Four `event_type` values carry a structured `details` that verification depends on. This
section gives the fields a verifier **consumes**; as everywhere in §9, a payload MAY carry
more than is listed and a verifier MUST ignore what it does not know. A **missing** listed
field is a malformed payload, and the rule for each type says what to do about it.

**`proxy.chain_gap`** — the producer's record of chain slots it consumed and could not fill.
§10 makes this Level 2 material: the record is only trustworthy once the event's signature
verifies. Top-level keys are `total_dropped`, `first_dropped_at`, `last_dropped_at`,
`by_reason`, `system_event_drops`, `out_of_chain_stamped_drops` and
`insert_failed_non_buffered`. The last is the one that names orphaned slots:

```
insert_failed_non_buffered: { count: integer, drops: [ … ] }
  each drop — consumed:     { chain_version: integer,
                              stamp_hash:    64-char hex — the consumed slot's leaf hash,
                              attempted_at:  RFC 3339,
                              identifying:   { leaf_kind: string, … } }
  each drop — informational: { source: "live" | "boot_replay" }
```

`identifying.leaf_kind` names what the missing leaf would have been — `action`, `erasure`,
`response`, `system_event`, `boot_event`, `panic_event`, `chain_gap_event`. The remaining
per-kind fields carry that kind's natural identifier where one exists (`target_action_id` for
an erasure, `action_id` for a response, `boot_id` for a boot event; `chain_gap_event` has
none), which a verifier MAY use to correlate and MUST NOT require.

A drop reconstructed at boot (`source: "boot_replay"`) carries less. Its `leaf_kind` is one of
`action`, `response`, `erasure` and `system_event`: it names the kind of leaf, not the event
type, so every event leaf — boot, panic and chain-gap included — is `system_event` there. Its
identifier is that row's own id: `action_id`
for an action or a response (a response also repeats its slot as `response_chain_version`),
`event_id` for an event, and for an erasure the erasure event's own id as `erasure_event_id`,
not the erased action's. Its `attempted_at` is when the drop was reconstructed, not when the
write was lost. Evidence from earlier builds shaped these drops differently: an erasure
carried its event's own id under `target_action_id`, and an action or an event was labelled
`chain_gap_event`. For a `boot_replay` drop a verifier MUST NOT read `target_action_id` as
the id of an erased action.

`source` is listed apart because **no verification step depends on it**: it says whether the
slot was consumed by the running process or reconstructed at boot replay, which an auditor can
use to place the loss in a process lifetime and which nothing in Level 1 or Level 2 depends on.
It is published here so that a field already travelling in signed evidence is not a field only
the producer knows how to read — not to make it a requirement. A verifier that correlates
identifiers reads it only to apply the `boot_replay` rule above; otherwise treat it as
informational, and do not reject a drop that omits it.

The three `by_reason` buckets and `system_event_drops` record a slot whose row the producer
abandoned before writing it. They attribute the gap to a reason and carry no `identifying`
object:

```
by_reason: { buffer_overflow | return_to_front_overflow | max_retries_exceeded:
             { count: integer, drops: [ … ] } }
  each drop — consumed:      { chain_version: integer, or null when the producer did not know it,
                               attempted_at:  RFC 3339 — the dropped leaf's own time }
  each drop — informational: { stamp_hash, agent_id, server_id, method, tool_name }

system_event_drops: { count: integer, drops: [ … ] }
  each drop — consumed:      { chain_version: integer,
                               dropped_at:    RFC 3339 — the dropped event's own time,
                               reason:        "buffer_overflow" | "return_to_front_overflow"
                                              | "max_retries_exceeded" }
  each drop — informational: { stamp_hash, event_type, actor, target_type, target_id }
```

A slot named in either is attributed to that reason and, where the seed can be rebuilt from
the bundle, reads *attributed, origin not authenticated* like any other attributed gap (§8).
It is not the attribution §10 threads linkage through: a verifier MUST NOT take these drops'
`stamp_hash` as a predecessor hash, and the leaf after such a slot is re-anchored as after any
other gap. Two or more signed claims on one slot that the date rule below leaves standing make
it *ambiguous* rather than attributed, and a slot that `insert_failed_non_buffered` names is resolved by that record whatever else
claims it.

A drop dated later than the first leaf after its slot in chain order — of any kind, and in a
run of lost slots the first slot that holds a leaf — SHOULD NOT attribute the slot: the
explanation would postdate what it explains. A leaf's date is its `timestamp`, or its
`response_chain_timestamp` for a response. A slot with no later leaf is not checked. The rule
does not apply to `insert_failed_non_buffered`, whose `attempted_at` is when the evidence was
written and whose `stamp_hash` the recompute checks instead. A `by_reason` drop whose
`chain_version` is null or absent names no slot; a verifier MAY show it beside a nearby gap,
need not show one whose `method` is empty, and MUST NOT attribute a gap with it.

> **Anti-wildcard rule (normative).** A bucket whose `count` is greater than zero and whose
> `drops` array is empty is a **synthesised wildcard**: a claim to explain slots without
> naming any. A verifier MUST reject the whole event rather than treat the claim as
> attribution, and the same holds for an `insert_failed_non_buffered` drop missing
> `chain_version`, `stamp_hash`, `attempted_at` or `identifying.leaf_kind`, for a `by_reason`
> drop missing `attempted_at`, and for a `system_event_drops` drop missing `chain_version`,
> `dropped_at` or a `reason` listed above. Without this rule a single event claiming
> `count: 500` and nothing else would attribute five hundred gaps — which is the one thing
> attribution must never be able to do cheaply.
>
> The rule covers the groups that name slots: `insert_failed_non_buffered`, the `by_reason`
> buckets and `system_event_drops`. `out_of_chain_stamped_drops` names none and is not
> consumed. Pylae's own verifier also sets aside the whole event when `by_reason` is absent or
> not an object, when a `by_reason` bucket has no `drops` array, when another group claims a
> `count` above zero with no `drops` array, when an `insert_failed_non_buffered` drop's
> `stamp_hash` is empty or not a string, when a drop's `attempted_at` or `dropped_at` is present
> but not RFC 3339, when a `chain_version` in `insert_failed_non_buffered` or
> `system_event_drops` is not an integer, and when `identifying` is not an object or its
> `leaf_kind` not a string. A verifier SHOULD do the same, so that two verifiers reach one
> verdict on one payload. An earlier text of this rule listed `identifying.leaf_kind` without
> saying which group it belongs to: it applies to `insert_failed_non_buffered` only, and the
> other groups carry no `identifying` object.

**`chain.gap_attested`** — the operator's declaration that a run of slots nothing explains was
lost. The producer writes it only when an operator asks, at a boot that refused to start over
those slots, and it writes one event per run, signed and stamped above the run. §10 makes it
Level 2 material, like `proxy.chain_gap`. Consumed fields, all required:

```
lost_from:      integer, at least 1 — the first lost slot
lost_to:        integer, at least lost_from — the last lost slot
resume_version: integer, above lost_to and below the event's own chain_version —
                the first slot above the run that something occupies
resume_hash:    string — that occupant's chain hash
resume_digest:  string — that occupant's content digest (below)
reason:         non-empty string — why the operator says the slots were lost
```

The occupant of `resume_version` has no predecessor to recompute against, so the attestation
binds it. For a leaf, `resume_digest` is its leaf hash (§5) recomputed with the ASCII string
`pylae:gap-attested` as predecessor hash and `resume_version − 1` as predecessor version; for a
slot the producer carried without a row, it repeats `resume_hash`. A Level 2 verifier MUST
recompute the digest of a leaf at `resume_version` and report that leaf as a mismatch when the
digest or the leaf's stored hash differs from the attestation's: it changed after the loss was
attested. Other attested slots may sit between `lost_to` and `resume_version`.

A payload missing a listed field, or with `lost_from` above `lost_to`, `resume_version` at or
below `lost_to`, or `resume_version` not below the event's own slot, is malformed, and a
verifier MUST set the whole event aside. The date rule above does not apply: an attestation
always postdates the run it attests.

**`compliance.config_active`** — the anchor for the active configuration (§9.2). Consumed
fields: `manifest.manifest_hash` and `rules_fingerprint`, both lowercase hex. The payload also
carries `manifest` metadata (`kid`, `schema_version`, `issued_at`, `expires_at`, `source`),
the active `thresholds`, and `shipped_defaults_delta` — per-axis `(current, shipped)` pairs
for any threshold the deployment relaxed below the shipped baseline, which an auditor reads
directly rather than by resolving the manifest. A deployment with no usable identity emits no
such event; its absence is reported as "no anchor for this window", never as "no divergence".

**`pin.demoted_pending_revalidation`** — a tool pin that stopped being trusted because the
rule set moved under it. Consumed fields: `server_name`, `tool_name`, `prev_rules_version`,
`current_rules_version`, `pin_version`. The two `*_rules_version` values are effective-rules
fingerprints and may be resolved against `config_archive.jsonl` exactly like the anchors of
§9.2 — but see the note there: they surface only for pins that were demoted, so they are not
a complete pin list and MUST NOT be read as one.

---

## 10. Verification levels (what a verifier reports)

- **Level 1 — STRUCTURAL (keyless, always available).** Recompute every leaf hash (§5) in
  `chain_version` order, checking each `prev_hash` links to the predecessor (first → genesis
  §4); recompute every block's Merkle and block root (§7); enforce the tombstone rule (§6)
  and config resolution (§9.2); verify `MANIFEST.json` (§9.1). This is fully independent and
  proves **structural integrity**: the chain is internally consistent and no leaf, ordering,
  block, or anchored config was altered without detection.
- **Level 2 — ATTRIBUTION (seed-required).** Verify HMAC event signatures and the Ed25519
  report (§8). Only possible for a party holding the deployment seed (or the seed-derived
  material). A keyless verifier MUST report this level as **skipped**, never as passed, and
  MUST NOT claim `intact` on the strength of Level 1 alone where signed leaves are present.

**Gaps, and what attribution does to them.** A `chain_version` that no leaf of any kind
holds is a **gap**. It is *attributed* when a signed chain-gap event (§8) names it, either in
`insert_failed_non_buffered` with its `stamp_hash` or with a reason (§9.3); *ambiguous* when two
or more reason claims name it (§9.3); *attested* when no chain-gap event names it and a signed
`chain.gap_attested` event (§9.3) covers it; otherwise it is *unexplained*. Attribution and
attestation are Level 2 material, because what the event says is only trustworthy if its
signature verifies:

- At **Level 1** a verifier has no verified `stamp_hash`. It MUST report the slot as a gap
  and MUST NOT thread linkage through it, whatever the event payload appears to say.
- At **Level 2** a verifier MAY thread linkage through a slot `insert_failed_non_buffered`
  attributes, by taking its orphaned `stamp_hash` as the predecessor hash for the next leaf.
  A slot attributed with a reason stays a gap for linkage (§9.3). Whichever the kind, where
  the seed was reconstructible from the bundle itself (Free — §8), it MUST label the result
  **attributed, origin not authenticated**, never *verified*.
- An **attested** slot is accounted for by the operator's word, not explained. A verifier MUST
  NOT report it as intact or as attributed, MUST NOT thread linkage through it, and reports the
  leaf after the run as it reports the leaf after any gap, re-anchored and not verified; at
  Level 2 it also holds that leaf to the attestation (§9.3). Where the seed was reconstructible,
  it labels the slot **attested, origin not authenticated**. A slot a leaf holds is not a gap,
  whatever an attestation claims.
- **Sealing is unaffected at both levels.** A block whose range contains a slot with no
  persisted leaf is not intact. Where the slot's leaf was sealed into the block before its
  row was lost, the Merkle root does not recompute and MUST be reported as a mismatch: the
  orphaned leaf's preimage is held by no row, so its contribution to the root is
  unreconstructible — a boundary of the format, not a defect a future verifier can close.
  Where the slot was held by nothing when the block was sealed — admitted at boot replay as
  a slot whose row never landed, or attested lost — it never entered the root, the root
  recomputes, and the block is reported for the missing slot instead. Attribution and
  attestation explain or account for a gap; neither restores a root.

A conformant verifier states which level it achieved and never conflates the two.

---

## 11. Versioning and conformance

- Each domain separator carries an explicit version (`:v1`, `:v2`, `:v4`). A leaf stamped
  under an older separator does not validate under a newer verifier even if the row survives
  — this is deliberate anti-replay. A verifier MUST select the construction by the persisted
  version/kind, never by guessing.
- A conformant verifier MUST read JSON with a parser that keeps **integer and float tokens
  apart** (§2.1), or recover the token from the raw text. This is not a preference about
  types: `1` and `1.0` are distinct inputs to both canonical encoders, so a reader that
  collapses them computes different hashes for leaves and manifests alike. §2.3 is the
  vector that detects it; an implementation that cannot reproduce §2.3 is not conformant,
  whatever else it passes.
- A conformant verifier MUST: recompute all Level-1 constructions exactly as specified;
  reject on any linkage, leaf, Merkle, block-count, tombstone, or manifest mismatch; and
  report Level 2 as skipped when the seed is absent. The single exception is the Level 2
  re-anchor through a gap `insert_failed_non_buffered` attributes (§10), which is not a
  linkage mismatch; it is not an exception to the Merkle rule, which holds at both levels
  without carve-out.
- This spec is versioned independently of the product. Breaking changes bump the affected
  domain separators and this document's version.

### 11.1 Conformance vector — attribution layer

Every step of §8's key ladder and event preimage, from a synthetic Free-tier deployment.
Free is used deliberately: with no host secret, the whole ladder is reproducible from the
`instance_id` alone, so an implementer can check each intermediate value rather than only
the final tag. **These values are normative.** The `details` below is chosen to exercise the
MAC, not to model a §9.3 payload; attribution would set it aside.

Matching the tag does imply the steps above it matched — that is what a MAC is for. The
intermediates are published because matching is not the interesting case: an implementation
that gets the tag wrong learns nothing from the tag about *which* step was wrong, and the
plausible mistakes here are several layers deep. Comparing downward stops at the first line
that differs.

```
instance_id     00000000-0000-4000-8000-000000000001
host_secret     (none — Free)
event_type      "proxy.chain_gap"
timestamp       "2026-01-01T00:00:00+00:00"
details         {"reason":"insert_failed_non_buffered","slot":7}

seed            3ae943125a572662cae5dce362ca6706d25d6e4e6869e8d57205b3dd8a9c59a9
fingerprint     6521cb9a40bbeb79c04fabdf3af3d5719e5ef058c4356c4100ab1b0d9da8d138
k_evt           be1a64857c6838cfd945a74843e0345f0b68a2b4d5258aa2a0abc96851f9253a
details_canonical_bytes
                100200000006000000726561736f6e301a000000696e736572745f6661696c65645f6e6f6e5f627566666572656404000000736c6f74410700000000000000
event_preimage  70796c61653a6576656e745f707265696d6167653a76310f00000070726f78792e636861696e5f67617019000000323032362d30312d30315430303a30303a30302b30303a30306521cb9a40bbeb79c04fabdf3af3d5719e5ef058c4356c4100ab1b0d9da8d1383f000000100200000006000000726561736f6e301a000000696e736572745f6661696c65645f6e6f6e5f627566666572656404000000736c6f74410700000000000000
signature       v1:3a981d7d47ac8cb114230d3635da6db6c88ee63e43f78fc2eddcb9f0f0f71d7d
event_uid       bfd8139ced6bb4f3bd4f74d9a7fda9b5
k_sig pubkey    zjLdQmprTuSqbXdiF9t9eke9QcWOJNSUv/37ql59aeM=   (base64, Ed25519)
```

Reading `details_canonical_bytes` against §2.1 is the fastest way to catch the two mistakes that
produce a wrong preimage: `10` opens the object with `02000000` for its two members, whose
keys appear **sorted** (`reason` before `slot`), and `41 0700000000000000` encodes `7` as a
tagged `i64le` rather than as the text `7`.

**These values pin the construction, not just the output.** Any change to a separator, to
either HKDF form, to the preimage layout or to `write_value` changes them. That is the
intent: a producer that alters the construction must bump the affected separator in §3 and
republish this vector, which is what keeps `:v1` meaning one thing.

*Report issues to security@pylae.net.*
