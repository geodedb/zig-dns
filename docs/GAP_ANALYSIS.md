# Gap Analysis

Last updated: 2026-03-24 (post-commit 6d42d51 -- 15 additional gaps closed; 7 open remain)

> This file contains ONLY open gaps. Resolved and Won't Do items are in [GAP_ANALYSIS_RESOLVED.md](GAP_ANALYSIS_RESOLVED.md).

## Gaps

### GAP-0015: 24 issues marked Complete in docs but Open in GitLab tracker
- **Issue:** [#78](https://gitlab.com/devnw/zig/dns/-/issues/78)
- **Category:** Bug
- **Severity:** Medium
- **Requirement source:** `docs/ROADMAP.md`; GitLab issue tracker
- **Current state (evidence):**
  - ROADMAP.md updated: phase headers and feature statuses annotated with "(code implemented, issue tracker reconciliation pending)"
  - Phase 3 (DNSSEC) downgraded from "COMPLETE" to "PARTIAL" to reflect RSA gap
  - DoT/DoH/DoQ statuses updated to "interface only"
- **Why this is a gap:** Docs-side is resolved but GitLab issue closure requires admin action. Tracker still shows 24+ open issues for completed work.
- **Impact/Risk:** Tracker does not reflect actual project state; confusing for contributors.
- **Recommended fix:** Admin batch-close the 24 completed issues in GitLab.
- **Acceptance criteria:**
  - [ ] All issues for completed features are closed in GitLab
  - [ ] ROADMAP.md annotations can be removed once tracker is reconciled

---

### GAP-0017: Functional UDP/TCP transports suppressed from public API
- **Issue:** [#80](https://gitlab.com/devnw/zig/dns/-/issues/80)
- **Category:** Feature
- **Severity:** Medium
- **Requirement source:** `docs/ARCHITECTURE.md` -- Transport Layer
- **Current state (evidence):**
  - Transport modules exposed in public API via GAP-0011 resolution
  - `src/recursive.zig:sendQuery()` still uses inline socket code instead of transport module abstractions
- **Why this is a gap:** Resolver wiring does not use the transport abstraction layer. Internal code bypasses the public transport API.
- **Impact/Risk:** Transport-level features (connection pooling, metrics) are not applied to recursive resolver queries.
- **Recommended fix:** Refactor `sendQuery()` to use transport module interfaces.
- **Acceptance criteria:**
  - [ ] Recursive resolver uses transport module abstractions for UDP/TCP queries
  - [ ] Transport-level features apply uniformly to all query paths

---

## Security Findings (Phase 3 + Adversarial Review)

The following security findings were identified in Phase 3 review and the subsequent adversarial security review (2026-03-24). Findings that duplicate existing GAP entries are cross-referenced. All new issues are created as **confidential** on GitLab.

### Stack-Ranked Security Findings

| Rank | Severity | Risk Score | Finding | Component | CWE/OWASP | Evidence | Issue | SLA | Status |
|------|----------|------------|---------|-----------|-----------|----------|-------|-----|--------|
| 1 | Critical | 80 | SEC-C22: PipelinedBatch infinite loop on connection close | connection_pool.zig | CWE-835 / A05:2021 | connection_pool.zig:468,490 | [#154](https://gitlab.com/devnw/zig/dns/-/issues/154) (confidential) / GAP-0028 [#133] | 7d | **Resolved** |
| 2 | High | 64 | SEC-NEW-01: OOB read in extractTsig -- rdlength not validated before slice | tsig.zig | CWE-125 / A03:2021 | tsig.zig:633 | Commit 6d42d51 | 30d | **Resolved** |
| 3 | High | 64 | SEC-NEW-02: OOB read in extractSig0 -- rdlength not validated before slice | sig0.zig | CWE-125 / A03:2021 | sig0.zig:561 | Pending | 30d | Triage |
| 4 | High | 64 | SEC-C02: Unchecked @enumFromInt (covers SEC-C20/C21) | record.zig, sig0.zig, tsig.zig + 3 more | CWE-704 / A03:2021 | sig0.zig:217, tsig.zig:217, record.zig:439+ | [#89](https://gitlab.com/devnw/zig/dns/-/issues/89) / GAP-0033 [#134] / GAP-0034 [#135] | 30d | **Resolved** |
| 5 | High | 64 | SEC-C05: Non-CSPRNG for transaction IDs (covers SEC-C24) | recursive.zig | CWE-330 / A02:2021 | recursive.zig:119,448 | [#94](https://gitlab.com/devnw/zig/dns/-/issues/94) | 30d | **Resolved** |
| 6 | High | 48 | SEC-C23: TSIG HMAC key truncation | tsig.zig | CWE-326 / A02:2021 | tsig.zig:442,457,472,487,502 | [#157](https://gitlab.com/devnw/zig/dns/-/issues/157) (confidential) | 30d | **Resolved** |
| 7 | High | 48 | SEC-C26: Partial write data loss (3 files) | connection_pool.zig, dot.zig, zone_transfer.zig | CWE-400 / A05:2021 | connection_pool.zig:454, dot.zig:305, zone_transfer.zig:523 | [#161](https://gitlab.com/devnw/zig/dns/-/issues/161) (confidential) / GAP-0027 [#132] | 30d | **Resolved** |
| 8 | Medium | 48 | SEC-NEW-03: skipRR returns offset+10+rdlength without bounds check | dns_name.zig | CWE-125 / A03:2021 | dns_name.zig:116 | Commit 6d42d51 | 90d | **Resolved** |
| 9 | Medium | 48 | SEC-NEW-06: Question skip adds +4 without bounds check | tsig.zig, sig0.zig | CWE-125 / A03:2021 | tsig.zig:599, sig0.zig:523 | Commit 6d42d51 | 90d | **Resolved** |
| 10 | Medium | 48 | SEC-C27: No glue record bailiwick validation | recursive.zig | CWE-345 / A01:2021 | recursive.zig:564-589 | [#165](https://gitlab.com/devnw/zig/dns/-/issues/165) (confidential) | 90d | **Resolved** |
| 11 | Medium | 36 | SEC-C28: Zone transfer auth defaults off | zone_transfer.zig | CWE-1188 / A05:2021 | zone_transfer.zig:46 | [#169](https://gitlab.com/devnw/zig/dns/-/issues/169) (confidential) | 90d | **Resolved** |
| 12 | Medium | 36 | SEC-C29: SIG(0) no replay protection | sig0.zig | CWE-294 / A07:2021 | sig0.zig:341-391 | [#172](https://gitlab.com/devnw/zig/dns/-/issues/172) (confidential) | 90d | Triage |
| 13 | Medium | 32 | SEC-C30: dns_name.zig allows forward compression pointers | dns_name.zig | CWE-345 / A03:2021 | dns_name.zig:60-63 | [#175](https://gitlab.com/devnw/zig/dns/-/issues/175) (confidential) | 90d | **Resolved** |
| 14 | Medium | 24 | SEC-C100: TSIG fudge value attacker-controlled (defense-in-depth) | tsig.zig | CWE-807 / A04:2021 | tsig.zig:384 | Commit 6d42d51 | 90d | **Resolved** |
| 15 | Medium | 24 | SEC-C06/C25: Key material not zeroed (stack + heap) | tsig.zig, sig0.zig | CWE-244 / A02:2021 | tsig.zig:435-495, sig0.zig:115-117 | [#104](https://gitlab.com/devnw/zig/dns/-/issues/104) / [#111](https://gitlab.com/devnw/zig/dns/-/issues/111) | 90d | **Resolved** |
| 16 | Medium | 24 | SEC-C14/C31: spice dependency pins main branch | build.zig.zon | CWE-829 / A06:2021 | build.zig.zon:29 | [#107](https://gitlab.com/devnw/zig/dns/-/issues/107) | 90d | Triage |
| 17 | Low | 24 | SEC-NEW-07: skipName compression pointer returns offset+2 without checking offset+1 < data.len | dns_name.zig | CWE-125 / A03:2021 | dns_name.zig:101 | Commit 6d42d51 | 180d | **Resolved** |
| 18 | Low | 16 | SEC-C101: TSIG time check before MAC creates timing oracle | tsig.zig | CWE-208 / A02:2021 | tsig.zig:350-398 | Commit 6d42d51 | 180d | **Resolved** |
| 19 | Low | 16 | SEC-NEW-04: TSIG other_data silently truncated when other_len exceeds available data | tsig.zig | CWE-130 / A03:2021 | tsig.zig:229 | Commit 6d42d51 | 180d | **Resolved** |
| 20 | Low | 16 | SEC-NEW-05: @intCast(u16) on options.len without bounds check | edns.zig | CWE-190 / A03:2021 | edns.zig:167 | Pending | 180d | Triage |
| 21 | Low | 16 | SEC-C33: Zone transfer short-read on length prefix | zone_transfer.zig | CWE-20 / A05:2021 | zone_transfer.zig:530-531 | [#178](https://gitlab.com/devnw/zig/dns/-/issues/178) (confidential) | 180d | **Resolved** |
| 22 | Low | 8 | SEC-C32: SIG(0) timestamp u32 overflow in 2106 | sig0.zig | CWE-190 / A05:2021 | sig0.zig:278,369 | [#176](https://gitlab.com/devnw/zig/dns/-/issues/176) (confidential) | 180d | Triage |

### Adversarial Review Finding Details

#### SEC-NEW-01 (HIGH): OOB read in extractTsig -- **RESOLVED** (commit 6d42d51)

- **Status:** Resolved (2026-03-24). Bounds check `if (offset + rdlength > message.len) return error.InvalidMessage;` added at `tsig.zig:633`. Test `SEC-NEW-01: extractTsig rejects rdlength exceeding message` added.
- **Resolution evidence:** `src/security/tsig.zig:633` -- bounds check; `src/security/tsig.zig:932+` -- test

#### SEC-NEW-02 (HIGH): OOB read in extractSig0 -- rdlength not validated before slice

- **Summary:** `extractSig0` has the identical pattern to SEC-NEW-01: `message[offset .. offset + rdlength]` without validating `offset + rdlength <= message.len`. A crafted DNS response with a SIG(0) record whose `rdlength` is inflated causes an out-of-bounds read.
- **Impact:** Same as SEC-NEW-01. Remotely triggerable crash or memory disclosure.
- **Likelihood:** High (4/5). Pre-auth, remote. Requires the victim to process SIG(0)-signed messages.
- **Evidence:** `sig0.zig:561` -- `message[offset .. offset + rdlength]` with no prior bounds check.
- **Attack scenario:** Attacker sends a DNS response with a SIG(0) record whose `rdlength` exceeds remaining message bytes. The verification code reads past the buffer boundary.
- **Fix guidance:** Add bounds check: `if (offset + rdlength > message.len) return error.InvalidMessage;`
- **Acceptance criteria:** (1) Bounds check added before the slice. (2) Unit test with truncated SIG(0) record triggers `error.InvalidMessage`.
- **References:** CWE-125, OWASP A03:2021. Exploit surface: internet-facing.
- **Risk score:** 64 (Impact 4 x Likelihood 4 x 4)
- **Confidence:** `confidence::confirmed` -- code path verified by inspection.

#### SEC-NEW-03 (MEDIUM): skipRR returns offset+10+rdlength without bounds check -- **RESOLVED** (commit 6d42d51)

- **Status:** Resolved (2026-03-24). Bounds check `if (end > data.len) return error.InvalidRR;` added at `dns_name.zig:116`. Tests `SEC-NEW-03: skipRR rejects rdlength exceeding data` and `SEC-NEW-03: skipRR accepts valid rdlength` added.
- **Resolution evidence:** `src/security/dns_name.zig:116` -- bounds check; `src/security/dns_name.zig:252+` -- tests

#### SEC-NEW-06 (MEDIUM): Question skip adds +4 without bounds check -- **RESOLVED** (commit 6d42d51)

- **Status:** Resolved (2026-03-24). Bounds check `if (offset + 4 > message.len) return error.InvalidMessage;` added before `offset += 4` in extractTsig at `tsig.zig:599`.
- **Resolution evidence:** `src/security/tsig.zig:599` -- bounds check

#### SEC-C100 (MEDIUM): TSIG fudge value attacker-controlled -- **RESOLVED** (commit 6d42d51)

- **Status:** Resolved (2026-03-24). After MAC verification passes, fudge is now clamped: `if (tsig.fudge > self.fudge * 2)` returns `bad_time`. This limits attacker-controlled fudge to at most 2x the verifier's configured fudge.
- **Resolution evidence:** `src/security/tsig.zig:384-386` -- fudge clamp after MAC check

#### SEC-C101 (LOW): TSIG time check before MAC creates timing oracle -- **RESOLVED** (commit 6d42d51)

- **Status:** Resolved (2026-03-24). Verification reordered: MAC is now computed and verified first (tsig.zig:350-380), then time and fudge are checked (tsig.zig:384-398). Invalid MACs always return `bad_sig` regardless of time status.
- **Resolution evidence:** `src/security/tsig.zig:350-398` -- MAC-first verification order

#### SEC-NEW-04 (LOW): TSIG other_data silently truncated -- **RESOLVED** (commit 6d42d51)

- **Status:** Resolved (2026-03-24). Returns `error.InvalidTsigRecord` when `offset + other_len > rdata.len` instead of silently truncating.
- **Resolution evidence:** `src/security/tsig.zig:229` -- error return on truncated other_data

#### SEC-NEW-05 (LOW): @intCast(u16) on options.len without bounds check

- **Summary:** At `edns.zig:167`, `self.options.len` is cast to `u16` via `@intCast` without first checking that the length fits in 16 bits. If `options.len > 65535`, this triggers a panic in safe builds or undefined behavior in release builds.
- **Impact:** Crash (safe build) or integer truncation (release build) leading to incorrect EDNS OPT record serialization. Requires the caller to pass an oversized options slice.
- **Likelihood:** Low (2/5). Requires the application to construct an EDNS record with > 64KB of options, which is unusual but not impossible with programmatic construction.
- **Evidence:** `edns.zig:167` -- `const rdlength: u16 = @intCast(self.options.len);` with no prior check.
- **Fix guidance:** Add: `if (self.options.len > std.math.maxInt(u16)) return error.OptionsTooLarge;`
- **Acceptance criteria:** (1) Bounds check before cast. (2) Test with oversized options triggers error.
- **References:** CWE-190 (Integer Overflow), OWASP A03:2021.
- **Risk score:** 16 (Impact 2 x Likelihood 2 x 4)
- **Confidence:** `confidence::confirmed` -- unchecked @intCast verified by code inspection.

#### SEC-NEW-07 (LOW): skipName compression pointer returns offset+2 without checking offset+1 < data.len -- **RESOLVED** (commit 6d42d51)

- **Status:** Resolved (2026-03-24). Bounds check `if (offset + 1 >= data.len) return error.InvalidName;` added before `return offset + 2` in skipName. Test `SEC-NEW-07: skipName rejects truncated compression pointer` added.
- **Resolution evidence:** `src/security/dns_name.zig:101` -- bounds check; `src/security/dns_name.zig:241+` -- test

### Phase 3 + Adversarial Review Security Summary

- **Critical:** 1 finding -- **1 resolved** (SEC-C22 infinite loop DoS)
- **High:** 6 findings -- **5 resolved** (SEC-C02 enum panic, SEC-C05 weak PRNG, SEC-C23 key truncation, SEC-C26 partial write, SEC-NEW-01 OOB in extractTsig); **1 open** (SEC-NEW-02 OOB in extractSig0)
- **Medium:** 9 findings -- **7 resolved** (SEC-C27 bailiwick, SEC-C28 auth default, SEC-C30 forward ptr, SEC-C06/C25 key zeroing, SEC-NEW-03 skipRR bounds, SEC-NEW-06 question skip bounds, SEC-C100 fudge clamp); **2 open** (SEC-C29 replay, SEC-C14/C31 supply chain)
- **Low:** 6 findings -- **5 resolved** (SEC-C33 short read, SEC-NEW-07 skipName ptr, SEC-C101 timing oracle reorder, SEC-NEW-04 other_data truncation error); **1 open** (SEC-NEW-05 intCast overflow, SEC-C32 timestamp overflow)

### Deduplication Notes

| Phase 3 ID | Existing Issue | Status |
|-------------|---------------|--------|
| SEC-C20 (SIG(0) enum panic) | #89 [SEC-C02] -- already listed in Evidence | Duplicate -- comment added |
| SEC-C21 (TSIG enum panic) | #89 [SEC-C02] -- already listed in Evidence | Duplicate -- comment added |
| SEC-C24 (PRNG for TXIDs) | #94 [SEC-C05] -- same root cause | Duplicate -- comment added |
| SEC-C25 (Key not zeroed) | #104 [SEC-C06] + #111 [SEC-C07] -- same root cause | Duplicate -- comment added |
| SEC-C31 (spice pins main) | #107 [SEC-C14] -- identical finding | Duplicate -- comment added |
| SEC-C11 (Thread pool page_allocator) | [#112](https://gitlab.com/devnw/zig/dns/-/issues/112) -- overlaps PF-17 (thread pool GPA wrapper) | Cross-reference -- both resolved |
| SEC-C12 (IPv4 format undefined trailing bytes) | [#115](https://gitlab.com/devnw/zig/dns/-/issues/115) -- overlaps QH-03 (Formatted struct with len) | Cross-reference -- both resolved |
| SEC-NEW-01 / SEC-NEW-02 | Same root cause (missing rdlength bounds check) in sibling functions | Tracked separately: different files, different code paths |
| SEC-NEW-03 / SEC-NEW-06 | Related root cause (missing bounds checks in wire parser helpers) | Tracked separately: skipRR vs question-skip are distinct code |

### Remediation Roadmap

**Completed (previous cycles):**
- ~~SEC-C22~~: `outer:` label + `continue :outer` in connection_pool.zig -- **Resolved**
- ~~SEC-C30~~: Forward pointer rejection in dns_name.zig -- **Resolved**
- ~~SEC-C33~~: Read loop for 2-byte length prefix in zone_transfer.zig -- **Resolved**
- ~~SEC-C28~~: `require_auth` defaults to `true` -- **Resolved**
- ~~SEC-C26~~: `writeAll()` / `writeAllWithTimeout()` in 3 files -- **Resolved**
- ~~SEC-C23~~: HMAC key handling delegated to stdlib (RFC 2104) -- **Resolved**
- ~~SEC-C02~~: Non-exhaustive enums for sig0/tsig/record.zig -- **Resolved** (all enums confirmed non-exhaustive with `_` variant)
- ~~SEC-C05~~: `std.crypto.random` (OS CSPRNG) for all TXIDs -- **Resolved**
- ~~SEC-C27~~: `isSubdomainOf()` bailiwick validation -- **Resolved**
- ~~SEC-C06/C25~~: `secureZero` on key material -- **Resolved**

**Completed quick wins (commit 6d42d51):**
- ~~SEC-NEW-01~~: Bounds check added before `message[offset .. offset + rdlength]` in extractTsig -- **Resolved**
- ~~SEC-NEW-03~~: Bounds check `if (end > data.len) return error.InvalidRR` added in skipRR -- **Resolved**
- ~~SEC-NEW-06~~: Bounds check `if (offset + 4 > message.len) return error.InvalidMessage` before question skip -- **Resolved**
- ~~SEC-NEW-07~~: Bounds check `if (offset + 1 >= data.len) return error.InvalidName` for compression pointer -- **Resolved**
- ~~SEC-NEW-04~~: Returns `error.InvalidTsigRecord` instead of silently truncating other_data -- **Resolved**
- ~~SEC-C101~~: MAC verification now precedes time check; fudge clamped post-MAC -- **Resolved**
- ~~SEC-C100~~: Fudge clamped to `self.fudge * 2` after MAC verification -- **Resolved**

**Remaining quick wins:**
- SEC-NEW-02: Add `if (offset + rdlength > message.len) return error.InvalidMessage;` before sig0.zig:561
- SEC-NEW-05: Add bounds check before `@intCast` at edns.zig:167

**Remaining (backlog):**
- SEC-C29: SIG(0) replay cache (bounded data structure + time-based eviction) -- defense-in-depth
- SEC-C32: SIG(0) timestamp u32 overflow in 2106 -- low priority
- SEC-C14/C31: spice dependency pins main branch -- upstream concern

---

## Gap Priority Matrix

| Severity | Total | Resolved | Open | Gap-IDs / SEC-IDs |
|----------|-------|----------|------|-------------------|
| Critical | 2 | 2 | 0 | GAP-0027/SEC-C26, GAP-0028/SEC-C22 |
| High | 9 | 8 | 1 | **Resolved:** GAP-0026, GAP-0029, GAP-0030, GAP-0033/SEC-C20, GAP-0034/SEC-C21, SEC-C23, SEC-C05/C24, SEC-NEW-01. **Open:** SEC-NEW-02 |
| Medium | 16 | 13 | 3 | **Resolved:** GAP-0015 (partial), GAP-0031, GAP-0032, GAP-0035, GAP-0036, GAP-0037, SEC-C27, SEC-C28, SEC-C30, SEC-C06/C25, SEC-NEW-03, SEC-NEW-06, SEC-C100. **Open:** GAP-0017, SEC-C29, SEC-C14/C31 |
| Low | 11 | 9 | 2 | **Resolved:** GAP-0021, GAP-0022, GAP-0023, GAP-0024, GAP-0025, SEC-C33, SEC-NEW-07, SEC-C101, SEC-NEW-04. **Open:** SEC-NEW-05, SEC-C32 |

## Production Readiness Assessment

### Remaining Open Items

| Gap-ID / SEC-ID | Blocks Production Use? | Rationale |
|-----------------|----------------------|-----------|
| GAP-0015 | No (partially resolved) | Docs updated; tracker reconciliation is administrative |
| GAP-0017 | No (partially resolved) | Transports exposed in API; resolver wiring is future refactor |
| GAP-0037 | **Resolved** | Compression hop limit added to `toString()`, `labelCount()`, and `parent()` |
| SEC-NEW-01 | **Resolved** | Bounds check added in extractTsig (commit 6d42d51) |
| SEC-NEW-02 | **Recommended fix before production** | OOB read remotely triggerable via crafted SIG(0) response; one-line bounds check fix |
| SEC-NEW-03 | **Resolved** | Bounds check added in skipRR (commit 6d42d51) |
| SEC-NEW-06 | **Resolved** | Bounds check added before question skip (commit 6d42d51) |
| SEC-C100 | **Resolved** | Fudge clamped to 2x verifier fudge after MAC check (commit 6d42d51) |
| SEC-C29 | No (defense-in-depth) | Replay requires capture + time window; mitigated by short validity |
| SEC-C14/C31 | No (mitigated) | Hash pinning provides partial protection |
| SEC-NEW-07 | **Resolved** | Bounds check added for compression pointer (commit 6d42d51) |
| SEC-C101 | **Resolved** | MAC verification now precedes time check (commit 6d42d51) |
| SEC-NEW-04 | **Resolved** | Returns error instead of silently truncating (commit 6d42d51) |
| SEC-NEW-05 | No (low impact) | Requires > 64KB options, which is abnormal usage |
| SEC-C32 | No | Year 2106 issue |

### Production Blockers

~~GAP-0037~~ (compression loop DoS in `toString`/`labelCount`/`parent`) is now **resolved**. Seven of the nine adversarial-review findings are now resolved (commit 6d42d51). Only SEC-NEW-02 (OOB in extractSig0) remains as a recommended pre-production fix -- it is a one-line bounds check in `sig0.zig`. SEC-NEW-05 (intCast overflow in edns.zig) is low-priority. All Critical and High severity bugs have been resolved except SEC-NEW-02.
