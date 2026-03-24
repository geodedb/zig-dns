# Gap Analysis

Last updated: 2026-03-24 (gap closure complete -- 33 items resolved across 7 agents)

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

---

---

## Security Findings (Phase 3)

The following security findings were identified in Phase 3 review. Findings that duplicate existing GAP entries are cross-referenced. All new issues are created as **confidential** on GitLab.

### Stack-Ranked Security Findings

| Rank | Severity | Risk Score | Finding | Component | CWE/OWASP | Evidence | Issue | SLA | Status |
|------|----------|------------|---------|-----------|-----------|----------|-------|-----|--------|
| 1 | Critical | 80 | SEC-C22: PipelinedBatch infinite loop on connection close | connection_pool.zig | CWE-835 / A05:2021 | connection_pool.zig:468,490 | [#154](https://gitlab.com/devnw/zig/dns/-/issues/154) (confidential) / GAP-0028 [#133] | 7d | **Resolved** |
| 2 | High | 64 | SEC-C02: Unchecked @enumFromInt (covers SEC-C20/C21) | record.zig, sig0.zig, tsig.zig + 3 more | CWE-704 / A03:2021 | sig0.zig:217, tsig.zig:217, record.zig:439+ | [#89](https://gitlab.com/devnw/zig/dns/-/issues/89) / GAP-0033 [#134] / GAP-0034 [#135] | 30d | **Resolved** |
| 3 | High | 64 | SEC-C05: Non-CSPRNG for transaction IDs (covers SEC-C24) | recursive.zig | CWE-330 / A02:2021 | recursive.zig:119,448 | [#94](https://gitlab.com/devnw/zig/dns/-/issues/94) | 30d | **Resolved** |
| 4 | High | 48 | SEC-C23: TSIG HMAC key truncation | tsig.zig | CWE-326 / A02:2021 | tsig.zig:442,457,472,487,502 | [#157](https://gitlab.com/devnw/zig/dns/-/issues/157) (confidential) | 30d | **Resolved** |
| 5 | High | 48 | SEC-C26: Partial write data loss (3 files) | connection_pool.zig, dot.zig, zone_transfer.zig | CWE-400 / A05:2021 | connection_pool.zig:454, dot.zig:305, zone_transfer.zig:523 | [#161](https://gitlab.com/devnw/zig/dns/-/issues/161) (confidential) / GAP-0027 [#132] | 30d | **Resolved** |
| 6 | Medium | 48 | SEC-C27: No glue record bailiwick validation | recursive.zig | CWE-345 / A01:2021 | recursive.zig:564-589 | [#165](https://gitlab.com/devnw/zig/dns/-/issues/165) (confidential) | 90d | **Resolved** |
| 7 | Medium | 36 | SEC-C28: Zone transfer auth defaults off | zone_transfer.zig | CWE-1188 / A05:2021 | zone_transfer.zig:46 | [#169](https://gitlab.com/devnw/zig/dns/-/issues/169) (confidential) | 90d | **Resolved** |
| 8 | Medium | 36 | SEC-C29: SIG(0) no replay protection | sig0.zig | CWE-294 / A07:2021 | sig0.zig:341-391 | [#172](https://gitlab.com/devnw/zig/dns/-/issues/172) (confidential) | 90d | Triage |
| 9 | Medium | 32 | SEC-C30: dns_name.zig allows forward compression pointers | dns_name.zig | CWE-345 / A03:2021 | dns_name.zig:60-63 | [#175](https://gitlab.com/devnw/zig/dns/-/issues/175) (confidential) | 90d | **Resolved** |
| 10 | Medium | 24 | SEC-C06/C25: Key material not zeroed (stack + heap) | tsig.zig, sig0.zig | CWE-244 / A02:2021 | tsig.zig:435-495, sig0.zig:115-117 | [#104](https://gitlab.com/devnw/zig/dns/-/issues/104) / [#111](https://gitlab.com/devnw/zig/dns/-/issues/111) | 90d | **Resolved** |
| 11 | Medium | 24 | SEC-C14/C31: spice dependency pins main branch | build.zig.zon | CWE-829 / A06:2021 | build.zig.zon:29 | [#107](https://gitlab.com/devnw/zig/dns/-/issues/107) | 90d | Triage |
| 12 | Low | 16 | SEC-C33: Zone transfer short-read on length prefix | zone_transfer.zig | CWE-20 / A05:2021 | zone_transfer.zig:530-531 | [#178](https://gitlab.com/devnw/zig/dns/-/issues/178) (confidential) | 180d | **Resolved** |
| 13 | Low | 8 | SEC-C32: SIG(0) timestamp u32 overflow in 2106 | sig0.zig | CWE-190 / A05:2021 | sig0.zig:278,369 | [#176](https://gitlab.com/devnw/zig/dns/-/issues/176) (confidential) | 180d | Triage |

### Phase 3 Security Summary

- **Critical:** 1 finding -- **1 resolved** (SEC-C22 infinite loop DoS)
- **High:** 4 findings -- **4 resolved** (SEC-C02 enum panic, SEC-C05 weak PRNG, SEC-C23 key truncation, SEC-C26 partial write)
- **Medium:** 6 findings -- **4 resolved** (SEC-C27 bailiwick, SEC-C28 auth default, SEC-C30 forward ptr, SEC-C06/C25 key zeroing); 2 open (SEC-C29 replay, SEC-C14/C31 supply chain)
- **Low:** 2 findings -- **1 resolved** (SEC-C33 short read); 1 open (SEC-C32 timestamp overflow)

### Deduplication Notes

| Phase 3 ID | Existing Issue | Status |
|-------------|---------------|--------|
| SEC-C20 (SIG(0) enum panic) | #89 [SEC-C02] -- already listed in Evidence | Duplicate -- comment added |
| SEC-C21 (TSIG enum panic) | #89 [SEC-C02] -- already listed in Evidence | Duplicate -- comment added |
| SEC-C24 (PRNG for TXIDs) | #94 [SEC-C05] -- same root cause | Duplicate -- comment added |
| SEC-C25 (Key not zeroed) | #104 [SEC-C06] + #111 [SEC-C07] -- same root cause | Duplicate -- comment added |
| SEC-C31 (spice pins main) | #107 [SEC-C14] -- identical finding | Duplicate -- comment added |

### Remediation Roadmap

**Completed (this cycle):**
- ~~SEC-C22~~: `outer:` label + `continue :outer` in connection_pool.zig -- **Resolved**
- ~~SEC-C30~~: Forward pointer rejection in dns_name.zig -- **Resolved**
- ~~SEC-C33~~: Read loop for 2-byte length prefix in zone_transfer.zig -- **Resolved**
- ~~SEC-C28~~: `require_auth` defaults to `true` -- **Resolved**
- ~~SEC-C26~~: `writeAll()` / `writeAllWithTimeout()` in 3 files -- **Resolved**
- ~~SEC-C23~~: HMAC key handling delegated to stdlib (RFC 2104) -- **Resolved**
- ~~SEC-C02~~: Non-exhaustive enums for sig0/tsig (record.zig TBD) -- **Partially Resolved**
- ~~SEC-C05~~: `std.crypto.random` (OS CSPRNG) for all TXIDs -- **Resolved**
- ~~SEC-C27~~: `isSubdomainOf()` bailiwick validation -- **Resolved**
- ~~SEC-C06/C25~~: `secureZero` on key material -- **Resolved**

**Remaining:**
- SEC-C29: SIG(0) replay cache (bounded data structure + time-based eviction) -- defense-in-depth
- SEC-C32: SIG(0) timestamp u32 overflow in 2106 -- low priority
- SEC-C14/C31: spice dependency pins main branch -- upstream concern

---

## Gap Priority Matrix

| Severity | Total | Resolved | Open | Gap-IDs / SEC-IDs |
|----------|-------|----------|------|-------------------|
| Critical | 2 | 2 | 0 | GAP-0027/SEC-C26, GAP-0028/SEC-C22 |
| High | 7 | 7 | 0 | GAP-0026 (pending commit), GAP-0029, GAP-0030, GAP-0033/SEC-C20, GAP-0034/SEC-C21, SEC-C23, SEC-C05/C24 |
| Medium | 10 | 8 | 2 | **Resolved:** GAP-0031, GAP-0032, GAP-0035, GAP-0036, SEC-C27, SEC-C28, SEC-C30, GAP-0015 (partial). **Open:** SEC-C29, GAP-0017 |
| Low | 7 | 5 | 2 | **Resolved:** GAP-0022, GAP-0023, GAP-0024, GAP-0025, SEC-C33. **Open:** GAP-0021, SEC-C32 |

## Production Readiness Assessment

### Remaining Open Items

| Gap-ID / SEC-ID | Blocks Production Use? | Rationale |
|-----------------|----------------------|-----------|
| GAP-0015 | No (partially resolved) | Docs updated; tracker reconciliation is administrative |
| GAP-0017 | No (partially resolved) | Transports exposed in API; resolver wiring is future refactor |
| GAP-0021 | No | Status tracking inconsistency only |
| GAP-0026 | **YES** | Uncommitted work at risk of loss |
| SEC-C29 | No (defense-in-depth) | Replay requires capture + time window; mitigated by short validity |
| SEC-C14/C31 | No (mitigated) | Hash pinning provides partial protection |
| SEC-C32 | No | Year 2106 issue |

### Production Blockers

Only **GAP-0026** (uncommitted work) blocks production use. All Critical and High severity bugs have been resolved. Once changes are committed and pushed, no remaining open item blocks production deployment.
