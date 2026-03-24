# Gap Analysis

Last updated: 2026-03-24 (adversarial security review -- 9 new findings added, 36 items resolved, 15 open)

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

### GAP-0037: Name.toString() missing compression hop limit -- **RESOLVED**
- **Issue:** (not yet filed -- skip-issues mode)
- **Category:** Security
- **Severity:** Medium
- **Status:** Resolved (2026-03-24)
- **Requirement source:** CWE-835 (Loop with Unreachable Exit Condition); RFC 1035 Section 4.1.4 (message compression)
- **Resolution:** Added `pointer_hops` counter with `max_compression_hops` check to `toString()`, `labelCount()`, and `parent()` in `src/name.zig`, matching the pattern already used in `toStringBuf()` and `eql()`. `labelCount()` return type changed from `usize` to `error{CompressionLoopDetected}!usize`. Three security tests added verifying all three methods detect self-referencing compression pointers (`0xC0, 0x00`) and return `error.CompressionLoopDetected`.
- **Acceptance criteria:**
  - [x] `toString()` returns `error.CompressionLoopDetected` after exceeding `max_compression_hops`
  - [x] `labelCount()` returns `error.CompressionLoopDetected` after exceeding `max_compression_hops`
  - [x] `parent()` returns `error.CompressionLoopDetected` after exceeding `max_compression_hops`
  - [x] Tests verify infinite-loop protection for all three methods with self-referencing compression pointers

---

## Security Findings (Phase 3 + Adversarial Review)

The following security findings were identified in Phase 3 review and the subsequent adversarial security review (2026-03-24). Findings that duplicate existing GAP entries are cross-referenced. All new issues are created as **confidential** on GitLab.

### Stack-Ranked Security Findings

| Rank | Severity | Risk Score | Finding | Component | CWE/OWASP | Evidence | Issue | SLA | Status |
|------|----------|------------|---------|-----------|-----------|----------|-------|-----|--------|
| 1 | Critical | 80 | SEC-C22: PipelinedBatch infinite loop on connection close | connection_pool.zig | CWE-835 / A05:2021 | connection_pool.zig:468,490 | [#154](https://gitlab.com/devnw/zig/dns/-/issues/154) (confidential) / GAP-0028 [#133] | 7d | **Resolved** |
| 2 | High | 64 | SEC-NEW-01: OOB read in extractTsig -- rdlength not validated before slice | tsig.zig | CWE-125 / A03:2021 | tsig.zig:626 | Pending | 30d | Triage |
| 3 | High | 64 | SEC-NEW-02: OOB read in extractSig0 -- rdlength not validated before slice | sig0.zig | CWE-125 / A03:2021 | sig0.zig:561 | Pending | 30d | Triage |
| 4 | High | 64 | SEC-C02: Unchecked @enumFromInt (covers SEC-C20/C21) | record.zig, sig0.zig, tsig.zig + 3 more | CWE-704 / A03:2021 | sig0.zig:217, tsig.zig:217, record.zig:439+ | [#89](https://gitlab.com/devnw/zig/dns/-/issues/89) / GAP-0033 [#134] / GAP-0034 [#135] | 30d | **Resolved** |
| 5 | High | 64 | SEC-C05: Non-CSPRNG for transaction IDs (covers SEC-C24) | recursive.zig | CWE-330 / A02:2021 | recursive.zig:119,448 | [#94](https://gitlab.com/devnw/zig/dns/-/issues/94) | 30d | **Resolved** |
| 6 | High | 48 | SEC-C23: TSIG HMAC key truncation | tsig.zig | CWE-326 / A02:2021 | tsig.zig:442,457,472,487,502 | [#157](https://gitlab.com/devnw/zig/dns/-/issues/157) (confidential) | 30d | **Resolved** |
| 7 | High | 48 | SEC-C26: Partial write data loss (3 files) | connection_pool.zig, dot.zig, zone_transfer.zig | CWE-400 / A05:2021 | connection_pool.zig:454, dot.zig:305, zone_transfer.zig:523 | [#161](https://gitlab.com/devnw/zig/dns/-/issues/161) (confidential) / GAP-0027 [#132] | 30d | **Resolved** |
| 8 | Medium | 48 | SEC-NEW-03: skipRR returns offset+10+rdlength without bounds check | dns_name.zig | CWE-125 / A03:2021 | dns_name.zig:112 | Pending | 90d | Triage |
| 9 | Medium | 48 | SEC-NEW-06: Question skip adds +4 without bounds check | tsig.zig, sig0.zig | CWE-125 / A03:2021 | tsig.zig:587, sig0.zig:523 | Pending | 90d | Triage |
| 10 | Medium | 48 | SEC-C27: No glue record bailiwick validation | recursive.zig | CWE-345 / A01:2021 | recursive.zig:564-589 | [#165](https://gitlab.com/devnw/zig/dns/-/issues/165) (confidential) | 90d | **Resolved** |
| 11 | Medium | 36 | SEC-C28: Zone transfer auth defaults off | zone_transfer.zig | CWE-1188 / A05:2021 | zone_transfer.zig:46 | [#169](https://gitlab.com/devnw/zig/dns/-/issues/169) (confidential) | 90d | **Resolved** |
| 12 | Medium | 36 | SEC-C29: SIG(0) no replay protection | sig0.zig | CWE-294 / A07:2021 | sig0.zig:341-391 | [#172](https://gitlab.com/devnw/zig/dns/-/issues/172) (confidential) | 90d | Triage |
| 13 | Medium | 32 | SEC-C30: dns_name.zig allows forward compression pointers | dns_name.zig | CWE-345 / A03:2021 | dns_name.zig:60-63 | [#175](https://gitlab.com/devnw/zig/dns/-/issues/175) (confidential) | 90d | **Resolved** |
| 14 | Medium | 24 | SEC-C100: TSIG fudge value attacker-controlled (defense-in-depth) | tsig.zig | CWE-807 / A04:2021 | tsig.zig:355 | Pending | 90d | Triage |
| 15 | Medium | 24 | SEC-C06/C25: Key material not zeroed (stack + heap) | tsig.zig, sig0.zig | CWE-244 / A02:2021 | tsig.zig:435-495, sig0.zig:115-117 | [#104](https://gitlab.com/devnw/zig/dns/-/issues/104) / [#111](https://gitlab.com/devnw/zig/dns/-/issues/111) | 90d | **Resolved** |
| 16 | Medium | 24 | SEC-C14/C31: spice dependency pins main branch | build.zig.zon | CWE-829 / A06:2021 | build.zig.zon:29 | [#107](https://gitlab.com/devnw/zig/dns/-/issues/107) | 90d | Triage |
| 17 | Low | 24 | SEC-NEW-07: skipName compression pointer returns offset+2 without checking offset+1 < data.len | dns_name.zig | CWE-125 / A03:2021 | dns_name.zig:100 | Pending | 180d | Triage |
| 18 | Low | 16 | SEC-C101: TSIG time check before MAC creates timing oracle | tsig.zig | CWE-208 / A02:2021 | tsig.zig:348-387 | Pending | 180d | Triage |
| 19 | Low | 16 | SEC-NEW-04: TSIG other_data silently truncated when other_len exceeds available data | tsig.zig | CWE-130 / A03:2021 | tsig.zig:229 | Pending | 180d | Triage |
| 20 | Low | 16 | SEC-NEW-05: @intCast(u16) on options.len without bounds check | edns.zig | CWE-190 / A03:2021 | edns.zig:167 | Pending | 180d | Triage |
| 21 | Low | 16 | SEC-C33: Zone transfer short-read on length prefix | zone_transfer.zig | CWE-20 / A05:2021 | zone_transfer.zig:530-531 | [#178](https://gitlab.com/devnw/zig/dns/-/issues/178) (confidential) | 180d | **Resolved** |
| 22 | Low | 8 | SEC-C32: SIG(0) timestamp u32 overflow in 2106 | sig0.zig | CWE-190 / A05:2021 | sig0.zig:278,369 | [#176](https://gitlab.com/devnw/zig/dns/-/issues/176) (confidential) | 180d | Triage |

### Adversarial Review Finding Details

#### SEC-NEW-01 (HIGH): OOB read in extractTsig -- rdlength not validated before slice

- **Summary:** `extractTsig` reads `rdlength` from the wire message and immediately uses it to slice `message[offset .. offset + rdlength]` without verifying `offset + rdlength <= message.len`. A crafted DNS response with an inflated `rdlength` causes an out-of-bounds read.
- **Impact:** Remotely triggerable crash (safety-checked build: panic; release build: memory disclosure). Any DNS peer that sends a TSIG-signed response can trigger this.
- **Likelihood:** High (4/5). Pre-auth, remote, any DNS peer can send a crafted response. No authentication required.
- **Evidence:** `tsig.zig:626` -- `message[offset .. offset + rdlength]` with no prior bounds check on rdlength vs remaining message length.
- **Attack scenario:** Attacker sends a DNS response with a TSIG record whose `rdlength` field exceeds the actual remaining message bytes. The victim's TSIG verification code reads past the buffer boundary.
- **Fix guidance:** Add bounds check before the slice: `if (offset + rdlength > message.len) return error.InvalidMessage;`
- **Acceptance criteria:** (1) Bounds check added before `message[offset .. offset + rdlength]`. (2) Fuzz test or unit test with a truncated TSIG record triggers `error.InvalidMessage` instead of panic.
- **References:** CWE-125 (Out-of-bounds Read), OWASP A03:2021 (Injection). Exploit surface: internet-facing (any DNS response path).
- **Risk score:** 64 (Impact 4 x Likelihood 4 x 4)
- **Confidence:** `confidence::confirmed` -- code path verified by inspection.

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

#### SEC-NEW-03 (MEDIUM): skipRR returns offset+10+rdlength without bounds check

- **Summary:** `skipRR` in `dns_name.zig` reads `rdlength` from the wire and returns `offset + 10 + rdlength` without verifying the result is within `data.len`. Callers use the returned offset for subsequent reads, leading to out-of-bounds access on crafted input.
- **Impact:** Crash on safety-checked builds; potential memory disclosure on release builds. Affects any code path that parses DNS records using `skipRR`.
- **Likelihood:** High (4/5). Remotely triggerable via any crafted DNS message with inflated rdlength in answer/authority/additional sections.
- **Evidence:** `dns_name.zig:112` -- `return offset + 10 + rdlength;` with only `offset + 10 > data.len` checked, not `offset + 10 + rdlength > data.len`.
- **Fix guidance:** Add: `if (offset + 10 + rdlength > data.len) return error.InvalidRR;`
- **Acceptance criteria:** (1) Bounds check covers rdlength. (2) Test with truncated RR triggers error.
- **References:** CWE-125, OWASP A03:2021. Exploit surface: internet-facing.
- **Risk score:** 48 (Impact 3 x Likelihood 4 x 4)
- **Confidence:** `confidence::confirmed` -- code path verified by inspection.

#### SEC-NEW-06 (MEDIUM): Question skip adds +4 without bounds check

- **Summary:** In both `extractTsig` (tsig.zig:587) and `extractSig0` (sig0.zig:523), the question-skipping loop does `offset += 4` (for QTYPE + QCLASS) after `skipName` without checking `offset + 4 <= message.len`. A crafted message with a question section that ends at the buffer boundary causes out-of-bounds access.
- **Impact:** Crash or memory disclosure. Affects TSIG and SIG(0) verification paths.
- **Likelihood:** High (4/5). Remotely triggerable; attacker controls qdcount and message content.
- **Evidence:** `tsig.zig:587` -- `offset += 4;` and `sig0.zig:523` -- `offset += 4;` with no prior bounds check.
- **Fix guidance:** Add `if (offset + 4 > message.len) return error.InvalidMessage;` before the `+= 4`.
- **Acceptance criteria:** (1) Bounds check before each `+= 4`. (2) Test with truncated question section triggers error.
- **References:** CWE-125, OWASP A03:2021. Exploit surface: internet-facing.
- **Risk score:** 48 (Impact 3 x Likelihood 4 x 4)
- **Confidence:** `confidence::confirmed` -- code path verified by inspection.

#### SEC-C100 (MEDIUM): TSIG fudge value attacker-controlled (defense-in-depth)

- **Summary:** TSIG time validation at `tsig.zig:355` uses the `fudge` value from the incoming TSIG record (attacker-controlled) to determine the acceptable time window: `if (time_diff > tsig.fudge)`. While RFC 2845 specifies this behavior, an attacker can set `fudge` to its maximum (65535 seconds / ~18 hours) to widen the replay window.
- **Impact:** Widens the TSIG replay/acceptance window from the expected value (typically 300s) to up to 18 hours. This degrades the time-based anti-replay protection.
- **Likelihood:** Low (2/5). Requires the attacker to intercept and modify a TSIG-signed message while also having a valid MAC (or exploiting a separate MAC bypass). The fudge alone does not bypass authentication.
- **Evidence:** `tsig.zig:355` -- `if (time_diff > tsig.fudge)` uses attacker-supplied fudge.
- **Fix guidance:** Clamp the accepted fudge to a server-configured maximum (e.g., `const effective_fudge = @min(tsig.fudge, self.max_fudge);`). Default max_fudge to 300 seconds per common practice.
- **Acceptance criteria:** (1) Fudge clamped to configurable maximum. (2) Test that excessive fudge values are rejected.
- **References:** CWE-807 (Reliance on Untrusted Inputs in a Security Decision), OWASP A04:2021 (Insecure Design). RFC 2845 Section 4.5.1.
- **Risk score:** 24 (Impact 3 x Likelihood 2 x 4)
- **Confidence:** `confidence::confirmed` -- RFC-compliant but defense-in-depth concern.

#### SEC-C101 (LOW): TSIG time check before MAC creates timing oracle

- **Summary:** In `tsig.zig:348-387`, the TSIG verification checks the time window (`time_diff > tsig.fudge`) before verifying the MAC. This means a `bad_time` error is returned for time-expired messages without first confirming the MAC is valid. An attacker can distinguish between "time expired" and "bad signature" responses, creating a timing oracle.
- **Impact:** Information leak -- attacker can determine whether a message's timestamp is within the acceptable window without needing a valid key. Limited practical impact because the MAC still blocks authentication bypass.
- **Likelihood:** Low (2/5). Requires network observation of error responses. Does not directly enable authentication bypass.
- **Evidence:** `tsig.zig:348-357` (time check) precedes `tsig.zig:359-387` (MAC computation and comparison). RFC 2845 Section 4.3.3 recommends verifying MAC before time.
- **Fix guidance:** Reorder verification: compute and verify MAC first, then check time validity. Return `bad_sig` for MAC failures regardless of time status.
- **Acceptance criteria:** (1) MAC verification precedes time check. (2) Time-expired messages with invalid MACs return `bad_sig`, not `bad_time`.
- **References:** CWE-208 (Observable Timing Discrepancy), OWASP A02:2021 (Cryptographic Failures). RFC 2845 Section 4.3.3.
- **Risk score:** 16 (Impact 2 x Likelihood 2 x 4)
- **Confidence:** `confidence::confirmed` -- verification order confirmed by code inspection.

#### SEC-NEW-04 (LOW): TSIG other_data silently truncated

- **Summary:** At `tsig.zig:229`, when `other_len > 0` but `offset + other_len > rdata.len`, the `other_data` field is silently set to an empty slice instead of returning an error. This means a malformed TSIG record with an inflated `other_len` is accepted with truncated data rather than rejected.
- **Impact:** Data integrity -- silently consuming malformed TSIG records may mask protocol errors or allow subtle manipulation of TSIG error reporting (other_data carries server time in BADTIME responses).
- **Likelihood:** Low (2/5). Requires crafted TSIG record. The truncated other_data primarily affects BADTIME error handling.
- **Evidence:** `tsig.zig:229` -- `if (other_len > 0 and offset + other_len <= rdata.len)` silently falls through when condition is false.
- **Fix guidance:** Return `error.InvalidTsig` when `offset + other_len > rdata.len` instead of silently truncating.
- **Acceptance criteria:** (1) Error returned for inconsistent other_len. (2) Test with inflated other_len triggers error.
- **References:** CWE-130 (Improper Handling of Inconsistent Structural Elements), OWASP A03:2021.
- **Risk score:** 16 (Impact 2 x Likelihood 2 x 4)
- **Confidence:** `confidence::confirmed` -- silent truncation verified by code inspection.

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

#### SEC-NEW-07 (LOW): skipName compression pointer returns offset+2 without checking offset+1 < data.len

- **Summary:** At `dns_name.zig:100`, when a compression pointer is detected (`len & 0xC0 == 0xC0`), the function returns `offset + 2` without verifying that `offset + 1 < data.len`. While `data[offset]` is valid (checked by the loop condition), the second byte of the compression pointer at `data[offset + 1]` is never read by `skipName` itself -- but returning `offset + 2` when only one byte remains means the returned offset could equal `data.len + 1`, which is past the valid range.
- **Impact:** The off-by-one returned offset could cause callers to read one byte past the buffer when they use the returned offset. Safe builds would panic; release builds would read one byte of adjacent memory.
- **Likelihood:** Medium (3/5). Remotely triggerable if a crafted DNS message has a compression pointer as the last byte.
- **Evidence:** `dns_name.zig:100` -- `if (len & 0xC0 == 0xC0) return offset + 2;` with loop condition only guaranteeing `offset < data.len`.
- **Fix guidance:** Add: `if (offset + 1 >= data.len) return error.InvalidName;` before returning `offset + 2`.
- **Acceptance criteria:** (1) Bounds check for second byte of compression pointer. (2) Test with compression pointer at buffer end triggers error.
- **References:** CWE-125, OWASP A03:2021.
- **Risk score:** 24 (Impact 2 x Likelihood 3 x 4)
- **Confidence:** `confidence::confirmed` -- off-by-one verified by code inspection.

### Phase 3 + Adversarial Review Security Summary

- **Critical:** 1 finding -- **1 resolved** (SEC-C22 infinite loop DoS)
- **High:** 6 findings -- **4 resolved** (SEC-C02 enum panic, SEC-C05 weak PRNG, SEC-C23 key truncation, SEC-C26 partial write); **2 open** (SEC-NEW-01 OOB in extractTsig, SEC-NEW-02 OOB in extractSig0)
- **Medium:** 9 findings -- **4 resolved** (SEC-C27 bailiwick, SEC-C28 auth default, SEC-C30 forward ptr, SEC-C06/C25 key zeroing); **5 open** (SEC-NEW-03 skipRR bounds, SEC-NEW-06 question skip bounds, SEC-C100 fudge, SEC-C29 replay, SEC-C14/C31 supply chain)
- **Low:** 6 findings -- **1 resolved** (SEC-C33 short read); **5 open** (SEC-NEW-07 skipName ptr, SEC-C101 timing oracle, SEC-NEW-04 other_data truncation, SEC-NEW-05 intCast overflow, SEC-C32 timestamp overflow)

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

**Quick wins (< 1 day) -- from adversarial review:**
- SEC-NEW-01: Add `if (offset + rdlength > message.len) return error.InvalidMessage;` before tsig.zig:626
- SEC-NEW-02: Add `if (offset + rdlength > message.len) return error.InvalidMessage;` before sig0.zig:561
- SEC-NEW-03: Add `if (offset + 10 + rdlength > data.len) return error.InvalidRR;` in dns_name.zig:112
- SEC-NEW-06: Add `if (offset + 4 > message.len) return error.InvalidMessage;` before `offset += 4` in tsig.zig:587 and sig0.zig:523
- SEC-NEW-07: Add `if (offset + 1 >= data.len) return error.InvalidName;` before dns_name.zig:100
- SEC-NEW-04: Return error instead of silently truncating other_data at tsig.zig:229
- SEC-NEW-05: Add bounds check before `@intCast` at edns.zig:167

**Medium effort (1-5 days):**
- SEC-C101: Reorder TSIG verification to check MAC before time (tsig.zig:348-387)
- SEC-C100: Add configurable max_fudge clamp for TSIG time validation (tsig.zig:355)
- SEC-C29: SIG(0) replay cache (bounded data structure + time-based eviction) -- defense-in-depth

**Remaining (backlog):**
- SEC-C32: SIG(0) timestamp u32 overflow in 2106 -- low priority
- SEC-C14/C31: spice dependency pins main branch -- upstream concern

---

## Gap Priority Matrix

| Severity | Total | Resolved | Open | Gap-IDs / SEC-IDs |
|----------|-------|----------|------|-------------------|
| Critical | 2 | 2 | 0 | GAP-0027/SEC-C26, GAP-0028/SEC-C22 |
| High | 9 | 7 | 2 | **Resolved:** GAP-0026, GAP-0029, GAP-0030, GAP-0033/SEC-C20, GAP-0034/SEC-C21, SEC-C23, SEC-C05/C24. **Open:** SEC-NEW-01, SEC-NEW-02 |
| Medium | 16 | 10 | 6 | **Resolved:** GAP-0015 (partial), GAP-0031, GAP-0032, GAP-0035, GAP-0036, GAP-0037, SEC-C27, SEC-C28, SEC-C30, SEC-C06/C25. **Open:** GAP-0017, SEC-NEW-03, SEC-NEW-06, SEC-C100, SEC-C29, SEC-C14/C31 |
| Low | 11 | 6 | 5 | **Resolved:** GAP-0021, GAP-0022, GAP-0023, GAP-0024, GAP-0025, SEC-C33. **Open:** SEC-NEW-07, SEC-C101, SEC-NEW-04, SEC-NEW-05, SEC-C32 |

## Production Readiness Assessment

### Remaining Open Items

| Gap-ID / SEC-ID | Blocks Production Use? | Rationale |
|-----------------|----------------------|-----------|
| GAP-0015 | No (partially resolved) | Docs updated; tracker reconciliation is administrative |
| GAP-0017 | No (partially resolved) | Transports exposed in API; resolver wiring is future refactor |
| GAP-0037 | **Resolved** | Compression hop limit added to `toString()`, `labelCount()`, and `parent()` |
| SEC-NEW-01 | **Recommended fix before production** | OOB read remotely triggerable by any DNS peer via crafted TSIG response; one-line bounds check fix |
| SEC-NEW-02 | **Recommended fix before production** | OOB read remotely triggerable via crafted SIG(0) response; one-line bounds check fix |
| SEC-NEW-03 | **Recommended fix before production** | OOB via skipRR on crafted response; one-line bounds check fix |
| SEC-NEW-06 | **Recommended fix before production** | OOB via question skip on crafted message; one-line bounds check fix |
| SEC-C100 | No (defense-in-depth) | Requires valid MAC to exploit; fudge clamp is hardening |
| SEC-C29 | No (defense-in-depth) | Replay requires capture + time window; mitigated by short validity |
| SEC-C14/C31 | No (mitigated) | Hash pinning provides partial protection |
| SEC-NEW-07 | No (low impact) | Off-by-one on compression pointer; low probability trigger |
| SEC-C101 | No (defense-in-depth) | Timing oracle does not bypass authentication |
| SEC-NEW-04 | No (low impact) | Silent truncation; affects BADTIME error handling only |
| SEC-NEW-05 | No (low impact) | Requires > 64KB options, which is abnormal usage |
| SEC-C32 | No | Year 2106 issue |

### Production Blockers

~~GAP-0037~~ (compression loop DoS in `toString`/`labelCount`/`parent`) is now **resolved**. The four adversarial-review OOB findings (SEC-NEW-01, SEC-NEW-02, SEC-NEW-03, SEC-NEW-06) are recommended to be fixed before production deployment. All four are quick wins -- each requires a single bounds-check line. All Critical and previously-known High severity bugs have been resolved; the two new High findings (SEC-NEW-01, SEC-NEW-02) are in triage with straightforward fixes.
