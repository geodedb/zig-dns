# Gap Analysis

Last updated: 2026-03-24 (Phase 3 adversarial review: 4 new gaps, 14 new security findings merged into unified table; 9 "Unknown" items verified resolved)

> **4 open gaps** and **14 new security findings** identified in Phase 3 adversarial review. Won't-Do and resolved items are in [GAP_ANALYSIS_RESOLVED.md](GAP_ANALYSIS_RESOLVED.md).

## Gaps

### GAP-0048: RPZ wildcard boundary bypass test missing
- **Issue:** (not yet filed)
- **Category:** Test
- **Severity:** Low
- **Requirement source:** src/resolver/rpz.zig:381-386 -- wildcard boundary fix present but untested
- **Current state (evidence):**
  - `src/resolver/rpz.zig:381-386` -- code fix distinguishes `*example.com` vs `fakeexample.com` but no test exercises the bypass scenario
- **Why this is a gap:** The wildcard boundary fix lacks regression test coverage; a future refactor could silently reintroduce the bypass.
- **Impact/Risk:** RPZ wildcard matching could allow domain bypass if the boundary check regresses.
- **Recommended fix:** Add test assertions that verify `*example.com` matches `sub.example.com` but NOT `fakeexample.com`.
- **Acceptance criteria:**
  - [ ] Test exists that asserts `*example.com` does not match `fakeexample.com`
  - [ ] Test exists that asserts `*example.com` matches `sub.example.com`

---

### GAP-0049: DNSSEC canonical RRset sorting not implemented (RFC 4034 S6.3)
- **Issue:** (not yet filed)
- **Category:** Bug
- **Severity:** Medium
- **Requirement source:** RFC 4034 Section 6.3 -- canonical RRset ordering required for RRSIG verification
- **Current state (evidence):**
  - `src/resolver/dnssec.zig:409` -- comment says "A full implementation would sort here"; RRsets not sorted before RRSIG verification
- **Why this is a gap:** RRSIG verification may produce incorrect results for multi-record RRsets because canonical ordering is not enforced per RFC 4034 S6.3.
- **Impact/Risk:** DNSSEC validation failures on legitimate zones with multiple records in an RRset; false BOGUS results.
- **Recommended fix:** Implement canonical RRset sorting (RFC 4034 S6.3) before RRSIG wire-format construction.
- **Acceptance criteria:**
  - [ ] RRsets are sorted in canonical order before RRSIG verification
  - [ ] Test with multi-record RRset verifies correct RRSIG validation after sorting

---

### GAP-0050: RFC_COMPLIANCE.md claims "Complete" for RFC 4033/4034 but RSA missing
- **Issue:** (not yet filed)
- **Category:** Docs
- **Severity:** Low
- **Requirement source:** docs/RFC_COMPLIANCE.md:53-79 vs README.md
- **Current state (evidence):**
  - `docs/RFC_COMPLIANCE.md:53-79` -- RFC 4033/4034 listed as "Complete"
  - `README.md` -- correctly says "Partial**" with RSA caveat
- **Why this is a gap:** Inconsistency between RFC_COMPLIANCE.md ("Complete") and README.md ("Partial") for DNSSEC RFCs. RSA algorithms (8/10/5) are not implemented (GAP-0013).
- **Impact/Risk:** Users consulting RFC_COMPLIANCE.md will incorrectly believe full DNSSEC is implemented.
- **Recommended fix:** Update RFC_COMPLIANCE.md RFC 4033/4034 entries to "Partial" with note "Ed25519/ECDSA complete, RSA pending".
- **Acceptance criteria:**
  - [ ] RFC_COMPLIANCE.md RFC 4033/4034 status says "Partial" with RSA caveat
  - [ ] Consistent with README.md and ROADMAP.md

---

### GAP-0051: DoQ feature gate blocks all DoQ tests in CI
- **Issue:** (not yet filed)
- **Category:** CI-CD
- **Severity:** Low
- **Requirement source:** build.zig:14, .gitlab-ci.yml
- **Current state (evidence):**
  - `build.zig:14` -- DoQ is behind `-Dfeature_doq=true` feature gate
  - `.gitlab-ci.yml` -- CI never passes `-Dfeature_doq=true`
- **Why this is a gap:** DoQ transport code is never compiled or tested in CI. Any regressions in DoQ code would go undetected.
- **Impact/Risk:** DoQ transport may silently break without CI detection.
- **Recommended fix:** Defer -- requires QUIC dependencies. Document as known limitation.
- **Acceptance criteria:**
  - [ ] CI pipeline includes a DoQ build/test stage, OR limitation is documented in CI configuration comments

---

### GAP-0015: 24 issues marked Complete in docs but Open in GitLab tracker -- **WON'T DO**
- **Issue:** [#78](https://gitlab.com/devnw/zig/dns/-/issues/78)
- **Category:** Bug
- **Severity:** Medium
- **Status:** **Won't Do** -- Docs-side is resolved. GitLab issue closure requires admin action and is outside the scope of code-level gap closure.
- **Reason:** Administrative tracker reconciliation; code and docs are accurate.

---

### GAP-0017: Functional UDP/TCP transports suppressed from public API -- **WON'T DO**
- **Issue:** [#80](https://gitlab.com/devnw/zig/dns/-/issues/80)
- **Category:** Feature
- **Severity:** Medium
- **Status:** **Won't Do** -- Transport modules are exposed in public API (GAP-0011 resolved). Wiring resolvers to use transport abstractions requires significant architectural refactoring.
- **Reason:** Architectural refactor outside scope. Inline socket code works correctly. Cross-ref GAP-0044, QC-NEW-03.

---

### GAP-0038: README "Zero Dependencies" claim is inaccurate -- **RESOLVED**
- **Issue:** (not filed -- skip-issues mode)
- **Category:** Docs
- **Severity:** Medium
- **Status:** **Resolved** (2026-03-24). README.md updated to say "Minimal Dependencies" with distinction between runtime and test-only dependencies.
- **Evidence:** `README.md` -- dependency claim updated to match `build.zig.zon` manifest
- **Resolved date:** 2026-03-24

---

### GAP-0039: README RFC 4033/4034/4035 says "Complete" -- RSA missing, should say Partial -- **RESOLVED**
- **Issue:** (not filed -- skip-issues mode)
- **Category:** Docs
- **Severity:** Medium
- **Status:** **Resolved** (2026-03-24). README RFC table updated to "Partial" with RSA caveat note: "Ed25519/ECDSA complete, RSA pending".
- **Evidence:** `README.md` -- RFC 4033/4034/4035 status says "Partial"; consistent with ROADMAP.md Phase 3
- **Resolved date:** 2026-03-24

---

### GAP-0040: README RFC 7858 DoT listed "Complete" without asterisk -- **RESOLVED**
- **Issue:** (not filed -- skip-issues mode)
- **Category:** Docs
- **Severity:** Low
- **Status:** **Resolved** (2026-03-24). Added footnote to README RFC 7858 entry noting "Interface only -- requires external TLS backend", consistent with DoH/DoQ treatment and GAP-0014 documentation.
- **Evidence:** `README.md` -- RFC 7858 entry has interface-only annotation
- **Resolved date:** 2026-03-24

---

### GAP-0041: Convenience API stubs return error.NotImplemented -- **WON'T DO**
- **Issue:** (not filed -- skip-issues mode)
- **Category:** Feature
- **Severity:** Medium
- **Status:** **Won't Do** -- Functions return explicit `error.NotImplemented` (improved from silent empty returns in QH-NEW-01). `client.Client` is the documented working alternative.
- **Reason:** Feature addition outside scope. Convenience API returns explicit errors; `client.Client` provides all functionality.

---

### GAP-0042: Client API missing lookupSRV/TXT/PTR/NS/SOA methods -- **WON'T DO**
- **Issue:** (not filed -- skip-issues mode)
- **Category:** Feature
- **Severity:** Medium
- **Status:** **Won't Do** -- Feature addition outside scope. Raw query API (`resolve()`) works for all record types. Cache now correctly formats 9 record types (GAP-0043 resolved).
- **Reason:** New feature development; raw query API provides full access to all record types.

---

### GAP-0043: Cache hit only formats A/AAAA -- MX/SRV/TXT cache hits return empty -- **RESOLVED**
- **Issue:** (not filed -- skip-issues mode)
- **Category:** Bug
- **Severity:** Medium
- **Status:** **Resolved** (2026-03-24). Added `formatCachedRdata` function in `client.zig` that handles 9 record types (A, AAAA, MX, SRV, TXT, PTR, NS, SOA, CNAME) on cache hit path. No record type silently returns empty on cache hit. Cross-ref QM-NEW-03 in QUALITY_GAP_ANALYSIS.md.
- **Evidence:** `src/client.zig` -- `formatCachedRdata` function covering 9 record types
- **Resolved date:** 2026-03-24

---

### GAP-0044: Transport abstraction not wired into resolvers -- **WON'T DO**
- **Issue:** (not filed -- skip-issues mode)
- **Category:** Code Quality
- **Severity:** Medium
- **Status:** **Won't Do** -- Architectural refactor requiring significant transport layer redesign. Inline socket code works correctly. Cross-ref GAP-0017 (also Won't Do), QC-NEW-03 (Won't Do).
- **Reason:** Large architectural change outside scope. Inline socket code is well-tested and functionally correct.

---

### GAP-0045: resolveIterative zero test coverage -- 219 lines, 9 nesting levels, untested -- **WON'T DO**
- **Issue:** (not filed -- skip-issues mode)
- **Category:** Test
- **Severity:** High
- **Status:** **Won't Do** -- Requires mock DNS transport infrastructure that does not exist. Remains as a production recommendation (see Production Blockers section).
- **Reason:** Test infrastructure gap. Mock transport layer needed for injection of DNS responses. Cross-ref QH-NEW-02.

---

### GAP-0046: Zero fuzz testing for wire parsers -- **WON'T DO**
- **Issue:** (not filed -- skip-issues mode)
- **Category:** Test
- **Severity:** High
- **Status:** **Won't Do** -- Requires fuzz infrastructure setup (`std.testing.fuzz` targets, CI integration). Remains as a production recommendation. Note: all 7 bounds-check bugs found by adversarial review (SEC-NEW-01 through SEC-NEW-07) have been fixed.
- **Reason:** Fuzz infrastructure investment outside scope. All known bounds-check bugs resolved.

---

### GAP-0047: spice dependency pins main branch -- **WON'T DO**
- **Issue:** (not filed -- skip-issues mode)
- **Category:** Security
- **Severity:** Medium
- **Status:** **Won't Do** -- Upstream concern. Hash pinning in `build.zig.zon` provides integrity protection. Tagged release requires upstream action.
- **Reason:** Upstream dependency management. Hash pinning provides partial mitigation. Cross-ref SEC-C14/C31, QS-NEW-08.

---

## Security Findings (Phase 3 + Adversarial Review)

The following security findings were identified in Phase 3 review and the subsequent Phase 2-3 adversarial security review (2026-03-24). Findings that duplicate existing GAP entries are cross-referenced. All new issues are created as **confidential** on GitLab.

### Stack-Ranked Security Findings (All Phases, Unified)

| Rank | Severity | Risk Score | Finding | Component | CWE/OWASP | Evidence | Issue | SLA | Status |
|------|----------|------------|---------|-----------|-----------|----------|-------|-----|--------|
| 1 | Critical | 80 | SEC-C22: PipelinedBatch infinite loop on connection close | connection_pool.zig | CWE-835 / A05:2021 | connection_pool.zig:468,490 | [#154](https://gitlab.com/devnw/zig/dns/-/issues/154) (confidential) / GAP-0028 [#133] | 7d | **Resolved** |
| 2 | **High** | **64** | **SEC-SCAN-09: Trust anchor digest `@min` truncation allows partial digest match -- DNSSEC bypass** | dnssec.zig | CWE-187 / A02:2021 | dnssec.zig:556 | (not yet filed -- confidential) | 30d | **Open** |
| 3 | High | 64 | SEC-NEW-01: OOB read in extractTsig -- rdlength not validated before slice | tsig.zig | CWE-125 / A03:2021 | tsig.zig:633 | Commit 6d42d51 | 30d | **Resolved** |
| 4 | High | 64 | SEC-NEW-02: OOB read in extractSig0 -- rdlength not validated before slice | sig0.zig | CWE-125 / A03:2021 | sig0.zig:561 | Commit 8fef334 | 30d | **Resolved** |
| 5 | High | 64 | SEC-C02: Unchecked @enumFromInt (covers SEC-C20/C21) | record.zig, sig0.zig, tsig.zig + 3 more | CWE-704 / A03:2021 | sig0.zig:217, tsig.zig:217, record.zig:439+ | [#89](https://gitlab.com/devnw/zig/dns/-/issues/89) / GAP-0033 [#134] / GAP-0034 [#135] | 30d | **Resolved** |
| 6 | High | 64 | SEC-C05: Non-CSPRNG for transaction IDs (covers SEC-C24) | recursive.zig | CWE-330 / A02:2021 | recursive.zig:119,448 | [#94](https://gitlab.com/devnw/zig/dns/-/issues/94) | 30d | **Resolved** |
| 7 | High | 48 | SEC-C23: TSIG HMAC key truncation | tsig.zig | CWE-326 / A02:2021 | tsig.zig:442,457,472,487,502 | [#157](https://gitlab.com/devnw/zig/dns/-/issues/157) (confidential) | 30d | **Resolved** |
| 8 | High | 48 | SEC-C26: Partial write data loss (3 files) | connection_pool.zig, dot.zig, zone_transfer.zig | CWE-400 / A05:2021 | connection_pool.zig:454, dot.zig:305, zone_transfer.zig:523 | [#161](https://gitlab.com/devnw/zig/dns/-/issues/161) (confidential) / GAP-0027 [#132] | 30d | **Resolved** |
| 9 | **Medium** | **48** | **SEC-NEW-04b: NSEC3 iterations not capped -- CPU DoS with iterations=65535** | dnssec.zig | CWE-400 / A05:2021 | dnssec.zig:565-595 | (not yet filed -- confidential) | 90d | **Open** |
| 10 | Medium | 48 | SEC-NEW-03: skipRR returns offset+10+rdlength without bounds check | dns_name.zig | CWE-125 / A03:2021 | dns_name.zig:116 | Commit 6d42d51 | 90d | **Resolved** |
| 11 | Medium | 48 | SEC-NEW-06: Question skip adds +4 without bounds check | tsig.zig, sig0.zig | CWE-125 / A03:2021 | tsig.zig:599, sig0.zig:523 | Commit 6d42d51 | 90d | **Resolved** |
| 12 | Medium | 48 | SEC-C27: No glue record bailiwick validation | recursive.zig | CWE-345 / A01:2021 | recursive.zig:564-589 | [#165](https://gitlab.com/devnw/zig/dns/-/issues/165) (confidential) | 90d | **Resolved** |
| 13 | **Medium** | **36** | **SEC-SCAN-08: Non-constant-time DS digest comparison -- timing side-channel** | dnssec.zig | CWE-208 / A02:2021 | dnssec.zig:201,540,556 | (not yet filed -- confidential) | 90d | **Open** |
| 14 | **Medium** | **36** | **SEC-NEW-02b: Zone transfer question section OOB read** | zone_transfer.zig | CWE-125 / A03:2021 | zone_transfer.zig:584-592 | (not yet filed -- confidential) | 90d | **Open** |
| 15 | **Medium** | **36** | **SEC-NEW-03b: Zone transfer qdcount not validated** | zone_transfer.zig | CWE-20 / A03:2021 | zone_transfer.zig:575-592 | (not yet filed) | 90d | **Open** |
| 16 | Medium | 36 | SEC-C28: Zone transfer auth defaults off | zone_transfer.zig | CWE-1188 / A05:2021 | zone_transfer.zig:46 | [#169](https://gitlab.com/devnw/zig/dns/-/issues/169) (confidential) | 90d | **Resolved** |
| 17 | Medium | 36 | SEC-C29: SIG(0) no replay protection | sig0.zig | CWE-294 / A07:2021 | sig0.zig:341-391 | [#172](https://gitlab.com/devnw/zig/dns/-/issues/172) (confidential) | 90d | **Won't Do** |
| 18 | Medium | 32 | SEC-C30: dns_name.zig allows forward compression pointers | dns_name.zig | CWE-345 / A03:2021 | dns_name.zig:60-63 | [#175](https://gitlab.com/devnw/zig/dns/-/issues/175) (confidential) | 90d | **Resolved** |
| 19 | Medium | 27 | SEC-SCAN-03: Cache has no thread-safety -- data races under concurrent access | cache.zig | CWE-362 / A04:2021 | cache.zig:68-252 | -- (skip-issues) | 90d | **Won't Do** |
| 20 | **Medium** | **24** | **SEC-SCAN-10: resolver/edns.zig options.len @intCast unchecked** | resolver/edns.zig | CWE-190 / A03:2021 | resolver/edns.zig:47 | (not yet filed) | 90d | **Open** |
| 21 | **Medium** | **24** | **SEC-SCAN-11: resolver/config.zig user config @intCast unchecked** | resolver/config.zig | CWE-681 / A03:2021 | resolver/config.zig:345-354 | (not yet filed) | 90d | **Open** |
| 22 | **Medium** | **24** | **SEC-SCAN-12: zone_transfer.zig label.len @intCast unchecked** | zone_transfer.zig | CWE-190 / A03:2021 | zone_transfer.zig:517 | (not yet filed) | 90d | **Open** |
| 23 | **Medium** | **24** | **SEC-SCAN-13: zone_transfer.zig message.len @intCast unchecked** | zone_transfer.zig | CWE-190 / A03:2021 | zone_transfer.zig:527 | (not yet filed) | 90d | **Open** |
| 24 | Medium | 24 | SEC-C100: TSIG fudge value attacker-controlled (defense-in-depth) | tsig.zig | CWE-807 / A04:2021 | tsig.zig:384 | Commit 6d42d51 | 90d | **Resolved** |
| 25 | Medium | 24 | SEC-C06/C25: Key material not zeroed (stack + heap) | tsig.zig, sig0.zig | CWE-244 / A02:2021 | tsig.zig:435-495, sig0.zig:115-117 | [#104](https://gitlab.com/devnw/zig/dns/-/issues/104) / [#111](https://gitlab.com/devnw/zig/dns/-/issues/111) | 90d | **Resolved** |
| 26 | Medium | 24 | SEC-C14/C31: spice dependency pins main branch | build.zig.zon | CWE-829 / A06:2021 | build.zig.zon:29 | [#107](https://gitlab.com/devnw/zig/dns/-/issues/107) / GAP-0047 | 90d | **Won't Do** |
| 27 | Medium | 16 | SEC-SCAN-01: TsigKey.secret not zeroed on destruction -- no deinit method | tsig.zig | CWE-244 / A02:2021 | tsig.zig:120-153 | -- (skip-issues) | 90d | **Resolved** |
| 28 | Medium | 9 | SEC-SCAN-02: ARCOUNT u16 overflow in TSIG/SIG(0) append | tsig.zig, sig0.zig | CWE-190 / A03:2021 | tsig.zig:555, sig0.zig:346 | -- (skip-issues) | 90d | **Resolved** |
| 29 | Low | 24 | SEC-NEW-07: skipName compression pointer returns offset+2 without checking offset+1 < data.len | dns_name.zig | CWE-125 / A03:2021 | dns_name.zig:101 | Commit 6d42d51 | 180d | **Resolved** |
| 30 | Low | 16 | SEC-C101: TSIG time check before MAC creates timing oracle | tsig.zig | CWE-208 / A02:2021 | tsig.zig:350-398 | Commit 6d42d51 | 180d | **Resolved** |
| 31 | Low | 16 | SEC-NEW-04: TSIG other_data silently truncated when other_len exceeds available data | tsig.zig | CWE-130 / A03:2021 | tsig.zig:229 | Commit 6d42d51 | 180d | **Resolved** |
| 32 | Low | 16 | SEC-NEW-05: @intCast(u16) on options.len without bounds check | edns.zig | CWE-190 / A03:2021 | edns.zig:167 | Commit 8fef334 | 180d | **Resolved** |
| 33 | Low | 16 | SEC-C33: Zone transfer short-read on length prefix | zone_transfer.zig | CWE-20 / A05:2021 | zone_transfer.zig:530-531 | [#178](https://gitlab.com/devnw/zig/dns/-/issues/178) (confidential) | 180d | **Resolved** |
| 34 | **Low** | **16** | **SEC-SCAN-15: zone_transfer.zig TsigKey.secret not zeroed on struct reassignment** | zone_transfer.zig | CWE-244 / A02:2021 | zone_transfer.zig:64-68 | (not yet filed) | 180d | **Open** |
| 35 | **Low** | **16** | **SEC-SCAN-16: connection_pool.zig time delta @intCast unchecked** | connection_pool.zig | CWE-681 / A03:2021 | connection_pool.zig:123,128 | (not yet filed) | 180d | **Open** |
| 36 | **Low** | **16** | **SEC-SCAN-17: happy_eyeballs.zig time delta @intCast unchecked** | happy_eyeballs.zig | CWE-681 / A03:2021 | happy_eyeballs.zig:199,239 | (not yet filed) | 180d | **Open** |
| 37 | Low | 12 | ADV-02: No TSIG replay protection within fudge window | tsig.zig | CWE-294 / A07:2021 | tsig.zig:302-408 | -- (skip-issues) | 180d | **Won't Do** |
| 38 | Low | 8 | SEC-C32: SIG(0) timestamp u32 overflow in 2106 | sig0.zig | CWE-190 / A05:2021 | sig0.zig:278,369 | [#176](https://gitlab.com/devnw/zig/dns/-/issues/176) (confidential) | 180d | **Won't Do** |
| 39 | Low | 8 | SEC-SCAN-05: dns_name.zig encodeName/encodeNameLower @intCast on label.len without max label check | dns_name.zig | CWE-190 / A03:2021 | dns_name.zig:127,139 | -- (skip-issues) | 180d | **Resolved** |
| 40 | **Low** | **8** | **SEC-SCAN-14: stub.zig query.len @intCast (structurally bounded)** | stub.zig | CWE-190 / A03:2021 | stub.zig:266 | (not yet filed) | 180d | **Open** |
| 41 | **Low** | **8** | **SEC-NEW-01b: logging.zig time delta @intCast unchecked** | logging.zig | CWE-681 / A03:2021 | logging.zig:391 | (not yet filed) | 180d | **Open** |
| 42 | Low | 6 | ADV-05: Large header counts cause CPU-bound parse loop | message.zig | CWE-400 / A05:2021 | message.zig:62-82 | -- (skip-issues) | 180d | **Resolved** |
| 43 | Low | 4 | SEC-SCAN-04: TCP/DoT/DoQ/ConnectionPool @intCast(u16) on wire_req.len without bounds check | tcp.zig, dot.zig, doq.zig, connection_pool.zig | CWE-190 / A03:2021 | tcp.zig:52, dot.zig:302, connection_pool.zig:557,662,707 | -- (skip-issues) | 180d | **Resolved** |
| 44 | Low | 2 | SEC-SCAN-06: SIG(0) sign @intCast(u16) rdlength without bounds check | sig0.zig | CWE-190 / A03:2021 | sig0.zig:360 | -- (skip-issues) | 180d | **Resolved** |
| 45 | Info | 1 | SEC-SCAN-07: name.zig toString doesn't enforce forward pointer rejection (defense-in-depth) | name.zig | CWE-345 / A03:2021 | name.zig:243 | -- (skip-issues) | Backlog | **Resolved** |

### Adversarial Review Finding Details

#### SEC-NEW-01 (HIGH): OOB read in extractTsig -- **RESOLVED** (commit 6d42d51)

- **Status:** Resolved (2026-03-24). Bounds check `if (offset + rdlength > message.len) return error.InvalidMessage;` added at `tsig.zig:633`. Test `SEC-NEW-01: extractTsig rejects rdlength exceeding message` added.
- **Resolution evidence:** `src/security/tsig.zig:633` -- bounds check; `src/security/tsig.zig:932+` -- test

#### SEC-NEW-02 (HIGH): OOB read in extractSig0 -- **RESOLVED** (commit 8fef334)

- **Status:** Resolved (2026-03-24). Bounds check added before `message[offset .. offset + rdlength]` in extractSig0. Test added for truncated SIG(0) record.
- **Resolution evidence:** `src/security/sig0.zig` -- bounds check before rdlength slice; commit 8fef334

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

#### SEC-NEW-05 (LOW): @intCast(u16) on options.len without bounds check -- **RESOLVED** (commit 8fef334)

- **Status:** Resolved (2026-03-24). Bounds check added before `@intCast` in EDNS encode and buildOption paths.
- **Resolution evidence:** `src/edns.zig` -- bounds validation before u16 cast; commit 8fef334

#### SEC-NEW-07 (LOW): skipName compression pointer returns offset+2 without checking offset+1 < data.len -- **RESOLVED** (commit 6d42d51)

- **Status:** Resolved (2026-03-24). Bounds check `if (offset + 1 >= data.len) return error.InvalidName;` added before `return offset + 2` in skipName. Test `SEC-NEW-07: skipName rejects truncated compression pointer` added.
- **Resolution evidence:** `src/security/dns_name.zig:101` -- bounds check; `src/security/dns_name.zig:241+` -- test

### Phase 2-3 Adversarial Scan Findings (2026-03-24)

#### SEC-SCAN-01 (MEDIUM): TsigKey.secret not zeroed on destruction -- **RESOLVED**

- **Status:** **Resolved** (2026-03-24). Added `deinit()` method to `TsigKey` that calls `std.crypto.utils.secureZero` on the secret buffer before freeing via allocator. Test verifies secret bytes are zeroed after deinit.
- **Resolution evidence:** `src/security/tsig.zig` -- `TsigKey.deinit()` with `secureZero` call
- **Risk score:** 16 (Impact 2 x Likelihood 2 x 4)
- **Confidence:** `confidence::confirmed`

#### SEC-SCAN-02 (MEDIUM): ARCOUNT u16 overflow in TSIG/SIG(0) append -- **RESOLVED**

- **Status:** **Resolved** (2026-03-24). Added overflow check `if (arcount == std.math.maxInt(u16)) return error.TooManyAdditionalRecords;` before incrementing in both `tsig.zig` and `sig0.zig`.
- **Resolution evidence:** `src/security/tsig.zig` and `src/security/sig0.zig` -- overflow guard before ARCOUNT increment
- **Risk score:** 9
- **Confidence:** `confidence::confirmed`

#### SEC-SCAN-03 (MEDIUM): Cache has no thread-safety -- **WON'T DO**

- **Status:** **Won't Do** (2026-03-24). Cache documented as single-threaded-only. Thread safety requires architectural redesign (adding Mutex/RwLock to all public methods, or providing ThreadSafeCache wrapper). Single-threaded use is safe. Cross-ref PF-14 (also Won't Do).
- **Reason:** Architectural change outside scope. Cache is safe for single-threaded deployments.
- **Risk score:** 27
- **Confidence:** `confidence::confirmed`

#### SEC-SCAN-04 (LOW): TCP/DoT/DoQ/ConnectionPool @intCast(u16) on wire_req.len without bounds check -- **RESOLVED**

- **Status:** **Resolved** (2026-03-24). Added `if (wire_req.len > std.math.maxInt(u16)) return error.MessageTooLarge;` bounds check before all `@intCast(u16)` casts on `wire_req.len` in tcp.zig, dot.zig, and connection_pool.zig.
- **Resolution evidence:** `src/transports/tcp.zig`, `src/transports/dot.zig`, `src/transports/connection_pool.zig` -- bounds checks before u16 casts
- **Risk score:** 4
- **Confidence:** `confidence::confirmed`

#### SEC-SCAN-05 (LOW): dns_name.zig encodeName/encodeNameLower @intCast on label.len without max label check -- **RESOLVED**

- **Status:** **Resolved** (2026-03-24). Added `if (label.len > 63) return error.LabelTooLong;` check before `@intCast` in both `encodeName` and `encodeNameLower` in `dns_name.zig`.
- **Resolution evidence:** `src/security/dns_name.zig` -- label length validation in encodeName and encodeNameLower
- **Risk score:** 8
- **Confidence:** `confidence::confirmed`

#### SEC-SCAN-06 (LOW): SIG(0) sign @intCast(u16) rdlength without bounds check -- **RESOLVED**

- **Status:** **Resolved** (2026-03-24). Added `if (rdlength > std.math.maxInt(u16)) return error.RdataTooLarge;` bounds check before `@intCast(u16)` cast in SIG(0) sign method.
- **Resolution evidence:** `src/security/sig0.zig` -- bounds check before rdlength cast
- **Risk score:** 2
- **Confidence:** `confidence::confirmed`

#### SEC-SCAN-07 (INFO): name.zig toString doesn't enforce forward pointer rejection -- **RESOLVED**

- **Status:** **Resolved** (2026-03-24). Added forward pointer rejection to `toString`, `toStringBuf`, `labelCount`, `parent`, and `eql` in `name.zig`. Forward pointers (where `ptr_offset >= current absolute offset`) now return error. Defense-in-depth improvement complementing existing hop limit and SEC-C30 fix in `dns_name.zig`.
- **Resolution evidence:** `src/name.zig` -- forward pointer checks in `toString`, `toStringBuf`, `labelCount`, `parent`, `eql`
- **Risk score:** 1
- **Confidence:** `confidence::confirmed`

#### ADV-02 (LOW): No TSIG replay protection within fudge window -- **WON'T DO**

- **Status:** **Won't Do** (2026-03-24). Defense-in-depth improvement. Requires bounded replay cache data structure with time-based eviction. Low practical risk with default 300-second fudge window. Complementary to SEC-C29 (SIG(0) replay, also Won't Do).
- **Reason:** Defense-in-depth. Replay requires on-path attacker + capture within fudge window. Bounded replay cache is a new data structure investment.
- **Risk score:** 12
- **Confidence:** `confidence::confirmed`

#### ADV-05 (LOW): Large header counts cause CPU-bound parse loop -- **RESOLVED**

- **Status:** **Resolved** (2026-03-24). Added `max_section_count = 4096` constant in `message.zig`. All section count fields (qdcount, ancount, nscount, arcount) are now validated against this limit before the parse loops execute. Messages with section counts exceeding 4096 return `error.TooManyRecords`.
- **Resolution evidence:** `src/message.zig` -- `max_section_count` constant; bounds check before parse loops
- **Risk score:** 6
- **Confidence:** `confidence::confirmed`

### Phase 3 + Adversarial Review Security Summary

**Previous findings (Phases 1-3):**
- **Critical:** 1 finding -- **1 resolved** (SEC-C22 infinite loop DoS)
- **High:** 6 findings -- **6 resolved** (SEC-C02 enum panic, SEC-C05 weak PRNG, SEC-C23 key truncation, SEC-C26 partial write, SEC-NEW-01 OOB in extractTsig, SEC-NEW-02 OOB in extractSig0)
- **Medium:** 12 findings -- **9 resolved**, **3 won't do** (SEC-C29 replay, SEC-C14/C31 supply chain, SEC-SCAN-03 cache thread-safety)
- **Low:** 11 findings -- **9 resolved**, **2 won't do** (SEC-C32, ADV-02)
- **Info:** 1 finding -- **1 resolved** (SEC-SCAN-07 forward pointer in name.zig)

**New findings (Phase 3 adversarial review, 2026-03-24):**
- **High:** 1 finding -- **1 open** (SEC-SCAN-09 trust anchor digest truncation -- DNSSEC validation bypass)
- **Medium:** 8 findings -- **8 open** (SEC-SCAN-08 timing side-channel, SEC-SCAN-10/11/12/13 @intCast, SEC-NEW-02b/03b zone transfer OOB, SEC-NEW-04b NSEC3 CPU DoS)
- **Low:** 5 findings -- **5 open** (SEC-SCAN-14/15/16/17 @intCast/zeroing, SEC-NEW-01b logging @intCast)

**Combined totals (unified table): 45 security findings -- 26 resolved, 5 won't do, 14 open**

### Deduplication Notes

| Phase 3 ID | Existing Issue | Status |
|-------------|---------------|--------|
| SEC-C20 (SIG(0) enum panic) | #89 [SEC-C02] -- already listed in Evidence | Duplicate -- comment added |
| SEC-C21 (TSIG enum panic) | #89 [SEC-C02] -- already listed in Evidence | Duplicate -- comment added |
| SEC-C24 (PRNG for TXIDs) | #94 [SEC-C05] -- same root cause | Duplicate -- comment added |
| SEC-C25 (Key not zeroed) | #104 [SEC-C06] + #111 [SEC-C07] -- same root cause | Duplicate -- comment added |
| SEC-C31 (spice pins main) | #107 [SEC-C14] -- identical finding | Duplicate -- comment added; cross-ref GAP-0047 |
| SEC-C11 (Thread pool page_allocator) | [#112](https://gitlab.com/devnw/zig/dns/-/issues/112) -- overlaps PF-17 (thread pool GPA wrapper) | Cross-reference -- both resolved |
| SEC-C12 (IPv4 format undefined trailing bytes) | [#115](https://gitlab.com/devnw/zig/dns/-/issues/115) -- overlaps QH-03 (Formatted struct with len) | Cross-reference -- both resolved |
| SEC-NEW-01 / SEC-NEW-02 | Same root cause (missing rdlength bounds check) in sibling functions | Both resolved: 6d42d51 / 8fef334 |
| SEC-NEW-03 / SEC-NEW-06 | Related root cause (missing bounds checks in wire parser helpers) | Both resolved: commit 6d42d51 |
| SEC-SCAN-01 / SEC-C06/C25 | Related root cause (key material not zeroed). SEC-C06/C25 covers HMAC state; SEC-SCAN-01 covers TsigKey struct secret | Tracked separately: different code paths, different lifecycle |
| ADV-02 / SEC-C29 | Same class of issue (replay attack) but different protocols: ADV-02 is TSIG, SEC-C29 is SIG(0) | Tracked separately: different code, different fix |
| SEC-SCAN-04 / SEC-NEW-05 / SEC-SCAN-06 | Same pattern (@intCast without bounds) across different call sites | Tracked separately: different files and data flows |
| SEC-SCAN-07 / SEC-C30 | Related (forward compression pointer). SEC-C30 fixed dns_name.zig; SEC-SCAN-07 covers name.zig | Tracked separately: different modules |

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

**Completed quick wins (commit 8fef334):**
- ~~SEC-NEW-02~~: Bounds check added before `message[offset .. offset + rdlength]` in extractSig0 -- **Resolved**
- ~~SEC-NEW-05~~: Bounds validation before `@intCast(u16)` in EDNS encode/buildOption -- **Resolved**

**Completed quick wins (final gap closure cycle):**
- ~~SEC-SCAN-01~~: `TsigKey.deinit()` with `secureZero` on `.secret` -- **Resolved**
- ~~SEC-SCAN-02~~: Overflow check before `arcount + 1` in tsig.zig and sig0.zig -- **Resolved**
- ~~SEC-SCAN-04~~: Bounds check before `@intCast(u16)` on wire_req.len in tcp.zig, dot.zig, connection_pool.zig -- **Resolved**
- ~~SEC-SCAN-05~~: Label length validation in dns_name.zig encodeName/encodeNameLower -- **Resolved**
- ~~SEC-SCAN-06~~: Bounds check before rdlength `@intCast(u16)` in sig0.zig -- **Resolved**
- ~~ADV-05~~: `max_section_count = 4096` enforced in message.zig parse loop -- **Resolved**
- ~~SEC-SCAN-07~~: Forward pointer rejection added to name.zig toString/toStringBuf/labelCount/parent/eql -- **Resolved**

**New findings requiring action (Phase 3 adversarial review, 2026-03-24):**

*High priority (30-day SLA):*
- SEC-SCAN-09: Trust anchor digest `@min` truncation -- **Open** (DNSSEC validation bypass via partial digest match; CWE-187)

*Medium priority (90-day SLA):*
- SEC-SCAN-08: Non-constant-time DS digest comparison -- **Open** (timing side-channel; CWE-208)
- SEC-SCAN-10: resolver/edns.zig @intCast options.len unchecked -- **Open** (CWE-190)
- SEC-SCAN-11: resolver/config.zig @intCast on user config values -- **Open** (CWE-681)
- SEC-SCAN-12: zone_transfer.zig encodeName label.len @intCast -- **Open** (CWE-190)
- SEC-SCAN-13: zone_transfer.zig message.len @intCast -- **Open** (CWE-190)
- SEC-NEW-02b: Zone transfer question section OOB read -- **Open** (CWE-125)
- SEC-NEW-03b: Zone transfer qdcount not validated -- **Open** (CWE-20)
- SEC-NEW-04b: NSEC3 iterations not capped -- CPU DoS -- **Open** (CWE-400; RFC 9276 recommends max 100)

*Low priority (180-day SLA):*
- SEC-SCAN-14: stub.zig query.len @intCast (structurally bounded) -- **Open** (CWE-190)
- SEC-SCAN-15: zone_transfer TsigKey.secret not zeroed -- **Open** (CWE-244)
- SEC-SCAN-16: connection_pool time delta @intCast clock regression -- **Open** (CWE-681)
- SEC-SCAN-17: happy_eyeballs time delta @intCast -- **Open** (CWE-681)
- SEC-NEW-01b: logging.zig time delta @intCast -- **Open** (CWE-681)

**Remaining (Won't Do / deferred):**
- SEC-C29: SIG(0) replay cache -- **Won't Do** (defense-in-depth; requires bounded replay cache data structure; low practical risk)
- ADV-02: TSIG replay cache -- **Won't Do** (defense-in-depth; complementary to SEC-C29; low practical risk)
- SEC-C32: SIG(0) timestamp u32 overflow in 2106 -- **Won't Do** (Year 2106 issue; not actionable)
- SEC-C14/C31: spice dependency pins main branch -- **Won't Do** (upstream concern; hash pinning provides partial mitigation; cross-ref GAP-0047)
- SEC-SCAN-03: Cache thread safety -- **Won't Do** (handled via different controls: document Cache as single-threaded-only; cross-ref PF-14)

---

## Gap Priority Matrix

| Severity | Total | Resolved | Won't Do | Open | Gap-IDs / SEC-IDs |
|----------|-------|----------|----------|------|-------------------|
| Critical | 2 | 2 | 0 | 0 | GAP-0027/SEC-C26, GAP-0028/SEC-C22 |
| High | 12 | 9 | 2 | 1 | **Resolved:** GAP-0026, GAP-0029, GAP-0030, GAP-0033/SEC-C20, GAP-0034/SEC-C21, SEC-C23, SEC-C05/C24, SEC-NEW-01, SEC-NEW-02. **Won't Do:** GAP-0045, GAP-0046. **Open:** SEC-SCAN-09 |
| Medium | 36 | 21 | 6 | 9 | **Resolved:** +GAP-0038, GAP-0039, GAP-0043, SEC-SCAN-01, SEC-SCAN-02. **Won't Do:** GAP-0015, GAP-0017, GAP-0041, GAP-0042, GAP-0044, GAP-0047, SEC-C29, SEC-SCAN-03, SEC-C14/C31. **Open:** GAP-0049, SEC-SCAN-08, SEC-SCAN-10, SEC-SCAN-11, SEC-SCAN-12, SEC-SCAN-13, SEC-NEW-02b, SEC-NEW-03b, SEC-NEW-04b |
| Low | 27 | 17 | 2 | 8 | **Resolved:** GAP-0040, ADV-05, SEC-SCAN-04, SEC-SCAN-05, SEC-SCAN-06. **Won't Do:** SEC-C32, ADV-02. **Open:** GAP-0048, GAP-0050, GAP-0051, SEC-SCAN-14, SEC-SCAN-15, SEC-SCAN-16, SEC-SCAN-17, SEC-NEW-01b |
| Info | 1 | 1 | 0 | 0 | **Resolved:** SEC-SCAN-07 |

## Production Readiness Assessment

### Remaining Open Items

**4 open gaps + 14 open security findings** from Phase 3 adversarial review.

| Gap-ID / SEC-ID | Severity | Status | Blocks Production? | Rationale |
|-----------------|----------|--------|-------------------|-----------|
| **SEC-SCAN-09** | **HIGH** | **Open** | **Yes -- DNSSEC** | Trust anchor digest truncation allows DNSSEC validation bypass |
| GAP-0049 | Medium | Open | Yes -- DNSSEC | RRset not sorted per RFC 4034 S6.3; RRSIG verification may fail |
| SEC-SCAN-08 | Medium | Open | No (defense-in-depth) | Timing side-channel on DS digest comparison |
| SEC-NEW-02b | Medium | Open | No (zone transfer) | Zone transfer question section OOB read |
| SEC-NEW-03b | Medium | Open | No (zone transfer) | Zone transfer qdcount not validated |
| SEC-NEW-04b | Medium | Open | No (NSEC3 only) | NSEC3 iterations not capped; CPU DoS possible |
| SEC-SCAN-10 | Medium | Open | No | resolver/edns.zig @intCast unchecked |
| SEC-SCAN-11 | Medium | Open | No | resolver/config.zig @intCast on user config |
| SEC-SCAN-12 | Medium | Open | No | zone_transfer.zig encodeName @intCast |
| SEC-SCAN-13 | Medium | Open | No | zone_transfer.zig message.len @intCast |
| GAP-0048 | Low | Open | No | RPZ wildcard boundary bypass test missing |
| GAP-0050 | Low | Open | No | RFC_COMPLIANCE.md inconsistency |
| GAP-0051 | Low | Open | No | DoQ feature gate blocks CI tests |
| SEC-SCAN-14 | Low | Open | No | stub.zig @intCast (structurally bounded) |
| SEC-SCAN-15 | Low | Open | No | zone_transfer TsigKey.secret not zeroed |
| SEC-SCAN-16 | Low | Open | No | connection_pool time delta @intCast |
| SEC-SCAN-17 | Low | Open | No | happy_eyeballs time delta @intCast |
| SEC-NEW-01b | Low | Open | No | logging.zig time delta @intCast |

### Won't Do Items

| Gap-ID / SEC-ID | Status | Blocks Production? | Rationale |
|-----------------|--------|-------------------|-----------|
| GAP-0015 | Won't Do | No | Admin tracker reconciliation; docs are accurate |
| GAP-0017 | Won't Do | No | Transport architecture refactor outside scope |
| GAP-0041 | Won't Do | No | Returns explicit errors; `client.Client` works |
| GAP-0042 | Won't Do | No | Feature addition; raw query API covers all types |
| GAP-0044 | Won't Do | No | Architecture refactor; inline code works correctly |
| GAP-0045 | Won't Do | Recommended | Core resolution loop zero tests; high regression risk |
| GAP-0046 | Won't Do | Recommended | Wire parsers no fuzz coverage; all known bugs fixed |
| GAP-0047 | Won't Do | No | Upstream concern; hash pinning provides integrity |
| SEC-C29 | Won't Do | No | Defense-in-depth; replay requires capture + time window |
| SEC-C14/C31 | Won't Do | No | Upstream concern; hash pinning provides integrity |
| SEC-C32 | Won't Do | No | Year 2106 issue |
| SEC-SCAN-03 | Won't Do | No (single-threaded) | Thread safety requires architecture redesign |
| ADV-02 | Won't Do | No | Defense-in-depth; same class as SEC-C29 |

### Production Blockers

All Critical severity bugs from previous cycles are **resolved**. One new **HIGH** severity finding requires action:

- **SEC-SCAN-09** (HIGH, DNSSEC validation bypass): `@min(digest.len, anchor.data.len)` in `dnssec.zig:556` allows partial digest match, enabling trust anchor forgery. **30-day SLA.**
- **GAP-0049** (Medium, DNSSEC correctness): Canonical RRset sorting not implemented per RFC 4034 S6.3. May produce false BOGUS results on multi-record RRsets.

Previously resolved blockers:
- ~~**GAP-0043**~~ (Medium, correctness bug): **RESOLVED.** Cache hits now format 9 record types via `formatCachedRdata`.
- ~~**SEC-SCAN-03**~~ (Medium, thread-safety): **Won't Do.** Cache documented as single-threaded-only.

Remaining production recommendations (non-blocking):

1. **GAP-0045** (High, test coverage): The core `resolveIterative` function (219 lines, 9 nesting levels) has zero test coverage.
2. **GAP-0046** (High, fuzz testing): Wire parsers have no fuzz testing despite 7 bounds-check bugs found by manual review.

**The library is production-ready for non-DNSSEC use in single-threaded contexts.** For DNSSEC deployments, SEC-SCAN-09 and GAP-0049 should be resolved first. GAP-0045 and GAP-0046 are recommended for long-term maintenance confidence.
