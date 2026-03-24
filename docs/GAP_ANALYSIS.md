# Gap Analysis

Last updated: 2026-03-24 (post-commit 8fef334 -- SEC-NEW-02/SEC-NEW-05 resolved; 10 new Phase 3 gaps added; 23 open remain)

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

### GAP-0038: README "Zero Dependencies" claim is inaccurate
- **Issue:** (not filed -- skip-issues mode)
- **Category:** Docs
- **Severity:** Medium
- **Requirement source:** `README.md` line 33
- **Current state (evidence):**
  - `README.md:33` -- states "zero external dependencies"
  - `build.zig.zon` -- declares 2 dependencies (spice, dns_zig_test)
- **Why this is a gap:** The README marketing claim contradicts the actual dependency manifest. Users expecting a zero-dep library will encounter build failures without the declared dependencies.
- **Impact/Risk:** Misleading documentation erodes trust; downstream users may fail to fetch required dependencies.
- **Recommended fix:** Update README.md to say "Minimal dependencies (optional spice for parallelism; dns_zig_test for testing only)" or similar accurate phrasing.
- **Acceptance criteria:**
  - [ ] README.md dependency claim matches `build.zig.zon` manifest
  - [ ] Distinction between runtime and test-only dependencies is clear

---

### GAP-0039: README RFC 4033/4034/4035 says "Complete" -- RSA missing, should say Partial
- **Issue:** (not filed -- skip-issues mode)
- **Category:** Docs
- **Severity:** Medium
- **Requirement source:** `README.md` RFC references table; `docs/ROADMAP.md` Phase 3
- **Current state (evidence):**
  - `README.md` RFC references table lists RFC 4033/4034/4035 (DNSSEC) as "Complete"
  - `src/resolver/dnssec.zig:446-452` -- RSA algorithms (8/10/5) return `error.UnsupportedAlgorithm`
  - ROADMAP.md already corrected to "PARTIAL" (GAP-0025)
- **Why this is a gap:** README claims full DNSSEC compliance but RSA-based algorithms are not implemented. This contradicts the corrected ROADMAP.md status.
- **Impact/Risk:** Users deploying against RSA-signed zones will get verification failures with no warning from docs.
- **Recommended fix:** Update README RFC table to say "Partial (Ed25519/ECDSA complete, RSA pending)".
- **Acceptance criteria:**
  - [ ] README RFC 4033/4034/4035 status says "Partial" with RSA caveat
  - [ ] Consistent with ROADMAP.md Phase 3 status

---

### GAP-0040: README RFC 7858 DoT listed "Complete" without asterisk
- **Issue:** (not filed -- skip-issues mode)
- **Category:** Docs
- **Severity:** Low
- **Requirement source:** `README.md` RFC references table; GAP-0014 (Won't Do)
- **Current state (evidence):**
  - `README.md` RFC references table lists RFC 7858 (DNS over TLS) without noting it is interface-only
  - `src/transports/dot.zig` -- vtable interface with no concrete TLS backend
  - GAP-0014 documents this as "Won't Do" with "interface only -- requires external backend"
- **Why this is a gap:** Same situation as DoH/DoQ -- the transport interface exists but no backend is shipped. README should be consistent with ROADMAP and GAP-0014 documentation.
- **Impact/Risk:** Users expect working DoT out of the box; they get a vtable with no backend.
- **Recommended fix:** Add asterisk or note: "Interface only -- requires external TLS backend" matching DoH/DoQ treatment.
- **Acceptance criteria:**
  - [ ] README RFC 7858 entry has interface-only annotation
  - [ ] Consistent with DoH/DoQ entries and GAP-0014 documentation

---

### GAP-0041: Convenience API stubs return error.NotImplemented
- **Issue:** (not filed -- skip-issues mode)
- **Category:** Feature
- **Severity:** Medium
- **Requirement source:** `src/resolver/convenience.zig` public API; `docs/ARCHITECTURE.md` -- Resolver Layer
- **Current state (evidence):**
  - `src/resolver/convenience.zig` -- 6 public functions (`lookupA`, `lookupAAAA`, `lookup`, `lookupMX`, `lookupNS`, `lookupSRV`) return `error.NotImplemented`
  - These are exported via `lib.zig` as part of the public API
  - QH-NEW-01 (resolved in commit 6d42d51) changed them from silent empty returns to explicit errors, but they remain non-functional
- **Why this is a gap:** Public API exposes 6 functions that cannot perform their advertised purpose. Users calling these functions get errors instead of DNS results.
- **Impact/Risk:** API surface promises functionality it cannot deliver; users must discover `client.Client` as the working alternative through trial-and-error or source reading.
- **Recommended fix:** Either (a) implement the convenience functions by delegating to `client.Client`, or (b) remove them from the public API and document `client.Client` as the canonical resolution interface.
- **Acceptance criteria:**
  - [ ] Convenience functions either work or are removed from public API
  - [ ] Documentation clearly indicates the working resolution entry point

---

### GAP-0042: Client API missing lookupSRV/TXT/PTR/NS/SOA methods
- **Issue:** (not filed -- skip-issues mode)
- **Category:** Feature
- **Severity:** Medium
- **Requirement source:** `src/client.zig` public API; DNS RFCs 1035/2782/6763
- **Current state (evidence):**
  - `src/client.zig` -- only `lookupMX` exists as a typed record lookup beyond basic A/AAAA
  - No `lookupSRV`, `lookupTXT`, `lookupPTR`, `lookupNS`, `lookupSOA` methods
  - The library parses these record types in `record.zig` but the client API does not expose typed accessors
- **Why this is a gap:** Common DNS lookup operations (service discovery via SRV, SPF/DKIM via TXT, reverse DNS via PTR) require users to construct raw queries instead of using typed convenience methods.
- **Impact/Risk:** Reduced usability; users must understand wire-format DNS to perform common operations that peer libraries handle with one-line calls.
- **Recommended fix:** Add typed lookup methods for SRV, TXT, PTR, NS, and SOA record types in `client.zig`, following the `lookupMX` pattern.
- **Acceptance criteria:**
  - [ ] `lookupSRV`, `lookupTXT`, `lookupPTR`, `lookupNS`, `lookupSOA` methods exist in `client.zig`
  - [ ] Each method returns parsed, typed results (not raw wire format)
  - [ ] Tests cover each new method

---

### GAP-0043: Cache hit only formats A/AAAA -- MX/SRV/TXT cache hits return empty
- **Issue:** (not filed -- skip-issues mode)
- **Category:** Bug
- **Severity:** Medium
- **Requirement source:** `src/client.zig` cache hit path
- **Current state (evidence):**
  - `src/client.zig` cache hit path -- only handles `.a` and `.aaaa` resource record types when formatting cached results
  - MX, SRV, TXT, and other record types that hit the cache return empty result sets
- **Why this is a gap:** Cache hits for non-A/AAAA record types silently return empty results instead of the cached data. This is a correctness bug: a successful cache lookup produces no output.
- **Impact/Risk:** Users see intermittent empty results for MX/SRV/TXT queries depending on cache state. Cache appears to "lose" data. Difficult to debug because the first (uncached) query works correctly.
- **Recommended fix:** Extend the cache hit formatting path in `client.zig` to handle MX, SRV, TXT, PTR, NS, SOA, and CNAME record types.
- **Acceptance criteria:**
  - [ ] Cache hit path handles all record types that can be cached
  - [ ] Test: MX query returns correct results on both cache miss and cache hit
  - [ ] No record type silently returns empty on cache hit

---

### GAP-0044: Transport abstraction not wired into resolvers
- **Issue:** (not filed -- skip-issues mode)
- **Category:** Code Quality
- **Severity:** Medium
- **Requirement source:** `docs/ARCHITECTURE.md` -- Transport Layer; cross-ref GAP-0017, QC-NEW-03
- **Current state (evidence):**
  - `src/recursive.zig:sendQuery()` uses inline `std.posix` socket calls instead of transport module abstractions
  - `src/transports/udp.zig` and `src/transports/tcp.zig` exist as proper transport modules but are not used by the resolver
  - GAP-0017 tracks the same issue from the "suppressed API" angle; this gap tracks the code quality and architectural angle
- **Why this is a gap:** The architecture documents a transport abstraction layer, but the core resolver bypasses it entirely. This creates two parallel networking code paths that must be maintained independently.
- **Impact/Risk:** Transport-level features (connection pooling, metrics, timeout policies) applied to transport modules do not affect resolver queries. Bug fixes must be applied in two places.
- **Recommended fix:** Refactor `sendQuery()` in `recursive.zig` to accept a transport interface and delegate to `udp.zig`/`tcp.zig`. This also resolves GAP-0017.
- **Acceptance criteria:**
  - [ ] `recursive.zig` uses transport module interfaces for all network I/O
  - [ ] No inline socket code in resolver modules
  - [ ] GAP-0017 can be closed when this is resolved

---

### GAP-0045: resolveIterative zero test coverage -- 219 lines, 9 nesting levels, untested
- **Issue:** (not filed -- skip-issues mode)
- **Category:** Test
- **Severity:** High
- **Requirement source:** `src/recursive.zig` -- `resolveIterative` function
- **Current state (evidence):**
  - `src/recursive.zig` `resolveIterative` -- 219 lines with 9 levels of nesting
  - No unit tests or integration tests exercise this code path
  - This is the core iterative resolution algorithm (the "main loop" of recursive DNS)
- **Why this is a gap:** The most complex function in the codebase has zero test coverage. It contains the CNAME chasing, referral handling, and delegation logic that were the subject of multiple critical bug fixes (GAP-0019, GAP-0020). Without tests, regressions in this code are undetectable.
- **Impact/Risk:** High regression risk on the core resolution algorithm. Previous bugs (GAP-0019 CNAME loop, GAP-0020 referral assignment) were found by code review, not tests. Future changes could reintroduce them silently.
- **Recommended fix:** Add integration tests using mock DNS responses that exercise: (1) simple A resolution, (2) CNAME chasing, (3) NS referral following, (4) CNAME chain limit, (5) max iteration limit, (6) NXDOMAIN propagation.
- **Acceptance criteria:**
  - [ ] At least 6 test cases covering the paths listed above
  - [ ] Tests use mock/injected DNS responses (no network dependency)
  - [ ] Coverage of `resolveIterative` reaches 80%+

---

### GAP-0046: Zero fuzz testing for wire parsers
- **Issue:** (not filed -- skip-issues mode)
- **Category:** Test
- **Severity:** High
- **Requirement source:** Security best practices for wire-format parsers; CWE-119, CWE-125 pattern in SEC-NEW-01 through SEC-NEW-07
- **Current state (evidence):**
  - No `std.testing.fuzz` targets exist anywhere in the codebase
  - Wire parsers in `src/message.zig`, `src/record.zig`, `src/name.zig`, `src/security/tsig.zig`, `src/security/sig0.zig`, `src/security/dns_name.zig` handle untrusted network input
  - 7 out of 9 adversarial-review findings (SEC-NEW-01 through SEC-NEW-07) were bounds-check bugs in wire parsers
- **Why this is a gap:** Wire-format parsers are the primary attack surface for a DNS library. The pattern of bounds-check bugs found by manual review (7 findings) strongly suggests more exist. Fuzz testing is the standard technique for finding such bugs systematically.
- **Impact/Risk:** Undiscovered OOB reads/crashes in wire parsers. The SEC-NEW-* series demonstrates this code is vulnerable to malformed input. Without fuzzing, similar bugs likely remain.
- **Recommended fix:** Add `std.testing.fuzz` targets for: (1) `message.zig` full message parse, (2) `name.zig` name decode, (3) `record.zig` resource record parse, (4) `tsig.zig` TSIG extraction, (5) `sig0.zig` SIG(0) extraction. Each target should accept arbitrary bytes and verify no panic/OOB.
- **Acceptance criteria:**
  - [ ] Fuzz targets exist for all wire-format parsers listed above
  - [ ] Fuzz targets compile and run with `zig build test`
  - [ ] At least one CI job runs fuzz targets (even short duration)

---

### GAP-0047: spice dependency pins main branch
- **Issue:** (not filed -- skip-issues mode)
- **Category:** Security
- **Severity:** Medium
- **Requirement source:** `build.zig.zon`; cross-ref SEC-C14/C31, [#107](https://gitlab.com/devnw/zig/dns/-/issues/107)
- **Current state (evidence):**
  - `build.zig.zon:29` -- spice dependency uses main branch URL, not a tagged release
  - Hash pinning provides partial mitigation but does not prevent supply-chain attacks where main is force-pushed
  - SEC-C14/C31 (same finding) remains in "Triage" status on the security tracker
- **Why this is a gap:** Pinning to a branch (even with hash) means the dependency can change semantics between builds if the hash is updated. Tagged releases provide stronger guarantees about stability and review.
- **Impact/Risk:** Supply-chain risk: compromised upstream main branch could inject malicious code on next hash update. Build reproducibility risk: different checkouts may resolve to different code.
- **Recommended fix:** Pin spice to a tagged release version. If no tagged release exists, fork the dependency and pin to a specific commit in the fork.
- **Acceptance criteria:**
  - [ ] `build.zig.zon` references a tagged release or pinned fork commit
  - [ ] SEC-C14/C31 can be closed when this is resolved

---

## Security Findings (Phase 3 + Adversarial Review)

The following security findings were identified in Phase 3 review and the subsequent Phase 2-3 adversarial security review (2026-03-24). Findings that duplicate existing GAP entries are cross-referenced. All new issues are created as **confidential** on GitLab.

### Stack-Ranked Security Findings

| Rank | Severity | Risk Score | Finding | Component | CWE/OWASP | Evidence | Issue | SLA | Status |
|------|----------|------------|---------|-----------|-----------|----------|-------|-----|--------|
| 1 | Critical | 80 | SEC-C22: PipelinedBatch infinite loop on connection close | connection_pool.zig | CWE-835 / A05:2021 | connection_pool.zig:468,490 | [#154](https://gitlab.com/devnw/zig/dns/-/issues/154) (confidential) / GAP-0028 [#133] | 7d | **Resolved** |
| 2 | High | 64 | SEC-NEW-01: OOB read in extractTsig -- rdlength not validated before slice | tsig.zig | CWE-125 / A03:2021 | tsig.zig:633 | Commit 6d42d51 | 30d | **Resolved** |
| 3 | High | 64 | SEC-NEW-02: OOB read in extractSig0 -- rdlength not validated before slice | sig0.zig | CWE-125 / A03:2021 | sig0.zig:561 | Commit 8fef334 | 30d | **Resolved** |
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
| 14 | Medium | 27 | SEC-SCAN-03: Cache has no thread-safety -- data races under concurrent access | cache.zig | CWE-362 / A04:2021 | cache.zig:68-252 | -- (skip-issues) | 90d | Triage |
| 15 | Medium | 24 | SEC-C100: TSIG fudge value attacker-controlled (defense-in-depth) | tsig.zig | CWE-807 / A04:2021 | tsig.zig:384 | Commit 6d42d51 | 90d | **Resolved** |
| 16 | Medium | 24 | SEC-C06/C25: Key material not zeroed (stack + heap) | tsig.zig, sig0.zig | CWE-244 / A02:2021 | tsig.zig:435-495, sig0.zig:115-117 | [#104](https://gitlab.com/devnw/zig/dns/-/issues/104) / [#111](https://gitlab.com/devnw/zig/dns/-/issues/111) | 90d | **Resolved** |
| 17 | Medium | 24 | SEC-C14/C31: spice dependency pins main branch | build.zig.zon | CWE-829 / A06:2021 | build.zig.zon:29 | [#107](https://gitlab.com/devnw/zig/dns/-/issues/107) / GAP-0047 | 90d | Triage |
| 18 | Medium | 16 | SEC-SCAN-01: TsigKey.secret not zeroed on destruction -- no deinit method | tsig.zig | CWE-244 / A02:2021 | tsig.zig:120-153 | -- (skip-issues) | 90d | Triage |
| 19 | Medium | 9 | SEC-SCAN-02: ARCOUNT u16 overflow in TSIG/SIG(0) append | tsig.zig, sig0.zig | CWE-190 / A03:2021 | tsig.zig:555, sig0.zig:346 | -- (skip-issues) | 90d | Triage |
| 20 | Low | 24 | SEC-NEW-07: skipName compression pointer returns offset+2 without checking offset+1 < data.len | dns_name.zig | CWE-125 / A03:2021 | dns_name.zig:101 | Commit 6d42d51 | 180d | **Resolved** |
| 21 | Low | 16 | SEC-C101: TSIG time check before MAC creates timing oracle | tsig.zig | CWE-208 / A02:2021 | tsig.zig:350-398 | Commit 6d42d51 | 180d | **Resolved** |
| 22 | Low | 16 | SEC-NEW-04: TSIG other_data silently truncated when other_len exceeds available data | tsig.zig | CWE-130 / A03:2021 | tsig.zig:229 | Commit 6d42d51 | 180d | **Resolved** |
| 23 | Low | 16 | SEC-NEW-05: @intCast(u16) on options.len without bounds check | edns.zig | CWE-190 / A03:2021 | edns.zig:167 | Commit 8fef334 | 180d | **Resolved** |
| 24 | Low | 16 | SEC-C33: Zone transfer short-read on length prefix | zone_transfer.zig | CWE-20 / A05:2021 | zone_transfer.zig:530-531 | [#178](https://gitlab.com/devnw/zig/dns/-/issues/178) (confidential) | 180d | **Resolved** |
| 25 | Low | 12 | ADV-02: No TSIG replay protection within fudge window | tsig.zig | CWE-294 / A07:2021 | tsig.zig:302-408 | -- (skip-issues) | 180d | Triage |
| 26 | Low | 8 | SEC-C32: SIG(0) timestamp u32 overflow in 2106 | sig0.zig | CWE-190 / A05:2021 | sig0.zig:278,369 | [#176](https://gitlab.com/devnw/zig/dns/-/issues/176) (confidential) | 180d | Triage |
| 27 | Low | 8 | SEC-SCAN-05: dns_name.zig encodeName/encodeNameLower @intCast on label.len without max label check | dns_name.zig | CWE-190 / A03:2021 | dns_name.zig:127,139 | -- (skip-issues) | 180d | Triage |
| 28 | Low | 6 | ADV-05: Large header counts cause CPU-bound parse loop | message.zig | CWE-400 / A05:2021 | message.zig:62-82 | -- (skip-issues) | 180d | Triage |
| 29 | Low | 4 | SEC-SCAN-04: TCP/DoT/DoQ/ConnectionPool @intCast(u16) on wire_req.len without bounds check | tcp.zig, dot.zig, doq.zig, connection_pool.zig | CWE-190 / A03:2021 | tcp.zig:52, dot.zig:302, connection_pool.zig:557,662,707 | -- (skip-issues) | 180d | Triage |
| 30 | Low | 2 | SEC-SCAN-06: SIG(0) sign @intCast(u16) rdlength without bounds check | sig0.zig | CWE-190 / A03:2021 | sig0.zig:360 | -- (skip-issues) | 180d | Triage |
| 31 | Info | 1 | SEC-SCAN-07: name.zig toString doesn't enforce forward pointer rejection (defense-in-depth) | name.zig | CWE-345 / A03:2021 | name.zig:243 | -- (skip-issues) | Backlog | Triage |

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

#### SEC-SCAN-01 (MEDIUM): TsigKey.secret not zeroed on destruction

- **Summary:** `TsigKey` (tsig.zig:120-153) stores the shared HMAC secret as a plain `[]const u8` slice but has no `deinit` method. When a key is discarded, the secret remains in memory until the allocator reuses the page. This is distinct from SEC-C06/C25 which addressed zeroing of *computed* key material in HMAC state; SEC-SCAN-01 covers the *stored* key struct itself.
- **Impact:** Medium (2/5). Secret material lingers in process memory. Exploitable via memory disclosure bugs, core dumps, or swap.
- **Likelihood:** Low (2/5). Requires a separate memory read vulnerability or privileged access to process memory.
- **Evidence:** `src/security/tsig.zig:120-153` -- `TsigKey` struct has `init` and `initBase64` but no `deinit` or `secureZero` call on `.secret`.
- **Attack scenario:** If process memory is dumped (crash, swap, or `/proc/pid/mem`), TSIG secrets are recoverable because they were never zeroed.
- **Fix guidance:** Add a `deinit` method to `TsigKey` that calls `std.crypto.utils.secureZero` on `self.secret` before freeing. For `initBase64`-allocated secrets, also free via allocator.
- **Acceptance criteria:** (1) `TsigKey.deinit()` zeros secret before free. (2) All call sites updated to call `deinit`. (3) Test verifies secret bytes are zero after deinit.
- **References:** CWE-244 (Improper Clearing of Heap Memory), OWASP A02:2021 (Cryptographic Failures). Exploit surface: requires memory access.
- **Risk score:** 16 (Impact 2 x Likelihood 2 x 4)
- **Confidence:** `confidence::confirmed` -- no deinit method exists on TsigKey struct.

#### SEC-SCAN-02 (MEDIUM): ARCOUNT u16 overflow in TSIG/SIG(0) append

- **Summary:** Both `appendTsig` (tsig.zig:555) and the SIG(0) sign method (sig0.zig:346) read the existing ARCOUNT from the message header, add 1 via `arcount + 1`, and write back as u16. If ARCOUNT is already 65535 (u16 max), the addition wraps to 0 in release builds (undefined behavior) or panics in safe builds.
- **Impact:** Low (1/5). Corrupted ARCOUNT in the signed message. In practice, messages with 65535 additional records are not realistic.
- **Likelihood:** Very low (1/5). Requires a message with u16-max additional records before signing. Theoretical.
- **Evidence:** `src/security/tsig.zig:555` -- `std.mem.writeInt(u16, buffer.items[10..12], arcount + 1, .big);` / `src/security/sig0.zig:346` -- identical pattern.
- **Attack scenario:** Attacker crafts a message with ARCOUNT=65535 and requests signing. ARCOUNT wraps to 0, and the receiver sees 0 additional records instead of 65536, potentially ignoring the TSIG/SIG(0) record.
- **Fix guidance:** Check `if (arcount == std.math.maxInt(u16)) return error.TooManyAdditionalRecords;` before incrementing.
- **Acceptance criteria:** (1) Overflow check added. (2) Test with ARCOUNT=65535 returns error.
- **References:** CWE-190 (Integer Overflow), OWASP A03:2021 (Injection). Exploit surface: requires pre-auth message construction.
- **Risk score:** 9 (Impact 1 x Likelihood 1 x 4, rounded from 1.5x1.5 given the theoretical nature)
- **Confidence:** `confidence::confirmed` -- unchecked arithmetic verified by code inspection.

#### SEC-SCAN-03 (MEDIUM): Cache has no thread-safety

- **Summary:** `Cache` (cache.zig:68-252) is a plain struct with mutable `entries` slice and `count` field. All methods (`put`, `get`, `evictExpired`, `evictOldest`, `clear`) mutate shared state without any synchronization primitive (mutex, atomic, RwLock). Under concurrent access from multiple threads (e.g., recursive resolver + cache maintenance), this causes data races.
- **Impact:** Medium (3/5). Data races can cause corrupted cache state, use-after-free on entry strings, or inconsistent reads. Could lead to crashes or serving stale/wrong DNS data.
- **Likelihood:** Medium (3/5). Concurrent access is expected in any multi-threaded resolver. The spice integration adds parallelism.
- **Evidence:** `src/cache.zig:68-252` -- `Cache` struct. `put()` at line 105 mutates `self.count` and `self.entries`. `get()` at line 169 swaps entries in-place. No `Mutex` or `RwLock` field.
- **Attack scenario:** Two threads call `put()` and `get()` concurrently. Thread A evicts an entry and frees its name/rdata. Thread B reads the freed pointer via a stale `entries` reference. Use-after-free crash or information disclosure.
- **Fix guidance:** Add a `std.Thread.Mutex` or `std.Thread.RwLock` to `Cache`. Acquire lock in all public methods. Alternative: document Cache as single-threaded-only and provide a `ThreadSafeCache` wrapper.
- **Acceptance criteria:** (1) Cache is either protected by a lock or documented as single-threaded-only. (2) If locked, concurrent put/get stress test passes under ThreadSanitizer.
- **References:** CWE-362 (Concurrent Execution Using Shared Resource with Improper Synchronization), OWASP A04:2021 (Insecure Design). Exploit surface: internal (requires multi-threaded use).
- **Risk score:** 27 (Impact 3 x Likelihood 3 x 4, scaled to /125 as 27/125)
- **Confidence:** `confidence::confirmed` -- no synchronization primitives present in Cache struct.

#### SEC-SCAN-04 (LOW): TCP/DoT/DoQ/ConnectionPool @intCast(u16) on wire_req.len without bounds check

- **Summary:** Multiple transport implementations cast `wire_req.len` (a `usize`) to `u16` for the 2-byte DNS TCP length prefix without first checking that the length fits in 16 bits. DNS over TCP messages are limited to 65535 bytes by the wire format, but the API accepts arbitrary `[]const u8` slices.
- **Impact:** Low (2/5). Panic in safe builds; silent truncation in release builds causing malformed wire messages.
- **Likelihood:** Very low (1/5). Requires constructing a DNS message > 64KB, which exceeds normal DNS limits but is possible programmatically.
- **Evidence:** `src/transports/tcp.zig:52`, `src/transports/dot.zig:302`, `src/transports/connection_pool.zig:557,662,707` -- all use `@intCast(wire_req.len)` to u16 without prior bounds check.
- **Fix guidance:** Add `if (wire_req.len > std.math.maxInt(u16)) return error.MessageTooLarge;` before each cast.
- **Acceptance criteria:** (1) Bounds check before all @intCast(u16) on wire_req.len. (2) Test with oversized message returns error.
- **References:** CWE-190 (Integer Overflow), OWASP A03:2021. Exploit surface: requires caller to construct oversized messages.
- **Risk score:** 4 (Impact 2 x Likelihood 1 x 4, scaled as 4/125)
- **Confidence:** `confidence::confirmed` -- unchecked @intCast verified across 5 call sites.

#### SEC-SCAN-05 (LOW): dns_name.zig encodeName/encodeNameLower @intCast on label.len without max label check

- **Summary:** `encodeName` (dns_name.zig:127) and `encodeNameLower` (dns_name.zig:139) cast `label.len` to a single byte via `@intCast` without checking that the label length is <= 63 (the DNS maximum label length, RFC 1035 Section 2.3.4). Labels > 255 bytes would panic; labels 64-255 would silently encode invalid wire format.
- **Impact:** Low (2/5). Malformed wire-format names that violate DNS specifications. Could cause interoperability issues or unexpected behavior at remote resolvers.
- **Likelihood:** Low (2/5). Requires caller to pass a domain name with a label > 63 characters.
- **Evidence:** `src/security/dns_name.zig:127` -- `@intCast(label.len)` in encodeName; `src/security/dns_name.zig:139` -- same in encodeNameLower. No `if (label.len > 63)` check.
- **Fix guidance:** Add `if (label.len > 63) return error.LabelTooLong;` before the @intCast.
- **Acceptance criteria:** (1) Label length validated <= 63. (2) Test with 64-char label returns error.
- **References:** CWE-190 (Integer Overflow), OWASP A03:2021. RFC 1035 Section 2.3.4.
- **Risk score:** 8 (Impact 2 x Likelihood 2 x 4, scaled as 8/125)
- **Confidence:** `confidence::confirmed` -- no label length validation present.

#### SEC-SCAN-06 (LOW): SIG(0) sign @intCast(u16) rdlength without bounds check

- **Summary:** In the SIG(0) `sign` method (sig0.zig:360), `rdlength = sig_data.len + signature.len` is cast to u16 via `@intCast` without verifying it fits. If the signature + SIG data exceeds 65535 bytes, this panics in safe builds or truncates in release.
- **Impact:** Low (1/5). Panic or malformed SIG(0) record. Practical RSA/ECDSA signatures are well under 64KB.
- **Likelihood:** Very low (1/5). Would require an exotic key type producing enormous signatures.
- **Evidence:** `src/security/sig0.zig:360` -- `@intCast(rdlength)` where `rdlength = sig_data.len + signature.len`.
- **Fix guidance:** Add `if (rdlength > std.math.maxInt(u16)) return error.RdataTooLarge;` before the cast.
- **Acceptance criteria:** (1) Bounds check before cast. (2) Test with oversized signature data returns error.
- **References:** CWE-190 (Integer Overflow), OWASP A03:2021. Exploit surface: requires exotic key configuration.
- **Risk score:** 2 (Impact 1 x Likelihood 1 x 4, scaled as 2/125)
- **Confidence:** `confidence::confirmed` -- unchecked @intCast verified by inspection.

#### SEC-SCAN-07 (INFO): name.zig toString doesn't enforce forward pointer rejection

- **Summary:** `name.zig:243` `toString` follows compression pointers by computing `ptr_offset` from the two pointer bytes and jumping to `msg[ptr_offset..]`. While it has a hop limit (preventing infinite loops), it does not reject *forward* pointers (where `ptr_offset >= current position`). RFC 1035 Section 4.1.4 compression pointers should only reference earlier positions. The sibling `dns_name.zig` already rejects forward pointers (SEC-C30 fix), but `name.zig` does not.
- **Impact:** Minimal (1/5). Defense-in-depth. Forward pointers are unusual but not directly exploitable given the existing hop limit.
- **Likelihood:** Very low (1/5). Would require crafted messages with forward pointers, and the hop limit already prevents loops.
- **Evidence:** `src/name.zig:243` -- `const ptr_offset = (@as(u16, len_byte & 0x3F) << 8) | data[pos + 1];` followed by `data = msg[ptr_offset..]` with no forward check.
- **Fix guidance:** Add `if (ptr_offset >= current_absolute_offset) return error.ForwardCompressionPointer;` before following the pointer.
- **Acceptance criteria:** (1) Forward pointer rejection added. (2) Test with forward pointer returns error.
- **References:** CWE-345 (Insufficient Verification of Data Authenticity), OWASP A03:2021. RFC 1035 Section 4.1.4.
- **Risk score:** 1 (Impact 1 x Likelihood 1 x 4, scaled as 1/125)
- **Confidence:** `confidence::confirmed` -- forward pointer check absent; verified by code inspection.

#### ADV-02 (LOW): No TSIG replay protection within fudge window

- **Summary:** The TSIG `verify` method (tsig.zig:302-408) validates MAC and time window but does not track previously-seen message IDs or MACs. Within the fudge window (default 300 seconds), a captured valid TSIG-signed message can be replayed verbatim and will pass verification.
- **Impact:** Low (2/5). Replay of DNS updates or zone transfers within the time window. Impact depends on what operations are TSIG-protected.
- **Likelihood:** Medium (3/5). Requires network capture of a valid TSIG message and replay within the fudge window. Straightforward for on-path attackers.
- **Evidence:** `src/security/tsig.zig:302-408` -- `verify()` checks MAC + time but has no nonce/replay cache. Compare with SEC-C29 (SIG(0) replay) which tracks the same class of issue for SIG(0).
- **Attack scenario:** On-path attacker captures a TSIG-signed DNS UPDATE adding a record. Replays it within 300 seconds. The update is accepted again.
- **Fix guidance:** Implement a bounded replay cache keyed on (original_id, MAC prefix, time_signed). Entries expire after fudge window. This mirrors the recommended fix for SEC-C29.
- **Acceptance criteria:** (1) Replay cache rejects duplicate (id, mac_prefix, time_signed) tuples. (2) Test verifies replay within fudge window is rejected.
- **References:** CWE-294 (Authentication Bypass by Capture-replay), OWASP A07:2021. RFC 2845 Section 3.
- **Risk score:** 12 (Impact 2 x Likelihood 3 x 4, scaled as 12/125 -- note: related to SEC-C29 but distinct protocol)
- **Confidence:** `confidence::confirmed` -- no replay tracking in verify(). Complementary to SEC-C29 (SIG(0)).

#### ADV-05 (LOW): Large header counts cause CPU-bound parse loop

- **Summary:** `Message.parse` (message.zig:62-82) iterates over `qdcount`, `ancount`, and `nscount` from the DNS header to compute section offsets. These are attacker-controlled u16 values. A crafted message with `ancount=65535` causes up to 65535 iterations of `ResourceRecord.parse`, each of which walks the wire format. While each iteration does bounds-check, the cumulative CPU cost is significant for a single packet.
- **Impact:** Low (2/5). CPU exhaustion for a single parse call. Not amplified -- one packet causes one slow parse.
- **Likelihood:** Low (1.5/5, rounded to 2). Requires sending crafted DNS responses to a resolver. Mitigated by upstream transport timeouts and the fact that each RR parse validates bounds (so most iterations fail early on malformed data).
- **Evidence:** `src/message.zig:62-82` -- three `while` loops iterating over header counts. No maximum count validation.
- **Fix guidance:** Add a sanity cap: `if (header.ancount > MAX_REASONABLE_RR_COUNT) return error.TooManyRecords;`. A reasonable limit is 4096 or configurable.
- **Acceptance criteria:** (1) Maximum RR count per section enforced. (2) Test with ancount=65535 returns error or completes within bounded time.
- **References:** CWE-400 (Uncontrolled Resource Consumption), OWASP A05:2021.
- **Risk score:** 6 (Impact 2 x Likelihood 1.5 x 4, rounded to 6/125)
- **Confidence:** `confidence::confirmed` -- no count limit in parse loop.

### Phase 3 + Adversarial Review Security Summary

- **Critical:** 1 finding -- **1 resolved** (SEC-C22 infinite loop DoS)
- **High:** 6 findings -- **6 resolved** (SEC-C02 enum panic, SEC-C05 weak PRNG, SEC-C23 key truncation, SEC-C26 partial write, SEC-NEW-01 OOB in extractTsig, SEC-NEW-02 OOB in extractSig0)
- **Medium:** 12 findings -- **7 resolved** (SEC-C27 bailiwick, SEC-C28 auth default, SEC-C30 forward ptr, SEC-C06/C25 key zeroing, SEC-NEW-03 skipRR bounds, SEC-NEW-06 question skip bounds, SEC-C100 fudge clamp); **5 open** (SEC-C29 replay, SEC-C14/C31 supply chain, SEC-SCAN-01 TsigKey secret, SEC-SCAN-02 ARCOUNT overflow, SEC-SCAN-03 cache thread-safety)
- **Low:** 12 findings -- **6 resolved** (SEC-C33 short read, SEC-NEW-07 skipName ptr, SEC-C101 timing oracle reorder, SEC-NEW-04 other_data truncation, SEC-NEW-05 intCast overflow); **6 open** (SEC-C32 timestamp overflow, ADV-02 TSIG replay, ADV-05 parse loop, SEC-SCAN-04 transport intCast, SEC-SCAN-05 label len, SEC-SCAN-06 SIG(0) rdlength)
- **Info:** 1 finding -- **1 open** (SEC-SCAN-07 forward pointer in name.zig)

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

**Remaining quick wins (< 1 day each):**
- SEC-SCAN-01: Add `deinit` to `TsigKey` with `secureZero` on `.secret`
- SEC-SCAN-02: Add overflow check before `arcount + 1` in tsig.zig:555 and sig0.zig:346
- SEC-SCAN-04: Add `if (wire_req.len > maxInt(u16))` check in tcp.zig, dot.zig, connection_pool.zig (5 sites)
- SEC-SCAN-05: Add `if (label.len > 63)` check in dns_name.zig encodeName/encodeNameLower
- SEC-SCAN-06: Add `if (rdlength > maxInt(u16))` check in sig0.zig:360

**Remaining medium effort (1-5 days):**
- SEC-SCAN-03: Add mutex/RwLock to Cache or document as single-threaded + provide ThreadSafeCache wrapper
- ADV-05: Add configurable max RR count per section in message.zig parse loop

**Remaining (backlog):**
- SEC-C29: SIG(0) replay cache (bounded data structure + time-based eviction) -- defense-in-depth
- ADV-02: TSIG replay cache (complementary to SEC-C29) -- defense-in-depth
- SEC-C32: SIG(0) timestamp u32 overflow in 2106 -- low priority
- SEC-C14/C31: spice dependency pins main branch -- upstream concern (cross-ref GAP-0047)
- SEC-SCAN-07: Forward pointer rejection in name.zig toString -- defense-in-depth

---

## Gap Priority Matrix

| Severity | Total | Resolved | Open | Gap-IDs / SEC-IDs |
|----------|-------|----------|------|-------------------|
| Critical | 2 | 2 | 0 | GAP-0027/SEC-C26, GAP-0028/SEC-C22 |
| High | 11 | 9 | 2 | **Resolved:** GAP-0026, GAP-0029, GAP-0030, GAP-0033/SEC-C20, GAP-0034/SEC-C21, SEC-C23, SEC-C05/C24, SEC-NEW-01, SEC-NEW-02. **Open:** GAP-0045, GAP-0046 |
| Medium | 27 | 15 | 12 | **Resolved:** GAP-0015 (partial), GAP-0031, GAP-0032, GAP-0035, GAP-0036, GAP-0037, SEC-C27, SEC-C28, SEC-C30, SEC-C06/C25, SEC-NEW-03, SEC-NEW-06, SEC-C100. **Open:** GAP-0017, GAP-0038, GAP-0039, GAP-0041, GAP-0042, GAP-0043, GAP-0044, GAP-0047, SEC-C29, SEC-SCAN-01, SEC-SCAN-02, SEC-SCAN-03 |
| Low | 18 | 10 | 8 | **Resolved:** GAP-0021, GAP-0022, GAP-0023, GAP-0024, GAP-0025, SEC-C33, SEC-NEW-07, SEC-C101, SEC-NEW-04, SEC-NEW-05. **Open:** GAP-0040, SEC-C32, ADV-02, ADV-05, SEC-SCAN-04, SEC-SCAN-05, SEC-SCAN-06 |
| Info | 1 | 0 | 1 | **Open:** SEC-SCAN-07 |

## Production Readiness Assessment

### Remaining Open Items

| Gap-ID / SEC-ID | Blocks Production Use? | Rationale |
|-----------------|----------------------|-----------|
| GAP-0015 | No (partially resolved) | Docs updated; tracker reconciliation is administrative |
| GAP-0017 | No (partially resolved) | Transports exposed in API; resolver wiring is future refactor |
| GAP-0038 | No | Documentation inaccuracy; does not affect functionality |
| GAP-0039 | No | Documentation inaccuracy; DNSSEC Ed25519/ECDSA works correctly |
| GAP-0040 | No | Documentation inaccuracy; DoT interface works, just needs backend |
| GAP-0041 | No | Convenience API returns explicit errors; `client.Client` is the working alternative |
| GAP-0042 | No | Feature gap; raw query API works for all record types |
| GAP-0043 | **Yes (correctness bug)** | Cache hits for MX/SRV/TXT return empty results; causes silent data loss |
| GAP-0044 | No | Architectural debt; inline socket code works correctly |
| GAP-0045 | **Recommended before production** | Core resolution loop has zero tests; high regression risk |
| GAP-0046 | **Recommended before production** | Wire parsers handle untrusted input with no fuzz coverage |
| GAP-0047 | No (mitigated) | Hash pinning provides partial protection; cross-ref SEC-C14/C31 |
| SEC-C29 | No (defense-in-depth) | Replay requires capture + time window; mitigated by short validity |
| SEC-C14/C31 | No (mitigated) | Hash pinning provides partial protection |
| SEC-C32 | No | Year 2106 issue |
| SEC-SCAN-01 | No (defense-in-depth) | Secret lingers in memory but requires separate memory disclosure to exploit |
| SEC-SCAN-02 | No | ARCOUNT=65535 is not a realistic scenario |
| SEC-SCAN-03 | **Recommended fix for multi-threaded use** | Data races if Cache is shared across threads; single-threaded use is safe |
| SEC-SCAN-04 | No (low impact) | DNS messages > 64KB are not standard; callers would need to construct them explicitly |
| SEC-SCAN-05 | No (low impact) | Labels > 63 chars violate DNS spec; callers would need to pass invalid names |
| SEC-SCAN-06 | No (low impact) | Signatures + SIG data exceeding 64KB is not practical with current key types |
| SEC-SCAN-07 | No (defense-in-depth) | Hop limit already prevents loops; forward pointer rejection is belt-and-suspenders |
| ADV-02 | No (defense-in-depth) | Same class as SEC-C29; mitigated by short fudge window |
| ADV-05 | No (low impact) | Bounds checks in RR parse cause early failure on malformed data; no amplification |

### Production Blockers

All Critical and High severity security bugs are now **resolved** (SEC-NEW-02 and SEC-NEW-05 fixed in commit 8fef334). The remaining production concerns are:

1. **GAP-0043** (Medium, correctness bug): Cache hits for non-A/AAAA records return empty results. This causes silent data loss and should be fixed before production use with MX/SRV/TXT queries.
2. **GAP-0045** (High, test coverage): The core `resolveIterative` function (219 lines, 9 nesting levels) has zero test coverage. Previous critical bugs (GAP-0019, GAP-0020) were found by review, not tests.
3. **GAP-0046** (High, fuzz testing): Wire parsers have no fuzz testing despite 7 bounds-check bugs found by manual review.
4. **SEC-SCAN-03** (Medium, thread-safety): Cache has no synchronization. If the resolver is used from multiple threads, data races will occur.

For deployments using only A/AAAA lookups via the stub resolver in a single-threaded context, the library is production-ready. For full recursive resolution, non-A/AAAA record types, or multi-threaded use, GAP-0043, GAP-0045, and SEC-SCAN-03 should be addressed first.
