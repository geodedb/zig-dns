# Gap Closure Completion Report

Generated: 2026-03-24
Pipeline: 5 phases of gap closure work across 3 analysis files

## GAP_ANALYSIS Status

| File | Closed | Blocked | Won't Do | Partially Resolved | Deferred | Total |
|------|--------|---------|----------|--------------------|----------|-------|
| GAP_ANALYSIS.md | 6 | 0 | 2 | 2 | 0 | 10 |
| QUALITY_GAP_ANALYSIS.md | 13 | 0 | 0 | 0 | 3 | 16 |
| PERF_GAP_ANALYSIS.md | 9 | 0 | 0 | 0 | 9 | 18 |
| **Totals** | **28** | **0** | **2** | **2** | **12** | **44** |

**Overall:** 28 closed, 2 won't do, 2 partially resolved, 12 deferred out of 44 total items.

No items are blocked. All items have been explicitly addressed -- none were silently skipped.

---

## Closed Items

| Gap-ID | File | Title | Evidence |
|--------|------|-------|----------|
| GAP-0011 | GAP_ANALYSIS.md | 18 modules suppressed from public API | `build.zig`: all `_ =` removed; `src/lib.zig`: 21 `pub const` re-exports; 316/316 tests pass |
| GAP-0012 | GAP_ANALYSIS.md | Dual recursive resolver placeholder | `src/resolver/recursive.zig` deleted; `src/recursive.zig` sole implementation; ARCHITECTURE.md updated |
| GAP-0016 | GAP_ANALYSIS.md | Placeholder resolver tests inflate count | Orphaned file deleted (GAP-0012); test count verified accurate at 316 |
| GAP-0018 | GAP_ANALYSIS.md | ARCHITECTURE.md says WIP/STUB for complete features | All WIP/STUB/placeholder labels removed from `docs/ARCHITECTURE.md`; synced with ROADMAP.md |
| GAP-0019 | GAP_ANALYSIS.md | CNAME continue targets wrong loop | `src/recursive.zig`: `outer:` label added; `continue :outer` after CNAME detection; tests: "CNAME break-then-continue-outer pattern", "CNAME chain limit enforcement" |
| GAP-0020 | GAP_ANALYSIS.md | Referral servers never assigned | `src/recursive.zig`: `owned_servers`/`owned_zone` ownership transfer; tests: "owned_servers memory lifecycle", "owned_zone memory lifecycle" |
| QC-01 | QUALITY_GAP_ANALYSIS.md | SVCB hint parsers return dangling stack pointers | `src/record.zig`: `parseSvcbIpv4Hint`/`parseSvcbIpv6Hint` accept allocator, return heap-allocated slices |
| QH-01 | QUALITY_GAP_ANALYSIS.md | CNAME continue targets inner loop | Same fix as GAP-0019 |
| QH-02 | QUALITY_GAP_ANALYSIS.md | Referral NS servers never assigned | Same fix as GAP-0020 |
| QH-03 | QUALITY_GAP_ANALYSIS.md | IPv4.format() undefined trailing bytes | `src/resolver/convenience.zig`: returns `Formatted` struct with `buf` + `len` fields |
| QH-04 | QUALITY_GAP_ANALYSIS.md | Name.eql() uses page_allocator (2 mmap/call) | `src/name.zig`: allocation-free label-by-label comparison rewrite |
| QM-01 | QUALITY_GAP_ANALYSIS.md | parseName() duplicated in tsig/sig0 | `src/security/dns_name.zig` extracted; shared by `tsig.zig` and `sig0.zig` |
| QM-02 | QUALITY_GAP_ANALYSIS.md | Duplicated root server definitions | Orphaned `src/resolver/recursive.zig` deleted (GAP-0012) |
| QM-04 | QUALITY_GAP_ANALYSIS.md | 18 modules lack API boundary docs | `build.zig`: all module declarations have `// Public API` or `// Internal` comments |
| QM-05 | QUALITY_GAP_ANALYSIS.md | Silent error swallowing (catch {}) | All `catch {}` sites documented with justification or upgraded to `catch \|err\| std.log.debug(...)` |
| QM-06 | QUALITY_GAP_ANALYSIS.md | ARCHITECTURE.md missing 60% of modules | `docs/ARCHITECTURE.md`: comprehensive Module Index table added for all 40+ modules |
| QL-01 | QUALITY_GAP_ANALYSIS.md | 7 identical @intFromPtr blocks | `src/record.zig`: `rdataOffset()` helper extracted; all 7 call sites updated |
| QL-02 | QUALITY_GAP_ANALYSIS.md | verifyCase0x20 reimplements std.mem.eql | `src/name.zig`: replaced with `std.mem.eql(u8, ...)` |
| QL-04 | QUALITY_GAP_ANALYSIS.md | No doc comment on rdata-offset invariant | `src/record.zig`: doc comments added to `ResourceRecord` struct and `rdataOffset()` helper |
| PF-01 | PERF_GAP_ANALYSIS.md | Name.eql() page_allocator (~1000x slower) | `src/name.zig`: zero-allocation label-by-label comparison |
| PF-04 | PERF_GAP_ANALYSIS.md | O(ns*additional) in extractReferral | `src/recursive.zig`: single-pass additional section collection |
| PF-06 | PERF_GAP_ANALYSIS.md | 65KB stack buffer per UDP receive | `src/stub.zig`, `src/recursive.zig`, `src/transports/udp.zig`: buffer reduced to 4096 (RFC 6891) |
| PF-07 | PERF_GAP_ANALYSIS.md | O(n) section skipping in message.zig | `src/message.zig`: section offsets cached at parse time; O(1) access |
| PF-08 | PERF_GAP_ANALYSIS.md | buildCnameChain re-iterates per hop | `src/client.zig`: pre-built CNAME mapping array; O(ancount + hops) |
| PF-11 | PERF_GAP_ANALYSIS.md | Memory leak: ResolutionState.last_query_name | `src/recursive.zig`: `ResolutionState.deinit()` added; `resolve()` uses `defer state.deinit()` |
| PF-12 | PERF_GAP_ANALYSIS.md | Memory leak: DnsCache zone_name not freed | `src/resolver/dns_cache.zig`: `on_evict` callback frees `zone_name`; `freeCacheEntry` updated |
| PF-15 | PERF_GAP_ANALYSIS.md | Double allocation in DnsCache.makeKey | `src/resolver/dns_cache.zig`: stack buffer `lower_buf: [max_name_length]u8` replaces heap allocation |
| PF-17 | PERF_GAP_ANALYSIS.md | Thread pool uses page_allocator | `src/parallel.zig`: GPA-backed allocator wraps pool allocator |

## Won't Do Items

| Gap-ID | File | Title | Reason |
|--------|------|-------|--------|
| GAP-0013 | GAP_ANALYSIS.md | DNSSEC RSA algorithms (8/10/5) return UnsupportedAlgorithm | Requires external cryptographic library (BoringSSL, mbedTLS, or bearssl). No pure-Zig RSA implementation exists. ROADMAP.md Phase 3 updated to PARTIAL. Ed25519 and ECDSA P-256/P-384 work via std.crypto. |
| GAP-0014 | GAP_ANALYSIS.md | DoT/DoH/DoQ transports ship zero backend implementations | Requires external TLS/HTTP/QUIC libraries. The vtable interface design is the correct architecture for a pure-Zig library. ROADMAP.md updated to clearly label as "interface only". Compatible libraries documented. |

## Partially Resolved Items

| Gap-ID | File | Title | What Was Done | What Remains |
|--------|------|-------|---------------|--------------|
| GAP-0015 | GAP_ANALYSIS.md | 24 issues marked Complete in docs but Open in GitLab | ROADMAP.md statuses updated to reflect actual code state; Phase 3 downgraded to PARTIAL; "Issue Tracker Note" section added | Close/reconcile GitLab issues #9-#22 and #42-#58 (administrative action) |
| GAP-0017 | GAP_ANALYSIS.md | Functional UDP/TCP transports suppressed from public API | Transport modules exposed in public API via `@import("dns").transport_udp` etc. (GAP-0011) | Refactor `src/recursive.zig:sendQuery()` to use transport module abstractions instead of inline socket code |

## Deferred Items

| Gap-ID | File | Title | Reason |
|--------|------|-------|--------|
| QH-05 | QUALITY_GAP_ANALYSIS.md | Zero fuzz testing for wire parsers | Requires fuzz infrastructure setup; important but non-blocking |
| QM-03 | QUALITY_GAP_ANALYSIS.md | resolveIterative 171 lines / 9 nesting levels | Bugs fixed (GAP-0019, GAP-0020); refactoring is lower risk now |
| QL-03 | QUALITY_GAP_ANALYSIS.md | 9 source files exceed 800-line threshold | Risky refactor with low priority; no correctness impact |
| PF-02 | PERF_GAP_ANALYSIS.md | O(n) linear-scan cache, DnsCache unused | Larger refactor; DnsCache leak fixed (PF-12) first |
| PF-03 | PERF_GAP_ANALYSIS.md | New UDP socket per query (5 syscalls) | ConnectionPool exists and is exposed; wiring into core resolvers is larger refactor |
| PF-05 | PERF_GAP_ANALYSIS.md | No per-query arena allocator | Architectural change affecting many files |
| PF-09 | PERF_GAP_ANALYSIS.md | responseMatchesQuery allocates string | Depends on further Name API work beyond PF-01 |
| PF-10 | PERF_GAP_ANALYSIS.md | allocPrint for IP formatting (17 sites) | 17 sites across 12 files; tedious but low-risk |
| PF-13 | PERF_GAP_ANALYSIS.md | No concurrent query support | Requires thread-safe cache (PF-14) first |
| PF-14 | PERF_GAP_ANALYSIS.md | Cache has no thread safety | Prerequisite for PF-13; larger effort |
| PF-16 | PERF_GAP_ANALYSIS.md | New PRNG per getSecureRandomId call | Low impact optimization |
| PF-18 | PERF_GAP_ANALYSIS.md | No benchmarks or perf regression CI | Sustained infrastructure effort |

---

## Tests Executed

| Command | Result |
|---------|--------|
| `zig build test` | PASS (316/316 tests) |
| `zig build` (all 95 build steps) | PASS (95/95) |
| `zig fmt --check src/ cmd/` | PASS (clean) |

54 new tests added during gap closure (262 -> 316).
0 regressions.

## Security Notes

- **QC-01 (Critical UB):** `parseSvcbIpv4Hint`/`parseSvcbIpv6Hint` returned slices to stack-local arrays (use-after-return). Fixed by accepting allocator parameter and returning heap-allocated owned slices. This was the highest-severity security fix.
- **PF-01 / QH-04 (DoS vector):** `Name.eql()` using `page_allocator` caused 2 mmap+munmap syscalls per comparison, enabling resource exhaustion. Fixed with zero-allocation label-by-label comparison.
- **GAP-0019 / GAP-0020 (Recursive resolver broken):** CNAME chasing and referral delegation were both non-functional. These were correctness bugs, not security bugs per se, but a non-functional resolver could push users to insecure fallback paths.
- **PF-11 / PF-12 (Memory leaks):** `ResolutionState.last_query_name` and `DnsCache.zone_name` were both leaking. Fixed with proper `deinit()` methods and `on_evict` callbacks. Memory leaks in a long-running resolver process eventually cause OOM.
- **Won't Do items (GAP-0013, GAP-0014):** RSA DNSSEC and encrypted transports require external crypto/TLS/HTTP/QUIC libraries. Documented limitations; users are aware that `dnssec_validate: true` does not work for RSA-signed zones (root zone, ~70-80% of signed domains).
- **No hardcoded secrets, credentials, or API keys found in any changed files.**

## Remaining Blockers

None. All items are either resolved, explicitly deferred with documented rationale, or categorized as Won't Do with justification.

The 2 partially resolved items (GAP-0015, GAP-0017) have clear remaining work scoped:
- GAP-0015: Administrative GitLab issue closure (no code changes needed)
- GAP-0017: Resolver transport abstraction refactor (future improvement, not a blocker)

---

## Platform Issues -- Recommended Actions

### Issues to Close (28 resolved gaps with linked issues)

| Gap-ID | Issue | Action | Evidence Summary |
|--------|-------|--------|------------------|
| GAP-0011 | [#74](https://gitlab.com/devnw/zig/dns/-/issues/74) | Close | All 21 modules exposed via lib.zig re-exports + build.zig wiring |
| GAP-0012 | [#75](https://gitlab.com/devnw/zig/dns/-/issues/75) | Close | `src/resolver/recursive.zig` deleted; single canonical implementation remains |
| GAP-0016 | [#79](https://gitlab.com/devnw/zig/dns/-/issues/79) | Close | Orphaned tests deleted; test count accurate at 316 |
| GAP-0018 | [#81](https://gitlab.com/devnw/zig/dns/-/issues/81) | Close | All WIP/STUB labels removed from ARCHITECTURE.md |
| GAP-0019 | [#85](https://gitlab.com/devnw/zig/dns/-/issues/85) | Close | `outer:` label pattern; CNAME chasing functional with tests |
| GAP-0020 | [#88](https://gitlab.com/devnw/zig/dns/-/issues/88) | Close | `owned_servers`/`owned_zone` ownership transfer with lifecycle tests |
| QC-01 | [#83](https://gitlab.com/devnw/zig/dns/-/issues/83) | Close | SVCB hint parsers accept allocator, return heap-allocated slices |
| QH-01 | [#86](https://gitlab.com/devnw/zig/dns/-/issues/86) | Close | Same fix as GAP-0019 (outer loop restart) |
| QH-02 | [#91](https://gitlab.com/devnw/zig/dns/-/issues/91) | Close | Same fix as GAP-0020 (owned_servers lifecycle) |
| QH-03 | [#92](https://gitlab.com/devnw/zig/dns/-/issues/92) | Close | IPv4.format() returns Formatted struct with buf+len |
| QH-04 | [#95](https://gitlab.com/devnw/zig/dns/-/issues/95) | Close | Name.eql() zero-allocation label-by-label comparison |
| QM-01 | [#102](https://gitlab.com/devnw/zig/dns/-/issues/102) | Close | Shared `src/security/dns_name.zig` extracted |
| QM-02 | [#106](https://gitlab.com/devnw/zig/dns/-/issues/106) | Close | Orphaned resolver deleted (GAP-0012) |
| QM-04 | [#113](https://gitlab.com/devnw/zig/dns/-/issues/113) | Close | API boundary comments added to all module declarations in build.zig |
| QM-05 | [#117](https://gitlab.com/devnw/zig/dns/-/issues/117) | Close | All catch {} sites documented or upgraded to logged errors |
| QM-06 | [#119](https://gitlab.com/devnw/zig/dns/-/issues/119) | Close | Comprehensive Module Index added to ARCHITECTURE.md |
| QL-01 | [#121](https://gitlab.com/devnw/zig/dns/-/issues/121) | Close | rdataOffset() helper extracted; all 7 duplicates removed |
| QL-02 | [#123](https://gitlab.com/devnw/zig/dns/-/issues/123) | Close | Replaced with std.mem.eql |
| QL-04 | [#127](https://gitlab.com/devnw/zig/dns/-/issues/127) | Close | Doc comments added to ResourceRecord struct and rdataOffset() |
| PF-01 | [#82](https://gitlab.com/devnw/zig/dns/-/issues/82) | Close | Zero-allocation label-by-label comparison in Name.eql() |
| PF-04 | [#93](https://gitlab.com/devnw/zig/dns/-/issues/93) | Close | Single-pass additional section collection in extractReferral |
| PF-06 | [#99](https://gitlab.com/devnw/zig/dns/-/issues/99) | Close | UDP buffer reduced from 65535 to 4096 in all 3 locations |
| PF-07 | [#101](https://gitlab.com/devnw/zig/dns/-/issues/101) | Close | Section offsets cached in Message struct at parse time |
| PF-08 | [#103](https://gitlab.com/devnw/zig/dns/-/issues/103) | Close | Pre-built CNAME mapping array; O(ancount + hops) |
| PF-11 | [#110](https://gitlab.com/devnw/zig/dns/-/issues/110) | Close | ResolutionState.deinit() with defer in resolve() |
| PF-12 | [#114](https://gitlab.com/devnw/zig/dns/-/issues/114) | Close | on_evict callback frees zone_name in DnsCache |
| PF-15 | [#120](https://gitlab.com/devnw/zig/dns/-/issues/120) | Close | Stack buffer lower_buf replaces heap allocation in makeKey |
| PF-17 | [#124](https://gitlab.com/devnw/zig/dns/-/issues/124) | Close | GPA-backed allocator wraps pool allocator |

### Issues to Comment (Won't Do)

| Gap-ID | Issue | Action | Comment |
|--------|-------|--------|---------|
| GAP-0013 | [#76](https://gitlab.com/devnw/zig/dns/-/issues/76) | Comment (won't do) | Requires external crypto library for RSA. Documented as PARTIAL in ROADMAP.md. Ed25519/ECDSA work. |
| GAP-0014 | [#77](https://gitlab.com/devnw/zig/dns/-/issues/77) | Comment (won't do) | Vtable interface is correct design. Documented as "interface only" requiring external backends. |

### Issues to Comment (Partially Resolved)

| Gap-ID | Issue | Action | Comment |
|--------|-------|--------|---------|
| GAP-0015 | [#78](https://gitlab.com/devnw/zig/dns/-/issues/78) | Comment (partial) | Docs updated to reflect code state. Tracker reconciliation remains. |
| GAP-0017 | [#80](https://gitlab.com/devnw/zig/dns/-/issues/80) | Comment (partial) | Transports exposed in public API. Resolver wiring to transport abstractions deferred. |

### Issues to Comment (Deferred)

| Gap-ID | Issue | Action | Comment |
|--------|-------|--------|---------|
| QH-05 | [#98](https://gitlab.com/devnw/zig/dns/-/issues/98) | Comment (deferred) | Fuzz infrastructure setup deferred to future cycle |
| QM-03 | [#109](https://gitlab.com/devnw/zig/dns/-/issues/109) | Comment (deferred) | Bugs fixed (GAP-0019/0020); complexity refactor deferred |
| QL-03 | [#126](https://gitlab.com/devnw/zig/dns/-/issues/126) | Comment (deferred) | File splitting deferred; low priority |
| PF-02 | [#87](https://gitlab.com/devnw/zig/dns/-/issues/87) | Comment (deferred) | DnsCache leak fixed (PF-12); migration deferred |
| PF-03 | [#90](https://gitlab.com/devnw/zig/dns/-/issues/90) | Comment (deferred) | ConnectionPool exposed; wiring deferred |
| PF-05 | [#96](https://gitlab.com/devnw/zig/dns/-/issues/96) | Comment (deferred) | Architectural change; deferred |
| PF-09 | [#105](https://gitlab.com/devnw/zig/dns/-/issues/105) | Comment (deferred) | Depends on further Name API work |
| PF-10 | [#108](https://gitlab.com/devnw/zig/dns/-/issues/108) | Comment (deferred) | 17 sites; tedious but low-risk; deferred |
| PF-13 | [#116](https://gitlab.com/devnw/zig/dns/-/issues/116) | Comment (deferred) | Requires PF-14 (thread-safe cache) first |
| PF-14 | [#118](https://gitlab.com/devnw/zig/dns/-/issues/118) | Comment (deferred) | Prerequisite for PF-13; deferred |
| PF-16 | [#122](https://gitlab.com/devnw/zig/dns/-/issues/122) | Comment (deferred) | Low impact; deferred |
| PF-18 | [#125](https://gitlab.com/devnw/zig/dns/-/issues/125) | Comment (deferred) | Infrastructure effort; deferred |

### Related Security Issues (Resolved by Same Fixes)

These security issues track the same underlying bugs that were fixed via gap closure. They should also be closed.

| Issue | Related Gap-ID | Evidence |
|-------|---------------|----------|
| [#84](https://gitlab.com/devnw/zig/dns/-/issues/84) (SEC-C01: Use-after-return in SVCB parsers) | QC-01 | Same fix: heap-allocated slices replace stack returns |
| [#97](https://gitlab.com/devnw/zig/dns/-/issues/97) (SEC-C10: Name.eql() page_allocator DoS) | QH-04 / PF-01 | Same fix: allocation-free label comparison |

---

## Change Statistics

| Metric | Value |
|--------|-------|
| Files changed | 27 |
| Lines added | +2,137 |
| Lines removed | -1,019 |
| Net change | +1,118 |
| New tests added | 54 (262 -> 316) |
| Build steps | 95/95 |
| Regressions | 0 |

## Files Modified (Key Changes)

| File | Change Summary |
|------|---------------|
| `src/recursive.zig` | CNAME outer-loop restart (GAP-0019), owned_servers lifecycle (GAP-0020), extractReferral single-pass (PF-04), ResolutionState.deinit() (PF-11) |
| `src/name.zig` | Name.eql() zero-allocation rewrite (QH-04/PF-01), verifyCase0x20 simplification (QL-02) |
| `src/record.zig` | SVCB hint parser heap allocation (QC-01), rdataOffset() helper extraction (QL-01), doc comments (QL-04) |
| `src/message.zig` | Section offset caching (PF-07) |
| `src/client.zig` | CNAME chain single-pass mapping (PF-08) |
| `src/resolver/convenience.zig` | IPv4.format() Formatted struct (QH-03) |
| `src/resolver/dns_cache.zig` | on_evict zone_name fix (PF-12), makeKey stack buffer (PF-15) |
| `src/security/dns_name.zig` | New shared module extracted from tsig/sig0 (QM-01) |
| `src/stub.zig` | UDP buffer 4096 (PF-06) |
| `src/transports/udp.zig` | UDP buffer 4096 (PF-06) |
| `src/parallel.zig` | GPA wrapper (PF-17) |
| `src/lib.zig` | 21 pub const re-exports (GAP-0011) |
| `build.zig` | Module wiring + API boundary comments (GAP-0011, QM-04) |
| `docs/ARCHITECTURE.md` | WIP/STUB removal, module index (GAP-0018, QM-06) |
| `src/resolver/recursive.zig` | **Deleted** (GAP-0012, QM-02) |

---

## Verification Checklist

- [x] Every gap item in GAP_ANALYSIS.md has been addressed (6 resolved, 2 won't do, 2 partial)
- [x] Every gap item in QUALITY_GAP_ANALYSIS.md has been addressed (13 resolved, 3 deferred)
- [x] Every gap item in PERF_GAP_ANALYSIS.md has been addressed (9 resolved, 9 deferred)
- [x] No item is unaddressed, ambiguous, or silently skipped
- [x] All 3 tracking files accurately reflect the final state
- [x] GAP_ANALYSIS_RESOLVED.md updated with resolved items from this cycle
- [x] All tests pass (316/316)
- [x] Build clean (95/95 steps)
- [x] Format clean (zig fmt)
- [x] No regressions
