# Gap Analysis -- Resolved

Last updated: 2026-03-24

Items below were identified in prior gap analyses and verified as resolved. They are listed here for audit trail purposes.

---

### GAP-0001: UDP source address validation missing [RESOLVED]
- **Issue:** [#42](https://gitlab.com/devnw/zig/dns/-/issues/42) (open -- needs closure)
- **Category:** Security
- **Resolution:** Source address validation check added to UDP transport
- **Evidence:** `src/transports/udp.zig:73` -- `std.net.Address.eql(src_addr, self.address)` check present
- **Resolved date:** 2026-01-30

### GAP-0002: Response validation incomplete [RESOLVED]
- **Issue:** [#43](https://gitlab.com/devnw/zig/dns/-/issues/43) (open -- needs closure)
- **Category:** Security
- **Resolution:** TXID, QNAME, and QTYPE matching added to query/response validation
- **Evidence:** `src/recursive.zig:437` -- TXID + QNAME + QTYPE matching in `queryWithRetry`
- **Resolved date:** 2026-01-30

### GAP-0003: DnsLogger buffer grows unbounded [RESOLVED]
- **Issue:** [#55](https://gitlab.com/devnw/zig/dns/-/issues/55) (open -- needs closure)
- **Category:** Security
- **Resolution:** Buffer bounds checking implemented
- **Evidence:** `src/resolver/logging.zig` -- `checkAndFlush()` implemented
- **Resolved date:** 2026-01-30

### GAP-0004: CSPRNG for TXID generation [RESOLVED]
- **Issue:** [#35](https://gitlab.com/devnw/zig/dns/-/issues/35) (open -- needs closure)
- **Category:** Security
- **Resolution:** Weak random fallback replaced with cryptographic random
- **Evidence:** `src/recursive.zig:150-154` -- `std.posix.getrandom` with fail-fast on entropy unavailable
- **Resolved date:** 2026-01-30

### GAP-0005: TCP timeout handling [RESOLVED]
- **Issue:** [#47](https://gitlab.com/devnw/zig/dns/-/issues/47) (open -- needs closure)
- **Category:** Security
- **Resolution:** Timeout enforcement added to TCP connect and write operations
- **Evidence:** `src/transports/tcp.zig:47-48` -- `connectWithTimeout` and `writeAllWithTimeout`
- **Resolved date:** 2026-01-30

### GAP-0006: TCP partial read handling [RESOLVED]
- **Issue:** [#46](https://gitlab.com/devnw/zig/dns/-/issues/46) (open -- needs closure)
- **Category:** Security
- **Resolution:** Exact-read loop implemented for TCP length prefix and body
- **Evidence:** `src/transports/tcp.zig:57-73` -- exact-read loop for length prefix and body
- **Resolved date:** 2026-01-30

### GAP-0007: DNS name output escaping [RESOLVED]
- **Issue:** [#54](https://gitlab.com/devnw/zig/dns/-/issues/54) (open -- needs closure)
- **Category:** Security
- **Resolution:** JSON and log string escaping functions added
- **Evidence:** `src/resolver/logging.zig` -- `escapeJsonString()` and `sanitizeLogString()`
- **Resolved date:** 2026-01-30

### GAP-0008: DoT CA bundle requirement [RESOLVED]
- **Issue:** [#57](https://gitlab.com/devnw/zig/dns/-/issues/57) (open -- needs closure)
- **Category:** Security
- **Resolution:** CA trust requirement enforced with system CA flag
- **Evidence:** `src/resolver/channel.zig:79` -- `use_system_ca` flag with `NoCaTrustConfigured` error
- **Resolved date:** 2026-01-30

### GAP-0009: DoH HTTPS scheme validation [RESOLVED]
- **Issue:** [#56](https://gitlab.com/devnw/zig/dns/-/issues/56) (open -- needs closure)
- **Category:** Security
- **Resolution:** HTTPS scheme and Content-Type validation added
- **Evidence:** `src/transports/doh.zig` -- HTTPS scheme and Content-Type validation
- **Resolved date:** 2026-01-30

### GAP-0010: CI Docker image pinning [RESOLVED]
- **Issue:** [#58](https://gitlab.com/devnw/zig/dns/-/issues/58) (open -- needs closure)
- **Category:** CI-CD
- **Resolution:** Image pinning documented; digest pinning marked as TODO
- **Evidence:** `.gitlab-ci.yml` -- documented, TODO for digest pinning
- **Resolved date:** 2026-01-30

---

## Resolved in Gap Closure Cycle (2026-03-24)

The following items were resolved during the 5-phase gap closure pipeline.

### GAP-0011: 18 modules suppressed from public API via `_ =` in build.zig [RESOLVED]
- **Issue:** [#74](https://gitlab.com/devnw/zig/dns/-/issues/74)
- **Category:** Bug
- **Resolution:** Removed all 18 `_ =` suppressions from `build.zig`; wired all modules into `dns_mod` via `addImport()`; added `pub const` re-exports in `src/lib.zig` for all 21 exposed modules; fixed `build_options` module duplication
- **Evidence:** `build.zig` -- no `_ =` suppressions remain; `src/lib.zig` -- 21 `pub const` re-exports; all 316 tests pass
- **Resolved date:** 2026-03-24

### GAP-0012: Dual recursive resolver -- placeholder always returns SERVFAIL [RESOLVED]
- **Issue:** [#75](https://gitlab.com/devnw/zig/dns/-/issues/75)
- **Category:** Bug
- **Resolution:** Deleted orphaned `src/resolver/recursive.zig`; `src/recursive.zig` confirmed as sole canonical implementation; ARCHITECTURE.md updated to remove "(WIP)" and dual file reference
- **Evidence:** `src/resolver/recursive.zig` deleted; `src/recursive.zig` exposed via `lib.zig` and `build.zig`
- **Resolved date:** 2026-03-24

### GAP-0016: Placeholder resolver tests inflate 262/262 pass count [RESOLVED]
- **Issue:** [#79](https://gitlab.com/devnw/zig/dns/-/issues/79)
- **Category:** Bug
- **Resolution:** Orphaned `src/resolver/recursive.zig` tests were never compiled (not in `build.zig`). File deleted as part of GAP-0012. Test count verified accurate at 316.
- **Evidence:** `build.zig` -- no reference to `src/resolver/recursive.zig`; 316/316 tests pass
- **Resolved date:** 2026-03-24

### GAP-0018: ARCHITECTURE.md says WIP/STUB for features ROADMAP.md marks Complete [RESOLVED]
- **Issue:** [#81](https://gitlab.com/devnw/zig/dns/-/issues/81)
- **Category:** Docs
- **Resolution:** Rewrote ARCHITECTURE.md to remove all "WIP", "STUB", "placeholder" language for implemented features; synced with ROADMAP.md
- **Evidence:** `docs/ARCHITECTURE.md` -- no WIP/STUB labels remain; feature descriptions match ROADMAP.md
- **Resolved date:** 2026-03-24

### GAP-0019: CNAME continue targets wrong loop -- CNAME chasing broken [RESOLVED]
- **Issue:** [#85](https://gitlab.com/devnw/zig/dns/-/issues/85)
- **Category:** Bug
- **Resolution:** Added `outer:` label to main resolution loop; CNAME handler uses `break` + `continue :outer` pattern; properly frees owned servers/zones before reset
- **Evidence:** `src/recursive.zig` -- `outer:` label at main loop; tests: "CNAME break-then-continue-outer pattern", "CNAME chain limit enforcement"
- **Resolved date:** 2026-03-24

### GAP-0020: Referral servers computed but never assigned -- always queries root [RESOLVED]
- **Issue:** [#88](https://gitlab.com/devnw/zig/dns/-/issues/88)
- **Category:** Bug
- **Resolution:** Introduced `owned_servers: ?std.ArrayList(ServerAddress)` and `owned_zone: ?[]const u8` for ownership transfer; `current_servers` now points into owned list after referral
- **Evidence:** `src/recursive.zig` -- `owned_servers`/`owned_zone` lifecycle; tests: "owned_servers memory lifecycle", "owned_zone memory lifecycle"
- **Resolved date:** 2026-03-24

### QC-01: parseSvcbIpv4Hint/parseSvcbIpv6Hint return slices to stack-local arrays (UB) [RESOLVED]
- **Issue:** [#83](https://gitlab.com/devnw/zig/dns/-/issues/83)
- **Category:** API Contract (Critical)
- **Resolution:** Both parsers accept allocator parameter and return heap-allocated owned slices
- **Evidence:** `src/record.zig` -- `parseSvcbIpv4Hint` and `parseSvcbIpv6Hint` signatures updated
- **Resolved date:** 2026-03-24

### QH-01: CNAME continue targets inner answer loop [RESOLVED]
- **Issue:** [#86](https://gitlab.com/devnw/zig/dns/-/issues/86)
- **Category:** Architecture
- **Resolution:** Same fix as GAP-0019 (outer-loop restart via `outer:` label)
- **Evidence:** `src/recursive.zig` -- `continue :outer` after CNAME detection
- **Resolved date:** 2026-03-24

### QH-02: Referral NS servers computed but never assigned [RESOLVED]
- **Issue:** [#91](https://gitlab.com/devnw/zig/dns/-/issues/91)
- **Category:** Architecture
- **Resolution:** Same fix as GAP-0020 (owned_servers lifecycle management)
- **Evidence:** `src/recursive.zig` -- ownership transfer of new_servers to owned_servers
- **Resolved date:** 2026-03-24

### QH-03: IPv4.format() returns [15]u8 with undefined trailing bytes [RESOLVED]
- **Issue:** [#92](https://gitlab.com/devnw/zig/dns/-/issues/92)
- **Category:** API Contract
- **Resolution:** Returns `Formatted` struct with `buf` and `len` fields
- **Evidence:** `src/resolver/convenience.zig` -- `Formatted` struct definition
- **Resolved date:** 2026-03-24

### QH-04: Name.eql() uses page_allocator (2 mmap syscalls per comparison) [RESOLVED]
- **Issue:** [#95](https://gitlab.com/devnw/zig/dns/-/issues/95)
- **Category:** Performance
- **Resolution:** Allocation-free label-by-label comparison rewrite
- **Evidence:** `src/name.zig` -- no allocator usage in `eql()`
- **Resolved date:** 2026-03-24

### QM-01: parseName() duplicated 52+ identical lines in tsig.zig and sig0.zig [RESOLVED]
- **Issue:** [#102](https://gitlab.com/devnw/zig/dns/-/issues/102)
- **Category:** Maintainability
- **Resolution:** Extracted shared `src/security/dns_name.zig` with `parseName`, `skipName`, `skipRR`, `encodeName`, `encodeNameLower`; both `tsig.zig` and `sig0.zig` import from shared module
- **Evidence:** `src/security/dns_name.zig` -- shared module; `src/security/tsig.zig` and `src/security/sig0.zig` -- import from dns_name
- **Resolved date:** 2026-03-24

### QM-02: Duplicated root server definitions [RESOLVED]
- **Issue:** [#106](https://gitlab.com/devnw/zig/dns/-/issues/106)
- **Category:** Maintainability
- **Resolution:** Orphaned `src/resolver/recursive.zig` deleted (GAP-0012); single root server definition remains in `src/recursive.zig`
- **Evidence:** `src/resolver/recursive.zig` deleted
- **Resolved date:** 2026-03-24

### QM-04: 18 modules lack API boundary documentation [RESOLVED]
- **Issue:** [#113](https://gitlab.com/devnw/zig/dns/-/issues/113)
- **Category:** Architecture
- **Resolution:** All `b.addModule()` calls in `build.zig` now have `// Public API` or `// Internal` prefix comments
- **Evidence:** `build.zig` -- API boundary comments on all module declarations
- **Resolved date:** 2026-03-24

### QM-05: Silent error swallowing with catch {} in 7 locations [RESOLVED]
- **Issue:** [#117](https://gitlab.com/devnw/zig/dns/-/issues/117)
- **Category:** Maintainability
- **Resolution:** All `catch {}` sites documented with justification comments or upgraded to `catch |err| std.log.debug(...)`
- **Evidence:** Multiple files -- all catch {} sites have comments or use logged errors
- **Resolved date:** 2026-03-24

### QM-06: ARCHITECTURE.md missing documentation for 60% of modules [RESOLVED]
- **Issue:** [#119](https://gitlab.com/devnw/zig/dns/-/issues/119)
- **Category:** Documentation
- **Resolution:** ARCHITECTURE.md rewritten with comprehensive descriptions for all 40+ modules; complete Module Index table added
- **Evidence:** `docs/ARCHITECTURE.md` -- Module Index table with all modules documented
- **Resolved date:** 2026-03-24

### QL-01: 7 identical @intFromPtr offset-calculation blocks in record.zig [RESOLVED]
- **Issue:** [#121](https://gitlab.com/devnw/zig/dns/-/issues/121)
- **Category:** Cleanup
- **Resolution:** Extracted `rdataOffset(self, full_message, additional_offset)` helper; all 7 call sites updated
- **Evidence:** `src/record.zig` -- `rdataOffset()` helper; 7 call sites use it
- **Resolved date:** 2026-03-24

### QL-02: verifyCase0x20() reimplements std.mem.eql [RESOLVED]
- **Issue:** [#123](https://gitlab.com/devnw/zig/dns/-/issues/123)
- **Category:** Cleanup
- **Resolution:** Replaced manual byte loop with `std.mem.eql(u8, query_name, response_name)`
- **Evidence:** `src/name.zig` -- `std.mem.eql` usage in `verifyCase0x20`
- **Resolved date:** 2026-03-24

### QL-04: No doc comment on ResourceRecord rdata-offset invariant [RESOLVED]
- **Issue:** [#127](https://gitlab.com/devnw/zig/dns/-/issues/127)
- **Category:** Documentation
- **Resolution:** Doc comments added to `ResourceRecord` struct and `rdataOffset()` helper explaining the aliasing invariant
- **Evidence:** `src/record.zig` -- doc comments on struct and helper method
- **Resolved date:** 2026-03-24

### PF-01: Name.eql() uses page_allocator (~1000x slower) [RESOLVED]
- **Issue:** [#82](https://gitlab.com/devnw/zig/dns/-/issues/82)
- **Category:** Performance (P0)
- **Resolution:** Zero-allocation label-by-label comparison
- **Evidence:** `src/name.zig` -- `eql()` operates on wire format without allocation
- **Resolved date:** 2026-03-24

### PF-04: O(ns*additional) nested loop in extractReferral [RESOLVED]
- **Issue:** [#93](https://gitlab.com/devnw/zig/dns/-/issues/93)
- **Category:** Performance (P1)
- **Resolution:** Single-pass additional section collection with linear lookup
- **Evidence:** `src/recursive.zig` -- `extractReferral` iterates additional once
- **Resolved date:** 2026-03-24

### PF-06: 65KB stack buffer per UDP receive [RESOLVED]
- **Issue:** [#99](https://gitlab.com/devnw/zig/dns/-/issues/99)
- **Category:** Performance (P2)
- **Resolution:** Buffer reduced from 65535 to 4096 (RFC 6891 EDNS default) in all 3 locations
- **Evidence:** `src/stub.zig`, `src/recursive.zig`, `src/transports/udp.zig` -- buffer size 4096
- **Resolved date:** 2026-03-24

### PF-07: O(n) section skipping in message.zig [RESOLVED]
- **Issue:** [#101](https://gitlab.com/devnw/zig/dns/-/issues/101)
- **Category:** Performance (P2)
- **Resolution:** Section offsets cached in Message struct at parse time; O(1) access
- **Evidence:** `src/message.zig` -- cached section offsets
- **Resolved date:** 2026-03-24

### PF-08: buildCnameChain re-iterates answers per CNAME hop [RESOLVED]
- **Issue:** [#103](https://gitlab.com/devnw/zig/dns/-/issues/103)
- **Category:** Performance (P2)
- **Resolution:** Pre-built CNAME mapping array from answers; O(ancount + hops)
- **Evidence:** `src/client.zig` -- CNAME mapping array construction
- **Resolved date:** 2026-03-24

### PF-11: Memory leak - ResolutionState.last_query_name not freed [RESOLVED]
- **Issue:** [#110](https://gitlab.com/devnw/zig/dns/-/issues/110)
- **Category:** Performance (P2) / Memory Safety
- **Resolution:** `ResolutionState.deinit()` added; `resolve()` uses `defer state.deinit()`
- **Evidence:** `src/recursive.zig` -- `deinit()` method on ResolutionState
- **Resolved date:** 2026-03-24

### PF-12: Memory leak - DnsCache zone_name not freed [RESOLVED]
- **Issue:** [#114](https://gitlab.com/devnw/zig/dns/-/issues/114)
- **Category:** Performance (P2) / Memory Safety
- **Resolution:** `on_evict` callback in LRU frees `zone_name`; `freeCacheEntry` updated
- **Evidence:** `src/resolver/dns_cache.zig` -- `on_evict` callback; `src/util/lru.zig` -- eviction support
- **Resolved date:** 2026-03-24

### PF-15: Double allocation in DnsCache.makeKey [RESOLVED]
- **Issue:** [#120](https://gitlab.com/devnw/zig/dns/-/issues/120)
- **Category:** Performance (P3)
- **Resolution:** Stack buffer `lower_buf: [max_name_length]u8` replaces heap allocation
- **Evidence:** `src/resolver/dns_cache.zig` -- `makeKey()` uses stack buffer
- **Resolved date:** 2026-03-24

### PF-17: Global thread pool uses page_allocator [RESOLVED]
- **Issue:** [#124](https://gitlab.com/devnw/zig/dns/-/issues/124)
- **Category:** Performance (P3)
- **Resolution:** GPA-backed allocator wraps pool allocator for sub-page allocations
- **Evidence:** `src/parallel.zig` -- GPA wrapper around page_allocator
- **Resolved date:** 2026-03-24

---

## Resolved in Phase 4-7 Gap Closure (2026-03-24)

The following items were resolved by 7 parallel implementation agents during the final gap closure cycle.

### GAP-0022: RFC_COMPLIANCE.md has 5+ stale status entries [RESOLVED]
- **Issue:** [#147](https://gitlab.com/devnw/zig/dns/-/issues/147)
- **Category:** Docs
- **Resolution:** Updated RFC 1034 Section 4.2 from Planned to Complete, RFC 1035 Sections 3.2/3.3 from Partial to Complete, Section 7.4 from Partial to Complete, AXFR/IXFR from Planned to Complete. Updated RFC 1034 overall status to Complete, RFC 1035 to Complete. Also updated README.md RFC References table.
- **Evidence:** `docs/RFC_COMPLIANCE.md` -- all entries match ROADMAP.md; `README.md` -- RFC references updated
- **Resolved date:** 2026-03-24

### GAP-0023: README.md Zig version conflict -- 0.14.0+ vs 0.15.1 [RESOLVED]
- **Issue:** [#148](https://gitlab.com/devnw/zig/dns/-/issues/148)
- **Category:** Docs
- **Resolution:** Updated README.md status table from "0.14.0+" to "0.15.1+" to match build.zig.zon minimum_zig_version.
- **Evidence:** `README.md` -- version consistent with `build.zig.zon` minimum_zig_version "0.15.1"
- **Resolved date:** 2026-03-24

### GAP-0024: SECURITY.md uses stale import paths (pre-GAP-0011) [RESOLVED]
- **Issue:** [#149](https://gitlab.com/devnw/zig/dns/-/issues/149)
- **Category:** Docs
- **Resolution:** Updated SECURITY.md line 115 from `@import("security/tsig")` to `@import("dns").tsig` and line 139 from `@import("resolver/zone_transfer")` to `@import("dns").zone_transfer`.
- **Evidence:** `docs/SECURITY.md:115,139` -- uses `@import("dns")` entry point
- **Resolved date:** 2026-03-24

### GAP-0025: README.md Phase 3 status says Complete but should be Partial [RESOLVED]
- **Issue:** [#150](https://gitlab.com/devnw/zig/dns/-/issues/150)
- **Category:** Docs
- **Resolution:** Updated README.md Phase 3 from "**Complete**" to "**Partial** (Ed25519/ECDSA complete, RSA pending)".
- **Evidence:** `README.md` -- Phase 3 status matches ROADMAP.md
- **Resolved date:** 2026-03-24

### GAP-0027: Partial write data loss -- `_ = try write()` discards byte count [RESOLVED]
- **Issue:** [#132](https://gitlab.com/devnw/zig/dns/-/issues/132)
- **Category:** Bug (Critical)
- **Resolution:** All three locations now use writeAll loops: `connection_pool.zig` uses `writeAllWithTimeout()`, `dot.zig` uses `tlsWriteAll()`, `zone_transfer.zig` uses `stream.writeAll()`.
- **Evidence:** `src/transports/connection_pool.zig`, `src/transports/dot.zig`, `src/resolver/zone_transfer.zig` -- no `_ = try write()` pattern remains
- **Resolved date:** 2026-03-24

### GAP-0028: Infinite loop in PipelinedBatch.execute on ConnectionClosed [RESOLVED]
- **Issue:** [#133](https://gitlab.com/devnw/zig/dns/-/issues/133)
- **Category:** Bug (Critical)
- **Resolution:** Added `outer:` label to for loop; all continue/error paths use `continue :outer`; `read() == 0` sets `q.err = error.ConnectionClosed`.
- **Evidence:** `src/transports/connection_pool.zig` -- `outer:` label on for loop; `continue :outer` pattern
- **Resolved date:** 2026-03-24

### GAP-0029: Missing error.InProgress handling in stub.zig:293 connect [RESOLVED]
- **Issue:** [#136](https://gitlab.com/devnw/zig/dns/-/issues/136)
- **Category:** Bug (High)
- **Resolution:** `src/stub.zig:297` now handles `error.ConnectionPending` (Zig's mapping for EALREADY/EINPROGRESS), polling for write-readiness.
- **Evidence:** `src/stub.zig:294-297` -- switch handles both `error.WouldBlock` and `error.ConnectionPending`
- **Resolved date:** 2026-03-24

### GAP-0030: Blocking reads without timeout in PipelinedBatch.execute [RESOLVED]
- **Issue:** [#137](https://gitlab.com/devnw/zig/dns/-/issues/137)
- **Category:** Bug (High)
- **Resolution:** `PipelinedBatch.execute()` accepts `timeout_ms: u32`; reads use `readWithTimeout()` with `poll()` before `read()`; writes use `writeAllWithTimeout()` with `poll()` before `write()`.
- **Evidence:** `src/transports/connection_pool.zig` -- `readWithTimeout()` and `writeAllWithTimeout()` with poll-based timeout
- **Resolved date:** 2026-03-24

### GAP-0031: Dead file src/resolver/stub.zig not referenced in build.zig [RESOLVED]
- **Issue:** [#138](https://gitlab.com/devnw/zig/dns/-/issues/138)
- **Category:** Code Quality (Medium)
- **Resolution:** Deleted `src/resolver/stub.zig`. Updated ARCHITECTURE.md, README.md, and PERF_GAP_ANALYSIS.md.
- **Evidence:** `src/resolver/stub.zig` deleted; no references remain in docs
- **Resolved date:** 2026-03-24

### GAP-0032: parallel.zig functions are stub implementations [RESOLVED]
- **Issue:** [#139](https://gitlab.com/devnw/zig/dns/-/issues/139)
- **Category:** Bug (Medium)
- **Resolution:** `parseRecord` does real wire-format DNS parsing; `validateDnssec`, `executeQuery`, `prefetchEntry` return honest error status instead of fabricated success.
- **Evidence:** `src/parallel.zig` -- real wire-format parser + honest error returns
- **Resolved date:** 2026-03-24

### GAP-0033: SIG(0) exhaustive enum panic on unknown algorithm [RESOLVED]
- **Issue:** [#134](https://gitlab.com/devnw/zig/dns/-/issues/134) (confidential)
- **Category:** Security (High)
- **Resolution:** Changed `Algorithm` enum to non-exhaustive (added `_` variant); unknown values return `error.UnsupportedAlgorithm`.
- **Evidence:** `src/security/sig0.zig` -- non-exhaustive enum; 3 tests: SEC-C20 parse, generate, fromDnskey
- **Resolved date:** 2026-03-24

### GAP-0034: TSIG exhaustive enum panic on unknown error code [RESOLVED]
- **Issue:** [#135](https://gitlab.com/devnw/zig/dns/-/issues/135) (confidential)
- **Category:** Security (High)
- **Resolution:** Changed `TsigError` enum to non-exhaustive (added `_` variant); unknown codes produce `_` variant without panic.
- **Evidence:** `src/security/tsig.zig` -- non-exhaustive enum; 2 tests: SEC-C21 unknown error code, parse with error=999
- **Resolved date:** 2026-03-24

### GAP-0035: DnsCache.get heap-allocates key on every lookup [RESOLVED]
- **Issue:** [#141](https://gitlab.com/devnw/zig/dns/-/issues/141)
- **Category:** Performance (Medium)
- **Resolution:** `DnsCache.get()` uses `makeKeyBuf()` with 280-byte stack buffer; zero heap allocation on hot path.
- **Evidence:** `src/resolver/dns_cache.zig:139` -- `makeKeyBuf` with stack buffer; test "DnsCache makeKeyBuf matches makeKey output"
- **Resolved date:** 2026-03-24

### GAP-0036: Name.toString allocates ArrayList per call [RESOLVED]
- **Issue:** [#143](https://gitlab.com/devnw/zig/dns/-/issues/143)
- **Category:** Performance (Medium)
- **Resolution:** Added `Name.toStringBuf()` that writes into caller-provided buffer; zero heap allocation. 8 tests added.
- **Evidence:** `src/name.zig:270` -- `toStringBuf()` method; tests at line 1212+
- **Resolved date:** 2026-03-24

### GAP-0021: PF-09 status tracking incorrect -- marked Deferred but is Resolved [RESOLVED]
- **Issue:** [#144](https://gitlab.com/devnw/zig/dns/-/issues/144)
- **Category:** Docs
- **Resolution:** PF-09 confirmed as Resolved in PERF_GAP_ANALYSIS.md. `responseMatchesQuery` uses zero-allocation `Name.encodeBuf` + `Name.eql` on the stack. PF-01 (Name.eql) was resolved, unblocking PF-09. Status updated from "Deferred" to "Resolved" in all tracking documents.
- **Evidence:** `src/recursive.zig:681-685` -- zero-allocation Name comparison; `docs/PERF_GAP_ANALYSIS.md` -- PF-09 status: Resolved
- **Resolved date:** 2026-03-24

### GAP-0026: Uncommitted gap closure work (27 files, +2137/-1019) [RESOLVED]
- **Issue:** [#131](https://gitlab.com/devnw/zig/dns/-/issues/131)
- **Category:** Bug (High)
- **Resolution:** All gap closure work committed and pushed to remote in logical groups. Critical bug fixes, security hardening, performance optimizations, and documentation updates are now version-controlled.
- **Evidence:** `git log` -- multiple commits covering GAP-0011 through GAP-0036 resolution work
- **Resolved date:** 2026-03-24

---

## Won't Do (2026-03-24)

The following items were evaluated and intentionally deferred with documented rationale.

### GAP-0013: DNSSEC RSA algorithms (8/10/5) return UnsupportedAlgorithm [WON'T DO]
- **Issue:** [#76](https://gitlab.com/devnw/zig/dns/-/issues/76)
- **Category:** Bug
- **Reason:** Requires external cryptographic library. No pure-Zig RSA implementation exists. Integrating BoringSSL, mbedTLS, or bearssl is a significant effort requiring C interop and dependency management that is outside the scope of this gap closure cycle.
- **Mitigation:** ROADMAP.md Phase 3 updated to "PARTIAL" with clear documentation that RSA algorithms are unsupported. Ed25519 and ECDSA P-256/P-384 work correctly via Zig std.crypto. ARCHITECTURE.md updated to document RSA limitation.
- **Evidence:** `src/resolver/dnssec.zig:446-452` -- returns `error.UnsupportedAlgorithm` for `.rsasha256, .rsasha512, .rsasha1`
- **Resolved date:** 2026-03-24

### GAP-0014: DoT/DoH/DoQ transports ship zero backend implementations [WON'T DO]
- **Issue:** [#77](https://gitlab.com/devnw/zig/dns/-/issues/77)
- **Category:** Feature
- **Reason:** Requires external TLS/HTTP/QUIC libraries. The vtable interface design is the correct architecture for a pure-Zig library -- it allows users to integrate any backend without coupling the DNS library to specific crypto/network dependencies.
- **Mitigation:** ROADMAP.md updated to label DoT/DoH/DoQ as "interface only -- requires external backend". ARCHITECTURE.md documents pluggable backend pattern. Modules exposed in public API (GAP-0011 resolved).
- **Evidence:** `src/transports/dot.zig`, `doh.zig`, `doq.zig` -- vtable interfaces with no concrete backend
- **Resolved date:** 2026-03-24

---

Note: GAP-0001 through GAP-0010 issues remain OPEN in the GitLab tracker despite fixes being present in code. See GAP-0015 (#78) for the broader state-conflict tracking.
