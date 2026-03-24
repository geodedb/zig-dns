# Quality Gap Analysis

Last updated: 2026-03-24

## Summary

| Severity | Open | Resolved/Closed | Total |
|----------|------|-----------------|-------|
| Critical | 0 | 4 | 4 |
| High | 4 | 9 | 13 |
| Medium | 5 | 10 | 15 |
| Low | 3 | 8 | 11 |
| **Total** | **12** | **31** | **43** |

### Top 10 Active Risks

1. **QC-NEW-03** (PriorityScore 64) -- sendQuery() triple duplication across stub.zig, recursive.zig, udp.zig (~150 lines copied verbatim).
2. **QH-05** (PriorityScore 64) -- Zero fuzz testing for security-critical DNS wire parsers. Deferred from Phase 2.
3. **QH-NEW-01** (PriorityScore 48) -- convenience.zig lookup functions (lookupA, lookupAAAA, lookup) are empty stubs returning empty results.
4. **QH-NEW-02** (PriorityScore 48) -- resolveIterative has zero direct test coverage (219 lines, most complex function in the resolver).
5. **QM-NEW-02** (PriorityScore 36) -- ResolveResult defined twice with incompatible shapes (client.zig vs recursive.zig).
6. **QM-NEW-03** (PriorityScore 36) -- Cache only formats A/AAAA on cache hit; silently returns empty for MX, SRV, TXT, etc.
7. **QM-03** (PriorityScore 36) -- resolveIterative is 219 lines with 9 levels of nesting (grew from 208 lines).
8. **QM-NEW-05** (PriorityScore 24) -- resolveNsAddress swallows all errors as null (OOM becomes silent skip).
9. **QM-NEW-01** (PriorityScore 24) -- Duplicate QueryType enum in convenience.zig mirrors types.Type.
10. **QL-03** (PriorityScore 16) -- 12 source files exceed 800-line threshold (was 9; added connection_pool.zig, parallel.zig, enhanced_metrics.zig).

## Stack-Ranked Findings

| Rank | ID | Severity | PriorityScore | Category | Finding | Component | Evidence | Issue | Fix Summary | Owner | Effort | Status |
|------|----|----------|---------------|----------|---------|-----------|----------|-------|-------------|-------|--------|--------|
| 1 | QC-03 | Critical | 80 | architecture | `_ = try write()` discards return value in 3 files, 6 sites -- partial write data loss | connection_pool, dot, zone_transfer | `connection_pool.zig:454-455`, `dot.zig:305-306`, `zone_transfer.zig:523-524` | [#152](https://gitlab.com/devnw/zig/dns/-/issues/152) | Use writeAll loop or existing writeAllWithTimeout helper | Transport maintainer | S | **Resolved** |
| 2 | QH-02 | High | 80 | architecture | Referral NS servers computed but never assigned to `current_servers` | recursive.zig | `src/recursive.zig:296-316` | [#91](https://gitlab.com/devnw/zig/dns/-/issues/91) | Assign `new_servers` items to `current_servers` with proper lifetime management | Resolver maintainer | M | Resolved |
| 3 | QH-07 | High | 64 | architecture | Blocking reads without timeout in PipelinedBatch.execute | connection_pool.zig | `connection_pool.zig:448-498` -- raw `std.posix.read/write` without poll/timeout | [#163](https://gitlab.com/devnw/zig/dns/-/issues/163) | Add timeout_ms parameter, use readWithTimeout/writeAllWithTimeout | Transport maintainer | S | **Resolved** |
| 4 | QH-08 | High | 64 | architecture | Zone transfer receiveTcpMessage single read for 2-byte length prefix | zone_transfer.zig | `zone_transfer.zig:530-540` -- read loop with `while (len_read < 2)` | [#166](https://gitlab.com/devnw/zig/dns/-/issues/166) | Read loop for 2-byte prefix; only n==0 means closed (SEC-C33/QH-08) | Resolver maintainer | S | **Resolved** |
| 5 | QH-01 | High | 64 | architecture | CNAME `continue` targets inner `ans_iter` loop, not outer resolution loop | recursive.zig | `src/recursive.zig:253-271` | [#86](https://gitlab.com/devnw/zig/dns/-/issues/86) | Replace `continue` with `break` + flag pattern to target outer loop | Resolver maintainer | S | Resolved |
| 6 | QH-04 | High | 64 | perf | `Name.eql()` uses `page_allocator` -- 2 mmap+munmap syscalls per comparison | name.zig | `src/name.zig:254-264` | [#95](https://gitlab.com/devnw/zig/dns/-/issues/95) | Compare labels directly without allocation | name.zig maintainer | M | Resolved |
| 7 | QH-05 | High | 64 | tests | Zero fuzz testing for security-critical DNS wire parsers | All parsers | No fuzz targets in build.zig | [#98](https://gitlab.com/devnw/zig/dns/-/issues/98) | Add `std.testing.fuzz` targets | Security/testing lead | M | Deferred |
| 8 | QC-NEW-03 | High | 64 | maintainability | sendQuery() triple duplication: ~50 lines of identical UDP socket+timeout+sendto+recvfrom logic copied verbatim in 3 files | stub.zig, recursive.zig, udp.zig | `stub.zig:198-246`, `recursive.zig:514-559`, `udp.zig:36-84` -- all create DGRAM socket, set RCVTIMEO, sendto, recvfrom loop with source validation | -- | Extract shared `sendUdpQuery()` into `transports/io.zig` (same pattern as TCP I/O dedup in QM-07) | Transport maintainer | M | Open |
| 9 | QC-02 | Critical | 60 | architecture | ConnectionPool.acquire mutex race: defer lock/unlock dance leaves lines 278-286 unprotected | connection_pool.zig | `connection_pool.zig:247-287` -- `defer self.mutex.lock()` at line 273 fires at scope exit, not line 277 | [#151](https://gitlab.com/devnw/zig/dns/-/issues/151) | Replace `defer self.mutex.lock()` with explicit `self.mutex.lock()` before mutations | Transport maintainer | S | **Resolved** |
| 10 | QC-04 | Critical | 60 | architecture | Infinite loop in PipelinedBatch.execute: `continue` targets inner while, not outer for | connection_pool.zig | `connection_pool.zig:468,490` -- `continue` after ConnectionClosed re-reads from closed fd forever | [#156](https://gitlab.com/devnw/zig/dns/-/issues/156) | Add `outer:` label to for loop, use `continue :outer` | Transport maintainer | S | **Resolved** |
| 11 | QC-01 | Critical | 60 | api-contract | `parseSvcbIpv4Hint`/`parseSvcbIpv6Hint` return slices to stack-local arrays (UB) | record.zig | `src/record.zig:601-630` | [#83](https://gitlab.com/devnw/zig/dns/-/issues/83) | Accept allocator parameter, return owned slice | record.zig maintainer | S | Closed |
| 12 | QH-06 | High | 48 | maintainability | Missing `error.InProgress` in stub.zig connectWithTimeout | stub.zig | `stub.zig:294-297` -- handles `error.WouldBlock` and `error.ConnectionPending` | [#160](https://gitlab.com/devnw/zig/dns/-/issues/160) | Added `error.ConnectionPending` to switch (Zig maps EALREADY to ConnectionPending) | Resolver maintainer | S | **Resolved** |
| 13 | QM-07 | **Resolved** | 48 | maintainability | ~~3x duplicate I/O helpers: connectWithTimeout, writeAllWithTimeout, readWithTimeout, readExactWithTimeout~~ | stub.zig, tcp.zig, connection_pool.zig | Extracted shared `src/transports/io.zig`; all 3 files now import and use canonical implementations; also fixed incorrect `error.InProgress`/`error.IsConnected` catch arms (not valid in Zig 0.15.2 ConnectError) | [#170](https://gitlab.com/devnw/zig/dns/-/issues/170) | Resolved: shared io.zig module with 4 tests | Transport maintainer | M | **Resolved** |
| 14 | QM-11 | Medium | 48 | perf | PooledTcpTransport.query calls connect on every query despite connection pooling | connection_pool.zig | `connection_pool.zig:537` -- `connectWithTimeout()` called unconditionally; `IsConnected` handled but wastes syscall | [#180](https://gitlab.com/devnw/zig/dns/-/issues/180) | Track connected state in PooledConnection or connect in acquire() | Transport maintainer | S | **Resolved** |
| 15 | QH-NEW-01 | High | 48 | api-contract | convenience.zig lookup functions (lookupA, lookupAAAA, lookup) are empty stubs returning empty results; `_ = hostname` discards input | convenience.zig | `src/resolver/convenience.zig:194-254` -- lookupA/lookupAAAA increment stats then return empty LookupResult with `_ = hostname`; lookup delegates to empty stubs | -- | Wire lookupA/lookupAAAA to StubResolver or RecursiveResolver; parse A/AAAA records from response into LookupResult.addresses | Convenience module maintainer | M | Open |
| 16 | QH-NEW-02 | High | 48 | tests | resolveIterative has zero direct test coverage; 219 lines, deepest nesting, most complex control flow in recursive resolver | recursive.zig | `src/recursive.zig:188-406` (219 lines) -- no test matches pattern `test.*resolveIterative` | -- | Add integration tests: CNAME following, referral handling, QNAME minimization, max-depth, NXDOMAIN | Resolver maintainer | L | Open |
| 17 | QH-03 | High | 48 | api-contract | `IPv4.format()` returns `[15]u8` with undefined trailing bytes | convenience.zig | `src/resolver/convenience.zig:34-43` | [#92](https://gitlab.com/devnw/zig/dns/-/issues/92) | Return struct with buf+len, or zero-fill buffer | Convenience module maintainer | S | Closed |
| 18 | QM-01 | **Resolved** | 36 | maintainability | ~~`parseName()` copy-pasted ~52 identical lines in tsig.zig and sig0.zig~~ | tsig.zig, sig0.zig | Extracted shared `src/security/dns_name.zig` | [#102](https://gitlab.com/devnw/zig/dns/-/issues/102) | Resolved by extracting shared dns_name module | Security module maintainer | S | Resolved |
| 19 | QM-09 | **Resolved** | 36 | architecture | ~~parallel.zig: 4 placeholder implementations return fabricated results~~ | parallel.zig | parseRecord now does real wire-format parsing; validateDnssec/executeQuery/prefetchEntry return honest error status instead of fabricated success | [#177](https://gitlab.com/devnw/zig/dns/-/issues/177) | parseRecord: real wire-format parser; others: honest not-implemented status | Parallel module maintainer | M | Resolved |
| 20 | QM-03 | Medium | 36 | readability | `resolveIterative` is 219 lines with 9 levels of nesting (was 171 at QM-03 filing, 208 at Phase 2, now 219) | recursive.zig | `src/recursive.zig:188-406` | [#109](https://gitlab.com/devnw/zig/dns/-/issues/109) | Extract `handleCnameChain()`, `handleReferral()`, `handleNodataResponse()` | Resolver maintainer | M | Deferred |
| 21 | QM-NEW-02 | Medium | 36 | architecture | ResolveResult defined twice with incompatible shapes: client.zig has `addresses: []const []const u8` + `from_cache: bool`; recursive.zig has `status: ResolveStatus` + `answer: ?[]u8` + `from_cache: bool` | client.zig, recursive.zig | `src/client.zig:318-332`, `src/recursive.zig:835-844` | -- | Unify into single type or rename to avoid confusion; client could wrap recursive result | Resolver maintainer | S | Open |
| 22 | QM-NEW-03 | Medium | 36 | api-contract | Cache hit path in Client.resolve only formats A and AAAA records; MX, SRV, TXT, NS, PTR cache hits silently return empty results | client.zig | `src/client.zig:150-165` -- `if (qtype == .a ... ) else if (qtype == .aaaa ...)` with no else branch; other record types skip formatting | -- | Add formatting branches for MX, SRV, TXT, NS, PTR or return raw rdata with type tag | Client maintainer | M | Open |
| 23 | QM-05 | **Resolved** | 36 | maintainability | ~~Silent error swallowing with `catch {}` in 5+ locations~~ | Multiple files | All catch {} sites documented or upgraded | [#117](https://gitlab.com/devnw/zig/dns/-/issues/117) | Resolved | Any contributor | S | Resolved |
| 24 | QL-07 | **Resolved** | 32 | ci-cd | ~~No `zig fmt --check` in CI pipeline~~ | .gitlab-ci.yml | zig-format job override now includes explicit `zig fmt --check src/ cmd/ build.zig` script | [#183](https://gitlab.com/devnw/zig/dns/-/issues/183) | Added explicit script to zig-format job override; added fmt-check Makefile target | CI/CD maintainer | S | **Resolved** |
| 25 | QM-NEW-01 | Medium | 24 | maintainability | Duplicate QueryType enum in convenience.zig (A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT, ANY) mirrors types.Type; will diverge as types.Type is extended | convenience.zig, types.zig | `src/resolver/convenience.zig:17-28` vs `src/types.zig:14+` (types.Type has 80+ variants) | -- | Remove QueryType; import and use types.Type directly | Convenience module maintainer | S | Open |
| 26 | QM-NEW-05 | Medium | 24 | architecture | resolveNsAddress catches all errors (including OOM) as null via `catch return null`; OOM during child resolveIterative silently skips NS instead of propagating | recursive.zig | `src/recursive.zig:688` -- `self.resolveIterative(&child_state) catch return null` | -- | Catch and propagate `error.OutOfMemory`; return null only for resolution failures | Resolver maintainer | S | Open |
| 27 | QM-08 | **Resolved** | 24 | cleanup | ~~Dead file `src/resolver/stub.zig` -- 353 lines not in build.zig, never imported~~ | resolver/stub.zig (deleted) | File deleted; ARCHITECTURE.md stale references removed; PERF_GAP_ANALYSIS.md PF-16 annotated | [#173](https://gitlab.com/devnw/zig/dns/-/issues/173) | Deleted file, updated ARCHITECTURE.md and PERF_GAP_ANALYSIS.md | Any contributor | S | **Resolved** |
| 28 | QM-10 | **Resolved** | 24 | cleanup | ~~Duplicate SOA parsing: extractSerial duplicates parseSoaRdata name-skipping logic~~ | zone_transfer.zig | `extractSerial` now delegates to `parseSoaRdata`; 24 duplicated lines removed | [#179](https://gitlab.com/devnw/zig/dns/-/issues/179) | extractSerial calls parseSoaRdata and returns .serial | Resolver maintainer | S | **Resolved** |
| 29 | QM-02 | **Resolved** | 24 | maintainability | ~~Duplicated root server definitions~~ | recursive.zig | Deleted `src/resolver/recursive.zig` (GAP-0012) | [#106](https://gitlab.com/devnw/zig/dns/-/issues/106) | Resolved | Resolver maintainer | S | Resolved |
| 30 | QM-04 | **Resolved** | 24 | architecture | ~~18 modules lack API boundary docs~~ | build.zig | Added API boundary comments | [#113](https://gitlab.com/devnw/zig/dns/-/issues/113) | Resolved | Project maintainer | S | Resolved |
| 31 | QM-06 | **Resolved** | 24 | docs | ~~ARCHITECTURE.md missing 60% of modules~~ | docs/ARCHITECTURE.md | Rewritten with all modules documented | [#119](https://gitlab.com/devnw/zig/dns/-/issues/119) | Resolved | Documentation lead | M | Resolved |
| 32 | QC-NEW-01 | **Resolved** | 64 | architecture | `acquire()` returns pointer into ArrayList backing array; dangling after realloc/swapRemove | connection_pool.zig | `connection_pool.zig:251,291` -- `&self.connections.items[len-1]` pointer invalidated by concurrent append/cleanup | -- | Return ConnectionHandle (value type with generation-based lookup) instead of pointer | Transport maintainer | M | **Resolved** |
| 33 | QC-NEW-02 | **Resolved** | 48 | architecture | TOCTOU in connection limit: countServerConnections check races with createConnection | connection_pool.zig | `connection_pool.zig:268-296` -- lock released for blocking connect, re-acquired without re-checking limit | -- | Re-check countServerConnections after re-acquiring mutex; close excess fd and try reuse | Transport maintainer | S | **Resolved** |
| 34 | QL-03 | Low | 16 | readability | 12 source files exceed 800-line threshold (was 9). New: `connection_pool.zig` (1070), `parallel.zig` (881), `enhanced_metrics.zig` (879). Largest: `record.zig` (1927) | Multiple files | `record.zig:1927`, `recursive.zig:1426`, `name.zig:1345`, `connection_pool.zig:1070`, `edns.zig:973`, `tsig.zig:916`, `zone_transfer.zig:894`, `dnssec.zig:889`, `parallel.zig:881`, `enhanced_metrics.zig:879`, `zone_file.zig:863`, `sig0.zig:814` | [#126](https://gitlab.com/devnw/zig/dns/-/issues/126) | Split large files by responsibility domain | Project maintainer | L | Deferred |
| 35 | QL-09 | Low | 16 | readability | 41 functions exceed 50-line threshold (was 30); resolveIterative at 219 lines | Multiple files | `recursive.zig:188+` (219 lines), record.zig, edns.zig, zone_transfer.zig parsers | [#185](https://gitlab.com/devnw/zig/dns/-/issues/185) | Decompose long functions; add lint gate | Project maintainer | L | Open |
| 36 | QL-NEW-01 | **Resolved** | 8 | cleanup | Duplicated testSocketPair helper identical to io.zig:118-126 | connection_pool.zig | `connection_pool.zig:665-673` -- copy-paste of `io.zig:118-126` | -- | Make io.zig testSocketPair public; replace duplicate with const alias | Any contributor | S | **Resolved** |
| 37 | QM-NEW-04 | Low | 16 | docs | lib.zig and CHANGELOG.md claim "Zero external dependencies" but build.zig.zon declares `spice` dependency (parallelism library) | lib.zig, CHANGELOG.md | `src/lib.zig:16` -- `//! - Zero external dependencies`; `build.zig.zon:28-30` -- `.spice = .{ .url = "https://gitlab.com/devnw/zig/spice/..." }` | -- | Update doc comment to "Minimal dependencies (spice for parallelism)" or similar | Documentation maintainer | S | Open |
| 38 | QL-04 | **Resolved** | 16 | docs | ~~No doc comment on rdata-offset invariant~~ | record.zig | Doc comments added | [#127](https://gitlab.com/devnw/zig/dns/-/issues/127) | Resolved | Any contributor | S | Resolved |
| 39 | QL-05 | **Resolved** | 16 | tests | ~~Mutable statics in MockTlsBackend~~ | dot.zig | `write_buffer` and `write_len` moved from struct-level statics to per-instance fields | [#181](https://gitlab.com/devnw/zig/dns/-/issues/181) | Moved to per-instance state | Any contributor | S | Resolved |
| 40 | QL-06 | **Resolved** | 12 | readability | ~~Magic number 6 for SOA record type in zone_transfer.zig~~ | zone_transfer.zig | All 5 instances of `rtype == 6` replaced with `soa_rtype` named constant | [#182](https://gitlab.com/devnw/zig/dns/-/issues/182) | Added `const soa_rtype: u16 = 6` and replaced all magic number usages | Any contributor | S | **Resolved** |
| 41 | QL-08 | **Resolved** | 12 | docs | ~~ARCHITECTURE.md references deleted/dead files (resolver/recursive.zig, resolver/stub.zig)~~ | docs/ARCHITECTURE.md | Stale references to `src/resolver/stub.zig` and `src/resolver/recursive.zig` removed | [#184](https://gitlab.com/devnw/zig/dns/-/issues/184) | Removed all stale references to deleted files | Documentation maintainer | S | **Resolved** |
| 42 | QL-01 | **Resolved** | 12 | cleanup | ~~7 identical @intFromPtr blocks~~ | record.zig | Extracted rdataOffset() helper | [#121](https://gitlab.com/devnw/zig/dns/-/issues/121) | Resolved | Any contributor | S | Resolved |
| 43 | QL-02 | Low | 8 | cleanup | `verifyCase0x20()` reimplements `std.mem.eql` | name.zig | `src/name.zig:451-462` | [#123](https://gitlab.com/devnw/zig/dns/-/issues/123) | Replace with std.mem.eql | Any contributor | S | Resolved |

## Findings by Category

### Architecture (9 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QC-03 | Critical | 80 | Partial write data loss (3 files, 6 sites) | [#152](https://gitlab.com/devnw/zig/dns/-/issues/152) | **Resolved** |
| QH-02 | High | 80 | Referral NS servers never assigned | [#91](https://gitlab.com/devnw/zig/dns/-/issues/91) | **Resolved** |
| QH-07 | High | 64 | Blocking reads without timeout in PipelinedBatch | [#163](https://gitlab.com/devnw/zig/dns/-/issues/163) | **Resolved** |
| QH-08 | High | 64 | Zone transfer short read on length prefix | [#166](https://gitlab.com/devnw/zig/dns/-/issues/166) | **Resolved** |
| QH-01 | High | 64 | CNAME continue targets wrong loop | [#86](https://gitlab.com/devnw/zig/dns/-/issues/86) | **Resolved** |
| QC-02 | Critical | 60 | ConnectionPool.acquire mutex race | [#151](https://gitlab.com/devnw/zig/dns/-/issues/151) | **Resolved** |
| QC-04 | Critical | 60 | Infinite loop in PipelinedBatch.execute | [#156](https://gitlab.com/devnw/zig/dns/-/issues/156) | **Resolved** |
| QM-09 | **Resolved** | 36 | parallel.zig placeholder implementations | [#177](https://gitlab.com/devnw/zig/dns/-/issues/177) | **Resolved** |
| QM-04 | Medium | 24 | 18 modules lack API boundary docs | [#113](https://gitlab.com/devnw/zig/dns/-/issues/113) | **Resolved** |
| QC-NEW-01 | **Resolved** | 64 | acquire() returns dangling pointer into ArrayList | -- | **Resolved** |
| QC-NEW-02 | **Resolved** | 48 | TOCTOU in connection limit check | -- | **Resolved** |
| QM-NEW-02 | Medium | 36 | ResolveResult defined twice with incompatible shapes (client.zig vs recursive.zig) | -- | Open |
| QM-NEW-05 | Medium | 24 | resolveNsAddress swallows all errors (including OOM) as null | -- | Open |

### API Contract (4 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QC-01 | Critical | 60 | SVCB hint parsers return dangling pointers | [#83](https://gitlab.com/devnw/zig/dns/-/issues/83) | **Closed** |
| QH-NEW-01 | High | 48 | convenience.zig lookupA/lookupAAAA/lookup are empty stubs returning empty results | -- | Open |
| QH-03 | High | 48 | IPv4.format() undefined trailing bytes | [#92](https://gitlab.com/devnw/zig/dns/-/issues/92) | **Closed** |
| QM-NEW-03 | Medium | 36 | Cache only formats A/AAAA on cache hit; other types silently empty | -- | Open |

### Performance (2 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QH-04 | High | 64 | Name.eql() mmap syscalls | [#95](https://gitlab.com/devnw/zig/dns/-/issues/95) | **Resolved** |
| QM-11 | Medium | 48 | PooledTcpTransport.query unnecessary connect per query | [#180](https://gitlab.com/devnw/zig/dns/-/issues/180) | **Resolved** |

### Maintainability (7 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QC-NEW-03 | High | 64 | sendQuery() triple duplication (~150 lines across stub.zig, recursive.zig, udp.zig) | -- | Open |
| QH-06 | High | 48 | Missing error.InProgress in stub.zig | [#160](https://gitlab.com/devnw/zig/dns/-/issues/160) | **Resolved** |
| QM-07 | **Resolved** | 48 | ~~3x duplicate I/O helpers (~240 lines)~~ Extracted shared `src/transports/io.zig` | [#170](https://gitlab.com/devnw/zig/dns/-/issues/170) | **Resolved** |
| QM-01 | **Resolved** | 36 | ~~parseName() duplicated in tsig/sig0~~ | [#102](https://gitlab.com/devnw/zig/dns/-/issues/102) | **Resolved** |
| QM-05 | **Resolved** | 36 | ~~Silent error swallowing (catch {})~~ | [#117](https://gitlab.com/devnw/zig/dns/-/issues/117) | **Resolved** |
| QM-NEW-01 | Medium | 24 | Duplicate QueryType enum in convenience.zig mirrors types.Type | -- | Open |
| QM-02 | **Resolved** | 24 | ~~Duplicated root server definitions~~ | [#106](https://gitlab.com/devnw/zig/dns/-/issues/106) | **Resolved** |

### Tests (3 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QH-05 | High | 64 | Zero fuzz testing for wire parsers | [#98](https://gitlab.com/devnw/zig/dns/-/issues/98) | **Deferred** |
| QH-NEW-02 | High | 48 | resolveIterative (219 lines) has zero direct test coverage | -- | Open |
| QL-05 | **Resolved** | 16 | Mutable statics in MockTlsBackend | [#181](https://gitlab.com/devnw/zig/dns/-/issues/181) | **Resolved** |

### Readability (4 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QM-03 | Medium | 36 | resolveIterative 219 lines / 9 nesting levels (was 208) | [#109](https://gitlab.com/devnw/zig/dns/-/issues/109) | **Deferred** |
| QL-07 | **Resolved** | 32 | ~~No zig fmt check in CI~~ | [#183](https://gitlab.com/devnw/zig/dns/-/issues/183) | **Resolved** |
| QL-03 | Low | 16 | 12 files over 800 lines (was 9) | [#126](https://gitlab.com/devnw/zig/dns/-/issues/126) | **Deferred** |
| QL-09 | Low | 16 | 41 functions exceed 50 lines (was 30) | [#185](https://gitlab.com/devnw/zig/dns/-/issues/185) | Open |
| QL-06 | **Resolved** | 12 | ~~Magic number 6 for SOA~~ | [#182](https://gitlab.com/devnw/zig/dns/-/issues/182) | **Resolved** |

### Documentation (4 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QM-06 | **Resolved** | 24 | ~~ARCHITECTURE.md missing 60% of modules~~ | [#119](https://gitlab.com/devnw/zig/dns/-/issues/119) | **Resolved** |
| QM-NEW-04 | Low | 16 | lib.zig claims "Zero external dependencies" but spice exists | -- | Open |
| QL-04 | **Resolved** | 16 | ~~No doc comment on rdata-offset invariant~~ | [#127](https://gitlab.com/devnw/zig/dns/-/issues/127) | **Resolved** |
| QL-08 | **Resolved** | 12 | ~~ARCHITECTURE.md references deleted/dead files~~ | [#184](https://gitlab.com/devnw/zig/dns/-/issues/184) | **Resolved** |

### Cleanup (4 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QM-08 | **Resolved** | 24 | ~~Dead file src/resolver/stub.zig~~ | [#173](https://gitlab.com/devnw/zig/dns/-/issues/173) | **Resolved** |
| QM-10 | **Resolved** | 24 | ~~Duplicate SOA parsing in zone_transfer.zig~~ | [#179](https://gitlab.com/devnw/zig/dns/-/issues/179) | **Resolved** |
| QL-01 | **Resolved** | 12 | ~~7 identical @intFromPtr blocks~~ | [#121](https://gitlab.com/devnw/zig/dns/-/issues/121) | **Resolved** |
| QL-02 | Low | 8 | verifyCase0x20 reimplements std.mem.eql | [#123](https://gitlab.com/devnw/zig/dns/-/issues/123) | **Resolved** |
| QL-NEW-01 | **Resolved** | 8 | Duplicated testSocketPair in connection_pool.zig | -- | **Resolved** |

## Remediation Roadmap

### Quick Wins (< 1 day)

| ID | PriorityScore | Finding | Effort | Status |
|----|---------------|---------|--------|--------|
| QM-NEW-01 | 24 | Remove duplicate QueryType; import types.Type | S | Open |
| QM-NEW-05 | 24 | Propagate OOM from resolveNsAddress instead of swallowing | S | Open |
| QM-NEW-04 | 16 | Fix "Zero external dependencies" claim in lib.zig / CHANGELOG.md | S | Open |

### Completed Quick Wins

| ID | PriorityScore | Finding | Status |
|----|---------------|---------|--------|
| QC-02 | 60 | ConnectionPool.acquire mutex race | **Resolved** |
| QC-04 | 60 | PipelinedBatch.execute infinite loop | **Resolved** |
| QM-11 | 48 | Track connected state in PooledConnection | **Resolved** |
| QC-01 | 60 | SVCB hint parsers return dangling pointers | **Resolved** |
| QH-01 | 64 | CNAME continue targets wrong loop | **Resolved** |
| QH-03 | 48 | IPv4.format() undefined bytes | **Resolved** |
| QH-06 | 48 | stub.zig missing InProgress/ConnectionPending | **Resolved** |
| QH-08 | 64 | Zone transfer short read -- read loop added | **Resolved** |
| QM-01 | 36 | Duplicated parseName | **Resolved** |
| QM-05 | 36 | Silent catch {} | **Resolved** |
| QM-08 | 24 | Dead file src/resolver/stub.zig deleted | **Resolved** |
| QM-02 | 24 | Duplicated root servers | **Resolved** |
| QM-04 | 24 | API boundary docs | **Resolved** |
| QM-10 | 24 | extractSerial delegates to parseSoaRdata | **Resolved** |
| QL-01 | 12 | @intFromPtr duplication | **Resolved** |
| QL-02 | 8 | verifyCase0x20 reimplements std.mem.eql | **Resolved** |
| QL-04 | 16 | rdata invariant doc | **Resolved** |
| QL-05 | 16 | Move mock statics to per-instance state | **Resolved** |
| QL-06 | 12 | Replace magic number 6 with named constant | **Resolved** |
| QL-07 | 32 | zig fmt --check added to CI (explicit script in zig-format override) | **Resolved** |
| QL-08 | 12 | ARCHITECTURE.md stale references removed | **Resolved** |
| QC-NEW-01 | 64 | acquire() returns ConnectionHandle instead of dangling pointer | **Resolved** |
| QC-NEW-02 | 48 | TOCTOU re-check after re-acquiring mutex in acquire() | **Resolved** |
| QL-NEW-01 | 8 | Deduplicated testSocketPair (import from io.zig) | **Resolved** |

### Medium Term (1-5 days)

| ID | PriorityScore | Finding | Effort | Status |
|----|---------------|---------|--------|--------|
| QC-NEW-03 | 64 | Extract shared sendUdpQuery() from 3 files (~150 lines) | M | Open |
| QH-NEW-01 | 48 | Wire convenience.zig lookupA/lookupAAAA to real resolver | M | Open |
| QH-NEW-02 | 48 | Add integration tests for resolveIterative (219 lines, 0 coverage) | L | Open |
| QM-NEW-02 | 36 | Unify or rename duplicate ResolveResult types | S | Open |
| QM-NEW-03 | 36 | Add cache formatting for MX, SRV, TXT, NS, PTR record types | M | Open |

### Completed Medium Term

| ID | PriorityScore | Finding | Status |
|----|---------------|---------|--------|
| QC-03 | 80 | Partial write data loss (3 files) | **Resolved** |
| QH-07 | 64 | PipelinedBatch blocking reads | **Resolved** |
| QH-02 | 80 | Referral NS never assigned | **Resolved** |
| QH-04 | 64 | Name.eql() mmap | **Resolved** |
| QM-06 | 24 | ARCHITECTURE.md gaps | **Resolved** |
| QM-07 | 48 | 3x duplicate I/O helpers extracted to io.zig | **Resolved** |
| QM-09 | 36 | parallel.zig placeholder implementations | **Resolved** |

### Strategic (> 5 days) / Deferred

| ID | PriorityScore | Finding | Reason |
|----|---------------|---------|--------|
| QH-05 | 64 | Fuzz testing | Requires fuzz infrastructure setup |
| QM-03 | 36 | resolveIterative complexity (219 lines) | Bugs fixed; refactoring is lower risk but function keeps growing |
| QL-03 | 16 | 12 files over 800 lines (was 9) | Risky refactor with low priority; trend is worsening |
| QL-09 | 16 | 41 functions over 50 lines (was 30) | Large-scale refactoring effort; trend is worsening |

## Related Issues (Pre-existing)

These existing issues overlap with or are related to quality findings:

| Existing Issue | Related Finding | Relationship |
|---------------|-----------------|--------------|
| [#46](https://gitlab.com/devnw/zig/dns/-/issues/46) (TCP length prefix short reads) | QH-08, QC-03 | Same root cause category -- QH-08 is zone_transfer specific, QC-03 covers writes |
| [#47](https://gitlab.com/devnw/zig/dns/-/issues/47) (TCP transports ignore timeout_ms) | QH-07 | Same category; #47 covers stub/tcp/pool query path, QH-07 covers PipelinedBatch |
| [#66](https://gitlab.com/devnw/zig/dns/-/issues/66) (Connection pooling module tracking) | QC-02, QC-04, QH-07, QM-11 | Feature tracking; quality findings are bugs within the module |
| [#68](https://gitlab.com/devnw/zig/dns/-/issues/68) (Parallel DNS operations module) | QM-09 | Feature tracking; QM-09 is about placeholder implementations within |
| [#75](https://gitlab.com/devnw/zig/dns/-/issues/75) (GAP-0012: Dual recursive resolver) | QM-02, QM-08 | Root server duplication resolved; QM-08 is the remaining dead resolver/stub.zig |
| [#40](https://gitlab.com/devnw/zig/dns/-/issues/40) (SEC-018: Code duplication in name parsing) | QM-01, QM-07, QC-NEW-03 | Same root cause pattern -- duplication leads to divergence; QC-NEW-03 is the UDP variant |
| [#109](https://gitlab.com/devnw/zig/dns/-/issues/109) (QM-03: resolveIterative) | QL-09, QH-NEW-02 | QM-03 is a subset of the broader 41-function finding; QH-NEW-02 highlights zero test coverage |
| [#161](https://gitlab.com/devnw/zig/dns/-/issues/161) (SEC-C26: Partial write in TCP framing) | QC-03 | Security perspective on the same partial write issue |
| [#170](https://gitlab.com/devnw/zig/dns/-/issues/170) (QM-07: I/O dedup) | QC-NEW-03 | QC-NEW-03 is the UDP equivalent of the TCP I/O dedup that was resolved in QM-07 |

## Scoring Methodology

**PriorityScore = Impact(1-5) x Likelihood(1-5) x 4**

| Scale | Impact | Likelihood |
|-------|--------|------------|
| 5 | Outages / major perf cost | Ubiquitous / touched often |
| 4 | Frequent bugs / major dev drag | Often encountered |
| 3 | Moderate impact | Sometimes encountered |
| 2 | Minor impact | Rare |
| 1 | Polish | Edge-case |

### New Finding Score Breakdown (Phase 3)

| ID | Impact | Likelihood | PriorityScore | Rationale |
|----|--------|------------|---------------|-----------|
| QC-NEW-03 | 4 (dev drag, divergence risk) | 4 (UDP query on every resolution) | 64 | Same pattern as QM-07 (TCP I/O dedup); three copies already show minor divergence in variable naming |
| QH-NEW-01 | 4 (advertised API non-functional) | 3 (users calling convenience API) | 48 | Public API promises resolution but returns empty; misleads consumers |
| QH-NEW-02 | 4 (most complex function untested) | 3 (regressions likely during maintenance) | 48 | 219-line function with CNAME, referral, QNAME minimization logic has zero test coverage |
| QM-NEW-01 | 2 (minor confusion) | 3 (encountered when extending types) | 24 | QueryType has 10 variants; types.Type has 80+; will diverge silently |
| QM-NEW-02 | 3 (API confusion) | 3 (encountered integrating client + recursive) | 36 | Two types with same name, different shapes; callers must know which module they are in |
| QM-NEW-03 | 3 (silent data loss for non-A/AAAA) | 3 (any MX/SRV/TXT cache hit) | 36 | Cache stores all types but only formats two; cache hit for MX returns empty results array |
| QM-NEW-04 | 1 (misleading docs) | 4 (seen by every new user) | 16 | spice is declared in build.zig.zon; "Zero external dependencies" is factually incorrect |
| QM-NEW-05 | 3 (OOM becomes silent skip) | 2 (OOM during NS resolution is rare) | 24 | `catch return null` on line 688 swallows OOM; should propagate OutOfMemory |

All new findings tagged `confidence::confirmed` -- verified via direct code inspection during Phase 3 review.
