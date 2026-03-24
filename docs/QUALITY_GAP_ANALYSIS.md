# Quality Gap Analysis

Last updated: 2026-03-24 (deep audit -- 10 new findings from architecture/reliability/test review)

## Summary

| Severity | Open (incl. Deferred) | Resolved/Closed | Won't Do | Total |
|----------|----------------------|-----------------|----------|-------|
| Critical | 0 | 4 | 0 | 4 |
| High | 3 | 10 | 2 | 15 |
| Medium | 11 | 17 | 4 | 32 |
| Low | 4 | 10 | 2 | 16 |
| Info | 0 | 6 | 0 | 6 |
| **Total** | **18** | **47** | **8** | **73** |

### Top Active Risks (after deep audit)

1. **MEM-01** (PriorityScore 60) -- initWithServer allocates ServerAddress slice never freed; deinit is no-op. Memory leak. [#186](https://gitlab.com/devnw/zig/dns/-/issues/186)
2. **EH-08** (PriorityScore 60) -- @intCast on time deltas panics on NTP clock regression; 6+ sites across happy_eyeballs, connection_pool, logging. [#192](https://gitlab.com/devnw/zig/dns/-/issues/192)
3. **QC-NEW-03** (PriorityScore 64) -- sendQuery() triple duplication across stub.zig, recursive.zig, udp.zig (~150 lines). **Won't Do** (large refactor).
4. **QH-05** (PriorityScore 64) -- Zero fuzz testing for wire parsers. **Deferred** (requires fuzz infrastructure).
5. **TC-01** (PriorityScore 48) -- resolveIterative zero integration test coverage for 220-line core function. [#190](https://gitlab.com/devnw/zig/dns/-/issues/190)
6. **QM-03** (PriorityScore 36) -- resolveIterative 219 lines / 9 nesting levels. **Deferred**.
7. **RD-01** (PriorityScore 30) -- name.zig compression pointer security checks repeated 7+ times; no shared LabelIterator. [#188](https://gitlab.com/devnw/zig/dns/-/issues/188)
8. **CI-04** (PriorityScore 30) -- cmd/zdig.zig 1051 lines, zero tests; security-sensitive escapeJsonString/addressMatches untested. [#196](https://gitlab.com/devnw/zig/dns/-/issues/196)

Note: RE-05, QM-NEW-03 (GAP-0043), AC-02, AC-03, QM-NEW-05, QS-NEW-05, RM-08, QS-NEW-02, QM-NEW-01, RM-04, QS-NEW-03, and DG-01 through DG-06 all **resolved** in prior gap closure cycle.

## Stack-Ranked Findings

| Rank | ID | Severity | PriorityScore | Category | Finding | Component | Evidence | Issue | Fix Summary | Owner | Effort | Status |
|------|----|----------|---------------|----------|---------|-----------|----------|-------|-------------|-------|--------|--------|
| 1 | QC-03 | Critical | 80 | architecture | `_ = try write()` discards return value in 3 files, 6 sites -- partial write data loss | connection_pool, dot, zone_transfer | `connection_pool.zig:454-455`, `dot.zig:305-306`, `zone_transfer.zig:523-524` | [#152](https://gitlab.com/devnw/zig/dns/-/issues/152) | Use writeAll loop or existing writeAllWithTimeout helper | Transport maintainer | S | **Resolved** |
| 2 | QH-02 | High | 80 | architecture | Referral NS servers computed but never assigned to `current_servers` | recursive.zig | `src/recursive.zig:296-316` | [#91](https://gitlab.com/devnw/zig/dns/-/issues/91) | Assign `new_servers` items to `current_servers` with proper lifetime management | Resolver maintainer | M | **Resolved** |
| 3 | QH-07 | High | 64 | architecture | Blocking reads without timeout in PipelinedBatch.execute | connection_pool.zig | `connection_pool.zig:448-498` -- raw `std.posix.read/write` without poll/timeout | [#163](https://gitlab.com/devnw/zig/dns/-/issues/163) | Add timeout_ms parameter, use readWithTimeout/writeAllWithTimeout | Transport maintainer | S | **Resolved** |
| 4 | QH-08 | High | 64 | architecture | Zone transfer receiveTcpMessage single read for 2-byte length prefix | zone_transfer.zig | `zone_transfer.zig:530-540` -- read loop with `while (len_read < 2)` | [#166](https://gitlab.com/devnw/zig/dns/-/issues/166) | Read loop for 2-byte prefix; only n==0 means closed (SEC-C33/QH-08) | Resolver maintainer | S | **Resolved** |
| 5 | QH-01 | High | 64 | architecture | CNAME `continue` targets inner `ans_iter` loop, not outer resolution loop | recursive.zig | `src/recursive.zig:253-271` | [#86](https://gitlab.com/devnw/zig/dns/-/issues/86) | Replace `continue` with `break` + flag pattern to target outer loop | Resolver maintainer | S | **Resolved** |
| 6 | QH-04 | High | 64 | perf | `Name.eql()` uses `page_allocator` -- 2 mmap+munmap syscalls per comparison | name.zig | `src/name.zig:254-264` | [#95](https://gitlab.com/devnw/zig/dns/-/issues/95) | Compare labels directly without allocation | name.zig maintainer | M | **Resolved** |
| 7 | QH-05 | High | 64 | tests | Zero fuzz testing for security-critical DNS wire parsers | All parsers | No fuzz targets in build.zig | [#98](https://gitlab.com/devnw/zig/dns/-/issues/98) | Add `std.testing.fuzz` targets | Security/testing lead | M | **Deferred** |
| 8 | QC-NEW-03 | High | 64 | maintainability | sendQuery() triple duplication: ~50 lines of identical UDP socket+timeout+sendto+recvfrom logic copied verbatim in 3 files | stub.zig, recursive.zig, udp.zig | `stub.zig:198-246`, `recursive.zig:514-559`, `udp.zig:36-84` | -- | **Won't Do** (large refactor requiring transport architecture changes; duplication is stable and well-tested) | Transport maintainer | M | **Won't Do** |
| 9 | QC-NEW-01 | **Resolved** | 64 | architecture | `acquire()` returns pointer into ArrayList backing array; dangling after realloc/swapRemove | connection_pool.zig | `connection_pool.zig:251,291` | -- | Return ConnectionHandle (value type with generation-based lookup) | Transport maintainer | M | **Resolved** |
| 10 | MEM-01 | High | 60 | architecture | `initWithServer` allocates ServerAddress slice never freed; `deinit` is no-op. Memory leak every call. | stub.zig | `src/stub.zig:109-123` | [#186](https://gitlab.com/devnw/zig/dns/-/issues/186) | Add `owns_servers: bool` flag; free in deinit when true | Resolver maintainer | S | Open |
| 11 | EH-08 | High | 60 | architecture | `@intCast` on time deltas panics on NTP clock regression; 6+ sites across happy_eyeballs, connection_pool, logging, zone_transfer | happy_eyeballs.zig, connection_pool.zig, logging.zig, zone_transfer.zig | `happy_eyeballs.zig:199,239`, `connection_pool.zig:123,128`, `logging.zig:391`, `zone_transfer.zig:317,329,398,413` | [#192](https://gitlab.com/devnw/zig/dns/-/issues/192) | Saturating subtraction or monotonic clock (`std.time.Instant`) | Transport/Resolver maintainer | S | Open |
| 12 | QC-02 | Critical | 60 | architecture | ConnectionPool.acquire mutex race: defer lock/unlock dance leaves lines 278-286 unprotected | connection_pool.zig | `connection_pool.zig:247-287` | [#151](https://gitlab.com/devnw/zig/dns/-/issues/151) | Replace `defer self.mutex.lock()` with explicit `self.mutex.lock()` before mutations | Transport maintainer | S | **Resolved** |
| 13 | QC-04 | Critical | 60 | architecture | Infinite loop in PipelinedBatch.execute: `continue` targets inner while, not outer for | connection_pool.zig | `connection_pool.zig:468,490` | [#156](https://gitlab.com/devnw/zig/dns/-/issues/156) | Add `outer:` label to for loop, use `continue :outer` | Transport maintainer | S | **Resolved** |
| 14 | QC-01 | Critical | 60 | api-contract | `parseSvcbIpv4Hint`/`parseSvcbIpv6Hint` return slices to stack-local arrays (UB) | record.zig | `src/record.zig:601-630` | [#83](https://gitlab.com/devnw/zig/dns/-/issues/83) | Accept allocator parameter, return owned slice | record.zig maintainer | S | **Closed** |
| 15 | QH-06 | High | 48 | maintainability | Missing `error.InProgress` in stub.zig connectWithTimeout | stub.zig | `stub.zig:294-297` | [#160](https://gitlab.com/devnw/zig/dns/-/issues/160) | Added `error.ConnectionPending` to switch | Resolver maintainer | S | **Resolved** |
| 16 | QH-NEW-01 | High | 48 | api-contract | convenience.zig lookupA/lookupAAAA/lookup were empty stubs returning empty results | convenience.zig | `src/resolver/convenience.zig:194-226` | Commit 6d42d51 | Returns `error.NotImplemented` so callers get explicit signal | Convenience module maintainer | S | **Resolved** |
| 17 | QH-NEW-02 | High | 48 | tests | resolveIterative has zero direct test coverage; 219 lines, deepest nesting, most complex control flow in recursive resolver | recursive.zig | `src/recursive.zig:188-406` -- no test matches pattern `test.*resolveIterative` | -- | **Won't Do** (requires mock DNS transport infrastructure; cross-ref GAP-0045) | Resolver maintainer | L | **Won't Do** |
| 18 | TC-01 | Medium | 48 | tests | resolveIterative zero integration test coverage for 220-line core resolution function (deep review confirmation of QH-NEW-02) | recursive.zig | `src/recursive.zig:188-406` | [#190](https://gitlab.com/devnw/zig/dns/-/issues/190) | Mock transport infrastructure + 5 integration tests covering CNAME/referral/NXDOMAIN paths | Resolver maintainer | L | Open |
| 19 | QH-03 | High | 48 | api-contract | `IPv4.format()` returns `[15]u8` with undefined trailing bytes | convenience.zig | `src/resolver/convenience.zig:34-43` | [#92](https://gitlab.com/devnw/zig/dns/-/issues/92) | Return struct with buf+len, or zero-fill buffer | Convenience module maintainer | S | **Closed** |
| 20 | QC-NEW-02 | **Resolved** | 48 | architecture | TOCTOU in connection limit: countServerConnections check races with createConnection | connection_pool.zig | `connection_pool.zig:268-296` | -- | Re-check countServerConnections after re-acquiring mutex | Transport maintainer | S | **Resolved** |
| 21 | QM-07 | **Resolved** | 48 | maintainability | ~~3x duplicate I/O helpers: connectWithTimeout, writeAllWithTimeout, readWithTimeout, readExactWithTimeout~~ | stub.zig, tcp.zig, connection_pool.zig | Extracted shared `src/transports/io.zig` | [#170](https://gitlab.com/devnw/zig/dns/-/issues/170) | Resolved: shared io.zig module with 4 tests | Transport maintainer | M | **Resolved** |
| 22 | QM-11 | Medium | 48 | perf | PooledTcpTransport.query calls connect on every query despite connection pooling | connection_pool.zig | `connection_pool.zig:537` | [#180](https://gitlab.com/devnw/zig/dns/-/issues/180) | Track connected state in PooledConnection or connect in acquire() | Transport maintainer | S | **Resolved** |
| 23 | QS-NEW-01 | Medium | 45 | maintainability | responseMatchesQuery duplicated in stub.zig and recursive.zig (~20 lines) | stub.zig, recursive.zig | `src/stub.zig:132-151` and `src/recursive.zig:749-768` | -- | **Won't Do** (low-risk duplication; function is stable and small) | Resolver maintainer | S | **Won't Do** |
| 24 | RE-05 | Medium | 40 | architecture | rdataOffset pointer arithmetic has no runtime safety check; relies on aliasing invariant that `self.rdata.ptr` points into `full_message` | record.zig | `src/record.zig:77-79` -- bounds check added; returns error on invariant violation | -- | Added bounds check and error return on violation | record.zig maintainer | S | **Resolved** |
| 25 | QM-NEW-02 | Medium | 36 | architecture | ResolveResult defined twice with incompatible shapes: client.zig has `addresses: []const []const u8` + `from_cache: bool`; recursive.zig has `status: ResolveStatus` + `answer: ?[]u8` + `from_cache: bool` | client.zig, recursive.zig | `src/client.zig:318-332`, `src/recursive.zig:835-844` | -- | Unify into single type or rename to avoid confusion; client could wrap recursive result | Resolver maintainer | S | **Won't Do** (large refactor; different shapes serve different layers) |
| 26 | QM-NEW-03 | Medium | 36 | api-contract | Cache hit path in Client.resolve only formats A and AAAA records; MX, SRV, TXT, NS, PTR cache hits silently return empty results | client.zig | `src/client.zig` -- `formatCachedRdata` added covering 9 record types | -- | Added `formatCachedRdata` for A, AAAA, MX, SRV, TXT, PTR, NS, SOA, CNAME | Client maintainer | M | **Resolved** |
| 27 | AC-02 | Medium | 36 | architecture | client.lookupMX leaks exchange strings on error -- errdefer only calls `results.deinit()` | client.zig | `src/client.zig` -- errdefer now frees exchange strings before deinit | -- | Added `errdefer { for (results.items) |mx| self.allocator.free(mx.exchange); results.deinit(self.allocator); }` | Client maintainer | S | **Resolved** |
| 28 | QM-03 | Medium | 36 | readability | `resolveIterative` is 219 lines with 9 levels of nesting (was 171 at QM-03 filing, 208 at Phase 2, now 219) | recursive.zig | `src/recursive.zig:188-406` | [#109](https://gitlab.com/devnw/zig/dns/-/issues/109) | Extract `handleCnameChain()`, `handleReferral()`, `handleNodataResponse()` | Resolver maintainer | M | **Deferred** |
| 26 | RD-01 | Medium | 30 | maintainability | name.zig compression pointer security checks repeated 7+ times across toString/toStringBuf/labelCount/eql/parent; no shared LabelIterator | name.zig | `src/name.zig` -- 7+ sites with identical ~10-line compression pointer traversal logic | [#188](https://gitlab.com/devnw/zig/dns/-/issues/188) | Extract `LabelIterator` struct encapsulating pointer traversal with all security checks | name.zig maintainer | M | Open |
| 27 | CI-04 | Medium | 30 | tests | cmd/zdig.zig: 1051 lines, zero tests; security-sensitive escapeJsonString and addressMatches untested | zdig.zig | `cmd/zdig.zig` -- 0 test blocks in 1051-line file | [#196](https://gitlab.com/devnw/zig/dns/-/issues/196) | Extract pure functions to testable module; add unit tests | CLI maintainer | M | Open |
| 28 | QS-NEW-04 | Medium | 30 | ci-cd | CI downloads+installs Zig in every job; binary directory not cached | .gitlab-ci.yml | `.gitlab-ci.yml:25-28` | -- | **Won't Do** (CI infrastructure improvement; not a code quality issue) | CI/CD maintainer | S | **Won't Do** |
| 29 | QS-NEW-06 | Medium | 30 | ci-cd | No code coverage measurement tool or CI integration; no coverage gates in pipeline | .gitlab-ci.yml, build.zig | No coverage integration | -- | **Won't Do** (CI infrastructure improvement; requires Zig coverage tooling maturation) | CI/CD maintainer | M | **Won't Do** |
| 30 | DUP-02 | Medium | 24 | maintainability | responseMatchesQuery duplicated identically (~20 lines) in stub.zig:132-151 and recursive.zig:768-787 | stub.zig, recursive.zig | `src/stub.zig:132-151` and `src/recursive.zig:768-787` | [#187](https://gitlab.com/devnw/zig/dns/-/issues/187) | Extract to shared module (cross-ref QS-NEW-01) | Resolver maintainer | S | Open |
| 31 | RM-04 | Medium | 24 | maintainability | Duplicate MXRecord/MxRecord types: `client.zig:337` defines `MXRecord` (uppercase X) and `convenience.zig:87` defines `MxRecord` (lowercase x) with identical shape | client.zig, convenience.zig | `src/client.zig` -- MxRecord consolidated; duplicate removed | -- | Consolidated MxRecord type; removed duplicate | Resolver maintainer | S | **Resolved** |
| 32 | RM-07 | Medium | 24 | maintainability | IPv4 formatting pattern `"{d}.{d}.{d}.{d}"` repeated inline in 4+ places | record.zig, recursive.zig, client.zig, convenience.zig | Multiple sites | -- | **Won't Do** (low-risk repetition; format string is idiomatic and unlikely to diverge) | Any contributor | S | **Won't Do** |
| 33 | QM-NEW-01 | Medium | 24 | maintainability | Duplicate QueryType enum in convenience.zig mirrors types.Type | convenience.zig, types.zig | `src/resolver/convenience.zig` -- QueryType removed; replaced with `types.Type` | -- | Removed duplicate QueryType; now imports and uses types.Type directly | Convenience module maintainer | S | **Resolved** |
| 34 | QM-NEW-05 | Medium | 24 | architecture | resolveNsAddress catches all errors (including OOM) as null via `catch return null` | recursive.zig | `src/recursive.zig` -- OOM now propagated; other errors return null | -- | `catch |err| switch (err) { error.OutOfMemory => return err, else => return null }` | Resolver maintainer | S | **Resolved** |
| 35 | QS-NEW-08 | Medium | 20 | deps | Spice dependency pinned to main branch tarball; no semver tag | build.zig.zon | `build.zig.zon:29` | -- | **Won't Do** (upstream concern; hash pinning provides integrity; cross-ref GAP-0047, SEC-C14/C31) | Project maintainer | S | **Won't Do** |
| 36 | QS-NEW-05 | Medium | 18 | architecture | stub.zig:170 swallows OOM errors via bare `catch` | stub.zig | `src/stub.zig` -- OOM now propagated via `catch |err| switch (err) { error.OutOfMemory => return err, else => continue }` | -- | Propagate OOM from bare catch in stub.zig | Resolver maintainer | S | **Resolved** |
| 37 | AC-03 | Medium | 18 | architecture | Cache-hit errdefer in resolve() does not free duped strings on error | client.zig | `src/client.zig` -- errdefer now frees duped strings and ArrayList backing | -- | Added `errdefer { for (results.items) |s| self.allocator.free(s); results.deinit(self.allocator); }` | Client maintainer | S | **Resolved** |
| 38 | DOC-01 | Medium | 18 | docs | No ownership documentation for Message.data (aliases caller's buffer); use-after-free risk | message.zig | `src/message.zig:42` -- `data: []const u8` with no lifetime doc | [#198](https://gitlab.com/devnw/zig/dns/-/issues/198) | Add `///` doc comment explaining aliasing/lifetime requirements | message.zig maintainer | S | Open |
| 39 | EH-11 | Medium | 18 | architecture | zdig TCP response read loop breaks on recv==0 without validating total_read==response_len; silent truncation | zdig.zig | `cmd/zdig.zig:640-644` | [#194](https://gitlab.com/devnw/zig/dns/-/issues/194) | Return `error.IncompleteRead` when connection closes before response_len bytes received | CLI maintainer | S | Open |
| 40 | QL-03 | Low | 16 | readability | 12 source files exceed 800-line threshold (was 9). New: `connection_pool.zig` (1070), `parallel.zig` (881), `enhanced_metrics.zig` (879). Largest: `record.zig` (1927) | Multiple files | `record.zig:1927`, `recursive.zig:1426`, `name.zig:1345`, `connection_pool.zig:1070`, `edns.zig:973`, `tsig.zig:916`, `zone_transfer.zig:894`, `dnssec.zig:889`, `parallel.zig:881`, `enhanced_metrics.zig:879`, `zone_file.zig:863`, `sig0.zig:814` | [#126](https://gitlab.com/devnw/zig/dns/-/issues/126) | Split large files by responsibility domain | Project maintainer | L | **Deferred** |
| 41 | QL-09 | Low | 16 | readability | 41 functions exceed 50-line threshold (was 30); resolveIterative at 219 lines | Multiple files | `recursive.zig:188+` (219 lines), record.zig, edns.zig, zone_transfer.zig parsers | [#185](https://gitlab.com/devnw/zig/dns/-/issues/185) | Decompose long functions; add lint gate | Project maintainer | L | **Deferred** |
| 42 | QS-NEW-03 | Low | 12 | cleanup | 4 lib.zig module exports never imported by any consumer: `convenience`, `rpz`, `config`, `cache_prefetch` | lib.zig | `src/lib.zig` -- exports documented as intentional public API with comments | -- | Documented as intentional public API (modules available for downstream consumers) | Any contributor | S | **Resolved** |
| 43 | QS-NEW-07 | Low | 12 | tests | Client tests bail on network failure; test passes vacuously in CI | client.zig | `src/client.zig:458-469` | -- | **Won't Do** (requires mock transport infrastructure; cross-ref GAP-0045) | Client maintainer | M | **Won't Do** |
| 44 | QS-NEW-02 | Low | 10 | cleanup | question.buildQuery at question.zig:102 is dead code | question.zig | `src/question.zig` -- dead code removed | -- | Deleted dead `question.buildQuery` function | Any contributor | S | **Resolved** |
| 45 | RM-08 | Low | 10 | cleanup | getMinimizedQname ignores `current_zone` parameter (dead parameter) | recursive.zig | `src/recursive.zig` -- `current_zone` parameter removed; all call sites updated | -- | Removed dead `current_zone` parameter from `getMinimizedQname` | Resolver maintainer | S | **Resolved** |
| 46 | QM-NEW-04 | Low | 16 | docs | lib.zig claimed "Zero external dependencies" but build.zig.zon declares `spice` dependency | lib.zig | `src/lib.zig:16` -- updated to `//! - Minimal dependencies (optional spice for parallelism)` | Commit 6d42d51 | Updated doc comment to accurately reflect spice dependency | Documentation maintainer | S | **Resolved** |
| 47 | QL-NEW-01 | **Resolved** | 8 | cleanup | Duplicated testSocketPair helper identical to io.zig:118-126 | connection_pool.zig | `connection_pool.zig:665-673` | -- | Make io.zig testSocketPair public; replace duplicate with const alias | Any contributor | S | **Resolved** |
| 48 | DOC-02 | Low | 8 | docs | connection_pool.zig createConnection accepts and discards server/timeout_ms params; misleading API (intentional lazy-connection design) | connection_pool.zig | `src/transports/connection_pool.zig:471-495` | [#200](https://gitlab.com/devnw/zig/dns/-/issues/200) | Add doc comment explaining lazy-connection design; consider renaming to `createSocket` | Transport maintainer | S | Open |
| 49 | DOC-03 | Low | 8 | docs | No module-level library user guide for downstream consumers; onboarding friction | docs/ | No usage guide exists | [#201](https://gitlab.com/devnw/zig/dns/-/issues/201) | Create docs/USAGE.md with quick-start examples and ownership/lifetime rules | Documentation maintainer | M | Open |
| 50 | QM-05 | **Resolved** | 36 | maintainability | ~~Silent error swallowing with `catch {}` in 5+ locations~~ | Multiple files | All catch {} sites documented or upgraded | [#117](https://gitlab.com/devnw/zig/dns/-/issues/117) | Resolved | Any contributor | S | **Resolved** |
| 51 | QM-01 | **Resolved** | 36 | maintainability | ~~`parseName()` copy-pasted ~52 identical lines in tsig.zig and sig0.zig~~ | tsig.zig, sig0.zig | Extracted shared `src/security/dns_name.zig` | [#102](https://gitlab.com/devnw/zig/dns/-/issues/102) | Resolved | Security module maintainer | S | **Resolved** |
| 52 | QM-09 | **Resolved** | 36 | architecture | ~~parallel.zig: 4 placeholder implementations return fabricated results~~ | parallel.zig | Real wire-format parsing; honest error status | [#177](https://gitlab.com/devnw/zig/dns/-/issues/177) | Resolved | Parallel module maintainer | M | **Resolved** |
| 53 | QL-07 | **Resolved** | 32 | ci-cd | ~~No `zig fmt --check` in CI pipeline~~ | .gitlab-ci.yml | zig-format job override now includes explicit script | [#183](https://gitlab.com/devnw/zig/dns/-/issues/183) | Resolved | CI/CD maintainer | S | **Resolved** |
| 54 | QM-08 | **Resolved** | 24 | cleanup | ~~Dead file `src/resolver/stub.zig`~~ | resolver/stub.zig (deleted) | File deleted | [#173](https://gitlab.com/devnw/zig/dns/-/issues/173) | Resolved | Any contributor | S | **Resolved** |
| 55 | QM-10 | **Resolved** | 24 | cleanup | ~~Duplicate SOA parsing: extractSerial duplicates parseSoaRdata~~ | zone_transfer.zig | `extractSerial` now delegates to `parseSoaRdata` | [#179](https://gitlab.com/devnw/zig/dns/-/issues/179) | Resolved | Resolver maintainer | S | **Resolved** |
| 56 | QM-02 | **Resolved** | 24 | maintainability | ~~Duplicated root server definitions~~ | recursive.zig | Deleted `src/resolver/recursive.zig` | [#106](https://gitlab.com/devnw/zig/dns/-/issues/106) | Resolved | Resolver maintainer | S | **Resolved** |
| 57 | QM-04 | **Resolved** | 24 | architecture | ~~18 modules lack API boundary docs~~ | build.zig | Added API boundary comments | [#113](https://gitlab.com/devnw/zig/dns/-/issues/113) | Resolved | Project maintainer | S | **Resolved** |
| 58 | QM-06 | **Resolved** | 24 | docs | ~~ARCHITECTURE.md missing 60% of modules~~ | docs/ARCHITECTURE.md | Rewritten with all modules documented | [#119](https://gitlab.com/devnw/zig/dns/-/issues/119) | Resolved | Documentation lead | M | **Resolved** |
| 59 | QL-04 | **Resolved** | 16 | docs | ~~No doc comment on rdata-offset invariant~~ | record.zig | Doc comments added | [#127](https://gitlab.com/devnw/zig/dns/-/issues/127) | Resolved | Any contributor | S | **Resolved** |
| 60 | QL-05 | **Resolved** | 16 | tests | ~~Mutable statics in MockTlsBackend~~ | dot.zig | Moved to per-instance state | [#181](https://gitlab.com/devnw/zig/dns/-/issues/181) | Resolved | Any contributor | S | **Resolved** |
| 61 | QL-06 | **Resolved** | 12 | readability | ~~Magic number 6 for SOA record type~~ | zone_transfer.zig | Replaced with `soa_rtype` named constant | [#182](https://gitlab.com/devnw/zig/dns/-/issues/182) | Resolved | Any contributor | S | **Resolved** |
| 62 | QL-08 | **Resolved** | 12 | docs | ~~ARCHITECTURE.md references deleted/dead files~~ | docs/ARCHITECTURE.md | Stale references removed | [#184](https://gitlab.com/devnw/zig/dns/-/issues/184) | Resolved | Documentation maintainer | S | **Resolved** |
| 63 | QL-01 | **Resolved** | 12 | cleanup | ~~7 identical @intFromPtr blocks~~ | record.zig | Extracted rdataOffset() helper | [#121](https://gitlab.com/devnw/zig/dns/-/issues/121) | Resolved | Any contributor | S | **Resolved** |
| 64 | QL-02 | Low | 8 | cleanup | `verifyCase0x20()` reimplements `std.mem.eql` | name.zig | `src/name.zig:451-462` | [#123](https://gitlab.com/devnw/zig/dns/-/issues/123) | Replace with std.mem.eql | Any contributor | S | **Resolved** |
| -- | DG-01 | Info | -- | docs | resolveIterative (219 lines) has no function-level doc comment | recursive.zig | `src/recursive.zig` -- doc comment added describing iterative resolution algorithm | -- | Added `///` doc comment to resolveIterative | Resolver maintainer | S | **Resolved** |
| -- | DG-02 | Info | -- | docs | ResolutionState struct has no doc comment explaining field semantics | recursive.zig | `src/recursive.zig` -- doc comments added to ResolutionState and fields | -- | Added `///` doc comments to ResolutionState and each field | Resolver maintainer | S | **Resolved** |
| -- | DG-03 | Info | -- | docs | MXRecord ownership semantics undocumented | client.zig | `src/client.zig` -- ownership doc comment added to MXRecord/MxRecord | -- | Added `/// Caller owns the returned slice and each .exchange string` | Client maintainer | S | **Resolved** |
| -- | DG-04 | Info | -- | docs | rdataOffset invariant only documented in code comment, not in public API doc | record.zig | `src/record.zig` -- `///` doc added to ResourceRecord explaining rdata aliasing | -- | Added public API doc explaining rdata slices alias into original message buffer | record.zig maintainer | S | **Resolved** |
| -- | DG-05 | Info | -- | docs | getMinimizedQname has no doc comment (RFC 9156) | recursive.zig | `src/recursive.zig` -- doc comment added referencing RFC 9156 | -- | Added doc comment referencing RFC 9156 and depth-based label minimization | Resolver maintainer | S | **Resolved** |
| -- | DG-06 | Info | -- | docs | Cache formatting logic in resolve() has no comment explaining supported types | client.zig | `src/client.zig` -- comment added; QM-NEW-03 resolved (9 types now supported) | -- | Comment added; all cacheable types now formatted via `formatCachedRdata` | Client maintainer | S | **Resolved** |

## Findings by Category

### Architecture (20 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QC-03 | Critical | 80 | Partial write data loss (3 files, 6 sites) | [#152](https://gitlab.com/devnw/zig/dns/-/issues/152) | **Resolved** |
| QH-02 | High | 80 | Referral NS servers never assigned | [#91](https://gitlab.com/devnw/zig/dns/-/issues/91) | **Resolved** |
| QH-07 | High | 64 | Blocking reads without timeout in PipelinedBatch | [#163](https://gitlab.com/devnw/zig/dns/-/issues/163) | **Resolved** |
| QH-08 | High | 64 | Zone transfer short read on length prefix | [#166](https://gitlab.com/devnw/zig/dns/-/issues/166) | **Resolved** |
| QH-01 | High | 64 | CNAME continue targets wrong loop | [#86](https://gitlab.com/devnw/zig/dns/-/issues/86) | **Resolved** |
| MEM-01 | High | 60 | initWithServer allocates ServerAddress slice never freed; deinit is no-op | [#186](https://gitlab.com/devnw/zig/dns/-/issues/186) | Open |
| EH-08 | High | 60 | @intCast on time deltas panics on NTP clock regression; 6+ sites | [#192](https://gitlab.com/devnw/zig/dns/-/issues/192) | Open |
| QC-02 | Critical | 60 | ConnectionPool.acquire mutex race | [#151](https://gitlab.com/devnw/zig/dns/-/issues/151) | **Resolved** |
| QC-04 | Critical | 60 | PipelinedBatch.execute infinite loop | [#156](https://gitlab.com/devnw/zig/dns/-/issues/156) | **Resolved** |
| RE-05 | Medium | 40 | rdataOffset pointer arithmetic -- bounds check added | -- | **Resolved** |
| QM-09 | **Resolved** | 36 | parallel.zig placeholder implementations | [#177](https://gitlab.com/devnw/zig/dns/-/issues/177) | **Resolved** |
| AC-02 | Medium | 36 | client.lookupMX leaks exchange strings on error -- errdefer fixed | -- | **Resolved** |
| QM-04 | **Resolved** | 24 | 18 modules lack API boundary docs | [#113](https://gitlab.com/devnw/zig/dns/-/issues/113) | **Resolved** |
| QC-NEW-01 | **Resolved** | 64 | acquire() returns dangling pointer into ArrayList | -- | **Resolved** |
| QC-NEW-02 | **Resolved** | 48 | TOCTOU in connection limit check | -- | **Resolved** |
| QM-NEW-02 | Medium | 36 | ResolveResult defined twice with incompatible shapes | -- | **Won't Do** |
| QM-NEW-05 | Medium | 24 | resolveNsAddress OOM now propagated | -- | **Resolved** |
| EH-11 | Medium | 18 | zdig TCP read loop silent truncation on connection close | [#194](https://gitlab.com/devnw/zig/dns/-/issues/194) | Open |
| AC-03 | Medium | 18 | Cache-hit errdefer in resolve() -- errdefer fixed | -- | **Resolved** |
| QS-NEW-05 | Medium | 18 | stub.zig OOM now propagated | -- | **Resolved** |

### API Contract (4 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QC-01 | Critical | 60 | SVCB hint parsers return dangling pointers | [#83](https://gitlab.com/devnw/zig/dns/-/issues/83) | **Closed** |
| QH-NEW-01 | High | 48 | convenience.zig lookupA/lookupAAAA/lookup now return error.NotImplemented | Commit 6d42d51 | **Resolved** |
| QH-03 | High | 48 | IPv4.format() undefined trailing bytes | [#92](https://gitlab.com/devnw/zig/dns/-/issues/92) | **Closed** |
| QM-NEW-03 | Medium | 36 | Cache formats 9 record types on cache hit (was A/AAAA only) | -- | **Resolved** |

### Performance (2 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QH-04 | High | 64 | Name.eql() mmap syscalls | [#95](https://gitlab.com/devnw/zig/dns/-/issues/95) | **Resolved** |
| QM-11 | Medium | 48 | PooledTcpTransport.query unnecessary connect per query | [#180](https://gitlab.com/devnw/zig/dns/-/issues/180) | **Resolved** |

### Maintainability (12 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QC-NEW-03 | High | 64 | sendQuery() triple duplication (~150 lines) | -- | **Won't Do** |
| QH-06 | High | 48 | Missing error.InProgress in stub.zig | [#160](https://gitlab.com/devnw/zig/dns/-/issues/160) | **Resolved** |
| QS-NEW-01 | Medium | 45 | responseMatchesQuery duplicated (~20 lines) | -- | **Won't Do** |
| RD-01 | Medium | 30 | name.zig compression pointer checks repeated 7+ times; no shared LabelIterator | [#188](https://gitlab.com/devnw/zig/dns/-/issues/188) | Open |
| DUP-02 | Medium | 24 | responseMatchesQuery duplicated in stub.zig and recursive.zig (~20 lines) | [#187](https://gitlab.com/devnw/zig/dns/-/issues/187) | Open |
| QM-07 | **Resolved** | 48 | ~~3x duplicate I/O helpers (~240 lines)~~ Extracted shared `src/transports/io.zig` | [#170](https://gitlab.com/devnw/zig/dns/-/issues/170) | **Resolved** |
| QM-01 | **Resolved** | 36 | ~~parseName() duplicated in tsig/sig0~~ | [#102](https://gitlab.com/devnw/zig/dns/-/issues/102) | **Resolved** |
| QM-05 | **Resolved** | 36 | ~~Silent error swallowing (catch {})~~ | [#117](https://gitlab.com/devnw/zig/dns/-/issues/117) | **Resolved** |
| RM-04 | Medium | 24 | Duplicate MXRecord/MxRecord -- consolidated | -- | **Resolved** |
| RM-07 | Medium | 24 | IPv4 formatting pattern repeated inline in 4+ places | -- | **Won't Do** |
| QM-NEW-01 | Medium | 24 | Duplicate QueryType removed; uses types.Type | -- | **Resolved** |
| QM-02 | **Resolved** | 24 | ~~Duplicated root server definitions~~ | [#106](https://gitlab.com/devnw/zig/dns/-/issues/106) | **Resolved** |

### Tests (6 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QH-05 | High | 64 | Zero fuzz testing for wire parsers | [#98](https://gitlab.com/devnw/zig/dns/-/issues/98) | **Deferred** |
| QH-NEW-02 | High | 48 | resolveIterative (219 lines) has zero direct test coverage | -- | **Won't Do** |
| TC-01 | Medium | 48 | resolveIterative zero integration test coverage (deep review confirmation of QH-NEW-02) | [#190](https://gitlab.com/devnw/zig/dns/-/issues/190) | Open |
| CI-04 | Medium | 30 | cmd/zdig.zig: 1051 lines, zero tests; security-sensitive functions untested | [#196](https://gitlab.com/devnw/zig/dns/-/issues/196) | Open |
| QS-NEW-07 | Low | 12 | Client tests bail on network failure | -- | **Won't Do** |
| QL-05 | **Resolved** | 16 | Mutable statics in MockTlsBackend | [#181](https://gitlab.com/devnw/zig/dns/-/issues/181) | **Resolved** |

### Readability (5 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QM-03 | Medium | 36 | resolveIterative 219 lines / 9 nesting levels (was 208) | [#109](https://gitlab.com/devnw/zig/dns/-/issues/109) | **Deferred** |
| QL-07 | **Resolved** | 32 | ~~No zig fmt check in CI~~ | [#183](https://gitlab.com/devnw/zig/dns/-/issues/183) | **Resolved** |
| QL-03 | Low | 16 | 12 files over 800 lines (was 9) | [#126](https://gitlab.com/devnw/zig/dns/-/issues/126) | **Deferred** |
| QL-09 | Low | 16 | 41 functions exceed 50 lines (was 30) | [#185](https://gitlab.com/devnw/zig/dns/-/issues/185) | **Deferred** |
| QL-06 | **Resolved** | 12 | ~~Magic number 6 for SOA~~ | [#182](https://gitlab.com/devnw/zig/dns/-/issues/182) | **Resolved** |

### CI/CD (2 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QS-NEW-04 | Medium | 30 | CI Zig install not cached | -- | **Won't Do** |
| QS-NEW-06 | Medium | 30 | No code coverage measurement or CI integration | -- | **Won't Do** |

### Dependencies (1 finding)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QS-NEW-08 | Medium | 20 | Spice dependency pinned to main branch tarball | -- | **Won't Do** |

### Cleanup (8 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QM-08 | **Resolved** | 24 | ~~Dead file src/resolver/stub.zig~~ | [#173](https://gitlab.com/devnw/zig/dns/-/issues/173) | **Resolved** |
| QM-10 | **Resolved** | 24 | ~~Duplicate SOA parsing in zone_transfer.zig~~ | [#179](https://gitlab.com/devnw/zig/dns/-/issues/179) | **Resolved** |
| QS-NEW-03 | Low | 12 | 4 lib.zig module exports -- documented as intentional | -- | **Resolved** |
| QS-NEW-02 | Low | 10 | question.buildQuery dead code deleted | -- | **Resolved** |
| RM-08 | Low | 10 | getMinimizedQname dead parameter removed | -- | **Resolved** |
| QL-01 | **Resolved** | 12 | ~~7 identical @intFromPtr blocks~~ | [#121](https://gitlab.com/devnw/zig/dns/-/issues/121) | **Resolved** |
| QL-02 | Low | 8 | verifyCase0x20 reimplements std.mem.eql | [#123](https://gitlab.com/devnw/zig/dns/-/issues/123) | **Resolved** |
| QL-NEW-01 | **Resolved** | 8 | Duplicated testSocketPair in connection_pool.zig | -- | **Resolved** |

### Documentation (13 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| DOC-01 | Medium | 18 | No ownership documentation for Message.data (aliases caller's buffer) | [#198](https://gitlab.com/devnw/zig/dns/-/issues/198) | Open |
| QM-06 | **Resolved** | 24 | ~~ARCHITECTURE.md missing 60% of modules~~ | [#119](https://gitlab.com/devnw/zig/dns/-/issues/119) | **Resolved** |
| QM-NEW-04 | Low | 16 | lib.zig updated: "Minimal dependencies (optional spice for parallelism)" | Commit 6d42d51 | **Resolved** |
| QL-04 | **Resolved** | 16 | ~~No doc comment on rdata-offset invariant~~ | [#127](https://gitlab.com/devnw/zig/dns/-/issues/127) | **Resolved** |
| QL-08 | **Resolved** | 12 | ~~ARCHITECTURE.md references deleted/dead files~~ | [#184](https://gitlab.com/devnw/zig/dns/-/issues/184) | **Resolved** |
| DOC-02 | Low | 8 | connection_pool createConnection accepts/discards server/timeout_ms; misleading API | [#200](https://gitlab.com/devnw/zig/dns/-/issues/200) | Open |
| DOC-03 | Low | 8 | No module-level library user guide for downstream consumers | [#201](https://gitlab.com/devnw/zig/dns/-/issues/201) | Open |
| DG-01 | Info | -- | resolveIterative doc comment added | -- | **Resolved** |
| DG-02 | Info | -- | ResolutionState doc comments added | -- | **Resolved** |
| DG-03 | Info | -- | MXRecord ownership doc added | -- | **Resolved** |
| DG-04 | Info | -- | rdataOffset invariant public API doc added | -- | **Resolved** |
| DG-05 | Info | -- | getMinimizedQname doc comment added (RFC 9156) | -- | **Resolved** |
| DG-06 | Info | -- | Cache formatting documented (9 types supported) | -- | **Resolved** |

## Remediation Roadmap

### Quick Wins (< 1 day)

New quick wins identified in deep audit (2026-03-24):

| ID | PriorityScore | Finding | Effort | Status |
|----|---------------|---------|--------|--------|
| MEM-01 | 60 | Add `owns_servers` flag to stub.zig; free in deinit when true | S | Open |
| EH-08 | 60 | Replace `@intCast(now - then)` with saturating subtraction at 6+ sites | S | Open |
| DOC-01 | 18 | Add ownership doc comment to Message.data explaining aliasing | S | Open |
| EH-11 | 18 | Add completeness check to zdig TCP read loop | S | Open |
| DUP-02 | 24 | Extract responseMatchesQuery to shared module | S | Open |
| DOC-02 | 8 | Add doc comment to createConnection explaining lazy-connection design | S | Open |

Previously resolved or Won't Do quick wins:

| ID | PriorityScore | Finding | Effort | Status |
|----|---------------|---------|--------|--------|
| AC-02 | 36 | Fix errdefer in lookupMX to free exchange strings | S | **Resolved** |
| AC-03 | 18 | Fix errdefer in resolve() cache-hit path to free duped strings | S | **Resolved** |
| QS-NEW-05 | 18 | Propagate OOM from bare catch in stub.zig | S | **Resolved** |
| QM-NEW-01 | 24 | Remove duplicate QueryType; import types.Type | S | **Resolved** |
| QM-NEW-05 | 24 | Propagate OOM from resolveNsAddress | S | **Resolved** |
| RM-04 | 24 | Consolidate MXRecord/MxRecord into one type | S | **Resolved** |
| RE-05 | 40 | Add bounds check to rdataOffset pointer arithmetic | S | **Resolved** |
| QS-NEW-02 | 10 | Delete dead question.buildQuery function | S | **Resolved** |
| QS-NEW-03 | 12 | Document lib.zig exports as intentional public API | S | **Resolved** |
| RM-08 | 10 | Remove dead current_zone parameter from getMinimizedQname | S | **Resolved** |
| DG-01 to DG-06 | Info | Add doc comments to 6 undocumented public interfaces | S | **Resolved** |
| QS-NEW-01 | 45 | Extract responseMatchesQuery to shared module | S | **Won't Do** |
| RM-07 | 24 | Extract formatIpv4 helper to shared module | S | **Won't Do** |
| QS-NEW-04 | 30 | Add zig install directory to CI cache paths | S | **Won't Do** |
| QS-NEW-08 | 20 | Pin spice to versioned release tarball | S | **Won't Do** |

### Completed Quick Wins

| ID | PriorityScore | Finding | Status |
|----|---------------|---------|--------|
| QH-NEW-01 | 48 | convenience.zig stubs return error.NotImplemented | **Resolved** (commit 6d42d51) |
| QM-NEW-04 | 16 | lib.zig "Zero external dependencies" claim fixed | **Resolved** (commit 6d42d51) |
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

New medium-term items from deep audit (2026-03-24):

| ID | PriorityScore | Finding | Effort | Status |
|----|---------------|---------|--------|--------|
| TC-01 | 48 | Add mock transport + integration tests for resolveIterative (confirms QH-NEW-02) | L | Open |
| RD-01 | 30 | Extract LabelIterator from 7+ duplicated compression pointer check sites in name.zig | M | Open |
| CI-04 | 30 | Extract and test security-sensitive zdig functions (escapeJsonString, addressMatches) | M | Open |
| DOC-03 | 8 | Create module-level library user guide (docs/USAGE.md) | M | Open |

Previously resolved or Won't Do medium-term items:

| ID | PriorityScore | Finding | Effort | Status |
|----|---------------|---------|--------|--------|
| QM-NEW-03 | 36 | Add cache formatting for MX, SRV, TXT, NS, PTR record types | M | **Resolved** |
| QC-NEW-03 | 64 | Extract shared sendUdpQuery() from 3 files (~150 lines) | M | **Won't Do** |
| QH-NEW-02 | 48 | Add integration tests for resolveIterative (219 lines, 0 coverage) | L | **Won't Do** |
| QM-NEW-02 | 36 | Unify or rename duplicate ResolveResult types | S | **Won't Do** |
| QS-NEW-06 | 30 | Add code coverage measurement tool and CI integration | M | **Won't Do** |
| QS-NEW-07 | 12 | Rewrite client tests with mock transport | M | **Won't Do** |

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
| [#40](https://gitlab.com/devnw/zig/dns/-/issues/40) (SEC-018: Code duplication in name parsing) | QM-01, QM-07, QC-NEW-03, QS-NEW-01 | Same root cause pattern -- duplication leads to divergence; QS-NEW-01 is responseMatchesQuery variant |
| [#107](https://gitlab.com/devnw/zig/dns/-/issues/107) (SEC-C14: spice pins main) | QS-NEW-08 | Same finding from dependency security perspective; QS-NEW-08 is the quality/stability angle |
| [#109](https://gitlab.com/devnw/zig/dns/-/issues/109) (QM-03: resolveIterative) | QL-09, QH-NEW-02 | QM-03 is a subset of the broader 41-function finding; QH-NEW-02 highlights zero test coverage |
| [#161](https://gitlab.com/devnw/zig/dns/-/issues/161) (SEC-C26: Partial write in TCP framing) | QC-03 | Security perspective on the same partial write issue |
| [#170](https://gitlab.com/devnw/zig/dns/-/issues/170) (QM-07: I/O dedup) | QC-NEW-03 | QC-NEW-03 is the UDP equivalent of the TCP I/O dedup that was resolved in QM-07 |
| [#40](https://gitlab.com/devnw/zig/dns/-/issues/40) (SEC-018: Code duplication) | DUP-02, RD-01 | DUP-02 is responseMatchesQuery duplication (same as QS-NEW-01); RD-01 is compression pointer check duplication in name.zig |
| [#109](https://gitlab.com/devnw/zig/dns/-/issues/109) (QM-03: resolveIterative) | TC-01 | TC-01 confirms QH-NEW-02 (zero test coverage) via deep review; related to resolveIterative complexity |
| [#46](https://gitlab.com/devnw/zig/dns/-/issues/46) (TCP length prefix short reads) | EH-11 | EH-11 is a related TCP read completeness issue in zdig |

## Scoring Methodology

**PriorityScore = Impact(1-5) x Likelihood(1-5) x 4**

| Scale | Impact | Likelihood |
|-------|--------|------------|
| 5 | Outages / major perf cost | Ubiquitous / touched often |
| 4 | Frequent bugs / major dev drag | Often encountered |
| 3 | Moderate impact | Sometimes encountered |
| 2 | Minor impact | Rare |
| 1 | Polish | Edge-case |

### New Finding Score Breakdown (Phase 2-3)

| ID | Impact | Likelihood | PriorityScore | Rationale |
|----|--------|------------|---------------|-----------|
| QC-NEW-03 | 4 (dev drag, divergence risk) | 4 (UDP query on every resolution) | 64 | Same pattern as QM-07 (TCP I/O dedup); three copies already show minor divergence in variable naming |
| QH-NEW-01 | 4 (advertised API non-functional) | 3 (users calling convenience API) | 48 | Public API promises resolution but returns empty; misleads consumers |
| QH-NEW-02 | 4 (most complex function untested) | 3 (regressions likely during maintenance) | 48 | 219-line function with CNAME, referral, QNAME minimization logic has zero test coverage |
| QS-NEW-01 | 3 (duplication leads to divergence) | 3 (updated rarely but easy to diverge) | 45 | ~20 identical lines; any fix to query matching logic must be applied in two places |
| RE-05 | 4 (crash on invariant violation) | 2 (rare: requires rdata from non-message buffer) | 40 | Pointer subtraction underflows if rdata doesn't alias into full_message; debug assert is zero-cost in release |
| AC-02 | 3 (memory leak on error path) | 3 (any error during MX iteration) | 36 | errdefer frees ArrayList but not heap-allocated exchange strings; leak proportional to MX records parsed before error |
| QM-NEW-01 | 2 (minor confusion) | 3 (encountered when extending types) | 24 | QueryType has 10 variants; types.Type has 80+; will diverge silently |
| QM-NEW-02 | 3 (API confusion) | 3 (encountered integrating client + recursive) | 36 | Two types with same name, different shapes; callers must know which module they are in |
| QM-NEW-03 | 3 (silent data loss for non-A/AAAA) | 3 (any MX/SRV/TXT cache hit) | 36 | Cache stores all types but only formats two; cache hit for MX returns empty results array |
| QM-NEW-04 | 1 (misleading docs) | 4 (seen by every new user) | 16 | spice is declared in build.zig.zon; "Zero external dependencies" is factually incorrect |
| QM-NEW-05 | 3 (OOM becomes silent skip) | 2 (OOM during NS resolution is rare) | 24 | `catch return null` on line 688 swallows OOM; should propagate OutOfMemory |
| QS-NEW-04 | 3 (CI time/bandwidth waste) | 2 (every pipeline run) | 30 | Zig tarball is ~45MB; download+extract adds 15-30s per job; easily cacheable |
| QS-NEW-06 | 3 (no visibility into test coverage) | 2 (blocks quality improvement decisions) | 30 | Cannot measure impact of test additions; no coverage regression gate |
| QS-NEW-05 | 3 (OOM swallowed as retry/skip) | 1 (OOM in query path is rare) | 18 | Bare catch in hot path swallows all errors including fatal OOM |
| AC-03 | 3 (memory leak on error path) | 1 (error during cache-hit formatting is rare) | 18 | errdefer only frees ArrayList backing; duped formatted strings leak |
| QS-NEW-03 | 2 (dead code / API surface noise) | 1 (never encountered by consumers) | 12 | Exports pollute public API; may cause confusion when browsing lib.zig |
| QS-NEW-07 | 2 (tests provide no coverage guarantee) | 1 (only affects CI without network) | 12 | Tests pass vacuously when network unavailable; no behavioral verification |
| QS-NEW-02 | 1 (dead code) | 2 (encountered when searching for buildQuery) | 10 | Confusing: two buildQuery functions, one never called |
| RM-04 | 2 (naming confusion) | 3 (encountered when using MX APIs) | 24 | MXRecord vs MxRecord with identical fields; Zig naming convention prefers MxRecord |
| RM-07 | 2 (inline repetition) | 3 (4+ call sites, growing) | 24 | Same format string copied; any format change requires updating all sites |
| RM-08 | 1 (dead parameter) | 2 (encountered when reading minimization code) | 10 | `_ = current_zone;` on first line is a clear dead-code signal |
| QS-NEW-08 | 2 (API stability risk) | 2 (only on dependency update) | 20 | main branch tarball means any spice push can break the build |

All Phase 2-3 findings tagged `confidence::confirmed` -- verified via direct code inspection during Phase 2-3 review.

### Deep Audit Score Breakdown (2026-03-24)

| ID | Impact | Likelihood | PriorityScore | Rationale |
|----|--------|------------|---------------|-----------|
| MEM-01 | 5 (resource leak, unbounded growth) | 3 (initWithServer used in examples/tests) | 60 | Every initWithServer call leaks a heap allocation; deinit is a no-op; comment "not owned" is incorrect for this constructor |
| EH-08 | 5 (panic/outage in resolver hot path) | 3 (NTP corrections happen in production) | 60 | @intCast to u32/u64 panics on negative delta from clock regression; 6+ sites across 4 files |
| TC-01 | 4 (most complex function untested) | 3 (regressions likely during maintenance) | 48 | Deep review confirmation of QH-NEW-02; 220-line function with CNAME/referral/QNAME minimization has zero coverage |
| RD-01 | 3 (security-adjacent duplication) | 2.5 (compression handling changes rare but high-stakes) | 30 | 7+ copies of identical ~10-line compression pointer traversal; missed fix in any copy is a security gap |
| CI-04 | 3 (security-sensitive functions) | 2.5 (CLI tool, output consumed by scripts) | 30 | 1051-line file with zero tests; escapeJsonString (JSON injection) and addressMatches (ACL) untested |
| DUP-02 | 2 (divergence risk) | 3 (updated rarely but easy to diverge) | 24 | Identical ~20-line responseMatchesQuery in two files; cross-ref QS-NEW-01 |
| DOC-01 | 3 (use-after-free risk from misunderstanding) | 1.5 (experienced devs understand aliasing) | 18 | Message.data aliases caller's buffer with no lifetime documentation |
| EH-11 | 3 (silent data truncation) | 1.5 (premature close uncommon) | 18 | TCP read loop breaks on recv==0 without checking total_read==response_len |
| DOC-02 | 1 (polish, misleading internal API) | 2 (internal API, rarely encountered) | 8 | createConnection accepts server/timeout but discards both; intentional lazy-connection design |
| DOC-03 | 1 (onboarding friction) | 2 (library not yet widely distributed) | 8 | No getting-started guide for downstream consumers |

All deep audit findings tagged `confidence::confirmed` -- verified via direct code inspection and source evidence.
