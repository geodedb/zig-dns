# Quality Gap Analysis

Last updated: 2026-03-24 (Phase 2-3 consolidated)

## Summary

| Severity | Open (incl. Deferred) | Resolved/Closed | Total |
|----------|----------------------|-----------------|-------|
| Critical | 0 | 4 | 4 |
| High | 3 | 10 | 13 |
| Medium | 15 | 11 | 26 |
| Low | 6 | 8 | 14 |
| Info | 6 | 0 | 6 |
| **Total** | **30** | **33** | **63** |

### Top 10 Active Risks

1. **QC-NEW-03** (PriorityScore 64) -- sendQuery() triple duplication across stub.zig, recursive.zig, udp.zig (~150 lines copied verbatim).
2. **QH-05** (PriorityScore 64) -- Zero fuzz testing for security-critical DNS wire parsers. Deferred from Phase 2.
3. **QH-NEW-02** (PriorityScore 48) -- resolveIterative has zero direct test coverage (219 lines, most complex function in the resolver).
4. **QS-NEW-01** (PriorityScore 45) -- responseMatchesQuery duplicated in stub.zig:132 and recursive.zig:749 (~20 identical lines).
5. **RE-05** (PriorityScore 40) -- rdataOffset pointer arithmetic has no runtime safety check for aliasing invariant.
6. **QM-NEW-02** (PriorityScore 36) -- ResolveResult defined twice with incompatible shapes (client.zig vs recursive.zig).
7. **QM-NEW-03** (PriorityScore 36) -- Cache only formats A/AAAA on cache hit; silently returns empty for MX, SRV, TXT, etc.
8. **AC-02** (PriorityScore 36) -- client.lookupMX leaks exchange strings on error; errdefer only frees ArrayList backing.
9. **QM-03** (PriorityScore 36) -- resolveIterative is 219 lines with 9 levels of nesting (grew from 208 lines). Deferred.
10. **QS-NEW-04** (PriorityScore 30) -- CI downloads+installs Zig in every job; zig binary directory not cached.

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
| 8 | QC-NEW-03 | High | 64 | maintainability | sendQuery() triple duplication: ~50 lines of identical UDP socket+timeout+sendto+recvfrom logic copied verbatim in 3 files | stub.zig, recursive.zig, udp.zig | `stub.zig:198-246`, `recursive.zig:514-559`, `udp.zig:36-84` -- all create DGRAM socket, set RCVTIMEO, sendto, recvfrom loop with source validation | -- | Extract shared `sendUdpQuery()` into `transports/io.zig` (same pattern as TCP I/O dedup in QM-07) | Transport maintainer | M | Open |
| 9 | QC-NEW-01 | **Resolved** | 64 | architecture | `acquire()` returns pointer into ArrayList backing array; dangling after realloc/swapRemove | connection_pool.zig | `connection_pool.zig:251,291` | -- | Return ConnectionHandle (value type with generation-based lookup) | Transport maintainer | M | **Resolved** |
| 10 | QC-02 | Critical | 60 | architecture | ConnectionPool.acquire mutex race: defer lock/unlock dance leaves lines 278-286 unprotected | connection_pool.zig | `connection_pool.zig:247-287` | [#151](https://gitlab.com/devnw/zig/dns/-/issues/151) | Replace `defer self.mutex.lock()` with explicit `self.mutex.lock()` before mutations | Transport maintainer | S | **Resolved** |
| 11 | QC-04 | Critical | 60 | architecture | Infinite loop in PipelinedBatch.execute: `continue` targets inner while, not outer for | connection_pool.zig | `connection_pool.zig:468,490` | [#156](https://gitlab.com/devnw/zig/dns/-/issues/156) | Add `outer:` label to for loop, use `continue :outer` | Transport maintainer | S | **Resolved** |
| 12 | QC-01 | Critical | 60 | api-contract | `parseSvcbIpv4Hint`/`parseSvcbIpv6Hint` return slices to stack-local arrays (UB) | record.zig | `src/record.zig:601-630` | [#83](https://gitlab.com/devnw/zig/dns/-/issues/83) | Accept allocator parameter, return owned slice | record.zig maintainer | S | **Closed** |
| 13 | QH-06 | High | 48 | maintainability | Missing `error.InProgress` in stub.zig connectWithTimeout | stub.zig | `stub.zig:294-297` | [#160](https://gitlab.com/devnw/zig/dns/-/issues/160) | Added `error.ConnectionPending` to switch | Resolver maintainer | S | **Resolved** |
| 14 | QH-NEW-01 | High | 48 | api-contract | convenience.zig lookupA/lookupAAAA/lookup were empty stubs returning empty results | convenience.zig | `src/resolver/convenience.zig:194-226` | Commit 6d42d51 | Returns `error.NotImplemented` so callers get explicit signal | Convenience module maintainer | S | **Resolved** |
| 15 | QH-NEW-02 | High | 48 | tests | resolveIterative has zero direct test coverage; 219 lines, deepest nesting, most complex control flow in recursive resolver | recursive.zig | `src/recursive.zig:188-406` -- no test matches pattern `test.*resolveIterative` | -- | Add integration tests: CNAME following, referral handling, QNAME minimization, max-depth, NXDOMAIN | Resolver maintainer | L | Open |
| 16 | QH-03 | High | 48 | api-contract | `IPv4.format()` returns `[15]u8` with undefined trailing bytes | convenience.zig | `src/resolver/convenience.zig:34-43` | [#92](https://gitlab.com/devnw/zig/dns/-/issues/92) | Return struct with buf+len, or zero-fill buffer | Convenience module maintainer | S | **Closed** |
| 17 | QC-NEW-02 | **Resolved** | 48 | architecture | TOCTOU in connection limit: countServerConnections check races with createConnection | connection_pool.zig | `connection_pool.zig:268-296` | -- | Re-check countServerConnections after re-acquiring mutex | Transport maintainer | S | **Resolved** |
| 18 | QM-07 | **Resolved** | 48 | maintainability | ~~3x duplicate I/O helpers: connectWithTimeout, writeAllWithTimeout, readWithTimeout, readExactWithTimeout~~ | stub.zig, tcp.zig, connection_pool.zig | Extracted shared `src/transports/io.zig` | [#170](https://gitlab.com/devnw/zig/dns/-/issues/170) | Resolved: shared io.zig module with 4 tests | Transport maintainer | M | **Resolved** |
| 19 | QM-11 | Medium | 48 | perf | PooledTcpTransport.query calls connect on every query despite connection pooling | connection_pool.zig | `connection_pool.zig:537` | [#180](https://gitlab.com/devnw/zig/dns/-/issues/180) | Track connected state in PooledConnection or connect in acquire() | Transport maintainer | S | **Resolved** |
| 20 | QS-NEW-01 | Medium | 45 | maintainability | responseMatchesQuery duplicated in stub.zig:132 and recursive.zig:749 -- ~20 identical lines of query/response validation logic | stub.zig, recursive.zig | `src/stub.zig:132-151` and `src/recursive.zig:749-768` -- identical function body: checks qr, opcode, qdcount, then does zero-alloc Name.encodeBuf + eql comparison | -- | Extract to shared module (e.g. `src/query_match.zig` or add to `src/message.zig`) and import from both files | Resolver maintainer | S | Open |
| 21 | RE-05 | Medium | 40 | architecture | rdataOffset pointer arithmetic has no runtime safety check; relies on aliasing invariant that `self.rdata.ptr` points into `full_message` | record.zig | `src/record.zig:77-79` -- `@intFromPtr(self.rdata.ptr) - @intFromPtr(full_message.ptr)` will underflow if invariant is violated, producing an invalid offset | -- | Add `std.debug.assert(rdata_start >= msg_start and rdata_start <= msg_start + full_message.len)` or return error on violation | record.zig maintainer | S | Open |
| 22 | QM-NEW-02 | Medium | 36 | architecture | ResolveResult defined twice with incompatible shapes: client.zig has `addresses: []const []const u8` + `from_cache: bool`; recursive.zig has `status: ResolveStatus` + `answer: ?[]u8` + `from_cache: bool` | client.zig, recursive.zig | `src/client.zig:318-332`, `src/recursive.zig:835-844` | -- | Unify into single type or rename to avoid confusion; client could wrap recursive result | Resolver maintainer | S | Open |
| 23 | QM-NEW-03 | Medium | 36 | api-contract | Cache hit path in Client.resolve only formats A and AAAA records; MX, SRV, TXT, NS, PTR cache hits silently return empty results | client.zig | `src/client.zig:150-167` -- `if (qtype == .a ...) else if (qtype == .aaaa ...)` with no else branch; other record types skip formatting | -- | Add formatting branches for MX, SRV, TXT, NS, PTR or return raw rdata with type tag | Client maintainer | M | Open |
| 24 | AC-02 | Medium | 36 | architecture | client.lookupMX leaks exchange strings on error -- errdefer only calls `results.deinit()` which frees the ArrayList backing memory but not the `.exchange` strings already duped into items | client.zig | `src/client.zig:288` -- `errdefer results.deinit(self.allocator)` does not free `exchange` allocations from lines 297-301; if `results.append` or later `ans_iter.next()` fails, all previously-duped exchange strings leak | -- | Add `errdefer { for (results.items) |mx| self.allocator.free(mx.exchange); results.deinit(self.allocator); }` | Client maintainer | S | Open |
| 25 | QM-03 | Medium | 36 | readability | `resolveIterative` is 219 lines with 9 levels of nesting (was 171 at QM-03 filing, 208 at Phase 2, now 219) | recursive.zig | `src/recursive.zig:188-406` | [#109](https://gitlab.com/devnw/zig/dns/-/issues/109) | Extract `handleCnameChain()`, `handleReferral()`, `handleNodataResponse()` | Resolver maintainer | M | **Deferred** |
| 26 | QS-NEW-04 | Medium | 30 | ci-cd | CI downloads+installs Zig in every job; binary directory not cached. CI caches `.zig-cache/` but the `zig-${ZIG_VERSION}/` install directory is re-downloaded and extracted every pipeline run | .gitlab-ci.yml | `.gitlab-ci.yml:25-28` -- `cache: paths: [.zig-cache/]` does not include `zig-${ZIG_VERSION}/`; lines 43-76 check `if [ ! -f "zig-${ZIG_VERSION}/zig" ]` but directory is never persisted | -- | Add `zig-${ZIG_VERSION}/` to cache paths list | CI/CD maintainer | S | Open |
| 27 | QS-NEW-06 | Medium | 30 | ci-cd | No code coverage measurement tool or CI integration; no coverage gates in pipeline | .gitlab-ci.yml, build.zig | No `--coverage` flag usage, no kcov/lcov integration, no coverage report artifacts | -- | Add `zig build test -Dcoverage` or kcov wrapper; publish coverage report as CI artifact; add coverage threshold gate | CI/CD maintainer | M | Open |
| 28 | RM-04 | Medium | 24 | maintainability | Duplicate MXRecord/MxRecord types: `client.zig:337` defines `MXRecord` (uppercase X) and `convenience.zig:87` defines `MxRecord` (lowercase x) with identical shape `{ preference: u16, exchange: []const u8 }` | client.zig, convenience.zig | `src/client.zig:337` -- `pub const MXRecord`, `src/resolver/convenience.zig:87` -- `pub const MxRecord`; both have identical fields | -- | Consolidate into one type (prefer `MxRecord` per Zig naming conventions) in a shared location; alias in both modules | Resolver maintainer | S | Open |
| 29 | RM-07 | Medium | 24 | maintainability | IPv4 formatting pattern `"{d}.{d}.{d}.{d}"` repeated inline in 4+ places across record.zig, recursive.zig, client.zig, convenience.zig | record.zig, recursive.zig, client.zig, convenience.zig | `src/record.zig:263`, `src/recursive.zig:638,711`, `src/client.zig:154`, `src/resolver/convenience.zig:46,261` | -- | Extract `formatIpv4(rdata: [4]u8, buf: *[15]u8) []const u8` helper to shared module; import everywhere | Any contributor | S | Open |
| 30 | QM-NEW-01 | Medium | 24 | maintainability | Duplicate QueryType enum in convenience.zig (A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT, ANY) mirrors types.Type; will diverge as types.Type is extended | convenience.zig, types.zig | `src/resolver/convenience.zig:17-28` vs `src/types.zig:14+` (types.Type has 80+ variants) | -- | Remove QueryType; import and use types.Type directly | Convenience module maintainer | S | Open |
| 31 | QM-NEW-05 | Medium | 24 | architecture | resolveNsAddress catches all errors (including OOM) as null via `catch return null`; OOM during child resolveIterative silently skips NS instead of propagating | recursive.zig | `src/recursive.zig:688` -- `self.resolveIterative(&child_state) catch return null` | -- | Catch and propagate `error.OutOfMemory`; return null only for resolution failures | Resolver maintainer | S | Open |
| 32 | QS-NEW-08 | Medium | 20 | deps | Spice dependency pinned to main branch tarball; no semver tag. Any main branch push changes the API surface without warning | build.zig.zon | `build.zig.zon:29` -- `.url = "https://gitlab.com/devnw/zig/spice/-/archive/main/spice-main.tar.gz"`. Hash provides integrity but not stability | -- | Tag a spice release (e.g. v0.1.0) and pin to versioned tarball URL | Project maintainer | S | Open |
| 33 | QS-NEW-05 | Medium | 18 | architecture | stub.zig:170 and happy_eyeballs.zig:161 swallow OOM errors via bare `catch`; OOM during sendQuery/startConnection silently retries or skips | stub.zig, happy_eyeballs.zig | `src/stub.zig:170` -- `self.sendQuery(query, server) catch { continue; }` swallows all errors including OOM; `src/transports/happy_eyeballs.zig:161` -- `self.startConnection(addr) catch { next_attempt_index += 1; continue; }` | -- | Use `catch |err| switch (err) { error.OutOfMemory => return err, else => continue }` pattern to propagate fatal errors | Resolver maintainer | S | Open |
| 34 | AC-03 | Medium | 18 | architecture | Cache-hit errdefer in resolve() does not free duped strings on error; `errdefer results.deinit(self.allocator)` at line 147 frees ArrayList backing but not the `dupe(u8, formatted)` strings already appended | client.zig | `src/client.zig:147` -- `errdefer results.deinit(self.allocator)` vs line 157/166 `try results.append(..., try self.allocator.dupe(u8, formatted))` | -- | Add `errdefer { for (results.items) |s| self.allocator.free(s); results.deinit(self.allocator); }` | Client maintainer | S | Open |
| 35 | QL-03 | Low | 16 | readability | 12 source files exceed 800-line threshold (was 9). New: `connection_pool.zig` (1070), `parallel.zig` (881), `enhanced_metrics.zig` (879). Largest: `record.zig` (1927) | Multiple files | `record.zig:1927`, `recursive.zig:1426`, `name.zig:1345`, `connection_pool.zig:1070`, `edns.zig:973`, `tsig.zig:916`, `zone_transfer.zig:894`, `dnssec.zig:889`, `parallel.zig:881`, `enhanced_metrics.zig:879`, `zone_file.zig:863`, `sig0.zig:814` | [#126](https://gitlab.com/devnw/zig/dns/-/issues/126) | Split large files by responsibility domain | Project maintainer | L | **Deferred** |
| 36 | QL-09 | Low | 16 | readability | 41 functions exceed 50-line threshold (was 30); resolveIterative at 219 lines | Multiple files | `recursive.zig:188+` (219 lines), record.zig, edns.zig, zone_transfer.zig parsers | [#185](https://gitlab.com/devnw/zig/dns/-/issues/185) | Decompose long functions; add lint gate | Project maintainer | L | Open |
| 37 | QS-NEW-03 | Low | 12 | cleanup | 4 lib.zig module exports never imported by any consumer: `convenience`, `rpz`, `config`, `cache_prefetch` | lib.zig | `src/lib.zig:99` -- `pub const rpz`, `src/lib.zig:101` -- `pub const config`, `src/lib.zig:102` -- `pub const convenience`, `src/lib.zig:103` -- `pub const cache_prefetch` | -- | Verify if these are intended public API or dead exports; remove if unused, add tests/examples if intended | Any contributor | S | Open |
| 38 | QS-NEW-07 | Low | 12 | tests | Client tests bail on network failure (catch-return), never verify behavior; test at client.zig:458 `catch { return; }` skips all assertions if network is unavailable | client.zig | `src/client.zig:458-469` -- `Client.initWithConfig(...) catch { return; }` -- test passes vacuously in CI without network | -- | Use mock resolver/transport backend so tests verify behavior regardless of network availability | Client maintainer | M | Open |
| 39 | QS-NEW-02 | Low | 10 | cleanup | question.buildQuery at question.zig:102 is dead code -- all callers use message.buildQuery instead | question.zig | `src/question.zig:102` -- `pub fn buildQuery(...)` has zero call sites (verified: no matches for `question.buildQuery` in src/); all callers use `src/message.zig:282` `pub fn buildQuery(...)` | -- | Delete `question.buildQuery` or deprecate with `@compileLog` warning | Any contributor | S | Open |
| 40 | RM-08 | Low | 10 | cleanup | getMinimizedQname ignores `current_zone` parameter (dead parameter) | recursive.zig | `src/recursive.zig:413-414` -- `fn getMinimizedQname(self: *Self, original: []const u8, current_zone: []const u8, depth: usize)` immediately does `_ = current_zone;` | -- | Remove `current_zone` parameter; update all call sites | Resolver maintainer | S | Open |
| 41 | QM-NEW-04 | Low | 16 | docs | lib.zig claimed "Zero external dependencies" but build.zig.zon declares `spice` dependency | lib.zig | `src/lib.zig:16` -- updated to `//! - Minimal dependencies (optional spice for parallelism)` | Commit 6d42d51 | Updated doc comment to accurately reflect spice dependency | Documentation maintainer | S | **Resolved** |
| 42 | QL-NEW-01 | **Resolved** | 8 | cleanup | Duplicated testSocketPair helper identical to io.zig:118-126 | connection_pool.zig | `connection_pool.zig:665-673` | -- | Make io.zig testSocketPair public; replace duplicate with const alias | Any contributor | S | **Resolved** |
| 43 | QM-05 | **Resolved** | 36 | maintainability | ~~Silent error swallowing with `catch {}` in 5+ locations~~ | Multiple files | All catch {} sites documented or upgraded | [#117](https://gitlab.com/devnw/zig/dns/-/issues/117) | Resolved | Any contributor | S | **Resolved** |
| 44 | QM-01 | **Resolved** | 36 | maintainability | ~~`parseName()` copy-pasted ~52 identical lines in tsig.zig and sig0.zig~~ | tsig.zig, sig0.zig | Extracted shared `src/security/dns_name.zig` | [#102](https://gitlab.com/devnw/zig/dns/-/issues/102) | Resolved | Security module maintainer | S | **Resolved** |
| 45 | QM-09 | **Resolved** | 36 | architecture | ~~parallel.zig: 4 placeholder implementations return fabricated results~~ | parallel.zig | Real wire-format parsing; honest error status | [#177](https://gitlab.com/devnw/zig/dns/-/issues/177) | Resolved | Parallel module maintainer | M | **Resolved** |
| 46 | QL-07 | **Resolved** | 32 | ci-cd | ~~No `zig fmt --check` in CI pipeline~~ | .gitlab-ci.yml | zig-format job override now includes explicit script | [#183](https://gitlab.com/devnw/zig/dns/-/issues/183) | Resolved | CI/CD maintainer | S | **Resolved** |
| 47 | QM-08 | **Resolved** | 24 | cleanup | ~~Dead file `src/resolver/stub.zig`~~ | resolver/stub.zig (deleted) | File deleted | [#173](https://gitlab.com/devnw/zig/dns/-/issues/173) | Resolved | Any contributor | S | **Resolved** |
| 48 | QM-10 | **Resolved** | 24 | cleanup | ~~Duplicate SOA parsing: extractSerial duplicates parseSoaRdata~~ | zone_transfer.zig | `extractSerial` now delegates to `parseSoaRdata` | [#179](https://gitlab.com/devnw/zig/dns/-/issues/179) | Resolved | Resolver maintainer | S | **Resolved** |
| 49 | QM-02 | **Resolved** | 24 | maintainability | ~~Duplicated root server definitions~~ | recursive.zig | Deleted `src/resolver/recursive.zig` | [#106](https://gitlab.com/devnw/zig/dns/-/issues/106) | Resolved | Resolver maintainer | S | **Resolved** |
| 50 | QM-04 | **Resolved** | 24 | architecture | ~~18 modules lack API boundary docs~~ | build.zig | Added API boundary comments | [#113](https://gitlab.com/devnw/zig/dns/-/issues/113) | Resolved | Project maintainer | S | **Resolved** |
| 51 | QM-06 | **Resolved** | 24 | docs | ~~ARCHITECTURE.md missing 60% of modules~~ | docs/ARCHITECTURE.md | Rewritten with all modules documented | [#119](https://gitlab.com/devnw/zig/dns/-/issues/119) | Resolved | Documentation lead | M | **Resolved** |
| 52 | QL-04 | **Resolved** | 16 | docs | ~~No doc comment on rdata-offset invariant~~ | record.zig | Doc comments added | [#127](https://gitlab.com/devnw/zig/dns/-/issues/127) | Resolved | Any contributor | S | **Resolved** |
| 53 | QL-05 | **Resolved** | 16 | tests | ~~Mutable statics in MockTlsBackend~~ | dot.zig | Moved to per-instance state | [#181](https://gitlab.com/devnw/zig/dns/-/issues/181) | Resolved | Any contributor | S | **Resolved** |
| 54 | QL-06 | **Resolved** | 12 | readability | ~~Magic number 6 for SOA record type~~ | zone_transfer.zig | Replaced with `soa_rtype` named constant | [#182](https://gitlab.com/devnw/zig/dns/-/issues/182) | Resolved | Any contributor | S | **Resolved** |
| 55 | QL-08 | **Resolved** | 12 | docs | ~~ARCHITECTURE.md references deleted/dead files~~ | docs/ARCHITECTURE.md | Stale references removed | [#184](https://gitlab.com/devnw/zig/dns/-/issues/184) | Resolved | Documentation maintainer | S | **Resolved** |
| 56 | QL-01 | **Resolved** | 12 | cleanup | ~~7 identical @intFromPtr blocks~~ | record.zig | Extracted rdataOffset() helper | [#121](https://gitlab.com/devnw/zig/dns/-/issues/121) | Resolved | Any contributor | S | **Resolved** |
| 57 | QL-02 | Low | 8 | cleanup | `verifyCase0x20()` reimplements `std.mem.eql` | name.zig | `src/name.zig:451-462` | [#123](https://gitlab.com/devnw/zig/dns/-/issues/123) | Replace with std.mem.eql | Any contributor | S | **Resolved** |
| -- | DG-01 | Info | -- | docs | resolveIterative (219 lines) has no function-level doc comment explaining algorithm, parameters, or return semantics | recursive.zig | `src/recursive.zig:188` -- `fn resolveIterative(self: *Self, state: *ResolutionState)` with no `///` comment | -- | Add doc comment describing iterative resolution algorithm, state machine transitions, and error semantics | Resolver maintainer | S | Open |
| -- | DG-02 | Info | -- | docs | ResolutionState struct has no doc comment explaining field semantics or lifecycle | recursive.zig | `src/recursive.zig:174` (approx) -- `ResolutionState` fields undocumented | -- | Add `///` doc comments to ResolutionState and each field | Resolver maintainer | S | Open |
| -- | DG-03 | Info | -- | docs | MXRecord ownership semantics undocumented -- caller must free `.exchange` strings | client.zig | `src/client.zig:337` -- `pub const MXRecord` has no ownership doc comment; `lookupMX` returns `[]MXRecord` with heap-allocated `.exchange` fields | -- | Add `/// Caller owns the returned slice and each `.exchange` string. Free with allocator.` | Client maintainer | S | Open |
| -- | DG-04 | Info | -- | docs | rdataOffset invariant only documented in code comment, not in public API doc | record.zig | `src/record.zig:74-76` -- invariant is in a comment block above the private fn, but ResourceRecord's public parse/rdata API does not mention the aliasing requirement | -- | Add `///` doc to ResourceRecord explaining that rdata slices alias into the original message buffer | record.zig maintainer | S | Open |
| -- | DG-05 | Info | -- | docs | getMinimizedQname has no doc comment explaining QNAME minimization (RFC 9156) algorithm | recursive.zig | `src/recursive.zig:413` -- `fn getMinimizedQname(...)` with no `///` comment | -- | Add doc comment referencing RFC 9156 and explaining the depth-based label minimization strategy | Resolver maintainer | S | Open |
| -- | DG-06 | Info | -- | docs | Cache formatting logic in resolve() has no comment explaining which types are supported and why others are skipped | client.zig | `src/client.zig:150-167` -- A/AAAA branches with no comment about missing types | -- | Add comment explaining the limitation (related to QM-NEW-03) or add TODO referencing QM-NEW-03 | Client maintainer | S | Open |

## Findings by Category

### Architecture (17 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QC-03 | Critical | 80 | Partial write data loss (3 files, 6 sites) | [#152](https://gitlab.com/devnw/zig/dns/-/issues/152) | **Resolved** |
| QH-02 | High | 80 | Referral NS servers never assigned | [#91](https://gitlab.com/devnw/zig/dns/-/issues/91) | **Resolved** |
| QH-07 | High | 64 | Blocking reads without timeout in PipelinedBatch | [#163](https://gitlab.com/devnw/zig/dns/-/issues/163) | **Resolved** |
| QH-08 | High | 64 | Zone transfer short read on length prefix | [#166](https://gitlab.com/devnw/zig/dns/-/issues/166) | **Resolved** |
| QH-01 | High | 64 | CNAME continue targets wrong loop | [#86](https://gitlab.com/devnw/zig/dns/-/issues/86) | **Resolved** |
| QC-02 | Critical | 60 | ConnectionPool.acquire mutex race | [#151](https://gitlab.com/devnw/zig/dns/-/issues/151) | **Resolved** |
| QC-04 | Critical | 60 | PipelinedBatch.execute infinite loop | [#156](https://gitlab.com/devnw/zig/dns/-/issues/156) | **Resolved** |
| RE-05 | Medium | 40 | rdataOffset pointer arithmetic has no runtime safety check | -- | Open |
| QM-09 | **Resolved** | 36 | parallel.zig placeholder implementations | [#177](https://gitlab.com/devnw/zig/dns/-/issues/177) | **Resolved** |
| AC-02 | Medium | 36 | client.lookupMX leaks exchange strings on error | -- | Open |
| QM-04 | **Resolved** | 24 | 18 modules lack API boundary docs | [#113](https://gitlab.com/devnw/zig/dns/-/issues/113) | **Resolved** |
| QC-NEW-01 | **Resolved** | 64 | acquire() returns dangling pointer into ArrayList | -- | **Resolved** |
| QC-NEW-02 | **Resolved** | 48 | TOCTOU in connection limit check | -- | **Resolved** |
| QM-NEW-02 | Medium | 36 | ResolveResult defined twice with incompatible shapes | -- | Open |
| QM-NEW-05 | Medium | 24 | resolveNsAddress swallows all errors (including OOM) as null | -- | Open |
| AC-03 | Medium | 18 | Cache-hit errdefer in resolve() leaks duped strings | -- | Open |
| QS-NEW-05 | Medium | 18 | stub.zig and happy_eyeballs.zig swallow OOM via bare catch | -- | Open |

### API Contract (4 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QC-01 | Critical | 60 | SVCB hint parsers return dangling pointers | [#83](https://gitlab.com/devnw/zig/dns/-/issues/83) | **Closed** |
| QH-NEW-01 | High | 48 | convenience.zig lookupA/lookupAAAA/lookup now return error.NotImplemented | Commit 6d42d51 | **Resolved** |
| QH-03 | High | 48 | IPv4.format() undefined trailing bytes | [#92](https://gitlab.com/devnw/zig/dns/-/issues/92) | **Closed** |
| QM-NEW-03 | Medium | 36 | Cache only formats A/AAAA on cache hit; other types silently empty | -- | Open |

### Performance (2 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QH-04 | High | 64 | Name.eql() mmap syscalls | [#95](https://gitlab.com/devnw/zig/dns/-/issues/95) | **Resolved** |
| QM-11 | Medium | 48 | PooledTcpTransport.query unnecessary connect per query | [#180](https://gitlab.com/devnw/zig/dns/-/issues/180) | **Resolved** |

### Maintainability (10 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QC-NEW-03 | High | 64 | sendQuery() triple duplication (~150 lines across stub.zig, recursive.zig, udp.zig) | -- | Open |
| QH-06 | High | 48 | Missing error.InProgress in stub.zig | [#160](https://gitlab.com/devnw/zig/dns/-/issues/160) | **Resolved** |
| QS-NEW-01 | Medium | 45 | responseMatchesQuery duplicated in stub.zig and recursive.zig (~20 lines) | -- | Open |
| QM-07 | **Resolved** | 48 | ~~3x duplicate I/O helpers (~240 lines)~~ Extracted shared `src/transports/io.zig` | [#170](https://gitlab.com/devnw/zig/dns/-/issues/170) | **Resolved** |
| QM-01 | **Resolved** | 36 | ~~parseName() duplicated in tsig/sig0~~ | [#102](https://gitlab.com/devnw/zig/dns/-/issues/102) | **Resolved** |
| QM-05 | **Resolved** | 36 | ~~Silent error swallowing (catch {})~~ | [#117](https://gitlab.com/devnw/zig/dns/-/issues/117) | **Resolved** |
| RM-04 | Medium | 24 | Duplicate MXRecord/MxRecord types in client.zig vs convenience.zig | -- | Open |
| RM-07 | Medium | 24 | IPv4 formatting pattern repeated inline in 4+ places | -- | Open |
| QM-NEW-01 | Medium | 24 | Duplicate QueryType enum in convenience.zig mirrors types.Type | -- | Open |
| QM-02 | **Resolved** | 24 | ~~Duplicated root server definitions~~ | [#106](https://gitlab.com/devnw/zig/dns/-/issues/106) | **Resolved** |

### Tests (4 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QH-05 | High | 64 | Zero fuzz testing for wire parsers | [#98](https://gitlab.com/devnw/zig/dns/-/issues/98) | **Deferred** |
| QH-NEW-02 | High | 48 | resolveIterative (219 lines) has zero direct test coverage | -- | Open |
| QS-NEW-07 | Low | 12 | Client tests bail on network failure, never verify behavior | -- | Open |
| QL-05 | **Resolved** | 16 | Mutable statics in MockTlsBackend | [#181](https://gitlab.com/devnw/zig/dns/-/issues/181) | **Resolved** |

### Readability (5 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QM-03 | Medium | 36 | resolveIterative 219 lines / 9 nesting levels (was 208) | [#109](https://gitlab.com/devnw/zig/dns/-/issues/109) | **Deferred** |
| QL-07 | **Resolved** | 32 | ~~No zig fmt check in CI~~ | [#183](https://gitlab.com/devnw/zig/dns/-/issues/183) | **Resolved** |
| QL-03 | Low | 16 | 12 files over 800 lines (was 9) | [#126](https://gitlab.com/devnw/zig/dns/-/issues/126) | **Deferred** |
| QL-09 | Low | 16 | 41 functions exceed 50 lines (was 30) | [#185](https://gitlab.com/devnw/zig/dns/-/issues/185) | Open |
| QL-06 | **Resolved** | 12 | ~~Magic number 6 for SOA~~ | [#182](https://gitlab.com/devnw/zig/dns/-/issues/182) | **Resolved** |

### CI/CD (2 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QS-NEW-04 | Medium | 30 | CI Zig install not cached; re-downloaded every pipeline | -- | Open |
| QS-NEW-06 | Medium | 30 | No code coverage measurement or CI integration | -- | Open |

### Dependencies (1 finding)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QS-NEW-08 | Medium | 20 | Spice dependency pinned to main branch tarball | -- | Open |

### Cleanup (8 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QM-08 | **Resolved** | 24 | ~~Dead file src/resolver/stub.zig~~ | [#173](https://gitlab.com/devnw/zig/dns/-/issues/173) | **Resolved** |
| QM-10 | **Resolved** | 24 | ~~Duplicate SOA parsing in zone_transfer.zig~~ | [#179](https://gitlab.com/devnw/zig/dns/-/issues/179) | **Resolved** |
| QS-NEW-03 | Low | 12 | 4 lib.zig module exports never imported | -- | Open |
| QS-NEW-02 | Low | 10 | question.buildQuery is dead code | -- | Open |
| RM-08 | Low | 10 | getMinimizedQname ignores current_zone parameter | -- | Open |
| QL-01 | **Resolved** | 12 | ~~7 identical @intFromPtr blocks~~ | [#121](https://gitlab.com/devnw/zig/dns/-/issues/121) | **Resolved** |
| QL-02 | Low | 8 | verifyCase0x20 reimplements std.mem.eql | [#123](https://gitlab.com/devnw/zig/dns/-/issues/123) | **Resolved** |
| QL-NEW-01 | **Resolved** | 8 | Duplicated testSocketPair in connection_pool.zig | -- | **Resolved** |

### Documentation (10 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QM-06 | **Resolved** | 24 | ~~ARCHITECTURE.md missing 60% of modules~~ | [#119](https://gitlab.com/devnw/zig/dns/-/issues/119) | **Resolved** |
| QM-NEW-04 | Low | 16 | lib.zig updated: "Minimal dependencies (optional spice for parallelism)" | Commit 6d42d51 | **Resolved** |
| QL-04 | **Resolved** | 16 | ~~No doc comment on rdata-offset invariant~~ | [#127](https://gitlab.com/devnw/zig/dns/-/issues/127) | **Resolved** |
| QL-08 | **Resolved** | 12 | ~~ARCHITECTURE.md references deleted/dead files~~ | [#184](https://gitlab.com/devnw/zig/dns/-/issues/184) | **Resolved** |
| DG-01 | Info | -- | resolveIterative has no doc comment | -- | Open |
| DG-02 | Info | -- | ResolutionState struct undocumented | -- | Open |
| DG-03 | Info | -- | MXRecord ownership semantics undocumented | -- | Open |
| DG-04 | Info | -- | rdataOffset invariant not in public API doc | -- | Open |
| DG-05 | Info | -- | getMinimizedQname has no doc comment (RFC 9156) | -- | Open |
| DG-06 | Info | -- | Cache formatting type support not documented | -- | Open |

## Remediation Roadmap

### Quick Wins (< 1 day)

| ID | PriorityScore | Finding | Effort | Status |
|----|---------------|---------|--------|--------|
| QS-NEW-01 | 45 | Extract responseMatchesQuery to shared module | S | Open |
| AC-02 | 36 | Fix errdefer in lookupMX to free exchange strings | S | Open |
| AC-03 | 18 | Fix errdefer in resolve() cache-hit path to free duped strings | S | Open |
| QS-NEW-05 | 18 | Propagate OOM from bare catch in stub.zig and happy_eyeballs.zig | S | Open |
| QM-NEW-01 | 24 | Remove duplicate QueryType; import types.Type | S | Open |
| QM-NEW-05 | 24 | Propagate OOM from resolveNsAddress instead of swallowing | S | Open |
| RM-04 | 24 | Consolidate MXRecord/MxRecord into one type | S | Open |
| RM-07 | 24 | Extract formatIpv4 helper to shared module | S | Open |
| QS-NEW-04 | 30 | Add zig install directory to CI cache paths | S | Open |
| QS-NEW-08 | 20 | Pin spice to versioned release tarball | S | Open |
| RE-05 | 40 | Add debug assert to rdataOffset pointer arithmetic | S | Open |
| QS-NEW-02 | 10 | Delete dead question.buildQuery function | S | Open |
| QS-NEW-03 | 12 | Audit/remove 4 unused lib.zig module exports | S | Open |
| RM-08 | 10 | Remove dead current_zone parameter from getMinimizedQname | S | Open |
| DG-01 to DG-06 | Info | Add doc comments to 6 undocumented public interfaces | S | Open |

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

| ID | PriorityScore | Finding | Effort | Status |
|----|---------------|---------|--------|--------|
| QC-NEW-03 | 64 | Extract shared sendUdpQuery() from 3 files (~150 lines) | M | Open |
| QH-NEW-02 | 48 | Add integration tests for resolveIterative (219 lines, 0 coverage) | L | Open |
| QM-NEW-02 | 36 | Unify or rename duplicate ResolveResult types | S | Open |
| QM-NEW-03 | 36 | Add cache formatting for MX, SRV, TXT, NS, PTR record types | M | Open |
| QS-NEW-06 | 30 | Add code coverage measurement tool and CI integration | M | Open |
| QS-NEW-07 | 12 | Rewrite client tests with mock transport to avoid network dependency | M | Open |

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

All new findings tagged `confidence::confirmed` -- verified via direct code inspection during Phase 2-3 review.
