# Gap Closure (2026-06-12 Audit) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close all 48 actionable gaps (GAP-0839..GAP-0890) from the 2026-06-12 audit with TDD, one commit per gap.

**Architecture:** Zig 0.16 DNS library. Fixes are grouped into 12 dependency-ordered batches: critical memory-safety first, shared-infrastructure consolidation second, then DNSSEC chain, zone-transfer/SIG(0), failover, split-DNS/RPZ, zdig CLI, misc correctness, zone-file, CI/bench, docs, and perf. Canonical tracking: `docs/GAP_ANALYSIS.md` (issue numbers per gap are listed there).

**Tech Stack:** Zig 0.16.0 only (stdlib; no new deps). Tests are inline `test` blocks per Zig convention; run via `zig build test --summary all` (baseline: 543/544 pass, 1 skip).

**Universal task protocol (applies to every task; the steps below are abbreviated to Test→Fail→Fix→Pass→Commit):**

1. Read the target file region first.
2. Write the failing test exactly where sibling tests live (bottom of the module unless noted).
3. `zig build test --summary all` → confirm the new test FAILS (or crashes) for the stated reason.
4. Implement the minimal fix.
5. `zig build test --summary all` → 543+N/544+N pass; `zig fmt --check src/ cmd/ build.zig` clean; `zig build` clean.
6. `git add -A && git commit -m "fix: close GAP-XXXX - <short title>"` (docs-only: `docs:`; won't-do: `chore:`).

---

## BATCH 1 — Critical memory safety

### Task 1: GAP-0867 — LruCache use-after-free on hashmap rehash (issue #304)

**Files:** Modify: `src/util/lru.zig` (struct def ~line 14, `put` 120-132, `moveToFront`/`evictLru`/`removeByHandle` 173-219, tests 223-318). Callers: `src/resolver/dns_cache.zig:101-107` (verify API unchanged).

- [ ] **Step 1: Write the failing stress test** in `src/util/lru.zig` tests section:

```zig
test "LRU survives hashmap growth (rehash pointer stability)" {
    const allocator = std.testing.allocator;
    var cache = try LruCache(usize).init(allocator, 2000);
    defer cache.deinit();
    var buf: [32]u8 = undefined;
    var i: usize = 0;
    while (i < 5000) : (i += 1) {
        const key = try std.fmt.bufPrint(&buf, "key-{d}", .{i});
        try cache.put(key, i);
        // interleaved gets touch the linked list across rehash boundaries
        if (i > 10) {
            const old = try std.fmt.bufPrint(&buf, "key-{d}", .{i - 10});
            _ = cache.get(old);
        }
    }
    // walk the list; length must equal count and order must be coherent
    var walked: usize = 0;
    var node = cache.head;
    while (node) |n| : (node = n.next) walked += 1;
    try std.testing.expectEqual(cache.count, walked);
}
```

(Adapt field/API names to the actual struct after reading the file.)

- [ ] **Step 2: Run; expect SIGSEGV/failure** (confirmed repro crashed at `lru.zig:130 head.prev = node` within ~1000 inserts).
- [ ] **Step 3: Fix — stable node storage.** Change `map: std.StringHashMap(Node)` to `map: std.StringHashMap(*Node)`; allocate each node with `allocator.create(Node)` on insert; `allocator.destroy(node)` on evict/remove/deinit (free after `on_evict` callback and after key free, matching current ownership order). All `getPtr` uses become plain `get` (value is already the pointer). Keep `key` ownership semantics identical (the duped key remains the map key and `node.key`).
- [ ] **Step 4: Run full suite; stress test passes; no leaks under `std.testing.allocator`.** Also run existing dns_cache tests.
- [ ] **Step 5: Commit** `fix: close GAP-0867 - LRU use-after-free on hashmap rehash (stable heap nodes)`.

### Task 2: GAP-0875 — zdig sendUdp double-free (issue #305)

**Files:** Modify: `cmd/zdig.zig:573-589`.

- [ ] **Step 1:** Read the function. The bug: `errdefer allocator.free(response_buf)` at ~574 PLUS explicit `allocator.free(response_buf)` before `return err` at ~581 and ~587.
- [ ] **Step 2: Test.** `cmd/zdig.zig` has no test infra for sockets; add a focused unit test only if a seam exists — otherwise rely on the structural fix + a new test that exercises the error path via an unroutable/refused server if cheap. Minimum bar: `zig build` + manual reasoning documented in commit body. Prefer extracting the free logic so the double-free is structurally impossible.
- [ ] **Step 3: Fix:** delete the two explicit `allocator.free(response_buf)` calls; rely solely on the `errdefer`:

```zig
const recv_len = net_compat.recvfrom(...) catch |err| return err; // errdefer frees
if (!addressMatches(&address.any, &source_addr)) return error.SourceAddressMismatch; // errdefer frees
```

- [ ] **Step 4: Verify** build+tests+fmt.
- [ ] **Step 5: Commit** `fix: close GAP-0875 - zdig sendUdp double-free on error paths`.

---

## BATCH 2 — Shared infrastructure consolidation

### Task 3: GAP-0878 — Consolidate the Zig-0.16 Mutex shim (issue #320)

**Files:** Modify: `src/util/clock.zig` sibling new file Create: `src/util/sync.zig`; Modify: `src/resolver/failover.zig:23-32`, `src/parallel.zig:68`, `src/transports/connection_pool.zig:27`, `build.zig` (wire `sync` module into the same module graph as `util/clock.zig` — follow how `clock.zig` or `random.zig` is wired).

- [ ] **Step 1:** Read the three copies; they are identical (`std.Io.Mutex` + `lockUncancelable`/`unlock` wrapper).
- [ ] **Step 2: Create `src/util/sync.zig`** containing the single shim (verbatim from one copy, with a doc comment) plus a trivial test (`lock`/`unlock` does not deadlock).
- [ ] **Step 3:** Replace the three inline copies with imports. Match each file's existing import style (`@import("util/sync.zig")` or module import per build graph — check how those files import other util modules).
- [ ] **Step 4:** Full suite passes (543/544 + new).
- [ ] **Step 5: Commit** `refactor: close GAP-0878 - single shared Mutex shim in util/sync.zig`.

### Task 4: GAP-0877 — Route all time reads through util/clock.zig (issue #319)

**Files:** Modify: `src/util/clock.zig` (ensure it exports `milliTimestamp()`/`timestamp()`; fix its stale comment claiming `std.time.milliTimestamp` was "removed in 0.16.0" — it was not); Modify 16 modules with inline shims: `src/resolver/failover.zig:17`, `src/recursive.zig:29`, `src/stub.zig:26`, `src/transports/io.zig:13`, `src/transports/udp.zig:13`, `src/transports/connection_pool.zig:21`, `src/resolver/logging.zig:15`, `src/resolver/config.zig:15`, `src/util/enhanced_metrics.zig:16`, `src/cache.zig:14`, `src/parallel.zig:63`, `src/resolver/split_dns.zig:21`, `src/resolver/dnssec.zig:50`, `src/security/sig0.zig:19`, `src/security/tsig.zig:20`, `src/transports/happy_eyeballs.zig:21`.

- [ ] **Step 1:** Read `util/clock.zig`; confirm its shim API; add a test asserting `milliTimestamp()` is monotone-ish (two calls, second >= first - 1000).
- [ ] **Step 2:** Mechanically replace each module's private inline `timeMilli()`/`now()` shim with a call into `util/clock.zig`. One module at a time; `zig build` after each. Do NOT change behavior (same units). Where a module's shim name is used widely inside the file, keep the local name as a thin alias of the util function.
- [ ] **Step 3:** Full suite passes; fmt clean.
- [ ] **Step 4: Commit** `refactor: close GAP-0877 - consolidate inline clock shims into util/clock.zig`.

### Task 5: GAP-0851 — Consolidate entropy helpers (issue #312)

**Files:** Modify: `src/util/random.zig` (add `pub fn systemRandomU16() !u16` if absent), `src/stub.zig:31`, `src/parallel.zig:80`, `src/recursive.zig:34` (delete verbatim copies; import util/random; propagate errors instead of `catch unreachable`), `src/util/backoff.zig:86-93` and `src/resolver/zone_transfer.zig:439,471` (switch `std.posix.getrandom` → the same util API), `build.zig` (wire `random` module to stub/parallel/recursive module graphs if needed).

- [ ] **Step 1: Failing test** in `src/util/random.zig`: `systemRandomU16()` returns without error and two consecutive calls are not always equal across 16 tries (probabilistic but safe: assert at least one differs).
- [ ] **Step 2:** Implement `systemRandomU16` using the existing fail-fast `std.Io.randomSecure` pattern, returning `RandomError.EntropyUnavailable` on failure (no `catch unreachable`).
- [ ] **Step 3:** Replace all five call sites. Callers that currently can't return errors: propagate (preferred — adjust signatures of private fns) or fail-closed with an explicit error return on their public API. Never `catch unreachable`.
- [ ] **Step 4:** Full suite; fmt.
- [ ] **Step 5: Commit** `refactor: close GAP-0851 - single entropy helper, no catch-unreachable on entropy`.

---

## BATCH 3 — DNSSEC chain (order matters: 0890 → 0841 → 0840 → 0839 → 0843; 0842 decision task last)

### Task 6: GAP-0890 — signed_data capacity reservation (issue #341)

**Files:** Modify: `src/resolver/dnssec.zig:378,397-423`.

- [ ] Pre-compute the signed-data size (RRSIG fixed 18 bytes + signer name len + Σ per-RR(owner+10+rdlen)) and `try signed_data.ensureTotalCapacity(allocator, total)` before the append sequence. No behavior change; existing DNSSEC tests must pass unchanged. Commit `perf: close GAP-0890 - reserve signed_data capacity in verifyRrsig`.

### Task 7: GAP-0841 — RRSIG labels validation, RFC 4035 §5.3.2 (issue #309)

**Files:** Modify: `src/resolver/dnssec.zig:361-394` (`verifyRrsig`), tests at module bottom.

- [ ] **Step 1: Failing tests:** (a) RRSIG with `labels` greater than owner label count → expect `error.InvalidRrsig` (or the module's invalid-signature error); (b) wildcard RRSIG (`labels` < owner count) must verify against the wildcard-reconstructed owner `*.` ++ rightmost-N-labels — craft with an Ed25519 test key signing the canonical wildcard form, then verify it validates for `a.example.test` but the same RRSIG is rejected for `b.c.example.test` (different depth).
- [ ] **Step 2: Fix in `verifyRrsig`:** count owner labels (ignore trailing root); `if (rrsig.labels > owner_labels) return error.<invalid>;` if `rrsig.labels < owner_labels`, build canonical owner as `*.` + rightmost `rrsig.labels` labels and use it in `appendCanonicalRrset` instead of the actual owner.
- [ ] Commit `fix: close GAP-0841 - validate RRSIG labels field (RFC 4035 wildcard rules)`.

### Task 8: GAP-0840 — Emit EDNS OPT with DO=1 when dnssec=true (issue #255)

**Files:** Modify: `src/message.zig` (`buildQueryBuf` ~:318 — current last param `rd: bool` is being fed `config.dnssec` by recursive.zig), `src/recursive.zig:594`, possibly `src/stub.zig` query-build path. Use existing `edns.withDnssec()` / OPT-append helpers (`src/edns.zig:197`).

- [ ] **Step 1: Failing test:** build a query with `dnssec=true`; parse the produced wire bytes; assert ARCOUNT==1, an OPT RR (type 41) exists, and its TTL field has the DO bit (0x8000 in the high 16 bits of TTL). Also assert `rd` remains independently controllable.
- [ ] **Step 2: Fix:** extend `buildQueryBuf` (and heap `buildQuery` for parity) with an explicit `opts: struct { rd: bool = true, dnssec: bool = false }` or separate `do` param (pick the minimal-diff style consistent with the codebase); when `dnssec`, append the OPT RR via the edns helper with DO=1 and a sane UDP payload size (4096, matching existing constants). Update `recursive.zig:594` to pass both flags correctly; audit all other `buildQueryBuf`/`buildQuery` callers (grep) and update.
- [ ] Commit `fix: close GAP-0840 - set EDNS DO bit when dnssec requested (was misrouted to RD)`.

### Task 9: GAP-0839 — Wire dnssec.Validator into the resolution path (issue #207)

**Files:** Modify: `src/recursive.zig` (response-processing after validation of TXID/question, before caching), `src/resolver/config.zig` (add `dnssec_mode: enum { off, permissive, strict } = .off` or reuse existing `dnssec: bool` + new `dnssec_strict: bool = false` — read config first and follow its style), `src/resolver/dnssec.zig` (public entry already exists: `Validator`).

- [ ] **Step 1: Failing tests** (resolver-level, using the existing mock-transport test seams in recursive/stub tests): (a) with `dnssec=true` + strict, a response carrying no RRSIG for a signed zone (validator returns bogus/insecure per trust anchors) is NOT returned/cached — expect `error.DnssecValidationFailed`; (b) with valid Ed25519 chain to a configured trust anchor, resolution succeeds and result is marked secure; (c) with `dnssec=false`, behavior unchanged.
- [ ] **Step 2: Fix:** when `config.dnssec` and a trust anchor is configured: collect answer/authority RRsets + RRSIG/DNSKEY/DS from the response, run `Validator.verifyRrsig`/`validateChainOfTrust`; map results: `bogus` → fail closed (drop, don't cache, return error); `insecure` → permissive: return with secure=false; strict: error; `secure` → proceed. Unverifiable algorithm (RSA until GAP-0842) → treat as `insecure` (documented). Keep the validator OFF by default (`dnssec=false`) so default behavior is unchanged.
- [ ] **Step 3:** Full suite + the three new tests pass.
- [ ] Commit `feat: close GAP-0839 - wire DNSSEC validator into recursive resolution (fail-closed on bogus)`.

### Task 10: GAP-0843 — Align isSupported() with verifySignature (issue #323)

**Files:** Modify: `src/record.zig:714-720`; test beside existing DnssecAlgorithm tests.

- [ ] Failing test: `try std.testing.expect(!DnssecAlgorithm.rsasha256.isSupported());` etc. Fix: return true only for `ed25519, ecdsap256sha256, ecdsap384sha384`. If GAP-0842 later adds RSA, this test gets updated there. Commit `fix: close GAP-0843 - isSupported() reflects actually verifiable algorithms`.

### Task 11: GAP-0842 — RSA DNSSEC decision (issue #76) — DECISION TASK

**Files:** Investigate `std.crypto` in Zig 0.16 for RSA PKCS#1 v1.5 verify (check `std.crypto.Certificate.rsa`). Then either implement or document.

- [ ] **Step 1:** `zig std` docs / grep the installed stdlib (`$(dirname $(which zig))/lib/std/crypto/Certificate.zig` and `rsa.zig`) for a usable public verify API (PublicKey from modulus+exponent, PKCS1v1_5 SHA-256/SHA-512 verify).
- [ ] **Step 2 (if usable):** implement algorithms 8 (RSA/SHA-256) and 10 (RSA/SHA-512) in `dnssec.zig` `verifySignature` — parse DNSKEY RSA wire format (RFC 3110: exponent length prefix), build `rsa.PublicKey`, verify. Add RFC 8080/5702 test vectors. Skip alg 5 (RSA/SHA-1, deprecated) — keep unsupported, documented. Update `isSupported()` + GAP-0843 test accordingly.
- [ ] **Step 2 (if NOT usable):** document-as-limitation: update `docs/RFC_COMPLIANCE.md` (RFC 4034/4035 → Partial, "RSA algorithms unsupported; root-zone validation unavailable"), `docs/SECURITY.md` and `dnssec.zig` module doc; ensure GAP-0839's wiring treats RSA-signed zones as `insecure` explicitly. Mark gap Won't-Do-for-now in tracking with this rationale.
- [ ] Commit `feat: close GAP-0842 - RSA DNSSEC verify (algs 8,10)` or `docs: close GAP-0842 as documented limitation - RSA DNSSEC unsupported`.

---

## BATCH 4 — Zone transfer + SIG(0)

### Task 12: GAP-0868 — TSIG sign/verify for zone transfers (issue #307)

**Files:** Modify: `src/resolver/zone_transfer.zig` (`buildTransferQuery`/`buildIxfrQuery` :432-504 — append TSIG; receive loop :299-334 + `parseTransferResponse` :580-652 — verify), reuse `src/security/tsig.zig` (sign/verify already implemented and hardened).

- [ ] **Step 1: Failing tests** (zone_transfer has mock-stream test infra — read existing tests first): (a) when `tsig_key` set, outgoing AXFR query contains a TSIG RR in additional (parse own query bytes); (b) a response stream whose message lacks TSIG → `error.TsigVerificationFailed` (when key set); (c) tampered record after valid TSIG → verification fails; (d) correctly signed multi-message stream verifies (RFC 8945 §5.3.2: subsequent messages MAC-chain over prior MAC; at minimum verify first and last message and enforce every message carries/chains per the tsig.zig API capabilities — implement chaining helper if tsig.zig lacks it).
- [ ] **Step 2: Fix:** sign outgoing query via tsig.zig; in the receive loop, verify each message's TSIG (chained: running MAC context seeded with prior MAC per RFC 8945 §5.3); abort transfer on missing/invalid MAC when `tsig_key != null`.
- [ ] Commit `feat: close GAP-0868 - enforce TSIG signing and chained verification on zone transfers`.

### Task 13: GAP-0869 — Bound the AXFR receive loop (issue #317)

**Files:** Modify: `src/resolver/zone_transfer.zig:299-334`; config: add `max_messages` (default e.g. 10_000) to `ZoneTransferConfig`.

- [ ] Failing test: mock stream that yields endless `ancount=0` messages → expect `error.TransferTimeout`/`error.TooManyMessages` rather than hang (cap loop in test via small `max_messages=4`). Fix: per-iteration `message_count` cap + wall-clock deadline check (`milliTimestamp() - start > config.timeout_ms` → error). Commit `fix: close GAP-0869 - bound AXFR loop with message cap and deadline`.

### Task 14: GAP-0870 — SIG(0) signer-name binding (issue #318)

**Files:** Modify: `src/security/sig0.zig:384-433` (`verify`), tests at bottom.

- [ ] Failing test: signature crafted with a key whose algorithm+key_tag match the trusted key but `signer_name` differs → must be rejected (`error.SignerNameMismatch`). Fix: after parsing, compare DNS-canonical (case-insensitive, trailing-dot-insensitive) `sig0.signer_name` vs `public_key.name`; reject mismatch. Commit `fix: close GAP-0870 - SIG(0) verify binds signer name to trusted key`.

### Task 15: GAP-0873 — SIG(0) validity-window sanity (issue #333)

**Files:** Modify: `src/security/sig0.zig:410-414`.

- [ ] Failing test: `sig_inception > sig_expiration` → `error.InvalidValidityWindow` (even when `now` accidentally passes the individual comparisons). Fix: explicit `if (inception > expiration) return error...` before the window checks. Commit `fix: close GAP-0873 - reject inverted SIG(0) validity windows`.

---

## BATCH 5 — Failover (after Batch 2 so clock/mutex shims exist)

### Task 16: GAP-0876 — Stable server handles in failover (issue #308)

**Files:** Modify: `src/resolver/failover.zig:248-256` (`selectServer` return), `:320-365` (`recordSuccess`/`recordFailure`), all callers (grep `selectServer`).

- [ ] **Step 1: Failing test:** select a server; `addServer` enough entries to force ArrayList realloc; `recordSuccess` on the held handle; under `std.testing.allocator` this is UAF (may not crash deterministically — assert via index/generation semantics instead after fix; the RED step is the API misuse compiling at all). Prefer: change API so the old pattern cannot compile.
- [ ] **Step 2: Fix:** return an opaque handle `ServerHandle { index: usize, generation: u32 }` (or key by address) instead of `*ServerState`; `recordSuccess/Failure(handle)` validates generation and looks up by index. Update callers + tests.
- [ ] Commit `fix: close GAP-0876 - failover uses stable handles, not raw ServerState pointers`.

### Task 17: GAP-0880 — Injectable clock + failover strategy tests (issue #321)

**Files:** Modify: `src/resolver/failover.zig` (accept a clock like `cache_prefetch.zig`'s MockClock pattern — read that file first and mirror it), tests.

- [ ] Failing tests (write all, watch fail, then implement clock injection): (a) circuit opens after 3 failures → `isAvailable=false`; advance mock clock past `circuit_timeout_ms` → `checkHealth` → available again; (b) weighted selection proportions over 1000 draws ≈ configured weights (±10%); (c) least-connections picks the lowest; (d) latency strategy picks the fastest recorded; (e) primary-secondary fails over and back. Commit `test: close GAP-0880 - injectable clock + failover strategy coverage`.

### Task 18: GAP-0885 — Smooth weighted round-robin (issue #338)

**Files:** Modify: `src/resolver/failover.zig:289-311`.

- [ ] Failing test: with weights {1,1}, 10 consecutive `selectWeighted` calls must alternate (not 5+5 batchy). Fix: implement smooth WRR (Nginx algorithm: per-server `current_weight += effective_weight`; pick max; subtract total). Commit `fix: close GAP-0885 - smooth weighted round-robin interleaving`.

### Task 19: GAP-0886 — Remove redundant isAvailable branch (issue #344)

**Files:** Modify: `src/resolver/failover.zig:101-109`.

- [ ] Simplify to the single final boolean expression; existing + Task 17 tests prove behavior unchanged. Commit `refactor: close GAP-0886 - remove redundant isAvailable early-return`.

---

## BATCH 6 — split_dns + RPZ

### Task 20: GAP-0847 — Label boundary in matchSuffix (issue #306)

**Files:** Modify: `src/resolver/split_dns.zig:71-78`; reference implementation: `src/resolver/rpz.zig:316-327`.

- [ ] Failing tests: `corp.local` rule must NOT match `evilcorp.local`; MUST match `corp.local` and `server.corp.local`; leading-dot `.corp.local` unchanged. Fix: after suffix equality, require `domain.len == pattern.len` OR `pattern[0] == '.'` OR `domain[domain.len - pattern.len - 1] == '.'`. Commit `fix: close GAP-0847 - split-DNS suffix match enforces label boundary`.

### Task 21: GAP-0855 — RPZ trailing-dot normalization (issue #325)

**Files:** Modify: `src/resolver/rpz.zig:302-332` (`matchPattern`); reuse `normalizeZone` from `cache_protection.zig` logic (copy locally or import per module graph).

- [ ] Failing tests: rule `malware.com` matches query `malware.com.`; rule `*.example.com` matches `x.example.com.`; rule `malware.com.` matches `malware.com`. Fix: strip one trailing `.` from both domain and pattern at fn top. Commit `fix: close GAP-0855 - RPZ matching normalizes trailing-dot FQDNs`.

### Task 22: GAP-0862 — Defer sorting in addRule (issue #328)

**Files:** Modify: `src/resolver/rpz.zig:141,244`, `src/resolver/split_dns.zig:298`.

- [ ] Failing test (behavioral): bulk-add N rules then match — results identical to before; perf assertion optional (skip timing asserts in unit tests). Fix: either sorted-insert (`std.sort.insertionContext` on the single new element via binary search + insert) or a `dirty` flag with lazy sort on first match. Keep ordering semantics identical (read how match uses order first!). Commit `perf: close GAP-0862 - avoid full re-sort on every addRule`.

### Task 23: GAP-0863 — Replace naive matchContains scan (issue #329)

**Files:** Modify: `src/resolver/split_dns.zig:89-101`.

- [ ] Behavior-preserving: use `std.ascii.indexOfIgnoreCase` (exists in 0.16) instead of the hand-rolled sliding window. Existing tests must pass; add one case-insensitivity test. Commit `perf: close GAP-0863 - stdlib case-insensitive search in matchContains`.

---

## BATCH 7 — zdig CLI

### Task 24: GAP-0881 — Non-zero exit on missing domain (issue #334)

**Files:** Modify: `cmd/zdig.zig:316-322`.

- [ ] Fix: `return error.MissingQueryName;` instead of bare `return` after printing usage (confirm main() maps errors to non-zero exit; adjust if needed). Test: if zdig has arg-parse unit tests, add one; else verify by `zig build` + run `./zig-out/bin/zdig; echo $?` expecting non-zero, and note in commit. Commit `fix: close GAP-0881 - zdig exits non-zero when no domain given`.

### Task 25: GAP-0882 — IPv6 @server support (issue #335)

**Files:** Modify: `cmd/zdig.zig:546-554,993`.

- [ ] Failing test on the server-parse helper: `@::1`, `@[::1]:5353`, `@2001:db8::1` parse correctly; bad input yields clear error. Fix: use `net_compat.Address.parseIp` (v4+v6) with bracket-port handling. Commit `feat: close GAP-0882 - zdig accepts IPv6 servers`.

### Task 26: GAP-0883 — Reject unknown +options (issue #336)

**Files:** Modify: `cmd/zdig.zig:331-369` (`parseOption`).

- [ ] Failing test: `+dnssecc` → error/warning, not silent no-op. Fix: unknown option → print `unknown option '+...'` to stderr and return error (dig-compatible behavior: error preferred). Commit `fix: close GAP-0883 - zdig errors on unknown +options`.

---

## BATCH 8 — Misc security + correctness

### Task 27: GAP-0846 — Zone-file continuation/owner inheritance (issue #257)

**Files:** Modify: `src/zone_file.zig` (`:302` trims before parse; `:419` dead check).

- [ ] Failing test: zone text `a.example. 300 IN A 1.2.3.4\n  300 IN A 5.6.7.8` (second line indented) → both records owned by `a.example.` (currently second mis-parses). Fix: capture `starts_with_ws = line.len > 0 and (line[0]==' ' or line[0]=='\t')` BEFORE trimming in the caller and thread it to `parseResourceRecord` (replace the dead `line[0]` check with the flag). Commit `fix: close GAP-0846 - zone-file leading-whitespace owner inheritance (was dead code)`.

### Task 28: GAP-0844 — errdefer in Client.initWithConfig (issue #258)

**Files:** Modify: `src/client.zig:87-138`.

- [ ] Failing test: force `StubResolver.init` failure (e.g., empty server list or a failing-allocator harness — read how stub tests induce failure) under `std.testing.allocator` → currently leaks; after fix, no leak. Fix: add `errdefer` for `server_addresses`, `cache`, `prefetcher` immediately after each allocation. Commit `fix: close GAP-0844 - errdefer cleanup in Client.initWithConfig`.

### Task 29: GAP-0845 — Guard clock-regression intCast (issue #310)

**Files:** Modify: `src/transports/happy_eyeballs.zig:207` (copy guarded pattern from `:231`).

- [ ] Fix: `const elapsed: u32 = @intCast(@max(0, timeMilli() - start_time));` Test: extract a tiny helper or test via the guarded math directly (assert `elapsedMs(start=now+5000)` == 0). Commit `fix: close GAP-0845 - clamp negative time delta before intCast`.

### Task 30: GAP-0854 — CA-trust gates for DoH/DoQ + fail-closed Content-Type (issue #324)

**Files:** Modify: `src/transports/doh.zig:171-182` (init gate), `:235-260` (Content-Type), `src/transports/doq.zig:141-156` (init gate); `src/resolver/channel.zig:91-96` (add `use_system_ca: bool = false` to DoQOptions; confirm DoHOptions has one — mirror DoTOptions `:72-80`).

- [ ] Failing tests: (a) `DoHTransport.init` with empty `ca_pem` and no system-CA flag → `error.NoCaTrustConfigured`; (b) same for `DoQTransport.init`; (c) DoH response with `content_type == null` → `error.InvalidContentType`. Fix per DoT reference (`dot.zig:213-215`). Update existing tests that construct these transports with empty ca_pem (set `use_system_ca = true` in test options). Commit `fix: close GAP-0854 - CA-trust gates for DoH/DoQ, fail-closed Content-Type`.

### Task 31: GAP-0856 — Bound calculatePadding cast (issue #326)

**Files:** Modify: `src/edns.zig:582,584`.

- [ ] Failing test: `calculatePadding(current_size=0, block_size=70000)` panics today (safe modes) → after fix returns error or clamps (choose error: `error.BlockSizeTooLarge`; update signature/callers — only constants 128/468 today). Commit `fix: close GAP-0856 - guard calculatePadding u16 cast`.

### Task 32: GAP-0871 — DoQ live-path Message ID check (issue #331)

**Files:** Modify: `src/transports/doq.zig:201-217` (mirror the check from `parseDoQResponse` :256-278).

- [ ] Failing test: mock backend returns response with ID=7 → `queryImpl` must reject (`error.InvalidMessageId` per RFC 9250). Commit `fix: close GAP-0871 - DoQ queryImpl enforces message ID == 0`.

### Task 33: GAP-0872 — ClientSubnet prefix bounds (issue #332)

**Files:** Modify: `src/edns.zig:295,310`.

- [ ] Failing test: `ClientSubnet.parse` with `source_prefix_length = 250` → today panics ((250+7)/8 overflows u8 math) → after fix returns `error.InvalidPrefixLength`. Fix: validate prefix per RFC 7871 (≤32 for IPv4 family 1, ≤128 for IPv6 family 2) BEFORE byte math; widen arithmetic to usize. Commit `fix: close GAP-0872 - validate ECS prefix length before byte math`.

### Task 34: GAP-0853 — UDP aggregate deadline (issue #259)

**Files:** Modify: `src/transports/udp.zig:46-80`.

- [ ] Fix: before each `recvfrom`, recompute remaining budget `remaining = timeout_ms - elapsed`; if ≤0 → `error.Timeout`; set `SO_RCVTIMEO` to `remaining` (not full timeout). Test: hard to unit-test sockets — add a pure helper `remainingBudget(start, now, timeout)` with tests (0 when exceeded; monotone decreasing) and use it. Commit `fix: close GAP-0853 - UDP enforces aggregate timeout across spurious packets`.

### Task 35: GAP-0874 — Semantic config validation (issue #343)

**Files:** Modify: `src/resolver/config.zig:321-371` (validation fn).

- [ ] Failing tests: `timeout_ms=0` → error or normalized to min (choose: `error.InvalidConfig` from `validate()`; check how config errors surface today); `retries > 10` → clamped/error; `max_ttl > 7*86400` → clamped to 7d (matches cache TTL clamp conventions in cache_protection). Commit `fix: close GAP-0874 - reject/clamp semantically invalid config values`.

### Task 36: GAP-0865 — SBOM exclude for unreachable dep CVEs (issue #342)

**Files:** Modify: `.gitlab-ci.yml` (sbom-scan component config — check the component's exclude/ignore variable convention; if unsupported, add a `.trivyignore`/`.grype.yaml` at repo root with CVE-2025-4565, CVE-2026-0994 + justification comments).

- [ ] Implement + commit `chore: close GAP-0865 - suppress unreachable protobuf CVEs in transitive zig-pkg dep`.

---

## BATCH 9 — Zone file $INCLUDE

### Task 37: GAP-0852 — $INCLUDE explicit error + doc truth (issue #244)

**Files:** Modify: `src/zone_file.zig:398-400` and module doc `~:10`.

- [ ] Failing test: zone text containing `$INCLUDE other.zone` → `error.IncludeNotSupported` (today: silent empty success). Fix: return the error; update module doc to list `$INCLUDE` as not supported (rejected explicitly). Commit `fix: close GAP-0852 - $INCLUDE rejected explicitly instead of silently ignored`.

---

## BATCH 10 — CI + benchmarks (0857 → 0849 → 0850 → 0859 → 0858)

### Task 38: GAP-0857 — Widen CI fmt scope (issue #327)

**Files:** Modify: `.gitlab-ci.yml:93`.

- [ ] Change fmt job to `zig fmt --check src/ cmd/ build.zig tests/ examples/ benchmarks/`. Verify locally (currently clean). Commit `ci: close GAP-0857 - fmt check covers tests, examples, benchmarks`.

### Task 39: GAP-0849 — Port bench.zig to Zig 0.16 timing (issue #216)

**Files:** Modify: `benchmarks/bench.zig` (9 sites: 162,173,193,209,224,263,290,307,332).

- [ ] RED: `zig build bench` fails (9 errors). Fix: replace `std.time.Timer` with the pattern already used in `benchmarks/scale_bench.zig` (`std.Io.Clock.Timestamp.now(io_inst, .awake)` deltas) — read scale_bench first and reuse its helper; extract a shared `benchmarks/timing.zig` if trivial. GREEN: `zig build bench` exits 0 and produces output. Commit `fix: close GAP-0849 - bench.zig uses Zig 0.16 clock API`.

### Task 40: GAP-0850 — Port compare.zig args (issue #311)

**Files:** Modify: `benchmarks/compare.zig:152`.

- [ ] RED: `zig build compare-bench` fails. Fix: copy the 0.16 args pattern from `cmd/zdig.zig:1059-1068`. GREEN: `zig build compare-bench -- benchmarks/results/baseline.json benchmarks/results/baseline.json` runs. Commit `fix: close GAP-0850 - compare.zig uses Zig 0.16 args API`.

### Task 41: GAP-0859 — Benchmark the production DnsCache (issue #314)

**Files:** Modify: `benchmarks/bench.zig:248,272`, `benchmarks/scale_bench.zig:264` (add DnsCache put/get benches alongside or replacing legacy `Cache` ones — label legacy clearly).

- [ ] Add `dns_cache_put`/`dns_cache_get` benchmarks exercising `DnsCache` with realistic keys; keep legacy benches renamed `legacy_cache_*`. Run `zig build bench` and `zig build scale-bench` (tiers ≤50K) to capture a fresh baseline → write `benchmarks/results/baseline.json` via the documented procedure (check how baseline was generated; scale-bench JSON stdout). Commit `feat: close GAP-0859 - benchmarks cover production DnsCache; baseline regenerated`.

### Task 42: GAP-0858 — Fix 100K scale-bench tier (issue #313)

**Files:** Modify: `benchmarks/scale_bench.zig:193` (allocator choice + which cache).

- [ ] Switch bench allocator from DebugAllocator/GPA to `std.heap.smp_allocator` or arena (match what bench.zig uses post-Task-39); with Task 41's DnsCache benches the O(n) legacy path no longer dominates; verify `zig build scale-bench` 100K tier completes < 180s. Commit `fix: close GAP-0858 - scale-bench 100K tier completes (release allocator + O(1) cache)`.

---

## BATCH 11 — Docs-only

### Task 43: GAP-0848 — Version truth (issue #211)

**Files:** Modify: `README.md:10,50` (0.15.1 → 0.16.0), `build.zig.zon:19` (`minimum_zig_version = "0.16.0"`), and `.version` → `"0.1.9"` (matches latest tag per ASR-006; verify with `git tag --list 'v*' | sort -V | tail -1` first — use whatever the latest tag is).

- [ ] Verify `zig build` still passes. Commit `docs: close GAP-0848 - correct Zig version requirement and package version`.

### Task 44: GAP-0884 — Fix stale entropy doc comment (issue #337)

**Files:** Modify: `src/recursive.zig:199`.

- [ ] Update comment to reference `std.Io.randomSecure` (or `util/random.zig` post-Task-5). Commit `docs: close GAP-0884 - correct entropy source doc comment`.

---

## BATCH 12 — Performance

### Task 45: GAP-0888 — Coalesce TCP framing writes (issue #322)

**Files:** Modify: `src/transports/tcp.zig:57-58`, `src/transports/connection_pool.zig:587-588,694-695,741-742`.

- [ ] Test: existing TCP framing tests must pass; add one asserting a mock writer receives the frame as a single write call (if the write seam allows counting; else assert bytes identical). Fix: build `[2 + payload.len]` buffer (stack for ≤512+2, else heap) and single `writeAllWithTimeout`; in `queryBatch`, coalesce all frames into one buffer/write. Commit `perf: close GAP-0888 - single-write TCP DNS framing`.

### Task 46: GAP-0861 — Linear rdata append in putRecordWithKey (issue #316)

**Files:** Modify: `src/resolver/dns_cache.zig:511-548`.

- [ ] Read the function; the O(N²) comes from copying the full packed buffer per record append. Fix: accumulate via `std.ArrayList(u8)` with capacity growth (amortized O(N)) or two-pass size-then-fill. Existing cache tests pass; add a multi-record (e.g., 50 A records) put/get round-trip test. Commit `perf: close GAP-0861 - linear rdata packing in putRecordWithKey`.

### Task 47: GAP-0860 — Arena per thread-pool task (issue #315)

**Files:** Modify: `src/parallel.zig:521-532,652-666`.

- [ ] Fix: wrap task-local allocations in `std.heap.ArenaAllocator` backed by a reusable allocator (the pool's GPA or `smp_allocator`), `defer arena.deinit()` per task instead of raw `page_allocator` per allocation. Existing parallel tests pass. Commit `perf: close GAP-0860 - arena allocator per thread-pool task`.

### Task 48: GAP-0887 — Stack-buffer 0x20 encoding (issue #339)

**Files:** Modify: `src/name.zig:711-717` (add `applyCase0x20Buf`), `src/recursive.zig:570` (use it).

- [ ] Test: `applyCase0x20Buf` output equals `applyCase0x20` for same RNG seed; no allocation (pass `std.testing.failing_allocator` where the buf variant takes no allocator). Fix: write into caller-supplied `[253]u8`. Commit `perf: close GAP-0887 - zero-alloc 0x20 case randomization on query path`.

### Task 49: GAP-0889 — Index-assisted connection pool acquire (issue #340)

**Files:** Modify: `src/transports/connection_pool.zig:299-356,483-491`.

- [ ] Fix conservatively: fold the duplicate `countServerConnections` calls into the single reuse-scan pass (one O(N) walk computing reuse candidate + count); keep `findByGeneration` as-is (bounded N). Existing pool tests pass. Commit `perf: close GAP-0889 - single-pass connection pool acquire`.

### Task 50: GAP-0864 — getPool mutex: close as Won't-Do (issue #330)

**Files:** Modify: `docs/GAP_ANALYSIS.md` (status + rationale).

- [ ] Document: mutex is correct primitive; lock-free fast path adds complexity/risk for negligible gain vs pool work. Commit `chore: close GAP-0864 as won't-do - mutex retained in getPool`.

### Task 51: GAP-0866 — Stale-tracker reconciliation: document decision (issue #345)

**Files:** Modify: `docs/GAP_ANALYSIS.md`.

- [ ] Mark Blocked/needs-maintainer-decision with the two options (bulk-close script vs manual revalidation); leave issue #345 open. Commit `docs: GAP-0866 marked needs-maintainer-decision (tracker reconciliation)`.

---

## Final verification (after all batches)

- [ ] `zig build && zig build test --summary all && zig build test-vectors --summary all && zig build examples && zig build bench && zig build scale-bench && zig fmt --check src/ cmd/ build.zig tests/ examples/ benchmarks/`
- [ ] `git status` clean; every gap has exactly one commit.
