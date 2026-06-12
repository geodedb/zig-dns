// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Incremental scale benchmark for dns library.
//!
//! Runs the same battery of operations at progressively larger message/record
//! counts and emits structured JSON to stdout for tracking over time.
//! A human-readable summary table is printed to stderr via std.debug.print.
//!
//! Run via: zig build scale-bench
//! Save:   zig build scale-bench 2>/dev/null > results.json

const std = @import("std");
const builtin = @import("builtin");
const dns = @import("dns");

inline fn nowNs() u64 {
    const io_inst = std.Io.Threaded.global_single_threaded.io();
    const ts = std.Io.Clock.Timestamp.now(io_inst, .awake);
    return @intCast(ts.raw.toNanoseconds());
}

inline fn timeSec() i64 {
    const io_inst = std.Io.Threaded.global_single_threaded.io();
    return std.Io.Clock.Timestamp.now(io_inst, .real).raw.toSeconds();
}

const Message = dns.message.Message;
const Name = dns.name.Name;
const ResourceRecord = dns.record.ResourceRecord;
const Type = dns.types.Type;
const Class = dns.types.Class;

const print = std.debug.print;

// ---------------------------------------------------------------------------
// Scale tier definitions
// ---------------------------------------------------------------------------

const Tier = struct {
    name: []const u8,
    /// Number of messages to parse
    message_count: usize,
    /// Number of queries to build
    query_count: usize,
    /// Number of names to encode/decode
    name_count: usize,
    /// Number of records to parse
    record_count: usize,
    /// Cache capacity
    cache_size: usize,
    /// Number of cache ops
    cache_ops: usize,
    /// Parallel zone parse record count
    parallel_records: usize,
    /// Iteration count for lookup/get benchmarks
    iterations: usize,
};

const tiers = [_]Tier{
    .{
        .name = "100",
        .message_count = 100,
        .query_count = 100,
        .name_count = 500,
        .record_count = 100,
        .cache_size = 200,
        .cache_ops = 500,
        .parallel_records = 128,
        .iterations = 1000,
    },
    .{
        .name = "1K",
        .message_count = 1_000,
        .query_count = 1_000,
        .name_count = 5_000,
        .record_count = 1_000,
        .cache_size = 2_000,
        .cache_ops = 5_000,
        .parallel_records = 1_024,
        .iterations = 2000,
    },
    .{
        .name = "10K",
        .message_count = 10_000,
        .query_count = 10_000,
        .name_count = 50_000,
        .record_count = 10_000,
        .cache_size = 20_000,
        .cache_ops = 50_000,
        .parallel_records = 4_096,
        .iterations = 5000,
    },
    .{
        .name = "50K",
        .message_count = 50_000,
        .query_count = 50_000,
        .name_count = 100_000,
        .record_count = 50_000,
        .cache_size = 50_000,
        .cache_ops = 100_000,
        .parallel_records = 8_192,
        .iterations = 10000,
    },
    .{
        .name = "100K",
        .message_count = 100_000,
        .query_count = 100_000,
        .name_count = 200_000,
        .record_count = 100_000,
        .cache_size = 100_000,
        .cache_ops = 200_000,
        .parallel_records = 16_384,
        .iterations = 20000,
    },
};

// ---------------------------------------------------------------------------
// Per-tier results
// ---------------------------------------------------------------------------

const TierResult = struct {
    name: []const u8,
    message_count: u64,
    msg_parse_ops_sec: f64,
    msg_build_ops_sec: f64,
    name_encode_ns: f64,
    name_decode_ns: f64,
    record_parse_ns: f64,
    /// Production O(1) LRU DnsCache (GAP-0859)
    dns_cache_put_ns: f64,
    dns_cache_get_ns: f64,
    /// Legacy O(n) dns.cache.Cache (kept for comparison)
    legacy_cache_put_ns: f64,
    legacy_cache_get_ns: f64,
    parallel_parse_ms: f64,
    skipped: bool = false,
    skip_reason: ?[]const u8 = null,
};

/// Maximum wall-clock time for a single tier (5 minutes in ns).
const TIER_TIMEOUT_NS: u64 = 5 * 60 * std.time.ns_per_s;

// ---------------------------------------------------------------------------
// Test data
// ---------------------------------------------------------------------------

fn makeTestResponse() [45]u8 {
    return .{
        0x12, 0x34, 0x81, 0x80,
        0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        7,    'e',  'x',  'a',
        'm',  'p',  'l',  'e',
        3,    'c',  'o',  'm',
        0,    0x00, 0x01, 0x00,
        0x01, 0xC0, 0x0C, 0x00,
        0x01, 0x00, 0x01, 0x00,
        0x00, 0x01, 0x2C, 0x00,
        0x04, 93,   184,  216,
        34,
    };
}

fn makeTestRecord() [27]u8 {
    return .{
        7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',
        3,    'c',  'o',  'm',  0,    0x00, 0x01, 0x00,
        0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04, 192,
        0,    2,    1,
    };
}

// ---------------------------------------------------------------------------
// Individual benchmark functions
// ---------------------------------------------------------------------------

fn benchMsgParse(count: usize) f64 {
    const data = makeTestResponse();

    const timer_start: u64 = nowNs();
    for (0..count) |_| {
        const msg = Message.parse(&data) catch continue;
        std.mem.doNotOptimizeAway(&msg);
    }
    const elapsed = nowNs() - timer_start;

    const count_f: f64 = @floatFromInt(count);
    const ns_f: f64 = @floatFromInt(elapsed);
    return count_f / (ns_f / 1_000_000_000.0);
}

fn benchMsgBuild(allocator: std.mem.Allocator, count: usize) f64 {
    const timer_start: u64 = nowNs();
    for (0..count) |i| {
        const id: u16 = @truncate(i);
        const query = dns.message.buildQuery(allocator, id, "example.com", .a, .in, true, false) catch continue;
        std.mem.doNotOptimizeAway(query.ptr);
        allocator.free(query);
    }
    const elapsed = nowNs() - timer_start;

    const count_f: f64 = @floatFromInt(count);
    const ns_f: f64 = @floatFromInt(elapsed);
    return count_f / (ns_f / 1_000_000_000.0);
}

fn benchNameEncode(allocator: std.mem.Allocator, count: usize) f64 {
    const timer_start: u64 = nowNs();
    for (0..count) |_| {
        const encoded = Name.encode(allocator, "sub.example.com") catch continue;
        std.mem.doNotOptimizeAway(encoded.ptr);
        allocator.free(encoded);
    }
    const elapsed = nowNs() - timer_start;

    const ns_f: f64 = @floatFromInt(elapsed);
    const count_f: f64 = @floatFromInt(count);
    return ns_f / count_f;
}

fn benchNameDecode(allocator: std.mem.Allocator, count: usize) f64 {
    const data = makeTestResponse();

    const timer_start: u64 = nowNs();
    for (0..count) |_| {
        const parsed = Name.parse(&data, 12) catch continue;
        const str = parsed.toString(allocator, &data) catch continue;
        std.mem.doNotOptimizeAway(str.ptr);
        allocator.free(str);
    }
    const elapsed = nowNs() - timer_start;

    const ns_f: f64 = @floatFromInt(elapsed);
    const count_f: f64 = @floatFromInt(count);
    return ns_f / count_f;
}

fn benchRecordParse(count: usize) f64 {
    const data = makeTestRecord();

    const timer_start: u64 = nowNs();
    for (0..count) |_| {
        const rr = ResourceRecord.parse(&data, 0) catch continue;
        std.mem.doNotOptimizeAway(&rr);
    }
    const elapsed = nowNs() - timer_start;

    const ns_f: f64 = @floatFromInt(elapsed);
    const count_f: f64 = @floatFromInt(count);
    return ns_f / count_f;
}

fn makeResourceRecord() ResourceRecord {
    const rdata = &[_]u8{ 192, 0, 2, 1 };
    return ResourceRecord{
        .name = Name{ .labels = &[_]u8{ 3, 'c', 'o', 'm', 0 }, .wire_length = 5 },
        .rtype = .a,
        .class = .in,
        .ttl = 300,
        .rdlength = 4,
        .rdata = rdata,
        .wire_length = 15,
    };
}

/// GAP-0858: the legacy cache is O(n) per operation by design. Measuring
/// it with hundreds of thousands of ops against a 100K-entry cache costs
/// minutes (200K gets x ~2.1 ms/op at the 100K tier) without changing the
/// per-op result, and made the full run blow its 180 s budget. Bound the
/// legacy benchmark work; the production DnsCache benches above exercise
/// the full tier scale.
const LEGACY_CACHE_MAX_OPS: usize = 20_000;
const LEGACY_CACHE_MAX_ENTRIES: usize = 20_000;

fn benchLegacyCachePut(allocator: std.mem.Allocator, raw_count: usize, raw_cache_size: usize) f64 {
    const count = @min(raw_count, LEGACY_CACHE_MAX_OPS);
    const cache_size = @min(raw_cache_size, LEGACY_CACHE_MAX_ENTRIES);

    var cache = dns.cache.Cache.init(allocator, cache_size);
    defer cache.deinit();

    const rr = makeResourceRecord();

    var domains: std.ArrayListUnmanaged([]u8) = .empty;
    defer {
        for (domains.items) |d| allocator.free(d);
        domains.deinit(allocator);
    }

    for (0..count) |i| {
        const d = std.fmt.allocPrint(allocator, "h{d}.example.com", .{i}) catch break;
        domains.append(allocator, d) catch break;
    }

    const timer_start: u64 = nowNs();
    for (domains.items) |domain| {
        cache.put(domain, rr) catch continue;
    }
    const elapsed = nowNs() - timer_start;

    const ns_f: f64 = @floatFromInt(elapsed);
    const count_f: f64 = @floatFromInt(domains.items.len);
    return if (count_f > 0) ns_f / count_f else 0;
}

fn benchLegacyCacheGet(allocator: std.mem.Allocator, raw_count: usize, raw_cache_size: usize) f64 {
    // GAP-0858: bounded -- see LEGACY_CACHE_MAX_OPS above.
    const count = @min(raw_count, LEGACY_CACHE_MAX_OPS);
    const cache_size = @min(raw_cache_size, LEGACY_CACHE_MAX_ENTRIES);

    var cache = dns.cache.Cache.init(allocator, cache_size);
    defer cache.deinit();

    const rr = makeResourceRecord();
    const pop = @min(count, cache_size);
    var domains: std.ArrayListUnmanaged([]u8) = .empty;
    defer {
        for (domains.items) |d| allocator.free(d);
        domains.deinit(allocator);
    }

    for (0..pop) |i| {
        const d = std.fmt.allocPrint(allocator, "h{d}.example.com", .{i}) catch break;
        domains.append(allocator, d) catch {
            allocator.free(d);
            break;
        };
        cache.put(d, rr) catch continue;
    }

    if (domains.items.len == 0) return 0;

    const timer_start: u64 = nowNs();
    for (0..count) |i| {
        const idx = i % domains.items.len;
        const result = cache.get(domains.items[idx], .a, .in);
        std.mem.doNotOptimizeAway(&result);
    }
    const elapsed = nowNs() - timer_start;

    const ns_f: f64 = @floatFromInt(elapsed);
    const count_f: f64 = @floatFromInt(count);
    return ns_f / count_f;
}

// GAP-0859: benchmark the production O(1) LRU DnsCache (used by the
// client and recursive resolver), not just the legacy O(n) cache.

fn benchDnsCachePut(allocator: std.mem.Allocator, count: usize, cache_size: usize) f64 {
    var sys_clock = dns.client.systemClock();
    var cache = dns.client.DnsCache.init(
        allocator,
        .{ .max_entries = cache_size },
        sys_clock.clock(),
    );
    defer cache.deinit();

    const rdata = [_]u8{ 192, 0, 2, 1 };

    var domains: std.ArrayListUnmanaged([]u8) = .empty;
    defer {
        for (domains.items) |d| allocator.free(d);
        domains.deinit(allocator);
    }

    for (0..count) |i| {
        const d = std.fmt.allocPrint(allocator, "h{d}.example.com", .{i}) catch break;
        domains.append(allocator, d) catch {
            allocator.free(d);
            break;
        };
    }

    const timer_start: u64 = nowNs();
    for (domains.items) |domain| {
        cache.putRecord(domain, .a, .in, &rdata, 300) catch continue;
    }
    const elapsed = nowNs() - timer_start;

    const ns_f: f64 = @floatFromInt(elapsed);
    const count_f: f64 = @floatFromInt(domains.items.len);
    return if (count_f > 0) ns_f / count_f else 0;
}

fn benchDnsCacheGet(allocator: std.mem.Allocator, count: usize, cache_size: usize) f64 {
    var sys_clock = dns.client.systemClock();
    var cache = dns.client.DnsCache.init(
        allocator,
        .{ .max_entries = cache_size },
        sys_clock.clock(),
    );
    defer cache.deinit();

    const rdata = [_]u8{ 192, 0, 2, 1 };
    const pop = @min(count, cache_size);
    var domains: std.ArrayListUnmanaged([]u8) = .empty;
    defer {
        for (domains.items) |d| allocator.free(d);
        domains.deinit(allocator);
    }

    for (0..pop) |i| {
        const d = std.fmt.allocPrint(allocator, "h{d}.example.com", .{i}) catch break;
        domains.append(allocator, d) catch {
            allocator.free(d);
            break;
        };
        cache.putRecord(d, .a, .in, &rdata, 300) catch continue;
    }

    if (domains.items.len == 0) return 0;

    const timer_start: u64 = nowNs();
    for (0..count) |i| {
        const idx = i % domains.items.len;
        const result = cache.get(domains.items[idx], .a, .in);
        std.mem.doNotOptimizeAway(&result);
    }
    const elapsed = nowNs() - timer_start;

    const ns_f: f64 = @floatFromInt(elapsed);
    const count_f: f64 = @floatFromInt(count);
    return ns_f / count_f;
}

fn benchParallelParse(allocator: std.mem.Allocator, count: usize) f64 {
    const record_data = makeTestRecord();

    const raw_records = allocator.alloc([]const u8, count) catch return 0;
    defer allocator.free(raw_records);
    for (raw_records) |*r| r.* = &record_data;

    const results = allocator.alloc(dns.parallel.ParsedRecord, count) catch return 0;
    defer allocator.free(results);

    const timer_start: u64 = nowNs();
    dns.parallel.parallelZoneRecordParse(allocator, raw_records, results);
    const elapsed = nowNs() - timer_start;

    const ns_f: f64 = @floatFromInt(elapsed);
    return ns_f / 1_000_000.0; // return ms
}

// ---------------------------------------------------------------------------
// Tier runner
// ---------------------------------------------------------------------------

fn runTier(allocator: std.mem.Allocator, tier: Tier) TierResult {
    const tier_start: u64 = nowNs();

    const msg_parse = benchMsgParse(tier.message_count);

    if ((nowNs() -% tier_start) > TIER_TIMEOUT_NS)
        return .{
            .name = tier.name,
            .message_count = tier.message_count,
            .msg_parse_ops_sec = msg_parse,
            .msg_build_ops_sec = 0,
            .name_encode_ns = 0,
            .name_decode_ns = 0,
            .record_parse_ns = 0,
            .dns_cache_put_ns = 0,
            .dns_cache_get_ns = 0,
            .legacy_cache_put_ns = 0,
            .legacy_cache_get_ns = 0,
            .parallel_parse_ms = 0,
            .skipped = true,
            .skip_reason = "timeout",
        };

    const msg_build = benchMsgBuild(allocator, tier.query_count);
    const name_enc = benchNameEncode(allocator, tier.name_count);
    const name_dec = benchNameDecode(allocator, tier.name_count);
    const rec_parse = benchRecordParse(tier.record_count);
    const dns_cache_put = benchDnsCachePut(allocator, tier.cache_ops, tier.cache_size);
    const dns_cache_get = benchDnsCacheGet(allocator, tier.cache_ops, tier.cache_size);
    const legacy_cache_put = benchLegacyCachePut(allocator, tier.cache_ops, tier.cache_size);
    const legacy_cache_get = benchLegacyCacheGet(allocator, tier.cache_ops, tier.cache_size);
    const parallel_ms = benchParallelParse(allocator, tier.parallel_records);

    return .{
        .name = tier.name,
        .message_count = tier.message_count,
        .msg_parse_ops_sec = msg_parse,
        .msg_build_ops_sec = msg_build,
        .name_encode_ns = name_enc,
        .name_decode_ns = name_dec,
        .record_parse_ns = rec_parse,
        .dns_cache_put_ns = dns_cache_put,
        .dns_cache_get_ns = dns_cache_get,
        .legacy_cache_put_ns = legacy_cache_put,
        .legacy_cache_get_ns = legacy_cache_get,
        .parallel_parse_ms = parallel_ms,
    };
}

// ---------------------------------------------------------------------------
// JSON output
// ---------------------------------------------------------------------------

fn writeJson(allocator: std.mem.Allocator, results: []const TierResult) !void {
    var json: std.ArrayListUnmanaged(u8) = .empty;
    defer json.deinit(allocator);

    try json.appendSlice(allocator, "{\n");
    try json.appendSlice(allocator, "  \"version\": 1,\n");
    try json.print(allocator, "  \"timestamp\": {d},\n", .{timeSec()});
    try json.print(allocator, "  \"system\": {{ \"os\": \"{s}\", \"arch\": \"{s}\" }},\n", .{
        @tagName(builtin.os.tag),
        @tagName(builtin.cpu.arch),
    });
    try json.appendSlice(allocator, "  \"git_commit\": \"unknown\",\n");
    try json.appendSlice(allocator, "  \"tiers\": [\n");

    for (results, 0..) |r, i| {
        try json.appendSlice(allocator, "    {\n");
        try json.print(allocator, "      \"name\": \"{s}\",\n", .{r.name});
        try json.print(allocator, "      \"message_count\": {d},\n", .{r.message_count});
        try json.print(allocator, "      \"msg_parse_ops_sec\": {d:.1},\n", .{r.msg_parse_ops_sec});
        try json.print(allocator, "      \"msg_build_ops_sec\": {d:.1},\n", .{r.msg_build_ops_sec});
        try json.print(allocator, "      \"name_encode_ns\": {d:.1},\n", .{r.name_encode_ns});
        try json.print(allocator, "      \"name_decode_ns\": {d:.1},\n", .{r.name_decode_ns});
        try json.print(allocator, "      \"record_parse_ns\": {d:.1},\n", .{r.record_parse_ns});
        try json.print(allocator, "      \"dns_cache_put_ns\": {d:.1},\n", .{r.dns_cache_put_ns});
        try json.print(allocator, "      \"dns_cache_get_ns\": {d:.1},\n", .{r.dns_cache_get_ns});
        try json.print(allocator, "      \"legacy_cache_put_ns\": {d:.1},\n", .{r.legacy_cache_put_ns});
        try json.print(allocator, "      \"legacy_cache_get_ns\": {d:.1},\n", .{r.legacy_cache_get_ns});
        try json.print(allocator, "      \"parallel_parse_ms\": {d:.2},\n", .{r.parallel_parse_ms});
        try json.print(allocator, "      \"skipped\": {}\n", .{r.skipped});

        if (i < results.len - 1) {
            try json.appendSlice(allocator, "    },\n");
        } else {
            try json.appendSlice(allocator, "    }\n");
        }
    }
    try json.appendSlice(allocator, "  ]\n");
    try json.appendSlice(allocator, "}\n");

    // Write the JSON to stdout (fd 1)
    var written: usize = 0;
    while (written < json.items.len) {
        const rc = std.os.linux.write(1, json.items[written..].ptr, json.items.len - written);
        const r: isize = @bitCast(rc);
        if (r <= 0) break;
        written += @intCast(r);
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    // GAP-0858: benchmarks must not pay DebugAllocator overhead -- its
    // per-allocation bookkeeping dominated large tiers and made the 100K
    // tier exceed its timeout. smp_allocator is the release-appropriate
    // thread-safe general-purpose allocator.
    const allocator = std.heap.smp_allocator;

    // Determine max tier from args
    var max_tier: usize = tiers.len;
    var args_it = init.minimal.args.iterate();
    _ = args_it.next(); // skip program name
    if (args_it.next()) |arg| {
        max_tier = std.fmt.parseInt(usize, arg, 10) catch tiers.len;
        max_tier = @min(max_tier, tiers.len);
    }

    // Run tiers
    var results: [tiers.len]TierResult = undefined;
    const run_count = @min(max_tier, tiers.len);

    // Print human-readable header to stderr
    print("\n{s}\n", .{"=" ** 90});
    print("  dns scale benchmark suite\n", .{});
    print("{s}\n\n", .{"=" ** 90});
    print("  {s:<6} {s:>16} {s:>16} {s:>12} {s:>12} {s:>12} {s:>10}\n", .{
        "Tier", "msg_parse/s", "msg_build/s", "name_enc_ns", "rec_parse_ns", "dns_get_ns", "par_ms",
    });
    print("  {s:<6} {s:>16} {s:>16} {s:>12} {s:>12} {s:>12} {s:>10}\n", .{
        "-" ** 6, "-" ** 16, "-" ** 16, "-" ** 12, "-" ** 12, "-" ** 12, "-" ** 10,
    });

    for (0..run_count) |i| {
        results[i] = runTier(allocator, tiers[i]);
        const r = results[i];

        if (r.skipped) {
            print("  {s:<6} SKIPPED: {s}\n", .{ r.name, r.skip_reason orelse "unknown" });
        } else {
            print("  {s:<6} {d:>16.0} {d:>16.0} {d:>12.1} {d:>12.1} {d:>12.1} {d:>10.2}\n", .{
                r.name,
                r.msg_parse_ops_sec,
                r.msg_build_ops_sec,
                r.name_encode_ns,
                r.record_parse_ns,
                r.dns_cache_get_ns,
                r.parallel_parse_ms,
            });
        }
    }

    print("\n{s}\n\n", .{"=" ** 90});

    // Cleanup thread pool if initialized
    dns.parallel.deinitPool();

    // Write JSON to stdout
    try writeJson(allocator, results[0..run_count]);
}
