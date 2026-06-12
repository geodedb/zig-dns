// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Performance benchmark harness for the dns library.
//!
//! Benchmarks: message parse, message build, name encode, name decode,
//! record parse, cache put, cache get, EDNS parse/build, parallel zone parse.
//!
//! Run via: zig build bench

const std = @import("std");
const dns = @import("dns");

/// Monotonic nanosecond clock. std.time.Timer was removed in Zig 0.16; this
/// mirrors the working helper in scale_bench.zig.
inline fn nowNs() u64 {
    const io_inst = std.Io.Threaded.global_single_threaded.io();
    const ts = std.Io.Clock.Timestamp.now(io_inst, .awake);
    return @intCast(ts.raw.toNanoseconds());
}

const Message = dns.message.Message;
const Name = dns.name.Name;
const ResourceRecord = dns.record.ResourceRecord;
const Type = dns.types.Type;
const Class = dns.types.Class;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const MSG_PARSE_COUNT: usize = 50_000;
const MSG_BUILD_COUNT: usize = 50_000;
const NAME_ENCODE_COUNT: usize = 100_000;
const NAME_DECODE_COUNT: usize = 100_000;
const RECORD_PARSE_COUNT: usize = 50_000;
const CACHE_PUT_COUNT: usize = 50_000;
const CACHE_GET_COUNT: usize = 100_000;
const EDNS_PARSE_COUNT: usize = 100_000;
const PARALLEL_ZONE_COUNT: usize = 256;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const BenchResult = struct {
    name: []const u8,
    count: usize,
    total_ns: u64,

    fn ops_per_sec(self: BenchResult) f64 {
        if (self.total_ns == 0) return 0;
        const count_f: f64 = @floatFromInt(self.count);
        const ns_f: f64 = @floatFromInt(self.total_ns);
        return count_f / (ns_f / 1_000_000_000.0);
    }

    fn avg_ns(self: BenchResult) f64 {
        if (self.count == 0) return 0;
        const ns_f: f64 = @floatFromInt(self.total_ns);
        const count_f: f64 = @floatFromInt(self.count);
        return ns_f / count_f;
    }
};

const print = std.debug.print;

fn printHeader() void {
    print("\n{s}\n", .{"=" ** 78});
    print("  dns benchmark suite\n", .{});
    print("{s}\n\n", .{"=" ** 78});
    print("  {s:<30} {s:>10} {s:>14} {s:>12} {s:>10}\n", .{
        "Benchmark", "Count", "Total (ms)", "Avg (ns)", "ops/sec",
    });
    print("  {s:<30} {s:>10} {s:>14} {s:>12} {s:>10}\n", .{
        "-" ** 30, "-" ** 10, "-" ** 14, "-" ** 12, "-" ** 10,
    });
}

fn printResult(r: BenchResult) void {
    const total_ms = @as(f64, @floatFromInt(r.total_ns)) / 1_000_000.0;
    print("  {s:<30} {d:>10} {d:>14.2} {d:>12.1} {d:>10.0}\n", .{
        r.name,
        r.count,
        total_ms,
        r.avg_ns(),
        r.ops_per_sec(),
    });
}

fn printFooter() void {
    print("\n{s}\n\n", .{"=" ** 78});
}

// ---------------------------------------------------------------------------
// Test data generators
// ---------------------------------------------------------------------------

/// Minimal valid DNS response: query for "example.com" A with one answer
fn makeTestResponse() [45]u8 {
    return .{
        // Header (12 bytes)
        0x12, 0x34, // ID
        0x81, 0x80, // Flags: QR=1, RD=1, RA=1
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x01, // ANCOUNT: 1
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
        // Question: example.com A IN (17 bytes)
        7,    'e',
        'x',  'a',
        'm',  'p',
        'l',  'e',
        3,    'c',
        'o',  'm',
        0, // root terminator
        0x00, 0x01, // QTYPE: A
        0x00, 0x01, // QCLASS: IN
        // Answer: example.com A 300 93.184.216.34 (14 bytes)
        0xC0, 0x0C, // pointer to offset 12 (example.com)
        0x00, 0x01, // TYPE: A
        0x00, 0x01, // CLASS: IN
        0x00, 0x00, 0x01, 0x2C, // TTL: 300
        0x00, 0x04, // RDLENGTH: 4
        93, 184, 216, 34, // RDATA: 93.184.216.34
    };
}

/// Wire-format resource record for parsing benchmarks
fn makeTestRecord() [27]u8 {
    return .{
        // Name: example.com (uncompressed)
        7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',
        3,    'c',  'o',  'm',  0,
        // Type: A (1)
           0x00, 0x01,
        // Class: IN (1)
        0x00,
        0x01,
        // TTL: 300
        0x00, 0x00, 0x01, 0x2C,
        // RDLENGTH: 4
        0x00, 0x04,
        // RDATA: 192.0.2.1
        192,
        0,    2,    1,
    };
}

/// Wire-format EDNS OPT pseudo-record
fn makeTestEdnsOpt() [11]u8 {
    return .{
        0x00, // Name: root
        0x00, 0x29, // TYPE: OPT (41)
        0x04, 0xD0, // CLASS: UDP payload 1232
        0x00, // Extended RCODE: 0
        0x00, // Version: 0
        0x80, 0x00, // Flags: DO=1
        0x00, 0x00, // RDLENGTH: 0 (no options)
    };
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

fn benchMessageParse() BenchResult {
    const data = makeTestResponse();

    const start_ns = nowNs();
    for (0..MSG_PARSE_COUNT) |_| {
        const msg = Message.parse(&data) catch continue;
        std.mem.doNotOptimizeAway(&msg);
    }
    const elapsed = nowNs() - start_ns;

    return .{ .name = "message parse", .count = MSG_PARSE_COUNT, .total_ns = elapsed };
}

fn benchMessageBuild(allocator: std.mem.Allocator) BenchResult {
    const start_ns = nowNs();
    for (0..MSG_BUILD_COUNT) |i| {
        const id: u16 = @truncate(i);
        const query = dns.message.buildQuery(allocator, id, "example.com", .a, .in, true) catch continue;
        std.mem.doNotOptimizeAway(query.ptr);
        allocator.free(query);
    }
    const elapsed = nowNs() - start_ns;

    return .{ .name = "message build", .count = MSG_BUILD_COUNT, .total_ns = elapsed };
}

fn benchNameEncode(allocator: std.mem.Allocator) BenchResult {
    const domains = [_][]const u8{
        "example.com",
        "sub.example.com",
        "deep.nested.sub.example.com",
        "a.b.c.d.e.f.g.h.example.com",
    };

    const start_ns = nowNs();
    for (0..NAME_ENCODE_COUNT) |i| {
        const domain = domains[i % domains.len];
        const encoded = Name.encode(allocator, domain) catch continue;
        std.mem.doNotOptimizeAway(encoded.ptr);
        allocator.free(encoded);
    }
    const elapsed = nowNs() - start_ns;

    return .{ .name = "name encode", .count = NAME_ENCODE_COUNT, .total_ns = elapsed };
}

fn benchNameDecode(allocator: std.mem.Allocator) BenchResult {
    // Parse names from a DNS response (exercises compression pointer resolution)
    const data = makeTestResponse();

    const start_ns = nowNs();
    for (0..NAME_DECODE_COUNT) |_| {
        const parsed = Name.parse(&data, 12) catch continue;
        const str = parsed.toString(allocator, &data) catch continue;
        std.mem.doNotOptimizeAway(str.ptr);
        allocator.free(str);
    }
    const elapsed = nowNs() - start_ns;

    return .{ .name = "name decode", .count = NAME_DECODE_COUNT, .total_ns = elapsed };
}

fn benchRecordParse() BenchResult {
    const data = makeTestRecord();

    const start_ns = nowNs();
    for (0..RECORD_PARSE_COUNT) |_| {
        const rr = ResourceRecord.parse(&data, 0) catch continue;
        std.mem.doNotOptimizeAway(&rr);
    }
    const elapsed = nowNs() - start_ns;

    return .{ .name = "record parse", .count = RECORD_PARSE_COUNT, .total_ns = elapsed };
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

fn benchCachePut(allocator: std.mem.Allocator) BenchResult {
    var cache = dns.cache.Cache.init(allocator, 10_000);
    defer cache.deinit();

    const rr = makeResourceRecord();

    // Build domain names ahead of time
    var domains: [CACHE_PUT_COUNT][]u8 = undefined;
    var allocated: usize = 0;
    defer for (domains[0..allocated]) |d| allocator.free(d);

    for (0..CACHE_PUT_COUNT) |i| {
        domains[i] = std.fmt.allocPrint(allocator, "host-{d}.example.com", .{i}) catch break;
        allocated = i + 1;
    }

    const start_ns = nowNs();
    for (domains[0..allocated]) |domain| {
        cache.put(domain, rr) catch continue;
    }
    const elapsed = nowNs() - start_ns;

    return .{ .name = "cache put", .count = allocated, .total_ns = elapsed };
}

fn benchCacheGet(allocator: std.mem.Allocator) BenchResult {
    var cache = dns.cache.Cache.init(allocator, 10_000);
    defer cache.deinit();

    const rr = makeResourceRecord();

    // Populate cache first
    const pop_count = @min(CACHE_GET_COUNT, 10_000);
    var domains: [10_000][]u8 = undefined;
    var allocated: usize = 0;
    defer for (domains[0..allocated]) |d| allocator.free(d);

    for (0..pop_count) |i| {
        domains[i] = std.fmt.allocPrint(allocator, "host-{d}.example.com", .{i}) catch break;
        allocated = i + 1;
        cache.put(domains[i], rr) catch continue;
    }

    const start_ns = nowNs();
    for (0..CACHE_GET_COUNT) |i| {
        const idx = i % allocated;
        const result = cache.get(domains[idx], .a, .in);
        std.mem.doNotOptimizeAway(&result);
    }
    const elapsed = nowNs() - start_ns;

    return .{ .name = "cache get", .count = CACHE_GET_COUNT, .total_ns = elapsed };
}

fn benchEdnsParse() BenchResult {
    const data = makeTestEdnsOpt();
    // Parse the OPT record first to get the structure
    const rr = ResourceRecord.parse(&data, 0) catch
        return .{ .name = "EDNS OPT parse", .count = 0, .total_ns = 0 };

    const start_ns = nowNs();
    for (0..EDNS_PARSE_COUNT) |_| {
        const opt = dns.edns.OptRecord.parse(
            rr.class.toInt(),
            rr.ttl,
            rr.rdata,
        );
        std.mem.doNotOptimizeAway(&opt);
    }
    const elapsed = nowNs() - start_ns;

    return .{ .name = "EDNS OPT parse", .count = EDNS_PARSE_COUNT, .total_ns = elapsed };
}

fn benchParallelZoneParse(allocator: std.mem.Allocator) BenchResult {
    const record_data = makeTestRecord();

    // Build array of raw records
    var raw_records: [PARALLEL_ZONE_COUNT][]const u8 = undefined;
    for (&raw_records) |*r| {
        r.* = &record_data;
    }

    var results: [PARALLEL_ZONE_COUNT]dns.parallel.ParsedRecord = undefined;

    const start_ns = nowNs();
    dns.parallel.parallelZoneRecordParse(allocator, &raw_records, &results);
    const elapsed = nowNs() - start_ns;

    // Cleanup thread pool
    defer dns.parallel.deinitPool();

    return .{ .name = "parallel zone parse", .count = PARALLEL_ZONE_COUNT, .total_ns = elapsed };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    printHeader();

    printResult(benchMessageParse());
    printResult(benchMessageBuild(allocator));
    printResult(benchNameEncode(allocator));
    printResult(benchNameDecode(allocator));
    printResult(benchRecordParse());
    printResult(benchCachePut(allocator));
    printResult(benchCacheGet(allocator));
    printResult(benchEdnsParse());
    printResult(benchParallelZoneParse(allocator));

    printFooter();
}
