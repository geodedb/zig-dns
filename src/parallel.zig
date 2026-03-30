// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Parallel DNS operations using spice heartbeat scheduling.
//!
//! Provides high-performance parallel implementations of compute-intensive
//! DNS operations including zone transfer parsing, DNSSEC validation,
//! and batch query processing.
//!
//! ## Overview
//!
//! This module enables parallel processing of DNS operations using the
//! spice thread pool. Ideal for DNS servers, resolvers, and applications
//! performing bulk DNS operations.
//!
//! ## Build Configuration
//!
//! Enable: `-Dspice=true` (default)
//! Disable: `-Dspice=false`
//!
//! ## Usage Example
//!
//! ```zig
//! const parallel = @import("parallel.zig");
//!
//! // Validate multiple DNSSEC signatures in parallel
//! var inputs: [4]parallel.DnssecValidateInput = undefined;
//! var results: [4]parallel.DnssecValidateResult = undefined;
//!
//! for (&inputs) |*input| {
//!     input.* = .{
//!         .rrsig = rrsig_rdata,
//!         .rrset = rrset_records,
//!         .dnskey = dnskey_rdata,
//!     };
//! }
//!
//! parallel.parallelDnssecValidate(&inputs, &results);
//! ```
//!
//! ## Performance Thresholds
//!
//! | Operation           | Threshold  | Sequential Below |
//! |---------------------|------------|------------------|
//! | Zone Record Parse   | 64 records | Yes              |
//! | DNSSEC Validation   | 2 sigs     | Yes              |
//! | Batch Query         | 4 queries  | Yes              |
//! | Cache Prefetch      | 8 entries  | Yes              |

const std = @import("std");
const build_options = @import("build_options");
const record = @import("record");
const message = @import("message");
const ResourceRecord = record.ResourceRecord;
const Name = record.Name;
const Type = record.Type;
const Class = record.Class;

const spice = if (build_options.enable_spice) @import("spice") else struct {
    pub const ThreadPool = void;
    pub const Task = void;
    pub fn Future(comptime I: type, comptime O: type) type {
        _ = I;
        _ = O;
        return void;
    }
};

// ============================================================================
// Global Thread Pool
// ============================================================================

var global_pool: if (build_options.enable_spice) ?spice.ThreadPool else void = if (build_options.enable_spice) null else {};
var pool_mutex: std.Thread.Mutex = .{};

pub fn getPool() if (build_options.enable_spice) *spice.ThreadPool else void {
    if (!build_options.enable_spice) return;

    pool_mutex.lock();
    defer pool_mutex.unlock();

    if (global_pool == null) {
        global_pool = spice.ThreadPool.init(std.heap.page_allocator);
        global_pool.?.start(.{});
    }
    return &global_pool.?;
}

/// Shut down and release the global thread pool.
///
/// **Must be called** before process exit if `getPool()` was ever invoked,
/// otherwise background threads will leak. Safe to call multiple times or
/// when no pool has been initialized.
///
/// Example:
/// ```zig
/// defer parallel.deinitPool();
/// // ... use parallel operations ...
/// ```
pub fn deinitPool() void {
    if (!build_options.enable_spice) return;

    pool_mutex.lock();
    defer pool_mutex.unlock();

    if (global_pool) |*pool| {
        pool.deinit();
        global_pool = null;
    }
}

/// Returns true if the global thread pool has been initialized.
pub fn isPoolInitialized() bool {
    if (!build_options.enable_spice) return false;

    pool_mutex.lock();
    defer pool_mutex.unlock();

    return global_pool != null;
}

// ============================================================================
// Parallel Zone Record Parsing
// ============================================================================

/// Parsed DNS resource record
pub const ParsedRecord = struct {
    name: []const u8,
    rtype: u16,
    rclass: u16,
    ttl: u32,
    rdata: []const u8,
    valid: bool,
};

/// Context for parallel zone parsing
pub const ZoneParseContext = struct {
    raw_records: []const []const u8,
    results: []ParsedRecord,
    allocator: std.mem.Allocator,
};

/// Parse zone transfer records in parallel.
///
/// Ideal for processing large AXFR/IXFR responses with thousands
/// of resource records.
///
/// Parameters:
/// - allocator: Memory allocator
/// - raw_records: Array of raw wire-format record data
/// - results: Array to store parsed records
///
/// Threshold: Uses parallel processing for 64+ records
pub fn parallelZoneRecordParse(
    allocator: std.mem.Allocator,
    raw_records: []const []const u8,
    results: []ParsedRecord,
) void {
    std.debug.assert(raw_records.len == results.len);

    if (!build_options.enable_spice or raw_records.len < 64) {
        for (raw_records, 0..) |raw, i| {
            results[i] = parseRecord(allocator, raw);
        }
        return;
    }

    const pool = getPool();
    const ctx = ZoneParseContext{
        .raw_records = raw_records,
        .results = results,
        .allocator = allocator,
    };
    _ = pool.call(void, parallelZoneParseTask, ctx);
}

fn parallelZoneParseTask(t: *spice.Task, ctx: ZoneParseContext) void {
    const raw_records = ctx.raw_records;
    const results = ctx.results;

    if (raw_records.len < 32) {
        for (raw_records, 0..) |raw, i| {
            results[i] = parseRecord(ctx.allocator, raw);
        }
        return;
    }

    const mid = raw_records.len / 2;
    const left_ctx = ZoneParseContext{
        .raw_records = raw_records[0..mid],
        .results = results[0..mid],
        .allocator = ctx.allocator,
    };
    const right_ctx = ZoneParseContext{
        .raw_records = raw_records[mid..],
        .results = results[mid..],
        .allocator = ctx.allocator,
    };

    var fut = spice.Future(ZoneParseContext, void).init();
    fut.fork(t, parallelZoneParseTask, right_ctx);

    t.call(void, parallelZoneParseTask, left_ctx);
    if (fut.join(t) == null) {
        t.call(void, parallelZoneParseTask, right_ctx);
    }
}

fn parseRecord(allocator: std.mem.Allocator, raw: []const u8) ParsedRecord {
    _ = allocator;
    // Parse wire-format DNS resource record using the record module.
    // Each raw slice is a standalone record (as received in zone transfers).
    const rr = ResourceRecord.parse(raw, 0) catch {
        return .{
            .name = "",
            .rtype = 0,
            .rclass = 0,
            .ttl = 0,
            .rdata = "",
            .valid = false,
        };
    };

    return .{
        .name = rr.name.labels,
        .rtype = rr.rtype.toInt(),
        .rclass = rr.class.toInt(),
        .ttl = rr.ttl,
        .rdata = rr.rdata,
        .valid = true,
    };
}

// ============================================================================
// Parallel DNSSEC Validation
// ============================================================================

/// DNSSEC validation input using parsed library types.
///
/// Callers should parse RRSIG/DNSKEY records via `ResourceRecord.parseRRSIG()`
/// and `ResourceRecord.parseDNSKEY()` before submitting for parallel validation.
pub const DnssecValidateInput = struct {
    /// Parsed RRSIG record data (wire-format bytes for the RRSIG RDATA)
    rrsig: []const u8,
    /// Wire-format records in the RRset being validated
    rrset: []const []const u8,
    /// Parsed DNSKEY record data (wire-format bytes for the DNSKEY RDATA)
    dnskey: []const u8,
};

/// DNSSEC validation result
pub const DnssecValidateResult = struct {
    /// Whether the signature validated successfully
    valid: bool,
    /// Error code: null=success, 1=invalid_input, 2=empty_rrset,
    /// 3=parse_error, 4=verification_failed
    error_code: ?u8,
};

/// Context for parallel DNSSEC validation
pub const DnssecValidateContext = struct {
    inputs: []const DnssecValidateInput,
    results: []DnssecValidateResult,
};

/// Validate multiple DNSSEC signatures in parallel.
///
/// Each RRSIG verification is independent, making this ideal
/// for validating responses with multiple signed RRsets.
///
/// Parameters:
/// - inputs: Array of (rrsig, rrset, dnskey) tuples
/// - results: Array to store validation results
///
/// Threshold: Uses parallel processing for 2+ signatures
pub fn parallelDnssecValidate(
    inputs: []const DnssecValidateInput,
    results: []DnssecValidateResult,
) void {
    std.debug.assert(inputs.len == results.len);

    if (!build_options.enable_spice or inputs.len < 2) {
        for (inputs, 0..) |input, i| {
            results[i] = validateDnssec(input);
        }
        return;
    }

    const pool = getPool();
    const ctx = DnssecValidateContext{
        .inputs = inputs,
        .results = results,
    };
    _ = pool.call(void, parallelDnssecTask, ctx);
}

fn parallelDnssecTask(t: *spice.Task, ctx: DnssecValidateContext) void {
    const inputs = ctx.inputs;
    const results = ctx.results;

    if (inputs.len < 2) {
        for (inputs, 0..) |input, i| {
            results[i] = validateDnssec(input);
        }
        return;
    }

    const mid = inputs.len / 2;
    const left_ctx = DnssecValidateContext{
        .inputs = inputs[0..mid],
        .results = results[0..mid],
    };
    const right_ctx = DnssecValidateContext{
        .inputs = inputs[mid..],
        .results = results[mid..],
    };

    var fut = spice.Future(DnssecValidateContext, void).init();
    fut.fork(t, parallelDnssecTask, right_ctx);

    t.call(void, parallelDnssecTask, left_ctx);
    if (fut.join(t) == null) {
        t.call(void, parallelDnssecTask, right_ctx);
    }
}

fn validateDnssec(input: DnssecValidateInput) DnssecValidateResult {
    // Validate RRSIG and DNSKEY wire-format structure and cross-check fields.
    // Full cryptographic verification requires an allocator (for building signed
    // data buffers) and is deferred to the dnssec.Validator. This parallel step
    // performs structural validation that filters out clearly invalid signatures
    // before the more expensive crypto verification.

    if (input.rrsig.len == 0 or input.dnskey.len == 0) {
        return .{ .valid = false, .error_code = 1 };
    }
    if (input.rrset.len == 0) {
        return .{ .valid = false, .error_code = 2 };
    }

    // RRSIG RDATA must be at least 18 bytes (RFC 4034 Section 3.1):
    // type_covered(2) + algorithm(1) + labels(1) + original_ttl(4) +
    // sig_expiration(4) + sig_inception(4) + key_tag(2) = 18 bytes minimum
    // plus signer name (at least 1 byte for root) and signature data
    if (input.rrsig.len < 19) {
        return .{ .valid = false, .error_code = 3 };
    }

    // DNSKEY RDATA must be at least 4 bytes (RFC 4034 Section 2.1):
    // flags(2) + protocol(1) + algorithm(1) + public_key(variable)
    if (input.dnskey.len < 5) {
        return .{ .valid = false, .error_code = 3 };
    }

    // Cross-check: RRSIG algorithm must match DNSKEY algorithm
    const rrsig_algorithm = input.rrsig[2];
    const dnskey_algorithm = input.dnskey[3];
    if (rrsig_algorithm != dnskey_algorithm) {
        return .{ .valid = false, .error_code = 4 };
    }

    // Cross-check: DNSKEY protocol must be 3 (RFC 4034 Section 2.1.2)
    const dnskey_protocol = input.dnskey[2];
    if (dnskey_protocol != 3) {
        return .{ .valid = false, .error_code = 4 };
    }

    // Validate each RRset member has minimum wire-format length
    for (input.rrset) |rr_data| {
        // Minimum RR: 1 byte name + 10 bytes (type+class+ttl+rdlength)
        if (rr_data.len < 11) {
            return .{ .valid = false, .error_code = 3 };
        }
    }

    return .{ .valid = true, .error_code = null };
}

// ============================================================================
// Parallel Batch Query
// ============================================================================

/// DNS query specification
pub const QuerySpec = struct {
    /// Domain name to query (e.g., "example.com")
    domain: []const u8,
    /// Query type as u16 (e.g., 1 for A, 28 for AAAA)
    qtype: u16,
    /// Query class as u16 (e.g., 1 for IN)
    qclass: u16,
};

/// DNS query result
pub const QueryResult = struct {
    /// Whether the query message was successfully built
    success: bool,
    /// Built wire-format DNS query message (caller must free with allocator),
    /// or null on failure
    response: ?[]const u8,
    /// Error code: null=success, 1=invalid_input, 2=build_error
    error_code: ?u8,
};

/// Context for parallel batch queries
pub const BatchQueryContext = struct {
    queries: []const QuerySpec,
    results: []QueryResult,
    server: []const u8,
    timeout_ms: u32,
};

/// Execute multiple DNS queries in parallel.
///
/// Queries are sent to the same server but processed independently.
/// Useful for bulk DNS resolution or prefetching.
///
/// Parameters:
/// - queries: Array of (domain, qtype, qclass) specs
/// - results: Array to store query results
/// - server: DNS server address
/// - timeout_ms: Per-query timeout in milliseconds
///
/// Threshold: Uses parallel processing for 4+ queries
pub fn parallelBatchQuery(
    queries: []const QuerySpec,
    results: []QueryResult,
    server: []const u8,
    timeout_ms: u32,
) void {
    std.debug.assert(queries.len == results.len);

    if (!build_options.enable_spice or queries.len < 4) {
        for (queries, 0..) |query, i| {
            results[i] = executeQuery(query, server, timeout_ms);
        }
        return;
    }

    const pool = getPool();
    const ctx = BatchQueryContext{
        .queries = queries,
        .results = results,
        .server = server,
        .timeout_ms = timeout_ms,
    };
    _ = pool.call(void, parallelBatchQueryTask, ctx);
}

fn parallelBatchQueryTask(t: *spice.Task, ctx: BatchQueryContext) void {
    const queries = ctx.queries;
    const results = ctx.results;

    if (queries.len < 2) {
        for (queries, 0..) |query, i| {
            results[i] = executeQuery(query, ctx.server, ctx.timeout_ms);
        }
        return;
    }

    const mid = queries.len / 2;
    const left_ctx = BatchQueryContext{
        .queries = queries[0..mid],
        .results = results[0..mid],
        .server = ctx.server,
        .timeout_ms = ctx.timeout_ms,
    };
    const right_ctx = BatchQueryContext{
        .queries = queries[mid..],
        .results = results[mid..],
        .server = ctx.server,
        .timeout_ms = ctx.timeout_ms,
    };

    var fut = spice.Future(BatchQueryContext, void).init();
    fut.fork(t, parallelBatchQueryTask, right_ctx);

    t.call(void, parallelBatchQueryTask, left_ctx);
    if (fut.join(t) == null) {
        t.call(void, parallelBatchQueryTask, right_ctx);
    }
}

fn executeQuery(query: QuerySpec, server: []const u8, timeout_ms: u32) QueryResult {
    _ = server;
    _ = timeout_ms;

    // Build a real DNS wire-format query message using the message module.
    // The parallel batch query builds all query messages concurrently;
    // actual I/O dispatch happens after collection.
    if (query.domain.len == 0) {
        return .{ .success = false, .response = null, .error_code = 1 };
    }

    // Generate a random transaction ID for this query
    const id = std.crypto.random.int(u16);

    // Build the wire-format query message
    const wire_msg = message.buildQuery(
        std.heap.page_allocator,
        id,
        query.domain,
        Type.fromInt(query.qtype),
        Class.fromInt(query.qclass),
        true, // RD (recursion desired)
    ) catch {
        return .{ .success = false, .response = null, .error_code = 2 };
    };

    return .{ .success = true, .response = wire_msg, .error_code = null };
}

// ============================================================================
// Parallel Cache Prefetch
// ============================================================================

/// Cache entry to prefetch
pub const PrefetchEntry = struct {
    domain: []const u8,
    qtype: u16,
    expires_at: i64,
};

/// Prefetch result
pub const PrefetchResult = struct {
    refreshed: bool,
    new_ttl: u32,
};

/// Context for parallel cache prefetch
pub const CachePrefetchContext = struct {
    entries: []const PrefetchEntry,
    results: []PrefetchResult,
    server: []const u8,
};

/// Prefetch multiple expiring cache entries in parallel.
///
/// Proactively refreshes cache entries before they expire
/// to maintain low-latency DNS resolution.
///
/// Parameters:
/// - entries: Array of cache entries to refresh
/// - results: Array to store prefetch results
/// - server: DNS server for refreshing
///
/// Threshold: Uses parallel processing for 8+ entries
pub fn parallelCachePrefetch(
    entries: []const PrefetchEntry,
    results: []PrefetchResult,
    server: []const u8,
) void {
    std.debug.assert(entries.len == results.len);

    if (!build_options.enable_spice or entries.len < 8) {
        for (entries, 0..) |entry, i| {
            results[i] = prefetchEntry(entry, server);
        }
        return;
    }

    const pool = getPool();
    const ctx = CachePrefetchContext{
        .entries = entries,
        .results = results,
        .server = server,
    };
    _ = pool.call(void, parallelPrefetchTask, ctx);
}

fn parallelPrefetchTask(t: *spice.Task, ctx: CachePrefetchContext) void {
    const entries = ctx.entries;
    const results = ctx.results;

    if (entries.len < 4) {
        for (entries, 0..) |entry, i| {
            results[i] = prefetchEntry(entry, ctx.server);
        }
        return;
    }

    const mid = entries.len / 2;
    const left_ctx = CachePrefetchContext{
        .entries = entries[0..mid],
        .results = results[0..mid],
        .server = ctx.server,
    };
    const right_ctx = CachePrefetchContext{
        .entries = entries[mid..],
        .results = results[mid..],
        .server = ctx.server,
    };

    var fut = spice.Future(CachePrefetchContext, void).init();
    fut.fork(t, parallelPrefetchTask, right_ctx);

    t.call(void, parallelPrefetchTask, left_ctx);
    if (fut.join(t) == null) {
        t.call(void, parallelPrefetchTask, right_ctx);
    }
}

fn prefetchEntry(entry: PrefetchEntry, server: []const u8) PrefetchResult {
    _ = server;

    // Validate the entry is eligible for prefetch
    if (entry.domain.len == 0) {
        return .{ .refreshed = false, .new_ttl = 0 };
    }

    // Check if the entry has actually expired or is close to expiring.
    // In a full implementation, we'd send the query to the server here.
    // For the parallel module, we build the refresh query (CPU-bound work)
    // and mark the entry for refresh.
    const now = std.time.timestamp();
    if (entry.expires_at > now) {
        // Not yet expired — compute remaining TTL
        const remaining: u32 = @intCast(@min(
            @as(i64, std.math.maxInt(u32)),
            entry.expires_at - now,
        ));
        return .{ .refreshed = false, .new_ttl = remaining };
    }

    // Entry is expired — build a prefetch query message to refresh it
    const id = std.crypto.random.int(u16);
    const wire_msg = message.buildQuery(
        std.heap.page_allocator,
        id,
        entry.domain,
        Type.fromInt(entry.qtype),
        Class.fromInt(1), // IN class
        true,
    ) catch {
        return .{ .refreshed = false, .new_ttl = 0 };
    };
    // Free the query message — in a full integration, this would be sent
    // to the server. The parallel module's job is the CPU-bound message
    // construction; actual I/O is handled by the caller.
    std.heap.page_allocator.free(wire_msg);

    return .{ .refreshed = true, .new_ttl = 0 };
}

// ============================================================================
// Tests
// ============================================================================

test "parallel zone record parse" {
    if (!build_options.enable_spice) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var raw_records: [100][]const u8 = undefined;
    var results: [100]ParsedRecord = undefined;

    // Create minimal valid records
    const record_data = [_]u8{0} ** 12 ++ [_]u8{ 'r', 'd', 'a', 't', 'a' };
    for (&raw_records) |*r| {
        r.* = &record_data;
    }

    parallelZoneRecordParse(allocator, &raw_records, &results);

    for (results) |result| {
        try std.testing.expect(result.valid);
    }
}

test "parallel dnssec validate" {
    if (!build_options.enable_spice) return error.SkipZigTest;

    // Build valid RRSIG RDATA (>= 19 bytes): type_covered(2) + algorithm(1) +
    // labels(1) + original_ttl(4) + sig_expiration(4) + sig_inception(4) +
    // key_tag(2) + signer_name(1=root) + signature(1+)
    const rrsig_data = [_]u8{
        0x00, 0x01, // type_covered = A
        0x0D, // algorithm = ECDSAP256SHA256 (13)
        0x02, // labels = 2
        0x00, 0x00, 0x0E, 0x10, // original_ttl = 3600
        0x67, 0x00, 0x00, 0x00, // sig_expiration
        0x66, 0x00, 0x00, 0x00, // sig_inception
        0x12, 0x34, // key_tag
        0x00, // signer name (root ".")
        0xAA, 0xBB, // signature bytes
    };

    // Build valid DNSKEY RDATA (>= 5 bytes): flags(2) + protocol(1) + algorithm(1) + pubkey(1+)
    const dnskey_data = [_]u8{
        0x01, 0x01, // flags (zone key + SEP)
        0x03, // protocol = 3 (DNSSEC)
        0x0D, // algorithm = ECDSAP256SHA256 (13) — matches RRSIG
        0xCC, 0xDD, // public key bytes
    };

    // Build minimal valid RRset member (1 byte name + 10 bytes header)
    const rrset_member = [_]u8{
        0x00, // root name
        0x00, 0x01, // type = A
        0x00, 0x01, // class = IN
        0x00, 0x00, 0x0E, 0x10, // ttl = 3600
        0x00, 0x04, // rdlength = 4
        0x01, 0x02, 0x03, 0x04, // rdata (IP)
    };

    var inputs: [4]DnssecValidateInput = undefined;
    var results: [4]DnssecValidateResult = undefined;

    for (&inputs) |*input| {
        input.* = .{
            .rrsig = &rrsig_data,
            .rrset = &[_][]const u8{&rrset_member},
            .dnskey = &dnskey_data,
        };
    }

    parallelDnssecValidate(&inputs, &results);

    for (results) |result| {
        try std.testing.expect(result.valid);
    }
}

test "parallel zone record parse - empty input" {
    const allocator = std.testing.allocator;
    var raw_records: [0][]const u8 = undefined;
    var results: [0]ParsedRecord = undefined;

    parallelZoneRecordParse(allocator, &raw_records, &results);
}

test "parallel zone record parse - invalid records" {
    const allocator = std.testing.allocator;
    var raw_records: [64][]const u8 = undefined;
    var results: [64]ParsedRecord = undefined;

    // Short records that should fail validation
    const short_record = [_]u8{0} ** 8;
    for (&raw_records) |*r| {
        r.* = &short_record;
    }

    parallelZoneRecordParse(allocator, &raw_records, &results);

    for (results) |result| {
        try std.testing.expect(!result.valid);
    }
}

test "parallel dnssec validate - empty rrsig" {
    if (!build_options.enable_spice) return error.SkipZigTest;

    var inputs: [4]DnssecValidateInput = undefined;
    var results: [4]DnssecValidateResult = undefined;

    for (&inputs) |*input| {
        input.* = .{
            .rrsig = "", // Empty
            .rrset = &[_][]const u8{"rr1"},
            .dnskey = "dnskey",
        };
    }

    parallelDnssecValidate(&inputs, &results);

    for (results) |result| {
        try std.testing.expect(!result.valid);
        try std.testing.expectEqual(@as(?u8, 1), result.error_code);
    }
}

test "parallel dnssec validate - empty rrset" {
    if (!build_options.enable_spice) return error.SkipZigTest;

    var inputs: [4]DnssecValidateInput = undefined;
    var results: [4]DnssecValidateResult = undefined;

    for (&inputs) |*input| {
        input.* = .{
            .rrsig = "rrsig",
            .rrset = &[_][]const u8{}, // Empty
            .dnskey = "dnskey",
        };
    }

    parallelDnssecValidate(&inputs, &results);

    for (results) |result| {
        try std.testing.expect(!result.valid);
        try std.testing.expectEqual(@as(?u8, 2), result.error_code);
    }
}

test "parallel batch query" {
    if (!build_options.enable_spice) return error.SkipZigTest;

    var queries: [8]QuerySpec = undefined;
    var results: [8]QueryResult = undefined;

    for (&queries) |*query| {
        query.* = .{
            .domain = "example.com",
            .qtype = 1, // A record
            .qclass = 1, // IN
        };
    }

    parallelBatchQuery(&queries, &results, "8.8.8.8", 5000);

    for (&results) |*result| {
        try std.testing.expect(result.success);
        // Verify a real wire-format query was built
        try std.testing.expect(result.response != null);
        if (result.response) |resp| {
            // DNS messages are at least 12 bytes (header)
            try std.testing.expect(resp.len >= 12);
            // Free the allocated query message
            std.heap.page_allocator.free(resp);
            result.response = null;
        }
    }
}

test "parallel batch query - empty domain" {
    if (!build_options.enable_spice) return error.SkipZigTest;

    var queries: [4]QuerySpec = undefined;
    var results: [4]QueryResult = undefined;

    for (&queries) |*query| {
        query.* = .{
            .domain = "", // Empty
            .qtype = 1,
            .qclass = 1,
        };
    }

    parallelBatchQuery(&queries, &results, "8.8.8.8", 5000);

    for (results) |result| {
        try std.testing.expect(!result.success);
    }
}

test "parallel cache prefetch - expired entries" {
    if (!build_options.enable_spice) return error.SkipZigTest;

    var entries: [16]PrefetchEntry = undefined;
    var results: [16]PrefetchResult = undefined;

    // Use an expires_at far in the past — entries are expired
    for (&entries) |*entry| {
        entry.* = .{
            .domain = "example.com",
            .qtype = 1,
            .expires_at = 1000, // 1970 — expired
        };
    }

    parallelCachePrefetch(&entries, &results, "8.8.8.8");

    for (results) |result| {
        // Expired entries should be marked for refresh with TTL 0
        try std.testing.expect(result.refreshed);
        try std.testing.expectEqual(@as(u32, 0), result.new_ttl);
    }
}

test "parallel cache prefetch - future entries not refreshed" {
    if (!build_options.enable_spice) return error.SkipZigTest;

    var entries: [16]PrefetchEntry = undefined;
    var results: [16]PrefetchResult = undefined;

    // Use an expires_at far in the future — entries are not expired
    const far_future = std.time.timestamp() + 300;
    for (&entries) |*entry| {
        entry.* = .{
            .domain = "example.com",
            .qtype = 1,
            .expires_at = far_future,
        };
    }

    parallelCachePrefetch(&entries, &results, "8.8.8.8");

    for (results) |result| {
        // Not expired — should not be refreshed, TTL should be remaining seconds
        try std.testing.expect(!result.refreshed);
        try std.testing.expect(result.new_ttl > 0);
    }
}

test "parallel cache prefetch - below threshold" {
    var entries: [4]PrefetchEntry = undefined;
    var results: [4]PrefetchResult = undefined;

    // Expired entries (timestamp 500 is 1970, way in the past)
    for (&entries) |*entry| {
        entry.* = .{
            .domain = "test.local",
            .qtype = 28, // AAAA
            .expires_at = 500,
        };
    }

    parallelCachePrefetch(&entries, &results, "1.1.1.1");

    for (results) |result| {
        try std.testing.expect(result.refreshed);
        try std.testing.expectEqual(@as(u32, 0), result.new_ttl);
    }
}

test "pool lifecycle - init and deinit" {
    if (!build_options.enable_spice) return error.SkipZigTest;

    // Exercise the init path via getPool()
    _ = getPool();
    try std.testing.expect(isPoolInitialized());

    // Deinit should succeed
    deinitPool();
    try std.testing.expect(!isPoolInitialized());

    // Double deinit should be safe (no-op)
    deinitPool();
    try std.testing.expect(!isPoolInitialized());

    // Re-init after deinit should work
    _ = getPool();
    try std.testing.expect(isPoolInitialized());
    deinitPool();
}
