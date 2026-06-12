// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! DNS Zone Transfer (AXFR/IXFR)
//!
//! RFC 5936: DNS Zone Transfer Protocol (AXFR)
//! RFC 1995: Incremental Zone Transfer in DNS (IXFR)
//!
//! Zone transfers are used to replicate DNS zone data between servers.
//! - AXFR: Full zone transfer - downloads complete zone
//! - IXFR: Incremental zone transfer - downloads only changes since a serial
//!
//! Key characteristics:
//! - Uses TCP transport (required for large transfers)
//! - Multiple DNS messages for large zones
//! - Transfer bounded by SOA records (starts and ends with SOA)
//! - AXFR returns all records; IXFR returns differences

const std = @import("std");
const parallel = @import("parallel");
const net = @import("net_compat");
const io = @import("transport_io");

/// Wall-clock milliseconds. std.time.milliTimestamp was removed in Zig 0.16;
/// axfr()/ixfr() are public but never referenced from a compiled path, so this
/// breakage stayed dormant until the SR-6/SR-7 deadline work and the
/// force-reference test below exercised them.
inline fn timeMilli() i64 {
    const io_inst = std.Io.Threaded.global_single_threaded.io();
    return std.Io.Clock.Timestamp.now(io_inst, .real).raw.toMilliseconds();
}

/// SOA record type value (RFC 1035 Section 3.2.2)
/// Used to identify SOA records in zone transfer boundary detection.
const soa_rtype: u16 = 6;

/// Zone transfer types
pub const TransferType = enum(u16) {
    /// RFC 5936: Full zone transfer
    axfr = 252,
    /// RFC 1995: Incremental zone transfer
    ixfr = 251,
};

/// Zone transfer configuration
pub const ZoneTransferConfig = struct {
    /// Maximum zone size (number of records)
    max_records: usize = 100000,
    /// Timeout for complete transfer (milliseconds)
    timeout_ms: u32 = 300000, // 5 minutes
    /// TCP receive buffer size
    buffer_size: usize = 65535,
    /// Whether to verify SOA serials
    verify_serial: bool = true,
    /// TSIG key for authenticated transfers (optional)
    tsig_key: ?TsigKey = null,

    // SECURITY: Authentication enforcement options (SEC-001)

    /// If true, zone transfers without TSIG authentication will fail.
    /// SECURITY (SEC-C28): Defaults to true to enforce authenticated zone transfers.
    /// Unauthenticated AXFR/IXFR can expose full zone contents to unauthorized parties.
    /// Set to false explicitly only in trusted networks or testing environments.
    require_auth: bool = true,

    /// If true, log a warning when performing unauthenticated zone transfers.
    /// Default true to alert operators of potential security risks.
    warn_unauthenticated: bool = true,

    /// Optional callback for security warnings.
    /// Called when unauthenticated transfers are attempted (if warn_unauthenticated is true).
    security_warning_callback: ?*const fn ([]const u8) void = null,
};

/// TSIG key for authenticated zone transfers
pub const TsigKey = struct {
    name: []const u8,
    algorithm: []const u8,
    secret: []const u8,

    /// Zero secret bytes before releasing. Uses volatile write to prevent
    /// compiler from optimizing away the zeroing (CWE-244).
    pub fn deinit(self: *TsigKey) void {
        if (self.secret.len > 0) {
            const ptr: [*]volatile u8 = @constCast(@volatileCast(self.secret.ptr));
            for (0..self.secret.len) |i| {
                ptr[i] = 0;
            }
        }
    }
};

/// Represents a DNS resource record in a zone
pub const ZoneRecord = struct {
    /// Record owner name
    name: []const u8,
    /// Record type (A, AAAA, MX, etc.)
    rtype: u16,
    /// Record class (usually IN)
    rclass: u16,
    /// Time-to-live
    ttl: u32,
    /// Record data
    rdata: []const u8,
};

/// Represents an entire DNS zone
pub const Zone = struct {
    allocator: std.mem.Allocator,
    /// Zone apex name
    name: []const u8,
    /// SOA record (zone metadata)
    soa: ?SoaRecord,
    /// All records in the zone
    records: std.ArrayList(ZoneRecord),
    /// Zone serial number (from SOA)
    serial: u32,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, name: []const u8) Self {
        return Self{
            .allocator = allocator,
            .name = name,
            .soa = null,
            .records = .empty,
            .serial = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.records.items) |record| {
            self.allocator.free(record.name);
            self.allocator.free(record.rdata);
        }
        self.records.deinit(self.allocator);
        if (self.soa) |soa| {
            self.allocator.free(soa.mname);
            self.allocator.free(soa.rname);
        }
    }

    pub fn addRecord(self: *Self, record: ZoneRecord) !void {
        const name_copy = try self.allocator.dupe(u8, record.name);
        errdefer self.allocator.free(name_copy);
        const rdata_copy = try self.allocator.dupe(u8, record.rdata);
        errdefer self.allocator.free(rdata_copy);

        try self.records.append(self.allocator, .{
            .name = name_copy,
            .rtype = record.rtype,
            .rclass = record.rclass,
            .ttl = record.ttl,
            .rdata = rdata_copy,
        });
    }

    pub fn recordCount(self: Self) usize {
        return self.records.items.len;
    }
};

/// SOA record data
pub const SoaRecord = struct {
    /// Primary name server
    mname: []const u8,
    /// Responsible person mailbox
    rname: []const u8,
    /// Zone serial number
    serial: u32,
    /// Refresh interval (seconds)
    refresh: u32,
    /// Retry interval (seconds)
    retry: u32,
    /// Expiry time (seconds)
    expire: u32,
    /// Minimum TTL (seconds)
    minimum: u32,
};

/// Zone transfer result
pub const TransferResult = struct {
    /// Whether transfer was successful
    success: bool,
    /// The transferred zone (if successful)
    zone: ?Zone,
    /// Number of records transferred
    record_count: usize,
    /// Number of messages received
    message_count: usize,
    /// Transfer duration in milliseconds
    duration_ms: u64,
    /// Error message (if failed)
    error_message: ?[]const u8,
};

/// IXFR change set
pub const IxfrChangeset = struct {
    /// Starting serial (before changes)
    old_serial: u32,
    /// Ending serial (after changes)
    new_serial: u32,
    /// Records to delete
    deletions: std.ArrayList(ZoneRecord),
    /// Records to add
    additions: std.ArrayList(ZoneRecord),

    const Self = @This();

    pub fn init(_: std.mem.Allocator, old_serial: u32, new_serial: u32) Self {
        return Self{
            .old_serial = old_serial,
            .new_serial = new_serial,
            .deletions = .empty,
            .additions = .empty,
        };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        for (self.deletions.items) |r| {
            allocator.free(r.name);
            allocator.free(r.rdata);
        }
        self.deletions.deinit(allocator);
        for (self.additions.items) |r| {
            allocator.free(r.name);
            allocator.free(r.rdata);
        }
        self.additions.deinit(allocator);
    }
};

/// Hard cap on the number of AXFR response messages, independent of the
/// per-message and per-record limits, to bound a server that withholds the
/// closing SOA while trickling empty messages (SEC-SR-6).
const max_transfer_messages: usize = 1_000_000;

/// True when the wall-clock transfer budget (config.timeout_ms) is exhausted.
/// The socket RCVTIMEO only bounds a single recv; this bounds the whole
/// transfer so a slow-drip server cannot hang the loop indefinitely (SEC-SR-6).
fn transferDeadlineExceeded(start_ms: i64, now_ms: i64, timeout_ms: u32) bool {
    if (timeout_ms == 0) return false; // 0 == no deadline
    return now_ms - start_ms > @as(i64, timeout_ms);
}

/// RFC 1982 serial-number comparison: returns true iff `a` is greater than `b`
/// in 32-bit serial arithmetic. Used to reject IXFR serial downgrades (SEC-SR-7).
fn serialGreater(a: u32, b: u32) bool {
    return a != b and (a -% b) < 0x8000_0000;
}

/// Zone Transfer Client
pub const ZoneTransferClient = struct {
    allocator: std.mem.Allocator,
    config: ZoneTransferConfig,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: ZoneTransferConfig) Self {
        return Self{
            .allocator = allocator,
            .config = config,
        };
    }

    /// Perform AXFR (full zone transfer)
    /// RFC 5936: Returns all records in the zone
    ///
    /// SECURITY: Zone transfers can expose sensitive DNS data. Consider:
    /// - Using TSIG authentication (set tsig_key in config)
    /// - Setting require_auth=true to enforce authentication
    pub fn axfr(self: *Self, zone_name: []const u8, server_addr: []const u8, port: u16) !TransferResult {
        // SECURITY: Check authentication requirements (SEC-001)
        if (self.config.tsig_key == null) {
            if (self.config.require_auth) {
                return TransferResult{
                    .success = false,
                    .zone = null,
                    .record_count = 0,
                    .message_count = 0,
                    .duration_ms = 0,
                    .error_message = "SECURITY: Zone transfer requires authentication but no TSIG key configured",
                };
            }
            if (self.config.warn_unauthenticated) {
                const warning = "SECURITY WARNING: Performing unauthenticated AXFR zone transfer. " ++
                    "Consider configuring TSIG authentication for zone transfers. " ++
                    "Set require_auth=true to enforce authentication. (CWE-306)";
                if (self.config.security_warning_callback) |callback| {
                    callback(warning);
                }
                // Note: In production, this would also log via std.log or similar
            }
        }

        const start_time = timeMilli();
        var zone = Zone.init(self.allocator, zone_name);
        errdefer zone.deinit();

        // Connect via TCP (net_compat + transport_io, like the TCP transport;
        // std.net was removed in Zig 0.16). Per-op timeouts replace SO_RCVTIMEO.
        const address = try net.Address.parseIp4(server_addr, port);
        const sock = try net.socket(
            address.any.family,
            std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK,
            std.os.linux.IPPROTO.TCP,
        );
        defer net.close(sock);
        try io.connectWithTimeout(sock, address, self.config.timeout_ms);

        // Build and send AXFR query
        const query = try self.buildTransferQuery(zone_name, .axfr);
        defer self.allocator.free(query);

        try self.sendTcpMessage(sock, query);

        // Receive and parse responses
        var message_count: usize = 0;
        var first_soa_seen = false;
        var second_soa_seen = false;

        while (!second_soa_seen) {
            // SEC-SR-6: enforce the transfer-wide deadline and a hard message
            // cap so a server that never sends the closing SOA (e.g. trickling
            // empty ancount=0 messages, which never trip max_records) cannot
            // hang the loop indefinitely.
            if (transferDeadlineExceeded(start_time, timeMilli(), self.config.timeout_ms)) {
                zone.deinit();
                return TransferResult{
                    .success = false,
                    .zone = null,
                    .record_count = 0,
                    .message_count = message_count,
                    .duration_ms = @intCast(@max(0, timeMilli() - start_time)),
                    .error_message = "Transfer deadline exceeded",
                };
            }

            const response = try self.receiveTcpMessage(sock);
            defer self.allocator.free(response);
            message_count += 1;

            if (message_count > max_transfer_messages) {
                zone.deinit();
                return TransferResult{
                    .success = false,
                    .zone = null,
                    .record_count = 0,
                    .message_count = message_count,
                    .duration_ms = @intCast(@max(0, timeMilli() - start_time)),
                    .error_message = "Too many transfer messages",
                };
            }

            // Parse response and extract records
            const records = try self.parseTransferResponse(response);
            defer self.allocator.free(records);

            for (records) |record| {
                // Check for SOA records (transfer boundaries)
                if (record.rtype == soa_rtype) {
                    if (!first_soa_seen) {
                        first_soa_seen = true;
                        zone.soa = try self.parseSoaRdata(record.rdata);
                        zone.serial = zone.soa.?.serial;
                    } else {
                        second_soa_seen = true;
                        break;
                    }
                }

                try zone.addRecord(record);

                if (zone.recordCount() > self.config.max_records) {
                    // Returning a value (not an error) does not fire the
                    // function-level `errdefer zone.deinit()`, so free the
                    // accumulated zone explicitly to avoid a leak, matching the
                    // deadline/message-cap branches above (CWE-401).
                    const count = zone.recordCount();
                    zone.deinit();
                    return TransferResult{
                        .success = false,
                        .zone = null,
                        .record_count = count,
                        .message_count = message_count,
                        .duration_ms = @intCast(@max(0, timeMilli() - start_time)),
                        .error_message = "Zone too large",
                    };
                }
            }
        }

        return TransferResult{
            .success = true,
            .zone = zone,
            .record_count = zone.recordCount(),
            .message_count = message_count,
            .duration_ms = @intCast(@max(0, timeMilli() - start_time)),
            .error_message = null,
        };
    }

    /// Perform IXFR (incremental zone transfer)
    /// RFC 1995: Returns only changes since the specified serial
    ///
    /// SECURITY: Zone transfers can expose sensitive DNS data. Consider:
    /// - Using TSIG authentication (set tsig_key in config)
    /// - Setting require_auth=true to enforce authentication
    pub fn ixfr(self: *Self, zone_name: []const u8, current_serial: u32, server_addr: []const u8, port: u16) !IxfrResult {
        // SECURITY: Check authentication requirements (SEC-001)
        if (self.config.tsig_key == null) {
            if (self.config.require_auth) {
                return IxfrResult{
                    .success = false,
                    .is_full_zone = false,
                    .changeset = null,
                    .new_serial = current_serial,
                    .duration_ms = 0,
                };
            }
            if (self.config.warn_unauthenticated) {
                const warning = "SECURITY WARNING: Performing unauthenticated IXFR zone transfer. " ++
                    "Consider configuring TSIG authentication for zone transfers. " ++
                    "Set require_auth=true to enforce authentication. (CWE-306)";
                if (self.config.security_warning_callback) |callback| {
                    callback(warning);
                }
            }
        }

        const start_time = timeMilli();

        // Connect via TCP (net_compat + transport_io; std.net removed in 0.16).
        const address = try net.Address.parseIp4(server_addr, port);
        const sock = try net.socket(
            address.any.family,
            std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK,
            std.os.linux.IPPROTO.TCP,
        );
        defer net.close(sock);
        try io.connectWithTimeout(sock, address, self.config.timeout_ms);

        // Build and send IXFR query with SOA showing our current serial
        const query = try self.buildIxfrQuery(zone_name, current_serial);
        defer self.allocator.free(query);

        try self.sendTcpMessage(sock, query);

        // Receive response
        const response = try self.receiveTcpMessage(sock);
        defer self.allocator.free(response);

        // Parse IXFR response
        // Server may respond with:
        // 1. Full AXFR if IXFR not supported or serial gap too large
        // 2. Incremental changes (deletions followed by additions)
        // 3. Just SOA if we're already up to date

        const records = try self.parseTransferResponse(response);
        defer self.allocator.free(records);

        // Check if server returned AXFR instead of IXFR
        if (self.isAxfrResponse(records)) {
            return IxfrResult{
                .success = true,
                .is_full_zone = true,
                .changeset = null,
                .new_serial = if (records.len > 0 and records[0].rtype == soa_rtype)
                    self.extractSerial(records[0].rdata)
                else
                    current_serial,
                .duration_ms = @intCast(@max(0, timeMilli() - start_time)),
            };
        }

        // Parse incremental changes
        var changeset = IxfrChangeset.init(self.allocator, current_serial, 0);
        errdefer changeset.deinit(self.allocator);

        try self.parseIxfrChanges(records, &changeset);

        // SEC-SR-7: reject a serial downgrade. A malicious primary must not be
        // able to roll the zone backwards via IXFR. Only enforced when the
        // server actually supplied a new SOA serial; an equal serial (already
        // up to date) is permitted, only a strictly older serial is rejected.
        if (self.config.verify_serial and
            records.len > 0 and records[0].rtype == soa_rtype and
            serialGreater(current_serial, changeset.new_serial))
        {
            return error.SerialNotAdvanced;
        }

        return IxfrResult{
            .success = true,
            .is_full_zone = false,
            .changeset = changeset,
            .new_serial = changeset.new_serial,
            .duration_ms = @intCast(@max(0, timeMilli() - start_time)),
        };
    }

    /// Build AXFR/IXFR query message
    ///
    /// SECURITY: Requires OS entropy for secure transaction ID generation.
    fn buildTransferQuery(self: *Self, zone_name: []const u8, transfer_type: TransferType) ![]u8 {
        var buffer: std.ArrayList(u8) = .empty;
        errdefer buffer.deinit(self.allocator);

        // Generate random ID
        // SECURITY: Fail-fast if entropy unavailable - predictable IDs enable cache poisoning
        var seed: u64 = undefined;
        const io_inst = std.Io.Threaded.global_single_threaded.io();
        std.Io.randomSecure(io_inst, std.mem.asBytes(&seed)) catch {
            return error.EntropyUnavailable;
        };
        var prng = std.Random.DefaultPrng.init(seed);
        const id = prng.random().int(u16);

        // Header
        try buffer.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, id))); // ID
        try buffer.appendSlice(self.allocator, &[_]u8{ 0x00, 0x00 }); // Flags: standard query
        try buffer.appendSlice(self.allocator, &[_]u8{ 0x00, 0x01 }); // QDCOUNT: 1
        try buffer.appendSlice(self.allocator, &[_]u8{ 0x00, 0x00 }); // ANCOUNT: 0
        try buffer.appendSlice(self.allocator, &[_]u8{ 0x00, 0x00 }); // NSCOUNT: 0
        try buffer.appendSlice(self.allocator, &[_]u8{ 0x00, 0x00 }); // ARCOUNT: 0

        // Question section
        try self.encodeName(&buffer, zone_name);
        try buffer.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, @intFromEnum(transfer_type))));
        try buffer.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, 1))); // IN class

        return buffer.toOwnedSlice(self.allocator);
    }

    /// Build IXFR query with authority section containing our SOA
    ///
    /// SECURITY: Requires OS entropy for secure transaction ID generation.
    fn buildIxfrQuery(self: *Self, zone_name: []const u8, current_serial: u32) ![]u8 {
        var buffer: std.ArrayList(u8) = .empty;
        errdefer buffer.deinit(self.allocator);

        // Generate random ID
        // SECURITY: Fail-fast if entropy unavailable - predictable IDs enable cache poisoning
        var seed: u64 = undefined;
        const io_inst = std.Io.Threaded.global_single_threaded.io();
        std.Io.randomSecure(io_inst, std.mem.asBytes(&seed)) catch {
            return error.EntropyUnavailable;
        };
        var prng = std.Random.DefaultPrng.init(seed);
        const id = prng.random().int(u16);

        // Header (with NSCOUNT=1 for our SOA)
        try buffer.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, id)));
        try buffer.appendSlice(self.allocator, &[_]u8{ 0x00, 0x00 }); // Flags
        try buffer.appendSlice(self.allocator, &[_]u8{ 0x00, 0x01 }); // QDCOUNT: 1
        try buffer.appendSlice(self.allocator, &[_]u8{ 0x00, 0x00 }); // ANCOUNT: 0
        try buffer.appendSlice(self.allocator, &[_]u8{ 0x00, 0x01 }); // NSCOUNT: 1 (our SOA)
        try buffer.appendSlice(self.allocator, &[_]u8{ 0x00, 0x00 }); // ARCOUNT: 0

        // Question section
        try self.encodeName(&buffer, zone_name);
        try buffer.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, 251))); // IXFR
        try buffer.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, 1))); // IN

        // Authority section with our current SOA
        try self.encodeName(&buffer, zone_name);
        try buffer.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, 6))); // SOA
        try buffer.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, 1))); // IN
        try buffer.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u32, 0))); // TTL

        // Minimal SOA RDATA
        const soa_rdata = try self.buildMinimalSoaRdata(zone_name, current_serial);
        defer self.allocator.free(soa_rdata);

        try buffer.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, @intCast(soa_rdata.len))));
        try buffer.appendSlice(self.allocator, soa_rdata);

        return buffer.toOwnedSlice(self.allocator);
    }

    fn buildMinimalSoaRdata(self: *Self, zone_name: []const u8, serial: u32) ![]u8 {
        var buffer: std.ArrayList(u8) = .empty;
        errdefer buffer.deinit(self.allocator);

        // MNAME (primary NS) - use zone name as placeholder
        try self.encodeName(&buffer, zone_name);
        // RNAME (admin email)
        try self.encodeName(&buffer, zone_name);
        // Serial
        try buffer.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u32, serial)));
        // Refresh, Retry, Expire, Minimum (placeholder values)
        try buffer.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u32, 3600)));
        try buffer.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u32, 600)));
        try buffer.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u32, 604800)));
        try buffer.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u32, 86400)));

        return buffer.toOwnedSlice(self.allocator);
    }

    fn encodeName(self: *Self, buffer: *std.ArrayList(u8), name: []const u8) !void {
        var iter = std.mem.splitScalar(u8, name, '.');
        while (iter.next()) |label| {
            if (label.len == 0) continue;
            // RFC 1035: max label length is 63 octets
            if (label.len > 63) return error.InvalidName;
            try buffer.append(self.allocator, @intCast(label.len));
            try buffer.appendSlice(self.allocator, label);
        }
        try buffer.append(self.allocator, 0); // Root label
    }

    fn sendTcpMessage(self: *Self, sock: std.posix.socket_t, message: []const u8) !void {
        // TCP DNS uses 2-byte length prefix; message must fit in u16
        if (message.len > std.math.maxInt(u16)) return error.MessageTooLarge;
        var length_prefix: [2]u8 = undefined;
        std.mem.writeInt(u16, &length_prefix, @intCast(message.len), .big);

        // writeAllWithTimeout ensures all bytes are sent and bounds the write.
        try io.writeAllWithTimeout(sock, &length_prefix, self.config.timeout_ms);
        try io.writeAllWithTimeout(sock, message, self.config.timeout_ms);
    }

    fn receiveTcpMessage(self: *Self, sock: std.posix.socket_t) ![]u8 {
        // Read exactly 2 bytes for the length prefix. readExactWithTimeout
        // loops internally (a single read may return 1 byte on a slow link)
        // and returns error.ConnectionClosed on EOF (SEC-C33/QH-08).
        var length_buf: [2]u8 = undefined;
        try io.readExactWithTimeout(sock, &length_buf, self.config.timeout_ms);

        const message_len = std.mem.readInt(u16, &length_buf, .big);
        if (message_len > self.config.buffer_size) {
            return error.MessageTooLarge;
        }

        // Read message
        const message = try self.allocator.alloc(u8, message_len);
        errdefer self.allocator.free(message);

        try io.readExactWithTimeout(sock, message, self.config.timeout_ms);

        return message;
    }

    fn parseTransferResponse(self: *Self, response: []const u8) ![]ZoneRecord {
        var records: std.ArrayList(ZoneRecord) = .empty;
        errdefer {
            for (records.items) |r| {
                self.allocator.free(r.name);
                self.allocator.free(r.rdata);
            }
            records.deinit(self.allocator);
        }

        if (response.len < 12) return error.InvalidResponse;

        // Parse header
        const qdcount = std.mem.readInt(u16, response[4..6], .big);
        const ancount = std.mem.readInt(u16, response[6..8], .big);

        // Validate qdcount (SEC-NEW-03b): must be 0 or 1
        if (qdcount > 1) return error.InvalidResponse;

        // Skip header and question section
        var offset: usize = 12;

        // Skip question section with bounds checking (SEC-NEW-02b)
        if (qdcount >= 1) {
            while (offset < response.len and response[offset] != 0) {
                if (response[offset] & 0xC0 == 0xC0) {
                    if (offset + 2 > response.len) return error.InvalidResponse;
                    offset += 2;
                    break;
                }
                const label_len = response[offset];
                if (offset + 1 + label_len > response.len) return error.InvalidResponse;
                offset += 1 + label_len;
            }
            if (offset < response.len and response[offset] == 0) offset += 1;
            if (offset + 4 > response.len) return error.InvalidResponse;
            offset += 4; // QTYPE + QCLASS
        }

        // Parse answer records.
        // Bound is `<=` so a final record whose 10-byte fixed header ends
        // exactly at response.len is still considered (SEC-SR-10); the inner
        // checks below reject anything genuinely truncated.
        var count: u16 = 0;
        while (count < ancount and offset + 10 <= response.len) {
            // Parse name (allocates name_result.name)
            const name_result = try self.parseName(response, offset);
            offset = name_result.new_offset;

            // On truncation we break out and keep what we parsed so far; the
            // current record's name is not appended, so free it explicitly —
            // errdefer does not fire on `break` (SEC-SR-9).
            if (offset + 10 > response.len) {
                self.allocator.free(name_result.name);
                break;
            }

            const rtype = std.mem.readInt(u16, response[offset..][0..2], .big);
            const rclass = std.mem.readInt(u16, response[offset + 2 ..][0..2], .big);
            const ttl = std.mem.readInt(u32, response[offset + 4 ..][0..4], .big);
            const rdlength = std.mem.readInt(u16, response[offset + 8 ..][0..2], .big);
            offset += 10;

            if (offset + rdlength > response.len) {
                self.allocator.free(name_result.name);
                break;
            }

            // Cover the fallible dupe/append below; on error the name is freed
            // here and the already-appended records by the function-level errdefer.
            errdefer self.allocator.free(name_result.name);

            const rdata = try self.allocator.dupe(u8, response[offset .. offset + rdlength]);
            errdefer self.allocator.free(rdata);

            try records.append(self.allocator, .{
                .name = name_result.name,
                .rtype = rtype,
                .rclass = rclass,
                .ttl = ttl,
                .rdata = rdata,
            });

            offset += rdlength;
            count += 1;
        }

        return records.toOwnedSlice(self.allocator);
    }

    const NameResult = struct {
        name: []const u8,
        new_offset: usize,
    };

    /// Maximum compression pointer hops to prevent infinite loops (RFC 1035)
    const max_compression_hops: u8 = 16;
    /// Maximum DNS name length per RFC 1035 Section 2.3.4
    const max_name_length: usize = 255;

    fn parseName(self: *Self, data: []const u8, start_offset: usize) !NameResult {
        var name: std.ArrayList(u8) = .empty;
        errdefer name.deinit(self.allocator);

        var offset = start_offset;
        var followed_pointer = false;
        var final_offset = start_offset;
        var pointer_hops: u8 = 0;
        var total_name_len: usize = 0;

        while (offset < data.len) {
            const len = data[offset];

            if (len == 0) {
                if (!followed_pointer) final_offset = offset + 1;
                break;
            }

            if (len & 0xC0 == 0xC0) {
                // Compression pointer - check for loop
                pointer_hops += 1;
                if (pointer_hops > max_compression_hops) {
                    return error.CompressionLoopDetected;
                }
                if (offset + 1 >= data.len) return error.InvalidName;
                const pointer = (@as(u16, len & 0x3F) << 8) | data[offset + 1];
                if (!followed_pointer) final_offset = offset + 2;
                followed_pointer = true;
                offset = pointer;
                continue;
            }

            if (offset + 1 + len > data.len) return error.InvalidName;

            // Check max name length (length byte + label)
            total_name_len += 1 + len;
            if (total_name_len > max_name_length) {
                return error.NameTooLong;
            }

            if (name.items.len > 0) {
                try name.append(self.allocator, '.');
            }
            try name.appendSlice(self.allocator, data[offset + 1 .. offset + 1 + len]);
            offset += 1 + len;
        }

        return NameResult{
            .name = try name.toOwnedSlice(self.allocator),
            .new_offset = final_offset,
        };
    }

    fn parseSoaRdata(self: *Self, rdata: []const u8) !SoaRecord {
        _ = self;
        if (rdata.len < 22) return error.InvalidSoa;

        // Skip MNAME and RNAME (variable length names)
        // For simplicity, just extract the serial which is at a fixed offset from end
        // Serial is at offset after two names, followed by refresh, retry, expire, minimum

        // Find the end of the two names
        var offset: usize = 0;

        // Skip MNAME
        while (offset < rdata.len and rdata[offset] != 0) {
            if (rdata[offset] & 0xC0 == 0xC0) {
                offset += 2;
                break;
            }
            offset += 1 + rdata[offset];
        }
        if (offset < rdata.len and rdata[offset] == 0) offset += 1;

        // Skip RNAME
        while (offset < rdata.len and rdata[offset] != 0) {
            if (rdata[offset] & 0xC0 == 0xC0) {
                offset += 2;
                break;
            }
            offset += 1 + rdata[offset];
        }
        if (offset < rdata.len and rdata[offset] == 0) offset += 1;

        if (offset + 20 > rdata.len) return error.InvalidSoa;

        return SoaRecord{
            .mname = "",
            .rname = "",
            .serial = std.mem.readInt(u32, rdata[offset..][0..4], .big),
            .refresh = std.mem.readInt(u32, rdata[offset + 4 ..][0..4], .big),
            .retry = std.mem.readInt(u32, rdata[offset + 8 ..][0..4], .big),
            .expire = std.mem.readInt(u32, rdata[offset + 12 ..][0..4], .big),
            .minimum = std.mem.readInt(u32, rdata[offset + 16 ..][0..4], .big),
        };
    }

    fn extractSerial(self: *Self, rdata: []const u8) u32 {
        // Delegate to parseSoaRdata to avoid duplicating name-skipping logic
        const soa = self.parseSoaRdata(rdata) catch return 0;
        return soa.serial;
    }

    fn isAxfrResponse(_: *Self, records: []const ZoneRecord) bool {
        // AXFR response has more than 2 SOA records or many records
        // IXFR has exactly 2 SOA records per changeset
        var soa_count: usize = 0;
        for (records) |r| {
            if (r.rtype == soa_rtype) soa_count += 1;
        }
        // If we see many records and SOAs at start/end, it's likely AXFR
        return records.len > 10 and soa_count >= 2;
    }

    fn parseIxfrChanges(self: *Self, records: []const ZoneRecord, changeset: *IxfrChangeset) !void {
        // IXFR format: SOA(new) [SOA(old) deletions SOA(new) additions]* SOA(new)
        // Each deletion/addition block is bounded by SOA records

        if (records.len == 0) return;

        // First SOA is the new serial
        if (records[0].rtype == soa_rtype) {
            changeset.new_serial = self.extractSerial(records[0].rdata);
        }

        var in_deletion = false;
        var i: usize = 1;

        while (i < records.len) {
            const record = records[i];

            if (record.rtype == soa_rtype) {
                // SOA toggles between deletion and addition mode
                in_deletion = !in_deletion;
                i += 1;
                continue;
            }

            const name_copy = try self.allocator.dupe(u8, record.name);
            errdefer self.allocator.free(name_copy);
            const rdata_copy = try self.allocator.dupe(u8, record.rdata);
            errdefer self.allocator.free(rdata_copy);

            const record_copy = ZoneRecord{
                .name = name_copy,
                .rtype = record.rtype,
                .rclass = record.rclass,
                .ttl = record.ttl,
                .rdata = rdata_copy,
            };

            if (in_deletion) {
                try changeset.deletions.append(self.allocator, record_copy);
            } else {
                try changeset.additions.append(self.allocator, record_copy);
            }

            i += 1;
        }
    }
};

/// IXFR result
pub const IxfrResult = struct {
    success: bool,
    /// True if server responded with full AXFR instead of incremental
    is_full_zone: bool,
    /// Incremental changes (if not full zone)
    changeset: ?IxfrChangeset,
    /// New serial after applying changes
    new_serial: u32,
    /// Transfer duration in milliseconds
    duration_ms: u64,
};

// ============================================================================
// Parallel Zone Record Parsing Integration
// ============================================================================

/// Parse raw wire-format zone records in parallel using the thread pool.
///
/// For large zone transfers (AXFR/IXFR) with 64+ records, this dispatches
/// parsing work across multiple threads. Below the threshold, records are
/// parsed sequentially.
///
/// Each raw_record slice should be a standalone wire-format resource record.
pub fn parseRecordsParallel(
    allocator: std.mem.Allocator,
    raw_records: []const []const u8,
    results: []parallel.ParsedRecord,
) void {
    parallel.parallelZoneRecordParse(allocator, raw_records, results);
}

test "axfr/ixfr type-check (Zig 0.16 dormant-breakage guard)" {
    // axfr() and ixfr() do real TCP I/O so they are not exercised directly by
    // unit tests, which means Zig never semantically analyzes their bodies.
    // Reference them so a removed-std-API (e.g. std.time.milliTimestamp) or
    // other breakage in those public entry points fails the build instead of
    // hiding until a consumer wires up zone transfer (Q-NEW-1).
    _ = &ZoneTransferClient.axfr;
    _ = &ZoneTransferClient.ixfr;
    // parseRecordsParallel is public API but unreferenced, so its
    // `@import("parallel")` was also a dormant-compile landmine (QC-1).
    _ = &parseRecordsParallel;
}

test "Zone basic operations" {
    const allocator = std.testing.allocator;

    var zone = Zone.init(allocator, "example.com");
    defer zone.deinit();

    try zone.addRecord(.{
        .name = "www.example.com",
        .rtype = 1, // A
        .rclass = 1, // IN
        .ttl = 300,
        .rdata = &[_]u8{ 192, 168, 1, 1 },
    });

    try std.testing.expectEqual(@as(usize, 1), zone.recordCount());
}

test "ZoneTransferConfig defaults" {
    const config = ZoneTransferConfig{};
    try std.testing.expectEqual(@as(usize, 100000), config.max_records);
    try std.testing.expectEqual(@as(u32, 300000), config.timeout_ms);
    try std.testing.expect(config.verify_serial);
    // Security defaults (SEC-C28)
    try std.testing.expect(config.require_auth); // Default true to enforce authentication
    try std.testing.expect(config.warn_unauthenticated); // Default true for security
    try std.testing.expect(config.tsig_key == null);
}

test "ZoneTransferConfig authentication enforcement" {
    // Test that require_auth can be configured
    const strict_config = ZoneTransferConfig{
        .require_auth = true,
        .warn_unauthenticated = true,
    };
    try std.testing.expect(strict_config.require_auth);
    try std.testing.expect(strict_config.tsig_key == null);

    // Test with TSIG key configured
    const auth_config = ZoneTransferConfig{
        .tsig_key = TsigKey{
            .name = "transfer-key",
            .algorithm = "hmac-sha256",
            .secret = "test-key-material",
        },
        .require_auth = true,
    };
    try std.testing.expect(auth_config.tsig_key != null);
}

test "IxfrChangeset basic" {
    const allocator = std.testing.allocator;

    var changeset = IxfrChangeset.init(allocator, 100, 101);
    defer changeset.deinit(allocator);

    try std.testing.expectEqual(@as(u32, 100), changeset.old_serial);
    try std.testing.expectEqual(@as(u32, 101), changeset.new_serial);
}

test "TransferType values" {
    try std.testing.expectEqual(@as(u16, 252), @intFromEnum(TransferType.axfr));
    try std.testing.expectEqual(@as(u16, 251), @intFromEnum(TransferType.ixfr));
}

test "SEC-C28: default config requires authentication" {
    // Verify that the default ZoneTransferConfig enforces authentication.
    // This prevents accidental exposure of zone data over unauthenticated AXFR/IXFR.
    const config = ZoneTransferConfig{};
    try std.testing.expect(config.require_auth);
    try std.testing.expect(config.tsig_key == null);
    // With no TSIG key and require_auth=true, transfers should be blocked.
    // This is verified by the axfr/ixfr methods checking require_auth first.
}

test "SEC-C28: explicit opt-out for unauthenticated transfers" {
    // Verify that callers can explicitly disable auth for testing/trusted networks.
    const config = ZoneTransferConfig{
        .require_auth = false,
    };
    try std.testing.expect(!config.require_auth);
}

test "SEC-NEW-02b: parseTransferResponse rejects truncated question section" {
    const allocator = std.testing.allocator;
    var client = ZoneTransferClient.init(allocator, .{ .require_auth = false });

    // Build a minimal DNS header with qdcount=1 but truncated question data.
    // 12-byte header + 1 byte label length claiming 200 bytes but only 2 bytes present.
    var response: [15]u8 = undefined;
    @memset(&response, 0);
    // qdcount = 1
    std.mem.writeInt(u16, response[4..6], 1, .big);
    // ancount = 0
    std.mem.writeInt(u16, response[6..8], 0, .big);
    // Label length byte claiming 200 bytes, but only 2 bytes left in response
    response[12] = 200;
    response[13] = 0x41; // 'A'
    response[14] = 0x42; // 'B'

    const result = client.parseTransferResponse(&response);
    try std.testing.expectError(error.InvalidResponse, result);
}

test "SEC-NEW-02b: parseTransferResponse rejects truncated compression pointer" {
    const allocator = std.testing.allocator;
    var client = ZoneTransferClient.init(allocator, .{ .require_auth = false });

    // 12-byte header + compression pointer (0xC0 xx) but only 1 byte for pointer
    var response: [13]u8 = undefined;
    @memset(&response, 0);
    std.mem.writeInt(u16, response[4..6], 1, .big); // qdcount = 1
    response[12] = 0xC0; // Compression pointer start, but no second byte

    const result = client.parseTransferResponse(&response);
    try std.testing.expectError(error.InvalidResponse, result);
}

test "SEC-NEW-02b: parseTransferResponse rejects truncated QTYPE+QCLASS" {
    const allocator = std.testing.allocator;
    var client = ZoneTransferClient.init(allocator, .{ .require_auth = false });

    // 12-byte header + root label (0x00) but no QTYPE/QCLASS bytes
    var response: [13]u8 = undefined;
    @memset(&response, 0);
    std.mem.writeInt(u16, response[4..6], 1, .big); // qdcount = 1
    response[12] = 0; // Root label

    const result = client.parseTransferResponse(&response);
    try std.testing.expectError(error.InvalidResponse, result);
}

test "SEC-NEW-03b: parseTransferResponse rejects qdcount > 1" {
    const allocator = std.testing.allocator;
    var client = ZoneTransferClient.init(allocator, .{ .require_auth = false });

    // DNS header with qdcount = 2 (invalid for transfer response)
    var response: [12]u8 = undefined;
    @memset(&response, 0);
    std.mem.writeInt(u16, response[4..6], 2, .big); // qdcount = 2

    const result = client.parseTransferResponse(&response);
    try std.testing.expectError(error.InvalidResponse, result);
}

test "SEC-NEW-03b: parseTransferResponse accepts qdcount 0" {
    const allocator = std.testing.allocator;
    var client = ZoneTransferClient.init(allocator, .{ .require_auth = false });

    // DNS header with qdcount=0, ancount=0 -- valid empty response
    var response: [12]u8 = undefined;
    @memset(&response, 0);
    // qdcount = 0, ancount = 0

    const records = try client.parseTransferResponse(&response);
    defer allocator.free(records);
    try std.testing.expectEqual(@as(usize, 0), records.len);
}

test "SEC-SR-6: transferDeadlineExceeded enforces a wall-clock budget" {
    // Within budget.
    try std.testing.expect(!transferDeadlineExceeded(1000, 1500, 1000));
    // Exactly at the budget is not yet exceeded.
    try std.testing.expect(!transferDeadlineExceeded(1000, 2000, 1000));
    // Past the budget.
    try std.testing.expect(transferDeadlineExceeded(1000, 2001, 1000));
    // 0 means "no deadline" and never trips, even far in the future.
    try std.testing.expect(!transferDeadlineExceeded(1000, 9_000_000, 0));
}

test "SEC-SR-7: serialGreater follows RFC 1982 arithmetic" {
    try std.testing.expect(serialGreater(101, 100));
    try std.testing.expect(!serialGreater(100, 100)); // equal is not greater
    try std.testing.expect(!serialGreater(100, 101)); // older is not greater
    // Wraparound: 0 is "greater than" 0xFFFFFFFF (just wrapped).
    try std.testing.expect(serialGreater(0, 0xFFFF_FFFF));
    try std.testing.expect(!serialGreater(0xFFFF_FFFF, 0));
}

test "SEC-SR-9: parseTransferResponse does not leak record name on truncation" {
    const allocator = std.testing.allocator;
    var client = ZoneTransferClient.init(allocator, .{ .require_auth = false });

    // Header: qdcount=0, ancount=1
    const header = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 };
    // A parseable 12-byte name (label "aaaaaaaaaa" + root)...
    const name = [_]u8{ 10, 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 0 };
    // ...followed by fewer than 10 bytes, so the RR header is truncated and
    // the answer loop breaks after parseName has already allocated the name.
    const response = header ++ name ++ [_]u8{ 0xAA, 0xBB };

    const records = try client.parseTransferResponse(&response);
    defer allocator.free(records);
    // No records survive truncation; the testing allocator fails the test if
    // the in-progress name allocation leaked.
    try std.testing.expectEqual(@as(usize, 0), records.len);
}

test "SEC-SCAN-12: encodeName rejects labels > 63 bytes" {
    const allocator = std.testing.allocator;
    var client = ZoneTransferClient.init(allocator, .{ .require_auth = false });

    var buffer: std.ArrayList(u8) = .empty;
    defer buffer.deinit(allocator);

    // Build a name with a 64-byte label (exceeds RFC 1035 max of 63)
    const long_label = "a" ** 64 ++ ".example.com";
    const result = client.encodeName(&buffer, long_label);
    try std.testing.expectError(error.InvalidName, result);
}

test "SEC-SCAN-12: encodeName accepts labels of exactly 63 bytes" {
    const allocator = std.testing.allocator;
    var client = ZoneTransferClient.init(allocator, .{ .require_auth = false });

    var buffer: std.ArrayList(u8) = .empty;
    defer buffer.deinit(allocator);

    // 63-byte label is the maximum allowed
    const max_label = "a" ** 63 ++ ".com";
    try client.encodeName(&buffer, max_label);
    // Verify the encoded label length byte is 63
    try std.testing.expectEqual(@as(u8, 63), buffer.items[0]);
}

test "SEC-SCAN-15: TsigKey.deinit zeroes secret bytes" {
    // Allocate a mutable secret so we can verify zeroing
    var secret_buf = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE };

    var key = TsigKey{
        .name = "test-key",
        .algorithm = "hmac-sha256",
        .secret = &secret_buf,
    };

    // Before deinit, secret should be non-zero
    try std.testing.expect(secret_buf[0] != 0 or secret_buf[1] != 0);

    key.deinit();

    // After deinit, all secret bytes should be zeroed
    for (secret_buf) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }
}

test "SEC-SCAN-15: TsigKey.deinit handles empty secret" {
    var key = TsigKey{
        .name = "test-key",
        .algorithm = "hmac-sha256",
        .secret = "",
    };
    // Should not panic or crash on empty secret
    key.deinit();
}
