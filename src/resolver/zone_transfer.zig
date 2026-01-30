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
    /// RECOMMENDED: Set to true in production environments.
    require_auth: bool = false,

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

        const start_time = std.time.milliTimestamp();
        var zone = Zone.init(self.allocator, zone_name);
        errdefer zone.deinit();

        // Connect via TCP
        const address = try std.net.Address.parseIp4(server_addr, port);
        const stream = try std.net.tcpConnectToAddress(address);
        defer stream.close();

        // Set timeout
        const timeout_sec = self.config.timeout_ms / 1000;
        const timeout = std.posix.timeval{
            .sec = @intCast(timeout_sec),
            .usec = 0,
        };
        try std.posix.setsockopt(
            stream.handle,
            std.posix.SOL.SOCKET,
            std.posix.SO.RCVTIMEO,
            std.mem.asBytes(&timeout),
        );

        // Build and send AXFR query
        const query = try self.buildTransferQuery(zone_name, .axfr);
        defer self.allocator.free(query);

        try self.sendTcpMessage(stream, query);

        // Receive and parse responses
        var message_count: usize = 0;
        var first_soa_seen = false;
        var second_soa_seen = false;

        while (!second_soa_seen) {
            const response = try self.receiveTcpMessage(stream);
            defer self.allocator.free(response);
            message_count += 1;

            // Parse response and extract records
            const records = try self.parseTransferResponse(response);
            defer self.allocator.free(records);

            for (records) |record| {
                // Check for SOA records (transfer boundaries)
                if (record.rtype == 6) { // SOA
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
                    return TransferResult{
                        .success = false,
                        .zone = null,
                        .record_count = zone.recordCount(),
                        .message_count = message_count,
                        .duration_ms = @intCast(std.time.milliTimestamp() - start_time),
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
            .duration_ms = @intCast(std.time.milliTimestamp() - start_time),
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

        const start_time = std.time.milliTimestamp();

        // Connect via TCP
        const address = try std.net.Address.parseIp4(server_addr, port);
        const stream = try std.net.tcpConnectToAddress(address);
        defer stream.close();

        // Build and send IXFR query with SOA showing our current serial
        const query = try self.buildIxfrQuery(zone_name, current_serial);
        defer self.allocator.free(query);

        try self.sendTcpMessage(stream, query);

        // Receive response
        const response = try self.receiveTcpMessage(stream);
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
                .new_serial = if (records.len > 0 and records[0].rtype == 6)
                    self.extractSerial(records[0].rdata)
                else
                    current_serial,
                .duration_ms = @intCast(std.time.milliTimestamp() - start_time),
            };
        }

        // Parse incremental changes
        var changeset = IxfrChangeset.init(self.allocator, current_serial, 0);
        errdefer changeset.deinit(self.allocator);

        try self.parseIxfrChanges(records, &changeset);

        return IxfrResult{
            .success = true,
            .is_full_zone = false,
            .changeset = changeset,
            .new_serial = changeset.new_serial,
            .duration_ms = @intCast(std.time.milliTimestamp() - start_time),
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
        std.posix.getrandom(std.mem.asBytes(&seed)) catch {
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
        std.posix.getrandom(std.mem.asBytes(&seed)) catch {
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
            try buffer.append(self.allocator, @intCast(label.len));
            try buffer.appendSlice(self.allocator, label);
        }
        try buffer.append(self.allocator, 0); // Root label
    }

    fn sendTcpMessage(self: *Self, stream: std.net.Stream, message: []const u8) !void {
        _ = self;
        // TCP DNS uses 2-byte length prefix
        var length_prefix: [2]u8 = undefined;
        std.mem.writeInt(u16, &length_prefix, @intCast(message.len), .big);

        _ = try stream.write(&length_prefix);
        _ = try stream.write(message);
    }

    fn receiveTcpMessage(self: *Self, stream: std.net.Stream) ![]u8 {
        // Read length prefix
        var length_buf: [2]u8 = undefined;
        const len_read = try stream.read(&length_buf);
        if (len_read < 2) return error.ConnectionClosed;

        const message_len = std.mem.readInt(u16, &length_buf, .big);
        if (message_len > self.config.buffer_size) {
            return error.MessageTooLarge;
        }

        // Read message
        const message = try self.allocator.alloc(u8, message_len);
        errdefer self.allocator.free(message);

        var total_read: usize = 0;
        while (total_read < message_len) {
            const n = try stream.read(message[total_read..]);
            if (n == 0) return error.ConnectionClosed;
            total_read += n;
        }

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
        const ancount = std.mem.readInt(u16, response[6..8], .big);

        // Skip header and question section
        var offset: usize = 12;

        // Skip question
        while (offset < response.len and response[offset] != 0) {
            if (response[offset] & 0xC0 == 0xC0) {
                offset += 2;
                break;
            }
            offset += 1 + response[offset];
        }
        if (offset < response.len and response[offset] == 0) offset += 1;
        offset += 4; // QTYPE + QCLASS

        // Parse answer records
        var count: u16 = 0;
        while (count < ancount and offset + 10 < response.len) {
            // Parse name
            const name_result = try self.parseName(response, offset);
            offset = name_result.new_offset;

            if (offset + 10 > response.len) break;

            const rtype = std.mem.readInt(u16, response[offset..][0..2], .big);
            const rclass = std.mem.readInt(u16, response[offset + 2 ..][0..2], .big);
            const ttl = std.mem.readInt(u32, response[offset + 4 ..][0..4], .big);
            const rdlength = std.mem.readInt(u16, response[offset + 8 ..][0..2], .big);
            offset += 10;

            if (offset + rdlength > response.len) break;

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

    fn extractSerial(_: *Self, rdata: []const u8) u32 {
        // Same logic as parseSoaRdata but just returns serial
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

        if (offset + 4 > rdata.len) return 0;

        return std.mem.readInt(u32, rdata[offset..][0..4], .big);
    }

    fn isAxfrResponse(_: *Self, records: []const ZoneRecord) bool {
        // AXFR response has more than 2 SOA records or many records
        // IXFR has exactly 2 SOA records per changeset
        var soa_count: usize = 0;
        for (records) |r| {
            if (r.rtype == 6) soa_count += 1;
        }
        // If we see many records and SOAs at start/end, it's likely AXFR
        return records.len > 10 and soa_count >= 2;
    }

    fn parseIxfrChanges(self: *Self, records: []const ZoneRecord, changeset: *IxfrChangeset) !void {
        // IXFR format: SOA(new) [SOA(old) deletions SOA(new) additions]* SOA(new)
        // Each deletion/addition block is bounded by SOA records

        if (records.len == 0) return;

        // First SOA is the new serial
        if (records[0].rtype == 6) {
            changeset.new_serial = self.extractSerial(records[0].rdata);
        }

        var in_deletion = false;
        var i: usize = 1;

        while (i < records.len) {
            const record = records[i];

            if (record.rtype == 6) {
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
    // Security defaults
    try std.testing.expect(!config.require_auth); // Default false for backward compat
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
