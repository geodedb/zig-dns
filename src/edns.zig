// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! EDNS0 - Extension Mechanisms for DNS
//!
//! RFC 6891: Extension Mechanisms for DNS (EDNS(0))
//!
//! EDNS uses the OPT pseudo-RR in the additional section to signal
//! extended capabilities and carry options.

const std = @import("std");
const types_mod = @import("types");

pub const Type = types_mod.Type;

/// EDNS Option Codes (RFC 6891)
pub const OptionCode = enum(u16) {
    /// RFC 7871: Client Subnet
    client_subnet = 8,
    /// RFC 7873: DNS Cookies
    cookie = 10,
    /// RFC 7828: TCP Keepalive
    tcp_keepalive = 11,
    /// RFC 7830: DNS Padding
    padding = 12,
    /// RFC 8145: Key Tag Signaling
    key_tag = 14,
    /// RFC 8914: Extended DNS Errors
    extended_error = 15,

    _,

    pub fn fromInt(value: u16) OptionCode {
        return @enumFromInt(value);
    }

    pub fn toInt(self: OptionCode) u16 {
        return @intFromEnum(self);
    }
};

/// Extended DNS Error Codes (RFC 8914)
pub const ExtendedErrorCode = enum(u16) {
    /// Other error
    other = 0,
    /// Unsupported DNSKEY algorithm
    unsupported_dnskey_algorithm = 1,
    /// Unsupported DS digest type
    unsupported_ds_digest_type = 2,
    /// Stale answer
    stale_answer = 3,
    /// Forged answer
    forged_answer = 4,
    /// DNSSEC indeterminate
    dnssec_indeterminate = 5,
    /// DNSSEC bogus
    dnssec_bogus = 6,
    /// Signature expired
    signature_expired = 7,
    /// Signature not yet valid
    signature_not_yet_valid = 8,
    /// DNSKEY missing
    dnskey_missing = 9,
    /// RRSIGs missing
    rrsigs_missing = 10,
    /// No zone key bit set
    no_zone_key_bit_set = 11,
    /// NSEC missing
    nsec_missing = 12,
    /// Cached error
    cached_error = 13,
    /// Not ready
    not_ready = 14,
    /// Blocked
    blocked = 15,
    /// Censored
    censored = 16,
    /// Filtered
    filtered = 17,
    /// Prohibited
    prohibited = 18,
    /// Stale NXDOMAIN answer
    stale_nxdomain_answer = 19,
    /// Not authoritative
    not_authoritative = 20,
    /// Not supported
    not_supported = 21,
    /// No reachable authority
    no_reachable_authority = 22,
    /// Network error
    network_error = 23,
    /// Invalid data
    invalid_data = 24,

    _,
};

/// EDNS Option
pub const Option = struct {
    code: OptionCode,
    data: []const u8,
};

/// EDNS OPT pseudo-RR (RFC 6891)
pub const OptRecord = struct {
    /// Requestor's UDP payload size
    udp_payload_size: u16,

    /// Extended RCODE (upper 8 bits)
    extended_rcode: u8,

    /// EDNS version
    version: u8,

    /// DO (DNSSEC OK) bit
    dnssec_ok: bool,

    /// Options
    options: []const u8,

    const Self = @This();

    /// Default UDP payload size
    pub const default_udp_size = 4096;

    /// Parse OPT record from resource record data
    /// The class field contains UDP payload size
    /// The TTL field contains extended RCODE, version, and flags
    pub fn parse(class_value: u16, ttl_value: u32, rdata: []const u8) Self {
        return Self{
            .udp_payload_size = class_value,
            .extended_rcode = @truncate((ttl_value >> 24) & 0xFF),
            .version = @truncate((ttl_value >> 16) & 0xFF),
            .dnssec_ok = ((ttl_value >> 15) & 1) == 1,
            .options = rdata,
        };
    }

    /// Iterate over options
    pub fn optionsIterator(self: Self) OptionIterator {
        return OptionIterator{ .data = self.options, .offset = 0 };
    }

    /// Encode OPT record fields for building a message
    pub fn encode(self: Self, buffer: []u8) !usize {
        if (buffer.len < 11) {
            return error.BufferTooSmall;
        }

        // NAME: root (empty)
        buffer[0] = 0;

        // TYPE: OPT (41)
        std.mem.writeInt(u16, buffer[1..3], @intFromEnum(Type.opt), .big);

        // CLASS: UDP payload size
        std.mem.writeInt(u16, buffer[3..5], self.udp_payload_size, .big);

        // TTL: extended RCODE, version, flags
        var ttl: u32 = 0;
        ttl |= @as(u32, self.extended_rcode) << 24;
        ttl |= @as(u32, self.version) << 16;
        if (self.dnssec_ok) {
            ttl |= 1 << 15;
        }
        std.mem.writeInt(u32, buffer[5..9], ttl, .big);

        // RDLENGTH
        // SECURITY (SEC-NEW-05): Validate options length fits in u16 before cast
        if (self.options.len > std.math.maxInt(u16)) return error.OptionsTooLarge;
        const rdlength: u16 = @intCast(self.options.len);
        std.mem.writeInt(u16, buffer[9..11], rdlength, .big);

        // RDATA (options)
        if (self.options.len > 0) {
            if (buffer.len < 11 + self.options.len) {
                return error.BufferTooSmall;
            }
            @memcpy(buffer[11..][0..self.options.len], self.options);
        }

        return 11 + self.options.len;
    }

    /// Create a default OPT record for queries
    pub fn default() Self {
        return Self{
            .udp_payload_size = default_udp_size,
            .extended_rcode = 0,
            .version = 0,
            .dnssec_ok = false,
            .options = &[_]u8{},
        };
    }

    /// Create an OPT record with DNSSEC OK flag
    pub fn withDnssec() Self {
        return Self{
            .udp_payload_size = default_udp_size,
            .extended_rcode = 0,
            .version = 0,
            .dnssec_ok = true,
            .options = &[_]u8{},
        };
    }
};

/// Iterator over EDNS options
pub const OptionIterator = struct {
    data: []const u8,
    offset: usize,

    const Self = @This();

    pub fn next(self: *Self) ?Option {
        if (self.offset + 4 > self.data.len) {
            return null;
        }

        const code = OptionCode.fromInt(std.mem.readInt(u16, self.data[self.offset..][0..2], .big));
        const length = std.mem.readInt(u16, self.data[self.offset + 2 ..][0..2], .big);

        if (self.offset + 4 + length > self.data.len) {
            return null;
        }

        const option = Option{
            .code = code,
            .data = self.data[self.offset + 4 ..][0..length],
        };

        self.offset += 4 + length;

        return option;
    }
};

/// Build a complete EDNS option from an option code and encoded payload.
///
/// Serializes the 4-byte header (option code + data length) followed by the
/// payload data. This is the shared helper that all EDNS option types delegate
/// to from their `buildOption` methods (QA-AUDIT-07).
pub fn buildOption(allocator: std.mem.Allocator, code: OptionCode, data: []const u8) ![]u8 {
    // SECURITY (SEC-NEW-05): Validate data length fits in u16 before cast
    if (data.len > std.math.maxInt(u16)) return error.OptionsTooLarge;
    const result = try allocator.alloc(u8, 4 + data.len);
    std.mem.writeInt(u16, result[0..2], code.toInt(), .big);
    std.mem.writeInt(u16, result[2..4], @intCast(data.len), .big);
    @memcpy(result[4..], data);
    return result;
}

/// Private alias for the module-level buildOption, usable from within structs
/// whose methods share the same `buildOption` name (QA-AUDIT-07).
const serializeEdnsOption = buildOption;

// =========================================================================
// RFC 7871: Client Subnet in DNS Queries (EDNS Client Subnet / ECS)
// =========================================================================

/// Address family for Client Subnet option
pub const AddressFamily = enum(u16) {
    ipv4 = 1,
    ipv6 = 2,
    _,
};

/// EDNS Client Subnet option (RFC 7871)
///
/// Allows a recursive resolver to include client network information
/// in queries to authoritative servers for geo-aware responses.
pub const ClientSubnet = struct {
    /// Address family (1=IPv4, 2=IPv6)
    family: AddressFamily,
    /// Source prefix length (bits of address included)
    source_prefix_length: u8,
    /// Scope prefix length (bits of address for which response is valid)
    scope_prefix_length: u8,
    /// Client address (truncated to source_prefix_length bits)
    address: []const u8,

    const Self = @This();

    /// Parse Client Subnet option from EDNS option data
    pub fn parse(data: []const u8) !Self {
        if (data.len < 4) {
            return error.InvalidOptionData;
        }

        const family = @as(AddressFamily, @enumFromInt(std.mem.readInt(u16, data[0..2], .big)));
        const source_prefix_length = data[2];
        const scope_prefix_length = data[3];

        // Calculate expected address length (rounded up to bytes)
        const addr_bytes = (source_prefix_length + 7) / 8;
        if (data.len < 4 + addr_bytes) {
            return error.InvalidOptionData;
        }

        return Self{
            .family = family,
            .source_prefix_length = source_prefix_length,
            .scope_prefix_length = scope_prefix_length,
            .address = data[4..][0..addr_bytes],
        };
    }

    /// Encode Client Subnet option to wire format
    pub fn encode(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const addr_bytes = (self.source_prefix_length + 7) / 8;
        const total_len = 4 + addr_bytes;

        const result = try allocator.alloc(u8, total_len);
        errdefer allocator.free(result);

        std.mem.writeInt(u16, result[0..2], @intFromEnum(self.family), .big);
        result[2] = self.source_prefix_length;
        result[3] = self.scope_prefix_length;

        if (addr_bytes > 0) {
            @memcpy(result[4..][0..addr_bytes], self.address[0..addr_bytes]);
        }

        return result;
    }

    /// Build complete EDNS option (with option code and length).
    /// Delegates to the shared serializeEdnsOption helper (QA-AUDIT-07).
    pub fn buildOption(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const data = try self.encode(allocator);
        defer allocator.free(data);
        return serializeEdnsOption(allocator, .client_subnet, data);
    }

    /// Create Client Subnet for IPv4 address
    pub fn fromIPv4(addr: [4]u8, prefix_length: u8) Self {
        const bytes_needed = (prefix_length + 7) / 8;
        return Self{
            .family = .ipv4,
            .source_prefix_length = prefix_length,
            .scope_prefix_length = 0, // Set by server in response
            .address = addr[0..bytes_needed],
        };
    }

    /// Create Client Subnet for IPv6 address
    pub fn fromIPv6(addr: [16]u8, prefix_length: u8) Self {
        const bytes_needed = (prefix_length + 7) / 8;
        return Self{
            .family = .ipv6,
            .source_prefix_length = prefix_length,
            .scope_prefix_length = 0, // Set by server in response
            .address = addr[0..bytes_needed],
        };
    }
};

// =========================================================================
// RFC 7873: Domain Name System (DNS) Cookies
// =========================================================================

/// DNS Cookie option (RFC 7873)
///
/// Provides lightweight transaction security for DNS queries,
/// protecting against amplification attacks and cache poisoning.
pub const Cookie = struct {
    /// Client cookie (8 bytes, always present)
    client_cookie: [8]u8,
    /// Server cookie (8-32 bytes, present in responses)
    server_cookie: ?[]const u8,

    const Self = @This();

    /// Minimum server cookie length
    pub const min_server_cookie_len = 8;
    /// Maximum server cookie length
    pub const max_server_cookie_len = 32;
    /// Client cookie length (always 8)
    pub const client_cookie_len = 8;

    /// Parse Cookie option from EDNS option data
    pub fn parse(data: []const u8) !Self {
        if (data.len < client_cookie_len) {
            return error.InvalidOptionData;
        }

        var self = Self{
            .client_cookie = undefined,
            .server_cookie = null,
        };

        @memcpy(&self.client_cookie, data[0..client_cookie_len]);

        if (data.len > client_cookie_len) {
            const server_len = data.len - client_cookie_len;
            if (server_len < min_server_cookie_len or server_len > max_server_cookie_len) {
                return error.InvalidCookieLength;
            }
            self.server_cookie = data[client_cookie_len..];
        }

        return self;
    }

    /// Encode Cookie option to wire format
    pub fn encode(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const server_len = if (self.server_cookie) |sc| sc.len else 0;
        const total_len = client_cookie_len + server_len;

        const result = try allocator.alloc(u8, total_len);
        errdefer allocator.free(result);

        @memcpy(result[0..client_cookie_len], &self.client_cookie);

        if (self.server_cookie) |sc| {
            @memcpy(result[client_cookie_len..], sc);
        }

        return result;
    }

    /// Build complete EDNS option (with option code and length).
    /// Delegates to the shared serializeEdnsOption helper (QA-AUDIT-07).
    pub fn buildOption(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const data = try self.encode(allocator);
        defer allocator.free(data);
        return serializeEdnsOption(allocator, .cookie, data);
    }

    /// Generate a new client cookie using random bytes
    pub fn generateClientCookie(random: *std.Random) Self {
        var cookie = Self{
            .client_cookie = undefined,
            .server_cookie = null,
        };
        random.bytes(&cookie.client_cookie);
        return cookie;
    }

    /// Create client cookie from client IP, server IP, and secret
    /// Uses SipHash for deterministic cookie generation
    pub fn computeClientCookie(
        client_ip: []const u8,
        server_ip: []const u8,
        secret: [16]u8,
    ) Self {
        var cookie = Self{
            .client_cookie = undefined,
            .server_cookie = null,
        };

        // Use SipHash-2-4 for cookie computation
        var hasher = std.crypto.auth.siphash.SipHash64(2, 4).init(&secret);
        hasher.update(client_ip);
        hasher.update(server_ip);
        const hash = hasher.finalInt();

        @memcpy(&cookie.client_cookie, &std.mem.toBytes(hash));
        return cookie;
    }

    /// Check if this is a valid response cookie (has server cookie)
    pub fn hasServerCookie(self: Self) bool {
        return self.server_cookie != null;
    }
};

// =========================================================================
// RFC 7828: edns-tcp-keepalive
// =========================================================================

/// TCP Keepalive option (RFC 7828)
///
/// Used to negotiate TCP session timeouts for DNS-over-TCP connections.
/// Allows clients and servers to signal their desired idle timeout.
pub const TcpKeepalive = struct {
    /// Idle timeout in units of 100 milliseconds
    /// 0 means the server is closing the connection
    /// Maximum value 65535 = ~109 minutes
    timeout: ?u16,

    const Self = @This();

    /// Parse TCP Keepalive option from EDNS option data
    pub fn parse(data: []const u8) !Self {
        if (data.len == 0) {
            // Client query: no timeout specified (requesting server's timeout)
            return Self{ .timeout = null };
        }

        if (data.len != 2) {
            return error.InvalidOptionData;
        }

        return Self{
            .timeout = std.mem.readInt(u16, data[0..2], .big),
        };
    }

    /// Encode TCP Keepalive option to wire format
    pub fn encode(self: Self, allocator: std.mem.Allocator) ![]u8 {
        if (self.timeout) |timeout| {
            const result = try allocator.alloc(u8, 2);
            std.mem.writeInt(u16, result[0..2], timeout, .big);
            return result;
        } else {
            return try allocator.alloc(u8, 0);
        }
    }

    /// Build complete EDNS option (with option code and length).
    /// Delegates to the shared serializeEdnsOption helper (QA-AUDIT-07).
    pub fn buildOption(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const data = try self.encode(allocator);
        defer allocator.free(data);
        return serializeEdnsOption(allocator, .tcp_keepalive, data);
    }

    /// Get timeout in seconds (from 100ms units)
    pub fn timeoutSeconds(self: Self) ?f32 {
        if (self.timeout) |t| {
            return @as(f32, @floatFromInt(t)) / 10.0;
        }
        return null;
    }

    /// Create from timeout in seconds
    pub fn fromSeconds(seconds: f32) Self {
        if (seconds <= 0) {
            return Self{ .timeout = 0 };
        }
        const units: u16 = @intFromFloat(@min(seconds * 10.0, 65535.0));
        return Self{ .timeout = units };
    }
};

// =========================================================================
// RFC 7830: DNS Padding
// =========================================================================

/// Padding option (RFC 7830)
///
/// Used to pad DNS messages to prevent traffic analysis.
/// Particularly important for DNS-over-TLS and DNS-over-HTTPS.
pub const Padding = struct {
    /// Padding length in bytes
    length: u16,

    const Self = @This();

    /// Parse Padding option from EDNS option data
    pub fn parse(data: []const u8) Self {
        return Self{ .length = @intCast(data.len) };
    }

    /// Encode Padding option to wire format
    pub fn encode(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const result = try allocator.alloc(u8, self.length);
        @memset(result, 0);
        return result;
    }

    /// Build complete EDNS option (with option code and length).
    /// Delegates to the shared serializeEdnsOption helper (QA-AUDIT-07).
    pub fn buildOption(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const data = try self.encode(allocator);
        defer allocator.free(data);
        return serializeEdnsOption(allocator, .padding, data);
    }

    /// Calculate padding needed to reach a target message size
    pub fn calculatePadding(current_size: usize, block_size: usize) Self {
        if (block_size == 0) return Self{ .length = 0 };

        const remainder = current_size % block_size;
        if (remainder == 0) return Self{ .length = 0 };

        // Account for option header (4 bytes) in padding calculation
        const padding_needed = block_size - remainder;
        if (padding_needed <= 4) {
            // Need to add an extra block to fit header
            return Self{ .length = @intCast(padding_needed + block_size - 4) };
        }
        return Self{ .length = @intCast(padding_needed - 4) };
    }

    /// Recommended block size for DNS-over-TLS (RFC 8467)
    pub const dot_block_size: usize = 468;
    /// Recommended block size for DNS-over-HTTPS
    pub const doh_block_size: usize = 128;
};

// =========================================================================
// RFC 8914: Extended DNS Errors
// =========================================================================

/// Extended DNS Error option (RFC 8914)
///
/// Provides additional error information beyond RCODE.
/// Used to communicate specific error conditions to clients.
pub const ExtendedError = struct {
    /// Error code
    code: ExtendedErrorCode,
    /// Optional human-readable error text (UTF-8)
    extra_text: ?[]const u8,

    const Self = @This();

    /// Parse Extended DNS Error option from EDNS option data
    pub fn parse(data: []const u8) !Self {
        if (data.len < 2) {
            return error.InvalidOptionData;
        }

        const code: ExtendedErrorCode = @enumFromInt(std.mem.readInt(u16, data[0..2], .big));

        var extra_text: ?[]const u8 = null;
        if (data.len > 2) {
            extra_text = data[2..];
        }

        return Self{
            .code = code,
            .extra_text = extra_text,
        };
    }

    /// Encode Extended DNS Error option to wire format
    pub fn encode(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const text_len = if (self.extra_text) |t| t.len else 0;
        const result = try allocator.alloc(u8, 2 + text_len);

        std.mem.writeInt(u16, result[0..2], @intFromEnum(self.code), .big);

        if (self.extra_text) |text| {
            @memcpy(result[2..], text);
        }

        return result;
    }

    /// Build complete EDNS option (with option code and length).
    /// Delegates to the shared serializeEdnsOption helper (QA-AUDIT-07).
    pub fn buildOption(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const data = try self.encode(allocator);
        defer allocator.free(data);
        return serializeEdnsOption(allocator, .extended_error, data);
    }

    /// Create error with optional text
    pub fn create(code: ExtendedErrorCode, extra_text: ?[]const u8) Self {
        return Self{
            .code = code,
            .extra_text = extra_text,
        };
    }

    /// Get human-readable description for error code
    pub fn codeDescription(self: Self) []const u8 {
        return switch (self.code) {
            .other => "Other",
            .unsupported_dnskey_algorithm => "Unsupported DNSKEY Algorithm",
            .unsupported_ds_digest_type => "Unsupported DS Digest Type",
            .stale_answer => "Stale Answer",
            .forged_answer => "Forged Answer",
            .dnssec_indeterminate => "DNSSEC Indeterminate",
            .dnssec_bogus => "DNSSEC Bogus",
            .signature_expired => "Signature Expired",
            .signature_not_yet_valid => "Signature Not Yet Valid",
            .dnskey_missing => "DNSKEY Missing",
            .rrsigs_missing => "RRSIGs Missing",
            .no_zone_key_bit_set => "No Zone Key Bit Set",
            .nsec_missing => "NSEC Missing",
            .cached_error => "Cached Error",
            .not_ready => "Not Ready",
            .blocked => "Blocked",
            .censored => "Censored",
            .filtered => "Filtered",
            .prohibited => "Prohibited",
            .stale_nxdomain_answer => "Stale NXDOMAIN Answer",
            .not_authoritative => "Not Authoritative",
            .not_supported => "Not Supported",
            .no_reachable_authority => "No Reachable Authority",
            .network_error => "Network Error",
            .invalid_data => "Invalid Data",
            _ => "Unknown",
        };
    }
};

// =========================================================================
// RFC 8145: EDNS Key Tag
// =========================================================================

/// Key Tag option (RFC 8145)
///
/// Signals which trust anchors a validating resolver has configured.
/// Helps zone operators understand key rollover status.
pub const KeyTag = struct {
    /// List of key tags
    tags: []const u16,

    const Self = @This();

    /// Parse Key Tag option from EDNS option data
    pub fn parse(allocator: std.mem.Allocator, data: []const u8) !Self {
        if (data.len % 2 != 0) {
            return error.InvalidOptionData;
        }

        const count = data.len / 2;
        const tags = try allocator.alloc(u16, count);
        errdefer allocator.free(tags);

        var i: usize = 0;
        while (i < count) : (i += 1) {
            tags[i] = std.mem.readInt(u16, data[i * 2 ..][0..2], .big);
        }

        return Self{ .tags = tags };
    }

    /// Free allocated tags
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.tags);
    }

    /// Encode Key Tag option to wire format
    pub fn encode(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const result = try allocator.alloc(u8, self.tags.len * 2);

        var i: usize = 0;
        while (i < self.tags.len) : (i += 1) {
            std.mem.writeInt(u16, result[i * 2 ..][0..2], self.tags[i], .big);
        }

        return result;
    }

    /// Build complete EDNS option (with option code and length).
    /// Delegates to the shared serializeEdnsOption helper (QA-AUDIT-07).
    pub fn buildOption(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const data = try self.encode(allocator);
        defer allocator.free(data);
        return serializeEdnsOption(allocator, .key_tag, data);
    }

    /// Create from a slice of key tags
    pub fn fromTags(tags: []const u16) Self {
        return Self{ .tags = tags };
    }

    /// Check if a specific key tag is present
    pub fn contains(self: Self, tag: u16) bool {
        for (self.tags) |t| {
            if (t == tag) return true;
        }
        return false;
    }
};

test "OptRecord.parse" {
    const opt = OptRecord.parse(4096, 0x00000000, &[_]u8{});

    try std.testing.expectEqual(@as(u16, 4096), opt.udp_payload_size);
    try std.testing.expectEqual(@as(u8, 0), opt.extended_rcode);
    try std.testing.expectEqual(@as(u8, 0), opt.version);
    try std.testing.expect(!opt.dnssec_ok);
}

test "OptRecord.parse with DNSSEC OK" {
    // TTL with DO bit set: 0x00008000
    const opt = OptRecord.parse(4096, 0x00008000, &[_]u8{});

    try std.testing.expect(opt.dnssec_ok);
}

test "OptRecord.encode" {
    const opt = OptRecord.default();
    var buffer: [64]u8 = undefined;

    const len = try opt.encode(&buffer);

    try std.testing.expectEqual(@as(usize, 11), len);
    try std.testing.expectEqual(@as(u8, 0), buffer[0]); // Root name
    try std.testing.expectEqual(@as(u8, 0), buffer[1]); // TYPE high byte
    try std.testing.expectEqual(@as(u8, 41), buffer[2]); // TYPE low byte (OPT)
}

test "OptionIterator" {
    const options = [_]u8{
        // Option 1: Cookie (code 10), length 8
        0x00, 0x0A,
        0x00, 0x08,
        0x01, 0x02,
        0x03, 0x04,
        0x05, 0x06,
        0x07, 0x08,
        // Option 2: Padding (code 12), length 4
        0x00, 0x0C,
        0x00, 0x04,
        0x00, 0x00,
        0x00, 0x00,
    };

    var iter = OptionIterator{ .data = &options, .offset = 0 };

    const opt1 = iter.next().?;
    try std.testing.expectEqual(OptionCode.cookie, opt1.code);
    try std.testing.expectEqual(@as(usize, 8), opt1.data.len);

    const opt2 = iter.next().?;
    try std.testing.expectEqual(OptionCode.padding, opt2.code);
    try std.testing.expectEqual(@as(usize, 4), opt2.data.len);

    try std.testing.expect(iter.next() == null);
}

test "ClientSubnet.parse IPv4" {
    const data = [_]u8{
        0x00, 0x01, // Family: IPv4
        0x18, // Source prefix: 24
        0x00, // Scope prefix: 0
        0xC0, 0xA8, 0x01, // 192.168.1.0/24
    };

    const ecs = try ClientSubnet.parse(&data);
    try std.testing.expectEqual(AddressFamily.ipv4, ecs.family);
    try std.testing.expectEqual(@as(u8, 24), ecs.source_prefix_length);
    try std.testing.expectEqual(@as(u8, 0), ecs.scope_prefix_length);
    try std.testing.expectEqual(@as(usize, 3), ecs.address.len);
    try std.testing.expectEqual(@as(u8, 0xC0), ecs.address[0]);
}

test "ClientSubnet.parse IPv6" {
    const data = [_]u8{
        0x00, 0x02, // Family: IPv6
        0x40, // Source prefix: 64
        0x00, // Scope prefix: 0
        0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00, // 2001:db8::/64
    };

    const ecs = try ClientSubnet.parse(&data);
    try std.testing.expectEqual(AddressFamily.ipv6, ecs.family);
    try std.testing.expectEqual(@as(u8, 64), ecs.source_prefix_length);
    try std.testing.expectEqual(@as(usize, 8), ecs.address.len);
}

test "ClientSubnet.encode" {
    const allocator = std.testing.allocator;

    const ecs = ClientSubnet{
        .family = .ipv4,
        .source_prefix_length = 24,
        .scope_prefix_length = 0,
        .address = &[_]u8{ 0xC0, 0xA8, 0x01 },
    };

    const encoded = try ecs.encode(allocator);
    defer allocator.free(encoded);

    try std.testing.expectEqual(@as(usize, 7), encoded.len);
    try std.testing.expectEqual(@as(u8, 0x00), encoded[0]); // Family high
    try std.testing.expectEqual(@as(u8, 0x01), encoded[1]); // Family low
    try std.testing.expectEqual(@as(u8, 24), encoded[2]); // Source prefix
    try std.testing.expectEqual(@as(u8, 0), encoded[3]); // Scope prefix
}

test "ClientSubnet.buildOption" {
    const allocator = std.testing.allocator;

    const ecs = ClientSubnet{
        .family = .ipv4,
        .source_prefix_length = 24,
        .scope_prefix_length = 0,
        .address = &[_]u8{ 0xC0, 0xA8, 0x01 },
    };

    const option = try ecs.buildOption(allocator);
    defer allocator.free(option);

    // Option code (2) + length (2) + data (7)
    try std.testing.expectEqual(@as(usize, 11), option.len);
    try std.testing.expectEqual(@as(u16, 8), std.mem.readInt(u16, option[0..2], .big)); // Option code
    try std.testing.expectEqual(@as(u16, 7), std.mem.readInt(u16, option[2..4], .big)); // Length
}

test "Cookie.parse client only" {
    const data = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

    const cookie = try Cookie.parse(&data);
    try std.testing.expectEqualSlices(u8, &data, &cookie.client_cookie);
    try std.testing.expect(cookie.server_cookie == null);
}

test "Cookie.parse with server cookie" {
    const data = [_]u8{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Client cookie
        0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, // Server cookie (8 bytes)
    };

    const cookie = try Cookie.parse(&data);
    try std.testing.expectEqualSlices(u8, data[0..8], &cookie.client_cookie);
    try std.testing.expect(cookie.server_cookie != null);
    try std.testing.expectEqual(@as(usize, 8), cookie.server_cookie.?.len);
}

test "Cookie.encode" {
    const allocator = std.testing.allocator;

    const cookie = Cookie{
        .client_cookie = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },
        .server_cookie = null,
    };

    const encoded = try cookie.encode(allocator);
    defer allocator.free(encoded);

    try std.testing.expectEqual(@as(usize, 8), encoded.len);
    try std.testing.expectEqualSlices(u8, &cookie.client_cookie, encoded);
}

test "Cookie.buildOption" {
    const allocator = std.testing.allocator;

    const cookie = Cookie{
        .client_cookie = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },
        .server_cookie = null,
    };

    const option = try cookie.buildOption(allocator);
    defer allocator.free(option);

    // Option code (2) + length (2) + client cookie (8)
    try std.testing.expectEqual(@as(usize, 12), option.len);
    try std.testing.expectEqual(@as(u16, 10), std.mem.readInt(u16, option[0..2], .big)); // Cookie option code
    try std.testing.expectEqual(@as(u16, 8), std.mem.readInt(u16, option[2..4], .big)); // Length
}

test "Cookie.computeClientCookie" {
    const client_ip = [_]u8{ 192, 168, 1, 100 };
    const server_ip = [_]u8{ 8, 8, 8, 8 };
    const secret = [_]u8{0} ** 16;

    const cookie = Cookie.computeClientCookie(&client_ip, &server_ip, secret);

    // Verify deterministic output
    const cookie2 = Cookie.computeClientCookie(&client_ip, &server_ip, secret);
    try std.testing.expectEqualSlices(u8, &cookie.client_cookie, &cookie2.client_cookie);

    // Different input should produce different cookie
    const different_ip = [_]u8{ 192, 168, 1, 101 };
    const cookie3 = Cookie.computeClientCookie(&different_ip, &server_ip, secret);
    try std.testing.expect(!std.mem.eql(u8, &cookie.client_cookie, &cookie3.client_cookie));
}

test "SEC-NEW-05: OptRecord.encode rejects options exceeding u16 max" {
    const allocator = std.testing.allocator;

    // Allocate options larger than u16 max (65535)
    const big_options = try allocator.alloc(u8, 65536);
    defer allocator.free(big_options);
    @memset(big_options, 0);

    const opt = OptRecord{
        .udp_payload_size = 4096,
        .extended_rcode = 0,
        .version = 0,
        .dnssec_ok = false,
        .options = big_options,
    };

    var buffer: [128]u8 = undefined;
    const result = opt.encode(&buffer);
    try std.testing.expectError(error.OptionsTooLarge, result);
}

test "SEC-NEW-05: buildOption rejects data exceeding u16 max" {
    const allocator = std.testing.allocator;

    // Allocate data larger than u16 max
    const big_data = try allocator.alloc(u8, 65536);
    defer allocator.free(big_data);
    @memset(big_data, 0);

    const result = buildOption(allocator, .cookie, big_data);
    try std.testing.expectError(error.OptionsTooLarge, result);
}
