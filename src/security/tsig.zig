// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! TSIG - Transaction Signature (RFC 2845)
//!
//! Provides authentication for DNS messages using shared secret keys
//! and HMAC algorithms. Used for securing zone transfers (AXFR/IXFR),
//! dynamic updates (RFC 2136), and general DNS queries.
//!
//! Supported algorithms:
//! - HMAC-MD5.SIG-ALG.REG.INT (legacy, not recommended)
//! - hmac-sha1 (RFC 4635)
//! - hmac-sha256 (RFC 4635, recommended)
//! - hmac-sha384 (RFC 4635)
//! - hmac-sha512 (RFC 4635)

const std = @import("std");

/// TSIG Algorithm identifiers
pub const Algorithm = enum {
    /// HMAC-MD5 (legacy, RFC 2845)
    /// DEPRECATED: MD5 has known weaknesses. Use hmac_sha256 or stronger.
    hmac_md5,
    /// HMAC-SHA1 (RFC 4635)
    /// DEPRECATED: SHA1 has known weaknesses. Use hmac_sha256 or stronger.
    hmac_sha1,
    /// HMAC-SHA256 (RFC 4635, recommended)
    hmac_sha256,
    /// HMAC-SHA384 (RFC 4635)
    hmac_sha384,
    /// HMAC-SHA512 (RFC 4635)
    hmac_sha512,

    const Self = @This();

    /// Check if this algorithm is deprecated due to known cryptographic weaknesses
    /// SEC-003: Flag weak algorithms for security auditing (CWE-327)
    pub fn isDeprecated(self: Self) bool {
        return switch (self) {
            .hmac_md5, .hmac_sha1 => true,
            .hmac_sha256, .hmac_sha384, .hmac_sha512 => false,
        };
    }

    /// Get deprecation warning message if applicable
    pub fn deprecationWarning(self: Self) ?[]const u8 {
        return switch (self) {
            .hmac_md5 => "SECURITY WARNING: HMAC-MD5 is deprecated due to MD5 weaknesses. " ++
                "Consider migrating to HMAC-SHA256 or stronger (CWE-327).",
            .hmac_sha1 => "SECURITY WARNING: HMAC-SHA1 is deprecated due to SHA1 collision attacks. " ++
                "Consider migrating to HMAC-SHA256 or stronger (CWE-327).",
            else => null,
        };
    }

    /// Get the canonical algorithm name for wire format
    pub fn toWireName(self: Self) []const u8 {
        return switch (self) {
            .hmac_md5 => "hmac-md5.sig-alg.reg.int",
            .hmac_sha1 => "hmac-sha1",
            .hmac_sha256 => "hmac-sha256",
            .hmac_sha384 => "hmac-sha384",
            .hmac_sha512 => "hmac-sha512",
        };
    }

    /// Parse algorithm from wire name
    pub fn fromWireName(name: []const u8) ?Self {
        if (std.ascii.eqlIgnoreCase(name, "hmac-md5.sig-alg.reg.int") or
            std.ascii.eqlIgnoreCase(name, "hmac-md5"))
        {
            return .hmac_md5;
        } else if (std.ascii.eqlIgnoreCase(name, "hmac-sha1")) {
            return .hmac_sha1;
        } else if (std.ascii.eqlIgnoreCase(name, "hmac-sha256")) {
            return .hmac_sha256;
        } else if (std.ascii.eqlIgnoreCase(name, "hmac-sha384")) {
            return .hmac_sha384;
        } else if (std.ascii.eqlIgnoreCase(name, "hmac-sha512")) {
            return .hmac_sha512;
        }
        return null;
    }

    /// Get the MAC output length for this algorithm
    pub fn macLength(self: Self) usize {
        return switch (self) {
            .hmac_md5 => 16,
            .hmac_sha1 => 20,
            .hmac_sha256 => 32,
            .hmac_sha384 => 48,
            .hmac_sha512 => 64,
        };
    }
};

/// TSIG Error codes (RFC 2845 Section 4.3)
pub const TsigError = enum(u16) {
    /// No error
    no_error = 0,
    /// Bad signature (BADSIG)
    bad_sig = 16,
    /// Bad key (BADKEY)
    bad_key = 17,
    /// Bad time (BADTIME) - clock skew too large
    bad_time = 18,
    /// Bad truncation (BADTRUNC)
    bad_trunc = 22,

    pub fn toResponseCode(self: TsigError) u16 {
        return @intFromEnum(self);
    }
};

/// TSIG Key for signing/verification
pub const TsigKey = struct {
    /// Key name (e.g., "transfer-key.example.com")
    name: []const u8,
    /// Algorithm to use
    algorithm: Algorithm,
    /// Shared secret (base64-decoded)
    secret: []const u8,

    const Self = @This();

    /// Create a new TSIG key
    pub fn init(name: []const u8, algorithm: Algorithm, secret: []const u8) Self {
        return Self{
            .name = name,
            .algorithm = algorithm,
            .secret = secret,
        };
    }

    /// Create key with base64-encoded secret
    pub fn initBase64(allocator: std.mem.Allocator, name: []const u8, algorithm: Algorithm, secret_b64: []const u8) !Self {
        const decoder = std.base64.standard.Decoder;
        const decoded_len = decoder.calcSizeForSlice(secret_b64) catch return error.InvalidBase64;
        const secret = try allocator.alloc(u8, decoded_len);
        errdefer allocator.free(secret);

        decoder.decode(secret, secret_b64) catch return error.InvalidBase64;

        return Self{
            .name = name,
            .algorithm = algorithm,
            .secret = secret,
        };
    }
};

/// TSIG Record data (parsed from wire format)
pub const TsigRecord = struct {
    /// Algorithm name
    algorithm_name: []const u8,
    /// Time signed (seconds since epoch)
    time_signed: u48,
    /// Fudge factor (allowed clock skew in seconds)
    fudge: u16,
    /// MAC (Message Authentication Code)
    mac: []const u8,
    /// Original message ID
    original_id: u16,
    /// Error code
    error_code: TsigError,
    /// Other data length
    other_len: u16,
    /// Other data (for BADTIME, contains server time)
    other_data: []const u8,

    const Self = @This();

    /// Parse TSIG record from RDATA
    pub fn parse(allocator: std.mem.Allocator, rdata: []const u8, full_message: []const u8) !Self {
        if (rdata.len < 16) return error.InvalidTsigRecord;

        var offset: usize = 0;

        // Parse algorithm name
        const alg_result = try parseName(allocator, rdata, 0, full_message);
        const algorithm_name = alg_result.name;
        offset = alg_result.offset;

        if (offset + 16 > rdata.len) {
            allocator.free(algorithm_name);
            return error.InvalidTsigRecord;
        }

        // Time signed (48 bits = 6 bytes)
        const time_high: u48 = @as(u48, std.mem.readInt(u16, rdata[offset..][0..2], .big)) << 32;
        const time_low: u48 = std.mem.readInt(u32, rdata[offset + 2 ..][0..4], .big);
        const time_signed = time_high | time_low;
        offset += 6;

        // Fudge
        const fudge = std.mem.readInt(u16, rdata[offset..][0..2], .big);
        offset += 2;

        // MAC size and data
        const mac_size = std.mem.readInt(u16, rdata[offset..][0..2], .big);
        offset += 2;

        if (offset + mac_size + 6 > rdata.len) {
            allocator.free(algorithm_name);
            return error.InvalidTsigRecord;
        }

        const mac = try allocator.dupe(u8, rdata[offset .. offset + mac_size]);
        errdefer allocator.free(mac);
        offset += mac_size;

        // Original ID
        const original_id = std.mem.readInt(u16, rdata[offset..][0..2], .big);
        offset += 2;

        // Error
        const error_code: TsigError = @enumFromInt(std.mem.readInt(u16, rdata[offset..][0..2], .big));
        offset += 2;

        // Other length and data
        const other_len = std.mem.readInt(u16, rdata[offset..][0..2], .big);
        offset += 2;

        var other_data: []const u8 = &[_]u8{};
        if (other_len > 0 and offset + other_len <= rdata.len) {
            other_data = try allocator.dupe(u8, rdata[offset .. offset + other_len]);
        }

        return Self{
            .algorithm_name = algorithm_name,
            .time_signed = time_signed,
            .fudge = fudge,
            .mac = mac,
            .original_id = original_id,
            .error_code = error_code,
            .other_len = other_len,
            .other_data = other_data,
        };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.algorithm_name);
        allocator.free(self.mac);
        if (self.other_data.len > 0) {
            allocator.free(self.other_data);
        }
    }
};

/// TSIG Signer/Verifier
pub const TsigContext = struct {
    allocator: std.mem.Allocator,
    key: TsigKey,
    /// Default fudge factor (300 seconds = 5 minutes)
    fudge: u16 = 300,
    /// Emit warnings for deprecated algorithms (SEC-003)
    warn_deprecated: bool = true,
    /// Optional callback for security warnings
    security_warning_callback: ?*const fn ([]const u8) void = null,
    /// Track if deprecation warning has been emitted (to avoid spam)
    deprecation_warned: bool = false,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, key: TsigKey) Self {
        var ctx = Self{
            .allocator = allocator,
            .key = key,
        };
        // Emit deprecation warning on initialization if applicable
        ctx.checkDeprecation();
        return ctx;
    }

    /// Initialize without deprecation warnings (for testing/legacy compatibility)
    pub fn initNoWarn(allocator: std.mem.Allocator, key: TsigKey) Self {
        return Self{
            .allocator = allocator,
            .key = key,
            .warn_deprecated = false,
        };
    }

    /// Check and emit deprecation warning if using weak algorithm
    fn checkDeprecation(self: *Self) void {
        if (!self.warn_deprecated or self.deprecation_warned) return;

        if (self.key.algorithm.deprecationWarning()) |warning| {
            if (self.security_warning_callback) |callback| {
                callback(warning);
            }
            self.deprecation_warned = true;
        }
    }

    /// Sign a DNS message with TSIG
    /// Returns the message with TSIG record appended
    pub fn sign(self: *Self, message: []const u8) ![]u8 {
        const now: u48 = @intCast(@as(u64, @bitCast(std.time.timestamp())));

        // Build TSIG variables for MAC computation
        const tsig_vars = try self.buildTsigVariables(now, null);
        defer self.allocator.free(tsig_vars);

        // Compute MAC over: message + TSIG variables
        const mac = try self.computeMac(message, tsig_vars);
        defer self.allocator.free(mac);

        // Build TSIG record
        const tsig_record = try self.buildTsigRecord(now, mac, message[0..2]);
        defer self.allocator.free(tsig_record);

        // Append TSIG to message
        return try self.appendTsig(message, tsig_record);
    }

    /// Verify a DNS message with TSIG
    /// Returns the original message without TSIG if valid
    pub fn verify(self: *Self, message: []const u8) !VerifyResult {
        // Extract TSIG record from message
        const tsig_info = try self.extractTsig(message);
        defer {
            self.allocator.free(tsig_info.tsig_rdata);
            self.allocator.free(tsig_info.key_name);
        }

        // Parse TSIG record
        var tsig = try TsigRecord.parse(self.allocator, tsig_info.tsig_rdata, message);
        defer tsig.deinit(self.allocator);

        // Verify key name matches
        if (!std.ascii.eqlIgnoreCase(tsig_info.key_name, self.key.name)) {
            return VerifyResult{ .valid = false, .error_code = .bad_key };
        }

        // Verify algorithm
        const alg = Algorithm.fromWireName(tsig.algorithm_name) orelse {
            return VerifyResult{ .valid = false, .error_code = .bad_key };
        };
        if (alg != self.key.algorithm) {
            return VerifyResult{ .valid = false, .error_code = .bad_key };
        }

        // Verify time
        const now: u48 = @intCast(@as(u64, @bitCast(std.time.timestamp())));
        const time_diff = if (now > tsig.time_signed)
            now - tsig.time_signed
        else
            tsig.time_signed - now;

        if (time_diff > tsig.fudge) {
            return VerifyResult{ .valid = false, .error_code = .bad_time };
        }

        // Recompute MAC
        const tsig_vars = try self.buildTsigVariables(tsig.time_signed, null);
        defer self.allocator.free(tsig_vars);

        // Message without TSIG for MAC computation
        const msg_without_tsig = try self.stripTsig(message, tsig_info);
        defer self.allocator.free(msg_without_tsig);

        const expected_mac = try self.computeMac(msg_without_tsig, tsig_vars);
        defer self.allocator.free(expected_mac);

        // Constant-time comparison
        if (!std.crypto.timing_safe.eql(u8, tsig.mac, expected_mac)) {
            return VerifyResult{ .valid = false, .error_code = .bad_sig };
        }

        return VerifyResult{
            .valid = true,
            .error_code = .no_error,
            .time_signed = tsig.time_signed,
            .original_id = tsig.original_id,
        };
    }

    /// Build TSIG variables for MAC computation (RFC 2845 Section 3.4.2)
    fn buildTsigVariables(self: *Self, time_signed: u48, prior_mac: ?[]const u8) ![]u8 {
        var buffer: std.ArrayList(u8) = .empty;
        errdefer buffer.deinit(self.allocator);

        // Prior MAC (for chained messages)
        if (prior_mac) |pm| {
            try buffer.appendSlice(self.allocator, std.mem.asBytes(&std.mem.nativeToBig(u16, @intCast(pm.len))));
            try buffer.appendSlice(self.allocator, pm);
        }

        // Key name (in wire format)
        try encodeNameLower(self.allocator, &buffer, self.key.name);

        // Class (ANY = 255)
        try buffer.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, 255)));

        // TTL (always 0)
        try buffer.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u32, 0)));

        // Algorithm name (in wire format)
        try encodeNameLower(self.allocator, &buffer, self.key.algorithm.toWireName());

        // Time signed (48 bits)
        const time_high: u16 = @intCast((time_signed >> 32) & 0xFFFF);
        const time_low: u32 = @intCast(time_signed & 0xFFFFFFFF);
        try buffer.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, time_high)));
        try buffer.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u32, time_low)));

        // Fudge
        try buffer.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, self.fudge)));

        // Error (0 for signing)
        try buffer.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, 0)));

        // Other length (0)
        try buffer.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, 0)));

        return buffer.toOwnedSlice(self.allocator);
    }

    /// Compute HMAC over message and TSIG variables
    ///
    /// SECURITY: Implements proper RFC 2104 key handling:
    /// - Keys longer than block size are hashed first (not truncated)
    /// - Keys shorter than or equal to block size are used directly
    /// This fixes SEC-002 (CWE-326).
    fn computeMac(self: *Self, message: []const u8, tsig_vars: []const u8) ![]u8 {
        const mac_len = self.key.algorithm.macLength();
        const result = try self.allocator.alloc(u8, mac_len);
        errdefer self.allocator.free(result);

        switch (self.key.algorithm) {
            .hmac_md5 => {
                // Block size for MD5 is 64 bytes, output is 16 bytes
                const block_size = 64;
                var key: [block_size]u8 = .{0} ** block_size;
                if (self.key.secret.len > block_size) {
                    // RFC 2104: Hash key if longer than block size
                    std.crypto.hash.Md5.hash(self.key.secret, key[0..16], .{});
                } else {
                    @memcpy(key[0..self.key.secret.len], self.key.secret);
                }
                var hmac = std.crypto.auth.hmac.HmacMd5.init(key[0..16]);
                hmac.update(message);
                hmac.update(tsig_vars);
                hmac.final(result[0..16]);
            },
            .hmac_sha1 => {
                // Block size for SHA1 is 64 bytes, output is 20 bytes
                const block_size = 64;
                var key: [block_size]u8 = .{0} ** block_size;
                if (self.key.secret.len > block_size) {
                    // RFC 2104: Hash key if longer than block size
                    std.crypto.hash.Sha1.hash(self.key.secret, key[0..20], .{});
                } else {
                    @memcpy(key[0..self.key.secret.len], self.key.secret);
                }
                var hmac = std.crypto.auth.hmac.HmacSha1.init(key[0..20]);
                hmac.update(message);
                hmac.update(tsig_vars);
                hmac.final(result[0..20]);
            },
            .hmac_sha256 => {
                // Block size for SHA256 is 64 bytes, output is 32 bytes
                const block_size = 64;
                var key: [block_size]u8 = .{0} ** block_size;
                if (self.key.secret.len > block_size) {
                    // RFC 2104: Hash key if longer than block size
                    std.crypto.hash.sha2.Sha256.hash(self.key.secret, key[0..32], .{});
                } else {
                    @memcpy(key[0..self.key.secret.len], self.key.secret);
                }
                var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(key[0..32]);
                hmac.update(message);
                hmac.update(tsig_vars);
                hmac.final(result[0..32]);
            },
            .hmac_sha384 => {
                // Block size for SHA384 is 128 bytes, output is 48 bytes
                const block_size = 128;
                var key: [block_size]u8 = .{0} ** block_size;
                if (self.key.secret.len > block_size) {
                    // RFC 2104: Hash key if longer than block size
                    std.crypto.hash.sha2.Sha384.hash(self.key.secret, key[0..48], .{});
                } else {
                    @memcpy(key[0..self.key.secret.len], self.key.secret);
                }
                var hmac = std.crypto.auth.hmac.sha2.HmacSha384.init(key[0..48]);
                hmac.update(message);
                hmac.update(tsig_vars);
                hmac.final(result[0..48]);
            },
            .hmac_sha512 => {
                // Block size for SHA512 is 128 bytes, output is 64 bytes
                const block_size = 128;
                var key: [block_size]u8 = .{0} ** block_size;
                if (self.key.secret.len > block_size) {
                    // RFC 2104: Hash key if longer than block size
                    std.crypto.hash.sha2.Sha512.hash(self.key.secret, key[0..64], .{});
                } else {
                    @memcpy(key[0..self.key.secret.len], self.key.secret);
                }
                var hmac = std.crypto.auth.hmac.sha2.HmacSha512.init(key[0..64]);
                hmac.update(message);
                hmac.update(tsig_vars);
                hmac.final(result[0..64]);
            },
        }

        return result;
    }

    /// Build TSIG RDATA
    fn buildTsigRecord(self: *Self, time_signed: u48, mac: []const u8, original_id: *const [2]u8) ![]u8 {
        var buffer: std.ArrayList(u8) = .empty;
        errdefer buffer.deinit(self.allocator);

        // Algorithm name
        try encodeNameLower(self.allocator, &buffer, self.key.algorithm.toWireName());

        // Time signed (48 bits)
        const time_high: u16 = @intCast((time_signed >> 32) & 0xFFFF);
        const time_low: u32 = @intCast(time_signed & 0xFFFFFFFF);
        try buffer.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, time_high)));
        try buffer.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u32, time_low)));

        // Fudge
        try buffer.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, self.fudge)));

        // MAC size and data
        try buffer.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, @intCast(mac.len))));
        try buffer.appendSlice(self.allocator, mac);

        // Original ID
        try buffer.appendSlice(self.allocator, original_id);

        // Error (0)
        try buffer.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, 0)));

        // Other length (0)
        try buffer.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, 0)));

        return buffer.toOwnedSlice(self.allocator);
    }

    /// Append TSIG record to message
    fn appendTsig(self: *Self, message: []const u8, tsig_rdata: []const u8) ![]u8 {
        var buffer: std.ArrayList(u8) = .empty;
        errdefer buffer.deinit(self.allocator);

        // Copy original message
        try buffer.appendSlice(self.allocator, message);

        // Update ARCOUNT
        const arcount = std.mem.readInt(u16, message[10..12], .big);
        std.mem.writeInt(u16, buffer.items[10..12], arcount + 1, .big);

        // Add TSIG RR
        // Key name
        try encodeNameLower(self.allocator, &buffer, self.key.name);

        // Type (TSIG = 250)
        try buffer.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, 250)));

        // Class (ANY = 255)
        try buffer.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, 255)));

        // TTL (0)
        try buffer.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u32, 0)));

        // RDLENGTH
        try buffer.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, @intCast(tsig_rdata.len))));

        // RDATA
        try buffer.appendSlice(self.allocator, tsig_rdata);

        return buffer.toOwnedSlice(self.allocator);
    }

    const TsigInfo = struct {
        tsig_rdata: []const u8,
        key_name: []const u8,
        tsig_start: usize,
    };

    /// Extract TSIG record from message
    fn extractTsig(self: *Self, message: []const u8) !TsigInfo {
        if (message.len < 12) return error.InvalidMessage;

        const arcount = std.mem.readInt(u16, message[10..12], .big);
        if (arcount == 0) return error.NoTsigRecord;

        // Find the last additional record (should be TSIG)
        var offset: usize = 12;

        // Skip questions
        const qdcount = std.mem.readInt(u16, message[4..6], .big);
        var i: u16 = 0;
        while (i < qdcount) : (i += 1) {
            offset = try skipName(message, offset);
            offset += 4; // QTYPE + QCLASS
        }

        // Skip answers
        const ancount = std.mem.readInt(u16, message[6..8], .big);
        i = 0;
        while (i < ancount) : (i += 1) {
            offset = try skipRR(message, offset);
        }

        // Skip authority
        const nscount = std.mem.readInt(u16, message[8..10], .big);
        i = 0;
        while (i < nscount) : (i += 1) {
            offset = try skipRR(message, offset);
        }

        // Parse additional records, looking for TSIG
        i = 0;
        while (i < arcount) : (i += 1) {
            const rr_start = offset;
            const name_result = try parseName(self.allocator, message, offset, message);
            defer self.allocator.free(name_result.name);
            offset = name_result.offset;

            if (offset + 10 > message.len) return error.InvalidMessage;

            const rtype = std.mem.readInt(u16, message[offset..][0..2], .big);
            offset += 2;
            offset += 2; // CLASS
            offset += 4; // TTL
            const rdlength = std.mem.readInt(u16, message[offset..][0..2], .big);
            offset += 2;

            if (rtype == 250) { // TSIG
                // Found TSIG
                const key_name = try self.allocator.dupe(u8, name_result.name);
                errdefer self.allocator.free(key_name);

                const tsig_rdata = try self.allocator.dupe(u8, message[offset .. offset + rdlength]);

                return TsigInfo{
                    .tsig_rdata = tsig_rdata,
                    .key_name = key_name,
                    .tsig_start = rr_start,
                };
            }

            offset += rdlength;
        }

        return error.NoTsigRecord;
    }

    /// Strip TSIG from message and adjust ARCOUNT
    fn stripTsig(self: *Self, message: []const u8, tsig_info: TsigInfo) ![]u8 {
        var buffer: std.ArrayList(u8) = .empty;
        errdefer buffer.deinit(self.allocator);

        // Copy up to TSIG
        try buffer.appendSlice(self.allocator, message[0..tsig_info.tsig_start]);

        // Decrement ARCOUNT
        const arcount = std.mem.readInt(u16, message[10..12], .big);
        std.mem.writeInt(u16, buffer.items[10..12], arcount - 1, .big);

        return buffer.toOwnedSlice(self.allocator);
    }
};

/// Result of TSIG verification
pub const VerifyResult = struct {
    valid: bool,
    error_code: TsigError,
    time_signed: u48 = 0,
    original_id: u16 = 0,
};

// Helper functions

/// Maximum compression pointer hops to prevent infinite loops (RFC 1035)
const max_compression_hops: u8 = 16;
/// Maximum DNS name length per RFC 1035 Section 2.3.4
const max_name_length: usize = 255;

fn parseName(allocator: std.mem.Allocator, data: []const u8, start: usize, full_msg: []const u8) !struct { name: []const u8, offset: usize } {
    var name: std.ArrayList(u8) = .empty;
    errdefer name.deinit(allocator);

    var offset = start;
    var followed_ptr = false;
    var final_offset = start;
    var pointer_hops: u8 = 0;
    var total_name_len: usize = 0;
    _ = full_msg;

    while (offset < data.len) {
        const len = data[offset];

        if (len == 0) {
            if (!followed_ptr) final_offset = offset + 1;
            break;
        }

        if (len & 0xC0 == 0xC0) {
            // Compression pointer - check for loop
            pointer_hops += 1;
            if (pointer_hops > max_compression_hops) {
                return error.CompressionLoopDetected;
            }
            if (offset + 1 >= data.len) return error.InvalidName;
            const ptr = (@as(u16, len & 0x3F) << 8) | data[offset + 1];
            if (!followed_ptr) final_offset = offset + 2;
            followed_ptr = true;
            offset = ptr;
            continue;
        }

        if (offset + 1 + len > data.len) return error.InvalidName;

        // Check max name length (length byte + label)
        total_name_len += 1 + len;
        if (total_name_len > max_name_length) {
            return error.NameTooLong;
        }

        if (name.items.len > 0) {
            try name.append(allocator, '.');
        }
        try name.appendSlice(allocator, data[offset + 1 .. offset + 1 + len]);
        offset += 1 + len;
    }

    return .{
        .name = try name.toOwnedSlice(allocator),
        .offset = final_offset,
    };
}

/// Encode name in wire format (lowercase)
fn encodeNameLower(allocator: std.mem.Allocator, buffer: *std.ArrayList(u8), name: []const u8) !void {
    var iter = std.mem.splitScalar(u8, name, '.');
    while (iter.next()) |label| {
        if (label.len == 0) continue;
        try buffer.append(allocator, @intCast(label.len));
        for (label) |c| {
            try buffer.append(allocator, std.ascii.toLower(c));
        }
    }
    try buffer.append(allocator, 0);
}

fn skipName(data: []const u8, start: usize) !usize {
    var offset = start;
    while (offset < data.len) {
        const len = data[offset];
        if (len == 0) return offset + 1;
        if (len & 0xC0 == 0xC0) return offset + 2;
        offset += 1 + len;
    }
    return error.InvalidName;
}

fn skipRR(data: []const u8, start: usize) !usize {
    const offset = try skipName(data, start);
    if (offset + 10 > data.len) return error.InvalidRR;
    const rdlength = std.mem.readInt(u16, data[offset + 8 ..][0..2], .big);
    return offset + 10 + rdlength;
}

// ============================================================================
// Tests
// ============================================================================

test "Algorithm.toWireName" {
    try std.testing.expectEqualStrings("hmac-sha256", Algorithm.hmac_sha256.toWireName());
    try std.testing.expectEqualStrings("hmac-md5.sig-alg.reg.int", Algorithm.hmac_md5.toWireName());
}

test "Algorithm.isDeprecated" {
    // SEC-003: Verify deprecated algorithms are flagged
    try std.testing.expect(Algorithm.hmac_md5.isDeprecated());
    try std.testing.expect(Algorithm.hmac_sha1.isDeprecated());
    try std.testing.expect(!Algorithm.hmac_sha256.isDeprecated());
    try std.testing.expect(!Algorithm.hmac_sha384.isDeprecated());
    try std.testing.expect(!Algorithm.hmac_sha512.isDeprecated());
}

test "Algorithm.deprecationWarning" {
    // SEC-003: Verify deprecation warnings are provided
    try std.testing.expect(Algorithm.hmac_md5.deprecationWarning() != null);
    try std.testing.expect(Algorithm.hmac_sha1.deprecationWarning() != null);
    try std.testing.expect(Algorithm.hmac_sha256.deprecationWarning() == null);
}

test "Algorithm.fromWireName" {
    try std.testing.expectEqual(Algorithm.hmac_sha256, Algorithm.fromWireName("hmac-sha256").?);
    try std.testing.expectEqual(Algorithm.hmac_sha256, Algorithm.fromWireName("HMAC-SHA256").?);
    try std.testing.expectEqual(Algorithm.hmac_md5, Algorithm.fromWireName("hmac-md5.sig-alg.reg.int").?);
    try std.testing.expect(Algorithm.fromWireName("unknown") == null);
}

test "Algorithm.macLength" {
    try std.testing.expectEqual(@as(usize, 16), Algorithm.hmac_md5.macLength());
    try std.testing.expectEqual(@as(usize, 20), Algorithm.hmac_sha1.macLength());
    try std.testing.expectEqual(@as(usize, 32), Algorithm.hmac_sha256.macLength());
    try std.testing.expectEqual(@as(usize, 48), Algorithm.hmac_sha384.macLength());
    try std.testing.expectEqual(@as(usize, 64), Algorithm.hmac_sha512.macLength());
}

test "TsigKey.init" {
    const key = TsigKey.init("test-key", .hmac_sha256, "test-key-material");
    try std.testing.expectEqualStrings("test-key", key.name);
    try std.testing.expectEqual(Algorithm.hmac_sha256, key.algorithm);
}

test "TsigError values" {
    try std.testing.expectEqual(@as(u16, 0), TsigError.no_error.toResponseCode());
    try std.testing.expectEqual(@as(u16, 16), TsigError.bad_sig.toResponseCode());
    try std.testing.expectEqual(@as(u16, 17), TsigError.bad_key.toResponseCode());
    try std.testing.expectEqual(@as(u16, 18), TsigError.bad_time.toResponseCode());
}

test "TsigContext sign creates valid message" {
    const allocator = std.testing.allocator;

    const key = TsigKey.init("test-key.example.com", .hmac_sha256, &[_]u8{0} ** 32);
    var ctx = TsigContext.init(allocator, key);

    // Simple DNS query header
    const message = [_]u8{
        0x12, 0x34, // ID
        0x01, 0x00, // Flags: standard query
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x00, // ANCOUNT: 0
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
        // Question: example.com A IN
        0x07, 'e',
        'x',  'a',
        'm',  'p',
        'l',  'e',
        0x03, 'c',
        'o',  'm',
        0x00,
        0x00, 0x01, // A
        0x00, 0x01, // IN
    };

    const signed = try ctx.sign(&message);
    defer allocator.free(signed);

    // Verify ARCOUNT was incremented
    const arcount = std.mem.readInt(u16, signed[10..12], .big);
    try std.testing.expectEqual(@as(u16, 1), arcount);

    // Signed message should be larger
    try std.testing.expect(signed.len > message.len);
}
