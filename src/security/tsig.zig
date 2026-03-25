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
/// Non-exhaustive to safely handle unknown error codes from wire data
/// without panicking (SEC-C21, CWE-704).
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
    /// Unknown/unrecognized error codes from wire data
    _,

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

    /// SECURITY (SEC-SCAN-01): Zero secret material on cleanup to prevent
    /// residual secrets in freed memory (CWE-244: Heap Inspection).
    /// If the secret was heap-allocated (via initBase64), pass the same
    /// allocator to also free the backing memory after zeroing.
    pub fn deinit(self: *Self, allocator: ?std.mem.Allocator) void {
        // Zero the secret bytes in-place for defense-in-depth.
        // @constCast is required because the field is []const u8; we own
        // the backing memory when it was allocated via initBase64.
        // @volatileCast prevents the compiler from optimizing out the zeroing.
        if (self.secret.len > 0) {
            const mutable = @constCast(self.secret);
            const volatile_ptr: [*]volatile u8 = @ptrCast(mutable.ptr);
            const volatile_slice: []volatile u8 = volatile_ptr[0..mutable.len];
            std.crypto.secureZero(u8, volatile_slice);
        }
        if (allocator) |alloc| {
            alloc.free(self.secret);
        }
        self.secret = &.{};
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
    pub fn parse(allocator: std.mem.Allocator, rdata: []const u8) !Self {
        if (rdata.len < 16) return error.InvalidTsigRecord;

        var offset: usize = 0;

        // Parse algorithm name
        const alg_result = try parseName_(allocator, rdata, 0);
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
        if (other_len > 0) {
            // SECURITY (SEC-NEW-04): Reject truncated other_data instead of silently ignoring
            if (offset + other_len > rdata.len) return error.InvalidTsigRecord;
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
        // When signing a new message, error is 0 and other_data is empty.
        const tsig_vars = try self.buildTsigVariables(now, null, 0, &.{});
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
        var tsig = try TsigRecord.parse(self.allocator, tsig_info.tsig_rdata);
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

        // SECURITY (SEC-C101): Verify MAC BEFORE time check to prevent
        // timing oracle attacks. An attacker could manipulate fudge/time_signed
        // to learn whether the MAC was valid by observing different error codes.

        // Recompute MAC using actual error and other_data from received TSIG
        // (SEC-AUDIT-03: these fields are part of the MAC input per RFC 2845)
        const tsig_vars = try self.buildTsigVariables(
            tsig.time_signed,
            null,
            tsig.error_code.toResponseCode(),
            tsig.other_data,
        );
        defer self.allocator.free(tsig_vars);

        // Message without TSIG for MAC computation
        const msg_without_tsig = try self.stripTsig(message, tsig_info);
        defer self.allocator.free(msg_without_tsig);

        const expected_mac = try self.computeMac(msg_without_tsig, tsig_vars);
        defer self.allocator.free(expected_mac);

        // Constant-time MAC comparison using known algorithm output sizes.
        // std.crypto.timing_safe.eql requires fixed-size arrays, so we convert
        // based on the expected MAC length for the configured algorithm.
        const mac_valid = switch (self.key.algorithm) {
            .hmac_md5 => tsig.mac.len == 16 and expected_mac.len == 16 and
                std.crypto.timing_safe.eql([16]u8, tsig.mac[0..16].*, expected_mac[0..16].*),
            .hmac_sha1 => tsig.mac.len == 20 and expected_mac.len == 20 and
                std.crypto.timing_safe.eql([20]u8, tsig.mac[0..20].*, expected_mac[0..20].*),
            .hmac_sha256 => tsig.mac.len == 32 and expected_mac.len == 32 and
                std.crypto.timing_safe.eql([32]u8, tsig.mac[0..32].*, expected_mac[0..32].*),
            .hmac_sha384 => tsig.mac.len == 48 and expected_mac.len == 48 and
                std.crypto.timing_safe.eql([48]u8, tsig.mac[0..48].*, expected_mac[0..48].*),
            .hmac_sha512 => tsig.mac.len == 64 and expected_mac.len == 64 and
                std.crypto.timing_safe.eql([64]u8, tsig.mac[0..64].*, expected_mac[0..64].*),
        };
        if (!mac_valid) {
            return VerifyResult{ .valid = false, .error_code = .bad_sig };
        }

        // SECURITY (SEC-C100): Reject excessively large fudge values.
        // An attacker-controlled fudge could bypass time validation entirely.
        // Limit to twice the verifier's configured fudge as a reasonable upper bound.
        // SEC-AUDIT-08: Widen to u32 before multiplication to prevent u16 overflow
        // when self.fudge > 32767 (e.g. 65535 * 2 = 131070 exceeds u16 max).
        if (@as(u32, tsig.fudge) > @as(u32, self.fudge) * 2) {
            return VerifyResult{ .valid = false, .error_code = .bad_time };
        }

        // Verify time (now safe -- MAC is already verified above)
        const now: u48 = @intCast(@as(u64, @bitCast(std.time.timestamp())));
        const time_diff = if (now > tsig.time_signed)
            now - tsig.time_signed
        else
            tsig.time_signed - now;

        if (time_diff > tsig.fudge) {
            return VerifyResult{ .valid = false, .error_code = .bad_time };
        }

        return VerifyResult{
            .valid = true,
            .error_code = .no_error,
            .time_signed = tsig.time_signed,
            .original_id = tsig.original_id,
        };
    }

    /// Build TSIG variables for MAC computation (RFC 2845 Section 3.4.2)
    ///
    /// `error_code` and `other_data` are included in the MAC input per the
    /// RFC.  Callers signing a new message pass 0 / empty; callers verifying
    /// a received message must pass the values from the received TSIG record
    /// so that the recomputed MAC matches the original (SEC-AUDIT-03).
    fn buildTsigVariables(self: *Self, time_signed: u48, prior_mac: ?[]const u8, error_code: u16, other_data: []const u8) ![]u8 {
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

        // Error code (SEC-AUDIT-03: use actual value, not hardcoded 0)
        try buffer.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, error_code)));

        // Other data length + data (SEC-AUDIT-03: use actual values)
        try buffer.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, @intCast(other_data.len))));
        if (other_data.len > 0) {
            try buffer.appendSlice(self.allocator, other_data);
        }

        return buffer.toOwnedSlice(self.allocator);
    }

    /// Compute HMAC over message and TSIG variables
    ///
    /// SECURITY: Delegates key handling to Zig's std.crypto.auth.hmac which
    /// implements RFC 2104 correctly: keys longer than block size are hashed
    /// first, keys shorter are zero-padded internally. Previous manual key
    /// handling truncated keys between hash-output-length and block-size,
    /// producing wrong MACs (SEC-C23, CWE-326).
    fn computeMac(self: *Self, message: []const u8, tsig_vars: []const u8) ![]u8 {
        const mac_len = self.key.algorithm.macLength();
        const result = try self.allocator.alloc(u8, mac_len);
        errdefer self.allocator.free(result);

        // Pass the raw secret directly to HMAC init. Zig's HMAC implementation
        // handles RFC 2104 key sizing internally (hash if > block size, zero-pad
        // if shorter). This avoids the previous bug where manual pre-processing
        // truncated keys between hash-output-length and block-size.
        //
        // SECURITY: Each HMAC instance is securely zeroed after use via defer
        // to prevent key-derived material from leaking through stack memory
        // (SEC-C25, CWE-244).
        switch (self.key.algorithm) {
            .hmac_md5 => {
                var hmac = std.crypto.auth.hmac.HmacMd5.init(self.key.secret);
                defer secureZeroHmac(@TypeOf(hmac), &hmac);
                hmac.update(message);
                hmac.update(tsig_vars);
                hmac.final(result[0..16]);
            },
            .hmac_sha1 => {
                var hmac = std.crypto.auth.hmac.HmacSha1.init(self.key.secret);
                defer secureZeroHmac(@TypeOf(hmac), &hmac);
                hmac.update(message);
                hmac.update(tsig_vars);
                hmac.final(result[0..20]);
            },
            .hmac_sha256 => {
                var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(self.key.secret);
                defer secureZeroHmac(@TypeOf(hmac), &hmac);
                hmac.update(message);
                hmac.update(tsig_vars);
                hmac.final(result[0..32]);
            },
            .hmac_sha384 => {
                var hmac = std.crypto.auth.hmac.sha2.HmacSha384.init(self.key.secret);
                defer secureZeroHmac(@TypeOf(hmac), &hmac);
                hmac.update(message);
                hmac.update(tsig_vars);
                hmac.final(result[0..48]);
            },
            .hmac_sha512 => {
                var hmac = std.crypto.auth.hmac.sha2.HmacSha512.init(self.key.secret);
                defer secureZeroHmac(@TypeOf(hmac), &hmac);
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
        // SECURITY (SEC-SCAN-02): Check for u16 overflow before incrementing (CWE-190)
        const arcount = std.mem.readInt(u16, message[10..12], .big);
        if (arcount == std.math.maxInt(u16)) return error.ArcountOverflow;
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
        // SECURITY (SEC-SCAN-06): Bounds check before @intCast to u16 (CWE-681)
        if (tsig_rdata.len > std.math.maxInt(u16)) return error.RdlengthOverflow;
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
            // SECURITY (SEC-NEW-06): Validate room for QTYPE + QCLASS after name
            if (offset + 4 > message.len) return error.InvalidMessage;
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
            const name_result = try parseName_(self.allocator, message, offset);
            defer self.allocator.free(name_result.name);
            offset = name_result.offset;

            if (offset + 10 > message.len) return error.InvalidMessage;

            const rtype = std.mem.readInt(u16, message[offset..][0..2], .big);
            offset += 2;
            offset += 2; // CLASS
            offset += 4; // TTL
            const rdlength = std.mem.readInt(u16, message[offset..][0..2], .big);
            offset += 2;

            // SECURITY (SEC-NEW-01): Validate rdlength does not exceed message
            if (offset + rdlength > message.len) return error.InvalidMessage;

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

/// Securely zero an HMAC state struct to prevent key-derived material from
/// leaking through stack memory (SEC-C25, CWE-244).
fn secureZeroHmac(comptime T: type, hmac_ptr: *T) void {
    const hmac_bytes: *[@sizeOf(T)]u8 = @ptrCast(hmac_ptr);
    std.crypto.secureZero(u8, hmac_bytes);
}

// Helper functions -- delegated to shared dns_name module to avoid duplication
const dns_name = @import("dns_name");
const parseName_ = dns_name.parseName;
const encodeNameLower = dns_name.encodeNameLower;
const skipName = dns_name.skipName;
const skipRR = dns_name.skipRR;

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

test "SEC-C21: TsigError handles unknown error codes without panic" {
    // Unknown error code from wire data must not panic
    const unknown_err: TsigError = @enumFromInt(999);
    try std.testing.expectEqual(@as(u16, 999), unknown_err.toResponseCode());

    // Known values still work
    const no_err: TsigError = @enumFromInt(0);
    try std.testing.expectEqual(TsigError.no_error, no_err);
}

test "SEC-C21: TsigRecord.parse does not panic on unknown error code" {
    const allocator = std.testing.allocator;

    // Build minimal TSIG RDATA with unknown error code
    // Structure: algorithm_name (wire format) + time(6) + fudge(2) + mac_size(2) + mac + original_id(2) + error(2) + other_len(2)
    var rdata_buf: [32]u8 = .{0} ** 32;
    var offset: usize = 0;

    // Algorithm name: "." (root) = single zero byte
    rdata_buf[offset] = 0;
    offset += 1;

    // Time signed (6 bytes)
    offset += 6;

    // Fudge (2 bytes)
    std.mem.writeInt(u16, rdata_buf[offset..][0..2], 300, .big);
    offset += 2;

    // MAC size = 0 (2 bytes)
    std.mem.writeInt(u16, rdata_buf[offset..][0..2], 0, .big);
    offset += 2;

    // Original ID (2 bytes)
    std.mem.writeInt(u16, rdata_buf[offset..][0..2], 0x1234, .big);
    offset += 2;

    // Error code = 999 (unknown) (2 bytes)
    std.mem.writeInt(u16, rdata_buf[offset..][0..2], 999, .big);
    offset += 2;

    // Other length = 0 (2 bytes)
    std.mem.writeInt(u16, rdata_buf[offset..][0..2], 0, .big);
    offset += 2;

    // Parse -- must NOT panic
    var tsig = try TsigRecord.parse(allocator, rdata_buf[0..offset]);
    defer tsig.deinit(allocator);

    // Error code should be preserved as raw value 999
    try std.testing.expectEqual(@as(u16, 999), tsig.error_code.toResponseCode());
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

test "SEC-C23: HMAC key between hash-output-length and block-size produces correct MAC" {
    const allocator = std.testing.allocator;

    // 50-byte key: between SHA-256 output (32) and block size (64)
    // Previously this was silently truncated to 32 bytes, producing wrong MACs.
    var key_50: [50]u8 = undefined;
    @memset(&key_50, 0xAB);

    const key = TsigKey.init("test-key.example.com", .hmac_sha256, &key_50);
    var ctx = TsigContext.initNoWarn(allocator, key);

    const message = [_]u8{
        0x12, 0x34, // ID
        0x01, 0x00, // Flags
        0x00, 0x01, // QDCOUNT
        0x00, 0x00, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
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

    // Sign and verify: this exercises the full HMAC path with the 50-byte key
    const signed = try ctx.sign(&message);
    defer allocator.free(signed);

    // Verify the signed message is self-consistent
    const result = try ctx.verify(signed);
    try std.testing.expect(result.valid);
    try std.testing.expectEqual(TsigError.no_error, result.error_code);
}

test "SEC-C23: HMAC with key longer than block size produces correct MAC" {
    const allocator = std.testing.allocator;

    // 100-byte key: longer than any HMAC block size (64 for SHA-256, 128 for SHA-384/512)
    var key_100: [100]u8 = undefined;
    @memset(&key_100, 0xCD);

    const key = TsigKey.init("test-key.example.com", .hmac_sha256, &key_100);
    var ctx = TsigContext.initNoWarn(allocator, key);

    const message = [_]u8{
        0x56, 0x78, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x07, 'e',  'x',  'a',
        'm',  'p',  'l',  'e',  0x03, 'c',  'o',  'm',
        0x00, 0x00, 0x01, 0x00, 0x01,
    };

    const signed = try ctx.sign(&message);
    defer allocator.free(signed);

    const result = try ctx.verify(signed);
    try std.testing.expect(result.valid);
}

test "SEC-C23: Different key sizes produce different MACs" {
    const allocator = std.testing.allocator;

    const message = [_]u8{
        0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x07, 'e',  'x',  'a',
        'm',  'p',  'l',  'e',  0x03, 'c',  'o',  'm',
        0x00, 0x00, 0x01, 0x00, 0x01,
    };

    // 32-byte key (SHA-256 output length)
    var key_32: [32]u8 = undefined;
    @memset(&key_32, 0xAB);
    const k32 = TsigKey.init("test-key.example.com", .hmac_sha256, &key_32);
    var ctx32 = TsigContext.initNoWarn(allocator, k32);
    const signed_32 = try ctx32.sign(&message);
    defer allocator.free(signed_32);

    // 50-byte key (same first 32 bytes as key_32, but longer)
    // Previously this would have been truncated to 32 bytes and produced the SAME MAC.
    var key_50: [50]u8 = undefined;
    @memset(key_50[0..32], 0xAB);
    @memset(key_50[32..], 0xEF); // Different trailing bytes
    const k50 = TsigKey.init("test-key.example.com", .hmac_sha256, &key_50);
    var ctx50 = TsigContext.initNoWarn(allocator, k50);
    const signed_50 = try ctx50.sign(&message);
    defer allocator.free(signed_50);

    // The signed messages should differ because the keys differ.
    // Before the fix, truncation to 32 bytes made them identical.
    try std.testing.expect(!std.mem.eql(u8, signed_32, signed_50));
}

test "SEC-NEW-01: extractTsig rejects rdlength exceeding message" {
    const allocator = std.testing.allocator;

    // Build a minimal DNS message with 1 additional record that has a TSIG type
    // but rdlength that extends past the end of the message.
    var msg: [64]u8 = .{0} ** 64;
    // ID
    msg[0] = 0x12;
    msg[1] = 0x34;
    // Flags: standard query
    msg[2] = 0x01;
    msg[3] = 0x00;
    // QDCOUNT: 0
    // ANCOUNT: 0
    // NSCOUNT: 0
    // ARCOUNT: 1
    msg[11] = 0x01;

    // Additional section starts at offset 12
    // RR Name: root (\x00)
    msg[12] = 0x00;
    // Type: TSIG (250)
    msg[13] = 0x00;
    msg[14] = 0xFA;
    // Class: ANY (255)
    msg[15] = 0x00;
    msg[16] = 0xFF;
    // TTL: 0
    // rdlength: 0x00FF = 255, but only a few bytes remain in the message
    msg[21] = 0x00;
    msg[22] = 0xFF;
    // Message ends at byte 64, but rdlength claims 255 bytes from offset 23

    const key = TsigKey.init("test-key.example.com", .hmac_sha256, &[_]u8{0} ** 32);
    var ctx = TsigContext.initNoWarn(allocator, key);

    const result = ctx.verify(msg[0 .. 23 + 5]); // Only 5 bytes of rdata available
    try std.testing.expectError(error.InvalidMessage, result);
}

test "SEC-NEW-04: TsigRecord.parse rejects truncated other_data" {
    const allocator = std.testing.allocator;

    // Build TSIG RDATA where other_len claims more data than available
    var rdata_buf: [32]u8 = .{0} ** 32;
    var offset: usize = 0;

    // Algorithm name: root
    rdata_buf[offset] = 0;
    offset += 1;

    // Time signed (6 bytes)
    offset += 6;

    // Fudge (2 bytes)
    std.mem.writeInt(u16, rdata_buf[offset..][0..2], 300, .big);
    offset += 2;

    // MAC size = 0
    std.mem.writeInt(u16, rdata_buf[offset..][0..2], 0, .big);
    offset += 2;

    // Original ID
    std.mem.writeInt(u16, rdata_buf[offset..][0..2], 0x1234, .big);
    offset += 2;

    // Error code
    std.mem.writeInt(u16, rdata_buf[offset..][0..2], 0, .big);
    offset += 2;

    // Other length = 100 (but no data follows)
    std.mem.writeInt(u16, rdata_buf[offset..][0..2], 100, .big);
    offset += 2;

    const result = TsigRecord.parse(allocator, rdata_buf[0..offset]);
    try std.testing.expectError(error.InvalidTsigRecord, result);
}

test "SEC-SCAN-01: TsigKey.deinit zeroes secret material" {
    const allocator = std.testing.allocator;

    // Allocate a secret on the heap so we can inspect memory after zeroing
    const secret = try allocator.dupe(u8, &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE });
    var key = TsigKey.init("test-key", .hmac_sha256, secret);

    // Verify secret is non-zero before deinit
    var any_nonzero = false;
    for (secret) |b| {
        if (b != 0) any_nonzero = true;
    }
    try std.testing.expect(any_nonzero);

    // deinit should zero and free the secret
    key.deinit(allocator);

    // After deinit, the key's secret slice should be empty
    try std.testing.expectEqual(@as(usize, 0), key.secret.len);
}

test "SEC-SCAN-01: TsigKey.deinit without allocator only zeroes" {
    // For stack-allocated or borrowed secrets, pass null allocator
    var secret_buf = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    var key = TsigKey.init("test-key", .hmac_sha256, &secret_buf);

    key.deinit(null);

    // Secret bytes should be zeroed
    for (secret_buf) |b| {
        try std.testing.expectEqual(@as(u8, 0), b);
    }
}

test "SEC-SCAN-02: TSIG appendTsig rejects ARCOUNT overflow" {
    const allocator = std.testing.allocator;

    const key = TsigKey.init("test-key.example.com", .hmac_sha256, &[_]u8{0} ** 32);
    var ctx = TsigContext.initNoWarn(allocator, key);

    // Build a message with ARCOUNT = 65535 (max u16)
    var msg: [16]u8 = .{0} ** 16;
    // Set ARCOUNT to 0xFFFF
    msg[10] = 0xFF;
    msg[11] = 0xFF;

    // sign() internally calls appendTsig which should detect the overflow
    const result = ctx.sign(&msg);
    try std.testing.expectError(error.ArcountOverflow, result);
}

test "SEC-AUDIT-03: buildTsigVariables uses actual error and other_data" {
    // Regression test: buildTsigVariables must include the actual error code
    // and other_data from the TSIG record, not hardcoded zeros.  When these
    // fields differ, the MAC input -- and thus the MAC -- must differ.
    const allocator = std.testing.allocator;

    const key = TsigKey.init("test-key.example.com", .hmac_sha256, &[_]u8{0} ** 32);
    var ctx = TsigContext.initNoWarn(allocator, key);

    const time_signed: u48 = 1700000000;

    // Build TSIG variables with error=0, other_data=empty (signing path)
    const vars_zero = try ctx.buildTsigVariables(time_signed, null, 0, &.{});
    defer allocator.free(vars_zero);

    // Build TSIG variables with error=18 (BADTIME), other_data=6 bytes of server time
    const other_data = [_]u8{ 0x00, 0x00, 0x65, 0x54, 0xF8, 0x00 };
    const vars_nonzero = try ctx.buildTsigVariables(time_signed, null, 18, &other_data);
    defer allocator.free(vars_nonzero);

    // They must NOT be equal -- different error/other_data must change the output
    try std.testing.expect(!std.mem.eql(u8, vars_zero, vars_nonzero));

    // Verify the non-zero variant is longer (it includes other_data bytes)
    try std.testing.expect(vars_nonzero.len > vars_zero.len);

    // Verify the last bytes of the non-zero variant contain the other_data
    const tail = vars_nonzero[vars_nonzero.len - other_data.len ..];
    try std.testing.expectEqualSlices(u8, &other_data, tail);
}

test "SEC-AUDIT-08: fudge u16*2 overflow with large fudge values" {
    const allocator = std.testing.allocator;

    const key = TsigKey.init("test-key.example.com", .hmac_sha256, &[_]u8{0} ** 32);

    // Set fudge to max u16 (65535) on both signer and verifier so MAC matches.
    // The old code would compute self.fudge * 2 which overflows u16
    // (65535 * 2 = 131070 > 65535).
    var ctx = TsigContext.initNoWarn(allocator, key);
    ctx.fudge = std.math.maxInt(u16); // 65535

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

    // Sign and verify with the same large-fudge context
    const signed = try ctx.sign(&message);
    defer allocator.free(signed);

    // Verify must not overflow/panic on self.fudge * 2 at the fudge check
    const result = try ctx.verify(signed);
    // The message should verify successfully (tsig.fudge=65535 <= 2*65535=131070)
    try std.testing.expect(result.valid);
    try std.testing.expectEqual(TsigError.no_error, result.error_code);
}

test "SEC-AUDIT-08: fudge comparison works for boundary values" {
    // Verify the arithmetic is correct for boundary values without overflow.
    // self.fudge=32768 would cause 32768*2=65536 which overflows u16.
    // After fix, this should use widened arithmetic and work correctly.

    const allocator = std.testing.allocator;

    const key = TsigKey.init("test-key.example.com", .hmac_sha256, &[_]u8{0} ** 32);

    var ctx = TsigContext.initNoWarn(allocator, key);
    ctx.fudge = 32768; // 0x8000 -- smallest value that causes overflow in u16*2

    const message = [_]u8{
        0x12, 0x34, // ID
        0x01, 0x00, // Flags: standard query
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x00, // ANCOUNT: 0
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
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

    // Sign and verify with the same context so MAC matches
    const signed = try ctx.sign(&message);
    defer allocator.free(signed);

    // Must not panic from overflow
    const result = try ctx.verify(signed);
    try std.testing.expect(result.valid);
}
