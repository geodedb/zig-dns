// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! SIG(0) - DNS Request and Transaction Signatures (RFC 2931)
//!
//! Provides authentication for DNS transactions using public key cryptography.
//! Unlike TSIG which uses shared secrets, SIG(0) uses asymmetric keys.
//!
//! Supported algorithms:
//! - ECDSAP256SHA256 (Algorithm 13)
//! - ECDSAP384SHA384 (Algorithm 14)
//! - ED25519 (Algorithm 15)
//!
//! Note: RSA algorithms require external crypto library.

const std = @import("std");

/// DNSSEC Algorithm numbers (subset relevant for SIG(0))
/// Non-exhaustive to safely handle unknown algorithm values from wire data
/// without panicking (SEC-C20, CWE-704).
pub const Algorithm = enum(u8) {
    /// RSA/SHA-256 (requires external crypto)
    rsa_sha256 = 8,
    /// RSA/SHA-512 (requires external crypto)
    rsa_sha512 = 10,
    /// ECDSA P-256 with SHA-256
    ecdsa_p256_sha256 = 13,
    /// ECDSA P-384 with SHA-384
    ecdsa_p384_sha384 = 14,
    /// Ed25519
    ed25519 = 15,
    /// Unknown/unrecognized algorithm values from wire data
    _,

    const Self = @This();

    /// Check if algorithm is supported by std.crypto
    pub fn isSupported(self: Self) bool {
        return switch (self) {
            .ecdsa_p256_sha256, .ecdsa_p384_sha384, .ed25519 => true,
            .rsa_sha256, .rsa_sha512 => false,
            _ => false,
        };
    }

    /// Get signature length for this algorithm
    pub fn signatureLength(self: Self) ?usize {
        return switch (self) {
            .ecdsa_p256_sha256 => 64, // r (32) + s (32)
            .ecdsa_p384_sha384 => 96, // r (48) + s (48)
            .ed25519 => 64,
            .rsa_sha256, .rsa_sha512 => null, // Variable
            _ => null,
        };
    }
};

/// SIG(0) Key pair
pub const Sig0KeyPair = struct {
    /// Key name (owner of the key, e.g., "host.example.com")
    name: []const u8,
    /// Algorithm
    algorithm: Algorithm,
    /// Private key material
    private_key: PrivateKey,
    /// Public key material (for DNSKEY record)
    public_key: []const u8,
    /// Key tag (calculated from public key)
    key_tag: u16,

    const Self = @This();

    pub const PrivateKey = union(Algorithm) {
        rsa_sha256: void,
        rsa_sha512: void,
        ecdsa_p256_sha256: std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey,
        ecdsa_p384_sha384: std.crypto.sign.ecdsa.EcdsaP384Sha384.SecretKey,
        ed25519: std.crypto.sign.Ed25519.SecretKey,
    };

    /// Generate a new key pair
    pub fn generate(allocator: std.mem.Allocator, name: []const u8, algorithm: Algorithm) !Self {
        switch (algorithm) {
            .ed25519 => {
                const key_pair = std.crypto.sign.Ed25519.KeyPair.generate();
                const public_key = try allocator.dupe(u8, &key_pair.public_key.bytes);
                return Self{
                    .name = name,
                    .algorithm = algorithm,
                    .private_key = .{ .ed25519 = key_pair.secret_key },
                    .public_key = public_key,
                    .key_tag = calculateKeyTag(algorithm, public_key),
                };
            },
            .ecdsa_p256_sha256 => {
                const key_pair = std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.generate();
                const public_key = try allocator.dupe(u8, &key_pair.public_key.toUncompressedSec1());
                return Self{
                    .name = name,
                    .algorithm = algorithm,
                    .private_key = .{ .ecdsa_p256_sha256 = key_pair.secret_key },
                    .public_key = public_key,
                    .key_tag = calculateKeyTag(algorithm, public_key),
                };
            },
            .ecdsa_p384_sha384 => {
                const key_pair = std.crypto.sign.ecdsa.EcdsaP384Sha384.KeyPair.generate();
                const public_key = try allocator.dupe(u8, &key_pair.public_key.toUncompressedSec1());
                return Self{
                    .name = name,
                    .algorithm = algorithm,
                    .private_key = .{ .ecdsa_p384_sha384 = key_pair.secret_key },
                    .public_key = public_key,
                    .key_tag = calculateKeyTag(algorithm, public_key),
                };
            },
            .rsa_sha256, .rsa_sha512 => return error.UnsupportedAlgorithm,
            _ => return error.UnsupportedAlgorithm,
        }
    }

    /// SECURITY: Zeros private key material before releasing memory to prevent
    /// key leakage through uncleared memory (SEC-C25, CWE-244).
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        // Zero private key material before struct goes out of scope
        switch (self.algorithm) {
            .ed25519 => {
                std.crypto.secureZero(u8, &self.private_key.ed25519.bytes);
            },
            .ecdsa_p256_sha256 => {
                const key_ptr: *[@sizeOf(std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey)]u8 =
                    @ptrCast(&self.private_key.ecdsa_p256_sha256);
                std.crypto.secureZero(u8, key_ptr);
            },
            .ecdsa_p384_sha384 => {
                const key_ptr: *[@sizeOf(std.crypto.sign.ecdsa.EcdsaP384Sha384.SecretKey)]u8 =
                    @ptrCast(&self.private_key.ecdsa_p384_sha384);
                std.crypto.secureZero(u8, key_ptr);
            },
            .rsa_sha256, .rsa_sha512 => {}, // void -- no key material
            _ => {}, // Unknown algorithm -- no key material to zero
        }
        allocator.free(self.public_key);
    }
};

/// SIG(0) Public Key (for verification)
pub const Sig0PublicKey = struct {
    /// Key name
    name: []const u8,
    /// Algorithm
    algorithm: Algorithm,
    /// Public key material
    public_key: PublicKey,
    /// Key tag
    key_tag: u16,

    const Self = @This();

    pub const PublicKey = union(Algorithm) {
        rsa_sha256: void,
        rsa_sha512: void,
        ecdsa_p256_sha256: std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey,
        ecdsa_p384_sha384: std.crypto.sign.ecdsa.EcdsaP384Sha384.PublicKey,
        ed25519: std.crypto.sign.Ed25519.PublicKey,
    };

    /// Parse public key from DNSKEY RDATA
    pub fn fromDnskey(name: []const u8, algorithm: Algorithm, key_data: []const u8) !Self {
        switch (algorithm) {
            .ed25519 => {
                if (key_data.len != 32) return error.InvalidKeyLength;
                const pk = std.crypto.sign.Ed25519.PublicKey.fromBytes(key_data[0..32].*) catch
                    return error.InvalidPublicKey;
                return Self{
                    .name = name,
                    .algorithm = algorithm,
                    .public_key = .{ .ed25519 = pk },
                    .key_tag = calculateKeyTag(algorithm, key_data),
                };
            },
            .ecdsa_p256_sha256 => {
                if (key_data.len != 64) return error.InvalidKeyLength;
                // Prepend 0x04 for uncompressed point format
                var uncompressed: [65]u8 = undefined;
                uncompressed[0] = 0x04;
                @memcpy(uncompressed[1..], key_data);
                const pk = std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey.fromSec1(&uncompressed) catch
                    return error.InvalidPublicKey;
                return Self{
                    .name = name,
                    .algorithm = algorithm,
                    .public_key = .{ .ecdsa_p256_sha256 = pk },
                    .key_tag = calculateKeyTag(algorithm, key_data),
                };
            },
            .ecdsa_p384_sha384 => {
                if (key_data.len != 96) return error.InvalidKeyLength;
                var uncompressed: [97]u8 = undefined;
                uncompressed[0] = 0x04;
                @memcpy(uncompressed[1..], key_data);
                const pk = std.crypto.sign.ecdsa.EcdsaP384Sha384.PublicKey.fromSec1(&uncompressed) catch
                    return error.InvalidPublicKey;
                return Self{
                    .name = name,
                    .algorithm = algorithm,
                    .public_key = .{ .ecdsa_p384_sha384 = pk },
                    .key_tag = calculateKeyTag(algorithm, key_data),
                };
            },
            .rsa_sha256, .rsa_sha512 => return error.UnsupportedAlgorithm,
            _ => return error.UnsupportedAlgorithm,
        }
    }
};

/// SIG(0) Record data
pub const Sig0Record = struct {
    /// Type covered (always 0 for SIG(0))
    type_covered: u16,
    /// Algorithm
    algorithm: Algorithm,
    /// Labels (always 0 for SIG(0))
    labels: u8,
    /// Original TTL (always 0 for SIG(0))
    original_ttl: u32,
    /// Signature expiration
    sig_expiration: u32,
    /// Signature inception
    sig_inception: u32,
    /// Key tag
    key_tag: u16,
    /// Signer's name
    signer_name: []const u8,
    /// Signature
    signature: []const u8,

    const Self = @This();

    /// Parse SIG(0) record from RDATA
    pub fn parse(allocator: std.mem.Allocator, rdata: []const u8) !Self {
        if (rdata.len < 18) return error.InvalidSig0Record;

        const type_covered = std.mem.readInt(u16, rdata[0..2], .big);
        const algorithm: Algorithm = @enumFromInt(rdata[2]);
        const labels = rdata[3];
        const original_ttl = std.mem.readInt(u32, rdata[4..8], .big);
        const sig_expiration = std.mem.readInt(u32, rdata[8..12], .big);
        const sig_inception = std.mem.readInt(u32, rdata[12..16], .big);
        const key_tag = std.mem.readInt(u16, rdata[16..18], .big);

        // Parse signer's name
        var offset: usize = 18;
        const name_result = try parseName_(allocator, rdata, offset);
        offset = name_result.offset;

        // Rest is signature
        if (offset >= rdata.len) {
            allocator.free(name_result.name);
            return error.InvalidSig0Record;
        }

        const signature = try allocator.dupe(u8, rdata[offset..]);

        return Self{
            .type_covered = type_covered,
            .algorithm = algorithm,
            .labels = labels,
            .original_ttl = original_ttl,
            .sig_expiration = sig_expiration,
            .sig_inception = sig_inception,
            .key_tag = key_tag,
            .signer_name = name_result.name,
            .signature = signature,
        };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.signer_name);
        allocator.free(self.signature);
    }
};

/// SIG(0) Context for signing and verification
pub const Sig0Context = struct {
    allocator: std.mem.Allocator,
    /// Signature validity period in seconds (default: 300 = 5 minutes)
    validity_seconds: u32 = 300,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{ .allocator = allocator };
    }

    /// Initialize with custom validity period
    pub fn initWithValidity(allocator: std.mem.Allocator, validity_seconds: u32) Self {
        return Self{
            .allocator = allocator,
            .validity_seconds = validity_seconds,
        };
    }

    /// Sign a DNS message with SIG(0)
    pub fn sign(self: *Self, message: []const u8, key_pair: *const Sig0KeyPair) ![]u8 {
        const now: u32 = @intCast(@as(u64, @bitCast(std.time.timestamp())));
        // SECURITY (SEC-AUDIT-04): Checked addition prevents u32 overflow (CWE-190).
        const expiration = std.math.add(u32, now, self.validity_seconds) catch
            return error.TimestampOverflow;

        // Build SIG(0) RDATA without signature
        var sig_rdata: std.ArrayList(u8) = .empty;
        errdefer sig_rdata.deinit(self.allocator);

        // Type covered (0 for SIG(0))
        try sig_rdata.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, 0)));
        // Algorithm
        try sig_rdata.append(self.allocator, @intFromEnum(key_pair.algorithm));
        // Labels (0 for SIG(0))
        try sig_rdata.append(self.allocator, 0);
        // Original TTL (0)
        try sig_rdata.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u32, 0)));
        // Signature expiration
        try sig_rdata.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u32, expiration)));
        // Signature inception
        try sig_rdata.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u32, now)));
        // Key tag
        try sig_rdata.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, key_pair.key_tag)));
        // Signer's name
        try encodeName(self.allocator, &sig_rdata, key_pair.name);

        // Compute signature over: SIG RDATA (without signature) + message
        const sig_data = try sig_rdata.toOwnedSlice(self.allocator);
        defer self.allocator.free(sig_data);

        const signature = try self.computeSignature(key_pair, sig_data, message);
        defer self.allocator.free(signature);

        // Build complete SIG(0) record
        var result: std.ArrayList(u8) = .empty;
        errdefer result.deinit(self.allocator);

        // Copy original message
        try result.appendSlice(self.allocator, message);

        // Update ARCOUNT
        // SECURITY (SEC-SCAN-02): Check for u16 overflow before incrementing (CWE-190)
        const arcount = std.mem.readInt(u16, message[10..12], .big);
        if (arcount == std.math.maxInt(u16)) return error.ArcountOverflow;
        std.mem.writeInt(u16, result.items[10..12], arcount + 1, .big);

        // Add SIG RR
        // Name (root)
        try result.append(self.allocator, 0);
        // Type (SIG = 24)
        try result.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, 24)));
        // Class (ANY = 255)
        try result.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, 255)));
        // TTL (0)
        try result.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u32, 0)));

        // RDLENGTH
        // SECURITY (SEC-SCAN-06): Bounds check before @intCast to u16 (CWE-681)
        const rdlength = sig_data.len + signature.len;
        if (rdlength > std.math.maxInt(u16)) return error.RdlengthOverflow;
        try result.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, @intCast(rdlength))));

        // RDATA
        try result.appendSlice(self.allocator, sig_data);
        try result.appendSlice(self.allocator, signature);

        return result.toOwnedSlice(self.allocator);
    }

    /// Verify a DNS message with SIG(0)
    pub fn verify(self: *Self, message: []const u8, public_key: *const Sig0PublicKey) !VerifyResult {
        // Extract SIG(0) record
        const sig_info = try self.extractSig0(message);
        defer {
            self.allocator.free(sig_info.sig_rdata);
        }

        // Parse SIG(0) record
        var sig0 = try Sig0Record.parse(self.allocator, sig_info.sig_rdata);
        defer sig0.deinit(self.allocator);

        // Verify type covered is 0
        if (sig0.type_covered != 0) {
            return VerifyResult{ .valid = false, .error_reason = "Invalid type covered" };
        }

        // Verify algorithm matches
        if (sig0.algorithm != public_key.algorithm) {
            return VerifyResult{ .valid = false, .error_reason = "Algorithm mismatch" };
        }

        // Verify key tag matches
        if (sig0.key_tag != public_key.key_tag) {
            return VerifyResult{ .valid = false, .error_reason = "Key tag mismatch" };
        }

        // Verify time validity
        const now: u32 = @intCast(@as(u64, @bitCast(std.time.timestamp())));
        if (now < sig0.sig_inception or now > sig0.sig_expiration) {
            return VerifyResult{ .valid = false, .error_reason = "Signature expired or not yet valid" };
        }

        // Get message without SIG(0) for verification
        const msg_without_sig = try self.stripSig0(message, sig_info);
        defer self.allocator.free(msg_without_sig);

        // Get SIG RDATA without signature
        const sig_rdata_len = sig_info.sig_rdata.len - sig0.signature.len;
        const sig_data_only = sig_info.sig_rdata[0..sig_rdata_len];

        // Verify signature
        const valid = try self.verifySignature(public_key, sig_data_only, msg_without_sig, sig0.signature);

        return VerifyResult{
            .valid = valid,
            .error_reason = if (valid) null else "Signature verification failed",
            .signer_name = sig0.signer_name,
            .key_tag = sig0.key_tag,
        };
    }

    fn computeSignature(self: *Self, key_pair: *const Sig0KeyPair, sig_data: []const u8, message: []const u8) ![]u8 {
        switch (key_pair.algorithm) {
            .ed25519 => {
                const sk = key_pair.private_key.ed25519;
                const pk = std.crypto.sign.Ed25519.PublicKey.fromBytes(key_pair.public_key[0..32].*) catch
                    return error.InvalidKey;
                const kp = std.crypto.sign.Ed25519.KeyPair{
                    .secret_key = sk,
                    .public_key = pk,
                };

                // Create message to sign: sig_data + message
                var to_sign: std.ArrayList(u8) = .empty;
                defer to_sign.deinit(self.allocator);
                try to_sign.appendSlice(self.allocator, sig_data);
                try to_sign.appendSlice(self.allocator, message);

                const sig = try kp.sign(to_sign.items, null);
                return try self.allocator.dupe(u8, &sig.toBytes());
            },
            .ecdsa_p256_sha256 => {
                const sk = key_pair.private_key.ecdsa_p256_sha256;
                const kp = try std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.fromSecretKey(sk);

                var to_sign: std.ArrayList(u8) = .empty;
                defer to_sign.deinit(self.allocator);
                try to_sign.appendSlice(self.allocator, sig_data);
                try to_sign.appendSlice(self.allocator, message);

                const sig = try kp.sign(to_sign.items, null);
                return try self.allocator.dupe(u8, &sig.toBytes());
            },
            .ecdsa_p384_sha384 => {
                const sk = key_pair.private_key.ecdsa_p384_sha384;
                const kp = try std.crypto.sign.ecdsa.EcdsaP384Sha384.KeyPair.fromSecretKey(sk);

                var to_sign: std.ArrayList(u8) = .empty;
                defer to_sign.deinit(self.allocator);
                try to_sign.appendSlice(self.allocator, sig_data);
                try to_sign.appendSlice(self.allocator, message);

                const sig = try kp.sign(to_sign.items, null);
                return try self.allocator.dupe(u8, &sig.toBytes());
            },
            .rsa_sha256, .rsa_sha512 => return error.UnsupportedAlgorithm,
            _ => return error.UnsupportedAlgorithm,
        }
    }

    fn verifySignature(self: *Self, public_key: *const Sig0PublicKey, sig_data: []const u8, message: []const u8, signature: []const u8) !bool {
        // Reconstruct signed data
        var to_verify: std.ArrayList(u8) = .empty;
        defer to_verify.deinit(self.allocator);
        try to_verify.appendSlice(self.allocator, sig_data);
        try to_verify.appendSlice(self.allocator, message);

        switch (public_key.algorithm) {
            .ed25519 => {
                if (signature.len != 64) return false;
                const pk = public_key.public_key.ed25519;
                const sig = std.crypto.sign.Ed25519.Signature.fromBytes(signature[0..64].*);
                sig.verify(to_verify.items, pk) catch return false;
                return true;
            },
            .ecdsa_p256_sha256 => {
                if (signature.len != 64) return false;
                const pk = public_key.public_key.ecdsa_p256_sha256;
                const sig = std.crypto.sign.ecdsa.EcdsaP256Sha256.Signature.fromBytes(signature[0..64].*);
                sig.verify(to_verify.items, pk) catch return false;
                return true;
            },
            .ecdsa_p384_sha384 => {
                if (signature.len != 96) return false;
                const pk = public_key.public_key.ecdsa_p384_sha384;
                const sig = std.crypto.sign.ecdsa.EcdsaP384Sha384.Signature.fromBytes(signature[0..96].*);
                sig.verify(to_verify.items, pk) catch return false;
                return true;
            },
            .rsa_sha256, .rsa_sha512 => return error.UnsupportedAlgorithm,
            _ => return error.UnsupportedAlgorithm,
        }
    }

    const Sig0Info = struct {
        sig_rdata: []const u8,
        sig_start: usize,
    };

    fn extractSig0(self: *Self, message: []const u8) !Sig0Info {
        if (message.len < 12) return error.InvalidMessage;

        const arcount = std.mem.readInt(u16, message[10..12], .big);
        if (arcount == 0) return error.NoSig0Record;

        // Navigate to additional section
        var offset: usize = 12;

        // Skip questions
        const qdcount = std.mem.readInt(u16, message[4..6], .big);
        var i: u16 = 0;
        while (i < qdcount) : (i += 1) {
            offset = try skipName(message, offset);
            // SECURITY (SEC-NEW-06): Validate room for QTYPE + QCLASS after name
            if (offset + 4 > message.len) return error.InvalidMessage;
            offset += 4;
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

        // Find SIG(0) in additional
        i = 0;
        while (i < arcount) : (i += 1) {
            const rr_start = offset;
            offset = try skipName(message, offset);

            if (offset + 10 > message.len) return error.InvalidMessage;

            const rtype = std.mem.readInt(u16, message[offset..][0..2], .big);
            offset += 2;
            offset += 2; // CLASS
            offset += 4; // TTL
            const rdlength = std.mem.readInt(u16, message[offset..][0..2], .big);
            offset += 2;

            // SECURITY (SEC-NEW-02): Validate rdlength does not exceed message
            if (offset + rdlength > message.len) return error.InvalidMessage;

            if (rtype == 24) { // SIG
                // Check if it's SIG(0) - type covered should be 0
                if (offset + 2 <= message.len) {
                    const type_covered = std.mem.readInt(u16, message[offset..][0..2], .big);
                    if (type_covered == 0) {
                        return Sig0Info{
                            .sig_rdata = try self.allocator.dupe(u8, message[offset .. offset + rdlength]),
                            .sig_start = rr_start,
                        };
                    }
                }
            }

            offset += rdlength;
        }

        return error.NoSig0Record;
    }

    fn stripSig0(self: *Self, message: []const u8, sig_info: Sig0Info) ![]u8 {
        var buffer: std.ArrayList(u8) = .empty;
        errdefer buffer.deinit(self.allocator);

        try buffer.appendSlice(self.allocator, message[0..sig_info.sig_start]);

        // Decrement ARCOUNT
        const arcount = std.mem.readInt(u16, message[10..12], .big);
        std.mem.writeInt(u16, buffer.items[10..12], arcount - 1, .big);

        return buffer.toOwnedSlice(self.allocator);
    }
};

/// Result of SIG(0) verification
pub const VerifyResult = struct {
    valid: bool,
    error_reason: ?[]const u8 = null,
    signer_name: []const u8 = "",
    key_tag: u16 = 0,
};

/// Calculate DNSKEY key tag (RFC 4034 Appendix B)
pub fn calculateKeyTag(algorithm: Algorithm, public_key: []const u8) u16 {
    // Build DNSKEY RDATA format
    // Flags (256 = ZSK, 257 = KSK) + Protocol (3) + Algorithm + Public Key
    var ac: u32 = 0;

    // Flags (assuming ZSK)
    ac += 256;

    // Protocol (always 3)
    ac += @as(u32, 3) << 8;

    // Algorithm
    ac += @intFromEnum(algorithm);

    // Public key bytes
    var i: usize = 0;
    while (i < public_key.len) : (i += 1) {
        if (i & 1 == 0) {
            ac += @as(u32, public_key[i]) << 8;
        } else {
            ac += public_key[i];
        }
    }

    ac += (ac >> 16) & 0xFFFF;
    return @intCast(ac & 0xFFFF);
}

// Helper functions -- delegated to shared dns_name module to avoid duplication
const dns_name = @import("dns_name");
const parseName_ = dns_name.parseName;
const encodeName = dns_name.encodeName;
const skipName = dns_name.skipName;
const skipRR = dns_name.skipRR;

// ============================================================================
// Tests
// ============================================================================

test "Algorithm.isSupported" {
    try std.testing.expect(Algorithm.ed25519.isSupported());
    try std.testing.expect(Algorithm.ecdsa_p256_sha256.isSupported());
    try std.testing.expect(!Algorithm.rsa_sha256.isSupported());
}

test "Algorithm.signatureLength" {
    try std.testing.expectEqual(@as(?usize, 64), Algorithm.ed25519.signatureLength());
    try std.testing.expectEqual(@as(?usize, 64), Algorithm.ecdsa_p256_sha256.signatureLength());
    try std.testing.expectEqual(@as(?usize, 96), Algorithm.ecdsa_p384_sha384.signatureLength());
    try std.testing.expect(Algorithm.rsa_sha256.signatureLength() == null);
}

test "Sig0KeyPair.generate Ed25519" {
    const allocator = std.testing.allocator;

    var key_pair = try Sig0KeyPair.generate(allocator, "test.example.com", .ed25519);
    defer key_pair.deinit(allocator);

    try std.testing.expectEqual(Algorithm.ed25519, key_pair.algorithm);
    try std.testing.expectEqual(@as(usize, 32), key_pair.public_key.len);
}

test "Sig0KeyPair.generate ECDSA P-256" {
    const allocator = std.testing.allocator;

    var key_pair = try Sig0KeyPair.generate(allocator, "test.example.com", .ecdsa_p256_sha256);
    defer key_pair.deinit(allocator);

    try std.testing.expectEqual(Algorithm.ecdsa_p256_sha256, key_pair.algorithm);
    try std.testing.expectEqual(@as(usize, 65), key_pair.public_key.len); // Uncompressed point
}

test "calculateKeyTag" {
    // Test with known public key
    const pub_key = [_]u8{0} ** 32;
    const tag = calculateKeyTag(.ed25519, &pub_key);
    try std.testing.expect(tag > 0);
}

test "Sig0Context.initWithValidity" {
    const allocator = std.testing.allocator;
    const ctx = Sig0Context.initWithValidity(allocator, 600);
    try std.testing.expectEqual(@as(u32, 600), ctx.validity_seconds);

    const default_ctx = Sig0Context.init(allocator);
    try std.testing.expectEqual(@as(u32, 300), default_ctx.validity_seconds);
}

test "Sig0Context sign and verify" {
    const allocator = std.testing.allocator;

    // Generate key pair
    var key_pair = try Sig0KeyPair.generate(allocator, "test.example.com", .ed25519);
    defer key_pair.deinit(allocator);

    // Create public key for verification
    const public_key = try Sig0PublicKey.fromDnskey("test.example.com", .ed25519, key_pair.public_key);

    var ctx = Sig0Context.init(allocator);

    // Simple DNS message
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

    // Sign
    const signed = try ctx.sign(&message, &key_pair);
    defer allocator.free(signed);

    // Verify ARCOUNT was incremented
    const arcount = std.mem.readInt(u16, signed[10..12], .big);
    try std.testing.expectEqual(@as(u16, 1), arcount);

    // Verify
    const result = try ctx.verify(signed, &public_key);
    try std.testing.expect(result.valid);
}

test "SEC-C20: Sig0Record.parse does not panic on unknown algorithm" {
    const allocator = std.testing.allocator;

    // Build minimal SIG(0) RDATA with unknown algorithm value 99
    var rdata: [32]u8 = .{0} ** 32;
    // type_covered = 0 (bytes 0-1)
    std.mem.writeInt(u16, rdata[0..2], 0, .big);
    // algorithm = 99 (unknown) (byte 2)
    rdata[2] = 99;
    // labels = 0 (byte 3)
    rdata[3] = 0;
    // original_ttl = 0 (bytes 4-7)
    // sig_expiration (bytes 8-11)
    // sig_inception (bytes 12-15)
    // key_tag = 0 (bytes 16-17)
    // signer name: root (single zero byte at byte 18)
    rdata[18] = 0;
    // signature: remaining bytes (19..32)

    // This must NOT panic -- it should parse successfully with the unknown algorithm
    var sig0 = try Sig0Record.parse(allocator, &rdata);
    defer sig0.deinit(allocator);

    // The algorithm should be preserved as the raw value 99
    try std.testing.expectEqual(@as(u8, 99), @intFromEnum(sig0.algorithm));

    // isSupported should return false for unknown algorithms
    try std.testing.expect(!sig0.algorithm.isSupported());

    // signatureLength should return null for unknown algorithms
    try std.testing.expect(sig0.algorithm.signatureLength() == null);
}

test "SEC-C20: Sig0KeyPair.generate rejects unknown algorithm" {
    const allocator = std.testing.allocator;
    const unknown_alg: Algorithm = @enumFromInt(99);
    const result = Sig0KeyPair.generate(allocator, "test.example.com", unknown_alg);
    try std.testing.expectError(error.UnsupportedAlgorithm, result);
}

test "SEC-C20: Sig0PublicKey.fromDnskey rejects unknown algorithm" {
    const unknown_alg: Algorithm = @enumFromInt(99);
    const key_data = [_]u8{0} ** 32;
    const result = Sig0PublicKey.fromDnskey("test.example.com", unknown_alg, &key_data);
    try std.testing.expectError(error.UnsupportedAlgorithm, result);
}

test "SEC-C25: Sig0KeyPair.deinit zeroes private key material (Ed25519)" {
    const allocator = std.testing.allocator;

    var key_pair = try Sig0KeyPair.generate(allocator, "test.example.com", .ed25519);

    // Verify key has non-zero bytes before deinit
    var has_nonzero = false;
    for (key_pair.private_key.ed25519.bytes) |b| {
        if (b != 0) {
            has_nonzero = true;
            break;
        }
    }
    try std.testing.expect(has_nonzero);

    // deinit should securely zero the private key
    key_pair.deinit(allocator);

    // After deinit, private key bytes should be zeroed
    for (key_pair.private_key.ed25519.bytes) |b| {
        try std.testing.expectEqual(@as(u8, 0), b);
    }
}

test "SEC-C25: Sig0KeyPair.deinit zeroes private key material (ECDSA P-256)" {
    const allocator = std.testing.allocator;

    var key_pair = try Sig0KeyPair.generate(allocator, "test.example.com", .ecdsa_p256_sha256);

    // deinit should securely zero the private key
    key_pair.deinit(allocator);

    // After deinit, private key struct bytes should be zeroed
    const key_ptr: *const [@sizeOf(std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey)]u8 =
        @ptrCast(&key_pair.private_key.ecdsa_p256_sha256);
    for (key_ptr) |b| {
        try std.testing.expectEqual(@as(u8, 0), b);
    }
}

test "SEC-NEW-02: extractSig0 rejects rdlength exceeding message" {
    const allocator = std.testing.allocator;

    // Build a minimal DNS message with 1 additional record that has a SIG type
    // but rdlength that extends past the end of the message.
    var msg: [32]u8 = .{0} ** 32;
    // ID
    msg[0] = 0x12;
    msg[1] = 0x34;
    // Flags
    msg[2] = 0x01;
    msg[3] = 0x00;
    // QDCOUNT: 0, ANCOUNT: 0, NSCOUNT: 0
    // ARCOUNT: 1
    msg[11] = 0x01;

    // Additional section starts at offset 12
    // RR Name: root (\x00)
    msg[12] = 0x00;
    // Type: SIG (24)
    msg[13] = 0x00;
    msg[14] = 0x18;
    // Class: ANY (255)
    msg[15] = 0x00;
    msg[16] = 0xFF;
    // TTL: 0 (bytes 17-20)
    // rdlength: 0x00FF = 255 (far exceeds remaining message)
    msg[21] = 0x00;
    msg[22] = 0xFF;

    // Generate a key pair for the public key needed by verify
    var key_pair = try Sig0KeyPair.generate(allocator, "test.example.com", .ed25519);
    defer key_pair.deinit(allocator);
    const public_key = try Sig0PublicKey.fromDnskey("test.example.com", .ed25519, key_pair.public_key);

    var ctx = Sig0Context.init(allocator);

    // Only provide 28 bytes total -- rdlength claims 255 but only ~5 bytes remain
    const result = ctx.verify(msg[0..28], &public_key);
    try std.testing.expectError(error.InvalidMessage, result);
}

test "SEC-SCAN-02: SIG(0) sign rejects ARCOUNT overflow" {
    const allocator = std.testing.allocator;

    var key_pair = try Sig0KeyPair.generate(allocator, "test.example.com", .ed25519);
    defer key_pair.deinit(allocator);

    var ctx = Sig0Context.init(allocator);

    // Build a message with ARCOUNT = 65535 (max u16)
    var msg: [16]u8 = .{0} ** 16;
    msg[10] = 0xFF;
    msg[11] = 0xFF;

    // sign() should detect the ARCOUNT overflow
    const result = ctx.sign(&msg, &key_pair);
    try std.testing.expectError(error.ArcountOverflow, result);
}

test "SEC-AUDIT-04: SIG(0) sign rejects expiration timestamp overflow" {
    // Regression test: now + validity_seconds must not overflow u32.
    // With validity_seconds = maxInt(u32) and any positive timestamp,
    // the addition would wrap.  The fix returns TimestampOverflow.
    const allocator = std.testing.allocator;

    var key_pair = try Sig0KeyPair.generate(allocator, "test.example.com", .ed25519);
    defer key_pair.deinit(allocator);

    // Use maxInt(u32) as validity so now + validity always overflows
    var ctx = Sig0Context.initWithValidity(allocator, std.math.maxInt(u32));

    // Minimal valid DNS message (12-byte header)
    var msg: [16]u8 = .{0} ** 16;

    const result = ctx.sign(&msg, &key_pair);
    try std.testing.expectError(error.TimestampOverflow, result);
}
