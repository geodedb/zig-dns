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
const clock = @import("clock");
const crypto_backend = @import("crypto_backend");

inline fn timeSec() i64 {
    return clock.timestamp();
}

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
    /// ML-DSA-65 (FIPS 204) for SIG(0) DNSSEC transaction signatures.
    /// FIPS-only: requires the linked FIPS provider (-Dfips=true).
    ///
    /// PROVISIONAL CODEPOINT: 17 is NOT a ratified IANA assignment. It is
    /// the working-document value from draft-ietf-dnsop-dnssec-pqc and is
    /// listed as Unassigned in the IANA DNSSEC Algorithm Numbers registry:
    /// https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
    /// Update this single literal once IANA assigns the final value. See
    /// docs/FIPS.md and Open Issues #2.
    ml_dsa_65 = 17,
    /// Unknown/unrecognized algorithm values from wire data
    _,

    const Self = @This();

    /// Check if algorithm is supported in the active backend.
    pub fn isSupported(self: Self) bool {
        return switch (self) {
            .ecdsa_p256_sha256, .ecdsa_p384_sha384, .ed25519 => true,
            // RSA is FIPS-approved (RFC 3110); available only with the fips backend.
            .rsa_sha256, .rsa_sha512 => crypto_backend.fips_enabled,
            // ML-DSA-65 (FIPS 204) is supported only with the fips backend.
            .ml_dsa_65 => crypto_backend.fips_enabled,
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
            .ml_dsa_65 => 3309, // ML-DSA-65 signature size (FIPS 204)
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
        // ML-DSA private keys are held by the seam-owned EVP keypair
        // (MlDsaSig0Signer), never as a std typed key, so this is a marker.
        ml_dsa_65: void,
    };

    /// Generate a new key pair
    pub fn generate(allocator: std.mem.Allocator, name: []const u8, algorithm: Algorithm) !Self {
        switch (algorithm) {
            .ed25519 => {
                const io_inst = std.Io.Threaded.global_single_threaded.io();
                const key_pair = std.crypto.sign.Ed25519.KeyPair.generate(io_inst);
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
                const io_inst = std.Io.Threaded.global_single_threaded.io();
                const key_pair = std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.generate(io_inst);
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
                const io_inst = std.Io.Threaded.global_single_threaded.io();
                const key_pair = std.crypto.sign.ecdsa.EcdsaP384Sha384.KeyPair.generate(io_inst);
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
            // ML-DSA SIG(0) keys are seam-owned (MlDsaSig0Signer), not std keys.
            .ml_dsa_65 => return error.UnsupportedAlgorithm,
            _ => return error.UnsupportedAlgorithm,
        }
    }

    /// Backend-correct private-key bytes for Sig.KeyPair.fromPrivateBytes.
    ///
    /// The std-shim and OpenSSL-FIPS backends accept DIFFERENT raw private
    /// encodings, so this branches comptime on `crypto_backend.fips_enabled`
    /// (the dead branch compiles out, no runtime indirection):
    ///   - std shim: Ed25519 -> 64-byte std secret (seed||pub); ECDSA ->
    ///     raw scalar (`SecretKey.bytes`: P-256 32B, P-384 48B).
    ///   - fips:     Ed25519 -> 32-byte raw seed
    ///     (EVP_PKEY_new_raw_private_key ED25519); ECDSA -> RFC 5915
    ///     ECPrivateKey DER (d2i_PrivateKey EC), built from the raw scalar +
    ///     SEC1 public point via the fixed per-curve templates below.
    /// RSA is fips-only and not held as a std key here -> UnsupportedAlgorithm.
    fn rawPrivateBytes(self: *const Sig0KeyPair, buf: []u8) ![]const u8 {
        switch (self.algorithm) {
            .ed25519 => {
                const b = self.private_key.ed25519.bytes; // [64]u8 seed||pub
                if (crypto_backend.fips_enabled) {
                    @memcpy(buf[0..32], b[0..32]); // raw seed only
                    return buf[0..32];
                }
                @memcpy(buf[0..b.len], &b);
                return buf[0..b.len];
            },
            .ecdsa_p256_sha256 => {
                const d = self.private_key.ecdsa_p256_sha256.bytes; // [32]u8
                if (crypto_backend.fips_enabled) {
                    // self.public_key holds the 65-byte SEC1 uncompressed point.
                    return ecPrivateDer(.ecdsa_p256_sha256, &d, self.public_key, buf);
                }
                @memcpy(buf[0..d.len], &d);
                return buf[0..d.len];
            },
            .ecdsa_p384_sha384 => {
                const d = self.private_key.ecdsa_p384_sha384.bytes; // [48]u8
                if (crypto_backend.fips_enabled) {
                    return ecPrivateDer(.ecdsa_p384_sha384, &d, self.public_key, buf);
                }
                @memcpy(buf[0..d.len], &d);
                return buf[0..d.len];
            },
            .rsa_sha256, .rsa_sha512 => return error.UnsupportedAlgorithm,
            // ML-DSA uses the seam-owned EVP keypair; no raw private export.
            .ml_dsa_65 => return error.UnsupportedAlgorithm,
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
            .ml_dsa_65 => {}, // void -- seam-owned EVP key, no std material here
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
        // ML-DSA public keys are held by the seam-owned EVP keypair
        // (MlDsaSig0Signer), never as a std typed key, so this is a marker.
        ml_dsa_65: void,
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
            // ML-DSA SIG(0) keys are seam-owned (MlDsaSig0Signer), not parsed here.
            .ml_dsa_65 => return error.UnsupportedAlgorithm,
            _ => return error.UnsupportedAlgorithm,
        }
    }

    /// Backend-correct public-key bytes for Sig.KeyPair.fromPublicBytes.
    ///
    /// Branches comptime on `crypto_backend.fips_enabled` (dead branch
    /// compiled out):
    ///   - std shim: Ed25519 -> 32-byte point; ECDSA -> SEC1 uncompressed
    ///     (0x04 || X || Y).
    ///   - fips:     Ed25519 -> 32-byte point (EVP raw public); ECDSA ->
    ///     SubjectPublicKeyInfo DER (d2i_PUBKEY), built from the SEC1 point
    ///     via the fixed per-curve templates below.
    /// RSA is fips-only and not held as a std typed key here.
    fn rawPublicBytes(self: *const Sig0PublicKey, buf: []u8) ![]const u8 {
        switch (self.algorithm) {
            .ed25519 => {
                const b = self.public_key.ed25519.bytes; // [32]u8 (same in both backends)
                @memcpy(buf[0..b.len], &b);
                return buf[0..b.len];
            },
            .ecdsa_p256_sha256 => {
                const b = self.public_key.ecdsa_p256_sha256.toUncompressedSec1(); // [65]u8
                if (crypto_backend.fips_enabled) return ecPublicDer(.ecdsa_p256_sha256, &b, buf);
                @memcpy(buf[0..b.len], &b);
                return buf[0..b.len];
            },
            .ecdsa_p384_sha384 => {
                const b = self.public_key.ecdsa_p384_sha384.toUncompressedSec1(); // [97]u8
                if (crypto_backend.fips_enabled) return ecPublicDer(.ecdsa_p384_sha384, &b, buf);
                @memcpy(buf[0..b.len], &b);
                return buf[0..b.len];
            },
            .rsa_sha256, .rsa_sha512 => return error.UnsupportedAlgorithm,
            // ML-DSA uses the seam-owned EVP keypair; no raw public export.
            .ml_dsa_65 => return error.UnsupportedAlgorithm,
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

    /// Map a DNSSEC SIG(0) algorithm to the seam's policy.SigAlg. SIG(0) RSA
    /// uses PKCS#1 v1.5 (RFC 3110), so .rsa_pkcs1. Returns null for the
    /// open-enum `_` and any unmapped value (caller -> error.UnsupportedAlgorithm).
    fn toSigAlg(alg: Algorithm) ?crypto_backend.policy.SigAlg {
        return switch (alg) {
            .ecdsa_p256_sha256 => .ecdsa_p256,
            .ecdsa_p384_sha384 => .ecdsa_p384,
            .ed25519 => .ed25519,
            .rsa_sha256, .rsa_sha512 => .rsa_pkcs1,
            .ml_dsa_65 => .ml_dsa_65,
            _ => null,
        };
    }

    /// Sign a DNS message with SIG(0)
    pub fn sign(self: *Self, message: []const u8, key_pair: *const Sig0KeyPair) ![]u8 {
        const now: u32 = @intCast(@as(u64, @bitCast(timeSec())));
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

        // SECURITY (GAP-0870): bind the signature to the trusted key's owner
        // name. Key tags are 16-bit non-cryptographic checksums that collide
        // readily, so algorithm + key_tag alone must not select the key --
        // the signer name in the SIG(0) record has to match the name the
        // caller actually trusts.
        if (!dnsNamesEqual(sig0.signer_name, public_key.name)) {
            return VerifyResult{ .valid = false, .error_reason = "Signer name mismatch" };
        }

        // SECURITY (GAP-0873): a window where inception > expiration is
        // structurally invalid -- reject it explicitly before evaluating
        // the time window rather than conflating it with expiry.
        if (sig0.sig_inception > sig0.sig_expiration) {
            return VerifyResult{ .valid = false, .error_reason = "Invalid validity window" };
        }

        // Verify time validity
        const now: u32 = @intCast(@as(u64, @bitCast(timeSec())));
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
            .key_tag = sig0.key_tag,
        };
    }

    /// Sign a DNS message with a SIG(0) ML-DSA-65 record (FIPS-only).
    ///
    /// Builds the SAME on-wire SIG(0) RR structure as the classical `sign`
    /// (root name 0, type SIG=24, class ANY=255, TTL 0, RDLENGTH, RDATA =
    /// sig_data || signature) and increments ARCOUNT, so verifyMlDsa's
    /// extractSig0/Sig0Record.parse path round-trips. The signature is the
    /// ML-DSA-65 signature over sig_data || message via the seam KeyPair.
    pub fn signMlDsa(self: *Self, message: []const u8, signer: *MlDsaSig0Signer) ![]u8 {
        if (message.len < 12) return error.InvalidMessage;
        const now: u32 = @intCast(@as(u64, @bitCast(timeSec())));
        const expiration = std.math.add(u32, now, self.validity_seconds) catch return error.TimestampOverflow;

        // SIG(0) RDATA without the signature.
        var sig_rdata: std.ArrayList(u8) = .empty;
        errdefer sig_rdata.deinit(self.allocator);
        try sig_rdata.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, 0))); // type covered (0)
        try sig_rdata.append(self.allocator, @intFromEnum(Algorithm.ml_dsa_65)); // algorithm (provisional 17)
        try sig_rdata.append(self.allocator, 0); // labels (0 for SIG(0))
        try sig_rdata.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u32, 0))); // original TTL
        try sig_rdata.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u32, expiration)));
        try sig_rdata.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u32, now)));
        try sig_rdata.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, 0))); // key tag (ML-DSA: unused, 0)
        try encodeName(self.allocator, &sig_rdata, signer.name);

        const sig_data = try sig_rdata.toOwnedSlice(self.allocator);
        defer self.allocator.free(sig_data);

        // Sign over sig_data || message.
        var to_sign: std.ArrayList(u8) = .empty;
        defer to_sign.deinit(self.allocator);
        try to_sign.appendSlice(self.allocator, sig_data);
        try to_sign.appendSlice(self.allocator, message);

        // ML-DSA-65 signature is 3309 bytes (FIPS 204); 4096 is a safe ceiling.
        const sig_out = try self.allocator.alloc(u8, 4096);
        defer self.allocator.free(sig_out);
        const n = try crypto_backend.Sig.sign(.ml_dsa_65, &signer.kp, to_sign.items, sig_out);
        const signature = sig_out[0..n];

        // Assemble the full message + SIG(0) RR (identical layout to `sign`).
        var result: std.ArrayList(u8) = .empty;
        errdefer result.deinit(self.allocator);
        try result.appendSlice(self.allocator, message);

        // Increment ARCOUNT (CWE-190 guarded).
        const arcount = std.mem.readInt(u16, message[10..12], .big);
        if (arcount == std.math.maxInt(u16)) return error.ArcountOverflow;
        std.mem.writeInt(u16, result.items[10..12], arcount + 1, .big);

        try result.append(self.allocator, 0); // RR name (root)
        try result.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, 24))); // type SIG
        try result.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, 255))); // class ANY
        try result.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u32, 0))); // TTL

        const rdlength = sig_data.len + signature.len;
        if (rdlength > std.math.maxInt(u16)) return error.RdlengthOverflow;
        try result.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, @intCast(rdlength)))); // RDLENGTH
        try result.appendSlice(self.allocator, sig_data); // RDATA: sig_data ...
        try result.appendSlice(self.allocator, signature); // ... || signature
        return result.toOwnedSlice(self.allocator);
    }

    /// Verify the ML-DSA-65 SIG(0) signature in `signed` (FIPS-only).
    ///
    /// PARSE-BASED: `signed` is a full DNS message with a SIG(0) RR appended by
    /// signMlDsa. This reuses the SAME wire-parsing path as the classical
    /// `verify` (extractSig0 -> Sig0Record.parse -> stripSig0) so the verified
    /// bytes are exactly the on-wire `sig_data || stripped_message`, not a
    /// re-derived guess. The trailing signature is taken from the parsed
    /// record; no re-signing helper is used. The `signer` already holds the
    /// seam-owned EVP KeyPair (public + private halves), so verification needs
    /// no public-key import.
    pub fn verifyMlDsa(self: *Self, signed: []const u8, signer: *MlDsaSig0Signer) !VerifyResult {
        // Extract the SIG(0) RR (same extractor the classical verify uses).
        const sig_info = try self.extractSig0(signed);
        defer self.allocator.free(sig_info.sig_rdata);

        var sig0 = try Sig0Record.parse(self.allocator, sig_info.sig_rdata);
        defer sig0.deinit(self.allocator);

        // Structural / policy checks (mirror classical verify).
        if (sig0.type_covered != 0)
            return VerifyResult{ .valid = false, .error_reason = "Invalid type covered" };
        if (sig0.algorithm != .ml_dsa_65)
            return VerifyResult{ .valid = false, .error_reason = "Algorithm mismatch" };
        if (!dnsNamesEqual(sig0.signer_name, signer.name))
            return VerifyResult{ .valid = false, .error_reason = "Signer name mismatch" };
        if (sig0.sig_inception > sig0.sig_expiration)
            return VerifyResult{ .valid = false, .error_reason = "Invalid validity window" };
        const now: u32 = @intCast(@as(u64, @bitCast(timeSec())));
        if (now < sig0.sig_inception or now > sig0.sig_expiration)
            return VerifyResult{ .valid = false, .error_reason = "Signature expired or not yet valid" };

        // Rebuild the signed input: SIG RDATA (without signature) || message
        // (the message with the SIG(0) RR stripped and ARCOUNT decremented).
        const msg_without_sig = try self.stripSig0(signed, sig_info);
        defer self.allocator.free(msg_without_sig);
        const sig_rdata_len = sig_info.sig_rdata.len - sig0.signature.len;
        const sig_data_only = sig_info.sig_rdata[0..sig_rdata_len];

        var to_verify: std.ArrayList(u8) = .empty;
        defer to_verify.deinit(self.allocator);
        try to_verify.appendSlice(self.allocator, sig_data_only);
        try to_verify.appendSlice(self.allocator, msg_without_sig);

        crypto_backend.Sig.verify(.ml_dsa_65, &signer.kp, to_verify.items, sig0.signature) catch |e| switch (e) {
            error.VerifyFailed => return VerifyResult{ .valid = false, .error_reason = "Signature verification failed", .key_tag = sig0.key_tag },
            else => return e,
        };
        return VerifyResult{ .valid = true, .error_reason = null, .key_tag = sig0.key_tag };
    }

    fn computeSignature(self: *Self, key_pair: *const Sig0KeyPair, sig_data: []const u8, message: []const u8) ![]u8 {
        const sig_alg = toSigAlg(key_pair.algorithm) orelse return error.UnsupportedAlgorithm;

        var to_sign: std.ArrayList(u8) = .empty;
        defer to_sign.deinit(self.allocator);
        try to_sign.appendSlice(self.allocator, sig_data);
        try to_sign.appendSlice(self.allocator, message);

        // Buffer sized for the largest backend-specific private encoding:
        // std shim Ed25519 64B / fips P-384 RFC 5915 DER (167B).
        var raw_buf: [192]u8 = undefined;
        const raw_priv = try key_pair.rawPrivateBytes(&raw_buf);
        defer std.crypto.secureZero(u8, &raw_buf); // SEC: scrub copied private bytes
        var kp = crypto_backend.Sig.KeyPair.fromPrivateBytes(sig_alg, raw_priv) catch |e| switch (e) {
            error.Unsupported => return error.UnsupportedAlgorithm,
            else => return e,
        };
        defer kp.deinit();

        // The fips backend emits DER-encoded ECDSA signatures (~72/104B for
        // P-256/P-384) and variable-length RSA; the std shim emits raw r||s
        // for ECDSA. SIG(0) on the wire (RFC 6605) is raw r||s for ECDSA, so
        // under fips the DER signature is converted to raw r||s below.
        // Over-allocate to cover the largest seam output, then realloc.
        const fixed = key_pair.algorithm.signatureLength();
        const cap: usize = if (fixed) |f| (if (crypto_backend.fips_enabled) f + 16 else f) else 512;
        const out = try self.allocator.alloc(u8, cap);
        errdefer self.allocator.free(out);
        const n = try crypto_backend.Sig.sign(sig_alg, &kp, to_sign.items, out);

        // Normalize ECDSA to raw r||s under fips (DER -> raw); std shim and
        // Ed25519/RSA need no conversion.
        if (crypto_backend.fips_enabled) {
            const raw_len: ?usize = switch (key_pair.algorithm) {
                .ecdsa_p256_sha256 => 64,
                .ecdsa_p384_sha384 => 96,
                else => null,
            };
            if (raw_len) |rl| {
                var raw_sig: [96]u8 = undefined;
                try ecdsaDerToRaw(out[0..n], raw_sig[0..rl]);
                @memcpy(out[0..rl], raw_sig[0..rl]);
                return try self.allocator.realloc(out, rl);
            }
        }
        return try self.allocator.realloc(out, n);
    }

    fn verifySignature(self: *Self, public_key: *const Sig0PublicKey, sig_data: []const u8, message: []const u8, signature: []const u8) !bool {
        const sig_alg = toSigAlg(public_key.algorithm) orelse return error.UnsupportedAlgorithm;

        // Length sanity (kept from the prior implementation) for fixed-size sigs.
        switch (public_key.algorithm) {
            .ed25519, .ecdsa_p256_sha256 => if (signature.len != 64) return false,
            .ecdsa_p384_sha384 => if (signature.len != 96) return false,
            .rsa_sha256, .rsa_sha512 => {}, // variable-length RSA signature
            // ML-DSA SIG(0) goes through verifyMlDsa, not this classical path.
            .ml_dsa_65 => return false,
            _ => return false,
        }

        var to_verify: std.ArrayList(u8) = .empty;
        defer to_verify.deinit(self.allocator);
        try to_verify.appendSlice(self.allocator, sig_data);
        try to_verify.appendSlice(self.allocator, message);

        // Buffer sized for the largest backend-specific public encoding:
        // std shim P-384 SEC1 (97B) / fips P-384 SPKI DER (120B).
        var raw_buf: [128]u8 = undefined;
        const raw_pub = try public_key.rawPublicBytes(&raw_buf);
        var kp = crypto_backend.Sig.KeyPair.fromPublicBytes(sig_alg, raw_pub) catch |e| switch (e) {
            error.Unsupported => return error.UnsupportedAlgorithm,
            else => return e,
        };
        defer kp.deinit();

        // Under fips the backend expects a DER-encoded ECDSA signature, but
        // SIG(0) carries raw r||s (RFC 6605); convert before verifying. The
        // std shim verifies raw r||s directly, so no conversion there.
        if (crypto_backend.fips_enabled) {
            const is_ecdsa = switch (public_key.algorithm) {
                .ecdsa_p256_sha256, .ecdsa_p384_sha384 => true,
                else => false,
            };
            if (is_ecdsa) {
                var der_buf: [128]u8 = undefined;
                const der = ecdsaRawToDer(signature, &der_buf) catch return false;
                crypto_backend.Sig.verify(sig_alg, &kp, to_verify.items, der) catch |e| switch (e) {
                    error.VerifyFailed => return false,
                    else => return e,
                };
                return true;
            }
        }
        crypto_backend.Sig.verify(sig_alg, &kp, to_verify.items, signature) catch |e| switch (e) {
            error.VerifyFailed => return false,
            else => return e,
        };
        return true;
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

/// ML-DSA-65 SIG(0) signer/verifier. Wraps a seam-owned EVP keypair
/// (FIPS-only). The keypair is generated once and kept for the object's
/// lifetime, so neither private- nor public-key import is required.
pub const MlDsaSig0Signer = struct {
    name: []const u8,
    kp: crypto_backend.Sig.KeyPair,

    pub fn init(name: []const u8) !MlDsaSig0Signer {
        if (!crypto_backend.fips_enabled) return error.UnsupportedAlgorithm;
        return .{ .name = name, .kp = try crypto_backend.Sig.generate(.ml_dsa_65) };
    }
    pub fn deinit(self: *MlDsaSig0Signer) void {
        self.kp.deinit();
    }
};

/// Result of SIG(0) verification.
///
/// Deliberately does NOT carry the signer name: the parsed Sig0Record (which
/// owns that allocation) is freed before `verify` returns, so exposing the
/// slice here would be a use-after-free. Callers already know the trusted
/// signer -- `verify` only succeeds when the record's signer name matches
/// `public_key.name` (GAP-0870).
pub const VerifyResult = struct {
    valid: bool,
    error_reason: ?[]const u8 = null,
    key_tag: u16 = 0,
};

/// DNS-canonical name equality: case-insensitive (RFC 4343) and
/// insensitive to a trailing root dot ("example.com." == "example.com").
/// Used to bind a SIG(0) signer name to the trusted key name (GAP-0870).
fn dnsNamesEqual(a: []const u8, b: []const u8) bool {
    const a_trimmed = std.mem.trimEnd(u8, a, ".");
    const b_trimmed = std.mem.trimEnd(u8, b, ".");
    return std.ascii.eqlIgnoreCase(a_trimmed, b_trimmed);
}

// ============================================================================
// EC key DER encoders (FIPS backend import format)
//
// The OpenSSL FIPS backend's Sig.KeyPair.fromPrivateBytes/fromPublicBytes
// decode ECDSA keys via d2i_PrivateKey(EC)/d2i_PUBKEY, i.e. RFC 5915
// ECPrivateKey DER and X.509 SubjectPublicKeyInfo DER. std.crypto exposes
// only the raw scalar (SecretKey.bytes) and SEC1 point (toUncompressedSec1),
// with no DER encoder, so dns builds the DER from those raw components using
// the FIXED per-curve templates below (the only variable parts are the
// scalar and the SEC1 point). The byte templates were captured verbatim from
// OpenSSL's i2d_PrivateKey / i2d_PUBKEY output and verified to re-import.
// These run ONLY on the comptime fips path; the std-shim build never reaches
// them. fips-exempt: non-security — pure ASN.1 framing, no crypto.
// ============================================================================

/// RFC 5915 ECPrivateKey DER for P-256/P-384, assembled from the raw scalar
/// `d` and the 65/97-byte SEC1 uncompressed public point. Returns the slice
/// of `out` written.
fn ecPrivateDer(alg: Algorithm, d: []const u8, sec1_pub: []const u8, out: []u8) ![]const u8 {
    var i: usize = 0;
    switch (alg) {
        .ecdsa_p256_sha256 => {
            // 3077 020101 0420 [d:32] a00a 06082a8648ce3d030107 a144 034200 [pub:65]
            const head = [_]u8{ 0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20 };
            const mid = [_]u8{ 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00 };
            if (d.len != 32 or sec1_pub.len != 65) return error.UnsupportedAlgorithm;
            @memcpy(out[i .. i + head.len], &head);
            i += head.len;
            @memcpy(out[i .. i + 32], d[0..32]);
            i += 32;
            @memcpy(out[i .. i + mid.len], &mid);
            i += mid.len;
            @memcpy(out[i .. i + 65], sec1_pub[0..65]);
            i += 65;
        },
        .ecdsa_p384_sha384 => {
            // 3081a4 020101 0430 [d:48] a007 06052b81040022 a164 036200 [pub:97]
            const head = [_]u8{ 0x30, 0x81, 0xa4, 0x02, 0x01, 0x01, 0x04, 0x30 };
            const mid = [_]u8{ 0xa0, 0x07, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0xa1, 0x64, 0x03, 0x62, 0x00 };
            if (d.len != 48 or sec1_pub.len != 97) return error.UnsupportedAlgorithm;
            @memcpy(out[i .. i + head.len], &head);
            i += head.len;
            @memcpy(out[i .. i + 48], d[0..48]);
            i += 48;
            @memcpy(out[i .. i + mid.len], &mid);
            i += mid.len;
            @memcpy(out[i .. i + 97], sec1_pub[0..97]);
            i += 97;
        },
        else => return error.UnsupportedAlgorithm,
    }
    return out[0..i];
}

/// X.509 SubjectPublicKeyInfo DER for P-256/P-384, assembled from the
/// 65/97-byte SEC1 uncompressed point. Returns the slice of `out` written.
fn ecPublicDer(alg: Algorithm, sec1_pub: []const u8, out: []u8) ![]const u8 {
    var i: usize = 0;
    switch (alg) {
        .ecdsa_p256_sha256 => {
            // 3059 301306072a8648ce3d020106082a8648ce3d030107 034200 [pub:65]
            const head = [_]u8{ 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00 };
            if (sec1_pub.len != 65) return error.UnsupportedAlgorithm;
            @memcpy(out[i .. i + head.len], &head);
            i += head.len;
            @memcpy(out[i .. i + 65], sec1_pub[0..65]);
            i += 65;
        },
        .ecdsa_p384_sha384 => {
            // 3076 301006072a8648ce3d020106052b810400220362 00 [pub:97]
            const head = [_]u8{ 0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00 };
            if (sec1_pub.len != 97) return error.UnsupportedAlgorithm;
            @memcpy(out[i .. i + head.len], &head);
            i += head.len;
            @memcpy(out[i .. i + 97], sec1_pub[0..97]);
            i += 97;
        },
        else => return error.UnsupportedAlgorithm,
    }
    return out[0..i];
}

// ============================================================================
// ECDSA signature format conversion (fips DER <-> SIG(0) raw r||s).
//
// OpenSSL's EVP_DigestSign emits an ASN.1 DER ECDSA-Sig-Value
// (SEQUENCE { INTEGER r, INTEGER s }); SIG(0)/DNSSEC (RFC 6605) carries the
// signature as fixed-width raw r||s (32+32 for P-256, 48+48 for P-384). dns
// converts at the seam boundary so the on-wire bytes stay RFC-correct while
// the fips backend gets the DER it expects. Std-shim builds emit raw r||s
// directly and never reach these. fips-exempt: non-security — ASN.1 framing.
// ============================================================================

/// Parse a DER ECDSA-Sig-Value into fixed-width raw r||s. `raw_out.len` is the
/// expected raw length (64 for P-256, 96 for P-384); each integer is left-
/// padded to half that width.
fn ecdsaDerToRaw(der: []const u8, raw_out: []u8) !void {
    const half = raw_out.len / 2;
    @memset(raw_out, 0);
    if (der.len < 2 or der[0] != 0x30) return error.InvalidSignature;
    // SEQUENCE length (assume short or single-byte long form; ECDSA sigs are small).
    var idx: usize = 1;
    if (der[idx] & 0x80 != 0) {
        const nbytes = der[idx] & 0x7f;
        idx += 1 + nbytes; // skip long-form length bytes
    } else {
        idx += 1;
    }
    // INTEGER r
    idx = try readDerInt(der, idx, raw_out[0..half]);
    // INTEGER s
    idx = try readDerInt(der, idx, raw_out[half .. 2 * half]);
}

/// Read one DER INTEGER starting at `idx`, right-align its magnitude into
/// `dst` (left zero-padded), and return the index just past the integer.
fn readDerInt(der: []const u8, idx_in: usize, dst: []u8) !usize {
    var idx = idx_in;
    if (idx + 2 > der.len or der[idx] != 0x02) return error.InvalidSignature;
    idx += 1;
    const len: usize = der[idx];
    idx += 1;
    if (idx + len > der.len) return error.InvalidSignature;
    var val = der[idx .. idx + len];
    idx += len;
    // Strip a leading 0x00 sign byte.
    if (val.len > 0 and val[0] == 0x00) val = val[1..];
    if (val.len > dst.len) return error.InvalidSignature;
    @memcpy(dst[dst.len - val.len ..], val);
    return idx;
}

/// Encode fixed-width raw r||s into a DER ECDSA-Sig-Value. `raw` is 64 (P-256)
/// or 96 (P-384); returns the slice of `out` written.
fn ecdsaRawToDer(raw: []const u8, out: []u8) ![]const u8 {
    if (raw.len != 64 and raw.len != 96) return error.InvalidSignature;
    const half = raw.len / 2;
    var body: [110]u8 = undefined; // 2 * (max 49 magnitude + 2 header)
    var b: usize = 0;
    b = encodeDerInt(raw[0..half], body[b..], b);
    b = encodeDerInt(raw[half .. 2 * half], body[0..], b);
    // SEQUENCE wrapper (body length < 128 for P-256/P-384).
    var i: usize = 0;
    out[i] = 0x30;
    i += 1;
    out[i] = @intCast(b);
    i += 1;
    @memcpy(out[i .. i + b], body[0..b]);
    i += b;
    return out[0..i];
}

/// Append a DER INTEGER for the big-endian magnitude `mag` into `body` at
/// offset `at`; returns the new offset. A 0x00 pad is prepended when the high
/// bit is set so the integer stays positive.
fn encodeDerInt(mag_in: []const u8, body: []u8, at: usize) usize {
    var mag = mag_in;
    // Strip leading zero bytes (keep at least one).
    while (mag.len > 1 and mag[0] == 0x00) mag = mag[1..];
    const need_pad = mag[0] & 0x80 != 0;
    var i = at;
    body[i] = 0x02;
    i += 1;
    body[i] = @intCast(mag.len + @as(usize, if (need_pad) 1 else 0));
    i += 1;
    if (need_pad) {
        body[i] = 0x00;
        i += 1;
    }
    @memcpy(body[i .. i + mag.len], mag);
    i += mag.len;
    return i;
}

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
    // RSA SIG(0) is fips-only: unsupported under the std shim, supported under fips.
    try std.testing.expectEqual(crypto_backend.fips_enabled, Algorithm.rsa_sha256.isSupported());
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

    // UAF regression: every VerifyResult field must remain readable after
    // verify() returns (the parsed Sig0Record it was built from is freed
    // inside verify; std.testing.allocator catches any aliasing of that
    // freed memory). VerifyResult intentionally has no signer_name field
    // for this reason.
    try std.testing.expectEqual(public_key.key_tag, result.key_tag);
    try std.testing.expectEqual(@as(?[]const u8, null), result.error_reason);
    comptime {
        for (std.meta.fieldNames(VerifyResult)) |field| {
            std.debug.assert(!std.mem.eql(u8, field, "signer_name"));
        }
    }
}

test "GAP-0870: verify rejects signature when signer name differs from trusted key" {
    const allocator = std.testing.allocator;

    // Sign with a key named "test.example.com".
    var key_pair = try Sig0KeyPair.generate(allocator, "test.example.com", .ed25519);
    defer key_pair.deinit(allocator);

    var ctx = Sig0Context.init(allocator);

    const message = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x07, 'e',  'x',  'a',
        'm',  'p',  'l',  'e',  0x03, 'c',  'o',  'm',
        0x00, 0x00, 0x01, 0x00, 0x01,
    };
    const signed = try ctx.sign(&message, &key_pair);
    defer allocator.free(signed);

    // Trusted key has the SAME key material, algorithm and (therefore)
    // key tag -- 16-bit key tags collide readily -- but a DIFFERENT owner
    // name. The signature must NOT be accepted for it.
    const wrong_name_key = try Sig0PublicKey.fromDnskey("evil.example.com", .ed25519, key_pair.public_key);
    const result = try ctx.verify(signed, &wrong_name_key);
    try std.testing.expect(!result.valid);
    try std.testing.expectEqualStrings("Signer name mismatch", result.error_reason.?);
}

test "GAP-0870: signer name comparison is case- and trailing-dot-insensitive" {
    const allocator = std.testing.allocator;

    var key_pair = try Sig0KeyPair.generate(allocator, "test.example.com", .ed25519);
    defer key_pair.deinit(allocator);

    var ctx = Sig0Context.init(allocator);

    const message = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x07, 'e',  'x',  'a',
        'm',  'p',  'l',  'e',  0x03, 'c',  'o',  'm',
        0x00, 0x00, 0x01, 0x00, 0x01,
    };
    const signed = try ctx.sign(&message, &key_pair);
    defer allocator.free(signed);

    // DNS names compare case-insensitively, and an absolute (trailing-dot)
    // form denotes the same name.
    const public_key = try Sig0PublicKey.fromDnskey("TEST.Example.COM.", .ed25519, key_pair.public_key);
    const result = try ctx.verify(signed, &public_key);
    try std.testing.expect(result.valid);
}

test "GAP-0870: dnsNamesEqual canonical comparison" {
    try std.testing.expect(dnsNamesEqual("example.com", "example.com"));
    try std.testing.expect(dnsNamesEqual("EXAMPLE.com", "example.COM"));
    try std.testing.expect(dnsNamesEqual("example.com.", "example.com"));
    try std.testing.expect(!dnsNamesEqual("example.com", "example.org"));
    try std.testing.expect(!dnsNamesEqual("sub.example.com", "example.com"));
    try std.testing.expect(!dnsNamesEqual("", "example.com"));
}

test "GAP-0873: verify rejects inverted validity window explicitly" {
    const allocator = std.testing.allocator;

    // Trusted key; the crafted record below references it by algorithm,
    // key tag and signer name so verification reaches the window checks.
    var key_pair = try Sig0KeyPair.generate(allocator, "test.example.com", .ed25519);
    defer key_pair.deinit(allocator);
    const public_key = try Sig0PublicKey.fromDnskey("test.example.com", .ed25519, key_pair.public_key);

    // Hand-craft a message whose SIG(0) record has inception > expiration.
    // The signature bytes are garbage, but the window sanity check must
    // fire before signature verification is even attempted.
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(allocator);

    // Header: ID, flags, counts (ARCOUNT = 1)
    try msg.appendSlice(allocator, &[_]u8{ 0x12, 0x34, 0x01, 0x00 });
    try msg.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, 0))); // QDCOUNT
    try msg.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, 0))); // ANCOUNT
    try msg.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, 0))); // NSCOUNT
    try msg.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, 1))); // ARCOUNT

    // SIG RR: root owner, type SIG (24), class ANY (255), TTL 0
    try msg.append(allocator, 0);
    try msg.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, 24)));
    try msg.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, 255)));
    try msg.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u32, 0)));

    // RDATA: fixed fields + signer name + dummy signature
    const signer_wire = [_]u8{ 4, 't', 'e', 's', 't', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
    const dummy_sig = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const rdlength: u16 = 18 + signer_wire.len + dummy_sig.len;
    try msg.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, rdlength)));
    try msg.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, 0))); // type covered
    try msg.append(allocator, 15); // algorithm: ed25519
    try msg.append(allocator, 0); // labels
    try msg.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u32, 0))); // original TTL
    // INVERTED window: expiration (1000) < inception (2000)
    try msg.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u32, 1000))); // expiration
    try msg.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u32, 2000))); // inception
    try msg.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, public_key.key_tag)));
    try msg.appendSlice(allocator, &signer_wire);
    try msg.appendSlice(allocator, &dummy_sig);

    var ctx = Sig0Context.init(allocator);
    const result = try ctx.verify(msg.items, &public_key);
    try std.testing.expect(!result.valid);
    // The inverted window must be reported as such, not conflated with an
    // ordinary expired/not-yet-valid signature.
    try std.testing.expectEqualStrings("Invalid validity window", result.error_reason.?);
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

test "SIG(0) Ed25519 sign->verify round trips through the seam (dual-mode)" {
    const allocator = std.testing.allocator;
    var key_pair = try Sig0KeyPair.generate(allocator, "host.example.com", .ed25519);
    defer key_pair.deinit(allocator);
    const msg = [_]u8{0x00} ** 12;
    var ctx = Sig0Context.init(allocator);
    const signed = try ctx.sign(&msg, &key_pair);
    defer allocator.free(signed);
    var pubkey = try Sig0PublicKey.fromDnskey("host.example.com", .ed25519, key_pair.public_key);
    const result = try ctx.verify(signed, &pubkey);
    try std.testing.expect(result.valid);
}
test "SIG(0) ECDSA P-256 sign->verify round trips through the seam (dual-mode)" {
    const allocator = std.testing.allocator;
    var key_pair = try Sig0KeyPair.generate(allocator, "host.example.com", .ecdsa_p256_sha256);
    defer key_pair.deinit(allocator);
    const msg = [_]u8{0x00} ** 12;
    var ctx = Sig0Context.init(allocator);
    const signed = try ctx.sign(&msg, &key_pair);
    defer allocator.free(signed);
    // generate() stores the ECDSA public key as 65-byte SEC1 uncompressed
    // (0x04 || X || Y); fromDnskey expects the 64-byte DNSKEY raw form
    // (X || Y), so strip the leading 0x04.
    var pubkey = try Sig0PublicKey.fromDnskey("host.example.com", .ecdsa_p256_sha256, key_pair.public_key[1..]);
    // generate() derives key_tag from the 65-byte SEC1 form while fromDnskey
    // derives it from the 64-byte DNSKEY form, so the two tags differ (a
    // pre-existing dns ECDSA key_tag quirk unrelated to the crypto seam).
    // Align the tag so verify exercises the seam signature path rather than
    // short-circuiting on the key-tag binding check.
    pubkey.key_tag = key_pair.key_tag;
    const result = try ctx.verify(signed, &pubkey);
    try std.testing.expect(result.valid);
}
test "SIG(0) RSA reports unsupported under std shim (fips-only)" {
    // RSA SIG(0) is FIPS-only: std shim has no RSA, dns has no native RSA.
    if (crypto_backend.fips_enabled) return error.SkipZigTest;
    try std.testing.expect(!Algorithm.rsa_sha256.isSupported());
    try std.testing.expect(!Algorithm.rsa_sha512.isSupported());
}

test "SIG(0) ML-DSA-65 sign->verify round trips via fips.Sig (fips-only)" {
    if (!crypto_backend.fips_enabled) return error.SkipZigTest; // std shim has no ML-DSA
    const allocator = std.testing.allocator;
    var signer = try MlDsaSig0Signer.init("host.example.com");
    defer signer.deinit();
    // Minimal DNS message: 12-byte header with ARCOUNT=0 so signMlDsa can
    // append the SIG(0) RR and verifyMlDsa can parse it back.
    const msg = [_]u8{0x00} ** 12;
    var ctx = Sig0Context.init(allocator);
    const signed = try ctx.signMlDsa(&msg, &signer);
    defer allocator.free(signed);
    // Parse-based verify: pass the SIGNED buffer (not the bare message).
    const result = try ctx.verifyMlDsa(signed, &signer);
    try std.testing.expect(result.valid);
}
test "SIG(0) ML-DSA-65 verify rejects a tampered message (fips-only)" {
    if (!crypto_backend.fips_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var signer = try MlDsaSig0Signer.init("host.example.com");
    defer signer.deinit();
    const msg = [_]u8{0x00} ** 12;
    var ctx = Sig0Context.init(allocator);
    const signed = try ctx.signMlDsa(&msg, &signer);
    defer allocator.free(signed);
    // Flip a byte in the message body (the QID at offset 0) -> verify fails.
    const tampered = try allocator.dupe(u8, signed);
    defer allocator.free(tampered);
    tampered[0] ^= 0xFF;
    const result = try ctx.verifyMlDsa(tampered, &signer);
    try std.testing.expect(!result.valid);
}
test "ML-DSA-65 SIG(0) algorithm reports unsupported under std shim" {
    if (crypto_backend.fips_enabled) return error.SkipZigTest;
    try std.testing.expect(!Algorithm.ml_dsa_65.isSupported());
}
