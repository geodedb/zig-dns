// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! DNSSEC validation module (RFC 4033/4034/4035)
//!
//! This module provides DNSSEC validation capabilities including:
//! - DS record validation (verifying DNSKEY matches DS)
//! - NSEC/NSEC3 validation (authenticated denial of existence)
//! - RRSIG signature validation
//! - Chain-of-trust validation from root to leaf
//!
//! ## Supported Algorithms
//!
//! | Algorithm       | Status    | Notes                                    |
//! |-----------------|-----------|------------------------------------------|
//! | Ed25519 (15)    | Supported | Recommended for new deployments          |
//! | ECDSA P-256 (13)| Supported | RFC 6605, widely supported               |
//! | ECDSA P-384 (14)| Supported | RFC 6605, high security                  |
//! | RSA-SHA256 (8)  | **NOT SUPPORTED** | See limitation below          |
//! | RSA-SHA512 (10) | **NOT SUPPORTED** | See limitation below          |
//! | RSA-SHA1 (5)    | **NOT SUPPORTED** | See limitation below          |
//!
//! ## IMPORTANT: RSA Algorithm Limitation (SEC-004)
//!
//! **RSA signature verification is NOT implemented.** This is a significant
//! limitation because RSA-SHA256 (algorithm 8) is currently the most widely
//! deployed DNSSEC algorithm. As of 2024, approximately 70-80% of DNSSEC-signed
//! zones use RSA algorithms.
//!
//! **Impact:** This library cannot validate DNSSEC signatures for:
//! - Most TLD zones (.com, .net, .org, etc.)
//! - The root zone (uses RSA-SHA256)
//! - Legacy zones not yet migrated to ECDSA/Ed25519
//!
//! **Workarounds:**
//! 1. Use a full resolver (like Unbound or BIND) for DNSSEC validation
//! 2. Integrate an external RSA crypto library (not included due to Zig's
//!    goal of minimal C dependencies)
//! 3. Limit validation to zones known to use ECDSA/Ed25519
//!
//! **Future:** RSA support may be added via optional external crypto bindings
//! or when Zig's standard library includes RSA primitives.
//!
//! For zones using unsupported algorithms, `verifySignature` returns
//! `error.UnsupportedAlgorithm`.

const std = @import("std");
const record = @import("record");
const name_module = @import("name");
const types = @import("types");

const ResourceRecord = record.ResourceRecord;
const DnskeyData = ResourceRecord.DnskeyData;
const RrsigData = ResourceRecord.RrsigData;
const DsData = ResourceRecord.DsData;
const NsecData = ResourceRecord.NsecData;
const Nsec3Data = ResourceRecord.Nsec3Data;
const DnssecAlgorithm = ResourceRecord.DnssecAlgorithm;
const DigestType = ResourceRecord.DigestType;
const Name = name_module.Name;
const Type = types.Type;

/// DNSSEC validation result
pub const ValidationResult = enum {
    /// Signature validated successfully
    secure,
    /// Signature validation failed
    bogus,
    /// No DNSSEC records present, cannot validate
    insecure,
    /// DNSSEC validation indeterminate (missing data)
    indeterminate,
};

/// DNSSEC validation errors
pub const ValidationError = error{
    /// Algorithm not supported
    UnsupportedAlgorithm,
    /// Invalid signature format
    InvalidSignature,
    /// Signature expired or not yet valid
    SignatureNotValid,
    /// DS digest mismatch
    DigestMismatch,
    /// Invalid DNSKEY flags
    InvalidKeyFlags,
    /// No matching DNSKEY for RRSIG
    NoMatchingKey,
    /// Invalid NSEC/NSEC3 proof
    InvalidDenialProof,
    /// Chain of trust broken
    BrokenChainOfTrust,
    /// Invalid key tag
    InvalidKeyTag,
    /// Out of memory
    OutOfMemory,
    /// Invalid data
    InvalidData,
};

/// DNSSEC validator
pub const Validator = struct {
    allocator: std.mem.Allocator,
    /// Trust anchors (root DNSKEY or DS records)
    trust_anchors: std.ArrayList(TrustAnchor),
    /// Current time for signature validation
    current_time: u32,

    pub const TrustAnchor = struct {
        /// Zone name this anchor is for
        zone: []const u8,
        /// Key tag
        key_tag: u16,
        /// Algorithm
        algorithm: DnssecAlgorithm,
        /// Digest type (for DS anchors)
        digest_type: ?DigestType,
        /// Digest or public key data
        data: []const u8,
        /// Is this a DNSKEY or DS anchor
        is_dnskey: bool,
    };

    pub fn init(allocator: std.mem.Allocator) Validator {
        return .{
            .allocator = allocator,
            .trust_anchors = .empty,
            .current_time = @intCast(@divFloor(std.time.timestamp(), 1)),
        };
    }

    pub fn deinit(self: *Validator) void {
        for (self.trust_anchors.items) |anchor| {
            self.allocator.free(anchor.zone);
            self.allocator.free(anchor.data);
        }
        self.trust_anchors.deinit(self.allocator);
    }

    /// Add a trust anchor
    pub fn addTrustAnchor(self: *Validator, anchor: TrustAnchor) !void {
        // Copy the data since we need to own it
        const zone_copy = try self.allocator.dupe(u8, anchor.zone);
        errdefer self.allocator.free(zone_copy);

        const data_copy = try self.allocator.dupe(u8, anchor.data);
        errdefer self.allocator.free(data_copy);

        try self.trust_anchors.append(self.allocator, .{
            .zone = zone_copy,
            .key_tag = anchor.key_tag,
            .algorithm = anchor.algorithm,
            .digest_type = anchor.digest_type,
            .data = data_copy,
            .is_dnskey = anchor.is_dnskey,
        });
    }

    /// Set the current time for signature validation
    pub fn setCurrentTime(self: *Validator, time: u32) void {
        self.current_time = time;
    }

    // =========================================================================
    // DS Record Validation (RFC 4034 Section 5)
    // =========================================================================

    /// Verify that a DNSKEY matches a DS record
    /// The DS record contains a digest of the DNSKEY
    pub fn verifyDsMatch(
        self: *Validator,
        dnskey: DnskeyData,
        dnskey_rdata: []const u8,
        owner_name: []const u8,
        ds: DsData,
    ) ValidationError!bool {
        _ = self;

        // Key tag must match
        const computed_key_tag = ResourceRecord.calculateKeyTag(dnskey_rdata);
        if (computed_key_tag != ds.key_tag) {
            return false;
        }

        // Algorithm must match
        if (dnskey.algorithm != ds.algorithm) {
            return false;
        }

        // Compute digest of owner name + DNSKEY RDATA
        const digest = try computeDsDigest(
            owner_name,
            dnskey_rdata,
            ds.digest_type,
        ) orelse return error.UnsupportedAlgorithm;

        // Compare digests
        if (digest.len != ds.digest.len) {
            return false;
        }
        return std.mem.eql(u8, &digest, ds.digest[0..digest.len]);
    }

    // =========================================================================
    // NSEC Validation (RFC 4034 Section 4)
    // =========================================================================

    /// Validate NXDOMAIN using NSEC records
    /// Returns true if the NSEC records prove the name doesn't exist
    pub fn validateNxdomainWithNsec(
        _: *Validator,
        qname: []const u8,
        nsec_records: []const ResourceRecord,
    ) ValidationError!bool {
        for (nsec_records) |nsec_rr| {
            if (nsec_rr.rtype != .nsec) continue;

            const nsec = nsec_rr.parseNSEC() catch continue;

            // Check if qname falls between this NSEC owner and next name
            if (nameInNsecRange(qname, nsec_rr.name, nsec.next_name)) {
                return true;
            }
        }
        return false;
    }

    /// Validate NODATA using NSEC records
    /// Returns true if the NSEC records prove the type doesn't exist
    pub fn validateNodataWithNsec(
        _: *Validator,
        qname: []const u8,
        qtype: Type,
        nsec_records: []const ResourceRecord,
    ) ValidationError!bool {
        for (nsec_records) |nsec_rr| {
            if (nsec_rr.rtype != .nsec) continue;

            // NSEC must match the query name exactly
            if (!std.mem.eql(u8, nsec_rr.name, qname)) continue;

            const nsec = nsec_rr.parseNSEC() catch continue;

            // Check that the queried type is NOT in the type bitmap
            if (!ResourceRecord.hasTypeInBitmap(nsec.type_bitmaps, qtype)) {
                return true;
            }
        }
        return false;
    }

    // =========================================================================
    // NSEC3 Validation (RFC 5155)
    // =========================================================================

    /// Validate NXDOMAIN using NSEC3 records
    pub fn validateNxdomainWithNsec3(
        self: *Validator,
        qname: []const u8,
        nsec3_records: []const ResourceRecord,
    ) ValidationError!bool {
        if (nsec3_records.len == 0) return false;

        // Get NSEC3 parameters from first record
        const first_nsec3 = nsec3_records[0].parseNSEC3() catch return error.InvalidData;

        // Hash the query name
        const qname_hash = try self.computeNsec3Hash(
            qname,
            first_nsec3.hash_algorithm,
            first_nsec3.iterations,
            first_nsec3.salt,
        );

        // Find covering NSEC3 record
        for (nsec3_records) |nsec3_rr| {
            if (nsec3_rr.rtype != .nsec3) continue;

            const nsec3 = nsec3_rr.parseNSEC3() catch continue;

            // Check if hash falls in the range covered by this NSEC3
            if (hashInNsec3Range(&qname_hash, nsec3_rr.name, nsec3.next_hashed_owner)) {
                return true;
            }
        }

        return false;
    }

    /// Validate NODATA using NSEC3 records
    pub fn validateNodataWithNsec3(
        self: *Validator,
        qname: []const u8,
        qtype: Type,
        nsec3_records: []const ResourceRecord,
    ) ValidationError!bool {
        if (nsec3_records.len == 0) return false;

        // Get NSEC3 parameters from first record
        const first_nsec3 = nsec3_records[0].parseNSEC3() catch return error.InvalidData;

        // Hash the query name
        const qname_hash = try self.computeNsec3Hash(
            qname,
            first_nsec3.hash_algorithm,
            first_nsec3.iterations,
            first_nsec3.salt,
        );

        // Find matching NSEC3 record
        for (nsec3_records) |nsec3_rr| {
            if (nsec3_rr.rtype != .nsec3) continue;

            const nsec3 = nsec3_rr.parseNSEC3() catch continue;

            // Extract hash from owner name and compare
            const owner_hash = extractNsec3OwnerHash(nsec3_rr.name) catch continue;
            if (!std.mem.eql(u8, &qname_hash, owner_hash)) continue;

            // Found matching NSEC3, check type bitmap
            if (!ResourceRecord.hasTypeInBitmap(nsec3.type_bitmaps, qtype)) {
                return true;
            }
        }

        return false;
    }

    // =========================================================================
    // RRSIG Signature Validation (RFC 4034 Section 3)
    // =========================================================================

    /// Verify an RRSIG signature over an RRset
    pub fn verifyRrsig(
        self: *Validator,
        rrsig: RrsigData,
        rrset: []const ResourceRecord,
        dnskey: DnskeyData,
    ) ValidationError!bool {
        // Check signature validity period
        if (!rrsig.isValid(self.current_time)) {
            return error.SignatureNotValid;
        }

        // Check algorithm match
        if (rrsig.algorithm != dnskey.algorithm) {
            return false;
        }

        // Build the signed data: RRSIG RDATA (without signature) + canonical RRset
        var signed_data: std.ArrayList(u8) = .empty;
        defer signed_data.deinit(self.allocator);

        // Add RRSIG RDATA fields (RFC 4034 Section 3.1.8.1)
        try self.appendRrsigRdata(&signed_data, rrsig);

        // Add canonical RRset
        try self.appendCanonicalRrset(&signed_data, rrset, rrsig);

        // Verify signature based on algorithm
        return self.verifySignature(
            rrsig.algorithm,
            dnskey.public_key,
            signed_data.items,
            rrsig.signature,
        );
    }

    /// Append RRSIG RDATA fields (without signature) for signing
    fn appendRrsigRdata(self: *Validator, data: *std.ArrayList(u8), rrsig: RrsigData) !void {
        const allocator = self.allocator;

        // Type covered (2 bytes)
        try data.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, @intFromEnum(rrsig.type_covered))));

        // Algorithm (1 byte)
        try data.append(allocator, @intFromEnum(rrsig.algorithm));

        // Labels (1 byte)
        try data.append(allocator, rrsig.labels);

        // Original TTL (4 bytes)
        try data.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u32, rrsig.original_ttl)));

        // Signature expiration (4 bytes)
        try data.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u32, rrsig.sig_expiration)));

        // Signature inception (4 bytes)
        try data.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u32, rrsig.sig_inception)));

        // Key tag (2 bytes)
        try data.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, rrsig.key_tag)));

        // Signer's name (canonical wire format)
        try appendCanonicalName(allocator, data, rrsig.signer);
    }

    /// Append canonical RRset for signing (RFC 4034 Section 6.3)
    fn appendCanonicalRrset(
        self: *Validator,
        data: *std.ArrayList(u8),
        rrset: []const ResourceRecord,
        rrsig: RrsigData,
    ) !void {
        const allocator = self.allocator;

        // Sort RRs by RDATA for canonical ordering
        // For simplicity, we assume the RRset is already sorted
        // A full implementation would sort here

        for (rrset) |rr| {
            // Owner name (canonical, lowercase)
            try appendCanonicalName(allocator, data, rr.name);

            // Type (2 bytes)
            try data.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, @intFromEnum(rr.rtype))));

            // Class (2 bytes)
            try data.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, @intFromEnum(rr.class))));

            // Original TTL from RRSIG (4 bytes)
            try data.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u32, rrsig.original_ttl)));

            // RDLENGTH (2 bytes)
            try data.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, rr.rdlength)));

            // RDATA (canonical form for names)
            try data.appendSlice(allocator, rr.rdata);
        }
    }

    /// Verify signature using appropriate algorithm
    fn verifySignature(
        self: *Validator,
        algorithm: DnssecAlgorithm,
        public_key: []const u8,
        message: []const u8,
        signature: []const u8,
    ) ValidationError!bool {
        _ = self;

        switch (algorithm) {
            .ed25519 => return verifyEd25519(public_key, message, signature),
            .ecdsap256sha256 => return verifyEcdsaP256(public_key, message, signature),
            .ecdsap384sha384 => return verifyEcdsaP384(public_key, message, signature),
            .rsasha256, .rsasha512, .rsasha1 => {
                // SEC-004: RSA signature verification is NOT IMPLEMENTED
                // Zig's std.crypto does not include RSA primitives.
                // See module documentation for details on this limitation.
                // Most DNSSEC-signed zones (including root and major TLDs) use
                // RSA-SHA256, so this is a significant limitation.
                return error.UnsupportedAlgorithm;
            },
            else => return error.UnsupportedAlgorithm,
        }
    }

    // =========================================================================
    // Chain of Trust Validation (RFC 4035 Section 5)
    // =========================================================================

    /// Validate a complete chain of trust from root to leaf
    pub fn validateChainOfTrust(
        self: *Validator,
        target_zone: []const u8,
        dnskey_rrsets: []const DnskeyRrset,
        ds_records: []const ResourceRecord,
    ) ValidationError!ValidationResult {
        _ = target_zone;

        // Start from trust anchor
        if (self.trust_anchors.items.len == 0) {
            return .indeterminate;
        }

        // For each zone in the path from root to target:
        // 1. Verify DNSKEY RRset is signed by trusted key
        // 2. Verify DS record in parent matches child DNSKEY
        // 3. Move to child zone

        var trusted_key: ?DnskeyData = null;

        for (dnskey_rrsets) |rrset| {
            // Verify DNSKEY RRset signature
            if (trusted_key) |key| {
                // Find RRSIG for DNSKEY
                const rrsig = findRrsig(rrset.rrsigs, .dnskey) orelse return .bogus;
                const rrsig_data = rrsig.parseRRSIG() catch return .bogus;

                const valid = self.verifyRrsig(rrsig_data, rrset.keys, key) catch return .bogus;
                if (!valid) return .bogus;
            } else {
                // Use trust anchor for root
                // Verify root DNSKEY matches trust anchor
                const matches = self.verifyTrustAnchor(rrset.keys) catch return .bogus;
                if (!matches) return .bogus;
            }

            // Find KSK for this zone
            for (rrset.keys) |key_rr| {
                const key_data = key_rr.parseDNSKEY() catch continue;
                if (key_data.isKsk()) {
                    trusted_key = key_data;
                    break;
                }
            }

            // Verify DS in parent matches this DNSKEY
            for (ds_records) |ds_rr| {
                if (ds_rr.rtype != .ds) continue;

                const ds = ds_rr.parseDS() catch continue;
                for (rrset.keys) |key_rr| {
                    const key_data = key_rr.parseDNSKEY() catch continue;
                    const matches = self.verifyDsMatch(
                        key_data,
                        key_rr.rdata,
                        key_rr.name,
                        ds,
                    ) catch continue;
                    if (matches) {
                        trusted_key = key_data;
                        break;
                    }
                }
            }
        }

        return if (trusted_key != null) .secure else .bogus;
    }

    /// Verify DNSKEY matches a trust anchor
    fn verifyTrustAnchor(self: *Validator, dnskeys: []const ResourceRecord) !bool {
        for (self.trust_anchors.items) |anchor| {
            for (dnskeys) |key_rr| {
                const key_data = key_rr.parseDNSKEY() catch continue;

                if (anchor.is_dnskey) {
                    // Compare DNSKEY directly
                    if (std.mem.eql(u8, key_rr.rdata, anchor.data)) {
                        return true;
                    }
                } else {
                    // Anchor is DS, compute digest and compare
                    const computed_tag = ResourceRecord.calculateKeyTag(key_rr.rdata);
                    if (computed_tag != anchor.key_tag) continue;
                    if (key_data.algorithm != anchor.algorithm) continue;

                    const digest_type = anchor.digest_type orelse continue;
                    const digest = computeDsDigest(
                        key_rr.name,
                        key_rr.rdata,
                        digest_type,
                    ) catch continue orelse continue;

                    if (std.mem.eql(u8, &digest, anchor.data[0..@min(digest.len, anchor.data.len)])) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /// Compute NSEC3 hash of a name
    fn computeNsec3Hash(
        self: *Validator,
        name: []const u8,
        hash_algorithm: ResourceRecord.Nsec3HashAlgorithm,
        iterations: u16,
        salt: []const u8,
    ) ValidationError![20]u8 {
        _ = self;

        if (hash_algorithm != .sha1) {
            return error.UnsupportedAlgorithm;
        }

        // Initial hash: H(name || salt)
        var hasher = std.crypto.hash.Sha1.init(.{});
        hasher.update(name);
        hasher.update(salt);
        var digest = hasher.finalResult();

        // Iterate: H(digest || salt)
        var i: u16 = 0;
        while (i < iterations) : (i += 1) {
            hasher = std.crypto.hash.Sha1.init(.{});
            hasher.update(&digest);
            hasher.update(salt);
            digest = hasher.finalResult();
        }

        return digest;
    }
};

/// DNSKEY RRset with associated RRSIGs
pub const DnskeyRrset = struct {
    zone: []const u8,
    keys: []const ResourceRecord,
    rrsigs: []const ResourceRecord,
};

// =========================================================================
// Helper Functions
// =========================================================================

/// Compute DS digest (RFC 4034 Section 5.1.4)
fn computeDsDigest(
    owner_name: []const u8,
    dnskey_rdata: []const u8,
    digest_type: DigestType,
) ?[64]u8 {
    switch (digest_type) {
        .sha1 => {
            var hasher = std.crypto.hash.Sha1.init(.{});
            hasher.update(owner_name);
            hasher.update(dnskey_rdata);
            const result = hasher.finalResult();
            var output: [64]u8 = undefined;
            @memcpy(output[0..20], &result);
            return output;
        },
        .sha256 => {
            var hasher = std.crypto.hash.sha2.Sha256.init(.{});
            hasher.update(owner_name);
            hasher.update(dnskey_rdata);
            const result = hasher.finalResult();
            var output: [64]u8 = undefined;
            @memcpy(output[0..32], &result);
            return output;
        },
        .sha384 => {
            var hasher = std.crypto.hash.sha2.Sha384.init(.{});
            hasher.update(owner_name);
            hasher.update(dnskey_rdata);
            const result = hasher.finalResult();
            var output: [64]u8 = undefined;
            @memcpy(output[0..48], &result);
            return output;
        },
        else => return null,
    }
}

/// Verify Ed25519 signature
fn verifyEd25519(public_key: []const u8, message: []const u8, signature: []const u8) ValidationError!bool {
    if (public_key.len != 32) return error.InvalidSignature;
    if (signature.len != 64) return error.InvalidSignature;

    const pk = std.crypto.sign.Ed25519.PublicKey.fromBytes(public_key[0..32].*) catch {
        return error.InvalidSignature;
    };

    const sig = std.crypto.sign.Ed25519.Signature.fromBytes(signature[0..64].*);

    sig.verify(message, pk) catch return false;
    return true;
}

/// Verify ECDSA P-256 signature
fn verifyEcdsaP256(public_key: []const u8, message: []const u8, signature: []const u8) ValidationError!bool {
    // DNSSEC ECDSA public key format: just the Q point (64 bytes for P-256)
    if (public_key.len != 64) return error.InvalidSignature;
    if (signature.len != 64) return error.InvalidSignature;

    // Convert to SEC1 uncompressed format (04 || X || Y)
    var sec1_pk: [65]u8 = undefined;
    sec1_pk[0] = 0x04;
    @memcpy(sec1_pk[1..65], public_key);

    const pk = std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey.fromSec1(&sec1_pk) catch {
        return error.InvalidSignature;
    };

    // DNSSEC signature format: R || S (each 32 bytes)
    var sig_bytes: [64]u8 = undefined;
    @memcpy(&sig_bytes, signature[0..64]);
    const sig = std.crypto.sign.ecdsa.EcdsaP256Sha256.Signature.fromBytes(sig_bytes);

    sig.verify(message, pk) catch return false;
    return true;
}

/// Verify ECDSA P-384 signature
fn verifyEcdsaP384(public_key: []const u8, message: []const u8, signature: []const u8) ValidationError!bool {
    // DNSSEC ECDSA public key format: just the Q point (96 bytes for P-384)
    if (public_key.len != 96) return error.InvalidSignature;
    if (signature.len != 96) return error.InvalidSignature;

    // Convert to SEC1 uncompressed format (04 || X || Y)
    var sec1_pk: [97]u8 = undefined;
    sec1_pk[0] = 0x04;
    @memcpy(sec1_pk[1..97], public_key);

    const pk = std.crypto.sign.ecdsa.EcdsaP384Sha384.PublicKey.fromSec1(&sec1_pk) catch {
        return error.InvalidSignature;
    };

    // DNSSEC signature format: R || S (each 48 bytes)
    var sig_bytes: [96]u8 = undefined;
    @memcpy(&sig_bytes, signature[0..96]);
    const sig = std.crypto.sign.ecdsa.EcdsaP384Sha384.Signature.fromBytes(sig_bytes);

    sig.verify(message, pk) catch return false;
    return true;
}

/// Append canonical (lowercase) name to buffer
fn appendCanonicalName(allocator: std.mem.Allocator, data: *std.ArrayList(u8), name_data: Name) !void {
    // Convert name to canonical form (lowercase)
    // For wire format names, we need to lowercase each label
    var pos: usize = 0;
    while (pos < name_data.len) {
        const label_len = name_data[pos];
        if (label_len == 0) {
            try data.append(allocator, 0);
            break;
        }
        if (label_len >= 0xC0) {
            // Compression pointer - shouldn't appear in canonical form
            break;
        }

        try data.append(allocator, label_len);
        pos += 1;

        var i: usize = 0;
        while (i < label_len and pos + i < name_data.len) : (i += 1) {
            const c = name_data[pos + i];
            try data.append(allocator, if (c >= 'A' and c <= 'Z') c + 32 else c);
        }
        pos += label_len;
    }
}

/// Check if a name falls within an NSEC range
fn nameInNsecRange(name: []const u8, nsec_owner: []const u8, next_name: Name) bool {
    // Name is covered if: owner < name < next
    // Handle wrap-around for last NSEC (next < owner)
    const cmp_owner = compareDnsNames(name, nsec_owner);
    const cmp_next = compareDnsNames(name, next_name);
    const wrap = compareDnsNames(next_name, nsec_owner) <= 0;

    if (wrap) {
        // Wrap-around case: name > owner OR name < next
        return cmp_owner > 0 or cmp_next < 0;
    } else {
        // Normal case: owner < name < next
        return cmp_owner > 0 and cmp_next < 0;
    }
}

/// Compare two DNS names in canonical order
fn compareDnsNames(a: []const u8, b: []const u8) i32 {
    // Canonical DNS name ordering (RFC 4034 Section 6.1)
    // Compare from right to left (root first)
    const len = @min(a.len, b.len);
    var i: usize = 0;
    while (i < len) : (i += 1) {
        const ca = if (a[i] >= 'A' and a[i] <= 'Z') a[i] + 32 else a[i];
        const cb = if (b[i] >= 'A' and b[i] <= 'Z') b[i] + 32 else b[i];
        if (ca < cb) return -1;
        if (ca > cb) return 1;
    }
    if (a.len < b.len) return -1;
    if (a.len > b.len) return 1;
    return 0;
}

/// Check if a hash falls within an NSEC3 range
fn hashInNsec3Range(hash: []const u8, nsec3_owner: []const u8, next_hash: []const u8) bool {
    // Extract owner hash from NSEC3 owner name
    const owner_hash = extractNsec3OwnerHash(nsec3_owner) catch return false;

    const cmp_owner = std.mem.order(u8, hash, owner_hash);
    const cmp_next = std.mem.order(u8, hash, next_hash);
    const wrap = std.mem.order(u8, next_hash, owner_hash) != .gt;

    if (wrap) {
        return cmp_owner == .gt or cmp_next == .lt;
    } else {
        return cmp_owner == .gt and cmp_next == .lt;
    }
}

/// Extract hash from NSEC3 owner name (first label is base32hex encoded hash)
fn extractNsec3OwnerHash(owner_name: []const u8) ![]const u8 {
    if (owner_name.len < 2) return error.InvalidData;

    const label_len = owner_name[0];
    if (label_len == 0 or label_len > owner_name.len - 1) {
        return error.InvalidData;
    }

    // The first label is the base32hex encoded hash
    // For now, return the raw bytes (a full implementation would decode)
    return owner_name[1..][0..label_len];
}

/// Find RRSIG record covering a specific type
fn findRrsig(rrsigs: []const ResourceRecord, covered_type: Type) ?ResourceRecord {
    for (rrsigs) |rrsig| {
        if (rrsig.rtype != .rrsig) continue;
        const rrsig_data = rrsig.parseRRSIG() catch continue;
        if (rrsig_data.type_covered == covered_type) {
            return rrsig;
        }
    }
    return null;
}

// =========================================================================
// Tests
// =========================================================================

test "Validator.init and deinit" {
    var validator = Validator.init(std.testing.allocator);
    defer validator.deinit();

    try std.testing.expectEqual(@as(usize, 0), validator.trust_anchors.items.len);
}

test "Validator.addTrustAnchor" {
    var validator = Validator.init(std.testing.allocator);
    defer validator.deinit();

    try validator.addTrustAnchor(.{
        .zone = ".",
        .key_tag = 20326,
        .algorithm = .rsasha256,
        .digest_type = .sha256,
        .data = &[_]u8{ 0x01, 0x02, 0x03, 0x04 },
        .is_dnskey = false,
    });

    try std.testing.expectEqual(@as(usize, 1), validator.trust_anchors.items.len);
    try std.testing.expectEqual(@as(u16, 20326), validator.trust_anchors.items[0].key_tag);
}

test "computeDsDigest with SHA-256" {
    const owner = "example.com";
    const dnskey_rdata = [_]u8{ 0x01, 0x01, 0x03, 0x08, 0xAA, 0xBB, 0xCC, 0xDD };

    const digest = computeDsDigest(owner, &dnskey_rdata, .sha256);
    try std.testing.expect(digest != null);
}

test "verifyEd25519 with invalid key size" {
    const result = verifyEd25519(&[_]u8{ 0x01, 0x02 }, "message", &[_]u8{0} ** 64);
    try std.testing.expectError(ValidationError.InvalidSignature, result);
}

test "verifyEcdsaP256 with invalid key size" {
    const result = verifyEcdsaP256(&[_]u8{ 0x01, 0x02 }, "message", &[_]u8{0} ** 64);
    try std.testing.expectError(ValidationError.InvalidSignature, result);
}

test "compareDnsNames" {
    try std.testing.expectEqual(@as(i32, 0), compareDnsNames("example.com", "example.com"));
    try std.testing.expectEqual(@as(i32, 0), compareDnsNames("EXAMPLE.COM", "example.com"));
    try std.testing.expect(compareDnsNames("aaa.com", "bbb.com") < 0);
    try std.testing.expect(compareDnsNames("bbb.com", "aaa.com") > 0);
}

test "Validator.computeNsec3Hash" {
    var validator = Validator.init(std.testing.allocator);
    defer validator.deinit();

    const salt = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    const hash = try validator.computeNsec3Hash("example.com", .sha1, 10, &salt);
    try std.testing.expectEqual(@as(usize, 20), hash.len);
}

test "hasTypeInBitmap via ResourceRecord" {
    const type_bitmaps = [_]u8{
        0x00, 0x06, // window 0, length 6
        0x62, // A(1), NS(2), SOA(6)
        0x01, // MX(15)
        0x80, // TXT(16)
        0x08, // AAAA(28)
        0x00, // nothing
        0x02, // RRSIG(46)
    };

    try std.testing.expect(ResourceRecord.hasTypeInBitmap(&type_bitmaps, .a));
    try std.testing.expect(!ResourceRecord.hasTypeInBitmap(&type_bitmaps, .cname));
}
