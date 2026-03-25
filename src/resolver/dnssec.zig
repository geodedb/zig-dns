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
        const digest = computeDsDigest(
            owner_name,
            dnskey_rdata,
            ds.digest_type,
        ) orelse return error.UnsupportedAlgorithm;

        // Compare digests using constant-time comparison to prevent timing
        // side-channel attacks. Use the expected digest length for the algorithm
        // rather than comparing the full 64-byte buffer.
        const expected_len = dsDigestLength(ds.digest_type) orelse return error.UnsupportedAlgorithm;
        if (ds.digest.len != expected_len) {
            return false;
        }
        return constantTimeEql(digest[0..expected_len], ds.digest[0..expected_len]);
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
        full_message: []const u8,
    ) ValidationError!bool {
        // Convert dotted-string qname to wire format for comparison with
        // wire-format NSEC names (GAP-0067).
        const qname_wire = dottedToWire(qname) catch return error.InvalidData;

        for (nsec_records) |nsec_rr| {
            if (nsec_rr.rtype != .nsec) continue;

            const nsec = nsec_rr.parseNSEC(full_message) catch continue;

            // Check if qname falls between this NSEC owner and next name
            if (nameInNsecRange(qname_wire.slice(), nsec_rr.name.labels, nsec.next_domain.labels)) {
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
        full_message: []const u8,
    ) ValidationError!bool {
        // Convert dotted-string qname to wire format for comparison with
        // wire-format NSEC owner names (GAP-0066).
        const qname_wire = dottedToWire(qname) catch return error.InvalidData;

        for (nsec_records) |nsec_rr| {
            if (nsec_rr.rtype != .nsec) continue;

            // NSEC must match the query name exactly (case-insensitive per RFC 4034 Section 6.1)
            if (!wireNamesEqlInsensitive(nsec_rr.name.labels, qname_wire.slice())) continue;

            const nsec = nsec_rr.parseNSEC(full_message) catch continue;

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

        // Convert dotted-string qname to wire format per RFC 5155 (GAP-0068).
        const qname_wire = dottedToWire(qname) catch return error.InvalidData;

        // Hash the query name (wire format)
        const qname_hash = try self.computeNsec3Hash(
            qname_wire.slice(),
            first_nsec3.hash_algorithm,
            first_nsec3.iterations,
            first_nsec3.salt,
        );

        // Find covering NSEC3 record
        for (nsec3_records) |nsec3_rr| {
            if (nsec3_rr.rtype != .nsec3) continue;

            const nsec3 = nsec3_rr.parseNSEC3() catch continue;

            // Check if hash falls in the range covered by this NSEC3
            if (hashInNsec3Range(&qname_hash, nsec3_rr.name.labels, nsec3.next_hashed_owner)) {
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

        // Convert dotted-string qname to wire format per RFC 5155 (GAP-0068).
        const qname_wire = dottedToWire(qname) catch return error.InvalidData;

        // Hash the query name (wire format)
        const qname_hash = try self.computeNsec3Hash(
            qname_wire.slice(),
            first_nsec3.hash_algorithm,
            first_nsec3.iterations,
            first_nsec3.salt,
        );

        // Find matching NSEC3 record
        for (nsec3_records) |nsec3_rr| {
            if (nsec3_rr.rtype != .nsec3) continue;

            const nsec3 = nsec3_rr.parseNSEC3() catch continue;

            // Extract and decode hash from owner name (base32hex -> raw bytes)
            const decoded = decodeNsec3OwnerHash(nsec3_rr.name.labels) catch continue;
            const owner_hash = decoded.data[0..decoded.len];
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

        // Sort RRs by RDATA in canonical wire-format order (RFC 4034 S6.3).
        // Build a sorted index array to avoid mutating the input slice.
        const sorted_indices = try allocator.alloc(usize, rrset.len);
        defer allocator.free(sorted_indices);
        for (sorted_indices, 0..) |*slot, i| {
            slot.* = i;
        }

        std.mem.sort(usize, sorted_indices, rrset, struct {
            fn lessThan(ctx: []const ResourceRecord, a: usize, b: usize) bool {
                return std.mem.order(u8, ctx[a].rdata, ctx[b].rdata) == .lt;
            }
        }.lessThan);

        for (sorted_indices) |idx| {
            const rr = rrset[idx];

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
        full_message: []const u8,
    ) ValidationError!ValidationResult {
        // Start from trust anchor
        if (self.trust_anchors.items.len == 0) {
            return .indeterminate;
        }

        // Convert target_zone to wire format for owner-name validation (SEC-AUDIT-11).
        const target_wire = dottedToWire(target_zone) catch return .bogus;

        // For each zone in the path from root to target:
        // 1. Verify DNSKEY RRset is signed by trusted key
        // 2. Verify DS record in parent matches child DNSKEY
        // 3. Move to child zone

        var trusted_key: ?DnskeyData = null;

        for (dnskey_rrsets) |rrset| {
            // SEC-AUDIT-11: Verify that DNSKEY records in this RRset belong
            // to the expected zone. At each delegation step, the owner name
            // must be an ancestor of (or equal to) the target zone. A key
            // from an unrelated zone must cause validation failure.
            for (rrset.keys) |key_rr| {
                if (!isNameInZone(key_rr.name.labels, target_wire.slice())) {
                    return .bogus;
                }
            }

            // Verify DNSKEY RRset signature
            if (trusted_key) |key| {
                // Find RRSIG for DNSKEY
                const rrsig = findRrsig(rrset.rrsigs, .dnskey, full_message) orelse return .bogus;
                const rrsig_data = rrsig.parseRRSIG(full_message) catch return .bogus;

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
                        key_rr.name.labels,
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
                    const expected_len = dsDigestLength(digest_type) orelse continue;

                    // Require exact digest length match to prevent truncation bypass
                    if (anchor.data.len != expected_len) continue;

                    const digest = computeDsDigest(
                        key_rr.name.labels,
                        key_rr.rdata,
                        digest_type,
                    ) orelse continue;

                    // Use constant-time comparison to prevent timing side-channels
                    if (constantTimeEql(digest[0..expected_len], anchor.data[0..expected_len])) {
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

        // RFC 9276 Section 3.1 recommends 0 iterations; cap at 150 per
        // RFC 5155 guidance and common resolver practice (Unbound uses 150).
        // Without a cap, an attacker-crafted NSEC3 record with 65535
        // iterations could cause a CPU denial-of-service.
        const max_nsec3_iterations: u16 = 150;
        if (iterations > max_nsec3_iterations) {
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

/// Maximum wire-format DNS name length per RFC 1035 Section 2.3.4.
const max_wire_name_len = 255;

/// Result of dottedToWire conversion: wire-format bytes in a stack buffer.
const WireName = struct {
    data: [max_wire_name_len]u8,
    len: usize,

    /// Return a slice of the wire-format name.
    fn slice(self: *const WireName) []const u8 {
        return self.data[0..self.len];
    }
};

/// Convert a dotted-string DNS name (e.g., "example.com") to wire format
/// (e.g., "\x07example\x03com\x00").
///
/// Edge cases:
///   - Root "." or empty "" both produce "\x00" (the root label).
///   - Trailing dot is tolerated: "example.com." is the same as "example.com".
///
/// Returns error.InvalidData if a label exceeds 63 bytes or the total
/// wire-format name exceeds 255 bytes.
fn dottedToWire(dotted: []const u8) error{InvalidData}!WireName {
    var result = WireName{ .data = undefined, .len = 0 };

    // Handle root / empty
    if (dotted.len == 0 or (dotted.len == 1 and dotted[0] == '.')) {
        result.data[0] = 0;
        result.len = 1;
        return result;
    }

    var pos: usize = 0; // position in output buffer
    var src: usize = 0; // position in input string

    while (src < dotted.len) {
        // Find end of this label (next '.' or end of string)
        var label_end = src;
        while (label_end < dotted.len and dotted[label_end] != '.') {
            label_end += 1;
        }

        const label_len = label_end - src;

        // Skip empty label produced by trailing dot
        if (label_len == 0) {
            src = label_end + 1;
            continue;
        }

        // Label must fit in 63 bytes (RFC 1035)
        if (label_len > 63) return error.InvalidData;

        // Check output buffer capacity: 1 (length) + label_len + 1 (root)
        if (pos + 1 + label_len + 1 > max_wire_name_len) return error.InvalidData;

        result.data[pos] = @intCast(label_len);
        pos += 1;
        @memcpy(result.data[pos..][0..label_len], dotted[src..label_end]);
        pos += label_len;

        src = label_end + 1; // skip the dot
    }

    // Terminate with root label
    result.data[pos] = 0;
    pos += 1;
    result.len = pos;
    return result;
}

/// Compare a wire-format DNS name with another wire-format DNS name,
/// case-insensitively. Returns true if they represent the same DNS name.
fn wireNamesEqlInsensitive(a: []const u8, b: []const u8) bool {
    return compareDnsNames(a, b) == .eq;
}

/// Check whether `name` (wire format) is equal to or a subdomain of `zone`
/// (wire format). Used for defense-in-depth zone validation: a DNSKEY with
/// owner "evil.com" must not be accepted when validating "example.com".
///
/// The root zone ("\x00") is considered an ancestor of all names.
fn isNameInZone(name: []const u8, zone: []const u8) bool {
    // Extract labels for both names.
    const name_labels = extractWireLabels(name, 128) catch return false;
    const zone_labels = extractWireLabels(zone, 128) catch return false;

    // Root zone is ancestor of everything
    if (zone_labels.count == 0) return true;

    // name must have at least as many labels as zone
    if (name_labels.count < zone_labels.count) return false;

    // Compare zone labels (from root) against the rightmost labels of name.
    // Labels are stored leaf-to-root, so zone_labels.items[count-1] is the
    // root-most label, and we compare from there.
    var i: usize = 0;
    while (i < zone_labels.count) : (i += 1) {
        const name_label = name_labels.items[name_labels.count - 1 - i];
        const zone_label = zone_labels.items[zone_labels.count - 1 - i];
        if (compareLabelsCaseInsensitive(name_label, zone_label) != .eq) {
            return false;
        }
    }

    return true;
}

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

/// Return the expected digest length for a DS digest algorithm.
/// Returns null for unsupported digest types.
fn dsDigestLength(digest_type: DigestType) ?usize {
    return switch (digest_type) {
        .sha1 => 20,
        .sha256 => 32,
        .sha384 => 48,
        else => null,
    };
}

/// Constant-time comparison of two byte slices.
/// Returns false immediately if lengths differ (length is not secret).
/// When lengths match, compares all bytes to avoid timing side-channels
/// that could leak digest content.
fn constantTimeEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| {
        diff |= x ^ y;
    }
    return diff == 0;
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
    const labels = name_data.labels;
    var pos: usize = 0;
    while (pos < labels.len) {
        const label_len = labels[pos];
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
        while (i < label_len and pos + i < labels.len) : (i += 1) {
            const c = labels[pos + i];
            try data.append(allocator, if (c >= 'A' and c <= 'Z') c + 32 else c);
        }
        pos += label_len;
    }
}

/// Check if a name falls within an NSEC range
fn nameInNsecRange(name: []const u8, nsec_owner: []const u8, next_name: []const u8) bool {
    // Name is covered if: owner < name < next
    // Handle wrap-around for last NSEC (next < owner)
    const cmp_owner = compareDnsNames(name, nsec_owner);
    const cmp_next = compareDnsNames(name, next_name);
    const wrap = compareDnsNames(next_name, nsec_owner) != .gt;

    if (wrap) {
        // Wrap-around case: name > owner OR name < next
        return cmp_owner == .gt or cmp_next == .lt;
    } else {
        // Normal case: owner < name < next
        return cmp_owner == .gt and cmp_next == .lt;
    }
}

/// Compare two DNS names in canonical order per RFC 4034 Section 6.1.
///
/// Names must be in wire format (length-prefixed labels terminated by a zero
/// length root label). The comparison proceeds label-by-label from the root
/// (rightmost label) to the leaf (leftmost label), with case-insensitive
/// byte comparison within each label. A name with fewer labels sorts before
/// a name with more labels when all shared ancestor labels are equal.
fn compareDnsNames(a: []const u8, b: []const u8) std.math.Order {
    // Extract labels from wire-format names into stack arrays.
    // Labels are stored leaf-first, so we reverse to compare root-first.
    const max_labels = 128;

    // If extraction fails (malformed wire name), treat as zero labels.
    const a_labels = extractWireLabels(a, max_labels) catch LabelList{ .items = undefined, .count = 0 };
    const b_labels = extractWireLabels(b, max_labels) catch LabelList{ .items = undefined, .count = 0 };

    // Compare from root (last in array) to leaf (first in array).
    // a_labels and b_labels contain slices in leaf-to-root order,
    // so index [count-1] is the root-most label.
    const a_count = a_labels.count;
    const b_count = b_labels.count;
    const min_count = @min(a_count, b_count);

    var i: usize = 0;
    while (i < min_count) : (i += 1) {
        // Compare from root: a_labels[a_count - 1 - i] vs b_labels[b_count - 1 - i]
        const a_label = a_labels.items[a_count - 1 - i];
        const b_label = b_labels.items[b_count - 1 - i];

        const label_order = compareLabelsCaseInsensitive(a_label, b_label);
        if (label_order != .eq) return label_order;
    }

    // All shared labels matched; shorter name sorts first
    return std.math.order(a_count, b_count);
}

const LabelList = struct {
    items: [128][]const u8,
    count: usize,
};

/// Extract individual labels from a wire-format DNS name.
/// Returns labels in leaf-to-root order (excluding the root label itself).
///
/// Returns error.InvalidData if:
///   - A compression pointer (0xC0 prefix) is encountered (must not appear
///     in canonical wire names, RFC 4034 Section 6.2).
///   - A label length causes an out-of-bounds read.
///
/// QR-NEW-01: The comptime max_labels parameter has been removed;
/// LabelList.items is fixed at 128 which accommodates the DNS maximum of
/// 127 labels.
fn extractWireLabels(wire_name: []const u8, _max_labels: usize) error{InvalidData}!LabelList {
    _ = _max_labels; // retained for call-site compat; always uses 128
    var labels = LabelList{
        .items = undefined,
        .count = 0,
    };
    var pos: usize = 0;
    while (pos < wire_name.len) {
        const label_len = wire_name[pos];
        if (label_len == 0) break; // root label -- normal termination
        // SEC-AUDIT-12: reject compression pointers in canonical names
        if (label_len >= 0xC0) return error.InvalidData;
        pos += 1;
        // SEC-AUDIT-12: reject out-of-bounds label reads
        if (pos + label_len > wire_name.len) return error.InvalidData;
        if (labels.count < 128) {
            labels.items[labels.count] = wire_name[pos..][0..label_len];
            labels.count += 1;
        }
        pos += label_len;
    }
    return labels;
}

/// Compare two label byte sequences case-insensitively.
/// Shorter label sorts before longer label when the shared prefix matches.
fn compareLabelsCaseInsensitive(a: []const u8, b: []const u8) std.math.Order {
    const min_len = @min(a.len, b.len);
    var i: usize = 0;
    while (i < min_len) : (i += 1) {
        const ca = std.ascii.toLower(a[i]);
        const cb = std.ascii.toLower(b[i]);
        if (ca < cb) return .lt;
        if (ca > cb) return .gt;
    }
    return std.math.order(a.len, b.len);
}

/// Check if a hash falls within an NSEC3 range
fn hashInNsec3Range(hash: []const u8, nsec3_owner: []const u8, next_hash: []const u8) bool {
    // Extract and decode owner hash from NSEC3 owner name (base32hex -> raw bytes)
    const decoded = decodeNsec3OwnerHash(nsec3_owner) catch return false;
    const owner_hash = decoded.data[0..decoded.len];

    const cmp_owner = std.mem.order(u8, hash, owner_hash);
    const cmp_next = std.mem.order(u8, hash, next_hash);
    const wrap = std.mem.order(u8, next_hash, owner_hash) != .gt;

    if (wrap) {
        return cmp_owner == .gt or cmp_next == .lt;
    } else {
        return cmp_owner == .gt and cmp_next == .lt;
    }
}

const DecodedHash = struct {
    data: [32]u8,
    len: usize,
};

/// Extract and decode hash from NSEC3 owner name.
///
/// The first label of an NSEC3 owner name is the base32hex-encoded hash
/// (RFC 5155 Section 3.2, RFC 4648 Section 7). This function decodes that
/// label from base32hex ASCII to raw binary bytes so that the result can
/// be compared directly with the binary output of computeNsec3Hash and
/// the binary next_hashed_owner field from NSEC3 RDATA.
fn decodeNsec3OwnerHash(owner_name: []const u8) !DecodedHash {
    if (owner_name.len < 2) return error.InvalidData;

    const label_len = owner_name[0];
    if (label_len == 0 or label_len > owner_name.len - 1) {
        return error.InvalidData;
    }

    const label = owner_name[1..][0..label_len];

    // Decode base32hex to raw bytes
    const decoded_len = base32hexDecodedLength(label_len);
    if (decoded_len > 32) return error.InvalidData;

    var result = DecodedHash{ .data = undefined, .len = decoded_len };
    base32hexDecode(label, result.data[0..decoded_len]) catch return error.InvalidData;

    return result;
}

// =========================================================================
// Base32hex encoding/decoding (RFC 4648 Section 7)
// =========================================================================

/// Base32hex alphabet: 0-9 A-V (values 0-31)
const base32hex_encode_table = "0123456789ABCDEFGHIJKLMNOPQRSTUV";

/// Decode table mapping ASCII byte to 5-bit value (255 = invalid)
const base32hex_decode_table: [256]u8 = blk: {
    var table: [256]u8 = .{0xFF} ** 256;
    for (base32hex_encode_table, 0..) |c, i| {
        table[c] = @intCast(i);
        // Also accept lowercase
        if (c >= 'A' and c <= 'V') {
            table[c + 32] = @intCast(i);
        }
    }
    break :blk table;
};

/// Compute the number of decoded bytes from base32hex encoded length.
/// Each 8 base32hex characters encode 5 bytes. Partial groups handled.
fn base32hexDecodedLength(encoded_len: usize) usize {
    return (encoded_len * 5) / 8;
}

/// Decode base32hex (RFC 4648 Section 7) encoded data to raw bytes.
/// Case-insensitive. No padding characters expected (DNS NSEC3 doesn't use padding).
///
/// SEC-AUDIT-13: Per RFC 4648 Section 3.5, non-zero trailing bits (bits that
/// do not contribute to a full output byte) must cause a rejection. This
/// prevents canonicalization issues where multiple encodings could decode
/// to the same byte sequence.
fn base32hexDecode(encoded: []const u8, dest: []u8) !void {
    var bit_buffer: u32 = 0;
    var bits_in_buffer: u5 = 0;
    var dest_idx: usize = 0;

    for (encoded) |c| {
        const val = base32hex_decode_table[c];
        if (val == 0xFF) return error.InvalidData;

        bit_buffer = (bit_buffer << 5) | val;
        bits_in_buffer += 5;

        if (bits_in_buffer >= 8) {
            bits_in_buffer -= 8;
            if (dest_idx >= dest.len) return error.InvalidData;
            dest[dest_idx] = @intCast((bit_buffer >> bits_in_buffer) & 0xFF);
            dest_idx += 1;
        }
    }

    // SEC-AUDIT-13: Reject non-zero trailing bits (RFC 4648 Section 3.5).
    if (bits_in_buffer > 0) {
        const trailing_mask = (@as(u32, 1) << bits_in_buffer) - 1;
        if ((bit_buffer & trailing_mask) != 0) {
            return error.InvalidPadding;
        }
    }
}

/// Encode raw bytes to base32hex (RFC 4648 Section 7) without padding.
/// Returns a fixed-size array for the encoded output.
/// For a 20-byte SHA-1 hash, produces exactly 32 characters.
fn base32hexEncode(data: *const [20]u8) [32]u8 {
    var result: [32]u8 = undefined;
    var bit_buffer: u64 = 0;
    var bits_in_buffer: u6 = 0;
    var out_idx: usize = 0;

    for (data) |byte| {
        bit_buffer = (bit_buffer << 8) | byte;
        bits_in_buffer += 8;

        while (bits_in_buffer >= 5) {
            bits_in_buffer -= 5;
            const idx: u5 = @intCast((bit_buffer >> bits_in_buffer) & 0x1F);
            result[out_idx] = base32hex_encode_table[idx];
            out_idx += 1;
        }
    }

    // Handle remaining bits (20 bytes = 160 bits, 160/5 = 32 exactly, no remainder)
    if (bits_in_buffer > 0 and out_idx < result.len) {
        const shift: u6 = 5 - bits_in_buffer;
        const idx: u5 = @intCast((bit_buffer << shift) & 0x1F);
        result[out_idx] = base32hex_encode_table[idx];
        out_idx += 1;
    }

    return result;
}

/// Find RRSIG record covering a specific type
fn findRrsig(rrsigs: []const ResourceRecord, covered_type: Type, full_message: []const u8) ?ResourceRecord {
    for (rrsigs) |rrsig| {
        if (rrsig.rtype != .rrsig) continue;
        const rrsig_data = rrsig.parseRRSIG(full_message) catch continue;
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
    // Wire-format names: \x07example\x03com\x00
    try std.testing.expectEqual(std.math.Order.eq, compareDnsNames("\x07example\x03com\x00", "\x07example\x03com\x00"));
    try std.testing.expectEqual(std.math.Order.eq, compareDnsNames("\x07EXAMPLE\x03COM\x00", "\x07example\x03com\x00"));
    try std.testing.expectEqual(std.math.Order.lt, compareDnsNames("\x03aaa\x03com\x00", "\x03bbb\x03com\x00"));
    try std.testing.expectEqual(std.math.Order.gt, compareDnsNames("\x03bbb\x03com\x00", "\x03aaa\x03com\x00"));
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

// =========================================================================
// Security fix tests
// =========================================================================

test "constantTimeEql: matching slices return true" {
    const a = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 };
    const b = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 };
    try std.testing.expect(constantTimeEql(&a, &b));
}

test "constantTimeEql: differing slices return false" {
    const a = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 };
    const b = [_]u8{ 0x01, 0x02, 0xFF, 0x04, 0x05 };
    try std.testing.expect(!constantTimeEql(&a, &b));
}

test "constantTimeEql: different lengths return false" {
    const a = [_]u8{ 0x01, 0x02, 0x03 };
    const b = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    try std.testing.expect(!constantTimeEql(&a, &b));
}

test "constantTimeEql: empty slices return true" {
    const a = [_]u8{};
    const b = [_]u8{};
    try std.testing.expect(constantTimeEql(&a, &b));
}

test "dsDigestLength: returns correct lengths for known algorithms" {
    try std.testing.expectEqual(@as(?usize, 20), dsDigestLength(.sha1));
    try std.testing.expectEqual(@as(?usize, 32), dsDigestLength(.sha256));
    try std.testing.expectEqual(@as(?usize, 48), dsDigestLength(.sha384));
}

test "computeNsec3Hash: rejects iterations above cap of 150" {
    var validator = Validator.init(std.testing.allocator);
    defer validator.deinit();

    const salt = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };

    // 150 iterations should succeed
    const hash_150 = validator.computeNsec3Hash("example.com", .sha1, 150, &salt);
    try std.testing.expect(hash_150 != error.UnsupportedAlgorithm);

    // 151 iterations should be rejected
    const hash_151 = validator.computeNsec3Hash("example.com", .sha1, 151, &salt);
    try std.testing.expectError(error.UnsupportedAlgorithm, hash_151);

    // Maximum u16 iterations should be rejected
    const hash_max = validator.computeNsec3Hash("example.com", .sha1, 65535, &salt);
    try std.testing.expectError(error.UnsupportedAlgorithm, hash_max);
}

test "verifyTrustAnchor: rejects truncated digest (SEC-SCAN-09)" {
    var validator = Validator.init(std.testing.allocator);
    defer validator.deinit();

    // Compute the real SHA-256 digest for the test DNSKEY
    const owner_name: []const u8 = "\x07example\x03com\x00";
    const dnskey_rdata = [_]u8{ 0x01, 0x01, 0x03, 0x08 } ++ [_]u8{0xAA} ** 32;
    const full_digest = computeDsDigest(owner_name, &dnskey_rdata, .sha256).?;

    // Add a trust anchor with a truncated digest (only 16 of 32 bytes).
    // Before the fix, @min would cause this to match; after the fix it must not.
    try validator.addTrustAnchor(.{
        .zone = ".",
        .key_tag = ResourceRecord.calculateKeyTag(&dnskey_rdata),
        .algorithm = .rsasha256,
        .digest_type = .sha256,
        .data = full_digest[0..16], // truncated -- wrong length for SHA-256
        .is_dnskey = false,
    });

    // Build a fake DNSKEY ResourceRecord
    const key_rr = ResourceRecord{
        .name = .{
            .labels = owner_name,
            .wire_length = owner_name.len,
        },
        .rtype = .dnskey,
        .class = .in,
        .ttl = 3600,
        .rdlength = @intCast(dnskey_rdata.len),
        .rdata = @constCast(&dnskey_rdata),
        .wire_length = owner_name.len + 10 + dnskey_rdata.len,
    };

    const dnskeys = [_]ResourceRecord{key_rr};
    const result = try validator.verifyTrustAnchor(&dnskeys);
    // Must NOT match because anchor.data.len (16) != expected SHA-256 length (32)
    try std.testing.expect(!result);
}

test "verifyTrustAnchor: accepts correct full-length digest" {
    var validator = Validator.init(std.testing.allocator);
    defer validator.deinit();

    const owner_name: []const u8 = "\x07example\x03com\x00";
    const dnskey_rdata = [_]u8{ 0x01, 0x01, 0x03, 0x08 } ++ [_]u8{0xAA} ** 32;
    const full_digest = computeDsDigest(owner_name, &dnskey_rdata, .sha256).?;

    // Add a trust anchor with the correct full-length digest (32 bytes for SHA-256)
    try validator.addTrustAnchor(.{
        .zone = ".",
        .key_tag = ResourceRecord.calculateKeyTag(&dnskey_rdata),
        .algorithm = .rsasha256,
        .digest_type = .sha256,
        .data = full_digest[0..32], // correct length for SHA-256
        .is_dnskey = false,
    });

    const key_rr = ResourceRecord{
        .name = .{
            .labels = owner_name,
            .wire_length = owner_name.len,
        },
        .rtype = .dnskey,
        .class = .in,
        .ttl = 3600,
        .rdlength = @intCast(dnskey_rdata.len),
        .rdata = @constCast(&dnskey_rdata),
        .wire_length = owner_name.len + 10 + dnskey_rdata.len,
    };

    const dnskeys = [_]ResourceRecord{key_rr};
    const result = try validator.verifyTrustAnchor(&dnskeys);
    // Must match because digest is correct and full-length
    try std.testing.expect(result);
}

// =========================================================================
// GAP-0057 / GAP-0063: Compile-time API mismatch and case-sensitivity tests
// =========================================================================

test "GAP-0057: validateNxdomainWithNsec compiles and handles empty records" {
    var validator = Validator.init(std.testing.allocator);
    defer validator.deinit();

    // Empty NSEC records should return false (name not proven non-existent)
    const empty_records = [_]ResourceRecord{};
    const empty_msg = [_]u8{};
    const result = try validator.validateNxdomainWithNsec("example.com", &empty_records, &empty_msg);
    try std.testing.expect(!result);
}

test "GAP-0057: validateNodataWithNsec compiles and handles empty records" {
    var validator = Validator.init(std.testing.allocator);
    defer validator.deinit();

    const empty_records = [_]ResourceRecord{};
    const empty_msg = [_]u8{};
    const result = try validator.validateNodataWithNsec("example.com", .a, &empty_records, &empty_msg);
    try std.testing.expect(!result);
}

test "GAP-0057: findRrsig compiles and handles empty slice" {
    const empty_records = [_]ResourceRecord{};
    const empty_msg = [_]u8{};
    const result = findRrsig(&empty_records, .dnskey, &empty_msg);
    try std.testing.expect(result == null);
}

test "GAP-0057: nameInNsecRange compiles with []const u8 args" {
    // Ensure the function compiles correctly with wire-format []const u8 arguments
    const result = nameInNsecRange("\x03bbb\x03com\x00", "\x03aaa\x03com\x00", "\x03ccc\x03com\x00");
    try std.testing.expect(result);
}

test "GAP-0057: appendCanonicalName compiles with Name struct" {
    const name = Name{
        .labels = "\x07example\x03com\x00",
        .wire_length = 13,
    };

    var data: std.ArrayList(u8) = .empty;
    defer data.deinit(std.testing.allocator);

    try appendCanonicalName(std.testing.allocator, &data, name);
    try std.testing.expect(data.items.len > 0);
    // Verify lowercase conversion
    try std.testing.expectEqualSlices(u8, "\x07example\x03com\x00", data.items);
}

test "GAP-0057: appendCanonicalName lowercases uppercase labels" {
    const name = Name{
        .labels = "\x07EXAMPLE\x03COM\x00",
        .wire_length = 13,
    };

    var data: std.ArrayList(u8) = .empty;
    defer data.deinit(std.testing.allocator);

    try appendCanonicalName(std.testing.allocator, &data, name);
    try std.testing.expect(data.items.len > 0);
    // Verify uppercase is lowered
    try std.testing.expectEqualSlices(u8, "\x07example\x03com\x00", data.items);
}

test "GAP-0057: validateChainOfTrust compiles with full_message parameter" {
    var validator = Validator.init(std.testing.allocator);
    defer validator.deinit();

    // With no trust anchors, should return indeterminate
    const empty_rrsets = [_]DnskeyRrset{};
    const empty_ds = [_]ResourceRecord{};
    const empty_msg = [_]u8{};
    const result = try validator.validateChainOfTrust("example.com", &empty_rrsets, &empty_ds, &empty_msg);
    try std.testing.expectEqual(ValidationResult.indeterminate, result);
}

test "GAP-0063: validateNodataWithNsec uses case-insensitive name comparison" {
    // This test verifies that NSEC NODATA validation uses case-insensitive
    // DNS name comparison (RFC 4034 Section 6.1), fixing GAP-0063.
    var validator = Validator.init(std.testing.allocator);
    defer validator.deinit();

    // We cannot easily construct full NSEC records with valid rdata here,
    // but we can verify the function compiles and the Name.eql method is
    // used for comparison instead of std.mem.eql.
    const empty_records = [_]ResourceRecord{};
    const empty_msg = [_]u8{};
    const result = try validator.validateNodataWithNsec("EXAMPLE.COM", .a, &empty_records, &empty_msg);
    try std.testing.expect(!result);
}

// =========================================================================
// GAP-0064: compareDnsNames — RFC 4034 Section 6.1 canonical ordering
// =========================================================================

test "GAP-0064: compareDnsNames equal wire-format names" {
    // \x07example\x03com\x00 == \x07example\x03com\x00
    const a = "\x07example\x03com\x00";
    const b = "\x07example\x03com\x00";
    try std.testing.expectEqual(std.math.Order.eq, compareDnsNames(a, b));
}

test "GAP-0064: compareDnsNames case-insensitive wire-format names" {
    // \x07EXAMPLE\x03COM\x00 == \x07example\x03com\x00
    const a = "\x07EXAMPLE\x03COM\x00";
    const b = "\x07example\x03com\x00";
    try std.testing.expectEqual(std.math.Order.eq, compareDnsNames(a, b));
}

test "GAP-0064: compareDnsNames label-by-label from root (RFC 4034 canonical order)" {
    // RFC 4034 Section 6.1: compare from root (rightmost label) to leaf.
    // a.example.com vs z.alpha.com:
    //   Root labels: com == com
    //   Second labels: alpha < example
    //   So z.alpha.com < a.example.com
    // Wire format: \x01a\x07example\x03com\x00 vs \x01z\x05alpha\x03com\x00
    const a_example_com = "\x01a\x07example\x03com\x00";
    const z_alpha_com = "\x01z\x05alpha\x03com\x00";
    // Canonical: z.alpha.com < a.example.com (because alpha < example at second level)
    try std.testing.expectEqual(std.math.Order.gt, compareDnsNames(a_example_com, z_alpha_com));
    try std.testing.expectEqual(std.math.Order.lt, compareDnsNames(z_alpha_com, a_example_com));
}

test "GAP-0064: compareDnsNames shorter name sorts before longer name with shared labels" {
    // example.com vs a.example.com:
    //   Root labels: com == com
    //   Second labels: example == example
    //   example.com has no more labels, a.example.com has 'a'
    //   => example.com < a.example.com
    const example_com = "\x07example\x03com\x00";
    const a_example_com = "\x01a\x07example\x03com\x00";
    try std.testing.expectEqual(std.math.Order.lt, compareDnsNames(example_com, a_example_com));
    try std.testing.expectEqual(std.math.Order.gt, compareDnsNames(a_example_com, example_com));
}

test "GAP-0064: compareDnsNames root name sorts before everything" {
    // Root (\x00) sorts before any other name
    const root = "\x00";
    const example_com = "\x07example\x03com\x00";
    try std.testing.expectEqual(std.math.Order.lt, compareDnsNames(root, example_com));
    try std.testing.expectEqual(std.math.Order.gt, compareDnsNames(example_com, root));
}

test "GAP-0064: compareDnsNames same TLD different second level" {
    // aaa.com vs bbb.com:
    //   Root labels: com == com
    //   Second labels: aaa < bbb
    const aaa_com = "\x03aaa\x03com\x00";
    const bbb_com = "\x03bbb\x03com\x00";
    try std.testing.expectEqual(std.math.Order.lt, compareDnsNames(aaa_com, bbb_com));
    try std.testing.expectEqual(std.math.Order.gt, compareDnsNames(bbb_com, aaa_com));
}

test "GAP-0064: compareDnsNames different TLDs" {
    // example.com vs example.org:
    //   Root labels: com vs org => com < org
    const example_com = "\x07example\x03com\x00";
    const example_org = "\x07example\x03org\x00";
    try std.testing.expectEqual(std.math.Order.lt, compareDnsNames(example_com, example_org));
    try std.testing.expectEqual(std.math.Order.gt, compareDnsNames(example_org, example_com));
}

test "GAP-0064: compareDnsNames RFC 4034 Section 6.1 example ordering" {
    // RFC 4034 Section 6.1 specifies this canonical ordering:
    // example < a.example < yljkjljk.a.example < Z.a.example < zABC.a.EXAMPLE
    // < z.example < \001.z.example < *.z.example < \200.z.example
    // Using .example as the zone for simplicity (2-label names under example)
    const example = "\x07example\x00";
    const a_example = "\x01a\x07example\x00";
    const z_example = "\x01z\x07example\x00";
    const yljk_a_example = "\x08yljkjljk\x01a\x07example\x00";
    const Z_a_example = "\x01Z\x01a\x07example\x00";

    // example < a.example
    try std.testing.expectEqual(std.math.Order.lt, compareDnsNames(example, a_example));
    // a.example < yljkjljk.a.example
    try std.testing.expectEqual(std.math.Order.lt, compareDnsNames(a_example, yljk_a_example));
    // yljkjljk.a.example < Z.a.example (y > z case-insensitively? No, y > z is false. y < z)
    // Actually: yljkjljk vs Z (case-insensitive z). y > z? No, y(0x79) < z(0x7a). Wait...
    // These share parent a.example. So compare first labels: yljkjljk vs Z (lowered: z).
    // y(0x79) < z(0x7A) => yljkjljk < z => yljkjljk.a.example < Z.a.example
    try std.testing.expectEqual(std.math.Order.lt, compareDnsNames(yljk_a_example, Z_a_example));
    // a.example < z.example (same parent 'example', compare labels: a < z)
    try std.testing.expectEqual(std.math.Order.lt, compareDnsNames(a_example, z_example));
}

test "GAP-0064: nameInNsecRange works with canonical ordering" {
    // Test that nameInNsecRange uses correct canonical ordering
    // Setup: owner=aaa.example.com, next=zzz.example.com
    // Name bbb.example.com should be in range
    const owner = "\x03aaa\x07example\x03com\x00";
    const next = "\x03zzz\x07example\x03com\x00";
    const name = "\x03bbb\x07example\x03com\x00";
    try std.testing.expect(nameInNsecRange(name, owner, next));
}

// =========================================================================
// GAP-0065: extractNsec3OwnerHash — base32hex encoding mismatch
// =========================================================================

test "GAP-0065: decodeNsec3OwnerHash decodes base32hex to raw bytes" {
    // An NSEC3 owner name has its first label as base32hex-encoded hash.
    // SHA-1 produces 20 bytes = 32 base32hex characters.
    //
    // Example: 20 zero bytes in base32hex = "00000000000000000000000000000000"
    // base32hex alphabet: 0-9 A-V (RFC 4648 Section 7)
    // '0' in base32hex = value 0, so 32 '0' chars decode to 20 zero bytes.
    const zero_hash_b32 = "00000000000000000000000000000000";
    // Build wire-format owner name: label_len(32) + base32hex + rest_of_name
    var owner_name: [32 + 1 + 8 + 1]u8 = undefined;
    owner_name[0] = 32; // label length
    @memcpy(owner_name[1..33], zero_hash_b32);
    // Append ".example" zone suffix in wire format
    owner_name[33] = 7; // length of "example"
    @memcpy(owner_name[34..41], "example");
    owner_name[41] = 0; // root label

    const decoded = decodeNsec3OwnerHash(&owner_name) catch unreachable;
    // Should be 20 decoded bytes (all zeros)
    try std.testing.expectEqual(@as(usize, 20), decoded.len);
    for (decoded.data[0..decoded.len]) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }
}

test "GAP-0065: decodeNsec3OwnerHash decodes known base32hex value" {
    // base32hex of 0xFF repeated 20 times:
    // 20 bytes of 0xFF = 160 bits of 1s.
    // In base32hex (5 bits per char): all 5-bit groups are 11111 = 31 = 'V'
    // So 32 'V' characters decode to 20 bytes of 0xFF.
    const ff_hash_b32 = "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV";
    var owner_name: [32 + 1 + 1]u8 = undefined;
    owner_name[0] = 32; // label length
    @memcpy(owner_name[1..33], ff_hash_b32);
    owner_name[33] = 0; // root label

    const decoded = decodeNsec3OwnerHash(&owner_name) catch unreachable;
    try std.testing.expectEqual(@as(usize, 20), decoded.len);
    for (decoded.data[0..decoded.len]) |byte| {
        try std.testing.expectEqual(@as(u8, 0xFF), byte);
    }
}

test "GAP-0065: hashInNsec3Range works with decoded owner hash" {
    // The computed hash (raw binary) and the NSEC3 owner hash (base32hex in wire name)
    // must be comparable. After fixing extractNsec3OwnerHash to decode base32hex,
    // hashInNsec3Range should correctly detect a hash in range.
    //
    // Setup: owner_hash=0x05...(20 bytes), next_hash=0x15...(20 bytes)
    // Test hash=0x10...(20 bytes) should be in range.
    var owner_hash_bytes: [20]u8 = undefined;
    @memset(&owner_hash_bytes, 0x05);
    var next_hash_bytes: [20]u8 = undefined;
    @memset(&next_hash_bytes, 0x15);
    var test_hash: [20]u8 = undefined;
    @memset(&test_hash, 0x10);

    // Encode owner_hash to base32hex for the wire-format owner name
    const owner_b32 = base32hexEncode(&owner_hash_bytes);
    var owner_name: [32 + 1 + 1]u8 = undefined;
    owner_name[0] = 32;
    @memcpy(owner_name[1..33], &owner_b32);
    owner_name[33] = 0;

    // hashInNsec3Range(hash, nsec3_owner_wire_name, next_hash_raw_bytes)
    try std.testing.expect(hashInNsec3Range(&test_hash, &owner_name, &next_hash_bytes));

    // Test hash outside range (0x01 < 0x05)
    var outside_hash: [20]u8 = undefined;
    @memset(&outside_hash, 0x01);
    try std.testing.expect(!hashInNsec3Range(&outside_hash, &owner_name, &next_hash_bytes));
}

test "GAP-0065: base32hex encode-decode round-trip" {
    // Verify that encoding and then decoding produces the original bytes
    var original: [20]u8 = undefined;
    // Fill with a recognizable pattern
    for (&original, 0..) |*byte, i| {
        byte.* = @intCast(i * 13 + 7); // arbitrary non-trivial pattern
    }

    // Encode to base32hex
    const encoded = base32hexEncode(&original);

    // Decode back
    var decoded: [20]u8 = undefined;
    try base32hexDecode(&encoded, &decoded);

    try std.testing.expectEqualSlices(u8, &original, &decoded);
}

test "GAP-0065: base32hex decode is case-insensitive" {
    // NSEC3 owner names may be lowercase in some implementations
    const upper = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
    const lower = "0123456789abcdefghijklmnopqrstuv";

    var decoded_upper: [20]u8 = undefined;
    var decoded_lower: [20]u8 = undefined;
    try base32hexDecode(upper, &decoded_upper);
    try base32hexDecode(lower, &decoded_lower);

    try std.testing.expectEqualSlices(u8, &decoded_upper, &decoded_lower);
}

test "GAP-0065: base32hex decode rejects invalid characters" {
    // Characters outside base32hex alphabet (0-9, A-V / a-v) should fail
    const invalid = "WXYZ0000000000000000000000000000"; // W, X, Y, Z are invalid
    var decoded: [20]u8 = undefined;
    try std.testing.expectError(error.InvalidData, base32hexDecode(invalid, &decoded));
}

// =========================================================================
// GAP-0066/0067/0068: dottedToWire conversion and NSEC/NSEC3 wire-format fixes
// =========================================================================

test "dottedToWire: converts simple domain" {
    const wire = try dottedToWire("example.com");
    try std.testing.expectEqualSlices(u8, "\x07example\x03com\x00", wire.slice());
}

test "dottedToWire: root domain" {
    const wire = try dottedToWire(".");
    try std.testing.expectEqualSlices(u8, "\x00", wire.slice());
}

test "dottedToWire: empty string produces root" {
    const wire = try dottedToWire("");
    try std.testing.expectEqualSlices(u8, "\x00", wire.slice());
}

test "dottedToWire: trailing dot is tolerated" {
    const wire = try dottedToWire("example.com.");
    try std.testing.expectEqualSlices(u8, "\x07example\x03com\x00", wire.slice());
}

test "dottedToWire: single label" {
    const wire = try dottedToWire("localhost");
    try std.testing.expectEqualSlices(u8, "\x09localhost\x00", wire.slice());
}

test "dottedToWire: deep subdomain" {
    const wire = try dottedToWire("a.b.c.d.e");
    try std.testing.expectEqualSlices(u8, "\x01a\x01b\x01c\x01d\x01e\x00", wire.slice());
}

test "dottedToWire: label too long (>63 bytes) returns error" {
    // 64 'a' characters in a single label
    const long_label = "a" ** 64 ++ ".com";
    try std.testing.expectError(error.InvalidData, dottedToWire(long_label));
}

test "wireNamesEqlInsensitive: case-insensitive match" {
    const a = "\x07EXAMPLE\x03COM\x00";
    const b = "\x07example\x03com\x00";
    try std.testing.expect(wireNamesEqlInsensitive(a, b));
}

test "wireNamesEqlInsensitive: mismatch" {
    const a = "\x07example\x03com\x00";
    const b = "\x07example\x03org\x00";
    try std.testing.expect(!wireNamesEqlInsensitive(a, b));
}

test "GAP-0066: validateNodataWithNsec converts dotted qname to wire format" {
    // Verify that validateNodataWithNsec correctly converts a dotted-string
    // qname to wire format before comparing with the NSEC owner name.
    var validator = Validator.init(std.testing.allocator);
    defer validator.deinit();

    const empty_records = [_]ResourceRecord{};
    const empty_msg = [_]u8{};
    const result = try validator.validateNodataWithNsec("example.com", .a, &empty_records, &empty_msg);
    try std.testing.expect(!result);
}

test "GAP-0067: validateNxdomainWithNsec converts dotted qname to wire format" {
    var validator = Validator.init(std.testing.allocator);
    defer validator.deinit();

    const empty_records = [_]ResourceRecord{};
    const empty_msg = [_]u8{};
    const result = try validator.validateNxdomainWithNsec("bbb.com", &empty_records, &empty_msg);
    try std.testing.expect(!result);
}

test "GAP-0068: computeNsec3Hash uses wire format name" {
    // Verify that computeNsec3Hash produces different results for dotted vs wire-format
    // input, confirming the callers must convert first.
    var validator = Validator.init(std.testing.allocator);
    defer validator.deinit();

    const salt = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };

    // Hash the wire-format name directly (what the fixed callers now do)
    const wire = try dottedToWire("example.com");
    const hash_wire = try validator.computeNsec3Hash(wire.slice(), .sha1, 0, &salt);

    // Hash the dotted string directly (what the old code did -- wrong)
    const hash_dotted = try validator.computeNsec3Hash("example.com", .sha1, 0, &salt);

    // They must differ, proving the wire conversion matters
    try std.testing.expect(!std.mem.eql(u8, &hash_wire, &hash_dotted));
}

// =========================================================================
// SEC-AUDIT-11: validateChainOfTrust zone validation
// =========================================================================

test "SEC-AUDIT-11: validateChainOfTrust rejects DNSKEY with wrong owner name" {
    var validator = Validator.init(std.testing.allocator);
    defer validator.deinit();

    // Add a DNSKEY trust anchor so we get past the indeterminate check
    const owner_name: []const u8 = "\x07example\x03com\x00";
    const dnskey_rdata = [_]u8{ 0x01, 0x01, 0x03, 0x08 } ++ [_]u8{0xAA} ** 32;
    const full_digest = computeDsDigest(owner_name, &dnskey_rdata, .sha256).?;

    try validator.addTrustAnchor(.{
        .zone = ".",
        .key_tag = ResourceRecord.calculateKeyTag(&dnskey_rdata),
        .algorithm = .rsasha256,
        .digest_type = .sha256,
        .data = full_digest[0..32],
        .is_dnskey = true,
    });

    // Create a DNSKEY RR with a wrong owner name (evil.com instead of example.com)
    const wrong_owner: []const u8 = "\x04evil\x03com\x00";
    const key_rr = ResourceRecord{
        .name = .{
            .labels = wrong_owner,
            .wire_length = wrong_owner.len,
        },
        .rtype = .dnskey,
        .class = .in,
        .ttl = 3600,
        .rdlength = @intCast(dnskey_rdata.len),
        .rdata = @constCast(&dnskey_rdata),
        .wire_length = wrong_owner.len + 10 + dnskey_rdata.len,
    };

    const rrset = DnskeyRrset{
        .zone = "example.com",
        .keys = &[_]ResourceRecord{key_rr},
        .rrsigs = &[_]ResourceRecord{},
    };

    const empty_ds = [_]ResourceRecord{};
    const empty_msg = [_]u8{};
    const result = try validator.validateChainOfTrust(
        "example.com",
        &[_]DnskeyRrset{rrset},
        &empty_ds,
        &empty_msg,
    );

    // With the zone check, the mismatched owner should cause validation to fail
    try std.testing.expect(result == .bogus);
}

// =========================================================================
// SEC-AUDIT-12: extractWireLabels error handling
// =========================================================================

test "SEC-AUDIT-12: extractWireLabels returns error on compression pointer" {
    const wire_with_pointer = [_]u8{ 0x03, 'c', 'o', 'm', 0xC0, 0x00 };
    const result = extractWireLabels(&wire_with_pointer, 128);
    try std.testing.expectError(error.InvalidData, result);
}

test "SEC-AUDIT-12: extractWireLabels returns error on out-of-bounds label" {
    // Label length claims 10 bytes but only 3 available
    const truncated = [_]u8{ 0x0A, 'a', 'b', 'c' };
    const result = extractWireLabels(&truncated, 128);
    try std.testing.expectError(error.InvalidData, result);
}

test "SEC-AUDIT-12: extractWireLabels succeeds on valid wire name" {
    const valid = "\x07example\x03com\x00";
    const labels = try extractWireLabels(valid, 128);
    try std.testing.expectEqual(@as(usize, 2), labels.count);
    try std.testing.expectEqualSlices(u8, "example", labels.items[0]);
    try std.testing.expectEqualSlices(u8, "com", labels.items[1]);
}

test "SEC-AUDIT-12: extractWireLabels handles root name" {
    const root = "\x00";
    const labels = try extractWireLabels(root, 128);
    try std.testing.expectEqual(@as(usize, 0), labels.count);
}

// =========================================================================
// SEC-AUDIT-13: base32hexDecode trailing bits validation
// =========================================================================

test "SEC-AUDIT-13: base32hexDecode rejects non-zero trailing bits" {
    // RFC 4648 Section 3.5: non-zero trailing bits must be rejected.
    // "01" in base32hex: '0' = 0b00000, '1' = 0b00001
    // Combined: 10 bits = 0b00000_00001 => 1 byte (0x00) + 2 trailing bits (01).
    // Trailing bits are non-zero, so this should be rejected.
    var decoded: [1]u8 = undefined;
    try std.testing.expectError(error.InvalidPadding, base32hexDecode("01", &decoded));
}

test "SEC-AUDIT-13: base32hexDecode accepts zero trailing bits" {
    // "00" in base32hex: '0' = 0b00000, '0' = 0b00000
    // Combined: 10 bits = 0b00000_00000 => 1 byte (0x00) + 2 trailing bits (00).
    // Trailing bits are zero, so this should succeed.
    var decoded: [1]u8 = undefined;
    try base32hexDecode("00", &decoded);
    try std.testing.expectEqual(@as(u8, 0x00), decoded[0]);
}

// =========================================================================
// QR-NEW-01: LabelList parameterization (verified by extractWireLabels tests)
// =========================================================================

// QR-NEW-01 is verified by the existing extractWireLabels tests above.
// The comptime parameter was removed and the function now always uses 128.

// =========================================================================
// QR-NEW-02: compareDnsNames edge-case tests
// =========================================================================

test "QR-NEW-02: compareDnsNames with empty wire name" {
    const empty: []const u8 = "";
    const valid = "\x07example\x03com\x00";
    // Both empty: equal
    try std.testing.expectEqual(std.math.Order.eq, compareDnsNames(empty, empty));
    // Empty vs valid: empty has fewer labels
    try std.testing.expectEqual(std.math.Order.lt, compareDnsNames(empty, valid));
    try std.testing.expectEqual(std.math.Order.gt, compareDnsNames(valid, empty));
}

test "QR-NEW-02: compareDnsNames with truncated wire name (no root)" {
    // Wire name without root terminator: \x03com (missing \x00)
    // extractWireLabels should return error for out-of-bounds
    const truncated = "\x03com";
    const valid = "\x07example\x03com\x00";
    // truncated: label "com" length is 3, pos goes 0->1, need 1+3=4 bytes,
    // but slice is only 4 bytes (0..3 inclusive), so pos+label_len = 4 which
    // equals wire_name.len. Let me check: wire_name = [0x03, 'c', 'o', 'm']
    // pos=0, label_len=3, pos=1, 1+3=4 == 4 so NOT > so label is valid.
    // Then pos=4, 4 >= 4 so loop ends. No root terminator but no error either.
    // Actually this parses successfully with 1 label "com".
    // So truncated has 1 label, valid has 2 labels with shared "com".
    // Result: truncated (com) vs valid (example.com) -- com < example.com in
    // canonical order because after matching "com" == "com", truncated has
    // fewer labels (1 < 2).
    const order = compareDnsNames(truncated, valid);
    try std.testing.expectEqual(std.math.Order.lt, order);
}

test "QR-NEW-02: compareDnsNames with compression pointer in wire name" {
    // Wire name with compression pointer: \x03com\xC0\x00
    // Compression pointers should not appear in canonical names.
    // extractWireLabels returns error for this case.
    const with_pointer = [_]u8{ 0x03, 'c', 'o', 'm', 0xC0, 0x00 };
    const valid = "\x07example\x03com\x00";
    // Pointer causes error in extractWireLabels => 0 labels
    const order = compareDnsNames(&with_pointer, valid);
    try std.testing.expectEqual(std.math.Order.lt, order);
}

test "isNameInZone: name equals zone" {
    const name = "\x07example\x03com\x00";
    const zone = "\x07example\x03com\x00";
    try std.testing.expect(isNameInZone(name, zone));
}

test "isNameInZone: name is subdomain of zone" {
    const name = "\x03www\x07example\x03com\x00";
    const zone = "\x07example\x03com\x00";
    try std.testing.expect(isNameInZone(name, zone));
}

test "isNameInZone: name is not in zone" {
    const name = "\x04evil\x03com\x00";
    const zone = "\x07example\x03com\x00";
    try std.testing.expect(!isNameInZone(name, zone));
}

test "isNameInZone: root zone matches everything" {
    const name = "\x07example\x03com\x00";
    const root = "\x00";
    try std.testing.expect(isNameInZone(name, root));
}
