// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Cache Poisoning Protection
//!
//! This module implements various techniques to protect DNS caches from poisoning attacks:
//!
//! RFC 5452: Measures for Making DNS More Resilient against Forged Answers
//!
//! Protection measures implemented:
//! - Bailiwick checking: Ensure records are within the queried zone
//! - TTL capping: Limit maximum TTL to prevent long-term pollution
//! - Source IP validation: Verify response comes from expected server
//! - Transaction ID validation: Match query/response IDs (done in resolver)
//! - 0x20 Case randomization: Already implemented in name.zig
//!
//! Additional recommendations (from RFC 5452):
//! - Use random source ports (OS default on modern systems)
//! - Use random transaction IDs (implemented in resolver)
//! - Don't accept responses from unexpected sources

const std = @import("std");

/// Cache protection configuration
pub const CacheProtectionConfig = struct {
    /// Maximum TTL allowed for positive responses (default: 1 day)
    max_positive_ttl_s: u32 = 86400,
    /// Maximum TTL allowed for negative responses (default: 3 hours)
    max_negative_ttl_s: u32 = 10800,
    /// Minimum TTL enforced (prevents rapid re-queries)
    min_ttl_s: u32 = 30,
    /// Enable strict bailiwick checking
    strict_bailiwick: bool = true,
    /// Enable source IP validation
    source_validation: bool = true,
    /// Enable glue record validation
    validate_glue: bool = true,
    /// Maximum glue depth (prevent deep delegation chains)
    max_glue_depth: u8 = 8,
};

/// Bailiwick check result
pub const BailiwickResult = enum {
    /// Record is within bailiwick (safe to cache)
    in_bailiwick,
    /// Record is out of bailiwick (should not be cached)
    out_of_bailiwick,
};

/// Check if a record name is within the bailiwick of a zone
/// RFC 5452 Section 4.1: Only cache records that are within bailiwick
///
/// Bailiwick rule: A record is in-bailiwick if its name is equal to or
/// a subdomain of the zone being queried.
///
/// Example: When querying "example.com":
/// - "example.com" -> in_bailiwick
/// - "www.example.com" -> in_bailiwick
/// - "other.com" -> out_of_bailiwick
/// - "com" -> out_of_bailiwick (parent zones are not in bailiwick)
pub fn checkBailiwick(record_name: []const u8, query_zone: []const u8) BailiwickResult {
    // Normalize names (remove trailing dots for comparison)
    const record_normalized = normalizeZone(record_name);
    const zone_normalized = normalizeZone(query_zone);

    // Empty zone means root
    if (zone_normalized.len == 0) {
        return .in_bailiwick; // Root zone - everything is in bailiwick
    }

    // Check if record_name is equal to or a subdomain of query_zone
    if (isSubdomainOrEqual(record_normalized, zone_normalized)) {
        return .in_bailiwick;
    }

    return .out_of_bailiwick;
}

/// Check if a child domain is equal to or a subdomain of parent
fn isSubdomainOrEqual(child: []const u8, parent: []const u8) bool {
    // Case-insensitive comparison
    if (std.ascii.eqlIgnoreCase(child, parent)) {
        return true;
    }

    // Check if child ends with ".parent"
    if (child.len <= parent.len) {
        return false;
    }

    const suffix_start = child.len - parent.len;
    if (child[suffix_start - 1] != '.') {
        return false;
    }

    return std.ascii.eqlIgnoreCase(child[suffix_start..], parent);
}

/// Normalize a zone name by removing trailing dot
fn normalizeZone(zone: []const u8) []const u8 {
    if (zone.len > 0 and zone[zone.len - 1] == '.') {
        return zone[0 .. zone.len - 1];
    }
    return zone;
}

/// Clamp TTL to configured limits (RFC 5452 Section 4.3)
pub fn clampTtl(ttl: u32, config: CacheProtectionConfig, is_negative: bool) u32 {
    const max_ttl = if (is_negative) config.max_negative_ttl_s else config.max_positive_ttl_s;
    return @max(config.min_ttl_s, @min(max_ttl, ttl));
}

/// Validate that response appears to come from expected source
/// Returns true if the source address matches expected
pub fn validateSource(
    response_source: [4]u8,
    expected_source: [4]u8,
) bool {
    return std.mem.eql(u8, &response_source, &expected_source);
}

/// Validate IPv6 source address
pub fn validateSourceV6(
    response_source: [16]u8,
    expected_source: [16]u8,
) bool {
    return std.mem.eql(u8, &response_source, &expected_source);
}

/// Validate transaction ID matches
pub fn validateTransactionId(query_id: u16, response_id: u16) bool {
    return query_id == response_id;
}

/// Validate glue records are reasonable (RFC 5452 Section 4.2)
/// Glue records should only contain A/AAAA for NS targets in the delegated zone
pub const GlueValidationResult = enum {
    valid,
    out_of_bailiwick,
    too_deep,
    unexpected_type,
};

/// Validate a potential glue record
pub fn validateGlue(
    glue_name: []const u8,
    glue_type: u16,
    delegated_zone: []const u8,
    ns_targets: []const []const u8,
    config: CacheProtectionConfig,
) GlueValidationResult {
    // Glue must be A (1) or AAAA (28)
    if (glue_type != 1 and glue_type != 28) {
        return .unexpected_type;
    }

    // Check if glue name is in the list of NS targets
    var found = false;
    for (ns_targets) |ns| {
        if (std.ascii.eqlIgnoreCase(normalizeZone(glue_name), normalizeZone(ns))) {
            found = true;
            break;
        }
    }

    if (!found) {
        return .out_of_bailiwick;
    }

    // Check bailiwick
    const bailiwick = checkBailiwick(glue_name, delegated_zone);
    if (bailiwick == .out_of_bailiwick) {
        return .out_of_bailiwick;
    }

    // Check depth (count labels)
    if (config.validate_glue) {
        var depth: u8 = 0;
        var iter = std.mem.splitScalar(u8, normalizeZone(glue_name), '.');
        while (iter.next()) |_| {
            depth += 1;
        }
        if (depth > config.max_glue_depth) {
            return .too_deep;
        }
    }

    return .valid;
}

/// Filter answer section to remove out-of-bailiwick records
/// Returns a new slice containing only safe records
pub fn filterAnswerSection(
    allocator: std.mem.Allocator,
    records: []const RecordInfo,
    query_zone: []const u8,
    config: CacheProtectionConfig,
) ![]RecordInfo {
    var result: std.ArrayList(RecordInfo) = .{};
    errdefer result.deinit(allocator);

    for (records) |record| {
        const bailiwick = checkBailiwick(record.name, query_zone);

        switch (bailiwick) {
            .in_bailiwick => {
                var clamped = record;
                clamped.ttl = clampTtl(record.ttl, config, false);
                try result.append(allocator, clamped);
            },
            .out_of_bailiwick => {
                // Skip out-of-bailiwick records in strict mode
                if (!config.strict_bailiwick) {
                    // In non-strict mode, still clamp TTL heavily
                    var clamped = record;
                    clamped.ttl = @min(300, record.ttl); // Max 5 minutes
                    try result.append(allocator, clamped);
                }
            },
        }
    }

    return try result.toOwnedSlice(allocator);
}

/// Simple record info for filtering (avoid full ResourceRecord dependency)
pub const RecordInfo = struct {
    name: []const u8,
    rtype: u16,
    ttl: u32,
    rdata: []const u8,
};

/// Response validation result
pub const ResponseValidation = struct {
    valid: bool,
    filtered_count: usize,
    reason: ?ValidationError,
};

/// Validation error reasons
pub const ValidationError = enum {
    transaction_id_mismatch,
    source_address_mismatch,
    all_records_filtered,
    malformed_response,
};

test "checkBailiwick - in bailiwick" {
    // Record exactly matching zone
    try std.testing.expectEqual(BailiwickResult.in_bailiwick, checkBailiwick("example.com", "example.com"));
    try std.testing.expectEqual(BailiwickResult.in_bailiwick, checkBailiwick("example.com.", "example.com."));

    // Subdomain in bailiwick
    try std.testing.expectEqual(BailiwickResult.in_bailiwick, checkBailiwick("www.example.com", "example.com"));
    try std.testing.expectEqual(BailiwickResult.in_bailiwick, checkBailiwick("mail.example.com", "example.com"));
    try std.testing.expectEqual(BailiwickResult.in_bailiwick, checkBailiwick("deep.sub.example.com", "example.com"));
}

test "checkBailiwick - out of bailiwick" {
    // Different domain entirely
    try std.testing.expectEqual(BailiwickResult.out_of_bailiwick, checkBailiwick("evil.com", "example.com"));

    // Parent domain (not allowed)
    try std.testing.expectEqual(BailiwickResult.out_of_bailiwick, checkBailiwick("com", "example.com"));

    // Sibling domain
    try std.testing.expectEqual(BailiwickResult.out_of_bailiwick, checkBailiwick("other.com", "example.com"));
}

test "checkBailiwick - subdomain of parent zone" {
    // When querying "com" zone, "example.com" and "ns1.example.com" are subdomains
    try std.testing.expectEqual(BailiwickResult.in_bailiwick, checkBailiwick("ns1.example.com", "com"));
    try std.testing.expectEqual(BailiwickResult.in_bailiwick, checkBailiwick("example.com", "com"));

    // ns1.sub.example.com is within example.com bailiwick (subdomain)
    try std.testing.expectEqual(BailiwickResult.in_bailiwick, checkBailiwick("ns1.sub.example.com", "example.com"));
}

test "clampTtl" {
    const config = CacheProtectionConfig{
        .max_positive_ttl_s = 86400,
        .max_negative_ttl_s = 3600,
        .min_ttl_s = 30,
    };

    // Normal TTL - no change
    try std.testing.expectEqual(@as(u32, 300), clampTtl(300, config, false));

    // TTL too high - clamped
    try std.testing.expectEqual(@as(u32, 86400), clampTtl(100000, config, false));

    // TTL too low - raised
    try std.testing.expectEqual(@as(u32, 30), clampTtl(5, config, false));

    // Negative response TTL
    try std.testing.expectEqual(@as(u32, 3600), clampTtl(86400, config, true));
}

test "validateTransactionId" {
    try std.testing.expect(validateTransactionId(0x1234, 0x1234));
    try std.testing.expect(!validateTransactionId(0x1234, 0x5678));
}

test "validateSource" {
    const expected = [_]u8{ 8, 8, 8, 8 };
    const matching = [_]u8{ 8, 8, 8, 8 };
    const different = [_]u8{ 8, 8, 4, 4 };

    try std.testing.expect(validateSource(matching, expected));
    try std.testing.expect(!validateSource(different, expected));
}

test "validateGlue" {
    const config = CacheProtectionConfig{};
    const ns_targets = [_][]const u8{ "ns1.example.com", "ns2.example.com" };

    // Valid glue A record
    try std.testing.expectEqual(
        GlueValidationResult.valid,
        validateGlue("ns1.example.com", 1, "example.com", &ns_targets, config),
    );

    // Valid glue AAAA record
    try std.testing.expectEqual(
        GlueValidationResult.valid,
        validateGlue("ns1.example.com", 28, "example.com", &ns_targets, config),
    );

    // Wrong record type
    try std.testing.expectEqual(
        GlueValidationResult.unexpected_type,
        validateGlue("ns1.example.com", 15, "example.com", &ns_targets, config),
    );

    // Not in NS targets
    try std.testing.expectEqual(
        GlueValidationResult.out_of_bailiwick,
        validateGlue("evil.example.com", 1, "example.com", &ns_targets, config),
    );
}

test "isSubdomainOrEqual" {
    try std.testing.expect(isSubdomainOrEqual("example.com", "example.com"));
    try std.testing.expect(isSubdomainOrEqual("www.example.com", "example.com"));
    try std.testing.expect(isSubdomainOrEqual("a.b.c.example.com", "example.com"));
    try std.testing.expect(!isSubdomainOrEqual("example.com", "www.example.com"));
    try std.testing.expect(!isSubdomainOrEqual("notexample.com", "example.com"));
    try std.testing.expect(!isSubdomainOrEqual("fakeexample.com", "example.com"));
}
