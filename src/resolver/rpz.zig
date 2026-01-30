// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Response Policy Zones (RFC 8646)
//!
//! Implements DNS firewall functionality using RPZ:
//! - Block malicious domains
//! - Redirect queries to safe pages
//! - Passthrough for allowed domains
//! - Local data injection
//! - NXDOMAIN/NODATA responses
//!
//! References:
//! - RFC 8646: Response Policy Zone (RPZ)

const std = @import("std");

/// RPZ action to take for matching queries
pub const RpzAction = enum {
    /// Allow the query (passthrough)
    passthrough,
    /// Return NXDOMAIN
    nxdomain,
    /// Return NODATA (empty response)
    nodata,
    /// Drop the query silently
    drop,
    /// Redirect to specified address
    redirect,
    /// Return local data
    local_data,
    /// Log and allow
    log_only,
};

/// RPZ trigger type
pub const TriggerType = enum {
    /// Query name (QNAME)
    qname,
    /// Response IP address
    response_ip,
    /// Nameserver name
    ns_name,
    /// Nameserver IP
    ns_ip,
    /// Client IP
    client_ip,
};

/// RPZ rule
pub const RpzRule = struct {
    /// Rule name/description
    name: []const u8,
    /// Trigger type
    trigger: TriggerType,
    /// Domain/IP pattern to match
    pattern: []const u8,
    /// Action to take
    action: RpzAction,
    /// Redirect target (for redirect action)
    redirect_target: ?[]const u8 = null,
    /// Local data (for local_data action)
    local_data_a: ?[4]u8 = null,
    local_data_aaaa: ?[16]u8 = null,
    local_data_cname: ?[]const u8 = null,
    /// Rule priority (lower = higher priority)
    priority: u16 = 100,
    /// Is rule enabled
    enabled: bool = true,
    /// Hit count
    hits: u64 = 0,
    /// Log matches
    log_matches: bool = false,
};

/// RPZ match result
pub const MatchResult = struct {
    /// The rule that matched
    rule: *const RpzRule,
    /// Action to take
    action: RpzAction,
    /// Redirect target if applicable
    redirect_target: ?[]const u8,
    /// Local A record if applicable
    local_a: ?[4]u8,
    /// Local AAAA record if applicable
    local_aaaa: ?[16]u8,
    /// Local CNAME if applicable
    local_cname: ?[]const u8,
};

/// Response Policy Zone
pub const ResponsePolicyZone = struct {
    allocator: std.mem.Allocator,
    /// Zone name
    name: []const u8,
    /// Rules in this zone
    rules: std.ArrayList(RpzRule),
    /// Is zone enabled
    enabled: bool = true,
    /// Zone priority
    priority: u16 = 0,
    /// Default action when no rules match
    default_action: RpzAction = .passthrough,
    /// Statistics
    stats: Stats,

    const Self = @This();

    pub const Stats = struct {
        /// Total queries checked
        queries_checked: u64 = 0,
        /// Queries that matched rules
        queries_matched: u64 = 0,
        /// Queries blocked (nxdomain/nodata/drop)
        queries_blocked: u64 = 0,
        /// Queries redirected
        queries_redirected: u64 = 0,
        /// Queries allowed (passthrough)
        queries_allowed: u64 = 0,
    };

    pub fn init(allocator: std.mem.Allocator, name: []const u8) Self {
        return Self{
            .allocator = allocator,
            .name = name,
            .rules = .empty,
            .stats = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        self.rules.deinit(self.allocator);
    }

    /// Add a rule to the zone
    pub fn addRule(self: *Self, rule: RpzRule) !void {
        try self.rules.append(self.allocator, rule);

        // Sort by priority
        std.mem.sort(RpzRule, self.rules.items, {}, struct {
            fn lessThan(_: void, a: RpzRule, b: RpzRule) bool {
                return a.priority < b.priority;
            }
        }.lessThan);
    }

    /// Remove a rule by name
    pub fn removeRule(self: *Self, name: []const u8) bool {
        for (self.rules.items, 0..) |rule, i| {
            if (std.mem.eql(u8, rule.name, name)) {
                _ = self.rules.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    /// Check a query against this zone
    pub fn check(self: *Self, qname: []const u8, trigger: TriggerType) ?MatchResult {
        if (!self.enabled) return null;

        self.stats.queries_checked += 1;

        for (self.rules.items) |*rule| {
            if (!rule.enabled) continue;
            if (rule.trigger != trigger) continue;

            if (matchPattern(qname, rule.pattern)) {
                rule.hits += 1;
                self.stats.queries_matched += 1;

                // Update action-specific stats
                switch (rule.action) {
                    .nxdomain, .nodata, .drop => self.stats.queries_blocked += 1,
                    .redirect => self.stats.queries_redirected += 1,
                    .passthrough, .log_only => self.stats.queries_allowed += 1,
                    .local_data => self.stats.queries_allowed += 1,
                }

                return MatchResult{
                    .rule = rule,
                    .action = rule.action,
                    .redirect_target = rule.redirect_target,
                    .local_a = rule.local_data_a,
                    .local_aaaa = rule.local_data_aaaa,
                    .local_cname = rule.local_data_cname,
                };
            }
        }

        return null;
    }

    /// Get statistics
    pub fn getStats(self: *const Self) Stats {
        return self.stats;
    }
};

/// RPZ Manager - manages multiple RPZ zones
pub const RpzManager = struct {
    allocator: std.mem.Allocator,
    /// Policy zones (sorted by priority)
    zones: std.ArrayList(ResponsePolicyZone),
    /// Global statistics
    stats: GlobalStats,

    const Self = @This();

    pub const GlobalStats = struct {
        /// Total queries processed
        total_queries: u64 = 0,
        /// Total matches across all zones
        total_matches: u64 = 0,
        /// Queries blocked
        blocked: u64 = 0,
        /// Queries redirected
        redirected: u64 = 0,
        /// Queries allowed
        allowed: u64 = 0,
    };

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .zones = .empty,
            .stats = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.zones.items) |*zone| {
            zone.deinit();
        }
        self.zones.deinit(self.allocator);
    }

    /// Add a policy zone
    pub fn addZone(self: *Self, zone: ResponsePolicyZone) !void {
        try self.zones.append(self.allocator, zone);

        // Sort by priority
        std.mem.sort(ResponsePolicyZone, self.zones.items, {}, struct {
            fn lessThan(_: void, a: ResponsePolicyZone, b: ResponsePolicyZone) bool {
                return a.priority < b.priority;
            }
        }.lessThan);
    }

    /// Check a query against all zones
    pub fn check(self: *Self, qname: []const u8, trigger: TriggerType) ?MatchResult {
        self.stats.total_queries += 1;

        for (self.zones.items) |*zone| {
            if (zone.check(qname, trigger)) |result| {
                self.stats.total_matches += 1;

                switch (result.action) {
                    .nxdomain, .nodata, .drop => self.stats.blocked += 1,
                    .redirect => self.stats.redirected += 1,
                    else => self.stats.allowed += 1,
                }

                return result;
            }
        }

        self.stats.allowed += 1;
        return null;
    }

    /// Get a zone by name
    pub fn getZone(self: *Self, name: []const u8) ?*ResponsePolicyZone {
        for (self.zones.items) |*zone| {
            if (std.mem.eql(u8, zone.name, name)) {
                return zone;
            }
        }
        return null;
    }

    /// Enable/disable a zone
    pub fn setZoneEnabled(self: *Self, name: []const u8, enabled: bool) bool {
        if (self.getZone(name)) |zone| {
            zone.enabled = enabled;
            return true;
        }
        return false;
    }

    /// Get global statistics
    pub fn getStats(self: *const Self) GlobalStats {
        return self.stats;
    }
};

/// Match a domain against a pattern (supports wildcards)
/// Wildcard matching validates domain boundaries to prevent bypasses:
/// - Pattern `*.example.com` matches `www.example.com` but NOT `fakeexample.com`
/// - Pattern `*example.com` (no dot) also validates boundary at the match point
fn matchPattern(domain: []const u8, pattern: []const u8) bool {
    // Handle wildcard prefix
    if (pattern.len > 0 and pattern[0] == '*') {
        const suffix = pattern[1..];
        if (suffix.len == 0) return true; // Match everything

        // Suffix match with domain boundary validation
        if (domain.len < suffix.len) return false;

        // Check the suffix matches
        if (!std.ascii.eqlIgnoreCase(domain[domain.len - suffix.len ..], suffix)) {
            return false;
        }

        // Validate domain boundary to prevent bypass:
        // - If suffix starts with '.', boundary is implicit
        // - If domain is exactly the suffix length, it's an exact match
        // - Otherwise, the character before the suffix in domain must be '.'
        if (suffix.len > 0 and suffix[0] == '.') {
            return true; // Boundary is implicit in pattern
        }
        if (domain.len == suffix.len) {
            return true; // Exact match
        }
        // Check that there's a domain boundary before the suffix
        return domain[domain.len - suffix.len - 1] == '.';
    }

    // Exact match (case insensitive)
    return std.ascii.eqlIgnoreCase(domain, pattern);
}

/// Create a blocking rule for a domain
pub fn blockDomain(name: []const u8, domain: []const u8) RpzRule {
    return RpzRule{
        .name = name,
        .trigger = .qname,
        .pattern = domain,
        .action = .nxdomain,
    };
}

/// Create a redirect rule
pub fn redirectDomain(name: []const u8, domain: []const u8, target: []const u8) RpzRule {
    return RpzRule{
        .name = name,
        .trigger = .qname,
        .pattern = domain,
        .action = .redirect,
        .redirect_target = target,
    };
}

/// Create a passthrough rule (whitelist)
pub fn allowDomain(name: []const u8, domain: []const u8) RpzRule {
    return RpzRule{
        .name = name,
        .trigger = .qname,
        .pattern = domain,
        .action = .passthrough,
        .priority = 0, // High priority for whitelists
    };
}

// ============================================================================
// Tests
// ============================================================================

test "RpzAction enum" {
    try std.testing.expectEqual(RpzAction.passthrough, RpzAction.passthrough);
    try std.testing.expectEqual(RpzAction.nxdomain, RpzAction.nxdomain);
}

test "matchPattern exact" {
    try std.testing.expect(matchPattern("example.com", "example.com"));
    try std.testing.expect(matchPattern("EXAMPLE.COM", "example.com"));
    try std.testing.expect(!matchPattern("www.example.com", "example.com"));
}

test "matchPattern wildcard" {
    try std.testing.expect(matchPattern("malware.example.com", "*.example.com"));
    try std.testing.expect(matchPattern("anything.example.com", "*.example.com"));
    try std.testing.expect(!matchPattern("example.com", "*.example.com"));
    try std.testing.expect(matchPattern("anything", "*"));
}

test "ResponsePolicyZone init/deinit" {
    const allocator = std.testing.allocator;

    var zone = ResponsePolicyZone.init(allocator, "test-zone");
    defer zone.deinit();

    try std.testing.expectEqual(@as(usize, 0), zone.rules.items.len);
}

test "ResponsePolicyZone add rule and check" {
    const allocator = std.testing.allocator;

    var zone = ResponsePolicyZone.init(allocator, "blocklist");
    defer zone.deinit();

    try zone.addRule(blockDomain("block-malware", "malware.com"));
    try zone.addRule(blockDomain("block-bad-wildcard", "*.bad.com"));

    // Should block malware.com
    const result1 = zone.check("malware.com", .qname);
    try std.testing.expect(result1 != null);
    try std.testing.expectEqual(RpzAction.nxdomain, result1.?.action);

    // Should block anything.bad.com
    const result2 = zone.check("anything.bad.com", .qname);
    try std.testing.expect(result2 != null);
    try std.testing.expectEqual(RpzAction.nxdomain, result2.?.action);

    // Should not block good.com
    const result3 = zone.check("good.com", .qname);
    try std.testing.expect(result3 == null);
}

test "RpzManager multiple zones" {
    const allocator = std.testing.allocator;

    var manager = RpzManager.init(allocator);
    defer manager.deinit();

    // Add whitelist zone (higher priority)
    var whitelist = ResponsePolicyZone.init(allocator, "whitelist");
    whitelist.priority = 0;
    try whitelist.addRule(allowDomain("allow-safe", "safe.example.com"));
    try manager.addZone(whitelist);

    // Add blocklist zone (lower priority)
    var blocklist = ResponsePolicyZone.init(allocator, "blocklist");
    blocklist.priority = 100;
    try blocklist.addRule(blockDomain("block-example", "*.example.com"));
    try manager.addZone(blocklist);

    // safe.example.com should be allowed (whitelist matches first)
    const result1 = manager.check("safe.example.com", .qname);
    try std.testing.expect(result1 != null);
    try std.testing.expectEqual(RpzAction.passthrough, result1.?.action);

    // other.example.com should be blocked
    const result2 = manager.check("other.example.com", .qname);
    try std.testing.expect(result2 != null);
    try std.testing.expectEqual(RpzAction.nxdomain, result2.?.action);
}

test "helper functions" {
    const block_rule = blockDomain("test", "bad.com");
    try std.testing.expectEqual(RpzAction.nxdomain, block_rule.action);

    const redirect_rule = redirectDomain("test", "ad.com", "0.0.0.0");
    try std.testing.expectEqual(RpzAction.redirect, redirect_rule.action);

    const allow_rule = allowDomain("test", "good.com");
    try std.testing.expectEqual(RpzAction.passthrough, allow_rule.action);
    try std.testing.expectEqual(@as(u16, 0), allow_rule.priority);
}
