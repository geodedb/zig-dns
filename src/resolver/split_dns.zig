// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Split DNS / Policy Routing
//!
//! Routes DNS queries to different resolvers based on:
//! - Domain name patterns (suffix matching, regex)
//! - Client source address
//! - Query type
//! - Time-based rules
//!
//! Common use cases:
//! - Internal vs external domain resolution
//! - Geographic-based routing
//! - VPN split tunneling
//! - Enterprise DNS policies

const std = @import("std");
const clock = @import("clock");

inline fn timeSec() i64 {
    return clock.timestamp();
}

/// Match type for domain patterns
pub const MatchType = enum {
    /// Exact domain match
    exact,
    /// Suffix match (*.example.com)
    suffix,
    /// Prefix match (internal.*)
    prefix,
    /// Contains substring
    contains,
    /// Wildcard match (supports * and ?)
    wildcard,
    /// Match all
    any,
};

/// Domain pattern for matching
pub const DomainPattern = struct {
    /// Pattern string
    pattern: []const u8,
    /// Match type
    match_type: MatchType,
    /// Case sensitive matching
    case_sensitive: bool = false,

    pub fn matches(self: *const DomainPattern, domain: []const u8) bool {
        // Normalize FQDN trailing dots (mirrors rpz.zig matchPattern,
        // GAP-0855): query names often arrive in FQDN form
        // ("server.corp.local.") while rules are stored relative
        // ("corp.local"), and vice versa. Strip ONE trailing dot from each
        // side so the forms compare equal. A bare root "." is left intact
        // -- stripping it would yield an empty pattern that matches
        // everything.
        const pattern = stripOneTrailingDot(self.pattern);
        const target = stripOneTrailingDot(domain);

        return switch (self.match_type) {
            .exact => self.matchExact(target, pattern),
            .suffix => self.matchSuffix(target, pattern),
            .prefix => self.matchPrefix(target, pattern),
            .contains => self.matchContains(target, pattern),
            .wildcard => self.matchWildcard(target, pattern),
            .any => true,
        };
    }

    fn matchExact(self: *const DomainPattern, domain: []const u8, pattern: []const u8) bool {
        if (self.case_sensitive) {
            return std.mem.eql(u8, domain, pattern);
        }
        return std.ascii.eqlIgnoreCase(domain, pattern);
    }

    fn matchSuffix(self: *const DomainPattern, domain: []const u8, pattern: []const u8) bool {
        if (pattern.len == 0) return true;
        if (domain.len < pattern.len) return false;
        const suffix = domain[domain.len - pattern.len ..];
        const suffix_eq = if (self.case_sensitive)
            std.mem.eql(u8, suffix, pattern)
        else
            std.ascii.eqlIgnoreCase(suffix, pattern);
        if (!suffix_eq) return false;

        // Label boundary validation (GAP-0847): a raw byte-suffix match would
        // let pattern "corp.local" match "evilcorp.local" (policy bypass).
        // Accept only when:
        // - the domain IS the pattern (exact match), or
        // - the pattern starts with '.' (boundary implicit in pattern), or
        // - the byte preceding the suffix in the domain is a label separator.
        if (domain.len == pattern.len) return true;
        if (pattern[0] == '.') return true;
        return domain[domain.len - pattern.len - 1] == '.';
    }

    fn matchPrefix(self: *const DomainPattern, domain: []const u8, pattern: []const u8) bool {
        if (domain.len < pattern.len) return false;
        const prefix = domain[0..pattern.len];
        if (self.case_sensitive) {
            return std.mem.eql(u8, prefix, pattern);
        }
        return std.ascii.eqlIgnoreCase(prefix, pattern);
    }

    fn matchContains(self: *const DomainPattern, domain: []const u8, pattern: []const u8) bool {
        if (self.case_sensitive) {
            return std.mem.indexOf(u8, domain, pattern) != null;
        }
        // GAP-0863: stdlib case-insensitive search (Boyer-Moore-Horspool on
        // large inputs) instead of a hand-rolled O(d*p) sliding window.
        return std.ascii.findIgnoreCase(domain, pattern) != null;
    }

    fn matchWildcard(self: *const DomainPattern, domain: []const u8, pattern: []const u8) bool {
        _ = self;
        return wildcardMatch(domain, pattern);
    }
};

/// Strip ONE trailing dot for FQDN/relative form equivalence (GAP-0855
/// convention; see rpz.zig matchPattern). A bare root "." is preserved.
fn stripOneTrailingDot(name: []const u8) []const u8 {
    if (name.len > 1 and name[name.len - 1] == '.') {
        return name[0 .. name.len - 1];
    }
    return name;
}

/// Wildcard matching (supports * and ?)
fn wildcardMatch(str: []const u8, pattern: []const u8) bool {
    var s_idx: usize = 0;
    var p_idx: usize = 0;
    var star_idx: ?usize = null;
    var match_idx: usize = 0;

    while (s_idx < str.len) {
        if (p_idx < pattern.len and (pattern[p_idx] == '?' or std.ascii.toLower(pattern[p_idx]) == std.ascii.toLower(str[s_idx]))) {
            s_idx += 1;
            p_idx += 1;
        } else if (p_idx < pattern.len and pattern[p_idx] == '*') {
            star_idx = p_idx;
            match_idx = s_idx;
            p_idx += 1;
        } else if (star_idx != null) {
            p_idx = star_idx.? + 1;
            match_idx += 1;
            s_idx = match_idx;
        } else {
            return false;
        }
    }

    while (p_idx < pattern.len and pattern[p_idx] == '*') {
        p_idx += 1;
    }

    return p_idx == pattern.len;
}

/// Query type filter
pub const QueryTypeFilter = enum {
    /// Match all query types
    any,
    /// Match specific types
    a,
    aaaa,
    mx,
    txt,
    srv,
    ptr,
    cname,
    ns,
    soa,
};

/// Time range for time-based rules
pub const TimeRange = struct {
    /// Start hour (0-23)
    start_hour: u8,
    /// End hour (0-23)
    end_hour: u8,
    /// Days of week (bitmap: bit 0 = Sunday, bit 6 = Saturday)
    days_of_week: u8 = 0x7F, // All days by default

    pub fn isActive(self: *const TimeRange, timestamp: i64) bool {
        // Convert timestamp to hour and day
        const seconds_per_day: i64 = 86400;
        const seconds_per_hour: i64 = 3600;

        // Days since Unix epoch (Jan 1, 1970 was Thursday = 4)
        const days_since_epoch = @divFloor(timestamp, seconds_per_day);
        const day_of_week: u3 = @intCast(@mod(days_since_epoch + 4, 7));

        // Hour of day
        const seconds_today = @mod(timestamp, seconds_per_day);
        const hour: u8 = @intCast(@divFloor(seconds_today, seconds_per_hour));

        // Check day
        if ((self.days_of_week & (@as(u8, 1) << day_of_week)) == 0) {
            return false;
        }

        // Check hour range
        if (self.start_hour <= self.end_hour) {
            return hour >= self.start_hour and hour < self.end_hour;
        } else {
            // Wraps around midnight
            return hour >= self.start_hour or hour < self.end_hour;
        }
    }
};

/// Resolver target
pub const ResolverTarget = struct {
    /// Server addresses
    servers: []const []const u8,
    /// Server port
    port: u16 = 53,
    /// Use TCP
    use_tcp: bool = false,
    /// Use TLS (DoT)
    use_tls: bool = false,
    /// Timeout (ms)
    timeout_ms: u32 = 5000,
};

/// Policy rule
pub const PolicyRule = struct {
    /// Rule name (for logging/debugging)
    name: []const u8,
    /// Priority (lower = higher priority)
    priority: u16 = 100,
    /// Domain patterns to match
    domains: []const DomainPattern,
    /// Query types to match
    query_types: []const QueryTypeFilter,
    /// Time restrictions
    time_range: ?TimeRange = null,
    /// Target resolver
    target: ResolverTarget,
    /// Is rule enabled
    enabled: bool = true,

    pub fn matches(self: *const PolicyRule, domain: []const u8, query_type: QueryTypeFilter, timestamp: i64) bool {
        if (!self.enabled) return false;

        // Check time range
        if (self.time_range) |tr| {
            if (!tr.isActive(timestamp)) return false;
        }

        // Check query type
        var type_match = false;
        for (self.query_types) |qt| {
            if (qt == .any or qt == query_type) {
                type_match = true;
                break;
            }
        }
        if (!type_match) return false;

        // Check domain patterns
        for (self.domains) |pattern| {
            if (pattern.matches(domain)) {
                return true;
            }
        }

        return false;
    }
};

/// Split DNS policy manager
pub const SplitDns = struct {
    allocator: std.mem.Allocator,
    /// Policy rules (sorted by priority)
    rules: std.ArrayList(PolicyRule),
    /// Default resolver (when no rules match)
    default_resolver: ResolverTarget,
    /// Statistics
    stats: Stats,

    const Self = @This();

    pub const Stats = struct {
        /// Total queries processed
        total_queries: u64 = 0,
        /// Queries matched by rules
        rule_matches: u64 = 0,
        /// Queries using default resolver
        default_matches: u64 = 0,
        /// Per-rule hit counts (keyed by rule name hash)
        rule_hits: std.AutoHashMap(u64, u64) = undefined,
    };

    pub fn init(allocator: std.mem.Allocator, default_resolver: ResolverTarget) Self {
        return Self{
            .allocator = allocator,
            .rules = .empty,
            .default_resolver = default_resolver,
            .stats = .{
                .rule_hits = std.AutoHashMap(u64, u64).init(allocator),
            },
        };
    }

    pub fn deinit(self: *Self) void {
        self.rules.deinit(self.allocator);
        self.stats.rule_hits.deinit();
    }

    /// Add a policy rule
    pub fn addRule(self: *Self, rule: PolicyRule) !void {
        // GAP-0862: binary-search insertion keeps the priority-sorted
        // invariant without a full re-sort on every add. Equal priorities
        // insert after existing entries, preserving insertion order.
        const idx = std.sort.upperBound(PolicyRule, self.rules.items, rule.priority, struct {
            fn compare(prio: u16, item: PolicyRule) std.math.Order {
                return std.math.order(prio, item.priority);
            }
        }.compare);
        try self.rules.insert(self.allocator, idx, rule);
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

    /// Find the resolver for a query
    pub fn resolve(self: *Self, domain: []const u8, query_type: QueryTypeFilter) *const ResolverTarget {
        const timestamp = timeSec();

        self.stats.total_queries += 1;

        for (self.rules.items) |*rule| {
            if (rule.matches(domain, query_type, timestamp)) {
                self.stats.rule_matches += 1;

                // Update per-rule stats
                // fips-exempt: non-security — Wyhash is a non-cryptographic stats key, not a crypto op
                const name_hash = std.hash.Wyhash.hash(0, rule.name);
                if (self.stats.rule_hits.getPtr(name_hash)) |count| {
                    count.* += 1;
                } else {
                    self.stats.rule_hits.put(name_hash, 1) catch |err| {
                        // Stats tracking is best-effort; routing proceeds regardless.
                        // Log at debug level so operators can diagnose stats OOM.
                        std.log.debug("stats rule_hits put failed: {}", .{err});
                    };
                }

                return &rule.target;
            }
        }

        self.stats.default_matches += 1;
        return &self.default_resolver;
    }

    /// Get statistics
    pub fn getStats(self: *const Self) Stats {
        return self.stats;
    }

    /// Enable/disable a rule by name
    pub fn setRuleEnabled(self: *Self, name: []const u8, enabled: bool) bool {
        for (self.rules.items) |*rule| {
            if (std.mem.eql(u8, rule.name, name)) {
                rule.enabled = enabled;
                return true;
            }
        }
        return false;
    }

    /// Get rule by name
    pub fn getRule(self: *Self, name: []const u8) ?*PolicyRule {
        for (self.rules.items) |*rule| {
            if (std.mem.eql(u8, rule.name, name)) {
                return rule;
            }
        }
        return null;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "DomainPattern exact match" {
    const pattern = DomainPattern{
        .pattern = "example.com",
        .match_type = .exact,
    };

    try std.testing.expect(pattern.matches("example.com"));
    try std.testing.expect(pattern.matches("EXAMPLE.COM"));
    try std.testing.expect(!pattern.matches("www.example.com"));
    try std.testing.expect(!pattern.matches("example.org"));
}

test "DomainPattern suffix match" {
    const pattern = DomainPattern{
        .pattern = ".example.com",
        .match_type = .suffix,
    };

    try std.testing.expect(pattern.matches("www.example.com"));
    try std.testing.expect(pattern.matches("api.example.com"));
    try std.testing.expect(!pattern.matches("example.com"));
    try std.testing.expect(!pattern.matches("example.org"));
}

test "DomainPattern FQDN trailing-dot normalization - exact" {
    // Mirrors rpz.zig matchPattern (GAP-0855): queries often arrive in
    // FQDN form while rules are stored relative, and vice versa.
    const pattern = DomainPattern{
        .pattern = "server.corp.local",
        .match_type = .exact,
    };
    try std.testing.expect(pattern.matches("server.corp.local."));

    const fqdn_pattern = DomainPattern{
        .pattern = "server.corp.local.",
        .match_type = .exact,
    };
    try std.testing.expect(fqdn_pattern.matches("server.corp.local"));

    // Bare root "." is left intact and must not match everything.
    const root_pattern = DomainPattern{
        .pattern = ".",
        .match_type = .exact,
    };
    try std.testing.expect(!root_pattern.matches("example.com"));
}

test "DomainPattern FQDN trailing-dot normalization - suffix" {
    const pattern = DomainPattern{
        .pattern = "corp.local",
        .match_type = .suffix,
    };
    try std.testing.expect(pattern.matches("server.corp.local."));
    try std.testing.expect(pattern.matches("corp.local."));
    // Label boundary enforcement (GAP-0847) still holds in FQDN form.
    try std.testing.expect(!pattern.matches("evilcorp.local."));

    const fqdn_rule = DomainPattern{
        .pattern = ".corp.local.",
        .match_type = .suffix,
    };
    try std.testing.expect(fqdn_rule.matches("server.corp.local"));
    try std.testing.expect(fqdn_rule.matches("server.corp.local."));
}

test "DomainPattern suffix match enforces label boundary (GAP-0847)" {
    // Pattern without leading dot must not match across label boundaries:
    // "corp.local" must NOT match "evilcorp.local" (policy-routing bypass).
    const pattern = DomainPattern{
        .pattern = "corp.local",
        .match_type = .suffix,
    };

    // Exact domain matches
    try std.testing.expect(pattern.matches("corp.local"));
    try std.testing.expect(pattern.matches("CORP.LOCAL"));
    // Subdomains match
    try std.testing.expect(pattern.matches("server.corp.local"));
    try std.testing.expect(pattern.matches("deep.server.corp.local"));
    // Label-boundary bypass must be rejected
    try std.testing.expect(!pattern.matches("evilcorp.local"));
    try std.testing.expect(!pattern.matches("notcorp.local"));
    try std.testing.expect(!pattern.matches("xcorp.local"));
}

test "DomainPattern suffix match leading-dot pattern keeps working (GAP-0847)" {
    const pattern = DomainPattern{
        .pattern = ".corp.local",
        .match_type = .suffix,
    };

    try std.testing.expect(pattern.matches("server.corp.local"));
    try std.testing.expect(pattern.matches("deep.server.corp.local"));
    // Leading-dot pattern does not match the bare apex (existing semantics)
    try std.testing.expect(!pattern.matches("corp.local"));
    // No bypass either
    try std.testing.expect(!pattern.matches("evilcorp.local"));
}

test "DomainPattern suffix match case-sensitive boundary (GAP-0847)" {
    const pattern = DomainPattern{
        .pattern = "corp.local",
        .match_type = .suffix,
        .case_sensitive = true,
    };

    try std.testing.expect(pattern.matches("corp.local"));
    try std.testing.expect(pattern.matches("server.corp.local"));
    try std.testing.expect(!pattern.matches("evilcorp.local"));
    try std.testing.expect(!pattern.matches("CORP.LOCAL"));
}

test "DomainPattern prefix match" {
    const pattern = DomainPattern{
        .pattern = "internal.",
        .match_type = .prefix,
    };

    try std.testing.expect(pattern.matches("internal.example.com"));
    try std.testing.expect(pattern.matches("internal.corp"));
    try std.testing.expect(!pattern.matches("example.internal.com"));
}

test "DomainPattern contains match is case-insensitive (GAP-0863)" {
    const pattern = DomainPattern{
        .pattern = "tracker",
        .match_type = .contains,
    };

    try std.testing.expect(pattern.matches("tracker.example.com"));
    try std.testing.expect(pattern.matches("ads.TRACKER.example.com"));
    try std.testing.expect(pattern.matches("AdTrAcKeR.net"));
    try std.testing.expect(pattern.matches("tracker"));
    try std.testing.expect(!pattern.matches("example.com"));
    try std.testing.expect(!pattern.matches("track.example.com"));

    const cs_pattern = DomainPattern{
        .pattern = "tracker",
        .match_type = .contains,
        .case_sensitive = true,
    };
    try std.testing.expect(cs_pattern.matches("ads.tracker.net"));
    try std.testing.expect(!cs_pattern.matches("ads.TRACKER.net"));
}

test "DomainPattern wildcard match" {
    const pattern = DomainPattern{
        .pattern = "*.example.*",
        .match_type = .wildcard,
    };

    try std.testing.expect(pattern.matches("www.example.com"));
    try std.testing.expect(pattern.matches("api.example.org"));
    try std.testing.expect(!pattern.matches("example.com"));
}

test "TimeRange basic" {
    const range = TimeRange{
        .start_hour = 9,
        .end_hour = 17,
        .days_of_week = 0x3E, // Monday-Friday
    };

    // Monday at 10:00 (should match)
    // Timestamp for a known Monday at 10:00
    const monday_10am: i64 = 345600 + 10 * 3600; // Jan 5, 1970 (Monday) + 10 hours
    try std.testing.expect(range.isActive(monday_10am));

    // Monday at 20:00 (should not match - outside hours)
    const monday_8pm: i64 = 345600 + 20 * 3600;
    try std.testing.expect(!range.isActive(monday_8pm));
}

test "SplitDns init/deinit" {
    const allocator = std.testing.allocator;

    const default = ResolverTarget{
        .servers = &[_][]const u8{"8.8.8.8"},
    };

    var dns = SplitDns.init(allocator, default);
    defer dns.deinit();

    try std.testing.expectEqual(@as(usize, 0), dns.rules.items.len);
}

test "SplitDns rule matching" {
    const allocator = std.testing.allocator;

    const default = ResolverTarget{
        .servers = &[_][]const u8{"8.8.8.8"},
    };

    var dns = SplitDns.init(allocator, default);
    defer dns.deinit();

    const corp_pattern = [_]DomainPattern{
        .{ .pattern = ".corp.local", .match_type = .suffix },
    };
    const any_type = [_]QueryTypeFilter{.any};

    try dns.addRule(.{
        .name = "corporate",
        .priority = 50,
        .domains = &corp_pattern,
        .query_types = &any_type,
        .target = .{ .servers = &[_][]const u8{"10.0.0.1"} },
    });

    // Should match corporate rule
    const result1 = dns.resolve("server.corp.local", .any);
    try std.testing.expectEqualStrings("10.0.0.1", result1.servers[0]);

    // Should use default
    const result2 = dns.resolve("google.com", .any);
    try std.testing.expectEqualStrings("8.8.8.8", result2.servers[0]);
}

test "addRule keeps rules in priority order regardless of insertion order (GAP-0862)" {
    const allocator = std.testing.allocator;

    const default = ResolverTarget{
        .servers = &[_][]const u8{"8.8.8.8"},
    };

    var dns = SplitDns.init(allocator, default);
    defer dns.deinit();

    const corp_pattern = [_]DomainPattern{
        .{ .pattern = ".corp.local", .match_type = .suffix },
    };
    const any_pattern = [_]DomainPattern{
        .{ .pattern = "", .match_type = .any },
    };
    const any_type = [_]QueryTypeFilter{.any};

    // Add the catch-all LOW-priority rule first, the specific HIGH-priority
    // (lower number) rule last -- in shuffled order.
    try dns.addRule(.{
        .name = "catch-all",
        .priority = 200,
        .domains = &any_pattern,
        .query_types = &any_type,
        .target = .{ .servers = &[_][]const u8{"1.1.1.1"} },
    });
    try dns.addRule(.{
        .name = "corporate",
        .priority = 10,
        .domains = &corp_pattern,
        .query_types = &any_type,
        .target = .{ .servers = &[_][]const u8{"10.0.0.1"} },
    });
    try dns.addRule(.{
        .name = "middle",
        .priority = 100,
        .domains = &any_pattern,
        .query_types = &any_type,
        .target = .{ .servers = &[_][]const u8{"9.9.9.9"} },
    });

    // Sorted-ascending invariant must hold.
    var prev: u16 = 0;
    for (dns.rules.items) |rule| {
        try std.testing.expect(rule.priority >= prev);
        prev = rule.priority;
    }

    // The priority-10 corporate rule must win for corp domains even though
    // the priority-200 catch-all was added first.
    const corp = dns.resolve("server.corp.local", .any);
    try std.testing.expectEqualStrings("10.0.0.1", corp.servers[0]);

    // Non-corp domains fall through to the priority-100 catch-all.
    const other = dns.resolve("google.com", .any);
    try std.testing.expectEqualStrings("9.9.9.9", other.servers[0]);
}

test "wildcardMatch" {
    try std.testing.expect(wildcardMatch("hello", "hello"));
    try std.testing.expect(wildcardMatch("hello", "h*o"));
    try std.testing.expect(wildcardMatch("hello", "h?llo"));
    try std.testing.expect(wildcardMatch("hello", "*"));
    try std.testing.expect(wildcardMatch("hello", "h*"));
    try std.testing.expect(wildcardMatch("hello", "*o"));
    try std.testing.expect(!wildcardMatch("hello", "h?o"));
    try std.testing.expect(!wildcardMatch("hello", "world"));
}
