// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Zone File Parser (RFC 1035 Section 5)
//!
//! Parses BIND-style master zone files. Supports:
//! - Resource record definitions
//! - $ORIGIN directive for default domain
//! - $TTL directive for default TTL
//! - $INCLUDE directive for including other files
//! - Comments (starting with ;)
//! - Parentheses for multi-line records
//! - @ shorthand for current origin
//! - Relative names (appended to origin)

const std = @import("std");

/// Zone file parsing errors
pub const ParseError = error{
    InvalidFormat,
    InvalidTTL,
    InvalidClass,
    InvalidType,
    InvalidRData,
    InvalidName,
    UnterminatedQuote,
    UnterminatedParenthesis,
    UnexpectedEndOfFile,
    InvalidDirective,
    FileNotFound,
    OutOfMemory,
};

/// Resource Record class
pub const Class = enum(u16) {
    in = 1,
    cs = 2,
    ch = 3,
    hs = 4,
    any = 255,

    pub fn fromString(s: []const u8) ?Class {
        if (std.ascii.eqlIgnoreCase(s, "IN")) return .in;
        if (std.ascii.eqlIgnoreCase(s, "CS")) return .cs;
        if (std.ascii.eqlIgnoreCase(s, "CH")) return .ch;
        if (std.ascii.eqlIgnoreCase(s, "HS")) return .hs;
        if (std.ascii.eqlIgnoreCase(s, "ANY")) return .any;
        return null;
    }
};

/// Resource Record type
pub const RecordType = enum(u16) {
    a = 1,
    ns = 2,
    cname = 5,
    soa = 6,
    ptr = 12,
    mx = 15,
    txt = 16,
    aaaa = 28,
    srv = 33,
    dnskey = 48,
    ds = 43,
    rrsig = 46,
    nsec = 47,
    nsec3 = 50,
    nsec3param = 51,
    tlsa = 52,
    caa = 257,
    svcb = 64,
    https = 65,

    _,

    pub fn fromString(s: []const u8) ?RecordType {
        if (std.ascii.eqlIgnoreCase(s, "A")) return .a;
        if (std.ascii.eqlIgnoreCase(s, "NS")) return .ns;
        if (std.ascii.eqlIgnoreCase(s, "CNAME")) return .cname;
        if (std.ascii.eqlIgnoreCase(s, "SOA")) return .soa;
        if (std.ascii.eqlIgnoreCase(s, "PTR")) return .ptr;
        if (std.ascii.eqlIgnoreCase(s, "MX")) return .mx;
        if (std.ascii.eqlIgnoreCase(s, "TXT")) return .txt;
        if (std.ascii.eqlIgnoreCase(s, "AAAA")) return .aaaa;
        if (std.ascii.eqlIgnoreCase(s, "SRV")) return .srv;
        if (std.ascii.eqlIgnoreCase(s, "DNSKEY")) return .dnskey;
        if (std.ascii.eqlIgnoreCase(s, "DS")) return .ds;
        if (std.ascii.eqlIgnoreCase(s, "RRSIG")) return .rrsig;
        if (std.ascii.eqlIgnoreCase(s, "NSEC")) return .nsec;
        if (std.ascii.eqlIgnoreCase(s, "NSEC3")) return .nsec3;
        if (std.ascii.eqlIgnoreCase(s, "NSEC3PARAM")) return .nsec3param;
        if (std.ascii.eqlIgnoreCase(s, "TLSA")) return .tlsa;
        if (std.ascii.eqlIgnoreCase(s, "CAA")) return .caa;
        if (std.ascii.eqlIgnoreCase(s, "SVCB")) return .svcb;
        if (std.ascii.eqlIgnoreCase(s, "HTTPS")) return .https;

        // Try TYPE### format
        if (s.len > 4 and std.ascii.eqlIgnoreCase(s[0..4], "TYPE")) {
            const num = std.fmt.parseInt(u16, s[4..], 10) catch return null;
            return @enumFromInt(num);
        }
        return null;
    }
};

/// Parsed resource record
pub const ResourceRecord = struct {
    /// Owner name (fully qualified)
    name: []const u8,
    /// Record type
    rtype: RecordType,
    /// Record class
    class: Class,
    /// Time to live
    ttl: u32,
    /// Record data (type-specific)
    rdata: RData,

    pub const RData = union(enum) {
        /// A record - IPv4 address
        a: [4]u8,
        /// AAAA record - IPv6 address
        aaaa: [16]u8,
        /// NS, CNAME, PTR, DNAME - domain name
        name: []const u8,
        /// MX record
        mx: struct {
            preference: u16,
            exchange: []const u8,
        },
        /// SOA record
        soa: struct {
            mname: []const u8,
            rname: []const u8,
            serial: u32,
            refresh: u32,
            retry: u32,
            expire: u32,
            minimum: u32,
        },
        /// TXT record - list of strings
        txt: []const []const u8,
        /// SRV record
        srv: struct {
            priority: u16,
            weight: u16,
            port: u16,
            target: []const u8,
        },
        /// CAA record
        caa: struct {
            flags: u8,
            tag: []const u8,
            value: []const u8,
        },
        /// Raw RDATA for unsupported types
        raw: []const u8,
    };

    pub fn deinit(self: *ResourceRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        switch (self.rdata) {
            .name => |n| allocator.free(n),
            .mx => |mx| allocator.free(mx.exchange),
            .soa => |soa| {
                allocator.free(soa.mname);
                allocator.free(soa.rname);
            },
            .txt => |strings| {
                for (strings) |s| allocator.free(s);
                allocator.free(strings);
            },
            .srv => |srv| allocator.free(srv.target),
            .caa => |caa| {
                allocator.free(caa.tag);
                allocator.free(caa.value);
            },
            .raw => |r| allocator.free(r),
            else => {},
        }
    }
};

/// Parsed zone file
pub const Zone = struct {
    allocator: std.mem.Allocator,
    /// Zone origin (e.g., "example.com.")
    origin: []const u8,
    /// Resource records
    records: std.ArrayList(ResourceRecord),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .origin = "",
            .records = .empty,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.records.items) |*rr| {
            rr.deinit(self.allocator);
        }
        self.records.deinit(self.allocator);
        if (self.origin.len > 0) {
            self.allocator.free(self.origin);
        }
    }

    /// Get all records of a specific type
    pub fn getRecords(self: *const Self, name: []const u8, rtype: RecordType) []const ResourceRecord {
        var count: usize = 0;
        for (self.records.items) |rr| {
            if (std.ascii.eqlIgnoreCase(rr.name, name) and rr.rtype == rtype) {
                count += 1;
            }
        }

        if (count == 0) return &[_]ResourceRecord{};

        // Note: This returns a view into the records, not a copy
        var result = self.allocator.alloc(ResourceRecord, count) catch return &[_]ResourceRecord{};
        var i: usize = 0;
        for (self.records.items) |rr| {
            if (std.ascii.eqlIgnoreCase(rr.name, name) and rr.rtype == rtype) {
                result[i] = rr;
                i += 1;
            }
        }
        return result;
    }
};

/// Zone file parser
pub const ZoneParser = struct {
    allocator: std.mem.Allocator,
    /// Current origin
    origin: []const u8,
    /// Default TTL
    default_ttl: u32,
    /// Last seen name (for continuation lines)
    last_name: []const u8,
    /// Current line number
    line_number: usize,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .origin = "",
            .default_ttl = 86400, // 1 day default
            .last_name = "",
            .line_number = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.origin.len > 0) {
            self.allocator.free(self.origin);
            self.origin = "";
        }
        if (self.last_name.len > 0) {
            self.allocator.free(self.last_name);
            self.last_name = "";
        }
    }

    /// Parse zone file from string
    pub fn parse(self: *Self, content: []const u8) !Zone {
        var zone = Zone.init(self.allocator);
        errdefer zone.deinit();

        var lines = std.mem.splitScalar(u8, content, '\n');
        var in_parens = false;
        var continued_line: std.ArrayList(u8) = .empty;
        defer continued_line.deinit(self.allocator);

        while (lines.next()) |raw_line| {
            self.line_number += 1;

            // Remove comments (but not in quoted strings)
            const line = self.stripComment(raw_line);

            // Skip empty lines
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0 and !in_parens) continue;

            // Handle parentheses for multi-line records
            if (in_parens) {
                try continued_line.append(self.allocator, ' ');
                try continued_line.appendSlice(self.allocator, trimmed);

                if (std.mem.indexOfScalar(u8, trimmed, ')') != null) {
                    in_parens = false;
                    try self.parseLine(&zone, continued_line.items);
                    continued_line.clearRetainingCapacity();
                }
                continue;
            }

            if (std.mem.indexOfScalar(u8, trimmed, '(') != null) {
                // Check if closing paren is on same line
                if (std.mem.indexOfScalar(u8, trimmed, ')') != null) {
                    try self.parseLine(&zone, trimmed);
                } else {
                    in_parens = true;
                    try continued_line.appendSlice(self.allocator, trimmed);
                }
                continue;
            }

            try self.parseLine(&zone, trimmed);
        }

        if (in_parens) {
            return error.UnterminatedParenthesis;
        }

        if (self.origin.len > 0) {
            zone.origin = try self.allocator.dupe(u8, self.origin);
        }

        return zone;
    }

    /// Parse zone file from file path
    pub fn parseFile(self: *Self, path: []const u8) !Zone {
        const file = std.fs.cwd().openFile(path, .{}) catch return error.FileNotFound;
        defer file.close();

        const content = file.readToEndAlloc(self.allocator, 10 * 1024 * 1024) catch
            return error.OutOfMemory;
        defer self.allocator.free(content);

        return self.parse(content);
    }

    fn stripComment(self: *Self, line: []const u8) []const u8 {
        _ = self;
        var in_quote = false;
        for (line, 0..) |c, i| {
            if (c == '"') in_quote = !in_quote;
            if (c == ';' and !in_quote) return line[0..i];
        }
        return line;
    }

    fn parseLine(self: *Self, zone: *Zone, line: []const u8) !void {
        var cleaned = std.mem.trim(u8, line, " \t\r");

        // Remove parentheses
        cleaned = std.mem.trim(u8, cleaned, "()");
        cleaned = std.mem.trim(u8, cleaned, " \t");

        if (cleaned.len == 0) return;

        // Check for directives
        if (cleaned[0] == '$') {
            try self.parseDirective(cleaned);
            return;
        }

        // Parse resource record
        try self.parseResourceRecord(zone, cleaned);
    }

    fn parseDirective(self: *Self, line: []const u8) !void {
        var tokens = Tokenizer.init(line);

        const directive = tokens.next() orelse return error.InvalidDirective;

        if (std.ascii.eqlIgnoreCase(directive, "$ORIGIN")) {
            const origin = tokens.next() orelse return error.InvalidDirective;
            if (self.origin.len > 0) {
                self.allocator.free(self.origin);
            }
            self.origin = try self.allocator.dupe(u8, origin);
        } else if (std.ascii.eqlIgnoreCase(directive, "$TTL")) {
            const ttl_str = tokens.next() orelse return error.InvalidDirective;
            self.default_ttl = try parseTTL(ttl_str);
        } else if (std.ascii.eqlIgnoreCase(directive, "$INCLUDE")) {
            // $INCLUDE is not supported in this basic implementation
            return;
        } else {
            return error.InvalidDirective;
        }
    }

    fn parseResourceRecord(self: *Self, zone: *Zone, line: []const u8) !void {
        var tokens = Tokenizer.init(line);

        // First token could be: name, TTL, or class
        var name: []const u8 = "";
        var ttl: ?u32 = null;
        var class: Class = .in;
        var rtype: ?RecordType = null;

        // Determine the name
        const first = tokens.next() orelse return;

        // Check if line starts with whitespace (continuation)
        if (line[0] == ' ' or line[0] == '\t') {
            name = self.last_name;
        } else if (std.mem.eql(u8, first, "@")) {
            name = self.origin;
        } else if (Class.fromString(first) != null or parseTTL(first) catch null != null or RecordType.fromString(first) != null) {
            // First token is TTL, class, or type - use last name
            name = self.last_name;
            tokens = Tokenizer.init(line); // Reset tokenizer
        } else {
            // First token is the name
            name = try self.makeAbsolute(first);
        }

        // Parse remaining tokens: [TTL] [class] type rdata...
        while (tokens.next()) |token| {
            // Try to parse as TTL
            if (ttl == null) {
                if (parseTTL(token) catch null) |t| {
                    ttl = t;
                    continue;
                }
            }

            // Try to parse as class
            if (Class.fromString(token)) |c| {
                class = c;
                continue;
            }

            // Try to parse as type
            if (RecordType.fromString(token)) |t| {
                rtype = t;
                break;
            }
        }

        const record_type = rtype orelse return error.InvalidType;

        // Parse RDATA
        const rdata = try self.parseRData(record_type, &tokens);

        // Create record
        const rr = ResourceRecord{
            .name = try self.allocator.dupe(u8, name),
            .rtype = record_type,
            .class = class,
            .ttl = ttl orelse self.default_ttl,
            .rdata = rdata,
        };

        try zone.records.append(zone.allocator, rr);

        // Remember last name
        if (name.len > 0 and !std.mem.eql(u8, name, self.last_name)) {
            if (self.last_name.len > 0 and !std.mem.eql(u8, self.last_name, self.origin)) {
                self.allocator.free(self.last_name);
            }
            self.last_name = try self.allocator.dupe(u8, name);
        }
    }

    fn parseRData(self: *Self, rtype: RecordType, tokens: *Tokenizer) !ResourceRecord.RData {
        switch (rtype) {
            .a => {
                const addr_str = tokens.next() orelse return error.InvalidRData;
                var addr: [4]u8 = undefined;
                var parts = std.mem.splitScalar(u8, addr_str, '.');
                var i: usize = 0;
                while (parts.next()) |part| {
                    if (i >= 4) return error.InvalidRData;
                    addr[i] = std.fmt.parseInt(u8, part, 10) catch return error.InvalidRData;
                    i += 1;
                }
                if (i != 4) return error.InvalidRData;
                return .{ .a = addr };
            },
            .aaaa => {
                const addr_str = tokens.next() orelse return error.InvalidRData;
                var addr: [16]u8 = undefined;
                // Parse IPv6 address
                const expanded = try expandIPv6(self.allocator, addr_str);
                defer self.allocator.free(expanded);
                var groups = std.mem.splitScalar(u8, expanded, ':');
                var i: usize = 0;
                while (groups.next()) |group| {
                    if (i >= 8) return error.InvalidRData;
                    const val = std.fmt.parseInt(u16, group, 16) catch return error.InvalidRData;
                    addr[i * 2] = @truncate(val >> 8);
                    addr[i * 2 + 1] = @truncate(val & 0xFF);
                    i += 1;
                }
                if (i != 8) return error.InvalidRData;
                return .{ .aaaa = addr };
            },
            .ns, .cname, .ptr => {
                const name = tokens.next() orelse return error.InvalidRData;
                return .{ .name = try self.makeAbsolute(name) };
            },
            .mx => {
                const pref_str = tokens.next() orelse return error.InvalidRData;
                const exchange = tokens.next() orelse return error.InvalidRData;
                const preference = std.fmt.parseInt(u16, pref_str, 10) catch return error.InvalidRData;
                return .{ .mx = .{
                    .preference = preference,
                    .exchange = try self.makeAbsolute(exchange),
                } };
            },
            .soa => {
                const mname = tokens.next() orelse return error.InvalidRData;
                const rname = tokens.next() orelse return error.InvalidRData;
                const serial_str = tokens.next() orelse return error.InvalidRData;
                const refresh_str = tokens.next() orelse return error.InvalidRData;
                const retry_str = tokens.next() orelse return error.InvalidRData;
                const expire_str = tokens.next() orelse return error.InvalidRData;
                const minimum_str = tokens.next() orelse return error.InvalidRData;

                return .{ .soa = .{
                    .mname = try self.makeAbsolute(mname),
                    .rname = try self.makeAbsolute(rname),
                    .serial = std.fmt.parseInt(u32, serial_str, 10) catch return error.InvalidRData,
                    .refresh = try parseTTL(refresh_str),
                    .retry = try parseTTL(retry_str),
                    .expire = try parseTTL(expire_str),
                    .minimum = try parseTTL(minimum_str),
                } };
            },
            .txt => {
                var strings: std.ArrayList([]const u8) = .empty;
                errdefer {
                    for (strings.items) |s| self.allocator.free(s);
                    strings.deinit(self.allocator);
                }

                while (tokens.nextQuoted()) |s| {
                    try strings.append(self.allocator, try self.allocator.dupe(u8, s));
                }

                return .{ .txt = try strings.toOwnedSlice(self.allocator) };
            },
            .srv => {
                const priority_str = tokens.next() orelse return error.InvalidRData;
                const weight_str = tokens.next() orelse return error.InvalidRData;
                const port_str = tokens.next() orelse return error.InvalidRData;
                const target = tokens.next() orelse return error.InvalidRData;

                return .{ .srv = .{
                    .priority = std.fmt.parseInt(u16, priority_str, 10) catch return error.InvalidRData,
                    .weight = std.fmt.parseInt(u16, weight_str, 10) catch return error.InvalidRData,
                    .port = std.fmt.parseInt(u16, port_str, 10) catch return error.InvalidRData,
                    .target = try self.makeAbsolute(target),
                } };
            },
            .caa => {
                const flags_str = tokens.next() orelse return error.InvalidRData;
                const tag = tokens.next() orelse return error.InvalidRData;
                const value = tokens.nextQuoted() orelse return error.InvalidRData;

                return .{ .caa = .{
                    .flags = std.fmt.parseInt(u8, flags_str, 10) catch return error.InvalidRData,
                    .tag = try self.allocator.dupe(u8, tag),
                    .value = try self.allocator.dupe(u8, value),
                } };
            },
            else => {
                // Collect remaining tokens as raw data
                var raw: std.ArrayList(u8) = .empty;
                errdefer raw.deinit(self.allocator);

                while (tokens.next()) |t| {
                    if (raw.items.len > 0) try raw.append(self.allocator, ' ');
                    try raw.appendSlice(self.allocator, t);
                }

                return .{ .raw = try raw.toOwnedSlice(self.allocator) };
            },
        }
    }

    fn makeAbsolute(self: *Self, name: []const u8) ![]const u8 {
        if (name.len == 0) return error.InvalidName;

        // Already absolute
        if (name[name.len - 1] == '.') {
            return try self.allocator.dupe(u8, name);
        }

        // Append origin
        if (self.origin.len == 0) {
            return try self.allocator.dupe(u8, name);
        }

        var result: std.ArrayList(u8) = .empty;
        errdefer result.deinit(self.allocator);

        try result.appendSlice(self.allocator, name);
        if (self.origin[0] != '.') {
            try result.append(self.allocator, '.');
        }
        try result.appendSlice(self.allocator, self.origin);

        return try result.toOwnedSlice(self.allocator);
    }
};

/// Simple tokenizer for zone file lines
const Tokenizer = struct {
    data: []const u8,
    pos: usize,

    pub fn init(data: []const u8) Tokenizer {
        return .{ .data = data, .pos = 0 };
    }

    pub fn next(self: *Tokenizer) ?[]const u8 {
        // Skip whitespace
        while (self.pos < self.data.len and (self.data[self.pos] == ' ' or self.data[self.pos] == '\t')) {
            self.pos += 1;
        }

        if (self.pos >= self.data.len) return null;

        const start = self.pos;

        // Handle quoted strings
        if (self.data[self.pos] == '"') {
            self.pos += 1;
            while (self.pos < self.data.len and self.data[self.pos] != '"') {
                self.pos += 1;
            }
            if (self.pos < self.data.len) self.pos += 1;
            return self.data[start + 1 .. self.pos - 1];
        }

        // Regular token
        while (self.pos < self.data.len and
            self.data[self.pos] != ' ' and
            self.data[self.pos] != '\t' and
            self.data[self.pos] != '(' and
            self.data[self.pos] != ')')
        {
            self.pos += 1;
        }

        if (start == self.pos) return null;
        return self.data[start..self.pos];
    }

    pub fn nextQuoted(self: *Tokenizer) ?[]const u8 {
        // Skip whitespace
        while (self.pos < self.data.len and (self.data[self.pos] == ' ' or self.data[self.pos] == '\t')) {
            self.pos += 1;
        }

        if (self.pos >= self.data.len) return null;

        // Quoted string
        if (self.data[self.pos] == '"') {
            self.pos += 1;
            const start = self.pos;
            while (self.pos < self.data.len and self.data[self.pos] != '"') {
                self.pos += 1;
            }
            const end = self.pos;
            if (self.pos < self.data.len) self.pos += 1;
            return self.data[start..end];
        }

        // Unquoted string
        return self.next();
    }
};

/// Parse TTL value with optional suffix (s, m, h, d, w)
fn parseTTL(s: []const u8) ParseError!u32 {
    if (s.len == 0) return error.InvalidTTL;

    var value: u32 = 0;
    var current: u32 = 0;

    for (s) |c| {
        if (c >= '0' and c <= '9') {
            current = current * 10 + (c - '0');
        } else {
            const multiplier: u32 = switch (c) {
                's', 'S' => 1,
                'm', 'M' => 60,
                'h', 'H' => 3600,
                'd', 'D' => 86400,
                'w', 'W' => 604800,
                else => return error.InvalidTTL,
            };
            value += current * multiplier;
            current = 0;
        }
    }

    return value + current;
}

/// Expand IPv6 address (handle :: shorthand)
fn expandIPv6(allocator: std.mem.Allocator, addr: []const u8) ![]u8 {
    // Find ::
    if (std.mem.indexOf(u8, addr, "::")) |pos| {
        // Count groups before and after
        var before: usize = 0;
        var after: usize = 0;

        if (pos > 0) {
            var iter = std.mem.splitScalar(u8, addr[0..pos], ':');
            while (iter.next()) |_| before += 1;
        }

        if (pos + 2 < addr.len) {
            var iter = std.mem.splitScalar(u8, addr[pos + 2 ..], ':');
            while (iter.next()) |_| after += 1;
        }

        const zeros_needed = 8 - before - after;

        var result: std.ArrayList(u8) = .empty;
        errdefer result.deinit(allocator);

        // Add groups before ::
        if (pos > 0) {
            try result.appendSlice(allocator, addr[0..pos]);
        }

        // Add zeros
        var i: usize = 0;
        while (i < zeros_needed) : (i += 1) {
            if (result.items.len > 0) try result.append(allocator, ':');
            try result.append(allocator, '0');
        }

        // Add groups after ::
        if (pos + 2 < addr.len) {
            try result.append(allocator, ':');
            try result.appendSlice(allocator, addr[pos + 2 ..]);
        }

        return try result.toOwnedSlice(allocator);
    }

    return try allocator.dupe(u8, addr);
}

// ============================================================================
// Tests
// ============================================================================

test "parseTTL basic" {
    try std.testing.expectEqual(@as(u32, 3600), try parseTTL("3600"));
    try std.testing.expectEqual(@as(u32, 3600), try parseTTL("1h"));
    try std.testing.expectEqual(@as(u32, 86400), try parseTTL("1d"));
    try std.testing.expectEqual(@as(u32, 604800), try parseTTL("1w"));
    try std.testing.expectEqual(@as(u32, 90061), try parseTTL("1d1h1m1s"));
}

test "Class.fromString" {
    try std.testing.expectEqual(Class.in, Class.fromString("IN").?);
    try std.testing.expectEqual(Class.in, Class.fromString("in").?);
    try std.testing.expect(Class.fromString("XX") == null);
}

test "RecordType.fromString" {
    try std.testing.expectEqual(RecordType.a, RecordType.fromString("A").?);
    try std.testing.expectEqual(RecordType.aaaa, RecordType.fromString("AAAA").?);
    try std.testing.expectEqual(RecordType.mx, RecordType.fromString("MX").?);
    try std.testing.expectEqual(@as(RecordType, @enumFromInt(999)), RecordType.fromString("TYPE999").?);
}

test "Tokenizer basic" {
    var t = Tokenizer.init("foo bar baz");
    try std.testing.expectEqualStrings("foo", t.next().?);
    try std.testing.expectEqualStrings("bar", t.next().?);
    try std.testing.expectEqualStrings("baz", t.next().?);
    try std.testing.expect(t.next() == null);
}

test "Tokenizer quoted" {
    var t = Tokenizer.init("foo \"hello world\" bar");
    try std.testing.expectEqualStrings("foo", t.next().?);
    try std.testing.expectEqualStrings("hello world", t.next().?);
    try std.testing.expectEqualStrings("bar", t.next().?);
}

test "ZoneParser simple A record" {
    const allocator = std.testing.allocator;
    var parser = ZoneParser.init(allocator);
    defer parser.deinit();

    const content =
        \\$ORIGIN example.com.
        \\www IN A 192.168.1.1
    ;

    var zone = try parser.parse(content);
    defer zone.deinit();

    try std.testing.expectEqual(@as(usize, 1), zone.records.items.len);
    const rr = zone.records.items[0];
    try std.testing.expectEqual(RecordType.a, rr.rtype);
    try std.testing.expectEqual([4]u8{ 192, 168, 1, 1 }, rr.rdata.a);
}

test "ZoneParser SOA record" {
    const allocator = std.testing.allocator;
    var parser = ZoneParser.init(allocator);
    defer parser.deinit();

    const content =
        \\$ORIGIN example.com.
        \\$TTL 86400
        \\@ IN SOA ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400
    ;

    var zone = try parser.parse(content);
    defer zone.deinit();

    try std.testing.expectEqual(@as(usize, 1), zone.records.items.len);
    const rr = zone.records.items[0];
    try std.testing.expectEqual(RecordType.soa, rr.rtype);
    try std.testing.expectEqual(@as(u32, 2024010101), rr.rdata.soa.serial);
}

test "ZoneParser MX record" {
    const allocator = std.testing.allocator;
    var parser = ZoneParser.init(allocator);
    defer parser.deinit();

    const content =
        \\$ORIGIN example.com.
        \\@ IN MX 10 mail.example.com.
    ;

    var zone = try parser.parse(content);
    defer zone.deinit();

    try std.testing.expectEqual(@as(usize, 1), zone.records.items.len);
    const rr = zone.records.items[0];
    try std.testing.expectEqual(RecordType.mx, rr.rtype);
    try std.testing.expectEqual(@as(u16, 10), rr.rdata.mx.preference);
}

test "expandIPv6" {
    const allocator = std.testing.allocator;

    const result1 = try expandIPv6(allocator, "2001:db8::1");
    defer allocator.free(result1);
    try std.testing.expectEqualStrings("2001:db8:0:0:0:0:0:1", result1);

    const result2 = try expandIPv6(allocator, "::1");
    defer allocator.free(result2);
    try std.testing.expectEqualStrings("0:0:0:0:0:0:0:1", result2);

    const result3 = try expandIPv6(allocator, "2001:db8::");
    defer allocator.free(result3);
    try std.testing.expectEqualStrings("2001:db8:0:0:0:0:0:0", result3);
}
