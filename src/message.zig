// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! DNS Message
//!
//! RFC 1035 Section 4: Messages
//!
//! Complete DNS message handling including header, question, answer,
//! authority, and additional sections.

const std = @import("std");
const name_mod = @import("name");
const header_mod = @import("header");
const question_mod = @import("question");
const record_mod = @import("record");
const types_mod = @import("types");

pub const Name = name_mod.Name;
pub const Header = header_mod.Header;
pub const Question = question_mod.Question;
pub const ResourceRecord = record_mod.ResourceRecord;
pub const Type = types_mod.Type;
pub const Class = types_mod.Class;

/// Maximum DNS message size for UDP
pub const max_udp_size = 512;

/// Maximum DNS message size with EDNS
pub const max_edns_size = 65535;

/// DNS Message (RFC 1035 Section 4)
pub const Message = struct {
    /// Raw message data
    data: []const u8,

    /// Message header
    header: Header,

    /// Offset where questions begin
    question_offset: usize,

    const Self = @This();

    /// Parse a DNS message from wire format
    pub fn parse(data: []const u8) !Self {
        const header = try Header.parse(data);

        return Self{
            .data = data,
            .header = header,
            .question_offset = header_mod.header_size,
        };
    }

    /// Iterate over questions
    pub fn questions(self: Self) QuestionIterator {
        return QuestionIterator{
            .message = self,
            .offset = self.question_offset,
            .remaining = self.header.qdcount,
        };
    }

    /// Iterate over answer records
    pub fn answers(self: Self) !RecordIterator {
        var offset = self.question_offset;

        // Skip questions
        var q_remaining = self.header.qdcount;
        while (q_remaining > 0) : (q_remaining -= 1) {
            const q = try Question.parse(self.data, offset);
            offset += q.wire_length;
        }

        return RecordIterator{
            .message = self,
            .offset = offset,
            .remaining = self.header.ancount,
        };
    }

    /// Iterate over authority records
    pub fn authority(self: Self) !RecordIterator {
        var offset = self.question_offset;

        // Skip questions
        var q_remaining = self.header.qdcount;
        while (q_remaining > 0) : (q_remaining -= 1) {
            const q = try Question.parse(self.data, offset);
            offset += q.wire_length;
        }

        // Skip answers
        var an_remaining = self.header.ancount;
        while (an_remaining > 0) : (an_remaining -= 1) {
            const rr = try ResourceRecord.parse(self.data, offset);
            offset += rr.wire_length;
        }

        return RecordIterator{
            .message = self,
            .offset = offset,
            .remaining = self.header.nscount,
        };
    }

    /// Iterate over additional records
    pub fn additional(self: Self) !RecordIterator {
        var offset = self.question_offset;

        // Skip questions
        var q_remaining = self.header.qdcount;
        while (q_remaining > 0) : (q_remaining -= 1) {
            const q = try Question.parse(self.data, offset);
            offset += q.wire_length;
        }

        // Skip answers
        var an_remaining = self.header.ancount;
        while (an_remaining > 0) : (an_remaining -= 1) {
            const rr = try ResourceRecord.parse(self.data, offset);
            offset += rr.wire_length;
        }

        // Skip authority
        var ns_remaining = self.header.nscount;
        while (ns_remaining > 0) : (ns_remaining -= 1) {
            const rr = try ResourceRecord.parse(self.data, offset);
            offset += rr.wire_length;
        }

        return RecordIterator{
            .message = self,
            .offset = offset,
            .remaining = self.header.arcount,
        };
    }

    /// Get all answer records of a specific type
    pub fn getAnswers(self: Self, allocator: std.mem.Allocator, rtype: Type) ![]ResourceRecord {
        var result: std.ArrayList(ResourceRecord) = .empty;
        errdefer result.deinit(allocator);

        var iter = try self.answers();
        while (try iter.next()) |rr| {
            if (rr.rtype == rtype) {
                try result.append(allocator, rr);
            }
        }

        return result.toOwnedSlice(allocator);
    }

    /// Check if the response is successful
    pub fn isSuccess(self: Self) bool {
        return self.header.isSuccess();
    }

    /// Check if the name was not found
    pub fn isNxdomain(self: Self) bool {
        return self.header.isNxdomain();
    }
};

/// Iterator over DNS questions
pub const QuestionIterator = struct {
    message: Message,
    offset: usize,
    remaining: u16,

    const Self = @This();

    pub fn next(self: *Self) !?Question {
        if (self.remaining == 0) {
            return null;
        }

        const q = try Question.parse(self.message.data, self.offset);
        self.offset += q.wire_length;
        self.remaining -= 1;

        return q;
    }
};

/// Iterator over DNS resource records
pub const RecordIterator = struct {
    message: Message,
    offset: usize,
    remaining: u16,

    const Self = @This();

    pub fn next(self: *Self) !?ResourceRecord {
        if (self.remaining == 0) {
            return null;
        }

        const rr = try ResourceRecord.parse(self.message.data, self.offset);
        self.offset += rr.wire_length;
        self.remaining -= 1;

        return rr;
    }
};

/// DNS Message Builder
pub const MessageBuilder = struct {
    allocator: std.mem.Allocator,
    buffer: std.ArrayList(u8),
    header: Header,
    questions_written: u16,
    answers_written: u16,
    authority_written: u16,
    additional_written: u16,

    const Self = @This();

    /// Create a new message builder for a query
    pub fn initQuery(allocator: std.mem.Allocator, id: u16, rd: bool) !Self {
        var builder = Self{
            .allocator = allocator,
            .buffer = .empty,
            .header = Header.newQuery(id, rd),
            .questions_written = 0,
            .answers_written = 0,
            .authority_written = 0,
            .additional_written = 0,
        };

        // Reserve space for header
        try builder.buffer.appendNTimes(allocator, 0, header_mod.header_size);

        return builder;
    }

    /// Create a new message builder for a response
    pub fn initResponse(allocator: std.mem.Allocator, query: Message, rcode: header_mod.ResponseCode) !Self {
        var builder = Self{
            .allocator = allocator,
            .buffer = .empty,
            .header = Header.newResponse(query.header, rcode),
            .questions_written = 0,
            .answers_written = 0,
            .authority_written = 0,
            .additional_written = 0,
        };

        // Reserve space for header
        try builder.buffer.appendNTimes(allocator, 0, header_mod.header_size);

        return builder;
    }

    /// Add a question
    pub fn addQuestion(self: *Self, domain: []const u8, qtype: Type, qclass: Class) !void {
        const encoded = try question_mod.buildQuery(self.allocator, domain, qtype, qclass);
        defer self.allocator.free(encoded);

        try self.buffer.appendSlice(self.allocator, encoded);
        self.questions_written += 1;
    }

    /// Finalize and return the message
    pub fn finish(self: *Self) ![]u8 {
        // Update header counts
        self.header.qdcount = self.questions_written;
        self.header.ancount = self.answers_written;
        self.header.nscount = self.authority_written;
        self.header.arcount = self.additional_written;

        // Write header
        try self.header.encode(self.buffer.items[0..header_mod.header_size]);

        return try self.buffer.toOwnedSlice(self.allocator);
    }

    /// Free resources
    pub fn deinit(self: *Self) void {
        self.buffer.deinit(self.allocator);
    }
};

/// Build a simple DNS query message
pub fn buildQuery(allocator: std.mem.Allocator, id: u16, domain: []const u8, qtype: Type, qclass: Class, rd: bool) ![]u8 {
    var builder = try MessageBuilder.initQuery(allocator, id, rd);
    errdefer builder.deinit();

    try builder.addQuestion(domain, qtype, qclass);

    return builder.finish();
}

test "Message.parse simple query" {
    // DNS query for example.com A record
    const data = [_]u8{
        // Header
        0x12, 0x34, // ID
        0x01, 0x00, // Flags: RD=1
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x00, // ANCOUNT: 0
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
        // Question: example.com A IN
        7,    'e',
        'x',  'a',
        'm',  'p',
        'l',  'e',
        3,    'c',
        'o',  'm',
        0,
        0x00, 0x01, // QTYPE: A
        0x00, 0x01, // QCLASS: IN
    };

    const msg = try Message.parse(&data);

    try std.testing.expectEqual(@as(u16, 0x1234), msg.header.id);
    try std.testing.expect(!msg.header.qr);
    try std.testing.expect(msg.header.rd);
    try std.testing.expectEqual(@as(u16, 1), msg.header.qdcount);

    var q_iter = msg.questions();
    const q = (try q_iter.next()).?;
    try std.testing.expectEqual(Type.a, q.qtype);
    try std.testing.expectEqual(Class.in, q.qclass);
}

test "Message.parse response with answer" {
    // DNS response for example.com A record
    const data = [_]u8{
        // Header
        0x12, 0x34, // ID
        0x81, 0x80, // Flags: QR=1, RD=1, RA=1
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x01, // ANCOUNT: 1
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
        // Question: example.com A IN
        7,    'e',
        'x',  'a',
        'm',  'p',
        'l',  'e',
        3,    'c',
        'o',  'm',
        0,
        0x00, 0x01, // QTYPE: A
        0x00, 0x01, // QCLASS: IN
        // Answer: example.com A IN 300 93.184.216.34
        0xC0, 0x0C, // Name pointer to offset 12
        0x00, 0x01, // TYPE: A
        0x00, 0x01, // CLASS: IN
        0x00, 0x00, 0x01, 0x2C, // TTL: 300
        0x00, 0x04, // RDLENGTH: 4
        93, 184, 216, 34, // RDATA
    };

    const msg = try Message.parse(&data);

    try std.testing.expect(msg.header.qr);
    try std.testing.expectEqual(@as(u16, 1), msg.header.ancount);
    try std.testing.expect(msg.isSuccess());

    var ans_iter = try msg.answers();
    const ans = (try ans_iter.next()).?;
    try std.testing.expectEqual(Type.a, ans.rtype);

    const addr = try ans.parseA();
    try std.testing.expectEqualSlices(u8, &[_]u8{ 93, 184, 216, 34 }, &addr);
}

test "buildQuery" {
    const allocator = std.testing.allocator;
    const query = try buildQuery(allocator, 0x1234, "example.com", .a, .in, true);
    defer allocator.free(query);

    const msg = try Message.parse(query);
    try std.testing.expectEqual(@as(u16, 0x1234), msg.header.id);
    try std.testing.expect(!msg.header.qr);
    try std.testing.expect(msg.header.rd);
    try std.testing.expectEqual(@as(u16, 1), msg.header.qdcount);
}
