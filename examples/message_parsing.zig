// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! DNS Message Parsing Example
//!
//! Demonstrates low-level DNS message building and parsing for applications
//! that need fine-grained control over DNS packets.
//!
//! This example shows:
//! - Building DNS query messages manually
//! - Parsing DNS response messages
//! - Iterating over resource records
//! - Extracting different record types (A, AAAA, MX, TXT, etc.)
//! - Understanding DNS message structure (header, questions, answers, etc.)
//!
//! Run with: zig build run-message-parsing
//! Or: zig build examples && ./zig-out/bin/message_parsing

const std = @import("std");
const dns = @import("dns");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("\n=== DNS Message Parsing Example ===\n\n", .{});

    // =========================================================================
    // DNS Message Structure (RFC 1035)
    // =========================================================================
    //
    // A DNS message consists of:
    //
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // |                    Header                      |
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // |                   Question                     | (repeated QDCOUNT times)
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // |                    Answer                      | (repeated ANCOUNT times)
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // |                   Authority                    | (repeated NSCOUNT times)
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // |                   Additional                   | (repeated ARCOUNT times)
    // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    std.debug.print("DNS Message Structure:\n", .{});
    std.debug.print("  Header:     12 bytes (ID, flags, counts)\n", .{});
    std.debug.print("  Question:   Domain name + type + class\n", .{});
    std.debug.print("  Answer:     Resource records (RRs)\n", .{});
    std.debug.print("  Authority:  NS records for delegation\n", .{});
    std.debug.print("  Additional: Extra info (e.g., glue records)\n", .{});
    std.debug.print("\n", .{});

    // =========================================================================
    // Example 1: Building a DNS Query Message
    // =========================================================================

    std.debug.print("[1] Building a DNS Query Message\n", .{});
    {
        // Build a query for example.com A record
        const query_id: u16 = 0xABCD; // Transaction ID
        const domain = "example.com";
        const rd = true; // Recursion Desired

        const query = try dns.message.buildQuery(allocator, query_id, domain, .a, rd);
        defer allocator.free(query);

        std.debug.print("    Built query for: {s}\n", .{domain});
        std.debug.print("    Query type: A (IPv4 address)\n", .{});
        std.debug.print("    Transaction ID: 0x{X:0>4}\n", .{query_id});
        std.debug.print("    Message size: {d} bytes\n", .{query.len});

        // Show the raw bytes (first 32 bytes)
        std.debug.print("    Raw bytes: ", .{});
        for (query[0..@min(32, query.len)]) |byte| {
            std.debug.print("{X:0>2} ", .{byte});
        }
        if (query.len > 32) {
            std.debug.print("...", .{});
        }
        std.debug.print("\n", .{});

        // Parse it back to verify
        const msg = try dns.Message.parse(query);
        std.debug.print("    Parsed back:\n", .{});
        std.debug.print("      ID: 0x{X:0>4}\n", .{msg.header.id});
        std.debug.print("      QR (query/response): {}\n", .{msg.header.qr});
        std.debug.print("      RD (recursion desired): {}\n", .{msg.header.rd});
        std.debug.print("      Questions: {d}\n", .{msg.header.qdcount});
    }

    std.debug.print("\n", .{});

    // =========================================================================
    // Example 2: Parsing a DNS Response
    // =========================================================================

    std.debug.print("[2] Parsing a DNS Response\n", .{});
    {
        // Simulated DNS response for example.com
        // In practice, you would receive this from a DNS server
        const response_data = [_]u8{
            // Header (12 bytes)
            0xAB, 0xCD, // ID: 0xABCD
            0x81, 0x80, // Flags: QR=1, RD=1, RA=1, RCODE=0
            0x00, 0x01, // QDCOUNT: 1 question
            0x00, 0x02, // ANCOUNT: 2 answers
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0

            // Question section
            7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // "example"
            3, 'c', 'o', 'm', // "com"
            0, // End of name
            0x00, 0x01, // QTYPE: A
            0x00, 0x01, // QCLASS: IN

            // Answer 1: example.com A 93.184.216.34
            0xC0, 0x0C, // Name pointer to offset 12
            0x00, 0x01, // TYPE: A
            0x00, 0x01, // CLASS: IN
            0x00, 0x00, 0x01, 0x2C, // TTL: 300 seconds
            0x00, 0x04, // RDLENGTH: 4 bytes
            93, 184, 216, 34, // RDATA: 93.184.216.34

            // Answer 2: example.com A 93.184.216.35
            0xC0, 0x0C, // Name pointer
            0x00, 0x01, // TYPE: A
            0x00, 0x01, // CLASS: IN
            0x00, 0x00, 0x00, 0x3C, // TTL: 60 seconds
            0x00, 0x04, // RDLENGTH: 4
            93, 184, 216, 35, // RDATA
        };

        const msg = try dns.Message.parse(&response_data);

        std.debug.print("    Response Header:\n", .{});
        std.debug.print("      ID: 0x{X:0>4}\n", .{msg.header.id});
        std.debug.print("      QR (is response): {}\n", .{msg.header.qr});
        std.debug.print("      AA (authoritative): {}\n", .{msg.header.aa});
        std.debug.print("      TC (truncated): {}\n", .{msg.header.tc});
        std.debug.print("      RD (recursion desired): {}\n", .{msg.header.rd});
        std.debug.print("      RA (recursion available): {}\n", .{msg.header.ra});
        std.debug.print("      RCODE: {s}\n", .{@tagName(msg.header.rcode)});
        std.debug.print("      Questions: {d}\n", .{msg.header.qdcount});
        std.debug.print("      Answers: {d}\n", .{msg.header.ancount});
        std.debug.print("      Authority: {d}\n", .{msg.header.nscount});
        std.debug.print("      Additional: {d}\n", .{msg.header.arcount});

        // Check success
        std.debug.print("    Is successful: {}\n", .{msg.isSuccess()});
        std.debug.print("    Is NXDOMAIN: {}\n", .{msg.isNxdomain()});

        // Iterate over answers
        std.debug.print("    Answers:\n", .{});
        var ans_iter = try msg.answers();
        var count: usize = 0;
        while (try ans_iter.next()) |rr| {
            count += 1;
            std.debug.print("      [{d}] Type: {s}, Class: {s}, TTL: {d}s\n", .{
                count,
                @tagName(rr.rtype),
                @tagName(rr.rclass),
                rr.ttl,
            });

            // Parse A record data
            if (rr.rtype == .a) {
                const addr = try rr.parseA();
                std.debug.print("          Address: {d}.{d}.{d}.{d}\n", .{
                    addr[0], addr[1], addr[2], addr[3],
                });
            }
        }
    }

    std.debug.print("\n", .{});

    // =========================================================================
    // Example 3: Using MessageBuilder for More Control
    // =========================================================================

    std.debug.print("[3] Using MessageBuilder\n", .{});
    {
        var builder = try dns.message.MessageBuilder.initQuery(allocator, 0x1234, true);
        defer builder.deinit();

        // Add multiple questions (unusual but allowed by spec)
        try builder.addQuestion("example.com", .a, .in);

        const query = try builder.finish();
        defer allocator.free(query);

        std.debug.print("    Built query with MessageBuilder\n", .{});
        std.debug.print("    Message size: {d} bytes\n", .{query.len});

        const msg = try dns.Message.parse(query);
        std.debug.print("    Questions in message: {d}\n", .{msg.header.qdcount});
    }

    std.debug.print("\n", .{});

    // =========================================================================
    // Example 4: Understanding DNS Name Encoding
    // =========================================================================

    std.debug.print("[4] DNS Name Encoding\n", .{});
    std.debug.print("    Domain names are encoded as labels:\n", .{});
    std.debug.print("    'www.example.com' becomes:\n", .{});
    std.debug.print("      3  'w' 'w' 'w'      (length + label)\n", .{});
    std.debug.print("      7  'e' 'x' 'a' 'm' 'p' 'l' 'e'\n", .{});
    std.debug.print("      3  'c' 'o' 'm'\n", .{});
    std.debug.print("      0                    (root/end marker)\n", .{});
    std.debug.print("\n", .{});
    std.debug.print("    Name compression uses pointers (0xC0 prefix):\n", .{});
    std.debug.print("    0xC0 0x0C = pointer to offset 12 in message\n", .{});
    std.debug.print("    This saves space when names repeat in the message.\n", .{});

    std.debug.print("\n", .{});

    // =========================================================================
    // Example 5: DNS Record Types
    // =========================================================================

    std.debug.print("[5] Common DNS Record Types\n", .{});
    std.debug.print("    A      (1):  IPv4 address\n", .{});
    std.debug.print("    AAAA  (28):  IPv6 address\n", .{});
    std.debug.print("    CNAME  (5):  Canonical name (alias)\n", .{});
    std.debug.print("    MX    (15):  Mail exchanger\n", .{});
    std.debug.print("    NS     (2):  Name server\n", .{});
    std.debug.print("    PTR   (12):  Pointer (reverse DNS)\n", .{});
    std.debug.print("    SOA    (6):  Start of authority\n", .{});
    std.debug.print("    TXT   (16):  Text record\n", .{});
    std.debug.print("    SRV   (33):  Service locator\n", .{});
    std.debug.print("    CAA  (257):  Certification Authority Authorization\n", .{});

    std.debug.print("\n", .{});

    // =========================================================================
    // Example 6: Sending a Real Query (if network available)
    // =========================================================================

    std.debug.print("[6] Sending a Real DNS Query\n", .{});
    {
        // Use stub resolver to send a real query
        const servers = try dns.stub.getSystemServers(allocator);
        defer allocator.free(servers);

        if (servers.len > 0) {
            std.debug.print("    System DNS servers found: {d}\n", .{servers.len});

            var resolver = dns.stub.StubResolver.init(allocator, .{
                .servers = servers,
                .timeout_ms = 3000,
            });
            defer resolver.deinit();

            std.debug.print("    Querying for github.com A record...\n", .{});
            const response = resolver.resolve("github.com", .a) catch |err| {
                std.debug.print("    Query failed: {}\n", .{err});
                return;
            };

            std.debug.print("    Response received:\n", .{});
            std.debug.print("      Success: {}\n", .{response.isSuccess()});
            std.debug.print("      Answers: {d}\n", .{response.header.ancount});

            var ans_iter = try response.answers();
            while (try ans_iter.next()) |rr| {
                if (rr.rtype == .a) {
                    const addr = try rr.parseA();
                    std.debug.print("      A record: {d}.{d}.{d}.{d}\n", .{
                        addr[0], addr[1], addr[2], addr[3],
                    });
                }
            }
        } else {
            std.debug.print("    No system DNS servers found\n", .{});
        }
    }

    std.debug.print("\n=== Example Complete ===\n\n", .{});
}
