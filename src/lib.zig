// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! DNS Library for Zig
//!
//! A pure Zig implementation of the Domain Name System (DNS) protocol.
//! Supports full recursive resolution and standard stub resolution.
//!
//! ## Features
//!
//! - RFC 1035 compliant DNS message parsing and encoding
//! - Stub resolver for simple DNS queries
//! - Full recursive resolver for complete name resolution
//! - EDNS0 support (RFC 6891)
//! - Cross-platform: Linux, macOS, Windows
//! - Zero external dependencies
//!
//! ## Quick Start
//!
//! ```zig
//! const dns = @import("dns");
//!
//! // Create a client
//! var client = dns.Client.init(allocator);
//! defer client.deinit();
//!
//! // Resolve a hostname
//! const result = try client.resolve("example.com", .a);
//! ```
//!
//! ## Module Organization
//!
//! - `types`: DNS record types, classes, and opcodes
//! - `name`: DNS name encoding and compression
//! - `header`: DNS message header
//! - `question`: DNS question section
//! - `record`: DNS resource records
//! - `message`: Complete DNS message handling
//! - `edns`: EDNS0 extensions
//! - `cache`: DNS response caching
//! - `stub`: Stub resolver (forwards to upstream)
//! - `recursive`: Full recursive resolver
//! - `client`: High-level resolution interface

const std = @import("std");

// Core protocol modules
pub const name = @import("name");
pub const header = @import("header");
pub const types = @import("types");
pub const question = @import("question");
pub const record = @import("record");
pub const message = @import("message");

// Extensions
pub const edns = @import("edns");

// Resolution
pub const cache = @import("cache");
pub const stub = @import("stub");
pub const recursive = @import("recursive");
pub const client = @import("client");

// Re-export commonly used types for convenience
pub const Name = name.Name;
pub const Header = header.Header;
pub const Message = message.Message;
pub const Question = question.Question;
pub const ResourceRecord = record.ResourceRecord;
pub const Client = client.Client;

// Type aliases
pub const Type = types.Type;
pub const Class = types.Class;
pub const Opcode = types.Opcode;
pub const ResponseCode = types.ResponseCode;

test {
    // Run all module tests
    std.testing.refAllDecls(@This());
}
