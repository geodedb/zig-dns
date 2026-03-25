// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Fuzz tests for security-critical DNS wire parsers (QH-05).
//!
//! These targets exercise the parsing entry points with arbitrary input,
//! ensuring they either return a valid result or a well-defined error
//! without panicking, crashing, or invoking undefined behavior.
//!
//! Run with: zig build test-fuzz
//! (In fuzz mode the test runner will repeatedly mutate inputs.)

const std = @import("std");
const header_mod = @import("header");
const message_mod = @import("message");
const name_mod = @import("name");
const record_mod = @import("record");
const question_mod = @import("question");

// ============================================================
// Fuzz targets
// ============================================================

test "fuzz Header.parse" {
    try std.testing.fuzz({}, struct {
        pub fn testOne(_: void, input: []const u8) anyerror!void {
            _ = header_mod.Header.parse(input) catch return;
        }
    }.testOne, .{});
}

test "fuzz Message.parse" {
    try std.testing.fuzz({}, struct {
        pub fn testOne(_: void, input: []const u8) anyerror!void {
            _ = message_mod.Message.parse(input) catch return;
        }
    }.testOne, .{});
}

test "fuzz Name.parse" {
    try std.testing.fuzz({}, struct {
        pub fn testOne(_: void, input: []const u8) anyerror!void {
            if (input.len == 0) return;
            _ = name_mod.Name.parse(input, 0) catch return;
        }
    }.testOne, .{});
}

test "fuzz ResourceRecord.parse" {
    try std.testing.fuzz({}, struct {
        pub fn testOne(_: void, input: []const u8) anyerror!void {
            if (input.len == 0) return;
            _ = record_mod.ResourceRecord.parse(input, 0) catch return;
        }
    }.testOne, .{});
}

test "fuzz Question.parse" {
    try std.testing.fuzz({}, struct {
        pub fn testOne(_: void, input: []const u8) anyerror!void {
            if (input.len == 0) return;
            _ = question_mod.Question.parse(input, 0) catch return;
        }
    }.testOne, .{});
}

test "fuzz Name.encodeBuf" {
    try std.testing.fuzz({}, struct {
        pub fn testOne(_: void, input: []const u8) anyerror!void {
            var buf: [256]u8 = undefined;
            _ = name_mod.Name.encodeBuf(input, &buf) catch return;
        }
    }.testOne, .{});
}

test "fuzz Message.parse with iteration" {
    try std.testing.fuzz({}, struct {
        pub fn testOne(_: void, input: []const u8) anyerror!void {
            const msg = message_mod.Message.parse(input) catch return;

            // Exercise question iteration
            var q_iter = msg.questions();
            while (q_iter.next() catch null) |_| {}

            // Exercise answer iteration
            var a_iter = msg.answers();
            while (a_iter.next() catch null) |_| {}

            // Exercise authority iteration
            var ns_iter = msg.authority();
            while (ns_iter.next() catch null) |_| {}

            // Exercise additional iteration
            var ar_iter = msg.additional();
            while (ar_iter.next() catch null) |_| {}
        }
    }.testOne, .{});
}
