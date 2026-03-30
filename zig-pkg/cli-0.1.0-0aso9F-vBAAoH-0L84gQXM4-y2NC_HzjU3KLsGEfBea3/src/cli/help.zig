// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Help Module
//!
//! Help text generation with examples-first approach and
//! support for concise vs. full help output.
//!
//! ## Custom Templates
//!
//! The help system supports custom templates for formatting help output.
//! Use `HelpTemplate` to customize section order, headers, and rendering.
//!
//! ```zig
//! const template = HelpTemplate{
//!     .sections = &.{ .usage, .examples, .description, .commands, .flags },
//!     .usage_header = "USAGE",
//!     .examples_header = "EXAMPLES",
//!     .show_global_flags = true,
//! };
//! printHelpWithTemplate(cmd, ctx, &template);
//! ```

const std = @import("std");
const mem = std.mem;

const command = @import("command.zig");
const Command = command.Command;
const Context = command.Context;
const FlagSpec = command.FlagSpec;

/// Help section types for template ordering
pub const HelpSection = enum {
    /// Command name and summary
    header,
    /// Usage line showing command syntax
    usage,
    /// Usage examples (examples-first approach)
    examples,
    /// Long description/help text
    description,
    /// List of subcommands
    commands,
    /// List of flags/options
    flags,
    /// Footer with additional hints
    footer,
};

/// Custom help template for formatting help output
pub const HelpTemplate = struct {
    /// Order of sections to display (default: header, usage, examples, description, commands, flags, footer)
    sections: []const HelpSection = &.{ .header, .usage, .examples, .description, .commands, .flags, .footer },

    /// Header for usage section
    usage_header: []const u8 = "Usage",
    /// Header for examples section
    examples_header: []const u8 = "Examples",
    /// Header for description section (empty = no header, just content)
    description_header: []const u8 = "",
    /// Header for commands section (supports groups override)
    commands_header: []const u8 = "Commands",
    /// Header for flags section
    flags_header: []const u8 = "Flags",

    /// Whether to show global flags (--help, --version, etc.)
    show_global_flags: bool = true,
    /// Whether to show the footer hint
    show_footer: bool = true,
    /// Custom footer text (null = default)
    footer_text: ?[]const u8 = null,

    /// Indentation for content (number of spaces)
    indent: u8 = 2,
    /// Column width for flag/command names before description
    name_column_width: u8 = 20,

    /// Custom section renderer callback (optional)
    /// If set, this function is called for each section, allowing full customization
    custom_renderer: ?*const fn (*const Command, *Context, HelpSection, *const HelpTemplate) bool = null,

    /// Default template with examples-first approach
    pub const default = HelpTemplate{};

    /// Minimal template (usage and flags only)
    pub const minimal = HelpTemplate{
        .sections = &.{ .usage, .flags },
        .show_global_flags = false,
        .show_footer = false,
    };

    /// Verbose template with all sections and descriptions
    pub const verbose = HelpTemplate{
        .sections = &.{ .header, .usage, .description, .examples, .commands, .flags, .footer },
        .usage_header = "USAGE",
        .examples_header = "EXAMPLES",
        .commands_header = "COMMANDS",
        .flags_header = "OPTIONS",
    };

    /// Man-page style template
    pub const manpage = HelpTemplate{
        .sections = &.{ .header, .usage, .description, .commands, .flags, .examples },
        .usage_header = "SYNOPSIS",
        .examples_header = "EXAMPLES",
        .description_header = "DESCRIPTION",
        .commands_header = "COMMANDS",
        .flags_header = "OPTIONS",
    };
};

/// Print help for a command
pub fn printHelp(cmd: *const Command, ctx: *Context) void {
    printHelpWithTemplate(cmd, ctx, &HelpTemplate.default);
}

/// Print help using a custom template
pub fn printHelpWithTemplate(cmd: *const Command, ctx: *Context, template: *const HelpTemplate) void {
    if (ctx.json) {
        printJsonHelp(cmd, ctx) catch {};
    } else {
        printTextHelpWithTemplate(cmd, ctx, template) catch {};
    }
}

/// Print text-format help using a template
fn printTextHelpWithTemplate(cmd: *const Command, ctx: *Context, template: *const HelpTemplate) !void {
    const w = ctx.stdout;
    const use_color = ctx.useColor();

    for (template.sections) |section| {
        // Check for custom renderer first
        if (template.custom_renderer) |renderer| {
            if (renderer(cmd, ctx, section, template)) {
                continue; // Custom renderer handled this section
            }
        }

        switch (section) {
            .header => try printSectionHeader(w, use_color, cmd),
            .usage => try printSectionUsage(w, cmd, template),
            .examples => try printSectionExamples(w, cmd, template),
            .description => try printSectionDescription(w, cmd, template),
            .commands => try printSectionCommands(w, use_color, cmd, template),
            .flags => try printSectionFlags(w, use_color, cmd, template),
            .footer => try printSectionFooter(w, cmd, template),
        }
    }
}

/// Print header section (name and summary)
fn printSectionHeader(w: anytype, use_color: bool, cmd: *const Command) !void {
    if (use_color) {
        try w.print("\x1b[1m{s}\x1b[0m", .{cmd.name});
    } else {
        try w.print("{s}", .{cmd.name});
    }
    try w.print(" - {s}\n", .{cmd.summary});
}

/// Print usage section
fn printSectionUsage(w: anytype, cmd: *const Command, template: *const HelpTemplate) !void {
    try w.print("\n{s}: {s} [flags]", .{ template.usage_header, cmd.name });
    if (cmd.hasSubcommands()) {
        try w.print(" <command> [args]", .{});
    }
    try w.print("\n", .{});
}

/// Print examples section
fn printSectionExamples(w: anytype, cmd: *const Command, template: *const HelpTemplate) !void {
    if (cmd.examples.len == 0) return;

    try w.print("\n{s}:\n", .{template.examples_header});
    for (cmd.examples) |example| {
        // Write indent
        var i: u8 = 0;
        while (i < template.indent) : (i += 1) {
            try w.writeAll(" ");
        }
        try w.print("{s}\n", .{example});
    }
}

/// Print description section
fn printSectionDescription(w: anytype, cmd: *const Command, template: *const HelpTemplate) !void {
    if (cmd.long_help.len == 0) return;

    if (template.description_header.len > 0) {
        try w.print("\n{s}:\n", .{template.description_header});
    } else {
        try w.print("\n", .{});
    }
    try w.print("{s}\n", .{cmd.long_help});
}

/// Print commands section (with group support)
fn printSectionCommands(w: anytype, use_color: bool, cmd: *const Command, template: *const HelpTemplate) !void {
    if (cmd.subcommands.len == 0) return;

    // Collect unique groups
    var groups: [32][]const u8 = undefined;
    var group_count: usize = 0;

    for (cmd.subcommands) |subcmd| {
        if (subcmd.hidden) continue;
        var found = false;
        for (groups[0..group_count]) |g| {
            if (std.mem.eql(u8, g, subcmd.group)) {
                found = true;
                break;
            }
        }
        if (!found and group_count < 32) {
            groups[group_count] = subcmd.group;
            group_count += 1;
        }
    }

    // Print commands by group
    for (groups[0..group_count]) |group_name| {
        if (group_name.len > 0) {
            if (use_color) {
                try w.print("\n\x1b[1m{s}:\x1b[0m\n", .{group_name});
            } else {
                try w.print("\n{s}:\n", .{group_name});
            }
        } else {
            try w.print("\n{s}:\n", .{template.commands_header});
        }

        for (cmd.subcommands) |subcmd| {
            if (subcmd.hidden) continue;
            if (!std.mem.eql(u8, subcmd.group, group_name)) continue;

            // Write indent
            var i: u8 = 0;
            while (i < template.indent) : (i += 1) {
                try w.writeAll(" ");
            }

            if (use_color) {
                try w.print("\x1b[36m{s}\x1b[0m", .{subcmd.name});
            } else {
                try w.print("{s}", .{subcmd.name});
            }

            // Padding to align descriptions
            const sub_name_len: usize = subcmd.name.len;
            const col_width: usize = @as(usize, template.name_column_width) - template.indent;
            const sub_min_len: usize = @min(sub_name_len, col_width);
            const sub_padding: usize = col_width - sub_min_len;
            var j: usize = 0;
            while (j < sub_padding) : (j += 1) {
                try w.writeAll(" ");
            }
            try w.print("{s}\n", .{subcmd.summary});
        }
    }
}

/// Print flags section
fn printSectionFlags(w: anytype, use_color: bool, cmd: *const Command, template: *const HelpTemplate) !void {
    if (cmd.flags.len == 0 and !template.show_global_flags) return;

    try w.print("\n{s}:\n", .{template.flags_header});

    // Global flags first (if enabled)
    if (template.show_global_flags) {
        try printFlagWithTemplate(w, use_color, template, &.{
            .name = "help",
            .short = 'h',
            .help = "Print help information",
            .ftype = .bool,
        });
        try printFlagWithTemplate(w, use_color, template, &.{
            .name = "version",
            .short = 'V',
            .help = "Print version information",
            .ftype = .bool,
        });
        try printFlagWithTemplate(w, use_color, template, &.{
            .name = "quiet",
            .short = 'q',
            .help = "Suppress non-essential output",
            .ftype = .bool,
        });
        try printFlagWithTemplate(w, use_color, template, &.{
            .name = "json",
            .short = null,
            .help = "Output in JSON format",
            .ftype = .bool,
        });
        try printFlagWithTemplate(w, use_color, template, &.{
            .name = "plain",
            .short = null,
            .help = "Output in plain text (no formatting)",
            .ftype = .bool,
        });
        try printFlagWithTemplate(w, use_color, template, &.{
            .name = "no-color",
            .short = null,
            .help = "Disable colored output",
            .ftype = .bool,
        });
        try printFlagWithTemplate(w, use_color, template, &.{
            .name = "dry-run",
            .short = 'n',
            .help = "Show what would be done without doing it",
            .ftype = .bool,
        });
        try printFlagWithTemplate(w, use_color, template, &.{
            .name = "no-input",
            .short = null,
            .help = "Disable interactive prompts",
            .ftype = .bool,
        });
    }

    // Command-specific flags
    for (cmd.flags) |*flag| {
        try printFlagWithTemplate(w, use_color, template, flag);
    }
}

/// Print a single flag with template settings
fn printFlagWithTemplate(w: anytype, use_color: bool, template: *const HelpTemplate, flag: *const FlagSpec) !void {
    // Write indent
    var i: u8 = 0;
    while (i < template.indent) : (i += 1) {
        try w.writeAll(" ");
    }

    // Short flag
    if (flag.short) |s| {
        if (use_color) {
            try w.print("\x1b[33m-{c}\x1b[0m, ", .{s});
        } else {
            try w.print("-{c}, ", .{s});
        }
    } else {
        try w.print("    ", .{});
    }

    // Long flag
    if (use_color) {
        try w.print("\x1b[33m--{s}\x1b[0m", .{flag.name});
    } else {
        try w.print("--{s}", .{flag.name});
    }

    // Padding
    const name_len: usize = flag.name.len;
    const col_width: usize = @as(usize, template.name_column_width) - template.indent - 6; // -6 for "  -X, "
    const min_len: usize = @min(name_len, col_width);
    const padding_amount: usize = if (col_width > min_len) col_width - min_len else 0;
    var j: usize = 0;
    while (j < padding_amount) : (j += 1) {
        try w.writeAll(" ");
    }

    // Help text
    try w.print("{s}", .{flag.help});

    // Default value
    if (flag.default_str) |def| {
        try w.print(" [default: {s}]", .{def});
    }

    // Required indicator
    if (flag.required) {
        if (use_color) {
            try w.print(" \x1b[31m(required)\x1b[0m", .{});
        } else {
            try w.print(" (required)", .{});
        }
    }

    // Deprecated indicator
    if (flag.is_deprecated) {
        if (use_color) {
            try w.print(" \x1b[33m(deprecated)\x1b[0m", .{});
        } else {
            try w.print(" (deprecated)", .{});
        }
    }

    // Environment variable indicator
    if (flag.env) |env_var| {
        if (use_color) {
            try w.print(" \x1b[36m[${s}]\x1b[0m", .{env_var});
        } else {
            try w.print(" [${s}]", .{env_var});
        }
    }

    try w.print("\n", .{});
}

/// Print footer section
fn printSectionFooter(w: anytype, cmd: *const Command, template: *const HelpTemplate) !void {
    if (!template.show_footer) return;

    if (template.footer_text) |footer| {
        try w.print("\n{s}\n", .{footer});
    } else {
        try w.print("\nFor full help: {s} --help\n", .{cmd.name});
    }
}

/// Print text-format help
fn printTextHelp(cmd: *const Command, ctx: *Context) !void {
    const w = ctx.stdout;
    const use_color = ctx.useColor();

    // Header
    if (use_color) {
        try w.print("\x1b[1m{s}\x1b[0m", .{cmd.name});
    } else {
        try w.print("{s}", .{cmd.name});
    }
    try w.print(" - {s}\n", .{cmd.summary});

    // Usage
    try w.print("\nUsage: {s} [flags]", .{cmd.name});
    if (cmd.hasSubcommands()) {
        try w.print(" <command> [args]", .{});
    }
    try w.print("\n", .{});

    // Examples (examples-first approach)
    if (cmd.examples.len > 0) {
        try w.print("\nExamples:\n", .{});
        for (cmd.examples) |example| {
            try w.print("  {s}\n", .{example});
        }
    }

    // Long help if available
    if (cmd.long_help.len > 0) {
        try w.print("\n{s}\n", .{cmd.long_help});
    }

    // Subcommands (grouped by group name)
    if (cmd.subcommands.len > 0) {
        // Collect unique groups
        var groups: [32][]const u8 = undefined;
        var group_count: usize = 0;

        // First pass: collect unique group names (empty string = ungrouped)
        for (cmd.subcommands) |subcmd| {
            if (subcmd.hidden) continue;
            var found = false;
            for (groups[0..group_count]) |g| {
                if (std.mem.eql(u8, g, subcmd.group)) {
                    found = true;
                    break;
                }
            }
            if (!found and group_count < 32) {
                groups[group_count] = subcmd.group;
                group_count += 1;
            }
        }

        // Print commands by group
        for (groups[0..group_count]) |group_name| {
            if (group_name.len > 0) {
                // Named group
                if (use_color) {
                    try w.print("\n\x1b[1m{s}:\x1b[0m\n", .{group_name});
                } else {
                    try w.print("\n{s}:\n", .{group_name});
                }
            } else {
                // Default "Commands" group for ungrouped commands
                try w.print("\nCommands:\n", .{});
            }

            for (cmd.subcommands) |subcmd| {
                if (subcmd.hidden) continue;
                if (!std.mem.eql(u8, subcmd.group, group_name)) continue;

                if (use_color) {
                    try w.print("  \x1b[36m{s}\x1b[0m", .{subcmd.name});
                } else {
                    try w.print("  {s}", .{subcmd.name});
                }
                // Padding
                const sub_name_len: usize = subcmd.name.len;
                const sub_min_len: usize = @min(sub_name_len, 18);
                const sub_padding: usize = 20 - sub_min_len;
                for (0..sub_padding) |_| {
                    try w.writeAll(" ");
                }
                try w.print("{s}\n", .{subcmd.summary});
            }
        }
    }

    // Flags
    if (cmd.flags.len > 0 or true) { // Always show global flags
        try w.print("\nFlags:\n", .{});

        // Global flags first
        try printFlag(w, use_color, &.{
            .name = "help",
            .short = 'h',
            .help = "Print help information",
            .ftype = .bool,
        });
        try printFlag(w, use_color, &.{
            .name = "version",
            .short = 'V',
            .help = "Print version information",
            .ftype = .bool,
        });
        try printFlag(w, use_color, &.{
            .name = "quiet",
            .short = 'q',
            .help = "Suppress non-essential output",
            .ftype = .bool,
        });
        try printFlag(w, use_color, &.{
            .name = "json",
            .short = null,
            .help = "Output in JSON format",
            .ftype = .bool,
        });
        try printFlag(w, use_color, &.{
            .name = "plain",
            .short = null,
            .help = "Output in plain text (no formatting)",
            .ftype = .bool,
        });
        try printFlag(w, use_color, &.{
            .name = "no-color",
            .short = null,
            .help = "Disable colored output",
            .ftype = .bool,
        });
        try printFlag(w, use_color, &.{
            .name = "dry-run",
            .short = 'n',
            .help = "Show what would be done without doing it",
            .ftype = .bool,
        });
        try printFlag(w, use_color, &.{
            .name = "no-input",
            .short = null,
            .help = "Disable interactive prompts",
            .ftype = .bool,
        });

        // Command-specific flags
        for (cmd.flags) |*flag| {
            try printFlag(w, use_color, flag);
        }
    }

    try w.print("\nFor full help: {s} --help\n", .{cmd.name});
}

fn printFlag(w: anytype, use_color: bool, flag: *const FlagSpec) !void {
    try w.print("  ", .{});

    // Short flag
    if (flag.short) |s| {
        if (use_color) {
            try w.print("\x1b[33m-{c}\x1b[0m, ", .{s});
        } else {
            try w.print("-{c}, ", .{s});
        }
    } else {
        try w.print("    ", .{});
    }

    // Long flag
    if (use_color) {
        try w.print("\x1b[33m--{s}\x1b[0m", .{flag.name});
    } else {
        try w.print("--{s}", .{flag.name});
    }

    // Padding
    const name_len: usize = flag.name.len;
    const min_len: usize = @min(name_len, 14);
    const padding: usize = 16 - min_len;
    for (0..padding) |_| {
        try w.writeAll(" ");
    }

    // Help text
    try w.print("{s}", .{flag.help});

    // Default value
    if (flag.default_str) |def| {
        try w.print(" [default: {s}]", .{def});
    }

    // Required indicator
    if (flag.required) {
        if (use_color) {
            try w.print(" \x1b[31m(required)\x1b[0m", .{});
        } else {
            try w.print(" (required)", .{});
        }
    }

    // Deprecated indicator
    if (flag.is_deprecated) {
        if (use_color) {
            try w.print(" \x1b[33m(deprecated)\x1b[0m", .{});
        } else {
            try w.print(" (deprecated)", .{});
        }
    }

    // Environment variable indicator
    if (flag.env) |env_var| {
        if (use_color) {
            try w.print(" \x1b[36m[$", .{});
            try w.print("{s}]\x1b[0m", .{env_var});
        } else {
            try w.print(" [${s}]", .{env_var});
        }
    }

    try w.print("\n", .{});
}

/// Print JSON-format help
fn printJsonHelp(cmd: *const Command, ctx: *Context) !void {
    const w = ctx.stdout;

    try w.print("{{", .{});
    try w.print("\"name\":\"{s}\",", .{cmd.name});
    try w.print("\"summary\":\"{s}\",", .{cmd.summary});
    try w.print("\"usage\":\"{s} [flags]", .{cmd.name});
    if (cmd.hasSubcommands()) {
        try w.print(" <command> [args]", .{});
    }
    try w.print("\",", .{});

    // Flags
    try w.print("\"flags\":[", .{});
    var first_flag = true;

    // Global flags
    for (command.global_flags) |*flag| {
        if (!first_flag) try w.print(",", .{});
        first_flag = false;
        try printJsonFlag(w, flag);
    }

    // Command flags
    for (cmd.flags) |*flag| {
        if (!first_flag) try w.print(",", .{});
        first_flag = false;
        try printJsonFlag(w, flag);
    }
    try w.print("],", .{});

    // Subcommands
    try w.print("\"subcommands\":[", .{});
    var first = true;
    for (cmd.subcommands) |subcmd| {
        if (subcmd.hidden) continue;
        if (!first) try w.print(",", .{});
        first = false;
        try w.print("{{\"name\":\"{s}\",\"summary\":\"{s}\"}}", .{ subcmd.name, subcmd.summary });
    }
    try w.print("]", .{});

    try w.print("}}\n", .{});
}

fn printJsonFlag(w: anytype, flag: *const FlagSpec) !void {
    try w.print("{{", .{});
    try w.print("\"name\":\"{s}\",", .{flag.name});
    if (flag.short) |s| {
        try w.print("\"short\":\"{c}\",", .{s});
    } else {
        try w.print("\"short\":null,", .{});
    }
    try w.print("\"type\":\"{s}\",", .{flag.ftype.format()});
    try w.print("\"required\":{},", .{flag.required});
    if (flag.env) |env_var| {
        try w.print("\"env\":\"{s}\"", .{env_var});
    } else {
        try w.print("\"env\":null", .{});
    }
    try w.print("}}", .{});
}

/// Generate man page in roff format
pub fn generateMan(cmd: *const Command, allocator: std.mem.Allocator) ![]const u8 {
    var list: std.ArrayList(u8) = .empty;
    const w = list.writer(allocator);

    try w.print(".TH {s} 1\n", .{cmd.name});
    try w.print(".SH NAME\n", .{});
    try w.print("{s} \\- {s}\n", .{ cmd.name, cmd.summary });

    try w.print(".SH SYNOPSIS\n", .{});
    try w.print(".B {s}\n", .{cmd.name});
    try w.print("[\\fIOPTIONS\\fR] ", .{});
    if (cmd.hasSubcommands()) {
        try w.print("<\\fICOMMAND\\fR> [\\fIARGS\\fR]", .{});
    }
    try w.print("\n", .{});

    if (cmd.long_help.len > 0) {
        try w.print(".SH DESCRIPTION\n", .{});
        try w.print("{s}\n", .{cmd.long_help});
    }

    if (cmd.examples.len > 0) {
        try w.print(".SH EXAMPLES\n", .{});
        for (cmd.examples) |example| {
            try w.print(".TP\n", .{});
            try w.print("\\fB{s}\\fR\n", .{example});
        }
    }

    try w.print(".SH OPTIONS\n", .{});
    for (cmd.flags) |*flag| {
        try w.print(".TP\n", .{});
        if (flag.short) |s| {
            try w.print("\\fB\\-{c}\\fR, ", .{s});
        }
        try w.print("\\fB\\-\\-{s}\\fR\n", .{flag.name});
        try w.print("{s}\n", .{flag.help});
    }

    if (cmd.subcommands.len > 0) {
        try w.print(".SH COMMANDS\n", .{});
        for (cmd.subcommands) |subcmd| {
            if (!subcmd.hidden) {
                try w.print(".TP\n", .{});
                try w.print("\\fB{s}\\fR\n", .{subcmd.name});
                try w.print("{s}\n", .{subcmd.summary});
            }
        }
    }

    try w.print(".SH AUTHOR\n", .{});
    try w.print("DevNW\n", .{});

    return list.toOwnedSlice(allocator);
}

/// Print version information
pub fn printVersion(cmd: *const Command, ctx: *Context) void {
    printVersionImpl(cmd, ctx) catch {};
}

fn printVersionImpl(cmd: *const Command, ctx: *Context) !void {
    const w = ctx.stdout;

    if (ctx.json) {
        try w.print("{{\"name\":\"{s}\",\"version\":\"{s}\"}}\n", .{
            cmd.name,
            if (cmd.version.len > 0) cmd.version else "0.0.0",
        });
    } else {
        try w.print("{s} ", .{cmd.name});
        if (cmd.version.len > 0) {
            try w.print("{s}\n", .{cmd.version});
        } else {
            try w.print("0.0.0\n", .{});
        }
    }
}

/// Generate Markdown documentation for a command tree
pub fn generateMarkdown(cmd: *const Command, allocator: std.mem.Allocator) ![]const u8 {
    var list: std.ArrayList(u8) = .empty;
    const w = list.writer(allocator);

    try generateMarkdownCommand(w, cmd, 1);

    return list.toOwnedSlice(allocator);
}

fn generateMarkdownCommand(w: anytype, cmd: *const Command, depth: usize) !void {
    // Header (depth determines heading level)
    for (0..depth) |_| {
        try w.writeAll("#");
    }
    try w.print(" {s}\n\n", .{cmd.name});

    // Summary
    try w.print("{s}\n\n", .{cmd.summary});

    // Synopsis
    try w.print("## Synopsis\n\n", .{});
    try w.print("```\n{s} [OPTIONS]", .{cmd.name});
    if (cmd.hasSubcommands()) {
        try w.print(" <COMMAND> [ARGS]", .{});
    }
    try w.print("\n```\n\n", .{});

    // Description
    if (cmd.long_help.len > 0) {
        try w.print("## Description\n\n", .{});
        try w.print("{s}\n\n", .{cmd.long_help});
    }

    // Examples
    if (cmd.examples.len > 0) {
        try w.print("## Examples\n\n", .{});
        for (cmd.examples) |example| {
            try w.print("```bash\n{s}\n```\n\n", .{example});
        }
    }

    // Options
    if (cmd.flags.len > 0) {
        try w.print("## Options\n\n", .{});
        try w.print("| Flag | Description | Default | Env Var |\n", .{});
        try w.print("|------|-------------|---------|--------|\n", .{});
        for (cmd.flags) |*flag| {
            try w.print("| ", .{});
            if (flag.short) |s| {
                try w.print("`-{c}`, ", .{s});
            }
            try w.print("`--{s}` | {s}", .{ flag.name, flag.help });
            if (flag.required) {
                try w.print(" **(required)**", .{});
            }
            try w.print(" | ", .{});
            if (flag.default_str) |def| {
                try w.print("`{s}`", .{def});
            } else {
                try w.print("-", .{});
            }
            try w.print(" | ", .{});
            if (flag.env) |env_var| {
                try w.print("`${s}`", .{env_var});
            } else {
                try w.print("-", .{});
            }
            try w.print(" |\n", .{});
        }
        try w.print("\n", .{});
    }

    // Subcommands
    if (cmd.subcommands.len > 0) {
        try w.print("## Commands\n\n", .{});

        // Collect unique groups
        var groups: [32][]const u8 = undefined;
        var group_count: usize = 0;

        for (cmd.subcommands) |subcmd| {
            if (subcmd.hidden) continue;
            var found = false;
            for (groups[0..group_count]) |g| {
                if (mem.eql(u8, g, subcmd.group)) {
                    found = true;
                    break;
                }
            }
            if (!found and group_count < 32) {
                groups[group_count] = subcmd.group;
                group_count += 1;
            }
        }

        // Print commands by group
        for (groups[0..group_count]) |group_name| {
            if (group_name.len > 0) {
                try w.print("### {s}\n\n", .{group_name});
            }

            try w.print("| Command | Description |\n", .{});
            try w.print("|---------|-------------|\n", .{});

            for (cmd.subcommands) |subcmd| {
                if (subcmd.hidden) continue;
                if (!mem.eql(u8, subcmd.group, group_name)) continue;
                try w.print("| `{s}` | {s} |\n", .{ subcmd.name, subcmd.summary });
            }
            try w.print("\n", .{});
        }

        // Recursively generate docs for subcommands
        try w.print("---\n\n", .{});
        for (cmd.subcommands) |subcmd| {
            if (!subcmd.hidden) {
                try generateMarkdownCommand(w, subcmd, depth + 1);
            }
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

test "generateMan" {
    const cmd = Command{
        .name = "test",
        .summary = "Test command",
        .long_help = "This is a test command.",
        .examples = &.{"test --help"},
    };

    const man = try generateMan(&cmd, std.testing.allocator);
    defer std.testing.allocator.free(man);

    try std.testing.expect(mem.indexOf(u8, man, ".TH test 1") != null);
    try std.testing.expect(mem.indexOf(u8, man, "Test command") != null);
}

test "help: generateMan with name section" {
    const cmd = Command{
        .name = "myapp",
        .summary = "My application",
    };

    const man = try generateMan(&cmd, std.testing.allocator);
    defer std.testing.allocator.free(man);

    try std.testing.expect(mem.indexOf(u8, man, ".TH myapp 1") != null);
    try std.testing.expect(mem.indexOf(u8, man, ".SH NAME") != null);
    try std.testing.expect(mem.indexOf(u8, man, "myapp \\- My application") != null);
}

test "help: generateMan with synopsis" {
    const cmd = Command{
        .name = "myapp",
        .summary = "My application",
    };

    const man = try generateMan(&cmd, std.testing.allocator);
    defer std.testing.allocator.free(man);

    try std.testing.expect(mem.indexOf(u8, man, ".SH SYNOPSIS") != null);
    try std.testing.expect(mem.indexOf(u8, man, ".B myapp") != null);
    try std.testing.expect(mem.indexOf(u8, man, "[\\fIOPTIONS\\fR]") != null);
}

test "help: generateMan with subcommands" {
    const subcmd1 = Command{
        .name = "start",
        .summary = "Start the service",
    };
    const subcmd2 = Command{
        .name = "stop",
        .summary = "Stop the service",
    };
    const cmd = Command{
        .name = "myapp",
        .summary = "My application",
        .subcommands = &.{ &subcmd1, &subcmd2 },
    };

    const man = try generateMan(&cmd, std.testing.allocator);
    defer std.testing.allocator.free(man);

    try std.testing.expect(mem.indexOf(u8, man, ".SH COMMANDS") != null);
    try std.testing.expect(mem.indexOf(u8, man, "\\fBstart\\fR") != null);
    try std.testing.expect(mem.indexOf(u8, man, "\\fBstop\\fR") != null);
    try std.testing.expect(mem.indexOf(u8, man, "Start the service") != null);
    try std.testing.expect(mem.indexOf(u8, man, "Stop the service") != null);
}

test "help: generateMan with hidden subcommands" {
    const subcmd1 = Command{
        .name = "visible",
        .summary = "Visible command",
    };
    const subcmd2 = Command{
        .name = "hidden",
        .summary = "Hidden command",
        .hidden = true,
    };
    const cmd = Command{
        .name = "myapp",
        .summary = "My application",
        .subcommands = &.{ &subcmd1, &subcmd2 },
    };

    const man = try generateMan(&cmd, std.testing.allocator);
    defer std.testing.allocator.free(man);

    try std.testing.expect(mem.indexOf(u8, man, "visible") != null);
    try std.testing.expect(mem.indexOf(u8, man, "hidden") == null);
}

test "help: generateMan with flags" {
    const cmd = Command{
        .name = "myapp",
        .summary = "My application",
        .flags = &.{
            FlagSpec{
                .name = "output",
                .short = 'o',
                .help = "Output file path",
                .ftype = .path,
            },
            FlagSpec{
                .name = "verbose",
                .help = "Enable verbose output",
                .ftype = .bool,
            },
        },
    };

    const man = try generateMan(&cmd, std.testing.allocator);
    defer std.testing.allocator.free(man);

    try std.testing.expect(mem.indexOf(u8, man, ".SH OPTIONS") != null);
    try std.testing.expect(mem.indexOf(u8, man, "\\fB\\-o\\fR") != null);
    try std.testing.expect(mem.indexOf(u8, man, "\\fB\\-\\-output\\fR") != null);
    try std.testing.expect(mem.indexOf(u8, man, "\\fB\\-\\-verbose\\fR") != null);
    try std.testing.expect(mem.indexOf(u8, man, "Output file path") != null);
}

test "help: generateMan with examples" {
    const cmd = Command{
        .name = "myapp",
        .summary = "My application",
        .examples = &.{
            "myapp start --config app.toml",
            "myapp stop --force",
            "myapp status",
        },
    };

    const man = try generateMan(&cmd, std.testing.allocator);
    defer std.testing.allocator.free(man);

    try std.testing.expect(mem.indexOf(u8, man, ".SH EXAMPLES") != null);
    try std.testing.expect(mem.indexOf(u8, man, "myapp start --config app.toml") != null);
    try std.testing.expect(mem.indexOf(u8, man, "myapp stop --force") != null);
    try std.testing.expect(mem.indexOf(u8, man, "myapp status") != null);
}

test "help: generateMan with description" {
    const cmd = Command{
        .name = "myapp",
        .summary = "My application",
        .long_help = "This is a detailed description of the application.\nIt spans multiple lines.",
    };

    const man = try generateMan(&cmd, std.testing.allocator);
    defer std.testing.allocator.free(man);

    try std.testing.expect(mem.indexOf(u8, man, ".SH DESCRIPTION") != null);
    try std.testing.expect(mem.indexOf(u8, man, "This is a detailed description") != null);
}

test "help: generateMan includes author section" {
    const cmd = Command{
        .name = "myapp",
        .summary = "My application",
    };

    const man = try generateMan(&cmd, std.testing.allocator);
    defer std.testing.allocator.free(man);

    try std.testing.expect(mem.indexOf(u8, man, ".SH AUTHOR") != null);
    try std.testing.expect(mem.indexOf(u8, man, "DevNW") != null);
}

test "help: generateMan with subcommands shows COMMAND in synopsis" {
    const subcmd = Command{
        .name = "run",
        .summary = "Run command",
    };
    const cmd = Command{
        .name = "myapp",
        .summary = "My application",
        .subcommands = &.{&subcmd},
    };

    const man = try generateMan(&cmd, std.testing.allocator);
    defer std.testing.allocator.free(man);

    try std.testing.expect(mem.indexOf(u8, man, "<\\fICOMMAND\\fR>") != null);
    try std.testing.expect(mem.indexOf(u8, man, "[\\fIARGS\\fR]") != null);
}

test "help: generateMan complete real-world example" {
    const subcmd1 = Command{
        .name = "serve",
        .summary = "Start the HTTP server",
    };
    const subcmd2 = Command{
        .name = "build",
        .summary = "Build the project",
    };
    const cmd = Command{
        .name = "webapp",
        .summary = "Web application toolkit",
        .long_help = "A comprehensive toolkit for building and deploying web applications.",
        .examples = &.{
            "webapp serve --port 8080",
            "webapp build --release",
        },
        .subcommands = &.{ &subcmd1, &subcmd2 },
        .flags = &.{
            FlagSpec{
                .name = "config",
                .short = 'c',
                .help = "Configuration file",
                .ftype = .path,
            },
        },
    };

    const man = try generateMan(&cmd, std.testing.allocator);
    defer std.testing.allocator.free(man);

    // Check all major sections
    try std.testing.expect(mem.indexOf(u8, man, ".TH webapp 1") != null);
    try std.testing.expect(mem.indexOf(u8, man, ".SH NAME") != null);
    try std.testing.expect(mem.indexOf(u8, man, ".SH SYNOPSIS") != null);
    try std.testing.expect(mem.indexOf(u8, man, ".SH DESCRIPTION") != null);
    try std.testing.expect(mem.indexOf(u8, man, ".SH EXAMPLES") != null);
    try std.testing.expect(mem.indexOf(u8, man, ".SH OPTIONS") != null);
    try std.testing.expect(mem.indexOf(u8, man, ".SH COMMANDS") != null);
    try std.testing.expect(mem.indexOf(u8, man, ".SH AUTHOR") != null);
}

// ============================================================================
// Markdown Generation Tests
// ============================================================================

test "help: generateMarkdown basic" {
    const cmd = Command{
        .name = "myapp",
        .summary = "My application",
    };

    const md = try generateMarkdown(&cmd, std.testing.allocator);
    defer std.testing.allocator.free(md);

    try std.testing.expect(mem.indexOf(u8, md, "# myapp") != null);
    try std.testing.expect(mem.indexOf(u8, md, "My application") != null);
    try std.testing.expect(mem.indexOf(u8, md, "## Synopsis") != null);
}

test "help: generateMarkdown with description" {
    const cmd = Command{
        .name = "myapp",
        .summary = "My application",
        .long_help = "This is a detailed description.",
    };

    const md = try generateMarkdown(&cmd, std.testing.allocator);
    defer std.testing.allocator.free(md);

    try std.testing.expect(mem.indexOf(u8, md, "## Description") != null);
    try std.testing.expect(mem.indexOf(u8, md, "This is a detailed description") != null);
}

test "help: generateMarkdown with examples" {
    const cmd = Command{
        .name = "myapp",
        .summary = "My application",
        .examples = &.{
            "myapp start",
            "myapp stop",
        },
    };

    const md = try generateMarkdown(&cmd, std.testing.allocator);
    defer std.testing.allocator.free(md);

    try std.testing.expect(mem.indexOf(u8, md, "## Examples") != null);
    try std.testing.expect(mem.indexOf(u8, md, "```bash") != null);
    try std.testing.expect(mem.indexOf(u8, md, "myapp start") != null);
    try std.testing.expect(mem.indexOf(u8, md, "myapp stop") != null);
}

test "help: generateMarkdown with options table" {
    const cmd = Command{
        .name = "myapp",
        .summary = "My application",
        .flags = &.{
            FlagSpec{
                .name = "config",
                .short = 'c',
                .help = "Config file",
                .ftype = .path,
            },
            FlagSpec{
                .name = "verbose",
                .help = "Verbose output",
                .ftype = .bool,
                .required = true,
            },
        },
    };

    const md = try generateMarkdown(&cmd, std.testing.allocator);
    defer std.testing.allocator.free(md);

    try std.testing.expect(mem.indexOf(u8, md, "## Options") != null);
    try std.testing.expect(mem.indexOf(u8, md, "| Flag | Description | Default |") != null);
    try std.testing.expect(mem.indexOf(u8, md, "`-c`") != null);
    try std.testing.expect(mem.indexOf(u8, md, "`--config`") != null);
    try std.testing.expect(mem.indexOf(u8, md, "**(required)**") != null);
}

test "help: generateMarkdown with subcommands" {
    const subcmd1 = Command{
        .name = "start",
        .summary = "Start the service",
    };
    const subcmd2 = Command{
        .name = "stop",
        .summary = "Stop the service",
    };
    const cmd = Command{
        .name = "service",
        .summary = "Service manager",
        .subcommands = &.{ &subcmd1, &subcmd2 },
    };

    const md = try generateMarkdown(&cmd, std.testing.allocator);
    defer std.testing.allocator.free(md);

    try std.testing.expect(mem.indexOf(u8, md, "## Commands") != null);
    try std.testing.expect(mem.indexOf(u8, md, "| Command | Description |") != null);
    try std.testing.expect(mem.indexOf(u8, md, "| `start` | Start the service |") != null);
    try std.testing.expect(mem.indexOf(u8, md, "| `stop` | Stop the service |") != null);
    // Subcommand sections
    try std.testing.expect(mem.indexOf(u8, md, "## start") != null);
    try std.testing.expect(mem.indexOf(u8, md, "## stop") != null);
}

test "help: generateMarkdown with command groups" {
    const subcmd1 = Command{
        .name = "start",
        .summary = "Start the service",
        .group = "Lifecycle",
    };
    const subcmd2 = Command{
        .name = "stop",
        .summary = "Stop the service",
        .group = "Lifecycle",
    };
    const subcmd3 = Command{
        .name = "logs",
        .summary = "View logs",
        .group = "Debugging",
    };
    const cmd = Command{
        .name = "service",
        .summary = "Service manager",
        .subcommands = &.{ &subcmd1, &subcmd2, &subcmd3 },
    };

    const md = try generateMarkdown(&cmd, std.testing.allocator);
    defer std.testing.allocator.free(md);

    try std.testing.expect(mem.indexOf(u8, md, "### Lifecycle") != null);
    try std.testing.expect(mem.indexOf(u8, md, "### Debugging") != null);
}

test "help: generateMarkdown hides hidden commands" {
    const subcmd1 = Command{
        .name = "visible",
        .summary = "Visible command",
    };
    const subcmd2 = Command{
        .name = "hidden",
        .summary = "Hidden command",
        .hidden = true,
    };
    const cmd = Command{
        .name = "myapp",
        .summary = "My application",
        .subcommands = &.{ &subcmd1, &subcmd2 },
    };

    const md = try generateMarkdown(&cmd, std.testing.allocator);
    defer std.testing.allocator.free(md);

    try std.testing.expect(mem.indexOf(u8, md, "| `visible`") != null);
    try std.testing.expect(mem.indexOf(u8, md, "| `hidden`") == null);
}

// ============================================================================
// Command Groups Tests (in help output)
// ============================================================================

test "help: command groups ordering" {
    const subcmd1 = Command{
        .name = "build",
        .summary = "Build project",
        .group = "Development",
    };
    const subcmd2 = Command{
        .name = "test",
        .summary = "Run tests",
        .group = "Development",
    };
    const subcmd3 = Command{
        .name = "deploy",
        .summary = "Deploy to production",
        .group = "Operations",
    };
    const subcmd4 = Command{
        .name = "version",
        .summary = "Show version",
    };
    const cmd = Command{
        .name = "app",
        .summary = "Application toolkit",
        .subcommands = &.{ &subcmd1, &subcmd2, &subcmd3, &subcmd4 },
    };

    const md = try generateMarkdown(&cmd, std.testing.allocator);
    defer std.testing.allocator.free(md);

    // Check groups are present
    try std.testing.expect(mem.indexOf(u8, md, "### Development") != null);
    try std.testing.expect(mem.indexOf(u8, md, "### Operations") != null);
    // Ungrouped commands should not have a group header
    try std.testing.expect(mem.indexOf(u8, md, "| `version`") != null);
}

// ============================================================================
// Environment Variable Documentation Tests
// ============================================================================

test "help: generateMarkdown with env vars" {
    const cmd = Command{
        .name = "myapp",
        .summary = "My application",
        .flags = &.{
            FlagSpec{
                .name = "config",
                .help = "Config file",
                .ftype = .path,
                .env = "MYAPP_CONFIG",
            },
            FlagSpec{
                .name = "verbose",
                .help = "Verbose output",
                .ftype = .bool,
            },
        },
    };

    const md = try generateMarkdown(&cmd, std.testing.allocator);
    defer std.testing.allocator.free(md);

    // Should have Env Var column
    try std.testing.expect(mem.indexOf(u8, md, "| Env Var |") != null);
    // Should show env var for config
    try std.testing.expect(mem.indexOf(u8, md, "`$MYAPP_CONFIG`") != null);
}

test "help: env vars shown with dash when not set" {
    const cmd = Command{
        .name = "myapp",
        .summary = "My application",
        .flags = &.{
            FlagSpec{
                .name = "verbose",
                .help = "Verbose output",
                .ftype = .bool,
            },
        },
    };

    const md = try generateMarkdown(&cmd, std.testing.allocator);
    defer std.testing.allocator.free(md);

    // Count occurrences of " - |" (dash in last column)
    var count: usize = 0;
    var i: usize = 0;
    while (i < md.len - 3) : (i += 1) {
        if (mem.eql(u8, md[i .. i + 4], " - |")) {
            count += 1;
        }
    }
    // Should have at least one flag with no env var
    try std.testing.expect(count >= 1);
}

// ============================================================================
// HelpTemplate Tests
// ============================================================================

test "help: HelpTemplate presets exist" {
    // Test that all preset templates are accessible
    const default_t = HelpTemplate.default;
    const minimal_t = HelpTemplate.minimal;
    const verbose_t = HelpTemplate.verbose;
    const manpage_t = HelpTemplate.manpage;

    // Default template has all sections
    try std.testing.expectEqual(@as(usize, 7), default_t.sections.len);

    // Minimal template has fewer sections
    try std.testing.expectEqual(@as(usize, 2), minimal_t.sections.len);
    try std.testing.expect(!minimal_t.show_global_flags);
    try std.testing.expect(!minimal_t.show_footer);

    // Verbose template has uppercase headers
    try std.testing.expect(mem.eql(u8, verbose_t.usage_header, "USAGE"));
    try std.testing.expect(mem.eql(u8, verbose_t.examples_header, "EXAMPLES"));

    // Manpage template uses SYNOPSIS instead of Usage
    try std.testing.expect(mem.eql(u8, manpage_t.usage_header, "SYNOPSIS"));
    try std.testing.expect(mem.eql(u8, manpage_t.description_header, "DESCRIPTION"));
}

test "help: HelpTemplate custom section order" {
    // Test that we can create a custom template with different section order
    const custom = HelpTemplate{
        .sections = &.{ .usage, .flags, .examples }, // Different order
        .show_footer = false,
    };

    try std.testing.expectEqual(@as(usize, 3), custom.sections.len);
    try std.testing.expectEqual(HelpSection.usage, custom.sections[0]);
    try std.testing.expectEqual(HelpSection.flags, custom.sections[1]);
    try std.testing.expectEqual(HelpSection.examples, custom.sections[2]);
}

test "help: HelpTemplate custom headers" {
    const custom = HelpTemplate{
        .usage_header = "HOW TO USE",
        .examples_header = "SAMPLE USAGE",
        .commands_header = "SUBCOMMANDS",
        .flags_header = "OPTIONS",
    };

    try std.testing.expect(mem.eql(u8, custom.usage_header, "HOW TO USE"));
    try std.testing.expect(mem.eql(u8, custom.examples_header, "SAMPLE USAGE"));
    try std.testing.expect(mem.eql(u8, custom.commands_header, "SUBCOMMANDS"));
    try std.testing.expect(mem.eql(u8, custom.flags_header, "OPTIONS"));
}

test "help: HelpTemplate custom footer" {
    const custom = HelpTemplate{
        .footer_text = "Visit https://example.com for more info",
    };

    try std.testing.expect(custom.footer_text != null);
    try std.testing.expect(mem.eql(u8, custom.footer_text.?, "Visit https://example.com for more info"));
}

test "help: HelpTemplate formatting options" {
    const custom = HelpTemplate{
        .indent = 4,
        .name_column_width = 30,
    };

    try std.testing.expectEqual(@as(u8, 4), custom.indent);
    try std.testing.expectEqual(@as(u8, 30), custom.name_column_width);
}

test "help: HelpSection enum values" {
    // Ensure all section types exist
    try std.testing.expectEqual(@as(u3, 0), @intFromEnum(HelpSection.header));
    try std.testing.expectEqual(@as(u3, 1), @intFromEnum(HelpSection.usage));
    try std.testing.expectEqual(@as(u3, 2), @intFromEnum(HelpSection.examples));
    try std.testing.expectEqual(@as(u3, 3), @intFromEnum(HelpSection.description));
    try std.testing.expectEqual(@as(u3, 4), @intFromEnum(HelpSection.commands));
    try std.testing.expectEqual(@as(u3, 5), @intFromEnum(HelpSection.flags));
    try std.testing.expectEqual(@as(u3, 6), @intFromEnum(HelpSection.footer));
}
