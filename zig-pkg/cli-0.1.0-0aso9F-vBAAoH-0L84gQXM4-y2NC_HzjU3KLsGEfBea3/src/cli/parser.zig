// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Parser Module
//!
//! Command-line argument parser with support for flags, subcommands,
//! and positional arguments. Implements order-independent parsing.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const command = @import("command.zig");
const Command = command.Command;
const Context = command.Context;
const FlagSpec = command.FlagSpec;
const FlagValue = command.FlagValue;
const FlagType = command.FlagType;
const SecretPolicy = command.SecretPolicy;
const FlagGroup = command.FlagGroup;
const FlagGroupType = command.FlagGroupType;
const ArgsValidator = command.ArgsValidator;
const ArgsValidationError = command.ArgsValidationError;
const ArgsErrorDetails = command.ArgsErrorDetails;

/// Parse errors
pub const ParseError = error{
    UnknownFlag,
    UnknownCommand,
    MissingValue,
    InvalidValue,
    MissingRequired,
    SecretInFlagOrEnv,
    HelpRequested,
    VersionRequested,
    OutOfMemory,
    MutuallyExclusiveFlags,
    RequiredTogetherFlags,
    OneRequiredFlags,
    InvalidArgs,
};

/// Parse result
pub const ParseResult = struct {
    /// The resolved command to execute
    command: *const Command,
    /// Execution context with parsed values
    context: Context,
    /// Whether help was requested
    help_requested: bool = false,
    /// Whether version was requested
    version_requested: bool = false,
    /// Chain of commands from root to current (for persistent hooks)
    command_chain: std.ArrayList(*const Command),

    /// Clean up all allocated resources
    pub fn deinit(self: *ParseResult, allocator: Allocator) void {
        self.command_chain.deinit(allocator);
        self.context.deinit();
    }
};

/// Argument parser
pub const Parser = struct {
    allocator: Allocator,
    root: *const Command,
    version: []const u8,
    env_prefix: []const u8,
    /// Name of missing required flag (for error reporting)
    missing_required_flag: ?[]const u8 = null,
    /// Current command being parsed (for error reporting)
    current_command: ?*const Command = null,
    /// Conflicting flags for mutually exclusive error
    conflicting_flags: ?[2][]const u8 = null,
    /// Missing flags for required together error
    missing_together_flags: ?[]const []const u8 = null,
    /// Group name for one required error
    one_required_group: ?[]const []const u8 = null,
    /// Args validation error details
    args_error: ?ArgsErrorDetails = null,

    const Self = @This();

    /// Initialize a new parser
    pub fn init(
        allocator: Allocator,
        root: *const Command,
        version: []const u8,
        env_prefix: []const u8,
    ) Self {
        return .{
            .allocator = allocator,
            .root = root,
            .version = version,
            .env_prefix = env_prefix,
        };
    }

    /// Parse command-line arguments
    pub fn parse(self: *Self, argv: []const []const u8) ParseError!ParseResult {
        var ctx = Context.init(self.allocator);
        ctx.env_prefix = self.env_prefix;

        // Track command chain for persistent hooks
        var command_chain: std.ArrayList(*const Command) = .empty;
        errdefer command_chain.deinit(self.allocator);
        command_chain.append(self.allocator, self.root) catch return ParseError.OutOfMemory;

        // Apply environment-based defaults
        self.applyEnvDefaults(&ctx);

        var current_cmd = self.root;
        self.current_command = self.root;
        var i: usize = 0;

        // Skip program name
        if (argv.len > 0) {
            i = 1;
        }

        while (i < argv.len) {
            const arg = argv[i];

            if (mem.startsWith(u8, arg, "--")) {
                // Long flag
                const flag_part = arg[2..];

                // Handle -- (end of flags)
                if (flag_part.len == 0) {
                    i += 1;
                    // Rest are positionals
                    while (i < argv.len) : (i += 1) {
                        ctx.positionals.append(ctx.allocator, argv[i]) catch return ParseError.OutOfMemory;
                    }
                    break;
                }

                // Check for --flag=value format
                if (mem.indexOf(u8, flag_part, "=")) |eq_pos| {
                    const name = flag_part[0..eq_pos];
                    const value = flag_part[eq_pos + 1 ..];
                    try self.handleFlag(&ctx, current_cmd, name, value);
                } else {
                    // Check if it's a boolean flag or needs a value
                    if (self.findFlagInChain(current_cmd, flag_part)) |flag| {
                        if (flag.ftype == .bool) {
                            try self.handleFlag(&ctx, current_cmd, flag_part, "true");
                        } else {
                            // Need next arg as value
                            i += 1;
                            if (i >= argv.len) {
                                return ParseError.MissingValue;
                            }
                            try self.handleFlag(&ctx, current_cmd, flag_part, argv[i]);
                        }
                    } else {
                        // Check global flags
                        if (mem.eql(u8, flag_part, "help")) {
                            return ParseResult{
                                .command = current_cmd,
                                .context = ctx,
                                .help_requested = true,
                                .command_chain = command_chain,
                            };
                        } else if (mem.eql(u8, flag_part, "version")) {
                            return ParseResult{
                                .command = current_cmd,
                                .context = ctx,
                                .version_requested = true,
                                .command_chain = command_chain,
                            };
                        }

                        // Handle other global flags
                        try self.handleGlobalFlag(&ctx, flag_part, if (i + 1 < argv.len) argv[i + 1] else null);
                    }
                }
            } else if (mem.startsWith(u8, arg, "-") and arg.len > 1) {
                // Short flags
                const flags = arg[1..];
                for (flags, 0..) |c, j| {
                    if (c == 'h') {
                        return ParseResult{
                            .command = current_cmd,
                            .context = ctx,
                            .help_requested = true,
                            .command_chain = command_chain,
                        };
                    } else if (c == 'V') {
                        return ParseResult{
                            .command = current_cmd,
                            .context = ctx,
                            .version_requested = true,
                            .command_chain = command_chain,
                        };
                    }

                    if (self.findFlagByShortInChain(current_cmd, c)) |flag| {
                        if (flag.ftype == .bool) {
                            try self.setFlagValue(&ctx, flag.name, FlagValue{ .bool = true });
                        } else if (j == flags.len - 1) {
                            // Last short flag, next arg is value
                            i += 1;
                            if (i >= argv.len) {
                                return ParseError.MissingValue;
                            }
                            try self.handleFlag(&ctx, current_cmd, flag.name, argv[i]);
                        }
                    } else {
                        try self.handleGlobalShortFlag(&ctx, c);
                    }
                }
            } else if (arg[0] == '-' and arg.len == 1) {
                // Single dash means stdin/stdout
                ctx.positionals.append(ctx.allocator, arg) catch return ParseError.OutOfMemory;
            } else {
                // Subcommand or positional
                if (current_cmd.findSubcommand(arg)) |subcmd| {
                    current_cmd = subcmd;
                    self.current_command = subcmd;
                    ctx.command_path.append(ctx.allocator, arg) catch return ParseError.OutOfMemory;
                    // Track command chain for persistent hooks
                    command_chain.append(self.allocator, subcmd) catch return ParseError.OutOfMemory;
                } else {
                    ctx.positionals.append(ctx.allocator, arg) catch return ParseError.OutOfMemory;
                }
            }

            i += 1;
        }

        // Check for required flags
        self.applyDefaultValues(&ctx, current_cmd);
        try self.checkRequired(&ctx, current_cmd);

        // Check flag groups
        try self.checkFlagGroups(&ctx, current_cmd);

        // Check positional argument validation
        try self.checkArgs(&ctx, current_cmd);

        return ParseResult{
            .command = current_cmd,
            .context = ctx,
            .command_chain = command_chain,
        };
    }

    fn handleFlag(
        self: *Self,
        ctx: *Context,
        cmd: *const Command,
        name: []const u8,
        value: []const u8,
    ) ParseError!void {
        // Find the flag spec
        if (self.findFlagInChain(cmd, name)) |flag| {
            // Check secret policy
            if (flag.secret == .from_file_or_stdin) {
                return ParseError.SecretInFlagOrEnv;
            }

            // Validate if needed
            if (!flag.validate(value)) {
                return ParseError.InvalidValue;
            }

            // Handle string arrays specially - they can be appended to
            if (flag.ftype == .string_array) {
                try self.appendToStringArray(ctx, name, value);
            } else {
                // Parse and set value
                const fval = try self.parseValue(flag.ftype, value);
                try self.setFlagValue(ctx, name, fval);
            }
        } else {
            return ParseError.UnknownFlag;
        }
    }

    fn handleGlobalFlag(self: *Self, ctx: *Context, name: []const u8, next_arg: ?[]const u8) ParseError!void {
        _ = self;
        if (mem.eql(u8, name, "quiet")) {
            ctx.quiet = true;
        } else if (mem.eql(u8, name, "json")) {
            ctx.json = true;
        } else if (mem.eql(u8, name, "plain")) {
            ctx.plain = true;
        } else if (mem.eql(u8, name, "no-color")) {
            ctx.no_color = true;
        } else if (mem.eql(u8, name, "dry-run")) {
            ctx.dry_run = true;
        } else if (mem.eql(u8, name, "no-input")) {
            ctx.no_input = true;
        } else {
            _ = next_arg;
            return ParseError.UnknownFlag;
        }
    }

    fn handleGlobalShortFlag(self: *Self, ctx: *Context, c: u8) ParseError!void {
        _ = self;
        switch (c) {
            'q' => ctx.quiet = true,
            'n' => ctx.dry_run = true,
            else => return ParseError.UnknownFlag,
        }
    }

    fn parseValue(self: *Self, ftype: FlagType, value: []const u8) ParseError!FlagValue {
        return switch (ftype) {
            .bool => FlagValue{ .bool = mem.eql(u8, value, "true") or mem.eql(u8, value, "1") },
            .int => FlagValue{ .int = std.fmt.parseInt(i64, value, 10) catch return ParseError.InvalidValue },
            .float => FlagValue{ .float = std.fmt.parseFloat(f64, value) catch return ParseError.InvalidValue },
            .string, .path => FlagValue{ .string = value },
            .string_array => blk: {
                // Create a new ArrayList and add the value
                var arr: std.ArrayList([]const u8) = .empty;
                // Handle comma-separated values
                var iter = mem.splitSequence(u8, value, ",");
                while (iter.next()) |item| {
                    const trimmed = mem.trim(u8, item, " \t");
                    if (trimmed.len > 0) {
                        arr.append(self.allocator, trimmed) catch return ParseError.OutOfMemory;
                    }
                }
                break :blk FlagValue{ .string_array = arr };
            },
        };
    }

    fn appendToStringArray(self: *Self, ctx: *Context, name: []const u8, value: []const u8) ParseError!void {
        if (ctx.flags.getPtr(name)) |existing| {
            switch (existing.*) {
                .string_array => |*arr| {
                    // Handle comma-separated values
                    var iter = mem.splitSequence(u8, value, ",");
                    while (iter.next()) |item| {
                        const trimmed = mem.trim(u8, item, " \t");
                        if (trimmed.len > 0) {
                            arr.append(self.allocator, trimmed) catch return ParseError.OutOfMemory;
                        }
                    }
                },
                else => {
                    // Shouldn't happen - type mismatch
                    return ParseError.InvalidValue;
                },
            }
        } else {
            // First occurrence, create new array
            const fval = try self.parseValue(.string_array, value);
            try self.setFlagValue(ctx, name, fval);
        }
    }

    fn setFlagValue(self: *Self, ctx: *Context, name: []const u8, value: FlagValue) ParseError!void {
        _ = self;
        ctx.flags.put(name, value) catch return ParseError.OutOfMemory;
    }

    fn findFlagInChain(self: *Self, cmd: *const Command, name: []const u8) ?*const FlagSpec {
        // Check command flags first
        if (cmd.findFlag(name)) |f| return f;

        // Check root command flags
        if (cmd != self.root) {
            if (self.root.findFlag(name)) |f| return f;
        }

        return null;
    }

    fn findFlagByShortInChain(self: *Self, cmd: *const Command, short: u8) ?*const FlagSpec {
        // Check command flags first
        if (cmd.findFlagByShort(short)) |f| return f;

        // Check root command flags
        if (cmd != self.root) {
            if (self.root.findFlagByShort(short)) |f| return f;
        }

        return null;
    }

    fn applyEnvDefaults(self: *Self, ctx: *Context) void {
        // Check NO_COLOR
        if (std.posix.getenv("NO_COLOR")) |_| {
            ctx.no_color = true;
        }

        // Check TERM=dumb
        if (std.posix.getenv("TERM")) |term| {
            if (mem.eql(u8, term, "dumb")) {
                ctx.no_color = true;
            }
        }

        // Apply environment variable flags
        for (self.root.flags) |flag| {
            if (flag.env) |env_name| {
                // Check if secret - skip env for secrets
                if (flag.secret == .from_file_or_stdin) continue;

                if (std.posix.getenv(env_name)) |value| {
                    const fval = self.parseValue(flag.ftype, value) catch continue;
                    self.setFlagValue(ctx, flag.name, fval) catch {};
                }
            }
        }
    }

    fn applyDefaultValues(self: *Self, ctx: *Context, cmd: *const Command) void {
        self.applyDefaultsForCommand(ctx, self.root);
        if (cmd != self.root) {
            self.applyDefaultsForCommand(ctx, cmd);
        }
    }

    fn applyDefaultsForCommand(self: *Self, ctx: *Context, cmd: *const Command) void {
        for (cmd.flags) |flag| {
            if (flag.default_str) |def| {
                if (ctx.getFlag(flag.name) != null) continue;
                const fval = self.parseValue(flag.ftype, def) catch continue;
                self.setFlagValue(ctx, flag.name, fval) catch {};
            }
        }
    }

    fn checkRequired(self: *Self, ctx: *Context, cmd: *const Command) ParseError!void {
        for (cmd.flags) |flag| {
            if (flag.required) {
                if (ctx.getFlag(flag.name) == null) {
                    // Store the missing flag name for better error reporting
                    self.missing_required_flag = flag.name;
                    return ParseError.MissingRequired;
                }
            }
        }
    }

    /// Check flag group constraints
    fn checkFlagGroups(self: *Self, ctx: *Context, cmd: *const Command) ParseError!void {
        for (cmd.flag_groups) |group| {
            switch (group.group_type) {
                .mutually_exclusive => {
                    // Check that at most one flag in the group is set
                    var set_count: usize = 0;
                    var first_set: ?[]const u8 = null;
                    var second_set: ?[]const u8 = null;
                    for (group.flags) |flag_name| {
                        if (ctx.getFlag(flag_name) != null) {
                            set_count += 1;
                            if (first_set == null) {
                                first_set = flag_name;
                            } else if (second_set == null) {
                                second_set = flag_name;
                            }
                        }
                    }
                    if (set_count > 1) {
                        if (first_set != null and second_set != null) {
                            self.conflicting_flags = .{ first_set.?, second_set.? };
                        }
                        return ParseError.MutuallyExclusiveFlags;
                    }
                },
                .required_together => {
                    // Check that either all or none are set
                    var any_set = false;
                    var all_set = true;
                    for (group.flags) |flag_name| {
                        if (ctx.getFlag(flag_name) != null) {
                            any_set = true;
                        } else {
                            all_set = false;
                        }
                    }
                    if (any_set and !all_set) {
                        self.missing_together_flags = group.flags;
                        return ParseError.RequiredTogetherFlags;
                    }
                },
                .one_required => {
                    // Check that at least one flag in the group is set
                    var any_set = false;
                    for (group.flags) |flag_name| {
                        if (ctx.getFlag(flag_name) != null) {
                            any_set = true;
                            break;
                        }
                    }
                    if (!any_set) {
                        self.one_required_group = group.flags;
                        return ParseError.OneRequiredFlags;
                    }
                },
            }
        }
    }

    /// Check positional argument constraints
    fn checkArgs(self: *Self, ctx: *Context, cmd: *const Command) ParseError!void {
        if (cmd.args) |args_validator| {
            args_validator.validate(ctx.positionals.items) catch {
                // Get error details for better error messages
                self.args_error = args_validator.getErrorDetails(ctx.positionals.items);
                return ParseError.InvalidArgs;
            };
        }
    }
};

/// Run a command with the given arguments
pub fn run(root: *const Command, argv: []const []const u8, allocator: Allocator) !u8 {
    var parser = Parser.init(allocator, root, "0.0.0", "");

    const result = parser.parse(argv) catch |err| {
        const stderr = std.fs.File.stderr().deprecatedWriter();
        switch (err) {
            ParseError.UnknownFlag => try stderr.print("Error: Unknown flag\n\n", .{}),
            ParseError.UnknownCommand => try stderr.print("Error: Unknown command\n\n", .{}),
            ParseError.MissingValue => try stderr.print("Error: Missing value for flag\n\n", .{}),
            ParseError.InvalidValue => try stderr.print("Error: Invalid value\n\n", .{}),
            ParseError.MissingRequired => {
                if (parser.missing_required_flag) |flag_name| {
                    try stderr.print("Error: Missing required flag --{s}\n\n", .{flag_name});
                } else {
                    try stderr.print("Error: Missing required flag\n\n", .{});
                }
            },
            ParseError.SecretInFlagOrEnv => {
                try stderr.print("Refusing secret in flags/env. Provide --<name>-file <path> or pipe via stdin.\n\n", .{});
            },
            ParseError.MutuallyExclusiveFlags => {
                if (parser.conflicting_flags) |flags| {
                    try stderr.print("Error: Flags --{s} and --{s} are mutually exclusive\n\n", .{ flags[0], flags[1] });
                } else {
                    try stderr.print("Error: Mutually exclusive flags specified\n\n", .{});
                }
            },
            ParseError.RequiredTogetherFlags => {
                if (parser.missing_together_flags) |flags| {
                    try stderr.print("Error: Flags must be used together: ", .{});
                    for (flags, 0..) |f, i| {
                        if (i > 0) try stderr.print(", ", .{});
                        try stderr.print("--{s}", .{f});
                    }
                    try stderr.print("\n\n", .{});
                } else {
                    try stderr.print("Error: Required flags must be used together\n\n", .{});
                }
            },
            ParseError.OneRequiredFlags => {
                if (parser.one_required_group) |flags| {
                    try stderr.print("Error: At least one of these flags is required: ", .{});
                    for (flags, 0..) |f, i| {
                        if (i > 0) try stderr.print(", ", .{});
                        try stderr.print("--{s}", .{f});
                    }
                    try stderr.print("\n\n", .{});
                } else {
                    try stderr.print("Error: At least one flag from group is required\n\n", .{});
                }
            },
            ParseError.InvalidArgs => {
                if (parser.args_error) |args_err| {
                    var buf: [256]u8 = undefined;
                    const msg = args_err.format(&buf);
                    try stderr.print("Error: {s}\n\n", .{msg});
                } else {
                    try stderr.print("Error: Invalid positional arguments\n\n", .{});
                }
            },
            else => try stderr.print("Error: Parse error\n\n", .{}),
        }

        // Show help for the current command on error
        if (parser.current_command) |cmd| {
            const help = @import("help.zig");
            var ctx = Context.init(allocator);
            defer ctx.deinit();
            help.printHelp(cmd, &ctx);
        }

        return 2;
    };

    if (result.help_requested) {
        const help = @import("help.zig");
        var ctx = result.context;
        help.printHelp(result.command, &ctx);
        return 0;
    }

    if (result.version_requested) {
        try result.context.stdout.print("0.0.0\n", .{});
        return 0;
    }

    // Execute the command
    const cmd = result.command;
    var ctx = result.context;
    const command_chain = result.command_chain.items;

    // Execute persistent pre-run hooks from root to current (in order)
    for (command_chain) |parent_cmd| {
        if (parent_cmd.persistent_pre_run) |persistent_pre| {
            persistent_pre(&ctx) catch |err| {
                try ctx.stderr.print("Error in persistent pre-run: {}\n", .{err});
                return 1;
            };
        }
    }

    // Pre-run hook (only for current command)
    if (cmd.pre_run) |pre| {
        pre(&ctx) catch |err| {
            try ctx.stderr.print("Error in pre-run: {}\n", .{err});
            return 1;
        };
    }

    // Main run
    if (cmd.run) |run_fn| {
        run_fn(&ctx) catch |err| {
            try ctx.stderr.print("Error: {}\n", .{err});
            return 1;
        };
    } else if (cmd.hasSubcommands()) {
        // No run function but has subcommands - show help
        const help = @import("help.zig");
        help.printHelp(cmd, &ctx);
        return 0;
    }

    // Post-run hook (only for current command)
    if (cmd.post_run) |post| {
        post(&ctx) catch |err| {
            try ctx.stderr.print("Error in post-run: {}\n", .{err});
            return 1;
        };
    }

    // Execute persistent post-run hooks from current to root (reverse order)
    var i: usize = command_chain.len;
    while (i > 0) {
        i -= 1;
        if (command_chain[i].persistent_post_run) |persistent_post| {
            persistent_post(&ctx) catch |err| {
                try ctx.stderr.print("Error in persistent post-run: {}\n", .{err});
                return 1;
            };
        }
    }

    return 0;
}

// ============================================================================
// Tests
// ============================================================================

test "Parser initialization" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
    };

    const parser = Parser.init(std.testing.allocator, &root, "1.0.0", "TEST_");
    try std.testing.expectEqualStrings("1.0.0", parser.version);
    try std.testing.expectEqualStrings("TEST_", parser.env_prefix);
}

test "Parse long flag with value" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
        .flags = &.{
            FlagSpec{
                .name = "config",
                .help = "Config file",
                .ftype = .string,
            },
        },
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{ "test", "--config", "test.toml" });
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(result.context.getString("config") != null);
}

test "Parse boolean flag" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
        .flags = &.{
            FlagSpec{
                .name = "verbose",
                .short = 'v',
                .help = "Verbose output",
                .ftype = .bool,
            },
        },
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{ "test", "-v" });
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(result.context.getBool("verbose"));
}

test "parser: help flag returns help_requested" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{ "test", "--help" });
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(result.help_requested);
}

test "parser: short help flag returns help_requested" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{ "test", "-h" });
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(result.help_requested);
}

test "parser: version flag returns version_requested" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{ "test", "--version" });
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(result.version_requested);
}

test "parser: short version flag returns version_requested" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{ "test", "-V" });
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(result.version_requested);
}

test "parser: flag with equals syntax" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
        .flags = &.{
            FlagSpec{
                .name = "config",
                .help = "Config file",
                .ftype = .string,
            },
        },
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{ "test", "--config=test.toml" });
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("test.toml", result.context.getString("config").?);
}

test "parser: integer flag" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
        .flags = &.{
            FlagSpec{
                .name = "port",
                .help = "Port number",
                .ftype = .int,
            },
        },
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{ "test", "--port", "8080" });
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(i64, 8080), result.context.getInt("port").?);
}

test "parser: float flag" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
        .flags = &.{
            FlagSpec{
                .name = "rate",
                .help = "Rate value",
                .ftype = .float,
            },
        },
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{ "test", "--rate", "3.14" });
    defer result.deinit(std.testing.allocator);

    // Float is stored in FlagValue, verify it was parsed
    const flag_val = result.context.getFlag("rate");
    try std.testing.expect(flag_val != null);
}

test "parser: subcommand parsing" {
    const subcmd = Command{
        .name = "run",
        .summary = "Run command",
    };
    const root = Command{
        .name = "test",
        .summary = "Test command",
        .subcommands = &.{&subcmd},
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{ "test", "run" });
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("run", result.command.name);
}

test "parser: positional arguments" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{ "test", "arg1", "arg2", "arg3" });
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 3), result.context.positionals.items.len);
    try std.testing.expectEqualStrings("arg1", result.context.positionals.items[0]);
    try std.testing.expectEqualStrings("arg2", result.context.positionals.items[1]);
    try std.testing.expectEqualStrings("arg3", result.context.positionals.items[2]);
}

test "parser: double dash ends flags" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{ "test", "--", "--not-a-flag", "-x" });
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), result.context.positionals.items.len);
    try std.testing.expectEqualStrings("--not-a-flag", result.context.positionals.items[0]);
    try std.testing.expectEqualStrings("-x", result.context.positionals.items[1]);
}

test "parser: global flags quiet" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{ "test", "--quiet" });
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(result.context.quiet);
}

test "parser: global flags short quiet" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{ "test", "-q" });
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(result.context.quiet);
}

test "parser: global flags json" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{ "test", "--json" });
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(result.context.json);
}

test "parser: global flags plain" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{ "test", "--plain" });
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(result.context.plain);
}

test "parser: global flags no-color" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{ "test", "--no-color" });
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(result.context.no_color);
}

test "parser: global flags dry-run" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{ "test", "--dry-run" });
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(result.context.dry_run);
}

test "parser: global flags no-input" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{ "test", "--no-input" });
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(result.context.no_input);
}

test "parser: unknown flag returns error" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    const result = parser.parse(&.{ "test", "--unknown" });

    try std.testing.expectError(ParseError.UnknownFlag, result);
}

test "parser: missing value returns error" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
        .flags = &.{
            FlagSpec{
                .name = "config",
                .help = "Config file",
                .ftype = .string,
            },
        },
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    const result = parser.parse(&.{ "test", "--config" });

    try std.testing.expectError(ParseError.MissingValue, result);
}

test "parser: invalid integer returns error" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
        .flags = &.{
            FlagSpec{
                .name = "port",
                .help = "Port number",
                .ftype = .int,
            },
        },
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    const result = parser.parse(&.{ "test", "--port", "not-a-number" });

    try std.testing.expectError(ParseError.InvalidValue, result);
}

test "parser: missing required flag returns error" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
        .flags = &.{
            FlagSpec{
                .name = "required-flag",
                .help = "Required flag",
                .ftype = .string,
                .required = true,
            },
        },
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    const result = parser.parse(&.{"test"});

    try std.testing.expectError(ParseError.MissingRequired, result);
}

test "parser: multiple short flags combined" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{ "test", "-qn" });
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(result.context.quiet);
    try std.testing.expect(result.context.dry_run);
}

test "parser: single dash as positional" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{ "test", "-" });
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), result.context.positionals.items.len);
    try std.testing.expectEqualStrings("-", result.context.positionals.items[0]);
}

test "parser: empty args" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{});
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("test", result.command.name);
}

test "parser: string array flag single value" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
        .flags = &.{
            FlagSpec{
                .name = "include",
                .help = "Include paths",
                .ftype = .string_array,
            },
        },
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{ "test", "--include", "foo" });
    defer result.deinit(std.testing.allocator);

    const arr = result.context.getStringArray("include");
    try std.testing.expect(arr != null);
    try std.testing.expectEqual(@as(usize, 1), arr.?.len);
    try std.testing.expectEqualStrings("foo", arr.?[0]);
}

test "parser: string array flag multiple values" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
        .flags = &.{
            FlagSpec{
                .name = "include",
                .help = "Include paths",
                .ftype = .string_array,
            },
        },
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{ "test", "--include", "foo", "--include", "bar", "--include", "baz" });
    defer result.deinit(std.testing.allocator);

    const arr = result.context.getStringArray("include");
    try std.testing.expect(arr != null);
    try std.testing.expectEqual(@as(usize, 3), arr.?.len);
    try std.testing.expectEqualStrings("foo", arr.?[0]);
    try std.testing.expectEqualStrings("bar", arr.?[1]);
    try std.testing.expectEqualStrings("baz", arr.?[2]);
}

test "parser: string array flag comma-separated" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
        .flags = &.{
            FlagSpec{
                .name = "include",
                .help = "Include paths",
                .ftype = .string_array,
            },
        },
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{ "test", "--include", "foo,bar,baz" });
    defer result.deinit(std.testing.allocator);

    const arr = result.context.getStringArray("include");
    try std.testing.expect(arr != null);
    try std.testing.expectEqual(@as(usize, 3), arr.?.len);
    try std.testing.expectEqualStrings("foo", arr.?[0]);
    try std.testing.expectEqualStrings("bar", arr.?[1]);
    try std.testing.expectEqualStrings("baz", arr.?[2]);
}

test "parser: string array flag mixed repeated and comma" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
        .flags = &.{
            FlagSpec{
                .name = "include",
                .help = "Include paths",
                .ftype = .string_array,
            },
        },
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{ "test", "--include", "a,b", "--include", "c" });
    defer result.deinit(std.testing.allocator);

    const arr = result.context.getStringArray("include");
    try std.testing.expect(arr != null);
    try std.testing.expectEqual(@as(usize, 3), arr.?.len);
    try std.testing.expectEqualStrings("a", arr.?[0]);
    try std.testing.expectEqualStrings("b", arr.?[1]);
    try std.testing.expectEqualStrings("c", arr.?[2]);
}

test "parser: string array flag with equals syntax" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
        .flags = &.{
            FlagSpec{
                .name = "include",
                .help = "Include paths",
                .ftype = .string_array,
            },
        },
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{ "test", "--include=foo,bar" });
    defer result.deinit(std.testing.allocator);

    const arr = result.context.getStringArray("include");
    try std.testing.expect(arr != null);
    try std.testing.expectEqual(@as(usize, 2), arr.?.len);
    try std.testing.expectEqualStrings("foo", arr.?[0]);
    try std.testing.expectEqualStrings("bar", arr.?[1]);
}

// ============================================================================
// Flag Group Tests
// ============================================================================

test "parser: mutually exclusive flags - valid (one set)" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
        .flags = &.{
            FlagSpec{ .name = "json", .help = "JSON output", .ftype = .bool },
            FlagSpec{ .name = "yaml", .help = "YAML output", .ftype = .bool },
        },
        .flag_groups = &.{
            FlagGroup{ .group_type = .mutually_exclusive, .flags = &.{ "json", "yaml" } },
        },
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{ "test", "--json" });
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(result.context.getBool("json"));
}

test "parser: mutually exclusive flags - error (both set)" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
        .flags = &.{
            FlagSpec{ .name = "json", .help = "JSON output", .ftype = .bool },
            FlagSpec{ .name = "yaml", .help = "YAML output", .ftype = .bool },
        },
        .flag_groups = &.{
            FlagGroup{ .group_type = .mutually_exclusive, .flags = &.{ "json", "yaml" } },
        },
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    const result = parser.parse(&.{ "test", "--json", "--yaml" });

    try std.testing.expectError(ParseError.MutuallyExclusiveFlags, result);
}

test "parser: required together flags - valid (all set)" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
        .flags = &.{
            FlagSpec{ .name = "username", .help = "Username", .ftype = .string },
            FlagSpec{ .name = "password", .help = "Password", .ftype = .string },
        },
        .flag_groups = &.{
            FlagGroup{ .group_type = .required_together, .flags = &.{ "username", "password" } },
        },
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{ "test", "--username", "user", "--password", "pass" });
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("user", result.context.getString("username").?);
    try std.testing.expectEqualStrings("pass", result.context.getString("password").?);
}

test "parser: required together flags - error (only one set)" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
        .flags = &.{
            FlagSpec{ .name = "username", .help = "Username", .ftype = .string },
            FlagSpec{ .name = "password", .help = "Password", .ftype = .string },
        },
        .flag_groups = &.{
            FlagGroup{ .group_type = .required_together, .flags = &.{ "username", "password" } },
        },
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    const result = parser.parse(&.{ "test", "--username", "user" });

    try std.testing.expectError(ParseError.RequiredTogetherFlags, result);
}

test "parser: one required flags - valid (one set)" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
        .flags = &.{
            FlagSpec{ .name = "token", .help = "Auth token", .ftype = .string },
            FlagSpec{ .name = "username", .help = "Username", .ftype = .string },
        },
        .flag_groups = &.{
            FlagGroup{ .group_type = .one_required, .flags = &.{ "token", "username" } },
        },
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{ "test", "--token", "abc123" });
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("abc123", result.context.getString("token").?);
}

test "parser: one required flags - error (none set)" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
        .flags = &.{
            FlagSpec{ .name = "token", .help = "Auth token", .ftype = .string },
            FlagSpec{ .name = "username", .help = "Username", .ftype = .string },
        },
        .flag_groups = &.{
            FlagGroup{ .group_type = .one_required, .flags = &.{ "token", "username" } },
        },
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    const result = parser.parse(&.{"test"});

    try std.testing.expectError(ParseError.OneRequiredFlags, result);
}

// ============================================================================
// Argument Validator Tests
// ============================================================================

test "parser: args validator - exact args valid" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
        .args = .{ .exact = 2 },
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{ "test", "arg1", "arg2" });
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), result.context.positionals.items.len);
}

test "parser: args validator - exact args error" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
        .args = .{ .exact = 2 },
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    const result = parser.parse(&.{ "test", "arg1" });

    try std.testing.expectError(ParseError.InvalidArgs, result);
}

test "parser: args validator - no args valid" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
        .args = .{ .none = {} },
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{"test"});
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 0), result.context.positionals.items.len);
}

test "parser: args validator - no args error" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
        .args = .{ .none = {} },
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    const result = parser.parse(&.{ "test", "unexpected" });

    try std.testing.expectError(ParseError.InvalidArgs, result);
}

test "parser: args validator - minimum args valid" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
        .args = .{ .minimum = 2 },
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{ "test", "arg1", "arg2", "arg3" });
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 3), result.context.positionals.items.len);
}

test "parser: args validator - minimum args error" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
        .args = .{ .minimum = 2 },
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    const result = parser.parse(&.{ "test", "arg1" });

    try std.testing.expectError(ParseError.InvalidArgs, result);
}

test "parser: args validator - maximum args valid" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
        .args = .{ .maximum = 2 },
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{ "test", "arg1" });
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), result.context.positionals.items.len);
}

test "parser: args validator - maximum args error" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
        .args = .{ .maximum = 2 },
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    const result = parser.parse(&.{ "test", "arg1", "arg2", "arg3" });

    try std.testing.expectError(ParseError.InvalidArgs, result);
}

test "parser: args validator - range valid" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
        .args = .{ .range = .{ .min = 1, .max = 3 } },
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{ "test", "arg1", "arg2" });
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), result.context.positionals.items.len);
}

test "parser: args validator - range error too few" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
        .args = .{ .range = .{ .min = 2, .max = 4 } },
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    const result = parser.parse(&.{ "test", "arg1" });

    try std.testing.expectError(ParseError.InvalidArgs, result);
}

test "parser: args validator - only valid values" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
        .args = .{ .only_valid = &.{ "start", "stop", "restart" } },
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{ "test", "start" });
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("start", result.context.positionals.items[0]);
}

test "parser: args validator - only valid values error" {
    const root = Command{
        .name = "test",
        .summary = "Test command",
        .args = .{ .only_valid = &.{ "start", "stop", "restart" } },
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    const result = parser.parse(&.{ "test", "invalid" });

    try std.testing.expectError(ParseError.InvalidArgs, result);
}

// ============================================================================
// Command Chain Tests (for persistent hooks)
// ============================================================================

test "parser: command chain includes root" {
    const root = Command{
        .name = "root",
        .summary = "Root command",
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{"root"});
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), result.command_chain.items.len);
    try std.testing.expectEqualStrings("root", result.command_chain.items[0].name);
}

test "parser: command chain includes subcommand" {
    const subcmd = Command{
        .name = "sub",
        .summary = "Subcommand",
    };
    const root = Command{
        .name = "root",
        .summary = "Root command",
        .subcommands = &.{&subcmd},
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{ "root", "sub" });
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), result.command_chain.items.len);
    try std.testing.expectEqualStrings("root", result.command_chain.items[0].name);
    try std.testing.expectEqualStrings("sub", result.command_chain.items[1].name);
}

test "parser: command chain includes nested subcommands" {
    const leaf = Command{
        .name = "leaf",
        .summary = "Leaf command",
    };
    const middle = Command{
        .name = "middle",
        .summary = "Middle command",
        .subcommands = &.{&leaf},
    };
    const root = Command{
        .name = "root",
        .summary = "Root command",
        .subcommands = &.{&middle},
    };

    var parser = Parser.init(std.testing.allocator, &root, "1.0.0", "");
    var result = try parser.parse(&.{ "root", "middle", "leaf" });
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 3), result.command_chain.items.len);
    try std.testing.expectEqualStrings("root", result.command_chain.items[0].name);
    try std.testing.expectEqualStrings("middle", result.command_chain.items[1].name);
    try std.testing.expectEqualStrings("leaf", result.command_chain.items[2].name);
}
