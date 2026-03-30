// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Command Module
//!
//! Core command tree definition for building CLI applications with
//! nested subcommands, flags, and lifecycle hooks.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Flag value types
pub const FlagType = enum {
    bool,
    int,
    float,
    string,
    path,
    string_array,

    pub fn format(self: FlagType) []const u8 {
        return switch (self) {
            .bool => "bool",
            .int => "int",
            .float => "float",
            .string => "string",
            .path => "path",
            .string_array => "string_array",
        };
    }
};

/// Secret handling policy
pub const SecretPolicy = enum {
    /// Not a secret, can be passed via flags/env
    none,
    /// Must be provided via file or stdin, not flags/env
    from_file_or_stdin,
};

/// Flag specification for command-line arguments
pub const FlagSpec = struct {
    /// Long flag name (e.g., "verbose" for --verbose)
    name: []const u8,
    /// Short flag character (e.g., 'v' for -v)
    short: ?u8 = null,
    /// Help text for this flag
    help: []const u8,
    /// The type of value this flag accepts
    ftype: FlagType,
    /// Whether this flag is required
    required: bool = false,
    /// Default value as string (will be parsed)
    default_str: ?[]const u8 = null,
    /// Environment variable name for this flag
    env: ?[]const u8 = null,
    /// Whether this flag can be specified multiple times
    is_repeatable: bool = false,
    /// Whether this flag is deprecated
    is_deprecated: bool = false,
    /// Secret handling policy
    secret: SecretPolicy = .none,
    /// Custom validator function
    validator: ?*const fn ([]const u8) bool = null,
    /// Static completion values for shell completion
    completions: []const []const u8 = &.{},
    /// Dynamic completion function for shell completion
    complete_fn: ?*const fn ([]const u8) []const []const u8 = null,

    /// Get the display name for help text
    pub fn displayName(self: *const FlagSpec) []const u8 {
        return self.name;
    }

    /// Check if a value is valid for this flag
    pub fn validate(self: *const FlagSpec, value: []const u8) bool {
        if (self.validator) |v| {
            return v(value);
        }
        return true;
    }
};

/// Command execution context
pub const Context = struct {
    /// Memory allocator
    allocator: Allocator,
    /// Standard output writer
    stdout: std.fs.File.DeprecatedWriter,
    /// Standard error writer
    stderr: std.fs.File.DeprecatedWriter,
    /// Whether stdout is a TTY
    is_tty_out: bool,
    /// Whether stderr is a TTY
    is_tty_err: bool,
    /// Quiet mode (-q/--quiet)
    quiet: bool = false,
    /// JSON output mode (--json)
    json: bool = false,
    /// Plain output mode (--plain)
    plain: bool = false,
    /// Disable color output (--no-color or NO_COLOR env)
    no_color: bool = false,
    /// Dry run mode (-n/--dry-run)
    dry_run: bool = false,
    /// Non-interactive mode (--no-input)
    no_input: bool = false,
    /// Environment variable prefix for config
    env_prefix: []const u8 = "",
    /// Parsed flag values
    flags: std.StringHashMap(FlagValue),
    /// Positional arguments
    positionals: std.ArrayList([]const u8),
    /// The command path (e.g., ["kv", "get"])
    command_path: std.ArrayList([]const u8),

    /// Initialize a new context
    pub fn init(allocator: Allocator) Context {
        const stdout_file = std.fs.File.stdout();
        const stderr_file = std.fs.File.stderr();
        return .{
            .allocator = allocator,
            .stdout = stdout_file.deprecatedWriter(),
            .stderr = stderr_file.deprecatedWriter(),
            .is_tty_out = stdout_file.isTty(),
            .is_tty_err = stderr_file.isTty(),
            .flags = std.StringHashMap(FlagValue).init(allocator),
            .positionals = .empty,
            .command_path = .empty,
        };
    }

    /// Deinitialize the context
    pub fn deinit(self: *Context) void {
        // Clean up any string_array flag values
        var iter = self.flags.valueIterator();
        while (iter.next()) |val| {
            switch (val.*) {
                .string_array => |*arr| arr.deinit(self.allocator),
                else => {},
            }
        }
        self.flags.deinit();
        self.positionals.deinit(self.allocator);
        self.command_path.deinit(self.allocator);
    }

    /// Get a flag value by name
    pub fn getFlag(self: *const Context, name: []const u8) ?FlagValue {
        return self.flags.get(name);
    }

    /// Get a string flag value
    pub fn getString(self: *const Context, name: []const u8) ?[]const u8 {
        if (self.getFlag(name)) |v| {
            return switch (v) {
                .string => |s| s,
                else => null,
            };
        }
        return null;
    }

    /// Get a boolean flag value
    pub fn getBool(self: *const Context, name: []const u8) bool {
        if (self.getFlag(name)) |v| {
            return switch (v) {
                .bool => |b| b,
                else => false,
            };
        }
        return false;
    }

    /// Get an integer flag value
    pub fn getInt(self: *const Context, name: []const u8) ?i64 {
        if (self.getFlag(name)) |v| {
            return switch (v) {
                .int => |i| i,
                else => null,
            };
        }
        return null;
    }

    /// Get a string array flag value
    pub fn getStringArray(self: *const Context, name: []const u8) ?[]const []const u8 {
        if (self.getFlag(name)) |v| {
            return switch (v) {
                .string_array => |arr| arr.items,
                else => null,
            };
        }
        return null;
    }

    /// Write to stdout (respects quiet mode)
    pub fn print(self: *Context, comptime fmt: []const u8, args: anytype) !void {
        if (!self.quiet) {
            try self.stdout.print(fmt, args);
        }
    }

    /// Write to stderr (always writes, for errors/warnings)
    pub fn err(self: *Context, comptime fmt: []const u8, args: anytype) !void {
        try self.stderr.print(fmt, args);
    }

    /// Check if color should be used
    pub fn useColor(self: *const Context) bool {
        if (self.no_color or self.plain) return false;
        if (!self.is_tty_out) return false;

        // Check TERM=dumb
        if (std.posix.getenv("TERM")) |term| {
            if (std.mem.eql(u8, term, "dumb")) return false;
        }

        // Check NO_COLOR environment variable
        if (std.posix.getenv("NO_COLOR")) |_| {
            return false;
        }

        return true;
    }
};

/// Parsed flag value
pub const FlagValue = union(enum) {
    bool: bool,
    int: i64,
    float: f64,
    string: []const u8,
    string_array: std.ArrayList([]const u8),

    /// Deinitialize array-based flag values
    pub fn deinit(self: *FlagValue, allocator: Allocator) void {
        switch (self.*) {
            .string_array => |*arr| arr.deinit(),
            else => {},
        }
        _ = allocator;
    }
};

/// Command pre/post run hook type
pub const HookFn = *const fn (*Context) anyerror!void;

/// Command run function type
pub const RunFn = *const fn (*Context) anyerror!void;

/// Flag group type for validation
pub const FlagGroupType = enum {
    /// Flags that cannot be used together
    mutually_exclusive,
    /// Flags that must all be used together if any is used
    required_together,
    /// At least one flag from the group must be provided
    one_required,
};

/// Flag group definition
pub const FlagGroup = struct {
    /// Type of validation for this group
    group_type: FlagGroupType,
    /// Names of flags in this group
    flags: []const []const u8,
};

/// Argument validation error type
pub const ArgsValidationError = error{
    NoArgsExpected,
    ExactArgsMismatch,
    TooFewArgs,
    TooManyArgs,
    RangeArgsMismatch,
    InvalidArg,
};

/// Argument validation error details (for error messages)
pub const ArgsErrorDetails = union(enum) {
    no_args_expected: usize,
    exact_args: struct { expected: usize, got: usize },
    minimum_args: struct { min: usize, got: usize },
    maximum_args: struct { max: usize, got: usize },
    range_args: struct { min: usize, max: usize, got: usize },
    invalid_arg: []const u8,

    pub fn format(self: ArgsErrorDetails, buf: []u8) []const u8 {
        return switch (self) {
            .no_args_expected => |n| std.fmt.bufPrint(buf, "expected no arguments, got {d}", .{n}) catch "no arguments expected",
            .exact_args => |e| std.fmt.bufPrint(buf, "expected exactly {d} argument(s), got {d}", .{ e.expected, e.got }) catch "wrong argument count",
            .minimum_args => |m| std.fmt.bufPrint(buf, "expected at least {d} argument(s), got {d}", .{ m.min, m.got }) catch "too few arguments",
            .maximum_args => |m| std.fmt.bufPrint(buf, "expected at most {d} argument(s), got {d}", .{ m.max, m.got }) catch "too many arguments",
            .range_args => |r| std.fmt.bufPrint(buf, "expected {d}-{d} arguments, got {d}", .{ r.min, r.max, r.got }) catch "wrong argument count",
            .invalid_arg => |a| std.fmt.bufPrint(buf, "invalid argument: '{s}'", .{a}) catch "invalid argument",
        };
    }
};

/// Positional argument validation rules
pub const ArgsValidator = union(enum) {
    /// No positional arguments allowed
    none: void,
    /// Any number of arguments (no validation)
    arbitrary: void,
    /// Exactly N arguments required
    exact: usize,
    /// At least N arguments required
    minimum: usize,
    /// At most N arguments allowed
    maximum: usize,
    /// Between min and max arguments (inclusive)
    range: struct {
        min: usize,
        max: usize,
    },
    /// Only values from a predefined list
    only_valid: []const []const u8,

    /// Validate the given positional arguments
    pub fn validate(self: ArgsValidator, args: []const []const u8) ArgsValidationError!void {
        switch (self) {
            .none => {
                if (args.len > 0) {
                    return ArgsValidationError.NoArgsExpected;
                }
            },
            .arbitrary => {},
            .exact => |n| {
                if (args.len != n) {
                    return ArgsValidationError.ExactArgsMismatch;
                }
            },
            .minimum => |n| {
                if (args.len < n) {
                    return ArgsValidationError.TooFewArgs;
                }
            },
            .maximum => |n| {
                if (args.len > n) {
                    return ArgsValidationError.TooManyArgs;
                }
            },
            .range => |r| {
                if (args.len < r.min or args.len > r.max) {
                    return ArgsValidationError.RangeArgsMismatch;
                }
            },
            .only_valid => |valid_args| {
                for (args) |arg| {
                    var found = false;
                    for (valid_args) |valid| {
                        if (std.mem.eql(u8, arg, valid)) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        return ArgsValidationError.InvalidArg;
                    }
                }
            },
        }
    }

    /// Get error details for a validation failure
    pub fn getErrorDetails(self: ArgsValidator, args: []const []const u8) ?ArgsErrorDetails {
        switch (self) {
            .none => {
                if (args.len > 0) {
                    return ArgsErrorDetails{ .no_args_expected = args.len };
                }
            },
            .arbitrary => {},
            .exact => |n| {
                if (args.len != n) {
                    return ArgsErrorDetails{ .exact_args = .{ .expected = n, .got = args.len } };
                }
            },
            .minimum => |n| {
                if (args.len < n) {
                    return ArgsErrorDetails{ .minimum_args = .{ .min = n, .got = args.len } };
                }
            },
            .maximum => |n| {
                if (args.len > n) {
                    return ArgsErrorDetails{ .maximum_args = .{ .max = n, .got = args.len } };
                }
            },
            .range => |r| {
                if (args.len < r.min or args.len > r.max) {
                    return ArgsErrorDetails{ .range_args = .{ .min = r.min, .max = r.max, .got = args.len } };
                }
            },
            .only_valid => |valid_args| {
                for (args) |arg| {
                    var found = false;
                    for (valid_args) |valid| {
                        if (std.mem.eql(u8, arg, valid)) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        return ArgsErrorDetails{ .invalid_arg = arg };
                    }
                }
            },
        }
        return null;
    }
};

/// Command definition
pub const Command = struct {
    /// Command name
    name: []const u8,
    /// Short summary for help (one line)
    summary: []const u8,
    /// Long help text (multiple paragraphs)
    long_help: []const u8 = "",
    /// Usage examples
    examples: []const []const u8 = &.{},
    /// Flag specifications
    flags: []const FlagSpec = &.{},
    /// Pre-run hook (runs only for this command)
    pre_run: ?HookFn = null,
    /// Main run function
    run: ?RunFn = null,
    /// Post-run hook (runs only for this command)
    post_run: ?HookFn = null,
    /// Persistent pre-run hook (runs for this command AND all subcommands)
    persistent_pre_run: ?HookFn = null,
    /// Persistent post-run hook (runs for this command AND all subcommands)
    persistent_post_run: ?HookFn = null,
    /// Command aliases
    aliases: []const []const u8 = &.{},
    /// Whether this command is hidden from help
    hidden: bool = false,
    /// Deprecation message (null if not deprecated)
    deprecated: ?[]const u8 = null,
    /// Subcommands
    subcommands: []const *const Command = &.{},
    /// Flag groups for validation (mutually exclusive, required together, etc.)
    flag_groups: []const FlagGroup = &.{},
    /// Positional argument validation rules
    args: ?ArgsValidator = null,
    /// Group name for organizing commands in help output
    group: []const u8 = "",
    /// Version string (e.g., "1.0.0")
    version: []const u8 = "",
    /// Active help messages for shell completion (displayed as hints during completion)
    /// These messages help guide users when typing commands
    active_help: []const []const u8 = &.{},
    /// Dynamic active help function - called during completion to generate contextual hints
    /// Return messages to display, or empty slice for no active help
    active_help_fn: ?*const fn (*const Command, []const []const u8) []const []const u8 = null,

    /// Find a subcommand by name or alias
    pub fn findSubcommand(self: *const Command, name: []const u8) ?*const Command {
        for (self.subcommands) |cmd| {
            if (std.mem.eql(u8, cmd.name, name)) {
                return cmd;
            }
            for (cmd.aliases) |alias| {
                if (std.mem.eql(u8, alias, name)) {
                    return cmd;
                }
            }
        }
        return null;
    }

    /// Find a flag by name
    pub fn findFlag(self: *const Command, name: []const u8) ?*const FlagSpec {
        for (self.flags) |*flag| {
            if (std.mem.eql(u8, flag.name, name)) {
                return flag;
            }
        }
        return null;
    }

    /// Find a flag by short character
    pub fn findFlagByShort(self: *const Command, short: u8) ?*const FlagSpec {
        for (self.flags) |*flag| {
            if (flag.short) |s| {
                if (s == short) {
                    return flag;
                }
            }
        }
        return null;
    }

    /// Get all visible subcommands (non-hidden)
    pub fn visibleSubcommands(self: *const Command) []const *const Command {
        var count: usize = 0;
        for (self.subcommands) |cmd| {
            if (!cmd.hidden) count += 1;
        }
        return self.subcommands; // Simplified for now
    }

    /// Check if this command has any subcommands
    pub fn hasSubcommands(self: *const Command) bool {
        return self.subcommands.len > 0;
    }

    /// Check if this command is runnable
    pub fn isRunnable(self: *const Command) bool {
        return self.run != null;
    }

    /// Get the full usage string
    pub fn usage(self: *const Command) []const u8 {
        _ = self;
        return "[flags] <command> [args]"; // Simplified
    }
};

/// Global flags that apply to all commands
pub const global_flags: []const FlagSpec = &.{
    .{
        .name = "help",
        .short = 'h',
        .help = "Print help information",
        .ftype = .bool,
    },
    .{
        .name = "version",
        .short = 'V',
        .help = "Print version information",
        .ftype = .bool,
    },
    .{
        .name = "quiet",
        .short = 'q',
        .help = "Suppress non-essential output",
        .ftype = .bool,
    },
    .{
        .name = "json",
        .short = null,
        .help = "Output in JSON format",
        .ftype = .bool,
    },
    .{
        .name = "plain",
        .short = null,
        .help = "Output in plain text (no formatting)",
        .ftype = .bool,
    },
    .{
        .name = "no-color",
        .short = null,
        .help = "Disable colored output",
        .ftype = .bool,
    },
    .{
        .name = "dry-run",
        .short = 'n',
        .help = "Show what would be done without doing it",
        .ftype = .bool,
    },
    .{
        .name = "no-input",
        .short = null,
        .help = "Disable interactive prompts",
        .ftype = .bool,
    },
};

// ============================================================================
// Tests
// ============================================================================

test "FlagSpec validation" {
    const flag = FlagSpec{
        .name = "test",
        .help = "Test flag",
        .ftype = .string,
    };

    try std.testing.expect(flag.validate("any value"));
}

test "Command findSubcommand" {
    const sub = Command{
        .name = "sub",
        .summary = "Subcommand",
        .aliases = &.{"s"},
    };

    const root = Command{
        .name = "root",
        .summary = "Root command",
        .subcommands = &.{&sub},
    };

    try std.testing.expect(root.findSubcommand("sub") != null);
    try std.testing.expect(root.findSubcommand("s") != null);
    try std.testing.expect(root.findSubcommand("unknown") == null);
}

test "Context initialization" {
    var ctx = Context.init(std.testing.allocator);
    defer ctx.deinit();

    try std.testing.expect(!ctx.quiet);
    try std.testing.expect(!ctx.json);
}
