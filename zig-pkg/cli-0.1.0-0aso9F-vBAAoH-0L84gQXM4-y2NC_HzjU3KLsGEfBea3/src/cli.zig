// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # CLI Module
//!
//! Command-line interface library providing Cobra/Viper-class features:
//! - Nested command trees with subcommands
//! - Type-safe flag parsing
//! - Automatic help generation with examples-first approach
//! - Shell completion generation (bash, zsh, fish, powershell)
//! - Man page generation
//! - Persistent hooks (runs for command and all subcommands)
//! - Flag groups (mutually exclusive, required together)
//! - Positional argument validators

const std = @import("std");

pub const command = @import("cli/command.zig");
pub const parser = @import("cli/parser.zig");
pub const help = @import("cli/help.zig");

pub const completion = struct {
    pub const bash = @import("cli/completion/bash.zig");
    pub const zsh = @import("cli/completion/zsh.zig");
    pub const fish = @import("cli/completion/fish.zig");
    pub const powershell = @import("cli/completion/powershell.zig");
};

// Re-export commonly used types
pub const Command = command.Command;
pub const Context = command.Context;
pub const FlagSpec = command.FlagSpec;
pub const FlagType = command.FlagType;
pub const FlagValue = command.FlagValue;
pub const SecretPolicy = command.SecretPolicy;
pub const HookFn = command.HookFn;
pub const RunFn = command.RunFn;
pub const global_flags = command.global_flags;

// Flag groups and argument validation
pub const FlagGroup = command.FlagGroup;
pub const FlagGroupType = command.FlagGroupType;
pub const ArgsValidator = command.ArgsValidator;
pub const ArgsValidationError = command.ArgsValidationError;
pub const ArgsErrorDetails = command.ArgsErrorDetails;

pub const Parser = parser.Parser;
pub const ParseError = parser.ParseError;
pub const ParseResult = parser.ParseResult;
pub const run = parser.run;

pub const printHelp = help.printHelp;
pub const printVersion = help.printVersion;
pub const generateMan = help.generateMan;
pub const generateMarkdown = help.generateMarkdown;

/// Shell type for completion generation
pub const Shell = enum { bash, zsh, fish, powershell };

/// Generate shell completion script
pub fn generateCompletions(shell: Shell, cmd: *const Command, allocator: std.mem.Allocator) ![]const u8 {
    return switch (shell) {
        .bash => try completion.bash.generate(cmd, allocator),
        .zsh => try completion.zsh.generate(cmd, allocator),
        .fish => try completion.fish.generate(cmd, allocator),
        .powershell => try completion.powershell.generate(cmd, allocator),
    };
}

// ============================================================================
// Tests
// ============================================================================

test {
    _ = command;
    _ = parser;
    _ = help;
    _ = completion.bash;
    _ = completion.zsh;
    _ = completion.fish;
    _ = completion.powershell;
}
