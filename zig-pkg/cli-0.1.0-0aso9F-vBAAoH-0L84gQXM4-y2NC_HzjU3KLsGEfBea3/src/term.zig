// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Terminal Module
//!
//! Terminal utilities:
//! - TTY detection and capabilities
//! - ANSI color support with NO_COLOR compliance
//! - Pager integration (less)
//! - Progress indicators (spinners, bars)

const std = @import("std");

pub const tty = @import("term/tty.zig");
pub const color = @import("term/color.zig");
pub const pager = @import("term/pager.zig");
pub const progress = @import("term/progress.zig");
pub const table = @import("term/table.zig");

// Re-export commonly used types
pub const TermInfo = tty.TermInfo;
pub const TermSize = tty.TermSize;
pub const getInfo = tty.getInfo;
pub const getTermSize = tty.getTermSize;
pub const isStdoutTty = tty.isStdoutTty;
pub const isStderrTty = tty.isStderrTty;
pub const isStdinTty = tty.isStdinTty;

pub const Color = color.Color;
pub const Style = color.Style;
pub const ColorContext = color.ColorContext;
pub const colorCode = color.colorCode;
pub const stripAnsi = color.stripAnsi;

pub const PagerConfig = pager.PagerConfig;
pub const PagerWriter = pager.PagerWriter;
pub const writeIfTty = pager.writeIfTty;

pub const Progress = progress.Progress;
pub const ProgressBar = progress.ProgressBar;
pub const SpinnerStyle = progress.SpinnerStyle;

pub const Table = table.Table;
pub const TableConfig = table.TableConfig;
pub const BorderStyle = table.BorderStyle;
pub const Alignment = table.Alignment;

// ============================================================================
// Tests
// ============================================================================

test {
    _ = tty;
    _ = color;
    _ = pager;
    _ = progress;
    _ = table;
}
