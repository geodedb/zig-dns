// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Table Module
//!
//! Terminal table formatting for structured output with support for:
//! - Auto-sizing columns based on content
//! - Configurable borders and padding
//! - ANSI color support
//! - Row separators and alignment

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Column alignment options
pub const Alignment = enum {
    left,
    center,
    right,
};

/// Border style for the table
pub const BorderStyle = enum {
    /// No borders
    none,
    /// ASCII borders (+, -, |)
    ascii,
    /// Unicode box drawing characters
    unicode,
    /// Markdown table format
    markdown,
};

/// Table column configuration
pub const Column = struct {
    /// Column header text
    header: []const u8,
    /// Minimum width (0 for auto)
    min_width: usize = 0,
    /// Maximum width (0 for unlimited)
    max_width: usize = 0,
    /// Text alignment
    alignment: Alignment = .left,
};

/// Table configuration
pub const TableConfig = struct {
    /// Border style
    border: BorderStyle = .ascii,
    /// Padding around cell content (left and right)
    padding: usize = 1,
    /// Show header row
    show_header: bool = true,
    /// Show row separator after header
    header_separator: bool = true,
    /// Use colors (for header)
    use_color: bool = false,
};

/// Table builder for formatted output
pub const Table = struct {
    allocator: Allocator,
    config: TableConfig,
    columns: std.ArrayList(Column),
    rows: std.ArrayList([]const []const u8),
    column_widths: std.ArrayList(usize),

    const Self = @This();

    /// Initialize a new table
    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .config = .{},
            .columns = .empty,
            .rows = .empty,
            .column_widths = .empty,
        };
    }

    /// Initialize with custom configuration
    pub fn initWithConfig(allocator: Allocator, config: TableConfig) Self {
        return .{
            .allocator = allocator,
            .config = config,
            .columns = .empty,
            .rows = .empty,
            .column_widths = .empty,
        };
    }

    /// Deinitialize the table
    pub fn deinit(self: *Self) void {
        for (self.rows.items) |row| {
            self.allocator.free(row);
        }
        self.rows.deinit(self.allocator);
        self.columns.deinit(self.allocator);
        self.column_widths.deinit(self.allocator);
    }

    /// Add a column definition
    pub fn addColumn(self: *Self, column: Column) !void {
        try self.columns.append(self.allocator, column);
        // Initialize width with header length
        try self.column_widths.append(self.allocator, column.header.len);
    }

    /// Add columns from a slice of headers (convenience method)
    pub fn addColumns(self: *Self, headers: []const []const u8) !void {
        for (headers) |header| {
            try self.addColumn(.{ .header = header });
        }
    }

    /// Add a row of data
    pub fn addRow(self: *Self, cells: []const []const u8) !void {
        if (cells.len != self.columns.items.len) {
            return error.ColumnCountMismatch;
        }

        // Copy the cells
        const row = try self.allocator.alloc([]const u8, cells.len);
        @memcpy(row, cells);
        try self.rows.append(self.allocator, row);

        // Update column widths
        for (cells, 0..) |cell, i| {
            const current_width = self.column_widths.items[i];
            const col = self.columns.items[i];

            var cell_width = cell.len;

            // Apply max width constraint
            if (col.max_width > 0 and cell_width > col.max_width) {
                cell_width = col.max_width;
            }

            // Update to larger of current or new
            if (cell_width > current_width) {
                // Apply min width constraint
                if (col.min_width > 0 and cell_width < col.min_width) {
                    self.column_widths.items[i] = col.min_width;
                } else {
                    self.column_widths.items[i] = cell_width;
                }
            }
        }
    }

    /// Render the table to a string
    pub fn render(self: *Self) ![]const u8 {
        var list: std.ArrayList(u8) = .empty;
        const w = list.writer(self.allocator);

        try self.renderTo(w);

        return list.toOwnedSlice(self.allocator);
    }

    /// Render the table to a writer
    pub fn renderTo(self: *Self, writer: anytype) !void {
        if (self.columns.items.len == 0) return;

        const border = self.config.border;
        const pad = self.config.padding;

        // Get border characters
        const chars = getBorderChars(border);

        // Top border (for unicode/ascii)
        if (border == .unicode or border == .ascii) {
            try self.writeHorizontalBorder(writer, chars.top_left, chars.top_mid, chars.top_right, chars.horizontal);
        }

        // Header row
        if (self.config.show_header) {
            try writer.writeAll(chars.vertical);
            for (self.columns.items, 0..) |col, i| {
                const width = self.column_widths.items[i];

                // Padding
                try writer.writeByteNTimes(' ', pad);

                // Header with optional color
                if (self.config.use_color) {
                    try writer.writeAll("\x1b[1m"); // Bold
                }
                try self.writeAligned(writer, col.header, width, col.alignment);
                if (self.config.use_color) {
                    try writer.writeAll("\x1b[0m"); // Reset
                }

                // Padding
                try writer.writeByteNTimes(' ', pad);

                try writer.writeAll(chars.vertical);
            }
            try writer.writeAll("\n");

            // Header separator
            if (self.config.header_separator) {
                if (border == .markdown) {
                    try self.writeMarkdownSeparator(writer);
                } else if (border != .none) {
                    try self.writeHorizontalBorder(writer, chars.mid_left, chars.mid_mid, chars.mid_right, chars.horizontal);
                }
            }
        }

        // Data rows
        for (self.rows.items) |row| {
            try writer.writeAll(chars.vertical);
            for (row, 0..) |cell, i| {
                const width = self.column_widths.items[i];
                const col = self.columns.items[i];

                // Padding
                try writer.writeByteNTimes(' ', pad);

                // Cell content (possibly truncated)
                var display_cell = cell;
                if (col.max_width > 0 and cell.len > col.max_width) {
                    display_cell = cell[0..col.max_width];
                }
                try self.writeAligned(writer, display_cell, width, col.alignment);

                // Padding
                try writer.writeByteNTimes(' ', pad);

                try writer.writeAll(chars.vertical);
            }
            try writer.writeAll("\n");
        }

        // Bottom border (for unicode/ascii)
        if (border == .unicode or border == .ascii) {
            try self.writeHorizontalBorder(writer, chars.bot_left, chars.bot_mid, chars.bot_right, chars.horizontal);
        }
    }

    fn writeAligned(self: *Self, writer: anytype, text: []const u8, width: usize, alignment: Alignment) !void {
        _ = self;
        if (text.len >= width) {
            try writer.writeAll(text[0..width]);
            return;
        }

        const space = width - text.len;
        switch (alignment) {
            .left => {
                try writer.writeAll(text);
                try writer.writeByteNTimes(' ', space);
            },
            .right => {
                try writer.writeByteNTimes(' ', space);
                try writer.writeAll(text);
            },
            .center => {
                const left_pad = space / 2;
                const right_pad = space - left_pad;
                try writer.writeByteNTimes(' ', left_pad);
                try writer.writeAll(text);
                try writer.writeByteNTimes(' ', right_pad);
            },
        }
    }

    fn writeHorizontalBorder(self: *Self, writer: anytype, left: []const u8, mid: []const u8, right: []const u8, horiz: []const u8) !void {
        const pad = self.config.padding;
        try writer.writeAll(left);
        for (self.column_widths.items, 0..) |width, i| {
            const total_width = width + (pad * 2);
            for (0..total_width) |_| {
                try writer.writeAll(horiz);
            }
            if (i < self.column_widths.items.len - 1) {
                try writer.writeAll(mid);
            }
        }
        try writer.writeAll(right);
        try writer.writeAll("\n");
    }

    fn writeMarkdownSeparator(self: *Self, writer: anytype) !void {
        const pad = self.config.padding;
        try writer.writeAll("|");
        for (self.column_widths.items, 0..) |width, i| {
            _ = i;
            try writer.writeByteNTimes(' ', pad);
            try writer.writeByteNTimes('-', width);
            try writer.writeByteNTimes(' ', pad);
            try writer.writeAll("|");
        }
        try writer.writeAll("\n");
    }
};

/// Border character set
const BorderChars = struct {
    horizontal: []const u8,
    vertical: []const u8,
    top_left: []const u8,
    top_mid: []const u8,
    top_right: []const u8,
    mid_left: []const u8,
    mid_mid: []const u8,
    mid_right: []const u8,
    bot_left: []const u8,
    bot_mid: []const u8,
    bot_right: []const u8,
};

fn getBorderChars(style: BorderStyle) BorderChars {
    return switch (style) {
        .none => .{
            .horizontal = "",
            .vertical = "",
            .top_left = "",
            .top_mid = "",
            .top_right = "",
            .mid_left = "",
            .mid_mid = "",
            .mid_right = "",
            .bot_left = "",
            .bot_mid = "",
            .bot_right = "",
        },
        .ascii => .{
            .horizontal = "-",
            .vertical = "|",
            .top_left = "+",
            .top_mid = "+",
            .top_right = "+",
            .mid_left = "+",
            .mid_mid = "+",
            .mid_right = "+",
            .bot_left = "+",
            .bot_mid = "+",
            .bot_right = "+",
        },
        .unicode => .{
            .horizontal = "─",
            .vertical = "│",
            .top_left = "┌",
            .top_mid = "┬",
            .top_right = "┐",
            .mid_left = "├",
            .mid_mid = "┼",
            .mid_right = "┤",
            .bot_left = "└",
            .bot_mid = "┴",
            .bot_right = "┘",
        },
        .markdown => .{
            .horizontal = "-",
            .vertical = "|",
            .top_left = "",
            .top_mid = "",
            .top_right = "",
            .mid_left = "|",
            .mid_mid = "|",
            .mid_right = "|",
            .bot_left = "",
            .bot_mid = "",
            .bot_right = "",
        },
    };
}

// ============================================================================
// Tests
// ============================================================================

test "table: basic creation" {
    var table = Table.init(std.testing.allocator);
    defer table.deinit();

    try table.addColumns(&.{ "Name", "Value" });
    try table.addRow(&.{ "foo", "bar" });
    try table.addRow(&.{ "hello", "world" });

    const output = try table.render();
    defer std.testing.allocator.free(output);

    try std.testing.expect(std.mem.indexOf(u8, output, "Name") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "foo") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "bar") != null);
}

test "table: ascii borders" {
    var table = Table.initWithConfig(std.testing.allocator, .{
        .border = .ascii,
    });
    defer table.deinit();

    try table.addColumns(&.{ "A", "B" });
    try table.addRow(&.{ "1", "2" });

    const output = try table.render();
    defer std.testing.allocator.free(output);

    try std.testing.expect(std.mem.indexOf(u8, output, "+") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "-") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "|") != null);
}

test "table: unicode borders" {
    var table = Table.initWithConfig(std.testing.allocator, .{
        .border = .unicode,
    });
    defer table.deinit();

    try table.addColumns(&.{ "A", "B" });
    try table.addRow(&.{ "1", "2" });

    const output = try table.render();
    defer std.testing.allocator.free(output);

    try std.testing.expect(std.mem.indexOf(u8, output, "┌") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "─") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "│") != null);
}

test "table: markdown format" {
    var table = Table.initWithConfig(std.testing.allocator, .{
        .border = .markdown,
    });
    defer table.deinit();

    try table.addColumns(&.{ "Name", "Value" });
    try table.addRow(&.{ "foo", "bar" });

    const output = try table.render();
    defer std.testing.allocator.free(output);

    // Markdown tables have | and --- separators
    try std.testing.expect(std.mem.indexOf(u8, output, "|") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "---") != null);
}

test "table: no borders" {
    var table = Table.initWithConfig(std.testing.allocator, .{
        .border = .none,
    });
    defer table.deinit();

    try table.addColumns(&.{ "Name", "Value" });
    try table.addRow(&.{ "foo", "bar" });

    const output = try table.render();
    defer std.testing.allocator.free(output);

    // Should not have border characters
    try std.testing.expect(std.mem.indexOf(u8, output, "+") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "─") == null);
}

test "table: column alignment" {
    var table = Table.init(std.testing.allocator);
    defer table.deinit();

    try table.addColumn(.{ .header = "Left", .alignment = .left });
    try table.addColumn(.{ .header = "Right", .alignment = .right });
    try table.addColumn(.{ .header = "Center", .alignment = .center });

    try table.addRow(&.{ "a", "b", "c" });

    const output = try table.render();
    defer std.testing.allocator.free(output);

    try std.testing.expect(output.len > 0);
}

test "table: column width constraints" {
    var table = Table.init(std.testing.allocator);
    defer table.deinit();

    try table.addColumn(.{ .header = "Name", .min_width = 10 });
    try table.addColumn(.{ .header = "Value", .max_width = 5 });

    try table.addRow(&.{ "a", "toolongvalue" });

    const output = try table.render();
    defer std.testing.allocator.free(output);

    // Should have truncated "toolongvalue" to max_width
    try std.testing.expect(std.mem.indexOf(u8, output, "toolo") != null);
}

test "table: column count mismatch error" {
    var table = Table.init(std.testing.allocator);
    defer table.deinit();

    try table.addColumns(&.{ "A", "B" });

    // Try to add row with wrong number of columns
    const result = table.addRow(&.{ "1", "2", "3" });
    try std.testing.expectError(error.ColumnCountMismatch, result);
}

test "table: empty table" {
    var table = Table.init(std.testing.allocator);
    defer table.deinit();

    const output = try table.render();
    defer std.testing.allocator.free(output);

    try std.testing.expectEqual(@as(usize, 0), output.len);
}

test "table: auto column width from content" {
    var table = Table.init(std.testing.allocator);
    defer table.deinit();

    try table.addColumns(&.{ "A", "B" });
    try table.addRow(&.{ "short", "much longer content" });

    // Column widths should be updated based on content
    try std.testing.expect(table.column_widths.items[0] >= 5);
    try std.testing.expect(table.column_widths.items[1] >= 19);
}

test "table: multiple rows" {
    var table = Table.init(std.testing.allocator);
    defer table.deinit();

    try table.addColumns(&.{ "ID", "Name", "Status" });
    try table.addRow(&.{ "1", "Alice", "Active" });
    try table.addRow(&.{ "2", "Bob", "Inactive" });
    try table.addRow(&.{ "3", "Charlie", "Active" });

    const output = try table.render();
    defer std.testing.allocator.free(output);

    try std.testing.expect(std.mem.indexOf(u8, output, "Alice") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Bob") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Charlie") != null);
}
