/// Shared string-encoding helpers for udev builtins.
/// Factored from usb_id.zig so blkid and other builtins can reuse them.
const std = @import("std");

/// Collapse runs of ASCII whitespace to a single '_', strip leading/trailing
/// whitespace. (systemd util_replace_whitespace)
pub fn replaceWhitespace(gpa: std.mem.Allocator, s: []const u8) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(gpa);

    var in_ws = true; // true at start so leading whitespace is skipped
    var last_real: usize = 0;

    for (s) |c| {
        if (std.ascii.isWhitespace(c)) {
            if (!in_ws) {
                try buf.append(gpa, '_');
                in_ws = true;
            }
        } else {
            try buf.append(gpa, c);
            in_ws = false;
            last_real = buf.items.len;
        }
    }

    // Trim the trailing '_' that results from trailing whitespace.
    buf.items.len = last_real;
    return buf.toOwnedSlice(gpa);
}

fn isAllowedChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or
        c == ' ' or c == '#' or c == '+' or c == '-' or c == '.' or
        c == ':' or c == '=' or c == '@' or c == '_' or c == '/';
}

/// Replace every byte NOT in [A-Za-z0-9 #+-.:=@_/] with '_'.
/// (systemd udev_util_replace_chars / util_replace_chars)
pub fn replaceChars(gpa: std.mem.Allocator, s: []const u8) ![]u8 {
    const out = try gpa.dupe(u8, s);
    for (out) |*c| {
        if (!isAllowedChar(c.*)) c.* = '_';
    }
    return out;
}

/// Udev-encode a string: keep printable ASCII (except ' ', '/', '\');
/// encode everything else as \xNN (lowercase two-digit hex).
/// (systemd encode_devnode_name / udev_encode_string)
pub fn encodeString(gpa: std.mem.Allocator, s: []const u8) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(gpa);

    for (s) |c| {
        const keep = std.ascii.isPrint(c) and c != ' ' and c != '/' and c != '\\';
        if (keep) {
            try buf.append(gpa, c);
        } else {
            var hex_buf: [4]u8 = undefined;
            const encoded = try std.fmt.bufPrint(&hex_buf, "\\x{x:0>2}", .{c});
            try buf.appendSlice(gpa, encoded);
        }
    }

    return buf.toOwnedSlice(gpa);
}

// Tests

test "encode: encodeString" {
    const gpa = std.testing.allocator;

    const enc = try encodeString(gpa, "a b/c");
    defer gpa.free(enc);
    try std.testing.expectEqualStrings("a\\x20b\\x2fc", enc);
}

test "encode: replaceWhitespace" {
    const gpa = std.testing.allocator;

    const rw = try replaceWhitespace(gpa, "USB  Receiver ");
    defer gpa.free(rw);
    try std.testing.expectEqualStrings("USB_Receiver", rw);
}
