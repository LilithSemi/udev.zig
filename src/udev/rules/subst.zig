//! udev string substitution for rule values.
//! Handles $name/$name{arg} and %x/%x{arg} expansion codes in a single
//! left-to-right pass, appending the result to a caller-owned ArrayListUnmanaged.
const std = @import("std");
const Device = @import("../device.zig").Device;
const runner_mod = @import("runner.zig");
pub const EventState = runner_mod.EventState;
const uevent = @import("../uevent.zig");
const context_mod = @import("../context.zig");

// Public API

/// Expand all substitution codes in `value`, appending the result to `out`.
/// `out` is caller-owned and backed by `gpa`. Literal text is copied as-is.
pub fn substitute(
    out: *std.ArrayListUnmanaged(u8),
    gpa: std.mem.Allocator,
    value: []const u8,
    dev: *Device,
    state: *const EventState,
) !void {
    var i: usize = 0;
    while (i < value.len) {
        const c = value[i];
        if (c == '$') {
            i += 1;
            if (i >= value.len) {
                try out.append(gpa, '$');
                break;
            }
            if (value[i] == '$') {
                try out.append(gpa, '$');
                i += 1;
                continue;
            }
            // Read identifier (alpha + '_')
            const name_start = i;
            while (i < value.len and isIdentChar(value[i])) i += 1;
            const name = value[name_start..i];
            // Optional {arg}
            var arg: ?[]const u8 = null;
            if (i < value.len and value[i] == '{') {
                i += 1;
                const as = i;
                while (i < value.len and value[i] != '}') i += 1;
                arg = value[as..i];
                if (i < value.len) i += 1; // consume '}'
            }
            try appendDollar(out, gpa, name, arg, dev, state);
        } else if (c == '%') {
            i += 1;
            if (i >= value.len) {
                try out.append(gpa, '%');
                break;
            }
            if (value[i] == '%') {
                try out.append(gpa, '%');
                i += 1;
                continue;
            }
            const code = value[i];
            i += 1;
            // Optional {arg}
            var arg: ?[]const u8 = null;
            if (i < value.len and value[i] == '{') {
                i += 1;
                const as = i;
                while (i < value.len and value[i] != '}') i += 1;
                arg = value[as..i];
                if (i < value.len) i += 1; // consume '}'
            }
            try appendPercent(out, gpa, code, arg, dev, state);
        } else {
            try out.append(gpa, c);
            i += 1;
        }
    }
}

// Private helpers

fn isIdentChar(c: u8) bool {
    return std.ascii.isAlphabetic(c) or c == '_';
}

/// Append the trailing decimal digit suffix of `sysname` to `out`.
fn appendNumber(out: *std.ArrayListUnmanaged(u8), gpa: std.mem.Allocator, sn: []const u8) !void {
    var j = sn.len;
    while (j > 0 and std.ascii.isDigit(sn[j - 1])) j -= 1;
    try out.appendSlice(gpa, sn[j..]);
}

/// Append a result (last_result) field expansion.
/// Without arg: whole string. With {N}: Nth whitespace-field (1-based).
/// With {N+}: fields N through end joined by single spaces.
fn appendResult(
    out: *std.ArrayListUnmanaged(u8),
    gpa: std.mem.Allocator,
    result: ?[]const u8,
    arg: ?[]const u8,
) !void {
    const r = result orelse "";
    if (arg == null) {
        try out.appendSlice(gpa, r);
        return;
    }
    const a = arg.?;
    const has_plus = a.len > 0 and a[a.len - 1] == '+';
    const num_str = if (has_plus) a[0 .. a.len - 1] else a;
    const n = std.fmt.parseInt(usize, num_str, 10) catch {
        try out.appendSlice(gpa, r);
        return;
    };
    if (n == 0) {
        try out.appendSlice(gpa, r);
        return;
    }
    var fields = std.mem.tokenizeAny(u8, r, " \t");
    var idx: usize = 0;
    while (fields.next()) |field| {
        idx += 1;
        if (idx == n) {
            try out.appendSlice(gpa, field);
            if (has_plus) {
                while (fields.next()) |f| {
                    try out.append(gpa, ' ');
                    try out.appendSlice(gpa, f);
                }
            }
            return;
        }
    }
    // Field index out of range: emit nothing.
}

fn appendDollar(
    out: *std.ArrayListUnmanaged(u8),
    gpa: std.mem.Allocator,
    name: []const u8,
    arg: ?[]const u8,
    dev: *Device,
    state: *const EventState,
) !void {
    if (std.mem.eql(u8, name, "kernel")) {
        try out.appendSlice(gpa, dev.sysname());
    } else if (std.mem.eql(u8, name, "number")) {
        try appendNumber(out, gpa, dev.sysname());
    } else if (std.mem.eql(u8, name, "devpath")) {
        try out.appendSlice(gpa, dev.getProperty("DEVPATH") orelse "");
    } else if (std.mem.eql(u8, name, "attr")) {
        const f = arg orelse "";
        const sysattr = try dev.getSysattr(f);
        const val: []const u8 = sysattr orelse dev.getProperty(f) orelse "";
        try out.appendSlice(gpa, val);
    } else if (std.mem.eql(u8, name, "env")) {
        const k = arg orelse "";
        const val: []const u8 = state.getProperty(k) orelse dev.getProperty(k) orelse "";
        try out.appendSlice(gpa, val);
    } else if (std.mem.eql(u8, name, "major")) {
        try out.appendSlice(gpa, dev.getProperty("MAJOR") orelse "");
    } else if (std.mem.eql(u8, name, "minor")) {
        try out.appendSlice(gpa, dev.getProperty("MINOR") orelse "");
    } else if (std.mem.eql(u8, name, "result")) {
        try appendResult(out, gpa, state.last_result, arg);
    } else if (std.mem.eql(u8, name, "name")) {
        try out.appendSlice(gpa, state.name orelse "");
    } else if (std.mem.eql(u8, name, "links")) {
        // Symlink list joining is the daemon's concern, so emit empty.
    } else if (std.mem.eql(u8, name, "driver")) {
        try out.appendSlice(gpa, (try dev.driver()) orelse dev.getProperty("DRIVER") orelse "");
    } else if (std.mem.eql(u8, name, "devnode")) {
        try out.appendSlice(gpa, dev.devnode() orelse "");
    } else if (std.mem.eql(u8, name, "sys")) {
        try out.appendSlice(gpa, "/sys");
    } else if (std.mem.eql(u8, name, "root")) {
        try out.appendSlice(gpa, "/dev");
    } else if (std.mem.eql(u8, name, "parent")) {
        var maybe_par = try dev.parent();
        if (maybe_par) |*p| {
            defer p.deinit();
            try out.appendSlice(gpa, p.sysname());
        }
    } else {
        // Unknown: emit verbatim including any arg.
        try out.append(gpa, '$');
        try out.appendSlice(gpa, name);
        if (arg) |a| {
            try out.append(gpa, '{');
            try out.appendSlice(gpa, a);
            try out.append(gpa, '}');
        }
    }
}

fn appendPercent(
    out: *std.ArrayListUnmanaged(u8),
    gpa: std.mem.Allocator,
    code: u8,
    arg: ?[]const u8,
    dev: *Device,
    state: *const EventState,
) !void {
    switch (code) {
        'k' => try out.appendSlice(gpa, dev.sysname()),
        'n' => try appendNumber(out, gpa, dev.sysname()),
        'p' => try out.appendSlice(gpa, dev.getProperty("DEVPATH") orelse ""),
        's' => {
            const f = arg orelse "";
            const sysattr = try dev.getSysattr(f);
            const val: []const u8 = sysattr orelse dev.getProperty(f) orelse "";
            try out.appendSlice(gpa, val);
        },
        'E' => {
            const k = arg orelse "";
            const val: []const u8 = state.getProperty(k) orelse dev.getProperty(k) orelse "";
            try out.appendSlice(gpa, val);
        },
        'M' => try out.appendSlice(gpa, dev.getProperty("MAJOR") orelse ""),
        'm' => try out.appendSlice(gpa, dev.getProperty("MINOR") orelse ""),
        'c' => try appendResult(out, gpa, state.last_result, arg),
        'N' => try out.appendSlice(gpa, dev.devnode() orelse ""),
        'S' => try out.appendSlice(gpa, "/sys"),
        'r' => try out.appendSlice(gpa, "/dev"),
        'P' => {
            var maybe_par = try dev.parent();
            if (maybe_par) |*p| {
                defer p.deinit();
                try out.appendSlice(gpa, p.sysname());
            }
        },
        else => {
            // Unknown: emit verbatim including any arg.
            try out.append(gpa, '%');
            try out.append(gpa, code);
            if (arg) |a| {
                try out.append(gpa, '{');
                try out.appendSlice(gpa, a);
                try out.append(gpa, '}');
            }
        },
    }
}

// Tests

// Test device: event12 with MAJOR=13, MINOR=64, DEVNAME=input/event12.
// Build via parseKernel + fromProps so no real sysfs is needed.
const test_buf = "add@/devices/bus/event12\x00" ++
    "DEVPATH=/devices/bus/event12\x00" ++
    "MAJOR=13\x00MINOR=64\x00DEVNAME=input/event12\x00";

test "substitute: $kernel and %k -> sysname" {
    var ctx = context_mod.Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();

    const parsed = try uevent.parseKernel(test_buf);
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    var state = EventState.init(std.testing.allocator);
    defer state.deinit();

    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(std.testing.allocator);

    try substitute(&out, std.testing.allocator, "$kernel", &dev, &state);
    try std.testing.expectEqualStrings("event12", out.items);

    out.clearRetainingCapacity();
    try substitute(&out, std.testing.allocator, "%k", &dev, &state);
    try std.testing.expectEqualStrings("event12", out.items);
}

test "substitute: $number and %n -> trailing digits of sysname" {
    var ctx = context_mod.Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();

    const parsed = try uevent.parseKernel(test_buf);
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    var state = EventState.init(std.testing.allocator);
    defer state.deinit();

    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(std.testing.allocator);

    try substitute(&out, std.testing.allocator, "$number", &dev, &state);
    try std.testing.expectEqualStrings("12", out.items);

    out.clearRetainingCapacity();
    try substitute(&out, std.testing.allocator, "%n", &dev, &state);
    try std.testing.expectEqualStrings("12", out.items);
}

test "substitute: $major/%M and $minor/%m" {
    var ctx = context_mod.Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();

    const parsed = try uevent.parseKernel(test_buf);
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    var state = EventState.init(std.testing.allocator);
    defer state.deinit();

    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(std.testing.allocator);

    try substitute(&out, std.testing.allocator, "$major", &dev, &state);
    try std.testing.expectEqualStrings("13", out.items);

    out.clearRetainingCapacity();
    try substitute(&out, std.testing.allocator, "%M", &dev, &state);
    try std.testing.expectEqualStrings("13", out.items);

    out.clearRetainingCapacity();
    try substitute(&out, std.testing.allocator, "$minor", &dev, &state);
    try std.testing.expectEqualStrings("64", out.items);

    out.clearRetainingCapacity();
    try substitute(&out, std.testing.allocator, "%m", &dev, &state);
    try std.testing.expectEqualStrings("64", out.items);
}

test "substitute: $env{FOO} and %E{FOO}" {
    var ctx = context_mod.Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();

    const parsed = try uevent.parseKernel(test_buf);
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    var state = EventState.init(std.testing.allocator);
    defer state.deinit();
    try state.setProperty("FOO", "bar");

    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(std.testing.allocator);

    try substitute(&out, std.testing.allocator, "$env{FOO}", &dev, &state);
    try std.testing.expectEqualStrings("bar", out.items);

    out.clearRetainingCapacity();
    try substitute(&out, std.testing.allocator, "%E{FOO}", &dev, &state);
    try std.testing.expectEqualStrings("bar", out.items);
}

test "substitute: $result/%c and %c{N} field selection" {
    var ctx = context_mod.Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();

    const parsed = try uevent.parseKernel(test_buf);
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    var state = EventState.init(std.testing.allocator);
    defer state.deinit();
    state.last_result = "a b c";

    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(std.testing.allocator);

    try substitute(&out, std.testing.allocator, "$result", &dev, &state);
    try std.testing.expectEqualStrings("a b c", out.items);

    out.clearRetainingCapacity();
    try substitute(&out, std.testing.allocator, "%c", &dev, &state);
    try std.testing.expectEqualStrings("a b c", out.items);

    out.clearRetainingCapacity();
    try substitute(&out, std.testing.allocator, "%c{2}", &dev, &state);
    try std.testing.expectEqualStrings("b", out.items);

    out.clearRetainingCapacity();
    try substitute(&out, std.testing.allocator, "%c{2+}", &dev, &state);
    try std.testing.expectEqualStrings("b c", out.items);
}

test "substitute: $$ -> dollar and %% -> percent" {
    var ctx = context_mod.Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();

    const parsed = try uevent.parseKernel(test_buf);
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    var state = EventState.init(std.testing.allocator);
    defer state.deinit();

    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(std.testing.allocator);

    try substitute(&out, std.testing.allocator, "$$", &dev, &state);
    try std.testing.expectEqualStrings("$", out.items);

    out.clearRetainingCapacity();
    try substitute(&out, std.testing.allocator, "%%", &dev, &state);
    try std.testing.expectEqualStrings("%", out.items);
}

test "substitute: literal text passes through unchanged" {
    var ctx = context_mod.Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();

    const parsed = try uevent.parseKernel(test_buf);
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    var state = EventState.init(std.testing.allocator);
    defer state.deinit();

    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(std.testing.allocator);

    try substitute(&out, std.testing.allocator, "hello world", &dev, &state);
    try std.testing.expectEqualStrings("hello world", out.items);
}

test "substitute: unknown code emitted verbatim" {
    var ctx = context_mod.Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();

    const parsed = try uevent.parseKernel(test_buf);
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    var state = EventState.init(std.testing.allocator);
    defer state.deinit();

    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(std.testing.allocator);

    try substitute(&out, std.testing.allocator, "$unknown", &dev, &state);
    try std.testing.expectEqualStrings("$unknown", out.items);

    out.clearRetainingCapacity();
    try substitute(&out, std.testing.allocator, "%z", &dev, &state);
    try std.testing.expectEqualStrings("%z", out.items);
}

test "substitute: $devnode/%N -> devnode path" {
    var ctx = context_mod.Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();

    const parsed = try uevent.parseKernel(test_buf);
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    var state = EventState.init(std.testing.allocator);
    defer state.deinit();

    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(std.testing.allocator);

    try substitute(&out, std.testing.allocator, "$devnode", &dev, &state);
    try std.testing.expectEqualStrings("/dev/input/event12", out.items);

    out.clearRetainingCapacity();
    try substitute(&out, std.testing.allocator, "%N", &dev, &state);
    try std.testing.expectEqualStrings("/dev/input/event12", out.items);
}

test "substitute: $sys/%S -> /sys and $root/%r -> /dev" {
    var ctx = context_mod.Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();

    const parsed = try uevent.parseKernel(test_buf);
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    var state = EventState.init(std.testing.allocator);
    defer state.deinit();

    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(std.testing.allocator);

    try substitute(&out, std.testing.allocator, "$sys", &dev, &state);
    try std.testing.expectEqualStrings("/sys", out.items);

    out.clearRetainingCapacity();
    try substitute(&out, std.testing.allocator, "%S", &dev, &state);
    try std.testing.expectEqualStrings("/sys", out.items);

    out.clearRetainingCapacity();
    try substitute(&out, std.testing.allocator, "$root", &dev, &state);
    try std.testing.expectEqualStrings("/dev", out.items);

    out.clearRetainingCapacity();
    try substitute(&out, std.testing.allocator, "%r", &dev, &state);
    try std.testing.expectEqualStrings("/dev", out.items);
}
