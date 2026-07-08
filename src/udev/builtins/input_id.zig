/// input_id builtin: classify input devices and set ID_INPUT_* properties.
/// Faithfully matches systemd's udev builtin input_id.c logic.
const std = @import("std");
const Device = @import("../device.zig").Device;
const EventState = @import("../rules/runner.zig").EventState;
const ic = @import("input_codes.zig");

const EV = ic.EV;
const KEY = ic.KEY;
const BTN = ic.BTN;
const REL = ic.REL;
const ABS = ic.ABS;
const INPUT_PROP = ic.INPUT_PROP;

// Bitmap helpers

/// Parse a space-separated hex-words capabilities file (highest word first)
/// into a slice where index 0 holds bits 0..63. Caller owns the returned slice.
fn parseBitmap(gpa: std.mem.Allocator, raw: []const u8) ![]u64 {
    // Count words (non-empty tokens)
    var count: usize = 0;
    var it = std.mem.tokenizeScalar(u8, raw, ' ');
    while (it.next()) |_| count += 1;

    if (count == 0) return gpa.alloc(u64, 0);

    const words = try gpa.alloc(u64, count);
    errdefer gpa.free(words);

    // Re-parse and fill reversed (file is highest first, we want index 0 = lowest)
    var idx: usize = count;
    var it2 = std.mem.tokenizeScalar(u8, raw, ' ');
    while (it2.next()) |tok| {
        idx -= 1;
        words[idx] = std.fmt.parseInt(u64, tok, 16) catch 0;
    }

    return words;
}

pub fn testBit(bits: []const u64, n: usize) bool {
    return (n / 64) < bits.len and ((bits[n / 64] >> @intCast(n % 64)) & 1) == 1;
}

// run

pub fn run(
    gpa: std.mem.Allocator,
    dev: *Device,
    state: *EventState,
    args: []const u8,
) anyerror!void {
    _ = args;

    // Find the device that has capabilities/ev (may be a parent)
    var cap_dev: ?Device = null;
    defer if (cap_dev) |*d| d.deinit();

    const ev_raw = blk: {
        if (try dev.getSysattr("capabilities/ev")) |v| break :blk v;

        // Walk parents
        var maybe = try dev.parent();
        while (maybe) |p| {
            var pd = p;
            const v = pd.getSysattr("capabilities/ev") catch |err| {
                pd.deinit();
                return err;
            };
            if (v != null) {
                // store the parent device so we can read other caps from it
                cap_dev = pd;
                break :blk v.?;
            }
            const next = pd.parent() catch |err| {
                pd.deinit();
                return err;
            };
            pd.deinit();
            maybe = next;
        }
        return; // no capabilities/ev found anywhere
    };

    // The device to read remaining caps from
    const src: *Device = if (cap_dev) |*d| d else dev;

    // Parse ev bitmap
    const ev = try parseBitmap(gpa, ev_raw);
    defer gpa.free(ev);

    // Parse key bitmap
    const key_raw = (try src.getSysattr("capabilities/key")) orelse "";
    const key = try parseBitmap(gpa, key_raw);
    defer gpa.free(key);

    // Parse rel bitmap
    const rel_raw = (try src.getSysattr("capabilities/rel")) orelse "";
    const rel = try parseBitmap(gpa, rel_raw);
    defer gpa.free(rel);

    // Parse abs bitmap
    const abs_raw = (try src.getSysattr("capabilities/abs")) orelse "";
    const abs = try parseBitmap(gpa, abs_raw);
    defer gpa.free(abs);

    // Parse the device-property bitmap. NOTE: this lives at the device root as "properties"
    // (NOT "capabilities/prop", which does not exist). systemd reads get_cap_mask(.., "properties").
    const prop_raw = (try src.getSysattr("properties")) orelse "";
    const prop = try parseBitmap(gpa, prop_raw);
    defer gpa.free(prop);

    // Always set ID_INPUT
    try state.setProperty("ID_INPUT", "1");

    // Derived flags
    const has_abs = testBit(abs, ABS.X) and testBit(abs, ABS.Y);
    const is_direct = testBit(prop, INPUT_PROP.DIRECT);
    const stylus = testBit(key, BTN.STYLUS) or testBit(key, BTN.TOOL_PEN);
    const finger = testBit(key, BTN.TOOL_FINGER) and !testBit(key, BTN.TOOL_PEN);
    // systemd scans the whole mouse-button range BTN_MOUSE(0x110)..BTN_JOYSTICK-1(0x11f),
    // not just BTN_LEFT, since a mouse may advertise BTN_RIGHT/MIDDLE without BTN_LEFT.
    const has_mouse_btn = blk: {
        var b: usize = BTN.MOUSE;
        while (b < BTN.JOYSTICK) : (b += 1) if (testBit(key, b)) break :blk true;
        break :blk false;
    };
    const has_touch = testBit(key, BTN.TOUCH);
    const has_rel = testBit(ev, EV.REL) and testBit(rel, REL.X) and testBit(rel, REL.Y);

    // Pointer / touch classification (mutually exclusive top branch)
    if (stylus and has_abs) {
        try state.setProperty("ID_INPUT_TABLET", "1");
    } else if (finger and has_abs and !is_direct) {
        try state.setProperty("ID_INPUT_TOUCHPAD", "1");
    } else if (has_touch and has_abs and is_direct) {
        try state.setProperty("ID_INPUT_TOUCHSCREEN", "1");
    }

    // Mouse (independent of above)
    if (has_rel and has_mouse_btn) {
        try state.setProperty("ID_INPUT_MOUSE", "1");
    }

    // Joystick
    const is_joystick = blk: {
        if (testBit(key, BTN.JOYSTICK)) break :blk true;
        // Classic joystick axes + gamepad/joystick/trigger button
        const has_joy_axis = testBit(abs, ABS.RX) or testBit(abs, ABS.RY) or
            testBit(abs, ABS.RZ) or testBit(abs, ABS.THROTTLE) or
            testBit(abs, ABS.RUDDER) or testBit(abs, ABS.WHEEL) or
            testBit(abs, ABS.GAS) or testBit(abs, ABS.BRAKE) or
            testBit(abs, ABS.HAT0X);
        const has_joy_btn = testBit(key, BTN.GAMEPAD) or testBit(key, BTN.TRIGGER_HAPPY);
        break :blk has_joy_axis and has_joy_btn;
    };
    if (is_joystick) {
        try state.setProperty("ID_INPUT_JOYSTICK", "1");
    }

    // Accelerometer
    if (testBit(prop, INPUT_PROP.ACCELEROMETER)) {
        try state.setProperty("ID_INPUT_ACCELEROMETER", "1");
    }

    // Switch
    if (testBit(ev, EV.SW)) {
        try state.setProperty("ID_INPUT_SWITCH", "1");
    }

    // Key / keyboard
    if (testBit(ev, EV.KEY)) {
        // Only KEY_* count here, NOT BTN_* (which share this bitmap). systemd scans words
        // 0..BTN_MISC/64-1 = the first 4 u64 words (bits 0x000-0x0ff). (Multimedia high-key
        // blocks are a documented partial: a device with ONLY high multimedia keys and no basic
        // keys won't get ID_INPUT_KEY here yet.)
        const key_words: usize = BTN.MISC / 64; // 0x100/64 = 4
        var any_key = false;
        for (key[0..@min(key_words, key.len)]) |word| {
            if (word != 0) {
                any_key = true;
                break;
            }
        }

        // Real keyboard: the low 32 bits ESC..(bit 31) all set, i.e. systemd's
        // FLAGS_SET(bitmask_key[0], 0xFFFFFFFE) covers bits 1..31 inclusive (KEY_RESERVED=0 excluded).
        const is_keyboard = key.len > 0 and (key[0] & 0xFFFF_FFFE) == 0xFFFF_FFFE;
        if (is_keyboard) {
            try state.setProperty("ID_INPUT_KEYBOARD", "1");
        }
        if (any_key or is_keyboard) {
            try state.setProperty("ID_INPUT_KEY", "1");
        }
    }
}

// Tests

/// Format a sorted list of bit indices into the capabilities file content
/// that the kernel produces: space-separated hex words, highest word first.
pub fn fmtBitmapWords(
    gpa: std.mem.Allocator,
    bits: []const usize,
) ![]u8 {
    if (bits.len == 0) return gpa.dupe(u8, "0");

    // Find highest bit
    var max_bit: usize = 0;
    for (bits) |b| if (b > max_bit) {
        max_bit = b;
    };

    const n_words = max_bit / 64 + 1;
    const words = try gpa.alloc(u64, n_words);
    defer gpa.free(words);
    @memset(words, 0);

    for (bits) |b| {
        words[b / 64] |= @as(u64, 1) << @intCast(b % 64);
    }

    // Emit highest word first
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(gpa);

    var word_buf: [20]u8 = undefined;
    var i: usize = n_words;
    while (i > 0) {
        i -= 1;
        if (buf.items.len > 0) try buf.append(gpa, ' ');
        const word_str = try std.fmt.bufPrint(&word_buf, "{x}", .{words[i]});
        try buf.appendSlice(gpa, word_str);
    }

    return buf.toOwnedSlice(gpa);
}

test "fmtBitmapWords round-trips through parseBitmap" {
    const gpa = std.testing.allocator;
    const bits = [_]usize{ 0, 1, 5, 64, 65 };
    const raw = try fmtBitmapWords(gpa, &bits);
    defer gpa.free(raw);

    const words = try parseBitmap(gpa, raw);
    defer gpa.free(words);

    for (bits) |b| {
        try std.testing.expect(testBit(words, b));
    }
    try std.testing.expect(!testBit(words, 2));
}

test "input_id: MOUSE device sets ID_INPUT and ID_INPUT_MOUSE, not ID_INPUT_KEYBOARD" {
    const testfs = @import("../testfs.zig");
    const context = @import("../context.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // EV bits: KEY(1) and REL(2)
    const ev_str = try fmtBitmapWords(gpa, &.{ EV.KEY, EV.REL });
    defer gpa.free(ev_str);
    // KEY bits: BTN.MOUSE (0x110 = 272)
    const key_str = try fmtBitmapWords(gpa, &.{BTN.MOUSE});
    defer gpa.free(key_str);
    // REL bits: X(0) and Y(1)
    const rel_str = try fmtBitmapWords(gpa, &.{ REL.X, REL.Y });
    defer gpa.free(rel_str);

    const syspath = try testfs.makeSysfs(&tmp, .{
        .name = "mouse0",
        .subsystem = "input",
        .uevent = "",
        .attrs = &.{
            .{ "capabilities/ev", ev_str },
            .{ "capabilities/key", key_str },
            .{ "capabilities/rel", rel_str },
        },
    });
    defer gpa.free(syspath);

    var ctx = context.Context.init(gpa, io);
    defer ctx.deinit();
    var dev = try Device.fromSyspath(&ctx, syspath);
    defer dev.deinit();

    var state = EventState.init(gpa);
    defer state.deinit();

    try run(gpa, &dev, &state, "");

    try std.testing.expectEqualStrings("1", state.getProperty("ID_INPUT").?);
    try std.testing.expectEqualStrings("1", state.getProperty("ID_INPUT_MOUSE").?);
    try std.testing.expect(state.getProperty("ID_INPUT_KEYBOARD") == null);
}

test "input_id: KEYBOARD device sets ID_INPUT_KEYBOARD and ID_INPUT_KEY" {
    const testfs = @import("../testfs.zig");
    const context = @import("../context.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // EV bits: KEY(1)
    const ev_str = try fmtBitmapWords(gpa, &.{EV.KEY});
    defer gpa.free(ev_str);

    // KEY bits: all of ESC(1)..D(32) for keyboard detection
    var kbd_bits: [32]usize = undefined;
    for (0..32) |i| kbd_bits[i] = i + 1; // ESC=1 .. D=32
    const key_str = try fmtBitmapWords(gpa, &kbd_bits);
    defer gpa.free(key_str);

    const syspath = try testfs.makeSysfs(&tmp, .{
        .name = "kbd0",
        .subsystem = "input",
        .uevent = "",
        .attrs = &.{
            .{ "capabilities/ev", ev_str },
            .{ "capabilities/key", key_str },
        },
    });
    defer gpa.free(syspath);

    var ctx = context.Context.init(gpa, io);
    defer ctx.deinit();
    var dev = try Device.fromSyspath(&ctx, syspath);
    defer dev.deinit();

    var state = EventState.init(gpa);
    defer state.deinit();

    try run(gpa, &dev, &state, "");

    try std.testing.expectEqualStrings("1", state.getProperty("ID_INPUT").?);
    try std.testing.expectEqualStrings("1", state.getProperty("ID_INPUT_KEY").?);
    try std.testing.expectEqualStrings("1", state.getProperty("ID_INPUT_KEYBOARD").?);
    try std.testing.expect(state.getProperty("ID_INPUT_MOUSE") == null);
}

test "input_id: caps on parent device" {
    const context = @import("../context.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const ev_str = try fmtBitmapWords(gpa, &.{ EV.KEY, EV.REL });
    defer gpa.free(ev_str);
    const key_str = try fmtBitmapWords(gpa, &.{BTN.MOUSE});
    defer gpa.free(key_str);
    const rel_str = try fmtBitmapWords(gpa, &.{ REL.X, REL.Y });
    defer gpa.free(rel_str);

    // Parent: has capabilities
    try tmp.dir.createDirPath(io, "devices/parent0");
    try tmp.dir.writeFile(io, .{ .sub_path = "devices/parent0/uevent", .data = "" });
    try tmp.dir.createDirPath(io, "devices/parent0/capabilities");
    try tmp.dir.writeFile(io, .{ .sub_path = "devices/parent0/capabilities/ev", .data = ev_str });
    try tmp.dir.writeFile(io, .{ .sub_path = "devices/parent0/capabilities/key", .data = key_str });
    try tmp.dir.writeFile(io, .{ .sub_path = "devices/parent0/capabilities/rel", .data = rel_str });

    // Child: no capabilities
    try tmp.dir.createDirPath(io, "devices/parent0/child0");
    try tmp.dir.writeFile(io, .{ .sub_path = "devices/parent0/child0/uevent", .data = "" });

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPathFile(io, "devices/parent0/child0", &rp_buf);
    const child_path = try gpa.dupe(u8, rp_buf[0..n]);
    defer gpa.free(child_path);

    var ctx = context.Context.init(gpa, io);
    defer ctx.deinit();
    var dev = try Device.fromSyspath(&ctx, child_path);
    defer dev.deinit();

    var state = EventState.init(gpa);
    defer state.deinit();

    try run(gpa, &dev, &state, "");

    try std.testing.expectEqualStrings("1", state.getProperty("ID_INPUT").?);
    try std.testing.expectEqualStrings("1", state.getProperty("ID_INPUT_MOUSE").?);
}

test "input_id: integration (skipped when /sys/class/input/event0 absent)" {
    const context = @import("../context.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    // Skip if event0 does not exist
    std.Io.Dir.cwd().access(io, "/sys/class/input/event0", .{}) catch return;

    // Resolve the real syspath via readlink of the class entry
    var lbuf: [std.fs.max_path_bytes]u8 = undefined;
    const n = std.Io.Dir.cwd().readLink(io, "/sys/class/input/event0", &lbuf) catch return;
    const link = lbuf[0..n];

    // link is like "../../devices/..." relative to /sys/class/input
    // Resolve to absolute
    var abs_buf: [std.fs.max_path_bytes]u8 = undefined;
    const abs_n = try std.Io.Dir.cwd().realPathFile(io, "/sys/class/input/event0", &abs_buf);
    const syspath = abs_buf[0..abs_n];
    _ = link;

    var ctx = context.Context.init(gpa, io);
    defer ctx.deinit();
    var dev = try Device.fromSyspath(&ctx, syspath);
    defer dev.deinit();

    var state = EventState.init(gpa);
    defer state.deinit();

    try run(gpa, &dev, &state, "");
    try std.testing.expectEqualStrings("1", state.getProperty("ID_INPUT").?);
}
