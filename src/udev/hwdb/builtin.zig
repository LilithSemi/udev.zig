//! hwdb builtin: import HWDB properties into an EventState for the matching modalias.
const std = @import("std");
const reader = @import("reader.zig");
const Device = @import("../device.zig").Device;
const EventState = @import("../rules/runner.zig").EventState;

/// Import hwdb properties for the device into `state`.
///
/// `arg` is whitespace-split and recognises:
///   --subsystem=<s>      parsed but not acted on yet (no modalias synthesis)
///   --lookup-prefix=<p>  only keys starting with <p> are imported
///   last non-flag token  explicit modalias (surrounding single quotes stripped)
///
/// Lookup string = explicit modalias else dev.getProperty("MODALIAS").
/// Returns immediately (nothing to do) when no modalias can be determined.
pub fn run(
    hw: *reader.Hwdb,
    gpa: std.mem.Allocator,
    arg: []const u8,
    dev: *Device,
    state: *EventState,
) !void {
    var prefix: ?[]const u8 = null;
    var explicit_modalias: ?[]const u8 = null;

    var tok_it = std.mem.tokenizeAny(u8, arg, " \t\r\n");
    while (tok_it.next()) |tok| {
        if (std.mem.startsWith(u8, tok, "--subsystem=")) {
            // Parsed but not used yet. No modalias synthesis from subsystem.
            continue;
        } else if (std.mem.startsWith(u8, tok, "--lookup-prefix=")) {
            prefix = tok["--lookup-prefix=".len..];
        } else if (!std.mem.startsWith(u8, tok, "--")) {
            // Last non-flag token is the explicit modalias. Strip surrounding single quotes.
            var m = tok;
            if (m.len >= 2 and m[0] == '\'' and m[m.len - 1] == '\'') {
                m = m[1 .. m.len - 1];
            }
            explicit_modalias = m;
        }
    }

    const modalias: []const u8 = explicit_modalias orelse
        dev.getProperty("MODALIAS") orelse
        return;

    const res = try hw.query(gpa, modalias);
    defer gpa.free(res);

    for (res) |kv| {
        if (prefix) |p| {
            if (!std.mem.startsWith(u8, kv.key, p)) continue;
        }
        try state.setProperty(kv.key, kv.value);
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

const uevent = @import("../uevent.zig");
const testbuild = @import("testbuild.zig");
const Context = @import("../context.zig").Context;

test "builtin.run imports ID_VENDOR from device MODALIAS" {
    const gpa = std.testing.allocator;

    const buf = try testbuild.build(gpa, &.{
        .{
            .pattern = "usb:v046Dp*",
            .values = &.{.{ .key = "ID_VENDOR", .value = "Logitech" }},
        },
    });
    var hw = try reader.Hwdb.openFromBuffer(gpa, buf);
    defer hw.deinit();

    var ctx = Context.init(gpa, std.testing.io);
    defer ctx.deinit();

    const ev_buf = "add@/devices/x\x00MODALIAS=usb:v046DpC52B\x00";
    const parsed = try uevent.parseKernel(ev_buf);
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    var state = EventState.init(gpa);
    defer state.deinit();

    try run(&hw, gpa, "", &dev, &state);

    try std.testing.expectEqualStrings("Logitech", state.getProperty("ID_VENDOR").?);
}

test "builtin.run explicit modalias arg + --lookup-prefix filters non-matching keys" {
    const gpa = std.testing.allocator;

    const buf = try testbuild.build(gpa, &.{
        .{
            .pattern = "usb:v046Dp*",
            .values = &.{
                .{ .key = "ID_VENDOR", .value = "Logitech" },
                .{ .key = "VENDOR_NOPREFIX", .value = "should-be-excluded" },
            },
        },
    });
    var hw = try reader.Hwdb.openFromBuffer(gpa, buf);
    defer hw.deinit();

    var ctx = Context.init(gpa, std.testing.io);
    defer ctx.deinit();

    // Device carries no MODALIAS, so the explicit token in arg drives the lookup.
    const ev_buf = "add@/devices/y\x00ACTION=add\x00";
    const parsed = try uevent.parseKernel(ev_buf);
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    var state = EventState.init(gpa);
    defer state.deinit();

    try run(&hw, gpa, "'usb:v046DpC52B' --lookup-prefix=ID_", &dev, &state);

    try std.testing.expectEqualStrings("Logitech", state.getProperty("ID_VENDOR").?);
    try std.testing.expect(state.getProperty("VENDOR_NOPREFIX") == null);
}
