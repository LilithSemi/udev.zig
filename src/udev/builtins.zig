/// Builtin registry for the pure-Zig udev reimplementation.
const std = @import("std");
const Device = @import("device.zig").Device;
const EventState = @import("rules/runner.zig").EventState;

pub const RunFn = *const fn (
    gpa: std.mem.Allocator,
    dev: *Device,
    state: *EventState,
    args: []const u8,
) anyerror!void;

pub const input_id = @import("builtins/input_id.zig");
pub const usb_id = @import("builtins/usb_id.zig");
pub const path_id = @import("builtins/path_id.zig");
pub const net_id = @import("builtins/net_id.zig");
const blkid_builtin = @import("builtins/blkid.zig");

const Entry = struct { name: []const u8, run: RunFn };

const registry = [_]Entry{
    .{ .name = "input_id", .run = input_id.run },
    .{ .name = "usb_id", .run = usb_id.run },
    .{ .name = "path_id", .run = path_id.run },
    .{ .name = "net_id", .run = net_id.run },
    .{ .name = "blkid", .run = blkid_builtin.run },
};

pub fn find(name: []const u8) ?RunFn {
    for (registry) |entry| {
        if (std.mem.eql(u8, entry.name, name)) return entry.run;
    }
    return null;
}

pub fn dispatch(
    name: []const u8,
    gpa: std.mem.Allocator,
    dev: *Device,
    state: *EventState,
    args: []const u8,
) !bool {
    const fn_ptr = find(name) orelse return false;
    try fn_ptr(gpa, dev, state, args);
    return true;
}

test {
    std.testing.refAllDecls(@This());
}

test "dispatch input_id returns true" {
    const testfs = @import("testfs.zig");
    const context = @import("context.zig");
    const input_id_mod = @import("builtins/input_id.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const ev_str = try input_id_mod.fmtBitmapWords(gpa, &.{ 0x01, 0x02 });
    defer gpa.free(ev_str);
    const key_str = try input_id_mod.fmtBitmapWords(gpa, &.{0x110});
    defer gpa.free(key_str);
    const rel_str = try input_id_mod.fmtBitmapWords(gpa, &.{ 0x00, 0x01 });
    defer gpa.free(rel_str);

    const syspath = try testfs.makeSysfs(&tmp, .{
        .name = "mouse1",
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

    const found = try dispatch("input_id", gpa, &dev, &state, "");
    try std.testing.expect(found);
    try std.testing.expectEqualStrings("1", state.getProperty("ID_INPUT").?);
}

test "dispatch unknown builtin returns false" {
    const context = @import("context.zig");
    const testfs = @import("testfs.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const syspath = try testfs.makeSysfs(&tmp, .{
        .name = "nope0",
        .subsystem = "input",
        .uevent = "",
    });
    defer gpa.free(syspath);

    var ctx = context.Context.init(gpa, io);
    defer ctx.deinit();
    var dev = try Device.fromSyspath(&ctx, syspath);
    defer dev.deinit();

    var state = EventState.init(gpa);
    defer state.deinit();

    const found = try dispatch("nope", gpa, &dev, &state, "");
    try std.testing.expect(!found);
}
