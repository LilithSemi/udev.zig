const std = @import("std");

/// The root udev handle. Holds the allocator and the `std.Io` used for all filesystem and socket
/// IO. Ownership is idiomatic Zig: `init` takes the allocator + io, `deinit` releases anything the
/// context owns. The context keeps no owned state here today, so `deinit` is a no-op, but the method
/// exists so the API stays stable as the context grows (e.g. a shared sysfs handle or udev-db cache).
pub const Context = struct {
    gpa: std.mem.Allocator,
    io: std.Io,

    pub fn init(gpa: std.mem.Allocator, io: std.Io) Context {
        return .{ .gpa = gpa, .io = io };
    }

    pub fn deinit(self: *Context) void {
        _ = self;
    }
};

test "Context holds allocator and io" {
    var ctx = Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();
    try std.testing.expect(ctx.gpa.ptr == std.testing.allocator.ptr);
}
