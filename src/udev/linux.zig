const std = @import("std");

pub const Group = enum(u32) { kernel = 1, udev = 2 };
pub const netlink_kobject_uevent = std.os.linux.NETLINK.KOBJECT_UEVENT;
pub const sys_root = "/sys";

pub fn nlAddr(groups: u32) std.os.linux.sockaddr.nl {
    return .{ .pid = 0, .groups = groups };
}

pub fn subsystemFromLink(link: []const u8) []const u8 {
    return std.fs.path.basename(link);
}

test "subsystemFromLink takes basename" {
    try std.testing.expectEqualStrings("input", subsystemFromLink("../../../../class/input"));
    try std.testing.expectEqualStrings("block", subsystemFromLink("/sys/class/block"));
}

test "Group values match kernel netlink group masks" {
    try std.testing.expectEqual(@as(u32, 1), @intFromEnum(Group.kernel));
    try std.testing.expectEqual(@as(u32, 2), @intFromEnum(Group.udev));
}
