//! Root of the pure-Zig libudev reimplementation (one `udev` module). Consumers reach the
//! pieces as namespaces: `udev.enumerate`, `udev.monitor`, `udev.device`, etc. The
//! client library covers the device model, sysfs enumeration, and the netlink uevent
//! monitor. Zero C deps.

const std = @import("std");

pub const linux = @import("udev/linux.zig");
pub const uevent = @import("udev/uevent.zig");
pub const context = @import("udev/context.zig");
pub const device = @import("udev/device.zig");
pub const enumerate = @import("udev/enumerate.zig");
pub const monitor = @import("udev/monitor.zig");
pub const rules = @import("udev/rules.zig");
pub const hwdb = @import("udev/hwdb.zig");
pub const builtins = @import("udev/builtins.zig");
pub const daemon = @import("udev/daemon.zig");
pub const udev_db = @import("udev/udev_db.zig");
pub const udevadm = @import("udev/udevadm.zig");

pub const Context = context.Context;
pub const Device = device.Device;
pub const Enumerate = enumerate.Enumerate;
pub const Monitor = monitor.Monitor;
pub const Source = monitor.Source;
pub const RuleSet = rules.RuleSet;
pub const Hwdb = hwdb.Hwdb;

test {
    std.testing.refAllDecls(@This());
}
