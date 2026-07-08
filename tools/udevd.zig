//! udevd - the udev device manager daemon.
//!
//! Wires the pure-Zig udev stack into a live event loop: it listens for kernel uevents on netlink,
//! evaluates the loaded rules against each device, persists the result to the udev database, actuates
//! the /dev node + symlinks, and rebroadcasts the processed event to .udev-group (libudev) clients.
//!
//! Requires root: netlink kernel-group membership and mknod both need privilege. The testable core is
//! `udev.daemon.Daemon.processDevice` (exercised without root in the library test suite).

const std = @import("std");
const udev = @import("udev");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    var ebuf: [512]u8 = undefined;
    var errf = std.Io.File.stderr().writer(io, &ebuf);
    const ew = &errf.interface;

    var ctx = udev.Context.init(gpa, io);
    defer ctx.deinit();

    var daemon = try udev.daemon.Daemon.init(gpa, io, .{});
    defer daemon.deinit();

    // Rebroadcast to libudev clients is best-effort: run without it if we lack netlink send privilege.
    // `daemon` borrows `bc` by pointer. This is sound because Daemon.deinit does NOT touch broadcaster,
    // so the LIFO deinit of `bc` before `daemon` is not a use-after-free.
    var bc: ?udev.daemon.netlink_broadcast.Broadcaster =
        udev.daemon.netlink_broadcast.Broadcaster.init() catch null;
    defer if (bc) |*b| b.deinit();
    if (bc) |*b| daemon.broadcaster = b;

    // Populate the udev db and /dev for devices already present in sysfs.
    daemon.coldplug(null) catch {};

    // Create kernel static device nodes (best-effort, needs root to mknod).
    {
        var relbuf: [128]u8 = undefined;
        if (std.Io.Dir.cwd().readFileAlloc(io, "/proc/sys/kernel/osrelease", gpa, .limited(256))) |rel| {
            defer gpa.free(rel);
            const release = std.mem.trim(u8, rel, " \t\r\n");
            const p = std.fmt.bufPrint(&relbuf, "/lib/modules/{s}/modules.devname", .{release}) catch null;
            if (p) |path| udev.daemon.static_nodes.createStaticNodes(gpa, io, path, "/dev") catch {};
        } else |_| {}
    }

    var watch_inst: ?udev.daemon.watcher.Watcher = udev.daemon.watcher.Watcher.init() catch null;
    defer if (watch_inst) |*wch| wch.deinit(gpa);
    if (watch_inst) |*wch| daemon.watcher = wch;

    var mon = udev.Monitor.initNetlink(&ctx, .kernel) catch |e| {
        ew.print("udevd: cannot open netlink monitor: {s}\n", .{@errorName(e)}) catch {};
        ew.flush() catch {};
        return;
    };
    defer mon.deinit();

    while (true) {
        // Poll both the netlink monitor fd and the inotify watcher fd (if present).
        var pfds_buf: [2]std.posix.pollfd = .{
            .{ .fd = mon.fd(), .events = std.posix.POLL.IN, .revents = 0 },
            .{ .fd = if (watch_inst) |*wch| wch.fd() else -1, .events = std.posix.POLL.IN, .revents = 0 },
        };
        const nfds: usize = if (watch_inst != null) 2 else 1;
        const nready = std.posix.poll(pfds_buf[0..nfds], -1) catch break;
        if (nready == 0) continue;

        // Monitor fd ready: drain receiveDevice.
        if ((pfds_buf[0].revents & @as(i16, std.posix.POLL.IN)) != 0) {
            while (mon.receiveDevice() catch null) |device| {
                var dev = device;
                defer dev.deinit();
                daemon.processDevice(&dev) catch continue;
            }
        }
        // Error on monitor fd: exit loop.
        const err_mask: i16 = std.posix.POLL.ERR | std.posix.POLL.HUP | std.posix.POLL.NVAL;
        if ((pfds_buf[0].revents & err_mask) != 0) break;

        // Watcher fd ready: re-process affected devices as "change".
        if (nfds > 1 and (pfds_buf[1].revents & @as(i16, std.posix.POLL.IN)) != 0) {
            daemon.handleWatchEvents() catch {};
        }
    }

    ew.writeAll("udevd: monitor loop ended\n") catch {};
    ew.flush() catch {};
}
