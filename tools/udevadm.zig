//! udevadm - the udev management/query CLI. Thin dispatch over the udev.udevadm library.
const std = @import("std");
const udev = @import("udev");

const usage_str =
    \\Usage: udevadm <command> [options]
    \\
    \\  info          query the udev database and sysfs for a device
    \\  test          simulate a rule run for a device (dry run)
    \\  test-builtin  run a single builtin and print the properties it sets
    \\  monitor       listen for events on netlink
    \\  trigger       request device events (re-emit uevents)
    \\  settle        wait for the event queue to drain
    \\
;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;

    var obuf: [8192]u8 = undefined;
    var out = std.Io.File.stdout().writer(io, &obuf);
    const w = &out.interface;

    var ebuf: [512]u8 = undefined;
    var errf = std.Io.File.stderr().writer(io, &ebuf);
    const ew = &errf.interface;

    var argv = std.ArrayList([]const u8).empty;
    defer argv.deinit(gpa);
    var it = init.minimal.args.iterate();
    _ = it.next(); // program name
    while (it.next()) |a| try argv.append(gpa, a);

    const opts = udev.udevadm.parseArgs(argv.items);
    if (opts.parse_error) |e| {
        try ew.print("udevadm: {s}\n", .{e});
        try ew.writeAll(usage_str);
        try ew.flush();
        std.process.exit(2);
    }

    // Non-zero exit on failure so scripts (e.g. `udevadm settle || ...`) work like real udevadm.
    var exit_code: u8 = 0;
    switch (opts.cmd.?) {
        .help => try w.writeAll(usage_str),
        .version => try w.writeAll("udevadm.zig 0.1\n"),
        .info => try udev.udevadm.info(gpa, io, opts, w),
        .test_builtin => {
            if (opts.positional == null or opts.positional2 == null) {
                try ew.writeAll("udevadm: test-builtin needs <builtin> <syspath>\n");
                exit_code = 2;
            } else {
                const ok = try udev.udevadm.testBuiltin(gpa, io, opts.positional.?, opts.positional2.?, w);
                if (!ok) {
                    try ew.print("udevadm: unknown builtin '{s}'\n", .{opts.positional.?});
                    exit_code = 1;
                }
            }
        },
        .test_cmd => try udev.udevadm.testCmd(gpa, io, opts, w),
        .settle => {
            const ok = try udev.udevadm.settleCmd(io, opts.run_root, opts.timeout_sec, opts.exit_if_exists);
            if (!ok) {
                try ew.writeAll("udevadm: settle timed out\n");
                exit_code = 1;
            }
        },
        .trigger => try udev.udevadm.triggerCmd(gpa, io, opts, w),
        .monitor => try udev.udevadm.monitorCmd(gpa, io, opts, w),
    }
    try w.flush();
    try ew.flush();
    if (exit_code != 0) std.process.exit(exit_code);
}
