const std = @import("std");
const Context = @import("context.zig").Context;
const Device = @import("device.zig").Device;
const Enumerate = @import("enumerate.zig").Enumerate;
const Monitor = @import("monitor.zig").Monitor;
const Source = @import("monitor.zig").Source;
const udev_db = @import("udev_db.zig");
const EventState = @import("rules/runner.zig").EventState;
const builtins = @import("builtins.zig");
const rules = @import("rules.zig");
const rules_loader = @import("daemon/rules_loader.zig");
const ExecRunner = @import("daemon/exec_runner.zig").ExecRunner;

pub const Command = enum { info, test_cmd, test_builtin, monitor, trigger, settle, help, version };

pub const Query = enum { all, property, name, symlink, path };

pub const Options = struct {
    cmd: ?Command = null,
    query: Query = .all,
    path: ?[]const u8 = null,
    name: ?[]const u8 = null,
    attribute_walk: bool = false,
    export_: bool = false,
    run_root: []const u8 = "/run/udev",
    positional: ?[]const u8 = null,
    positional2: ?[]const u8 = null,
    action: []const u8 = "add",
    parse_error: ?[]const u8 = null,
    subsystem_match: ?[]const u8 = null,
    dry_run: bool = false,
    trigger_type: []const u8 = "devices",
    timeout_sec: u32 = 120,
    exit_if_exists: ?[]const u8 = null,
    source_kernel: bool = false,
    source_udev: bool = false,
    print_properties: bool = false,
};

fn parseCommand(s: []const u8) ?Command {
    if (std.mem.eql(u8, s, "info")) return .info;
    if (std.mem.eql(u8, s, "test")) return .test_cmd;
    if (std.mem.eql(u8, s, "test-builtin")) return .test_builtin;
    if (std.mem.eql(u8, s, "monitor")) return .monitor;
    if (std.mem.eql(u8, s, "trigger")) return .trigger;
    if (std.mem.eql(u8, s, "settle")) return .settle;
    if (std.mem.eql(u8, s, "help") or std.mem.eql(u8, s, "--help") or std.mem.eql(u8, s, "-h")) return .help;
    if (std.mem.eql(u8, s, "--version") or std.mem.eql(u8, s, "-V")) return .version;
    return null;
}

fn parseQuery(s: []const u8) ?Query {
    if (std.mem.eql(u8, s, "all")) return .all;
    if (std.mem.eql(u8, s, "property")) return .property;
    if (std.mem.eql(u8, s, "name")) return .name;
    if (std.mem.eql(u8, s, "symlink")) return .symlink;
    if (std.mem.eql(u8, s, "path")) return .path;
    return null;
}

/// Parse udevadm args (argv WITHOUT the program name). argv[0] is the subcommand.
/// Usage errors set `parse_error` and stop; the caller reports it. No heap allocation.
pub fn parseArgs(argv: []const []const u8) Options {
    var opts = Options{};
    if (argv.len == 0) {
        opts.parse_error = "no subcommand given";
        return opts;
    }
    opts.cmd = parseCommand(argv[0]);
    if (opts.cmd == null) {
        opts.parse_error = "unknown command";
        return opts;
    }
    var i: usize = 1;
    while (i < argv.len) : (i += 1) {
        const a = argv[i];
        if (std.mem.startsWith(u8, a, "--query=")) {
            const mode = a["--query=".len..];
            opts.query = parseQuery(mode) orelse {
                opts.parse_error = "invalid --query mode";
                return opts;
            };
        } else if (std.mem.startsWith(u8, a, "--path=")) {
            opts.path = a["--path=".len..];
        } else if (std.mem.startsWith(u8, a, "--name=")) {
            opts.name = a["--name=".len..];
        } else if (std.mem.eql(u8, a, "-a") or std.mem.eql(u8, a, "--attribute-walk")) {
            opts.attribute_walk = true;
        } else if (std.mem.eql(u8, a, "-x") or std.mem.eql(u8, a, "--export")) {
            opts.export_ = true;
        } else if (std.mem.startsWith(u8, a, "--action=")) {
            const v = a["--action=".len..];
            if (!std.mem.eql(u8, v, "add") and !std.mem.eql(u8, v, "change") and !std.mem.eql(u8, v, "remove")) {
                opts.parse_error = "invalid --action";
                return opts;
            }
            opts.action = v;
        } else if (std.mem.startsWith(u8, a, "--subsystem-match=")) {
            opts.subsystem_match = a["--subsystem-match=".len..];
        } else if (std.mem.eql(u8, a, "-n") or std.mem.eql(u8, a, "--dry-run")) {
            opts.dry_run = true;
        } else if (std.mem.startsWith(u8, a, "--type=")) {
            const v = a["--type=".len..];
            if (!std.mem.eql(u8, v, "devices") and !std.mem.eql(u8, v, "subsystems")) {
                opts.parse_error = "invalid --type";
                return opts;
            }
            opts.trigger_type = v;
        } else if (std.mem.startsWith(u8, a, "--timeout=")) {
            opts.timeout_sec = std.fmt.parseInt(u32, a["--timeout=".len..], 10) catch {
                opts.parse_error = "invalid --timeout";
                return opts;
            };
        } else if (std.mem.startsWith(u8, a, "--exit-if-exists=")) {
            opts.exit_if_exists = a["--exit-if-exists=".len..];
        } else if (std.mem.eql(u8, a, "-k") or std.mem.eql(u8, a, "--kernel")) {
            opts.source_kernel = true;
        } else if (std.mem.eql(u8, a, "-u") or std.mem.eql(u8, a, "--udev")) {
            opts.source_udev = true;
        } else if (std.mem.eql(u8, a, "-p") or std.mem.eql(u8, a, "--property")) {
            opts.print_properties = true;
        } else if (a.len > 0 and a[0] == '-') {
            opts.parse_error = "unknown option";
            return opts;
        } else {
            if (opts.positional == null) {
                opts.positional = a;
            } else if (opts.positional2 == null) {
                opts.positional2 = a;
            } else {
                opts.parse_error = "too many arguments";
                return opts;
            }
        }
    }
    return opts;
}

// Helpers

fn stripDev(s: []const u8) []const u8 {
    if (std.mem.startsWith(u8, s, "/dev/")) return s["/dev/".len..];
    return s;
}

fn sysnum(name: []const u8) []const u8 {
    var i: usize = name.len;
    while (i > 0 and std.ascii.isDigit(name[i - 1])) : (i -= 1) {}
    return name[i..];
}

fn deriveDevpath(syspath: []const u8) []const u8 {
    if (std.mem.startsWith(u8, syspath, "/sys")) return syspath["/sys".len..];
    return syspath;
}

fn lessThanByKey(_: void, a: udev_db.KeyVal, b: udev_db.KeyVal) bool {
    return std.mem.lessThan(u8, a.key, b.key);
}

/// Collect this device's sysattr names (flat files + one level of nested dir/file), sorted.
/// Returns names owned by `aa`.
fn collectAttrNames(aa: std.mem.Allocator, io: std.Io, dev: *Device) ![]const []const u8 {
    var names: std.ArrayListUnmanaged([]const u8) = .empty;
    var d = std.Io.Dir.cwd().openDir(io, dev.syspath(), .{ .iterate = true }) catch return &.{};
    defer d.close(io);
    var it = d.iterateAssumeFirstIteration();
    while (it.next(io) catch null) |entry| {
        if (entry.kind == .sym_link) continue;
        if (entry.kind == .directory) {
            var subbuf: [std.fs.max_path_bytes]u8 = undefined;
            const subpath = std.fmt.bufPrint(&subbuf, "{s}/{s}", .{ dev.syspath(), entry.name }) catch continue;
            // Skip subdirs that are themselves device nodes (uevent present).
            var ue_buf: [std.fs.max_path_bytes]u8 = undefined;
            const ue_path = std.fmt.bufPrint(&ue_buf, "{s}/uevent", .{subpath}) catch continue;
            if (std.Io.Dir.cwd().access(io, ue_path, .{})) |_| continue else |_| {}
            var sd = std.Io.Dir.cwd().openDir(io, subpath, .{ .iterate = true }) catch continue;
            defer sd.close(io);
            var sit = sd.iterateAssumeFirstIteration();
            while (sit.next(io) catch null) |sub| {
                if (sub.kind != .file) continue;
                names.append(aa, std.fmt.allocPrint(aa, "{s}/{s}", .{ entry.name, sub.name }) catch continue) catch {};
            }
        } else if (entry.kind == .file) {
            names.append(aa, aa.dupe(u8, entry.name) catch continue) catch {};
        }
    }
    const slice = try names.toOwnedSlice(aa);
    std.mem.sort([]const u8, slice, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lt);
    return slice;
}

/// Print KERNEL(S)/SUBSYSTEM(S)/DRIVER(S) + ATTR(S){name}=="value" for one device.
fn writeDeviceAttrs(gpa: std.mem.Allocator, io: std.Io, dev: *Device, w: *std.Io.Writer, is_parent: bool) !void {
    const kk = if (is_parent) "KERNELS" else "KERNEL";
    const ks = if (is_parent) "SUBSYSTEMS" else "SUBSYSTEM";
    const kd = if (is_parent) "DRIVERS" else "DRIVER";
    const ka = if (is_parent) "ATTRS" else "ATTR";
    try w.print("    {s}==\"{s}\"\n", .{ kk, dev.sysname() });
    try w.print("    {s}==\"{s}\"\n", .{ ks, (try dev.subsystem()) orelse "" });
    try w.print("    {s}==\"{s}\"\n", .{ kd, (try dev.driver()) orelse "" });

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const aa = arena.allocator();
    const names = try collectAttrNames(aa, io, dev);
    for (names) |name| {
        const val = (dev.getSysattr(name) catch null) orelse continue;
        if (std.mem.indexOfScalar(u8, val, '\n') != null) continue;
        try w.print("    {s}{{{s}}}==\"{s}\"\n", .{ ka, name, val });
    }
}

/// Walk the device and its parent chain, printing attributes in udev-rules key format.
pub fn attributeWalk(gpa: std.mem.Allocator, io: std.Io, dev: *Device, w: *std.Io.Writer) !void {
    try w.writeAll(
        \\
        \\Udevadm info starts with the device specified by the devpath and then
        \\walks up the chain of parent devices. It prints for every device
        \\found, all possible attributes in the udev rules key format.
        \\A rule to match, can be composed by the attributes of the device
        \\and the attributes from one single parent device.
        \\
        \\
    );
    try w.print("  looking at device '{s}':\n", .{deriveDevpath(dev.syspath())});
    try writeDeviceAttrs(gpa, io, dev, w, false);

    var cur: ?Device = dev.parent() catch null;
    while (cur) |p| {
        var pd = p;
        try w.print("\n  looking at parent device '{s}':\n", .{deriveDevpath(pd.syspath())});
        try writeDeviceAttrs(gpa, io, &pd, w, true);
        const next = pd.parent() catch null;
        pd.deinit();
        cur = next;
    }
}

/// Build a sorted, merged property list from dev.props overlaid with any udev db record.
/// All returned strings are allocated via `aa`. Caller owns the slice; free by deiniting the
/// arena that backs `aa`. `gpa` is used for scratch allocations (deviceId, Record) freed here.
fn mergedProperties(
    gpa: std.mem.Allocator,
    aa: std.mem.Allocator,
    io: std.Io,
    run_root: []const u8,
    dev: *Device,
) ![]udev_db.KeyVal {
    var list: std.ArrayListUnmanaged(udev_db.KeyVal) = .empty;

    // 1. Seed list with every dev.props entry.
    var it = dev.props.iterator();
    while (it.next()) |kv| {
        try list.append(aa, .{
            .key = try aa.dupe(u8, kv.key_ptr.*),
            .val = try aa.dupe(u8, kv.value_ptr.*),
        });
    }

    // DEVNAME should be the full node path, matching real udev.
    if (dev.devnode()) |dn| {
        for (list.items) |*item| {
            if (std.mem.eql(u8, item.key, "DEVNAME")) {
                item.val = try aa.dupe(u8, dn);
                break;
            }
        }
    }

    // 2. Overlay db record (db value wins on key clash).
    if (udev_db.deviceId(gpa, dev)) |db_id| {
        defer gpa.free(db_id);
        if (udev_db.read(gpa, io, run_root, db_id)) |rec_val| {
            var rec = rec_val;
            defer rec.deinit();

            for (rec.properties) |kv| {
                var found = false;
                for (list.items) |*item| {
                    if (std.mem.eql(u8, item.key, kv.key)) {
                        item.val = try aa.dupe(u8, kv.val);
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    try list.append(aa, .{
                        .key = try aa.dupe(u8, kv.key),
                        .val = try aa.dupe(u8, kv.val),
                    });
                }
            }

            // 3. Synthesize DEVLINKS = space-joined /dev/<sym>.
            if (rec.symlinks.len > 0) {
                var buf: std.ArrayListUnmanaged(u8) = .empty;
                for (rec.symlinks, 0..) |sym, idx| {
                    if (idx > 0) try buf.append(aa, ' ');
                    try buf.appendSlice(aa, "/dev/");
                    try buf.appendSlice(aa, sym);
                }
                try list.append(aa, .{
                    .key = "DEVLINKS",
                    .val = try buf.toOwnedSlice(aa),
                });
            }

            // 4. Synthesize TAGS = :t1:t2: (unique tags only, since G: and Q: lines share rec.tags).
            if (rec.tags.len > 0) {
                var buf: std.ArrayListUnmanaged(u8) = .empty;
                var seen: std.ArrayListUnmanaged([]const u8) = .empty;
                try buf.append(aa, ':');
                for (rec.tags) |tag| {
                    var already_seen = false;
                    for (seen.items) |s| {
                        if (std.mem.eql(u8, s, tag)) {
                            already_seen = true;
                            break;
                        }
                    }
                    if (already_seen) continue;
                    try seen.append(aa, tag);
                    try buf.appendSlice(aa, tag);
                    try buf.append(aa, ':');
                }
                try list.append(aa, .{
                    .key = "TAGS",
                    .val = try buf.toOwnedSlice(aa),
                });
            }

            // 5. Synthesize CURRENT_TAGS = :t1:t2: from Q: lines (rec.current_tags).
            if (rec.current_tags.len > 0) {
                var cbuf: std.ArrayListUnmanaged(u8) = .empty;
                try cbuf.append(aa, ':');
                for (rec.current_tags) |tag| {
                    try cbuf.appendSlice(aa, tag);
                    try cbuf.append(aa, ':');
                }
                try list.append(aa, .{
                    .key = "CURRENT_TAGS",
                    .val = try cbuf.toOwnedSlice(aa),
                });
            }
        } else |_| {}
    } else |_| {}

    // 6. Sort by key for deterministic output.
    std.mem.sort(udev_db.KeyVal, list.items, {}, lessThanByKey);

    return list.toOwnedSlice(aa);
}

/// Resolve a --name value (a /dev node path, a bare devnode name, or a sysname) to a canonical
/// syspath. Returns gpa-owned memory (caller frees) or null if not found.
fn resolveName(gpa: std.mem.Allocator, io: std.Io, name: []const u8) !?[]u8 {
    const bare = if (std.mem.startsWith(u8, name, "/dev/")) name["/dev/".len..] else name;
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    var rp: [std.fs.max_path_bytes]u8 = undefined;

    // Direct candidate: /sys/block/<bare>.
    const direct = std.fmt.bufPrint(&buf, "/sys/block/{s}", .{bare}) catch return null;
    if (std.Io.Dir.cwd().realPathFile(io, direct, &rp)) |n| {
        return try gpa.dupe(u8, rp[0..n]);
    } else |_| {}

    // Scan /sys/class/<subsys>/<bare>.
    var class_dir = std.Io.Dir.cwd().openDir(io, "/sys/class", .{ .iterate = true }) catch return null;
    defer class_dir.close(io);
    var it = class_dir.iterateAssumeFirstIteration();
    while (it.next(io) catch null) |entry| {
        const cand = std.fmt.bufPrint(&buf, "/sys/class/{s}/{s}", .{ entry.name, bare }) catch continue;
        if (std.Io.Dir.cwd().realPathFile(io, cand, &rp)) |n| {
            return try gpa.dupe(u8, rp[0..n]);
        } else |_| {}
    }
    return null;
}

/// Render `udevadm info` output for the device described by opts to writer w.
pub fn info(gpa: std.mem.Allocator, io: std.Io, opts: Options, w: *std.Io.Writer) !void {
    // Resolve the target syspath from --path / positional / --name.
    var owned_name: ?[]u8 = null;
    defer if (owned_name) |s| gpa.free(s);
    const raw_syspath = opts.path orelse opts.positional orelse blk: {
        if (opts.name) |n| {
            owned_name = (try resolveName(gpa, io, n)) orelse return;
            break :blk owned_name.?;
        }
        return;
    };

    // Canonicalize so DEVPATH derivation works for /sys/class symlink inputs.
    var canon_buf: [std.fs.max_path_bytes]u8 = undefined;
    const syspath = if (std.Io.Dir.cwd().realPathFile(io, raw_syspath, &canon_buf)) |n| canon_buf[0..n] else |_| raw_syspath;

    var ctx = Context.init(gpa, io);
    defer ctx.deinit();

    var dev = Device.fromSyspath(&ctx, syspath) catch return;
    defer dev.deinit();

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const aa = arena.allocator();

    if (opts.attribute_walk) {
        try attributeWalk(gpa, io, &dev, w);
        return;
    }

    switch (opts.query) {
        .path => {
            const devpath = dev.getProperty("DEVPATH") orelse deriveDevpath(syspath);
            try w.print("{s}\n", .{devpath});
        },
        .name => {
            if (dev.devnode()) |dn| try w.print("{s}\n", .{stripDev(dn)});
        },
        .symlink => {
            // Read db for symlinks. Missing db means no symlinks.
            const db_symlinks: []const []const u8 = blk: {
                const did = udev_db.deviceId(gpa, &dev) catch break :blk &.{};
                defer gpa.free(did);
                var rec = udev_db.read(gpa, io, opts.run_root, did) catch break :blk &.{};
                defer rec.deinit();
                // Dupe symlinks into arena so they survive rec.deinit().
                const syms = try aa.dupe([]const u8, rec.symlinks);
                for (syms, 0..) |sym, i| syms[i] = try aa.dupe(u8, sym);
                break :blk syms;
            };
            for (db_symlinks, 0..) |sym, i| {
                if (i > 0) try w.writeAll(" ");
                try w.writeAll(sym);
            }
            try w.writeAll("\n");
        },
        .property => {
            const props = try mergedProperties(gpa, aa, io, opts.run_root, &dev);
            for (props) |kv| {
                if (opts.export_) {
                    try w.print("{s}='{s}'\n", .{ kv.key, kv.val });
                } else {
                    try w.print("{s}={s}\n", .{ kv.key, kv.val });
                }
            }
        },
        .all => {
            const devpath = dev.getProperty("DEVPATH") orelse deriveDevpath(syspath);
            try w.print("P: {s}\n", .{devpath});
            try w.print("M: {s}\n", .{dev.sysname()});
            const num = sysnum(dev.sysname());
            if (num.len > 0) try w.print("R: {s}\n", .{num});
            if (udev_db.deviceId(gpa, &dev)) |jid| {
                defer gpa.free(jid);
                try w.print("J: {s}\n", .{jid});
            } else |_| {}
            const sub = try dev.subsystem();
            if (sub) |s| try w.print("U: {s}\n", .{s});
            if (dev.devtype()) |dt| try w.print("T: {s}\n", .{dt});
            if (dev.getProperty("MAJOR")) |maj| {
                if (dev.getProperty("MINOR")) |min| {
                    const is_block = sub != null and std.mem.eql(u8, sub.?, "block");
                    try w.print("D: {c} {s}:{s}\n", .{ @as(u8, if (is_block) 'b' else 'c'), maj, min });
                }
            }
            if (dev.devnode()) |dn| {
                try w.print("N: {s}\n", .{stripDev(dn)});
                try w.writeAll("L: 0\n");
            }
            // S: lines: read db for symlinks, a separate read that avoids coupling with mergedProperties.
            {
                const did = udev_db.deviceId(gpa, &dev) catch null;
                if (did) |id| {
                    defer gpa.free(id);
                    if (udev_db.read(gpa, io, opts.run_root, id)) |rec_val| {
                        var rec = rec_val;
                        defer rec.deinit();
                        for (rec.symlinks) |sym| {
                            try w.print("S: {s}\n", .{sym});
                        }
                    } else |_| {}
                }
            }
            // E: lines from mergedProperties.
            const props = try mergedProperties(gpa, aa, io, opts.run_root, &dev);
            for (props) |kv| {
                try w.print("E: {s}={s}\n", .{ kv.key, kv.val });
            }
        },
    }
}

/// Run a single builtin against the device at `syspath` and print the properties it sets
/// (sorted KEY=value). Returns false if the builtin name is unknown (caller reports it).
pub fn testBuiltin(gpa: std.mem.Allocator, io: std.Io, name: []const u8, syspath: []const u8, w: *std.Io.Writer) !bool {
    var ctx = Context.init(gpa, io);
    defer ctx.deinit();
    var dev = Device.fromSyspath(&ctx, syspath) catch return true; // bad path -> nothing printed, not "unknown"
    defer dev.deinit();

    var state = EventState.init(gpa);
    defer state.deinit();

    const ran = try builtins.dispatch(name, gpa, &dev, &state, "");
    if (!ran) return false;

    // Print exactly what the builtin set (do NOT seed ACTION), sorted by key.
    var list: std.ArrayListUnmanaged(udev_db.KeyVal) = .empty;
    defer list.deinit(gpa);
    var it = state.properties.iterator();
    while (it.next()) |kv| try list.append(gpa, .{ .key = kv.key_ptr.*, .val = kv.value_ptr.* });
    std.mem.sort(udev_db.KeyVal, list.items, {}, lessThanByKey);
    for (list.items) |kv| try w.print("{s}={s}\n", .{ kv.key, kv.val });
    return true;
}

/// Dry-run: evaluate `ruleset` against `dev` (ACTION injected) and print the outcome. No actuation.
pub fn testDevice(gpa: std.mem.Allocator, io: std.Io, ruleset: *const rules.RuleSet, dev: *Device, action: []const u8, w: *std.Io.Writer) !void {
    if (dev.props.get("ACTION") == null) {
        const a = dev.arena.allocator();
        try dev.props.put(a, try a.dupe(u8, "ACTION"), try a.dupe(u8, action));
    }

    var exec = ExecRunner{ .gpa = gpa, .io = io, .hwdb = null, .helper_dirs = &.{ "/usr/lib/udev", "/lib/udev" } };
    var state = try ruleset.apply(gpa, dev, exec.runner());
    defer state.deinit();

    if (state.name) |n| try w.print("Named: {s}\n", .{n});

    if (state.symlinks.items.len > 0) {
        try w.writeAll("Device node symlinks:\n");
        for (state.symlinks.items) |sym| try w.print("  /dev/{s}\n", .{sym});
    }

    if (state.tags.count() > 0) {
        // state.tags is a hash set, so keys are already unique (no dedup needed, unlike the
        // udev_db.Record.tags slice which can carry the same tag from both G: and Q: lines).
        try w.writeAll("Tags:\n");
        var tit = state.tags.iterator();
        while (tit.next()) |e| try w.print("  {s}\n", .{e.key_ptr.*});
    }

    if (state.run_list.items.len > 0) {
        try w.writeAll("Run commands:\n");
        for (state.run_list.items) |r| try w.print("  {s}\n", .{r.command});
    }

    try w.writeAll("Properties:\n");
    var list: std.ArrayListUnmanaged(udev_db.KeyVal) = .empty;
    defer list.deinit(gpa);
    var it = state.properties.iterator();
    while (it.next()) |kv| try list.append(gpa, .{ .key = kv.key_ptr.*, .val = kv.value_ptr.* });
    std.mem.sort(udev_db.KeyVal, list.items, {}, lessThanByKey);
    for (list.items) |kv| try w.print("  {s}={s}\n", .{ kv.key, kv.val });
}

/// CLI entry: load rules from the standard dirs, build the device, dry-run it.
pub fn testCmd(gpa: std.mem.Allocator, io: std.Io, opts: Options, w: *std.Io.Writer) !void {
    const syspath = opts.path orelse opts.positional orelse return;
    var ruleset = rules_loader.load(gpa, io, .{ .dirs = &rules_loader.default_dirs }) catch return;
    defer ruleset.deinit();
    var ctx = Context.init(gpa, io);
    defer ctx.deinit();
    var dev = Device.fromSyspath(&ctx, syspath) catch return;
    defer dev.deinit();
    try testDevice(gpa, io, &ruleset, &dev, opts.action, w);
}

// settle + trigger

/// True when the udev queue is drained: `<run_root>/queue` does not exist (how real udev signals idle).
/// If `exit_if_exists` names a path that exists, also returns true immediately.
pub fn queueEmpty(io: std.Io, run_root: []const u8, exit_if_exists: ?[]const u8) bool {
    if (exit_if_exists) |f| {
        if (std.Io.Dir.cwd().access(io, f, .{})) |_| return true else |_| {}
    }
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const q = std.fmt.bufPrint(&buf, "{s}/queue", .{run_root}) catch return false;
    if (std.Io.Dir.cwd().access(io, q, .{})) |_| return false else |_| return true;
}

/// Poll until the queue drains, the exit-file appears, or the timeout elapses. Returns true if drained.
pub fn settleCmd(io: std.Io, run_root: []const u8, timeout_sec: u32, exit_if_exists: ?[]const u8) !bool {
    var waited_ms: u64 = 0;
    const limit: u64 = @as(u64, timeout_sec) * 1000;
    while (true) {
        if (queueEmpty(io, run_root, exit_if_exists)) return true;
        if (waited_ms >= limit) return false;
        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(200), .awake) catch return false;
        waited_ms += 200;
    }
}

/// Enumerate matching devices; print each syspath (dry-run) or re-emit its uevent (actuate, root-gated).
/// When --type=subsystems, walks /sys/bus and /sys/class for subsystem dirs that have a uevent file.
pub fn triggerList(gpa: std.mem.Allocator, io: std.Io, opts: Options, sys_root: ?[]const u8, w: *std.Io.Writer, actuate: bool) !void {
    if (std.mem.eql(u8, opts.trigger_type, "subsystems")) {
        // --subsystem-match limits which subsystems are triggered (matched by directory name).
        const base = sys_root orelse "/sys";
        const kinds = [_][]const u8{ "bus", "class" };
        for (kinds) |kind| {
            const dirpath = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ base, kind });
            defer gpa.free(dirpath);
            var d = std.Io.Dir.cwd().openDir(io, dirpath, .{ .iterate = true }) catch continue;
            defer d.close(io);
            var it = d.iterateAssumeFirstIteration();
            while (it.next(io) catch null) |entry| {
                if (opts.subsystem_match) |m| {
                    if (!std.mem.eql(u8, entry.name, m)) continue;
                }
                const subpath = try std.fmt.allocPrint(gpa, "{s}/{s}/{s}", .{ base, kind, entry.name });
                defer gpa.free(subpath);
                const uev = try std.fmt.allocPrint(gpa, "{s}/uevent", .{subpath});
                defer gpa.free(uev);
                std.Io.Dir.cwd().access(io, uev, .{}) catch continue;
                if (!actuate) {
                    try w.print("{s}\n", .{subpath});
                } else {
                    const data = try std.fmt.allocPrint(gpa, "{s}\n", .{opts.action});
                    defer gpa.free(data);
                    std.Io.Dir.cwd().writeFile(io, .{ .sub_path = uev, .data = data }) catch {};
                }
            }
        }
        return;
    }
    var ctx = Context.init(gpa, io);
    defer ctx.deinit();
    var en = Enumerate.init(&ctx);
    defer en.deinit();
    if (sys_root) |r| try en.setSysRoot(r);
    if (opts.subsystem_match) |s| try en.addMatchSubsystem(s);
    try en.scanDevices();
    var it = en.devices();
    while (it.next()) |syspath| {
        if (!actuate) {
            try w.print("{s}\n", .{syspath});
        } else {
            const p = try std.fmt.allocPrint(gpa, "{s}/uevent", .{syspath});
            defer gpa.free(p);
            const data = try std.fmt.allocPrint(gpa, "{s}\n", .{opts.action});
            defer gpa.free(data);
            std.Io.Dir.cwd().writeFile(io, .{ .sub_path = p, .data = data }) catch {};
        }
    }
}

pub fn triggerCmd(gpa: std.mem.Allocator, io: std.Io, opts: Options, w: *std.Io.Writer) !void {
    try triggerList(gpa, io, opts, null, w, !opts.dry_run);
}

// monitor

const MonSel = struct { kernel: bool, udev: bool };

/// Which sources to monitor: no flag = both; a single flag = just that one.
fn monitorSources(opts: Options) MonSel {
    const both = !opts.source_kernel and !opts.source_udev;
    return .{ .kernel = opts.source_kernel or both, .udev = opts.source_udev or both };
}

/// Print the monitor header for the selected sources (UDEV listed before KERNEL, matching real udevadm).
fn writeMonitorHeader(w: *std.Io.Writer, sel: MonSel) !void {
    try w.writeAll("monitor will print the received events for:\n");
    if (sel.udev) try w.writeAll("UDEV - the event which udev sends out after rule processing\n");
    if (sel.kernel) try w.writeAll("KERNEL - the kernel uevent\n");
    try w.writeAll("\n");
}

/// Format one monitor event line, close to real `udevadm monitor`:
///   "UDEV[1234.000005] add /devices/x/sda (block)\n"
pub fn formatEventLine(w: *std.Io.Writer, label: []const u8, mono_usec: u64, dev: *Device) !void {
    const action = dev.getProperty("ACTION") orelse "";
    const devpath = dev.getProperty("DEVPATH") orelse dev.syspath();
    const sub = dev.getProperty("SUBSYSTEM") orelse "";
    try w.print("{s}[{d}.{d:0>6}] {s} {s} ({s})\n", .{ label, mono_usec / 1_000_000, mono_usec % 1_000_000, action, devpath, sub });
}

fn monoUsec() u64 {
    var ts: std.os.linux.timespec = undefined;
    const rc = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    if (std.os.linux.errno(rc) != .SUCCESS) return 0;
    if (ts.sec < 0) return 0;
    return @as(u64, @intCast(ts.sec)) * 1_000_000 + @as(u64, @intCast(@divTrunc(ts.nsec, 1000)));
}

/// Poll both kernel and udev netlink groups by default; --kernel or --udev selects one.
/// Netlink/root-gated: if no socket can open, print a note and return.
pub fn monitorCmd(gpa: std.mem.Allocator, io: std.Io, opts: Options, w: *std.Io.Writer) !void {
    const sel = monitorSources(opts);
    try writeMonitorHeader(w, sel);
    try w.flush();

    var ctx = Context.init(gpa, io);
    defer ctx.deinit();

    const Sub = struct { mon: Monitor, label: []const u8 };
    var subs: [2]Sub = undefined;
    var count: usize = 0;
    if (sel.udev) {
        if (Monitor.initNetlink(&ctx, .udev)) |m| {
            subs[count] = .{ .mon = m, .label = "UDEV" };
            count += 1;
        } else |_| {}
    }
    if (sel.kernel) {
        if (Monitor.initNetlink(&ctx, .kernel)) |m| {
            subs[count] = .{ .mon = m, .label = "KERNEL" };
            count += 1;
        } else |_| {}
    }
    if (count == 0) {
        try w.writeAll("(cannot open netlink monitor)\n");
        try w.flush();
        return;
    }
    defer for (subs[0..count]) |*s| s.mon.deinit();

    if (opts.subsystem_match) |match| {
        for (subs[0..count]) |*s| try s.mon.addMatchSubsystemDevtype(match, null);
    }

    while (true) {
        var pfds: [2]std.posix.pollfd = undefined;
        for (subs[0..count], 0..) |*s, i| {
            pfds[i] = .{ .fd = s.mon.fd(), .events = std.posix.POLL.IN, .revents = 0 };
        }
        // std.posix.poll handles EINTR internally. Its error set has no Interrupted to catch.
        _ = std.posix.poll(pfds[0..count], -1) catch break;
        for (subs[0..count], 0..) |*s, i| {
            if ((pfds[i].revents & @as(i16, std.posix.POLL.IN)) == 0) continue;
            while (s.mon.receiveDevice() catch break) |d| {
                var dev = d;
                defer dev.deinit();
                try formatEventLine(w, s.label, monoUsec(), &dev);
                if (opts.print_properties) {
                    var it = dev.props.iterator();
                    while (it.next()) |kv| try w.print("{s}={s}\n", .{ kv.key_ptr.*, kv.value_ptr.* });
                    try w.writeAll("\n");
                }
                try w.flush();
            }
        }
    }
}

// Tests

const testing = std.testing;

test "parseArgs (a): info with query and path" {
    const opts = parseArgs(&.{ "info", "--query=property", "--path=/sys/x" });
    try testing.expectEqual(Command.info, opts.cmd.?);
    try testing.expectEqual(Query.property, opts.query);
    try testing.expectEqualStrings("/sys/x", opts.path.?);
    try testing.expect(opts.parse_error == null);
}

test "parseArgs (b): info with -a and -x flags" {
    const opts = parseArgs(&.{ "info", "--query=all", "-a", "-x" });
    try testing.expectEqual(Query.all, opts.query);
    try testing.expect(opts.attribute_walk);
    try testing.expect(opts.export_);
}

test "parseArgs (c): info with positional" {
    const opts = parseArgs(&.{ "info", "/sys/class/block/sda" });
    try testing.expectEqual(Command.info, opts.cmd.?);
    try testing.expectEqualStrings("/sys/class/block/sda", opts.positional.?);
}

test "parseArgs (d): invalid query mode sets parse_error" {
    const opts = parseArgs(&.{ "info", "--query=bogus" });
    try testing.expect(opts.parse_error != null);
}

test "parseArgs (e): unknown command and empty argv set parse_error" {
    {
        const opts = parseArgs(&.{"frobnicate"});
        try testing.expect(opts.cmd == null);
        try testing.expect(opts.parse_error != null);
    }
    {
        const opts = parseArgs(&.{});
        try testing.expect(opts.parse_error != null);
    }
}

test "parseArgs (f): --version and monitor" {
    {
        const opts = parseArgs(&.{"--version"});
        try testing.expectEqual(Command.version, opts.cmd.?);
    }
    {
        const opts = parseArgs(&.{"monitor"});
        try testing.expectEqual(Command.monitor, opts.cmd.?);
    }
}

// info renderer tests

test "info (a): --query=property no db returns sorted props" {
    const testfs = @import("testfs.zig");
    const io = testing.io;
    const gpa = testing.allocator;

    var sysfs_tmp = std.testing.tmpDir(.{});
    defer sysfs_tmp.cleanup();

    var run_tmp = std.testing.tmpDir(.{});
    defer run_tmp.cleanup();

    const syspath = try testfs.makeSysfs(&sysfs_tmp, .{
        .name = "sda",
        .subsystem = "block",
        .uevent = "DEVNAME=sda\nMAJOR=8\nMINOR=0\nSUBSYSTEM=block\nDEVTYPE=disk\n",
    });
    defer gpa.free(syspath);

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try run_tmp.dir.realPathFile(io, ".", &rp_buf);
    const run_root = rp_buf[0..n];

    var buf: [4096]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);

    try info(gpa, io, .{
        .cmd = .info,
        .query = .property,
        .path = syspath,
        .run_root = run_root,
    }, &w);

    try testing.expectEqualStrings(
        "DEVNAME=/dev/sda\nDEVTYPE=disk\nMAJOR=8\nMINOR=0\nSUBSYSTEM=block\n",
        w.buffered(),
    );
}

test "info (b): --query=name and --query=path" {
    const testfs = @import("testfs.zig");
    const io = testing.io;
    const gpa = testing.allocator;

    var sysfs_tmp = std.testing.tmpDir(.{});
    defer sysfs_tmp.cleanup();

    var run_tmp = std.testing.tmpDir(.{});
    defer run_tmp.cleanup();

    const syspath = try testfs.makeSysfs(&sysfs_tmp, .{
        .name = "sda",
        .subsystem = "block",
        .uevent = "DEVNAME=sda\nMAJOR=8\nMINOR=0\nSUBSYSTEM=block\nDEVTYPE=disk\n",
    });
    defer gpa.free(syspath);

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try run_tmp.dir.realPathFile(io, ".", &rp_buf);
    const run_root = rp_buf[0..n];

    // --query=name
    {
        var buf: [256]u8 = undefined;
        var w = std.Io.Writer.fixed(&buf);
        try info(gpa, io, .{
            .cmd = .info,
            .query = .name,
            .path = syspath,
            .run_root = run_root,
        }, &w);
        try testing.expectEqualStrings("sda\n", w.buffered());
    }

    // --query=path (no DEVPATH property, derives from syspath)
    {
        var buf: [1024]u8 = undefined;
        var w = std.Io.Writer.fixed(&buf);
        try info(gpa, io, .{
            .cmd = .info,
            .query = .path,
            .path = syspath,
            .run_root = run_root,
        }, &w);
        const out = w.buffered();
        // syspath is an abs tmpdir path (not under /sys), so devpath == syspath.
        var expected_buf: [std.fs.max_path_bytes + 2]u8 = undefined;
        const expected = try std.fmt.bufPrint(&expected_buf, "{s}\n", .{syspath});
        try testing.expectEqualStrings(expected, out);
    }
}

test "info (c): --query=symlink with db" {
    const testfs = @import("testfs.zig");
    const io = testing.io;
    const gpa = testing.allocator;

    var sysfs_tmp = std.testing.tmpDir(.{});
    defer sysfs_tmp.cleanup();

    var run_tmp = std.testing.tmpDir(.{});
    defer run_tmp.cleanup();

    const syspath = try testfs.makeSysfs(&sysfs_tmp, .{
        .name = "sda",
        .subsystem = "block",
        .uevent = "DEVNAME=sda\nMAJOR=8\nMINOR=0\nSUBSYSTEM=block\nDEVTYPE=disk\n",
    });
    defer gpa.free(syspath);

    // Write db record: b8:0
    try run_tmp.dir.createDirPath(io, "data");
    try run_tmp.dir.writeFile(io, .{
        .sub_path = "data/b8:0",
        .data = "E:ID_FS_TYPE=ext4\nS:disk/by-id/x\nG:systemd\n",
    });

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try run_tmp.dir.realPathFile(io, ".", &rp_buf);
    const run_root = rp_buf[0..n];

    var buf: [512]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try info(gpa, io, .{
        .cmd = .info,
        .query = .symlink,
        .path = syspath,
        .run_root = run_root,
    }, &w);

    try testing.expectEqualStrings("disk/by-id/x\n", w.buffered());
}

test "info (d): --query=all with db contains expected lines" {
    const testfs = @import("testfs.zig");
    const io = testing.io;
    const gpa = testing.allocator;

    var sysfs_tmp = std.testing.tmpDir(.{});
    defer sysfs_tmp.cleanup();

    var run_tmp = std.testing.tmpDir(.{});
    defer run_tmp.cleanup();

    const syspath = try testfs.makeSysfs(&sysfs_tmp, .{
        .name = "sda",
        .subsystem = "block",
        .uevent = "DEVNAME=sda\nMAJOR=8\nMINOR=0\nSUBSYSTEM=block\nDEVTYPE=disk\n",
    });
    defer gpa.free(syspath);

    try run_tmp.dir.createDirPath(io, "data");
    try run_tmp.dir.writeFile(io, .{
        .sub_path = "data/b8:0",
        .data = "E:ID_FS_TYPE=ext4\nS:disk/by-id/x\nG:systemd\n",
    });

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try run_tmp.dir.realPathFile(io, ".", &rp_buf);
    const run_root = rp_buf[0..n];

    var buf: [4096]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try info(gpa, io, .{
        .cmd = .info,
        .query = .all,
        .path = syspath,
        .run_root = run_root,
    }, &w);

    const out = w.buffered();
    try testing.expect(std.mem.indexOf(u8, out, "P: ") != null);
    try testing.expect(std.mem.indexOf(u8, out, "M: sda\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "N: sda\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "S: disk/by-id/x\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "E: ID_FS_TYPE=ext4\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "E: DEVLINKS=/dev/disk/by-id/x\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "E: TAGS=:systemd:\n") != null);
}

test "info (e): --query=property --export uses single-quoted values" {
    const testfs = @import("testfs.zig");
    const io = testing.io;
    const gpa = testing.allocator;

    var sysfs_tmp = std.testing.tmpDir(.{});
    defer sysfs_tmp.cleanup();

    var run_tmp = std.testing.tmpDir(.{});
    defer run_tmp.cleanup();

    const syspath = try testfs.makeSysfs(&sysfs_tmp, .{
        .name = "sda",
        .subsystem = "block",
        .uevent = "DEVNAME=sda\nMAJOR=8\nMINOR=0\nSUBSYSTEM=block\nDEVTYPE=disk\n",
    });
    defer gpa.free(syspath);

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try run_tmp.dir.realPathFile(io, ".", &rp_buf);
    const run_root = rp_buf[0..n];

    var buf: [4096]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try info(gpa, io, .{
        .cmd = .info,
        .query = .property,
        .export_ = true,
        .path = syspath,
        .run_root = run_root,
    }, &w);

    try testing.expectEqualStrings(
        "DEVNAME='/dev/sda'\nDEVTYPE='disk'\nMAJOR='8'\nMINOR='0'\nSUBSYSTEM='block'\n",
        w.buffered(),
    );
}

// Tests

test "parseArgs (g): test-builtin with two positionals" {
    const opts = parseArgs(&.{ "test-builtin", "usb_id", "/sys/x" });
    try testing.expectEqual(Command.test_builtin, opts.cmd.?);
    try testing.expectEqualStrings("usb_id", opts.positional.?);
    try testing.expectEqualStrings("/sys/x", opts.positional2.?);
    try testing.expect(opts.parse_error == null);
}

test "parseArgs (h): too many positionals sets parse_error" {
    const opts = parseArgs(&.{ "info", "a", "b", "c" });
    try testing.expect(opts.parse_error != null);
}

test "parseArgs (i): --action=change" {
    const opts = parseArgs(&.{ "test", "--action=change", "/sys/x" });
    try testing.expectEqualStrings("change", opts.action);
    try testing.expectEqualStrings("/sys/x", opts.positional.?);
}

test "parseArgs (j): --action=bogus sets parse_error" {
    const opts = parseArgs(&.{ "test", "--action=bogus" });
    try testing.expect(opts.parse_error != null);
}

test "testBuiltin input_id: minimal fixture, ID_INPUT=1 only" {
    const testfs = @import("testfs.zig");
    const io = testing.io;
    const gpa = testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const syspath = try testfs.makeSysfs(&tmp, .{
        .name = "mouse0",
        .subsystem = "input",
        .uevent = "",
        .attrs = &.{.{ "capabilities/ev", "1" }},
    });
    defer gpa.free(syspath);

    var buf: [256]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    const ok = try testBuiltin(gpa, io, "input_id", syspath, &w);
    try testing.expect(ok);
    try testing.expectEqualStrings("ID_INPUT=1\n", w.buffered());
}

test "testBuiltin unknown builtin returns false" {
    const testfs = @import("testfs.zig");
    const io = testing.io;
    const gpa = testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const syspath = try testfs.makeSysfs(&tmp, .{
        .name = "mouse0",
        .subsystem = "input",
        .uevent = "",
        .attrs = &.{.{ "capabilities/ev", "1" }},
    });
    defer gpa.free(syspath);

    var buf: [256]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    const ok = try testBuiltin(gpa, io, "nope_builtin", syspath, &w);
    try testing.expect(!ok);
    try testing.expectEqual(@as(usize, 0), w.buffered().len);
}

test "info (f): duplicate G:/Q: tags are deduplicated in TAGS output" {
    const testfs = @import("testfs.zig");
    const io = testing.io;
    const gpa = testing.allocator;

    var sysfs_tmp = std.testing.tmpDir(.{});
    defer sysfs_tmp.cleanup();

    var run_tmp = std.testing.tmpDir(.{});
    defer run_tmp.cleanup();

    const syspath = try testfs.makeSysfs(&sysfs_tmp, .{
        .name = "sda",
        .subsystem = "block",
        .uevent = "DEVNAME=sda\nMAJOR=8\nMINOR=0\nSUBSYSTEM=block\nDEVTYPE=disk\n",
    });
    defer gpa.free(syspath);

    // db record has both G:systemd and Q:systemd, the same tag name from two prefixes.
    try run_tmp.dir.createDirPath(io, "data");
    try run_tmp.dir.writeFile(io, .{
        .sub_path = "data/b8:0",
        .data = "G:systemd\nQ:systemd\n",
    });

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try run_tmp.dir.realPathFile(io, ".", &rp_buf);
    const run_root = rp_buf[0..n];

    var buf: [4096]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try info(gpa, io, .{
        .cmd = .info,
        .query = .all,
        .path = syspath,
        .run_root = run_root,
    }, &w);

    const out = w.buffered();
    // Must contain deduplicated TAGS value.
    try testing.expect(std.mem.indexOf(u8, out, "TAGS=:systemd:\n") != null);
    // Must NOT contain the duplicated form.
    try testing.expect(std.mem.indexOf(u8, out, "TAGS=:systemd:systemd:\n") == null);
}

// Tests

test "triggerList (deferred-b4b): subsystems dry-run skips no-uevent dirs" {
    const io = testing.io;
    const gpa = testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(io, "bus/pci");
    try tmp.dir.writeFile(io, .{ .sub_path = "bus/pci/uevent", .data = "" });
    try tmp.dir.createDirPath(io, "class/block");
    try tmp.dir.writeFile(io, .{ .sub_path = "class/block/uevent", .data = "" });
    try tmp.dir.createDirPath(io, "class/no_uevent_here");

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPathFile(io, ".", &rp_buf);
    const base = rp_buf[0..n];

    var buf: [2048]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try triggerList(gpa, io, .{ .trigger_type = "subsystems" }, base, &w, false);
    const out = w.buffered();
    try testing.expect(std.mem.indexOf(u8, out, "bus/pci") != null);
    try testing.expect(std.mem.indexOf(u8, out, "class/block") != null);
    try testing.expect(std.mem.indexOf(u8, out, "no_uevent_here") == null);
}

test "triggerList (cleanup-c1): subsystems --subsystem-match=block filters out bus/pci" {
    const io = testing.io;
    const gpa = testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(io, "bus/pci");
    try tmp.dir.writeFile(io, .{ .sub_path = "bus/pci/uevent", .data = "" });
    try tmp.dir.createDirPath(io, "class/block");
    try tmp.dir.writeFile(io, .{ .sub_path = "class/block/uevent", .data = "" });

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPathFile(io, ".", &rp_buf);
    const base = rp_buf[0..n];

    var buf: [2048]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try triggerList(gpa, io, .{ .trigger_type = "subsystems", .subsystem_match = "block" }, base, &w, false);
    const out = w.buffered();
    try testing.expect(std.mem.indexOf(u8, out, "class/block") != null);
    try testing.expect(std.mem.indexOf(u8, out, "bus/pci") == null);
}

// Tests

test "parseArgs (k): settle --timeout and --exit-if-exists" {
    const opts = parseArgs(&.{ "settle", "--timeout=5", "--exit-if-exists=/x" });
    try testing.expectEqual(Command.settle, opts.cmd.?);
    try testing.expectEqual(@as(u32, 5), opts.timeout_sec);
    try testing.expectEqualStrings("/x", opts.exit_if_exists.?);
    try testing.expect(opts.parse_error == null);
}

test "parseArgs (l): trigger --action --subsystem-match -n" {
    const opts = parseArgs(&.{ "trigger", "--action=change", "--subsystem-match=block", "-n" });
    try testing.expectEqualStrings("change", opts.action);
    try testing.expectEqualStrings("block", opts.subsystem_match.?);
    try testing.expect(opts.dry_run);
}

test "parseArgs (m): trigger --type=bogus sets parse_error" {
    const opts = parseArgs(&.{ "trigger", "--type=bogus" });
    try testing.expect(opts.parse_error != null);
}

test "parseArgs (n): monitor -k -p" {
    const opts = parseArgs(&.{ "monitor", "-k", "-p" });
    try testing.expect(opts.source_kernel);
    try testing.expect(opts.print_properties);
}

test "parseArgs (o): settle --timeout=notanum sets parse_error" {
    const opts = parseArgs(&.{ "settle", "--timeout=notanum" });
    try testing.expect(opts.parse_error != null);
}

test "queueEmpty: no queue file returns true, file present returns false, exit_if_exists overrides" {
    const io = testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const rp_n = try tmp.dir.realPathFile(io, ".", &rp_buf);
    const rp = rp_buf[0..rp_n];

    // No queue file -> empty
    try testing.expect(queueEmpty(io, rp, null) == true);

    // Create queue file -> not empty
    try tmp.dir.writeFile(io, .{ .sub_path = "queue", .data = "" });
    try testing.expect(queueEmpty(io, rp, null) == false);

    // exit_if_exists pointing at existing file -> true even with queue present
    var q_buf: [std.fs.max_path_bytes]u8 = undefined;
    const q = try std.fmt.bufPrint(&q_buf, "{s}/queue", .{rp});
    try testing.expect(queueEmpty(io, rp, q) == true);
}

test "triggerList dry-run: block devices appear in output" {
    const testfs = @import("testfs.zig");
    const io = testing.io;
    const gpa = testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try testfs.makeClassDevice(&tmp, .{
        .subsystem = "block",
        .name = "sda",
        .uevent = "MAJOR=8\nMINOR=0\n",
    });
    try testfs.makeClassDevice(&tmp, .{
        .subsystem = "block",
        .name = "sdb",
        .uevent = "MAJOR=8\nMINOR=16\n",
    });

    var sda_buf: [std.fs.max_path_bytes]u8 = undefined;
    const sda_n = try tmp.dir.realPathFile(io, "devices/sda", &sda_buf);
    const sda_abs: []const u8 = sda_buf[0..sda_n];
    const devices_dir = std.fs.path.dirname(sda_abs).?;
    const tmp_abs = std.fs.path.dirname(devices_dir).?;

    var sdb_buf: [std.fs.max_path_bytes]u8 = undefined;
    const sdb_n = try tmp.dir.realPathFile(io, "devices/sdb", &sdb_buf);
    const sdb_abs: []const u8 = sdb_buf[0..sdb_n];

    var buf: [2048]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try triggerList(gpa, io, .{ .subsystem_match = "block" }, tmp_abs, &w, false);

    const out = w.buffered();
    try testing.expect(std.mem.indexOf(u8, out, sda_abs) != null);
    try testing.expect(std.mem.indexOf(u8, out, sdb_abs) != null);
}

// Tests

test "formatEventLine: deterministic output from kernel message" {
    const io = testing.io;
    const gpa = testing.allocator;

    const buf = "add@/devices/x/sda\x00ACTION=add\x00SUBSYSTEM=block\x00DEVPATH=/devices/x/sda\x00";
    var ctx = Context.init(gpa, io);
    defer ctx.deinit();
    var dev = (try Monitor.deviceFromMessage(&ctx, .kernel, buf)).?;
    defer dev.deinit();
    var b: [256]u8 = undefined;
    var w = std.Io.Writer.fixed(&b);
    try formatEventLine(&w, "UDEV", 1234000005, &dev);
    try testing.expectEqualStrings("UDEV[1234.000005] add /devices/x/sda (block)\n", w.buffered());
}

test "testDevice (a): dry-run block device with injected ruleset" {
    const testfs = @import("testfs.zig");
    const io = testing.io;
    const gpa = testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const syspath = try testfs.makeSysfs(&tmp, .{
        .name = "sda",
        .subsystem = "block",
        .uevent = "DEVNAME=sda\nMAJOR=8\nMINOR=0\nSUBSYSTEM=block\nDEVTYPE=disk\n",
    });
    defer gpa.free(syspath);

    var rs = try rules.RuleSet.parse(gpa, "SUBSYSTEM==\"block\", SYMLINK+=\"by-sub/blk\", ENV{FOO}=\"bar\"");
    defer rs.deinit();

    var ctx = Context.init(gpa, io);
    defer ctx.deinit();
    var dev = try Device.fromSyspath(&ctx, syspath);
    defer dev.deinit();

    var buf: [2048]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try testDevice(gpa, io, &rs, &dev, "add", &w);

    const out = w.buffered();
    try testing.expect(std.mem.indexOf(u8, out, "Device node symlinks:\n  /dev/by-sub/blk\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "Properties:\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "  ACTION=add\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "  FOO=bar\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "  SUBSYSTEM=block\n") != null);
}

// Deferred Batch 2a Tests

test "info (deferred-b2a a): DEVNAME rewrite adds /dev/ prefix" {
    const testfs = @import("testfs.zig");
    const io = testing.io;
    const gpa = testing.allocator;

    var sysfs_tmp = std.testing.tmpDir(.{});
    defer sysfs_tmp.cleanup();

    var run_tmp = std.testing.tmpDir(.{});
    defer run_tmp.cleanup();

    const syspath = try testfs.makeSysfs(&sysfs_tmp, .{
        .name = "sda",
        .subsystem = "block",
        .uevent = "DEVNAME=sda\nMAJOR=8\nMINOR=0\nSUBSYSTEM=block\n",
    });
    defer gpa.free(syspath);

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try run_tmp.dir.realPathFile(io, ".", &rp_buf);
    const run_root = rp_buf[0..n];

    var buf: [4096]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try info(gpa, io, .{
        .cmd = .info,
        .query = .property,
        .path = syspath,
        .run_root = run_root,
    }, &w);

    const out = w.buffered();
    try testing.expect(std.mem.indexOf(u8, out, "DEVNAME=/dev/sda\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "DEVNAME=sda\n") == null);
}

test "info (deferred-b2a b): CURRENT_TAGS and J: line in --query=all" {
    const testfs = @import("testfs.zig");
    const io = testing.io;
    const gpa = testing.allocator;

    var sysfs_tmp = std.testing.tmpDir(.{});
    defer sysfs_tmp.cleanup();

    var run_tmp = std.testing.tmpDir(.{});
    defer run_tmp.cleanup();

    const syspath = try testfs.makeSysfs(&sysfs_tmp, .{
        .name = "sda",
        .subsystem = "block",
        .uevent = "DEVNAME=sda\nMAJOR=8\nMINOR=0\nSUBSYSTEM=block\n",
    });
    defer gpa.free(syspath);

    try run_tmp.dir.createDirPath(io, "data");
    try run_tmp.dir.writeFile(io, .{
        .sub_path = "data/b8:0",
        .data = "G:systemd\nQ:seat\n",
    });

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try run_tmp.dir.realPathFile(io, ".", &rp_buf);
    const run_root = rp_buf[0..n];

    var buf: [4096]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try info(gpa, io, .{
        .cmd = .info,
        .query = .all,
        .path = syspath,
        .run_root = run_root,
    }, &w);

    const out = w.buffered();
    try testing.expect(std.mem.indexOf(u8, out, "E: CURRENT_TAGS=:seat:\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "E: TAGS=:systemd:\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "J: b8:0\n") != null);
}

test "resolveName (deferred-b2a c): not-found returns null" {
    const io = testing.io;
    const gpa = testing.allocator;
    const result = try resolveName(gpa, io, "definitely_not_a_dev_xyzzy");
    try testing.expect(result == null);
}

test "info (deferred-b2a d): P: canonicalization from class symlink path" {
    const testfs = @import("testfs.zig");
    const io = testing.io;
    const gpa = testing.allocator;

    var sysfs_tmp = std.testing.tmpDir(.{});
    defer sysfs_tmp.cleanup();

    var run_tmp = std.testing.tmpDir(.{});
    defer run_tmp.cleanup();

    try testfs.makeClassDevice(&sysfs_tmp, .{
        .name = "sda",
        .subsystem = "block",
        .uevent = "DEVNAME=sda\nMAJOR=8\nMINOR=0\nSUBSYSTEM=block\n",
    });

    // Get the absolute tmpdir path to construct the symlink path.
    var tmp_rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_n = try sysfs_tmp.dir.realPathFile(io, ".", &tmp_rp_buf);
    const tmp_abs = tmp_rp_buf[0..tmp_n];

    // Build path to the class symlink (not following it).
    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    const link_path = try std.fmt.bufPrint(&link_buf, "{s}/class/block/sda", .{tmp_abs});

    // Resolve the canonical device dir path.
    var dev_rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dev_n = try sysfs_tmp.dir.realPathFile(io, "devices/sda", &dev_rp_buf);
    const dev_abs = dev_rp_buf[0..dev_n];

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const rn = try run_tmp.dir.realPathFile(io, ".", &rp_buf);
    const run_root = rp_buf[0..rn];

    var buf: [2048]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try info(gpa, io, .{
        .cmd = .info,
        .query = .path,
        .path = link_path,
        .run_root = run_root,
    }, &w);

    const out = w.buffered();
    // Output should be the canonical device path (devices/sda), not the class symlink path.
    var expected_buf: [std.fs.max_path_bytes + 2]u8 = undefined;
    const expected = try std.fmt.bufPrint(&expected_buf, "{s}\n", .{dev_abs});
    try testing.expectEqualStrings(expected, out);
}

// Deferred Batch 2b Tests

test "info (deferred-b2b a): attribute-walk basic" {
    const testfs = @import("testfs.zig");
    const io = testing.io;
    const gpa = testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const syspath = try testfs.makeSysfs(&tmp, .{
        .name = "input9",
        .subsystem = "input",
        .uevent = "",
        .attrs = &.{
            .{ "capabilities/ev", "3" },
            .{ "id/bustype", "0019" },
            .{ "name", "Test KB" },
        },
    });
    defer gpa.free(syspath);

    var ctx = Context.init(gpa, io);
    defer ctx.deinit();
    var dev = try Device.fromSyspath(&ctx, syspath);
    defer dev.deinit();

    var aw = std.Io.Writer.Allocating.init(gpa);
    defer aw.deinit();
    try attributeWalk(gpa, io, &dev, &aw.writer);

    const out = aw.writer.buffered();
    try testing.expect(std.mem.indexOf(u8, out, "  looking at device '") != null);
    try testing.expect(std.mem.indexOf(u8, out, "    KERNEL==\"input9\"\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "    SUBSYSTEM==\"input\"\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "    DRIVER==\"\"\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "    ATTR{capabilities/ev}==\"3\"\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "    ATTR{id/bustype}==\"0019\"\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "    ATTR{name}==\"Test KB\"\n") != null);
    // Verify sorted order: capabilities/ev < id/bustype < name
    const pos_ev = std.mem.indexOf(u8, out, "capabilities/ev").?;
    const pos_bus = std.mem.indexOf(u8, out, "id/bustype").?;
    const pos_name = std.mem.indexOf(u8, out, "ATTR{name}").?;
    try testing.expect(pos_ev < pos_bus);
    try testing.expect(pos_bus < pos_name);
}

test "info (deferred-b2b b): db-DEVNAME wins over devnode rewrite" {
    const testfs = @import("testfs.zig");
    const io = testing.io;
    const gpa = testing.allocator;

    var sysfs_tmp = std.testing.tmpDir(.{});
    defer sysfs_tmp.cleanup();

    var run_tmp = std.testing.tmpDir(.{});
    defer run_tmp.cleanup();

    const syspath = try testfs.makeSysfs(&sysfs_tmp, .{
        .name = "sda",
        .subsystem = "block",
        .uevent = "DEVNAME=sda\nMAJOR=8\nMINOR=0\nSUBSYSTEM=block\n",
    });
    defer gpa.free(syspath);

    // Write db record: E:DEVNAME points to a mapper path.
    try run_tmp.dir.createDirPath(io, "data");
    try run_tmp.dir.writeFile(io, .{
        .sub_path = "data/b8:0",
        .data = "E:DEVNAME=/dev/mapper/custom\n",
    });

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try run_tmp.dir.realPathFile(io, ".", &rp_buf);
    const run_root = rp_buf[0..n];

    var buf: [4096]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try info(gpa, io, .{
        .cmd = .info,
        .query = .property,
        .path = syspath,
        .run_root = run_root,
    }, &w);

    const out = w.buffered();
    // db value wins: /dev/mapper/custom, NOT /dev/sda
    try testing.expect(std.mem.indexOf(u8, out, "DEVNAME=/dev/mapper/custom\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "DEVNAME=/dev/sda\n") == null);
}

// FIX 1 regression: child-device subdirs must not be descended in collectAttrNames

test "attributeWalk (fix1): child-device subdir is not descended" {
    const testfs = @import("testfs.zig");
    const io = testing.io;
    const gpa = testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Build the parent device with a non-device attr subdir (id/).
    const syspath = try testfs.makeSysfs(&tmp, .{
        .name = "input0",
        .subsystem = "input",
        .uevent = "",
        .attrs = &.{
            .{ "id/bustype", "0019" },
        },
    });
    defer gpa.free(syspath);

    // Manually plant a child-device subdir event0/ with its own uevent and a dev file.
    try tmp.dir.createDirPath(io, "devices/input0/event0");
    try tmp.dir.writeFile(io, .{ .sub_path = "devices/input0/event0/uevent", .data = "" });
    try tmp.dir.writeFile(io, .{ .sub_path = "devices/input0/event0/dev", .data = "13:64" });

    var ctx = Context.init(gpa, io);
    defer ctx.deinit();
    var dev = try Device.fromSyspath(&ctx, syspath);
    defer dev.deinit();

    var aw = std.Io.Writer.Allocating.init(gpa);
    defer aw.deinit();
    try attributeWalk(gpa, io, &dev, &aw.writer);

    const out = aw.writer.buffered();
    // Non-device subdir id/ must still be descended.
    try testing.expect(std.mem.indexOf(u8, out, "ATTR{id/bustype}") != null);
    // Child-device subdir event0/ must NOT be descended (it has a uevent file).
    try testing.expect(std.mem.indexOf(u8, out, "ATTR{event0/dev}") == null);
    try testing.expect(std.mem.indexOf(u8, out, "ATTR{event0/uevent}") == null);
}

// Deferred Batch 4a Tests

test "monitorSources (deferred-b4a a): no flags -> both sources" {
    const sel = monitorSources(.{});
    try testing.expect(sel.kernel);
    try testing.expect(sel.udev);
}

test "monitorSources (deferred-b4a b): --kernel only -> kernel=true, udev=false" {
    const sel = monitorSources(.{ .source_kernel = true });
    try testing.expect(sel.kernel);
    try testing.expect(!sel.udev);
}

test "monitorSources (deferred-b4a c): --udev only -> udev=true, kernel=false" {
    const sel = monitorSources(.{ .source_udev = true });
    try testing.expect(sel.udev);
    try testing.expect(!sel.kernel);
}

test "monitorSources (deferred-b4a d): both flags -> both true" {
    const sel = monitorSources(.{ .source_kernel = true, .source_udev = true });
    try testing.expect(sel.kernel);
    try testing.expect(sel.udev);
}

test "writeMonitorHeader (deferred-b4a e): both sources -> contains UDEV and KERNEL lines" {
    var buf: [512]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try writeMonitorHeader(&w, .{ .kernel = true, .udev = true });
    const out = w.buffered();
    try testing.expect(std.mem.indexOf(u8, out, "UDEV - ") != null);
    try testing.expect(std.mem.indexOf(u8, out, "KERNEL - ") != null);
}

test "writeMonitorHeader (deferred-b4a f): kernel only -> KERNEL present, UDEV absent" {
    var buf: [512]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try writeMonitorHeader(&w, .{ .kernel = true, .udev = false });
    const out = w.buffered();
    try testing.expect(std.mem.indexOf(u8, out, "KERNEL - ") != null);
    try testing.expect(std.mem.indexOf(u8, out, "UDEV - ") == null);
}

test "writeMonitorHeader (cleanup-c2): udev only -> UDEV present, KERNEL absent" {
    var buf: [256]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try writeMonitorHeader(&w, .{ .kernel = false, .udev = true });
    const out = w.buffered();
    try testing.expect(std.mem.indexOf(u8, out, "UDEV - ") != null);
    try testing.expect(std.mem.indexOf(u8, out, "KERNEL - ") == null);
}
