//! Load and merge udev rules files from precedence directories.
//! Higher-index dirs in opts.dirs have LOWER precedence (index 0 wins).
//! A basename symlinked to /dev/null at higher precedence masks the file at lower
//! precedence entirely.
const std = @import("std");
const rules = @import("../rules.zig");
const parser = @import("../rules/parser.zig");

pub const default_dirs = [_][]const u8{
    "/etc/udev/rules.d",
    "/run/udev/rules.d",
    "/usr/lib/udev/rules.d",
};

pub const Options = struct {
    dirs: []const []const u8 = &default_dirs,
};

/// Load, deduplicate, sort, and parse all .rules files found across opts.dirs.
/// Directory precedence: opts.dirs[0] is highest. A basename already claimed
/// (by map or masked set) is skipped when encountered in a later dir.
/// The returned RuleSet owns all data via its arena; call RuleSet.deinit when done.
/// All scratch allocations are freed before this function returns.
pub fn load(gpa: std.mem.Allocator, io: std.Io, opts: Options) !rules.RuleSet {
    // Scratch arena for all string dupes used as map keys/values.
    var scratch = std.heap.ArenaAllocator.init(gpa);
    defer scratch.deinit();
    const sa = scratch.allocator();

    // basename -> absolute path  (keys+values point into scratch arena)
    var file_map: std.StringHashMapUnmanaged([]const u8) = .empty;
    defer file_map.deinit(gpa);

    // basenames masked by a /dev/null symlink at higher precedence
    var masked: std.StringHashMapUnmanaged(void) = .empty;
    defer masked.deinit(gpa);

    // Phase 1: discover files across dirs in precedence order.
    for (opts.dirs) |dir_path| {
        var d = std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true }) catch continue;
        defer d.close(io);
        var it = d.iterate();
        while (try it.next(io)) |entry| {
            if (!std.mem.endsWith(u8, entry.name, ".rules")) continue;
            const basename = entry.name;

            // Higher-precedence dir already claimed this basename.
            if (file_map.contains(basename) or masked.contains(basename)) continue;

            // Build the absolute path for readLink and readFileAlloc later.
            var fp_buf: [std.fs.max_path_bytes]u8 = undefined;
            const fullpath = try std.fmt.bufPrint(&fp_buf, "{s}/{s}", .{ dir_path, basename });

            // Check whether this entry is a symlink to /dev/null.
            var lbuf: [std.fs.max_path_bytes]u8 = undefined;
            const is_null_dev: bool = blk: {
                const n = std.Io.Dir.cwd().readLink(io, fullpath, &lbuf) catch break :blk false;
                break :blk std.mem.eql(u8, lbuf[0..n], "/dev/null");
            };

            if (is_null_dev) {
                try masked.put(gpa, try sa.dupe(u8, basename), {});
            } else {
                try file_map.put(
                    gpa,
                    try sa.dupe(u8, basename),
                    try sa.dupe(u8, fullpath),
                );
            }
        }
    }

    // Phase 2: collect basenames + sort ascending.
    var keys: std.ArrayListUnmanaged([]const u8) = .empty;
    defer keys.deinit(gpa);
    {
        var it = file_map.iterator();
        while (it.next()) |entry| {
            try keys.append(gpa, entry.key_ptr.*);
        }
    }
    std.mem.sort([]const u8, keys.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lt);

    // Phase 3: load + parse files into the RuleSet arena.
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const aa = arena.allocator();

    var merged: std.ArrayListUnmanaged(parser.Rule) = .empty;
    var diags: std.ArrayListUnmanaged(parser.Diagnostic) = .empty;

    for (keys.items) |basename| {
        const path = file_map.get(basename).?;
        const text = std.Io.Dir.cwd().readFileAlloc(io, path, aa, .limited(4 << 20)) catch continue;
        var fdiags: std.ArrayListUnmanaged(parser.Diagnostic) = .empty;
        const frules = try parser.parse(aa, text, &fdiags);
        try merged.appendSlice(aa, frules);
        for (fdiags.items) |fd| {
            try diags.append(aa, .{
                .line = fd.line,
                .message = try std.fmt.allocPrint(aa, "{s}: {s}", .{ basename, fd.message }),
            });
        }
    }

    // Scratch (maps + keys list + string dupes) freed by defers above.
    return rules.RuleSet{
        .arena = arena,
        .rules = try merged.toOwnedSlice(aa),
        .diagnostics = try diags.toOwnedSlice(aa),
    };
}

// Tests
test "rules_loader: basename order across dirs" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(io, "etc/udev/rules.d");
    try tmp.dir.createDirPath(io, "lib/udev/rules.d");

    try tmp.dir.writeFile(io, .{
        .sub_path = "etc/udev/rules.d/10-a.rules",
        .data = "SUBSYSTEM==\"a\", TAG+=\"atag\"\n",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "lib/udev/rules.d/20-b.rules",
        .data = "SUBSYSTEM==\"b\", TAG+=\"btag\"\n",
    });

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const rp_n = try tmp.dir.realPathFile(io, ".", &rp_buf);
    const realpath = rp_buf[0..rp_n];

    const etc_dir = try std.fmt.allocPrint(gpa, "{s}/etc/udev/rules.d", .{realpath});
    defer gpa.free(etc_dir);
    const lib_dir = try std.fmt.allocPrint(gpa, "{s}/lib/udev/rules.d", .{realpath});
    defer gpa.free(lib_dir);

    const dirs = [_][]const u8{ etc_dir, lib_dir };
    var rs = try load(gpa, io, .{ .dirs = &dirs });
    defer rs.deinit();

    try std.testing.expectEqual(@as(usize, 2), rs.rules.len);
    // 10-a.rules sorts before 20-b.rules. First rule entry value must be "a".
    try std.testing.expectEqualStrings("a", rs.rules[0].entries[0].value);
}

test "rules_loader: shadow, etc beats lib for same basename" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(io, "etc/udev/rules.d");
    try tmp.dir.createDirPath(io, "lib/udev/rules.d");

    try tmp.dir.writeFile(io, .{
        .sub_path = "etc/udev/rules.d/50-x.rules",
        .data = "KERNEL==\"etcwin\"\n",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "lib/udev/rules.d/50-x.rules",
        .data = "KERNEL==\"liblose\"\n",
    });

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const rp_n = try tmp.dir.realPathFile(io, ".", &rp_buf);
    const realpath = rp_buf[0..rp_n];

    const etc_dir = try std.fmt.allocPrint(gpa, "{s}/etc/udev/rules.d", .{realpath});
    defer gpa.free(etc_dir);
    const lib_dir = try std.fmt.allocPrint(gpa, "{s}/lib/udev/rules.d", .{realpath});
    defer gpa.free(lib_dir);

    const dirs = [_][]const u8{ etc_dir, lib_dir };
    var rs = try load(gpa, io, .{ .dirs = &dirs });
    defer rs.deinit();

    var found_etcwin = false;
    var found_liblose = false;
    for (rs.rules) |rule| {
        for (rule.entries) |entry| {
            if (std.mem.eql(u8, entry.value, "etcwin")) found_etcwin = true;
            if (std.mem.eql(u8, entry.value, "liblose")) found_liblose = true;
        }
    }
    try std.testing.expect(found_etcwin);
    try std.testing.expect(!found_liblose);
}

test "rules_loader: mask, /dev/null symlink hides lower-precedence file" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(io, "etc/udev/rules.d");
    try tmp.dir.createDirPath(io, "lib/udev/rules.d");

    // etc masks the basename with a /dev/null symlink.
    try tmp.dir.symLink(io, "/dev/null", "etc/udev/rules.d/60-m.rules", .{});

    // lib has a real file that must not be loaded.
    try tmp.dir.writeFile(io, .{
        .sub_path = "lib/udev/rules.d/60-m.rules",
        .data = "KERNEL==\"masked\"\n",
    });

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const rp_n = try tmp.dir.realPathFile(io, ".", &rp_buf);
    const realpath = rp_buf[0..rp_n];

    const etc_dir = try std.fmt.allocPrint(gpa, "{s}/etc/udev/rules.d", .{realpath});
    defer gpa.free(etc_dir);
    const lib_dir = try std.fmt.allocPrint(gpa, "{s}/lib/udev/rules.d", .{realpath});
    defer gpa.free(lib_dir);

    const dirs = [_][]const u8{ etc_dir, lib_dir };
    var rs = try load(gpa, io, .{ .dirs = &dirs });
    defer rs.deinit();

    for (rs.rules) |rule| {
        for (rule.entries) |entry| {
            try std.testing.expect(!std.mem.eql(u8, entry.value, "masked"));
        }
    }
}

test "rules_loader: end-to-end load->apply via ExecRunner (input_id)" {
    const testfs = @import("../testfs.zig");
    const context = @import("../context.zig");
    const input_id_mod = @import("../builtins/input_id.zig");
    const daemon_exec = @import("exec_runner.zig");
    const Device = @import("../device.zig").Device;
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Create rules dir and write one rule file.
    try tmp.dir.createDirPath(io, "etc/udev/rules.d");
    try tmp.dir.writeFile(io, .{
        .sub_path = "etc/udev/rules.d/50-input.rules",
        .data = "IMPORT{builtin}=\"input_id\"\n",
    });

    // Resolve the absolute path for the tmp root.
    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const rp_n = try tmp.dir.realPathFile(io, ".", &rp_buf);
    const realpath = rp_buf[0..rp_n];

    const rules_dir = try std.fmt.allocPrint(gpa, "{s}/etc/udev/rules.d", .{realpath});
    defer gpa.free(rules_dir);

    // Load rules from the on-disk rules dir.
    const dirs = [_][]const u8{rules_dir};
    var rs = try load(gpa, io, .{ .dirs = &dirs });
    defer rs.deinit();

    try std.testing.expect(rs.rules.len > 0);

    // Build a fake INPUT keyboard device in the same tmp sysfs.
    const ev_str = try input_id_mod.fmtBitmapWords(gpa, &.{1}); // EV_KEY = 1
    defer gpa.free(ev_str);

    var kbd_bits: [32]usize = undefined;
    for (0..32) |i| kbd_bits[i] = i + 1;
    const key_str = try input_id_mod.fmtBitmapWords(gpa, &kbd_bits);
    defer gpa.free(key_str);

    const syspath = try testfs.makeSysfs(&tmp, .{
        .name = "kbd_loader_e2e",
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

    // Apply the disk-loaded ruleset via the real ExecRunner.
    var er = daemon_exec.ExecRunner{ .gpa = gpa, .io = io };
    var st = try rs.apply(gpa, &dev, er.runner());
    defer st.deinit();

    try std.testing.expectEqualStrings("1", st.getProperty("ID_INPUT").?);
}

test "rules_loader: integration, real /etc/udev/rules.d parses non-empty" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    // Skip cleanly if the real rules dir is absent (container/minimal env).
    std.Io.Dir.cwd().access(io, "/etc/udev/rules.d", .{}) catch return;

    var rs = load(gpa, io, .{}) catch return;
    defer rs.deinit();

    try std.testing.expect(rs.rules.len > 0);
}

test {
    std.testing.refAllDecls(@This());
}
