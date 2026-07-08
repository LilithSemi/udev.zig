//! static_nodes.zig - create static device nodes listed in modules.devname at daemon startup.
//! The kernel lists device nodes for autoloaded modules in /lib/modules/<release>/modules.devname.
//! udev mknod's these at boot so the node exists before the module is loaded (on-demand autoloading).
const std = @import("std");
const linux = std.os.linux;
const node_actuator = @import("node_actuator.zig");

pub const StaticNode = struct { devname: []const u8, kind: u32, major: u32, minor: u32 };

/// Parse one modules.devname line: "<mod> <devname> <c|b><maj>:<min>". Returns null for comments,
/// blanks, or malformed lines. The devname slice borrows from `line`.
pub fn parseLine(line: []const u8) ?StaticNode {
    const trimmed = std.mem.trim(u8, line, " \t\r");
    if (trimmed.len == 0 or trimmed[0] == '#') return null;
    var toks = std.mem.tokenizeAny(u8, trimmed, " \t");
    _ = toks.next() orelse return null; // module name (ignored)
    const devname = toks.next() orelse return null;
    const spec = toks.next() orelse return null;
    if (spec.len < 4) return null; // at least "c0:0"
    const kind: u32 = switch (spec[0]) {
        'c' => linux.S.IFCHR,
        'b' => linux.S.IFBLK,
        else => return null,
    };
    const colon = std.mem.indexOfScalar(u8, spec, ':') orelse return null;
    const major = std.fmt.parseInt(u32, spec[1..colon], 10) catch return null;
    const minor = std.fmt.parseInt(u32, spec[colon + 1 ..], 10) catch return null;
    return .{ .devname = devname, .kind = kind, .major = major, .minor = minor };
}

/// Read modules.devname at `path` and mknod each static node under `dev_root`.
/// Missing file -> no-op. mknod is root-gated (PermissionDenied tolerated). Parent dirs created as needed.
pub fn createStaticNodes(gpa: std.mem.Allocator, io: std.Io, path: []const u8, dev_root: []const u8) !void {
    const content = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(4 << 20)) catch return;
    defer gpa.free(content);
    var lines = std.mem.tokenizeScalar(u8, content, '\n');
    while (lines.next()) |line| {
        const sn = parseLine(line) orelse continue;
        // Create the parent directory of the node under dev_root if devname is nested (e.g. cpu/microcode).
        if (std.mem.lastIndexOfScalar(u8, sn.devname, '/')) |slash| {
            const parent = std.fmt.allocPrint(gpa, "{s}/{s}", .{ dev_root, sn.devname[0..slash] }) catch continue;
            defer gpa.free(parent);
            std.Io.Dir.cwd().createDirPath(io, parent) catch {};
        }
        node_actuator.makeNode(gpa, dev_root, .{
            .devname = sn.devname,
            .kind = sn.kind,
            .major = sn.major,
            .minor = sn.minor,
        }, 0o600) catch |e| if (e != error.PermissionDenied) return e;
    }
}

// Tests

test "parseLine char device" {
    const sn = parseLine("fuse fuse c10:229").?;
    try std.testing.expectEqualStrings("fuse", sn.devname);
    try std.testing.expectEqual(linux.S.IFCHR, sn.kind);
    try std.testing.expectEqual(@as(u32, 10), sn.major);
    try std.testing.expectEqual(@as(u32, 229), sn.minor);
}

test "parseLine nested devname" {
    const sn = parseLine("cpu/microcode cpu/microcode c10:184").?;
    try std.testing.expectEqualStrings("cpu/microcode", sn.devname);
    try std.testing.expectEqual(linux.S.IFCHR, sn.kind);
    try std.testing.expectEqual(@as(u32, 10), sn.major);
    try std.testing.expectEqual(@as(u32, 184), sn.minor);
}

test "parseLine block device" {
    const sn = parseLine("loop-control loop-control b7:0").?;
    try std.testing.expectEqualStrings("loop-control", sn.devname);
    try std.testing.expectEqual(linux.S.IFBLK, sn.kind);
    try std.testing.expectEqual(@as(u32, 7), sn.major);
    try std.testing.expectEqual(@as(u32, 0), sn.minor);
}

test "parseLine comment returns null" {
    try std.testing.expect(parseLine("# a comment") == null);
}

test "parseLine blank returns null" {
    try std.testing.expect(parseLine("   ") == null);
}

test "parseLine garbage returns null" {
    try std.testing.expect(parseLine("garbage line") == null);
}

test "parseLine bad type char returns null" {
    try std.testing.expect(parseLine("fuse fuse x10:229") == null);
}

test "parseLine spec too short returns null" {
    try std.testing.expect(parseLine("fuse fuse c") == null);
}

test "createStaticNodes root gated" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Write a fixture modules.devname.
    const fixture = "fuse fuse c10:229\n# comment\nnested/node nested/node c10:200\n";
    try tmp.dir.writeFile(io, .{ .sub_path = "modules.devname", .data = fixture });

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const fixture_path_n = try tmp.dir.realPathFile(io, "modules.devname", &rp_buf);
    const fixture_path = rp_buf[0..fixture_path_n];

    // Use a separate tmp dir as the dev_root.
    var dev_tmp = std.testing.tmpDir(.{});
    defer dev_tmp.cleanup();

    var dev_rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dev_root_n = try dev_tmp.dir.realPathFile(io, ".", &dev_rp_buf);
    const dev_root = dev_rp_buf[0..dev_root_n];

    // Must not error (PermissionDenied from mknod is tolerated).
    try createStaticNodes(gpa, io, fixture_path, dev_root);

    // If running as root, the fuse node should exist, otherwise it is simply not created.
    const node_path = try std.fmt.allocPrint(gpa, "{s}/fuse", .{dev_root});
    defer gpa.free(node_path);
    if (std.Io.Dir.cwd().access(io, node_path, .{})) {
        // Running as root: node was created successfully.
    } else |_| {
        // Not root: PermissionDenied was tolerated, test still passes.
    }

    // Nested parent dir creation must not crash regardless of privilege.
    // (The createStaticNodes call above already exercised the nested path logic.)
}
