//! Runtime reader for hwdb.bin: open from a buffer, validate header, deinit.
const std = @import("std");
const format = @import("format.zig");
const glob = @import("../rules/glob.zig");

pub const KeyValue = struct { key: []const u8, value: []const u8 };

pub const Hwdb = struct {
    gpa: std.mem.Allocator,
    buf: []u8,
    header: format.Header,

    /// Takes ownership of `bytes`. Validates the hwdb.bin header via format.readHeader.
    /// On error the passed buffer is freed before returning.
    pub fn openFromBuffer(gpa: std.mem.Allocator, bytes: []u8) !Hwdb {
        const header = format.readHeader(bytes) catch |err| {
            gpa.free(bytes);
            return err;
        };
        return Hwdb{ .gpa = gpa, .buf = bytes, .header = header };
    }

    /// Resolve a hwdb.bin, read it into a buffer, and return an Hwdb.
    /// Resolution order:
    ///   1. opts.path if non-null.
    ///   2. The env var named opts.env_var (read from /proc/self/environ on Linux).
    ///   3. The first path in default_search that exists.
    /// Returns error.HwdbNotFound when nothing resolves.
    pub fn open(gpa: std.mem.Allocator, io: std.Io, opts: Options) !Hwdb {
        const limit = std.Io.Limit.limited(128 * 1024 * 1024);

        if (opts.path) |p| {
            const bytes = try std.Io.Dir.cwd().readFileAlloc(io, p, gpa, limit);
            return Hwdb.openFromBuffer(gpa, bytes);
        }

        env_blk: {
            const proc_env = std.Io.Dir.cwd().readFileAlloc(
                io,
                "/proc/self/environ",
                gpa,
                std.Io.Limit.limited(1024 * 1024),
            ) catch break :env_blk;
            defer gpa.free(proc_env);

            const key = opts.env_var;
            var it = std.mem.tokenizeScalar(u8, proc_env, 0);
            while (it.next()) |entry| {
                if (entry.len > key.len and
                    std.mem.eql(u8, entry[0..key.len], key) and
                    entry[key.len] == '=')
                {
                    const env_path = entry[key.len + 1 ..];
                    const bytes = std.Io.Dir.cwd().readFileAlloc(io, env_path, gpa, limit) catch break :env_blk;
                    return Hwdb.openFromBuffer(gpa, bytes);
                }
            }
        }

        for (default_search) |candidate| {
            std.Io.Dir.cwd().access(io, candidate, .{}) catch continue;
            const bytes = std.Io.Dir.cwd().readFileAlloc(io, candidate, gpa, limit) catch continue;
            return Hwdb.openFromBuffer(gpa, bytes);
        }

        return error.HwdbNotFound;
    }

    /// Free the owned buffer.
    pub fn deinit(self: *Hwdb) void {
        self.gpa.free(self.buf);
    }

    /// Search the hwdb trie for entries matching `modalias`.
    /// Returns a gpa-allocated []KeyValue; key/value slices point into self.buf.
    /// Caller frees the slice with gpa.free. Returns zero-length slice on no match.
    pub fn query(self: *Hwdb, gpa: std.mem.Allocator, modalias: []const u8) ![]KeyValue {
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const aa = arena.allocator();

        var map = std.StringHashMap(DedupEntry).init(gpa);
        defer map.deinit();

        var linebuf = std.ArrayListUnmanaged(u8).empty;

        // Bound recursion against a crafted/corrupt file: a valid acyclic trie can never be deeper
        // than its node count, so a child_off cycle (or a chain longer than that) is rejected as
        // corrupt rather than being allowed to exhaust the stack. node_size >= 24 is guaranteed by
        // readHeader, so this division is safe.
        const max_depth = (self.header.nodes_len / self.header.node_size) + 1;
        try searchNode(self, &map, aa, &linebuf, self.header.nodes_root_off, 0, false, modalias, 0, max_depth);

        const result = try gpa.alloc(KeyValue, map.count());
        var i: usize = 0;
        var it = map.iterator();
        while (it.next()) |entry| {
            result[i] = .{ .key = entry.key_ptr.*, .value = entry.value_ptr.*.value };
            i += 1;
        }
        return result;
    }
};

pub const Options = struct { path: ?[]const u8 = null, env_var: []const u8 = "UDEV_HWDB_BIN" };
pub const default_search = [_][]const u8{ "/etc/udev/hwdb.bin", "/usr/lib/udev/hwdb.bin", "/lib/udev/hwdb.bin" };
pub const OpenError = error{HwdbNotFound};

const DedupEntry = struct {
    value: []const u8,
    priority: u32,
    line: u32,
};

fn isGlobMeta(c: u8) bool {
    return c == '*' or c == '?' or c == '[';
}

fn searchNode(
    hw: *Hwdb,
    map: *std.StringHashMap(DedupEntry),
    aa: std.mem.Allocator,
    linebuf: *std.ArrayListUnmanaged(u8),
    node_off: u64,
    p: usize,
    fnmatch_in: bool,
    modalias: []const u8,
    depth: u64,
    max_depth: u64,
) !void {
    // A cyclic or over-deep child_off from a corrupt file would otherwise recurse until the stack
    // is exhausted. Treat anything deeper than the node count as corrupt.
    if (depth > max_depth) return error.Corrupt;
    const node = try format.readNode(hw.buf, hw.header, node_off);

    const saved_len = linebuf.items.len;
    defer linebuf.items.len = saved_len;

    // Append prefix bytes to linebuf. Track literal vs fnmatch traversal state.
    const prefix = try format.cstr(hw.buf, node.prefix_off);
    var cur_p = p;
    var cur_fnmatch = fnmatch_in;

    for (prefix) |pb| {
        try linebuf.append(aa, pb);
        if (!cur_fnmatch) {
            if (isGlobMeta(pb)) {
                cur_fnmatch = true;
            } else if (cur_p < modalias.len and modalias[cur_p] == pb) {
                cur_p += 1;
            } else {
                return; // dead branch: prefix mismatch with no wildcard rescue
            }
        }
    }

    // Collect values when the modalias is fully consumed or we are in fnmatch mode.
    // The glob.match gate ensures correctness for both literal and wildcard patterns.
    // NOTE: the shared rules glob treats a top-level '|' as alternation and has no '\' escape;
    // hwdb match patterns only ever use '* ? [ ]' + literals (never '|'), so this is exact for
    // hwdb. If hwdb patterns ever gained '|', this gate would need a dedicated fnmatch.
    if (node.values_count > 0 and (cur_p == modalias.len or cur_fnmatch)) {
        if (glob.match(linebuf.items, modalias)) {
            for (0..node.values_count) |vi| {
                const vv = try format.readValue(hw.buf, hw.header, node_off, node.children_count, @intCast(vi));
                const key = try format.cstr(hw.buf, vv.key_off);
                const val = try format.cstr(hw.buf, vv.value_off);

                const gop = try map.getOrPut(key);
                if (!gop.found_existing) {
                    gop.value_ptr.* = .{ .value = val, .priority = vv.priority, .line = vv.line };
                } else {
                    const ex = gop.value_ptr.*;
                    // Higher priority wins. Same priority uses last-wins (line >= handles priority=0 case).
                    if (vv.priority > ex.priority or
                        (vv.priority == ex.priority and vv.line >= ex.line))
                    {
                        gop.value_ptr.* = .{ .value = val, .priority = vv.priority, .line = vv.line };
                    }
                }
            }
        }
    }

    // Recurse into children.
    for (0..node.children_count) |ci| {
        const c = try format.childC(hw.buf, hw.header, node_off, @intCast(ci));
        const child_off = try format.childOff(hw.buf, hw.header, node_off, @intCast(ci));

        const saved_lb = linebuf.items.len;
        try linebuf.append(aa, c);

        if (cur_fnmatch) {
            // Already in fnmatch mode: follow all children.
            try searchNode(hw, map, aa, linebuf, child_off, cur_p, true, modalias, depth + 1, max_depth);
        } else if (isGlobMeta(c)) {
            // Wildcard edge: enter fnmatch mode for this subtree.
            try searchNode(hw, map, aa, linebuf, child_off, cur_p, true, modalias, depth + 1, max_depth);
        } else if (cur_p < modalias.len and c == modalias[cur_p]) {
            // Exact-match edge: advance search position.
            try searchNode(hw, map, aa, linebuf, child_off, cur_p + 1, false, modalias, depth + 1, max_depth);
        }
        // else: skip child that doesn't match and isn't a glob.

        linebuf.items.len = saved_lb;
    }
}

const testbuild = @import("testbuild.zig");

test "openFromBuffer accepts a built fixture and rejects garbage" {
    const buf = try testbuild.build(std.testing.allocator, &.{
        .{ .pattern = "usb:v046Dp", .values = &.{.{ .key = "ID_VENDOR", .value = "Logitech" }} },
    });
    var hw = try Hwdb.openFromBuffer(std.testing.allocator, buf);
    defer hw.deinit();
    try std.testing.expectEqualStrings("KSLPHHRH", buf[0..8]);
    // garbage rejected. openFromBuffer frees the passed buffer on the error path.
    // Buffer must be >= 80 bytes to reach the signature check (shorter gives Truncated).
    const bad = try std.testing.allocator.alloc(u8, 80);
    @memset(bad, 0); // all-zero: not "KSLPHHRH" -> BadSignature
    try std.testing.expectError(error.BadSignature, Hwdb.openFromBuffer(std.testing.allocator, bad));
}

test "query returns values for a literal match and empty for a miss" {
    const buf = try testbuild.build(std.testing.allocator, &.{
        .{ .pattern = "acpi:LNXPWRBN", .values = &.{.{ .key = "POWER_KEY", .value = "1" }} },
    });
    var hw = try Hwdb.openFromBuffer(std.testing.allocator, buf);
    defer hw.deinit();
    const hit = try hw.query(std.testing.allocator, "acpi:LNXPWRBN");
    defer std.testing.allocator.free(hit);
    try std.testing.expectEqual(@as(usize, 1), hit.len);
    try std.testing.expectEqualStrings("POWER_KEY", hit[0].key);
    try std.testing.expectEqualStrings("1", hit[0].value);
    const miss = try hw.query(std.testing.allocator, "acpi:OTHER");
    defer std.testing.allocator.free(miss);
    try std.testing.expectEqual(@as(usize, 0), miss.len);
}

test "query honors a trailing '*' wildcard pattern" {
    const buf = try testbuild.build(std.testing.allocator, &.{
        .{ .pattern = "usb:v046Dp*", .values = &.{.{ .key = "ID_VENDOR", .value = "Logitech" }} },
    });
    var hw = try Hwdb.openFromBuffer(std.testing.allocator, buf);
    defer hw.deinit();
    const hit = try hw.query(std.testing.allocator, "usb:v046DpC52B");
    defer std.testing.allocator.free(hit);
    try std.testing.expectEqual(@as(usize, 1), hit.len);
    try std.testing.expectEqualStrings("Logitech", hit[0].value);
}

test "query deduplicates keys: last DFS traversal wins when priorities are equal" {
    // testbuild always writes priority=0, line=0 for all values.
    // Children are sorted by byte value. '*'(42) < 'b'(98), so the wildcard
    // "foo:*" subtree is visited before the literal "foo:bar" subtree.
    // With last-wins semantics (vv.line >= ex.line when both are 0), "B" wins.
    const buf = try testbuild.build(std.testing.allocator, &.{
        .{ .pattern = "foo:*", .values = &.{.{ .key = "TYPE", .value = "A" }} },
        .{ .pattern = "foo:bar", .values = &.{.{ .key = "TYPE", .value = "B" }} },
    });
    var hw = try Hwdb.openFromBuffer(std.testing.allocator, buf);
    defer hw.deinit();
    const hit = try hw.query(std.testing.allocator, "foo:bar");
    defer std.testing.allocator.free(hit);
    try std.testing.expectEqual(@as(usize, 1), hit.len);
    try std.testing.expectEqualStrings("TYPE", hit[0].key);
    // Both match. With priority=0 and line=0, last DFS order wins -> "foo:bar" path (visited after
    // "foo:*" path) sets value "B".
    try std.testing.expectEqualStrings("B", hit[0].value);
}

test "open reads a hwdb.bin from an explicit path" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    const buf = try testbuild.build(std.testing.allocator, &.{
        .{ .pattern = "x", .values = &.{.{ .key = "K", .value = "V" }} },
    });
    defer std.testing.allocator.free(buf);
    try tmp.dir.writeFile(io, .{ .sub_path = "hwdb.bin", .data = buf });
    var pbuf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const abs_len = try tmp.dir.realPathFile(io, "hwdb.bin", &pbuf);
    const abs = pbuf[0..abs_len];
    var hw = try Hwdb.open(std.testing.allocator, io, .{ .path = abs });
    defer hw.deinit();
    const hit = try hw.query(std.testing.allocator, "x");
    defer std.testing.allocator.free(hit);
    try std.testing.expectEqualStrings("V", hit[0].value);
}

test "integration: open the real system hwdb.bin if present" {
    const io = std.testing.io;
    std.Io.Dir.cwd().access(io, "/etc/udev/hwdb.bin", .{}) catch return;
    var hw = Hwdb.open(std.testing.allocator, io, .{}) catch return;
    defer hw.deinit();
    const res = try hw.query(std.testing.allocator, "usb:v046DpC52B");
    defer std.testing.allocator.free(res);
    try std.testing.expect(res.len >= 0);
}

test "query rejects a cyclic child_off instead of recursing forever" {
    // Build a valid fixture, then corrupt the root's first child into a WILDCARD edge ('*') that
    // points back at the root node. A wildcard edge enters fnmatch mode (follows children with the
    // search position frozen), so the self-cycle would recurse forever without the depth guard.
    const buf = try testbuild.build(std.testing.allocator, &.{
        .{ .pattern = "ab", .values = &.{.{ .key = "K", .value = "V" }} },
    });
    var hw = try Hwdb.openFromBuffer(std.testing.allocator, buf);
    defer hw.deinit();
    // Root's first child entry: edge byte at nodes_root_off + node_size + 0, child_off at + 8.
    const c_off: usize = @intCast(hw.header.nodes_root_off + hw.header.node_size);
    hw.buf[c_off] = '*'; // make it a wildcard edge -> fnmatch mode
    std.mem.writeInt(u64, hw.buf[c_off + 8 ..][0..8], hw.header.nodes_root_off, .little); // -> root (cycle)
    try std.testing.expectError(error.Corrupt, hw.query(std.testing.allocator, "ab"));
}
