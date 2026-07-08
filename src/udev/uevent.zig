const std = @import("std");

pub const ParseError = error{ BadMagic, Truncated, Malformed };

pub const PropList = struct {
    data: []const u8,

    /// Linear scan of NUL-separated "KEY=VALUE" tokens; returns value slice or null.
    pub fn get(self: PropList, key: []const u8) ?[]const u8 {
        var iter = self.iterator();
        while (iter.next()) |token| {
            if (std.mem.indexOfScalar(u8, token, '=')) |eq| {
                if (std.mem.eql(u8, token[0..eq], key)) {
                    return token[eq + 1 ..];
                }
            }
        }
        return null;
    }

    pub const Iter = struct {
        data: []const u8,
        pos: usize,

        /// Yields each non-empty NUL-separated token; stops at trailing NUL or end.
        pub fn next(self: *Iter) ?[]const u8 {
            if (self.pos >= self.data.len) return null;
            const start = self.pos;
            const end = std.mem.indexOfScalarPos(u8, self.data, self.pos, 0) orelse self.data.len;
            if (end == start) {
                self.pos = self.data.len;
                return null;
            }
            self.pos = end + 1;
            return self.data[start..end];
        }
    };

    pub fn iterator(self: PropList) Iter {
        return .{ .data = self.data, .pos = 0 };
    }
};

pub const Parsed = struct {
    action: ?[]const u8,
    devpath: ?[]const u8,
    props: PropList,
};

/// Parse kernel uevent format: "action@devpath\0KEY=VALUE\0...".
/// Returns views into `buf`; no allocation.
pub fn parseKernel(buf: []const u8) ParseError!Parsed {
    const first_nul = std.mem.indexOfScalar(u8, buf, 0) orelse buf.len;
    const first_token = buf[0..first_nul];

    const at = std.mem.indexOfScalar(u8, first_token, '@') orelse return error.Malformed;
    const action = first_token[0..at];
    const devpath = first_token[at + 1 ..];

    const props_start = if (first_nul < buf.len) first_nul + 1 else buf.len;

    return .{
        .action = action,
        .devpath = devpath,
        .props = .{ .data = buf[props_start..] },
    };
}

/// Parse libudev monitor format: "libudev\0" prefix + 0xfeedcafe magic + header fields + props.
/// Returns views into `buf`; no allocation.
pub fn parseUdev(buf: []const u8) ParseError!Parsed {
    // Need at least 24 bytes to read prefix(8) + magic(4) + header_size(4) +
    // properties_off(4) + properties_len(4).
    if (buf.len < 24) return error.Truncated;

    if (!std.mem.eql(u8, buf[0..8], "libudev\x00")) return error.BadMagic;

    const magic = std.mem.readInt(u32, buf[8..12], .little);
    if (magic != 0xfeedcafe) return error.BadMagic;

    const properties_off = std.mem.readInt(u32, buf[16..20], .little);
    const properties_len = std.mem.readInt(u32, buf[20..24], .little);

    // properties_off must point past the full fixed header: 8-byte prefix + 4-byte magic +
    // 12 bytes of u32 fields + 16 bytes of filter hashes = 40 bytes total. Rejecting anything
    // in [0, 40) prevents filter-hash bytes from being aliased as property data.
    if (properties_off < 40) return error.Malformed;

    // Overflow-safe bounds check (usize is 32-bit on 32-bit targets).
    const needed = std.math.add(usize, properties_off, properties_len) catch return error.Truncated;
    if (needed > buf.len) return error.Truncated;

    return .{
        .action = null,
        .devpath = null,
        .props = .{ .data = buf[properties_off..][0..properties_len] },
    };
}

// Tests
test "parseKernel splits action, devpath, props" {
    const buf = "add@/devices/x/event0\x00ACTION=add\x00SUBSYSTEM=input\x00MAJOR=13\x00";
    const p = try parseKernel(buf);
    try std.testing.expectEqualStrings("add", p.action.?);
    try std.testing.expectEqualStrings("/devices/x/event0", p.devpath.?);
    try std.testing.expectEqualStrings("input", p.props.get("SUBSYSTEM").?);
    try std.testing.expectEqualStrings("13", p.props.get("MAJOR").?);
    try std.testing.expect(p.props.get("NOPE") == null);
}

test "parseUdev validates magic header then parses props" {
    // off(40) + props.len(25) = 65 bytes, so the buffer needs to be [65]u8.
    var buf: [65]u8 = undefined;
    @memcpy(buf[0..8], "libudev\x00");
    std.mem.writeInt(u32, buf[8..12], 0xfeedcafe, .little);
    const props = "ACTION=add\x00SUBSYSTEM=drm\x00";
    const off: u32 = 40;
    std.mem.writeInt(u32, buf[12..16], off, .little); // header_size
    std.mem.writeInt(u32, buf[16..20], off, .little); // properties_off
    std.mem.writeInt(u32, buf[20..24], @as(u32, props.len), .little); // properties_len
    @memset(buf[24..40], 0); // 4 filter-hash u32s
    @memcpy(buf[off..][0..props.len], props);
    const p = try parseUdev(buf[0 .. off + props.len]);
    try std.testing.expectEqualStrings("drm", p.props.get("SUBSYSTEM").?);
}

test "parseUdev rejects bad magic" {
    var buf: [40]u8 = [_]u8{0} ** 40;
    @memcpy(buf[0..8], "libudev\x00");
    try std.testing.expectError(error.BadMagic, parseUdev(&buf));
}

test "parseUdev rejects a buffer shorter than the header" {
    const buf = "libudev\x00\xce\xfa\xed\xfe"; // prefix + magic, but no header fields
    try std.testing.expectError(error.Truncated, parseUdev(buf));
}

test "parseUdev rejects properties_off aliasing the header" {
    var buf: [40]u8 = [_]u8{0} ** 40;
    @memcpy(buf[0..8], "libudev\x00");
    std.mem.writeInt(u32, buf[8..12], 0xfeedcafe, .little);
    std.mem.writeInt(u32, buf[16..20], 0, .little); // properties_off = 0 -> would leak header
    std.mem.writeInt(u32, buf[20..24], 4, .little);
    try std.testing.expectError(error.Malformed, parseUdev(&buf));
}

test "parseKernel rejects a first token with no '@'" {
    const buf = "noatsign\x00KEY=VALUE\x00";
    try std.testing.expectError(error.Malformed, parseKernel(buf));
}
