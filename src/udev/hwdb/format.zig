//! On-disk structs and readers for the compiled hwdb.bin trie.
//! All offsets in hwdb.bin are absolute byte offsets into the file buffer.
//! All multi-byte integers are little-endian.
//! No allocations: readers return views/values backed by the caller's buffer.

const std = @import("std");

pub const signature = "KSLPHHRH";

pub const Header = struct {
    tool_version: u64,
    file_size: u64,
    header_size: u64,
    node_size: u64,
    child_entry_size: u64,
    value_entry_size: u64,
    nodes_root_off: u64,
    nodes_len: u64,
    strings_len: u64,
};

pub const FormatError = error{ BadSignature, Truncated, Corrupt };

/// Parse and validate the 80-byte file header.
/// Returns error.Truncated if bytes.len < 80.
/// Returns error.BadSignature if the magic bytes do not match.
/// Returns error.Corrupt if any structural invariant is violated.
pub fn readHeader(bytes: []const u8) FormatError!Header {
    if (bytes.len < 80) return error.Truncated;
    if (!std.mem.eql(u8, bytes[0..8], signature)) return error.BadSignature;

    const tool_version = std.mem.readInt(u64, bytes[8..][0..8], .little);
    const file_size = std.mem.readInt(u64, bytes[16..][0..8], .little);
    const header_size = std.mem.readInt(u64, bytes[24..][0..8], .little);
    const node_size = std.mem.readInt(u64, bytes[32..][0..8], .little);
    const child_entry_size = std.mem.readInt(u64, bytes[40..][0..8], .little);
    const value_entry_size = std.mem.readInt(u64, bytes[48..][0..8], .little);
    const nodes_root_off = std.mem.readInt(u64, bytes[56..][0..8], .little);
    const nodes_len = std.mem.readInt(u64, bytes[64..][0..8], .little);
    const strings_len = std.mem.readInt(u64, bytes[72..][0..8], .little);

    if (header_size < 80) return error.Corrupt;
    if (file_size > @as(u64, bytes.len)) return error.Corrupt;
    if (node_size < 24) return error.Corrupt;
    if (child_entry_size < 16) return error.Corrupt;
    if (value_entry_size != 16 and value_entry_size != 32) return error.Corrupt;
    const root_end = std.math.add(u64, nodes_root_off, node_size) catch return error.Corrupt;
    if (root_end > @as(u64, bytes.len)) return error.Corrupt;

    return Header{
        .tool_version = tool_version,
        .file_size = file_size,
        .header_size = header_size,
        .node_size = node_size,
        .child_entry_size = child_entry_size,
        .value_entry_size = value_entry_size,
        .nodes_root_off = nodes_root_off,
        .nodes_len = nodes_len,
        .strings_len = strings_len,
    };
}

/// View of a trie node at absolute offset `off`.
pub const NodeView = struct {
    prefix_off: u64,
    children_count: u8,
    values_count: u64,
};

/// Read a NodeView from bytes at absolute offset `off`.
/// On-disk layout (node_size >= 24):
///   off+0:  prefix_off   u64
///   off+8:  children_count u8
///   off+9:  _pad[7]
///   off+16: values_count u64
pub fn readNode(bytes: []const u8, h: Header, off: u64) FormatError!NodeView {
    const end_u64 = std.math.add(u64, off, h.node_size) catch return error.Corrupt;
    if (end_u64 > @as(u64, bytes.len)) return error.Corrupt;
    const o = std.math.cast(usize, off) orelse return error.Corrupt;

    const prefix_off = std.mem.readInt(u64, bytes[o..][0..8], .little);
    const children_count = bytes[o + 8];
    const values_count = std.mem.readInt(u64, bytes[o + 16 ..][0..8], .little);

    return NodeView{
        .prefix_off = prefix_off,
        .children_count = children_count,
        .values_count = values_count,
    };
}

/// Return the child character byte for child index `i` of the node at `node_off`.
/// Child i lives at node_off + node_size + i * child_entry_size.
/// On-disk child entry (child_entry_size >= 16):
///   +0: c u8
///   +1: _pad[7]
///   +8: child_off u64
pub fn childC(bytes: []const u8, h: Header, node_off: u64, i: u8) FormatError!u8 {
    const child_base = std.math.add(u64, node_off, h.node_size) catch return error.Corrupt;
    const stride = std.math.mul(u64, @as(u64, i), h.child_entry_size) catch return error.Corrupt;
    const entry_off = std.math.add(u64, child_base, stride) catch return error.Corrupt;
    const entry_end = std.math.add(u64, entry_off, h.child_entry_size) catch return error.Corrupt;
    if (entry_end > @as(u64, bytes.len)) return error.Corrupt;
    const o = std.math.cast(usize, entry_off) orelse return error.Corrupt;
    return bytes[o];
}

/// Return the child node offset for child index `i` of the node at `node_off`.
pub fn childOff(bytes: []const u8, h: Header, node_off: u64, i: u8) FormatError!u64 {
    const child_base = std.math.add(u64, node_off, h.node_size) catch return error.Corrupt;
    const stride = std.math.mul(u64, @as(u64, i), h.child_entry_size) catch return error.Corrupt;
    const entry_off = std.math.add(u64, child_base, stride) catch return error.Corrupt;
    const entry_end = std.math.add(u64, entry_off, h.child_entry_size) catch return error.Corrupt;
    if (entry_end > @as(u64, bytes.len)) return error.Corrupt;
    const o = std.math.cast(usize, entry_off) orelse return error.Corrupt;
    return std.mem.readInt(u64, bytes[o + 8 ..][0..8], .little);
}

/// View of a trie value entry.
/// v1 (value_entry_size == 16): priority and line are 0.
/// v2 (value_entry_size == 32): priority == file_priority, line == line.
pub const ValueView = struct {
    key_off: u64,
    value_off: u64,
    priority: u32,
    line: u32,
};

/// Read value index `i` for the node at `node_off` with `children_count` children.
/// Value section starts at: node_off + node_size + children_count * child_entry_size.
/// v1 on-disk (16 bytes): key_off u64, value_off u64.
/// v2 on-disk (32 bytes): key_off u64, value_off u64, filename_off u64, line u32, file_priority u32.
pub fn readValue(bytes: []const u8, h: Header, node_off: u64, children_count: u8, i: u64) FormatError!ValueView {
    const child_section = std.math.mul(u64, @as(u64, children_count), h.child_entry_size) catch return error.Corrupt;
    const value_base_rel = std.math.add(u64, h.node_size, child_section) catch return error.Corrupt;
    const value_base = std.math.add(u64, node_off, value_base_rel) catch return error.Corrupt;
    const entry_stride = std.math.mul(u64, i, h.value_entry_size) catch return error.Corrupt;
    const entry_off = std.math.add(u64, value_base, entry_stride) catch return error.Corrupt;
    const entry_end = std.math.add(u64, entry_off, h.value_entry_size) catch return error.Corrupt;
    if (entry_end > @as(u64, bytes.len)) return error.Corrupt;
    const o = std.math.cast(usize, entry_off) orelse return error.Corrupt;

    const key_off = std.mem.readInt(u64, bytes[o..][0..8], .little);
    const value_off = std.mem.readInt(u64, bytes[o + 8 ..][0..8], .little);

    if (h.value_entry_size == 32) {
        const line = std.mem.readInt(u32, bytes[o + 24 ..][0..4], .little);
        const priority = std.mem.readInt(u32, bytes[o + 28 ..][0..4], .little);
        return ValueView{ .key_off = key_off, .value_off = value_off, .priority = priority, .line = line };
    } else {
        return ValueView{ .key_off = key_off, .value_off = value_off, .priority = 0, .line = 0 };
    }
}

/// Return the NUL-terminated string at absolute byte offset `off` in `bytes`.
/// Returns error.Corrupt if off is out of range or no NUL is found before the end.
pub fn cstr(bytes: []const u8, off: u64) FormatError![]const u8 {
    const o = std.math.cast(usize, off) orelse return error.Corrupt;
    if (o >= bytes.len) return error.Corrupt;
    const rest = bytes[o..];
    const null_pos = std.mem.indexOfScalar(u8, rest, 0) orelse return error.Corrupt;
    return rest[0..null_pos];
}

test "readHeader parses a valid 80-byte header" {
    var buf: [80]u8 = [_]u8{0} ** 80;
    @memcpy(buf[0..8], "KSLPHHRH");
    // field k (0-based) at offset 8 + k*8
    std.mem.writeInt(u64, buf[8..16], 260, .little); // tool_version
    std.mem.writeInt(u64, buf[16..24], 80, .little); // file_size == buf.len
    std.mem.writeInt(u64, buf[24..32], 80, .little); // header_size
    std.mem.writeInt(u64, buf[32..40], 24, .little); // node_size
    std.mem.writeInt(u64, buf[40..48], 16, .little); // child_entry_size
    std.mem.writeInt(u64, buf[48..56], 32, .little); // value_entry_size (v2)
    std.mem.writeInt(u64, buf[56..64], 56, .little); // nodes_root_off (fits since node_size 24 -> 80)
    std.mem.writeInt(u64, buf[64..72], 24, .little); // nodes_len
    std.mem.writeInt(u64, buf[72..80], 0, .little); // strings_len
    const h = try readHeader(&buf);
    try std.testing.expectEqual(@as(u64, 32), h.value_entry_size);
    try std.testing.expectEqual(@as(u64, 56), h.nodes_root_off);
}

test "readHeader rejects bad signature and truncation" {
    var buf: [80]u8 = [_]u8{0} ** 80;
    try std.testing.expectError(error.BadSignature, readHeader(&buf));
    @memcpy(buf[0..8], "KSLPHHRH");
    try std.testing.expectError(error.Truncated, readHeader(buf[0..40]));
}

test "cstr reads a NUL-terminated string and bounds-checks" {
    const b = "abc\x00def\x00";
    try std.testing.expectEqualStrings("abc", try cstr(b, 0));
    try std.testing.expectEqualStrings("def", try cstr(b, 4));
    try std.testing.expectError(error.Corrupt, cstr(b, 99));
}
