//! Test-only fixture builder: produces a valid v2 hwdb.bin buffer in memory.
//! Used by reader tests to build controlled trie fixtures without touching disk.
//! Not for production use.
const std = @import("std");

pub const KV = struct { key: []const u8, value: []const u8 };
pub const Entry = struct { pattern: []const u8, values: []const KV };

// ─── In-memory trie ──────────────────────────────────────────────────────────

const TrieNode = struct {
    children: std.AutoHashMapUnmanaged(u8, *TrieNode) = .empty,
    values: std.ArrayListUnmanaged(KV) = .empty,

    fn deinit(self: *TrieNode, gpa: std.mem.Allocator) void {
        var it = self.children.valueIterator();
        while (it.next()) |vp| {
            vp.*.deinit(gpa);
            gpa.destroy(vp.*);
        }
        self.children.deinit(gpa);
        self.values.deinit(gpa);
    }
};

const ChildEntry = struct { c: u8, child: *TrieNode };

fn childLT(_: void, a: ChildEntry, b: ChildEntry) bool {
    return a.c < b.c;
}

// ─── Public builder ───────────────────────────────────────────────────────────

/// Build a valid v2 hwdb.bin buffer from `entries`.
/// The caller (or Hwdb.openFromBuffer) owns the returned slice.
pub fn build(gpa: std.mem.Allocator, entries: []const Entry) ![]u8 {
    // ── 1. Build char-by-char trie ────────────────────────────────────────────
    var root = TrieNode{};
    defer root.deinit(gpa);

    for (entries) |e| {
        var node: *TrieNode = &root;
        for (e.pattern) |c| {
            const gop = try node.children.getOrPut(gpa, c);
            if (!gop.found_existing) {
                const child = try gpa.create(TrieNode);
                child.* = TrieNode{};
                gop.value_ptr.* = child;
            }
            node = gop.value_ptr.*;
        }
        for (e.values) |kv| try node.values.append(gpa, kv);
    }

    // ── 2. Build strings blob ─────────────────────────────────────────────────
    // Strings blob starts at absolute offset 80 (right after the 80-byte header).
    const HEADER_SIZE: u64 = 80;
    const NODE_SIZE: u64 = 24;
    const CHILD_ENTRY_SIZE: u64 = 16;
    const VALUE_ENTRY_SIZE: u64 = 32;

    var str_map = std.StringHashMapUnmanaged(u64).empty;
    defer str_map.deinit(gpa);

    var strings = std.ArrayListUnmanaged(u8).empty;
    defer strings.deinit(gpa);

    // First byte of the strings blob is a NUL, representing the empty prefix.
    // Its absolute offset is HEADER_SIZE = 80.
    try strings.append(gpa, 0);
    const empty_off: u64 = HEADER_SIZE;

    // Intern every distinct key and value string.
    for (entries) |e| {
        for (e.values) |kv| {
            if (!str_map.contains(kv.key)) {
                const off = HEADER_SIZE + @as(u64, strings.items.len);
                try str_map.put(gpa, kv.key, off);
                try strings.appendSlice(gpa, kv.key);
                try strings.append(gpa, 0);
            }
            if (!str_map.contains(kv.value)) {
                const off = HEADER_SIZE + @as(u64, strings.items.len);
                try str_map.put(gpa, kv.value, off);
                try strings.appendSlice(gpa, kv.value);
                try strings.append(gpa, 0);
            }
        }
    }
    const strings_len: u64 = @intCast(strings.items.len);
    const nodes_base: u64 = HEADER_SIZE + strings_len;

    // ── 3. BFS: collect nodes in traversal order ──────────────────────────────
    var order = std.ArrayListUnmanaged(*TrieNode).empty;
    defer order.deinit(gpa);

    try order.append(gpa, &root);
    var qi: usize = 0;
    while (qi < order.items.len) : (qi += 1) {
        const node = order.items[qi];
        var clist = std.ArrayListUnmanaged(ChildEntry).empty;
        defer clist.deinit(gpa);
        var it = node.children.iterator();
        while (it.next()) |ce| {
            try clist.append(gpa, .{ .c = ce.key_ptr.*, .child = ce.value_ptr.* });
        }
        std.sort.insertion(ChildEntry, clist.items, {}, childLT);
        for (clist.items) |ce| try order.append(gpa, ce.child);
    }

    // ── 4. Assign absolute offsets (second pass) ──────────────────────────────
    var offsets = std.AutoHashMapUnmanaged(*TrieNode, u64).empty;
    defer offsets.deinit(gpa);

    var cur: u64 = nodes_base;
    for (order.items) |node| {
        try offsets.put(gpa, node, cur);
        const cc: u64 = @intCast(node.children.count());
        const vc: u64 = @intCast(node.values.items.len);
        cur += NODE_SIZE + cc * CHILD_ENTRY_SIZE + vc * VALUE_ENTRY_SIZE;
    }
    const nodes_len: u64 = cur - nodes_base;
    const file_size: u64 = HEADER_SIZE + strings_len + nodes_len;
    const root_off: u64 = offsets.get(&root).?;

    // ── 5. Serialize ──────────────────────────────────────────────────────────
    var buf = std.ArrayListUnmanaged(u8).empty;
    errdefer buf.deinit(gpa);
    try buf.ensureTotalCapacity(gpa, @intCast(file_size));

    var t8: [8]u8 = undefined;
    var t4: [4]u8 = undefined;

    // Header (80 bytes)
    try buf.appendSlice(gpa, "KSLPHHRH");
    std.mem.writeInt(u64, &t8, 1, .little);
    try buf.appendSlice(gpa, &t8); // tool_version
    std.mem.writeInt(u64, &t8, file_size, .little);
    try buf.appendSlice(gpa, &t8); // file_size
    std.mem.writeInt(u64, &t8, HEADER_SIZE, .little);
    try buf.appendSlice(gpa, &t8); // header_size
    std.mem.writeInt(u64, &t8, NODE_SIZE, .little);
    try buf.appendSlice(gpa, &t8); // node_size
    std.mem.writeInt(u64, &t8, CHILD_ENTRY_SIZE, .little);
    try buf.appendSlice(gpa, &t8); // child_entry_size
    std.mem.writeInt(u64, &t8, VALUE_ENTRY_SIZE, .little);
    try buf.appendSlice(gpa, &t8); // value_entry_size
    std.mem.writeInt(u64, &t8, root_off, .little);
    try buf.appendSlice(gpa, &t8); // nodes_root_off
    std.mem.writeInt(u64, &t8, nodes_len, .little);
    try buf.appendSlice(gpa, &t8); // nodes_len
    std.mem.writeInt(u64, &t8, strings_len, .little);
    try buf.appendSlice(gpa, &t8); // strings_len

    // Strings blob
    try buf.appendSlice(gpa, strings.items);

    // Nodes (BFS order matches the offsets assigned above)
    for (order.items) |node| {
        // Re-sort children so child_off entries match BFS-assigned offsets.
        var clist = std.ArrayListUnmanaged(ChildEntry).empty;
        defer clist.deinit(gpa);
        var it = node.children.iterator();
        while (it.next()) |ce| {
            try clist.append(gpa, .{ .c = ce.key_ptr.*, .child = ce.value_ptr.* });
        }
        std.sort.insertion(ChildEntry, clist.items, {}, childLT);

        const cc: u8 = @intCast(clist.items.len);
        const vc: u64 = @intCast(node.values.items.len);

        // Node header: prefix_off(8) children_count(1) pad(7) values_count(8) = 24 bytes
        std.mem.writeInt(u64, &t8, empty_off, .little);
        try buf.appendSlice(gpa, &t8);
        try buf.append(gpa, cc);
        try buf.appendNTimes(gpa, 0, 7);
        std.mem.writeInt(u64, &t8, vc, .little);
        try buf.appendSlice(gpa, &t8);

        // Child entries: c(1) pad(7) child_off(8) = 16 bytes each
        for (clist.items) |ce| {
            try buf.append(gpa, ce.c);
            try buf.appendNTimes(gpa, 0, 7);
            std.mem.writeInt(u64, &t8, offsets.get(ce.child).?, .little);
            try buf.appendSlice(gpa, &t8);
        }

        // Value entries: key_off(8) value_off(8) filename_off(8) line(4) prio(4) = 32 bytes each
        for (node.values.items) |kv| {
            std.mem.writeInt(u64, &t8, str_map.get(kv.key).?, .little);
            try buf.appendSlice(gpa, &t8);
            std.mem.writeInt(u64, &t8, str_map.get(kv.value).?, .little);
            try buf.appendSlice(gpa, &t8);
            std.mem.writeInt(u64, &t8, empty_off, .little);
            try buf.appendSlice(gpa, &t8);
            std.mem.writeInt(u32, &t4, 0, .little);
            try buf.appendSlice(gpa, &t4); // line
            std.mem.writeInt(u32, &t4, 0, .little);
            try buf.appendSlice(gpa, &t4); // file_priority
        }
    }

    std.debug.assert(buf.items.len == file_size);
    return buf.toOwnedSlice(gpa);
}
