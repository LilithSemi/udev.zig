//! udev hardware database (hwdb): runtime reader for the compiled hwdb.bin trie + the hwdb builtin.
const std = @import("std");
pub const format = @import("hwdb/format.zig");
pub const reader = @import("hwdb/reader.zig");
pub const builtin = @import("hwdb/builtin.zig");
pub const Hwdb = reader.Hwdb;
pub const KeyValue = reader.KeyValue;
test {
    std.testing.refAllDecls(@This());
}
