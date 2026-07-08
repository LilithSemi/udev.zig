//! Lexer helpers for udev rules files.
//! Handles entry splitting (commas outside double quotes) and per-entry
//! tokenization into key / optional {arg} / operator / quoted value.
//! Key-to-enum mapping and AST construction live in parser.zig.

const std = @import("std");

/// One entry tokenized from a raw text entry string.
/// All slices are views into the original text; no allocation is performed here.
pub const RawEntry = struct {
    key: []const u8,
    arg: ?[]const u8,
    op: []const u8,
    value: []const u8,
};

fn isKeyChar(c: u8) bool {
    return (c >= 'A' and c <= 'Z') or
        (c >= 'a' and c <= 'z') or
        (c >= '0' and c <= '9') or
        c == '_';
}

/// Split `line` on commas that are outside double quotes.
/// Returns a slice of trimmed, non-empty entry strings (views into `line`).
/// The returned slice and its backing array are owned by `allocator`.
pub fn splitEntries(allocator: std.mem.Allocator, line: []const u8) ![]const []const u8 {
    var list: std.ArrayListUnmanaged([]const u8) = .empty;
    var start: usize = 0;
    var in_quote = false;
    var i: usize = 0;
    while (i < line.len) : (i += 1) {
        const c = line[i];
        if (c == '"') {
            in_quote = !in_quote;
        } else if (c == ',' and !in_quote) {
            const s = std.mem.trim(u8, line[start..i], " \t");
            if (s.len > 0) try list.append(allocator, s);
            start = i + 1;
        }
    }
    const tail = std.mem.trim(u8, line[start..], " \t");
    if (tail.len > 0) try list.append(allocator, tail);
    return try list.toOwnedSlice(allocator);
}

/// Tokenize one entry string (e.g. `ENV{ID_FS_TYPE}=="ext4"`).
/// Returns null on any malformed input (caller should emit a diagnostic).
/// All slices in the result are views into `entry`, with no allocation.
pub fn tokenizeEntry(entry: []const u8) ?RawEntry {
    var i: usize = 0;

    // KEY: one or more key characters
    const key_start = i;
    while (i < entry.len and isKeyChar(entry[i])) : (i += 1) {}
    if (i == key_start) return null;
    const key = entry[key_start..i];

    // Optional {arg}
    var arg: ?[]const u8 = null;
    if (i < entry.len and entry[i] == '{') {
        i += 1; // skip '{'
        const arg_start = i;
        while (i < entry.len and entry[i] != '}') : (i += 1) {}
        if (i >= entry.len) return null; // unclosed brace
        // An empty arg ("{}") yields arg = "" (not null). That is intentional: semantic validity of
        // the arg is the evaluator's job, not the lexer's.
        arg = entry[arg_start..i];
        i += 1; // skip '}'
    }

    // Skip optional whitespace between the key/{arg} and the operator. Real udev tolerates spaces
    // around operators (e.g. `KERNEL == "sd*"`), so rules files in the wild must not be rejected.
    while (i < entry.len and (entry[i] == ' ' or entry[i] == '\t')) : (i += 1) {}

    // Operator: check two-char forms first, then single '='
    if (i >= entry.len) return null;
    const op: []const u8 = blk: {
        if (i + 1 < entry.len) {
            const two = entry[i .. i + 2];
            if (std.mem.eql(u8, two, "==") or
                std.mem.eql(u8, two, "!=") or
                std.mem.eql(u8, two, "+=") or
                std.mem.eql(u8, two, "-=") or
                std.mem.eql(u8, two, ":="))
            {
                i += 2;
                break :blk two;
            }
        }
        if (entry[i] == '=') {
            const s = entry[i .. i + 1];
            i += 1;
            break :blk s;
        }
        return null;
    };

    // Optional whitespace between operator and value
    while (i < entry.len and (entry[i] == ' ' or entry[i] == '\t')) : (i += 1) {}

    // Double-quoted value
    if (i >= entry.len or entry[i] != '"') return null;
    i += 1; // skip opening quote
    const val_start = i;
    // NOTE: value ends at the first '"'. Backslash-escaped quotes inside a value (`\"`) are not
    // supported yet. Real udev rules almost never embed quotes. Revisit if a rule file needs it.
    while (i < entry.len and entry[i] != '"') : (i += 1) {}
    if (i >= entry.len) return null; // unclosed quote
    const value = entry[val_start..i];

    return RawEntry{ .key = key, .arg = arg, .op = op, .value = value };
}
