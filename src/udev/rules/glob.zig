//! udev-rules glob matcher.
//! Supports: `*` (any run incl. empty), `?` (one char), `[...]`/`[!...]` char classes
//! with `a-z` ranges, and top-level `|` alternation. No allocation.

const std = @import("std");

/// Returns true if `text` matches `pattern`.
/// Pattern syntax:
///   `*`       matches any sequence of characters (including empty)
///   `?`       matches exactly one character
///   `[abc]`   matches any char in the set
///   `[a-z]`   matches any char in the range a..z
///   `[!abc]`  matches any char NOT in the set
///   `p1|p2`   top-level alternation: true if text matches p1 OR p2
pub fn match(pattern: []const u8, text: []const u8) bool {
    var pi: usize = 0;
    var alt_start: usize = 0;

    while (pi <= pattern.len) {
        const at_end = (pi == pattern.len);
        const is_pipe = (!at_end and pattern[pi] == '|');

        if (at_end or is_pipe) {
            if (matchOne(pattern[alt_start..pi], text)) return true;
            alt_start = pi + 1;
            pi += 1;
            continue;
        }

        // Skip over '[...]' so a '|' inside a class is not treated as alternation.
        if (pattern[pi] == '[') {
            pi += 1;
            if (pi < pattern.len and pattern[pi] == '!') pi += 1;
            while (pi < pattern.len and pattern[pi] != ']') pi += 1;
            // pi now points at ']' or past end. Outer pi += 1 below will advance past it.
        }

        pi += 1;
    }
    return false;
}

/// Match a single alternative (no '|') against text.
fn matchOne(pattern: []const u8, text: []const u8) bool {
    var pi: usize = 0;
    var ti: usize = 0;
    // star_pi: position in pattern right after the last '*' we saw (null = none seen).
    var star_pi: ?usize = null;
    // star_ti: text position at the time we last matched a '*'.
    var star_ti: usize = 0;

    while (ti < text.len) {
        if (pi < pattern.len and pattern[pi] == '*') {
            star_pi = pi + 1;
            star_ti = ti;
            pi += 1;
        } else if (pi < pattern.len and matchChar(pattern, &pi, text[ti])) {
            ti += 1;
        } else if (star_pi) |sp| {
            // Backtrack: the star eats one more character.
            star_ti += 1;
            ti = star_ti;
            pi = sp;
        } else {
            return false;
        }
    }

    // Skip any trailing stars.
    while (pi < pattern.len and pattern[pi] == '*') pi += 1;

    return pi == pattern.len;
}

/// Attempt to match text[ti] against the pattern element starting at pattern[pi.*].
/// Advances pi past the consumed pattern element on success. Returns false on failure
/// (pi is not advanced).
fn matchChar(pattern: []const u8, pi: *usize, c: u8) bool {
    if (pi.* >= pattern.len) return false;

    const ch = pattern[pi.*];

    if (ch == '?') {
        pi.* += 1;
        return true;
    } else if (ch == '[') {
        return matchClass(pattern, pi, c);
    } else if (ch == '*') {
        // Stars are handled by the caller loop. Reaching here means we should not
        // consume a star as a literal match attempt.
        return false;
    } else {
        if (ch == c) {
            pi.* += 1;
            return true;
        }
        return false;
    }
}

/// Parse and evaluate a `[...]` or `[!...]` character class starting at pattern[pi.*] == '['.
/// On success (pattern is well-formed and class matches c), advances pi past ']' and returns true.
/// On negated success (class does not match c), advances pi and returns false.
fn matchClass(pattern: []const u8, pi: *usize, c: u8) bool {
    const class_start = pi.*;
    pi.* += 1; // skip '['

    const negate = (pi.* < pattern.len and pattern[pi.*] == '!');
    if (negate) pi.* += 1;

    var matched = false;

    while (pi.* < pattern.len and pattern[pi.*] != ']') {
        const a = pattern[pi.*];
        pi.* += 1;

        // Check for range `a-z` where the char after `-` is not `]`.
        if (pi.* < pattern.len and pattern[pi.*] == '-' and
            pi.* + 1 < pattern.len and pattern[pi.* + 1] != ']')
        {
            pi.* += 1; // skip '-'
            const b = pattern[pi.*];
            pi.* += 1;
            if (c >= a and c <= b) matched = true;
        } else {
            if (c == a) matched = true;
        }
    }

    if (pi.* < pattern.len and pattern[pi.*] == ']') {
        pi.* += 1; // consume ']'
    } else {
        // Malformed class: rewind and treat the '[' as a literal.
        pi.* = class_start + 1;
        return pattern[class_start] == c;
    }

    return matched != negate;
}

test "glob wildcards and classes" {
    try std.testing.expect(match("sd*", "sda"));
    try std.testing.expect(match("event?", "event0"));
    try std.testing.expect(!match("event?", "event12"));
    try std.testing.expect(match("tty[0-9]", "tty3"));
    try std.testing.expect(!match("tty[!0-9]", "tty3"));
    try std.testing.expect(match("*", ""));
    try std.testing.expect(match("sd*|vd*", "vdb"));
    try std.testing.expect(!match("sd*|vd*", "nvme0"));
    try std.testing.expect(match("abc", "abc"));
    try std.testing.expect(!match("abc", "abd"));
}
