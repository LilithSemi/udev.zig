/// Pure-Zig subset of linux/input-event-codes.h needed by input_id.
/// Zero C deps. Values match Linux uapi 6.x (stable).
const std = @import("std");

pub const EV = struct {
    pub const SYN: u8 = 0x00;
    pub const KEY: u8 = 0x01;
    pub const REL: u8 = 0x02;
    pub const ABS: u8 = 0x03;
    pub const MSC: u8 = 0x04;
    pub const SW: u8 = 0x05;
    pub const LED: u8 = 0x11;
    pub const FF: u8 = 0x15;
    pub const MAX: u8 = 0x1f;
};

pub const INPUT_PROP = struct {
    pub const POINTER: u8 = 0x00;
    pub const DIRECT: u8 = 0x01;
    pub const ACCELEROMETER: u8 = 0x06;
};

pub const KEY = struct {
    pub const ESC: u16 = 1;
    pub const Q: u16 = 16;
    pub const D: u16 = 32;
    pub const MAX: u16 = 0x2ff;
    pub const CNT: u16 = 0x300;
};

pub const BTN = struct {
    pub const MISC: u16 = 0x100;
    pub const MOUSE: u16 = 0x110;
    pub const LEFT: u16 = 0x110;
    pub const JOYSTICK: u16 = 0x120;
    pub const GAMEPAD: u16 = 0x130;
    pub const TOOL_PEN: u16 = 0x140;
    pub const TOOL_FINGER: u16 = 0x145;
    pub const TOUCH: u16 = 0x14a;
    pub const STYLUS: u16 = 0x14b;
    pub const TRIGGER_HAPPY: u16 = 0x2c0;
};

pub const REL = struct {
    pub const X: u8 = 0x00;
    pub const Y: u8 = 0x01;
};

pub const ABS = struct {
    pub const X: u8 = 0x00;
    pub const Y: u8 = 0x01;
    pub const Z: u8 = 0x02;
    pub const RX: u8 = 0x03;
    pub const RY: u8 = 0x04;
    pub const RZ: u8 = 0x05;
    pub const THROTTLE: u8 = 0x06;
    pub const RUDDER: u8 = 0x07;
    pub const WHEEL: u8 = 0x08;
    pub const GAS: u8 = 0x09;
    pub const BRAKE: u8 = 0x0a;
    pub const HAT0X: u8 = 0x10;
    pub const MISC: u8 = 0x28;
    pub const MT_SLOT: u8 = 0x2f;
    pub const MT_POSITION_X: u8 = 0x35;
    pub const MT_POSITION_Y: u8 = 0x36;
    pub const MAX: u8 = 0x3f;
};

test "EV.KEY == 1" {
    try std.testing.expectEqual(@as(u8, 1), EV.KEY);
}

test "ABS.MT_POSITION_X == 0x35" {
    try std.testing.expectEqual(@as(u8, 0x35), ABS.MT_POSITION_X);
}

test "BTN.TOUCH == 0x14a" {
    try std.testing.expectEqual(@as(u16, 0x14a), BTN.TOUCH);
}

test "KEY.MAX == 0x2ff" {
    try std.testing.expectEqual(@as(u16, 0x2ff), KEY.MAX);
}
