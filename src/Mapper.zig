const std = @import("std");

context: *allowzero anyopaque,
id: Type,
vt: *const VTable,

const Self = @This();

pub const VTable = struct {
    read: *const fn (context: *allowzero anyopaque, addr: u16) ?u8,
    write: *const fn (context: *allowzero anyopaque, addr: u16, val: u8) void,
    deinit: ?*const fn (context: *anyopaque) void,
};

pub const Type = enum(u8) {
    nrom = 0,
    dummy,
};

pub fn read(self: *Self, addr: u16) ?u8 {
    return self.vt.read(self.context, addr);
}

pub fn write(self: *Self, addr: u16, val: u8) void {
    self.vt.write(self.context, addr, val);
}

pub fn deinit(self: *Self) void {
    if (self.vt.deinit) |f| f(self.context);
}
