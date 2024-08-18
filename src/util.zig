const std = @import("std");
const builtin = @import("builtin");

pub fn assert_le() void {
    comptime std.debug.assert(builtin.target.cpu.arch.endian() == .little);
}

pub var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
pub var alloc: std.mem.Allocator = gpa.allocator();
