const std = @import("std");
const util = @import("util.zig");
const Nes = @import("Nes.zig");

pub fn main() !void {
    const rom_file = try std.fs.cwd().openFile("other/helloworld.nes", .{});
    defer rom_file.close();

    var machine = try Nes.fromRom(rom_file.reader().any());
    defer machine.deinit();
}
