const std = @import("std");
const util = @import("util.zig");
const Nes = @import("Nes.zig");
const instr = @import("instruction.zig");

pub fn main() !void {
    const rom_file = try std.fs.cwd().openFile("other/nestest.nes", .{});
    defer rom_file.close();

    const test_data = [_]struct { instr.Op, instr.Operand }{
        .{ .lda, .{ .abs = 0x0001 } },
        .{ .lda, .{ .abs = 0xfdff } },
        .{ .stp, .implicit },
    };
    const assembled = instr.encodeStreamDebug(&test_data);
    std.debug.dumpHex(assembled);

    // var machine = try Nes.fromRom(rom_file.reader().any());
    var machine = try Nes.fromCpuInstructions(assembled);
    defer machine.destroy();

    machine.debugStuff();
}
