const std = @import("std");
const util = @import("util.zig");
const Nes = @import("Nes.zig");
const instr = @import("instruction.zig");

pub fn main() !void {
    const rom_file = try std.fs.cwd().openFile("other/helloworld.nes", .{});
    defer rom_file.close();

    const test_data = [_]struct { instr.Op, instr.Operand }{
        .{ .sei, .implicit },
        .{ .cld, .implicit },
        .{ .ldx, .{ .imm = 0x40 } },
        .{ .jmp, .{ .ind = 0xfffc } },
        .{ .beq, .{ .rel = @bitCast(@as(i8, -2)) } },
        .{ .cmp, .{ .ind_idx = 0xfc } },
    };
    const assembled = instr.encodeStreamDebug(&test_data);
    std.debug.dumpHex(assembled);

    //var machine = try Nes.fromRom(rom_file.reader().any());
    var machine = try Nes.fromCpuInstructions(assembled);
    defer machine.deinit();

    machine.debugStuff();
}
