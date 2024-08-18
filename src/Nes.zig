const std = @import("std");
const util = @import("util.zig");

m: AnyMapper,
cpu_ram: *[0x800]u8,

const Self = @This();

const AnyMapper = @import("Mapper.zig");

/// NROM
const Mapper0 = struct {
    prg_rom: [0x4000]u8,
    chr_rom: [0x2000]u8,

    const S = @This();

    pub fn create() !*S {
        // TODO:
        return try util.alloc.create(S);
    }

    pub fn read(self: *S, addr: u16) u8 {
        _ = self;
        _ = addr;
        return 0;
    }

    pub fn write(self: *S, addr: u16, data: u8) void {
        _ = self;
        _ = addr;
        _ = data;
    }

    pub fn destroy(self: *S) void {
        util.alloc.destroy(self);
    }

    pub fn any(self: *S) AnyMapper {
        return .{
            .context = self,
            .id = .NROM,
            .vt = &.{
                .read = @ptrCast(&S.read),
                .write = @ptrCast(&S.write),
                .deinit = @ptrCast(&S.destroy),
            },
        };
    }
};

fn busRead(self: *Self, addr: u16) u8 {
    _ = self;
    _ = addr;
}

fn busWrite(self: *Self, addr: u16, val: u8) void {
    _ = self;
    _ = addr;
    _ = val;
}

/// Initializes an NES from iNES data.
pub fn fromRom(reader: std.io.AnyReader) !Self {
    // TODO: implement NES2.0
    const ROMHeader = packed struct {
        // NOTE: https://github.com/ziglang/zig/issues/12547
        // this means not even byte arrays are allowed
        // TODO: write a better readStruct
        magic: u32,
        /// Size of PRG ROM in 16KB units.
        prg_npages: u8,
        /// Size of CHR ROM in 8KB units.
        chr_npages: u8,

        nametable_arr: u1, // TODO
        extra_mem: bool, // TODO
        trainer: bool, // TODO
        alt_nametable: bool, // TODO
        mapper_lower: u4,
        vs_unisystem: bool, // TODO
        playchoice_10: bool, // TODO
        nes2_id: u2,
        mapper_upper: u4,

        /// TODO
        _flags8: u8,
        /// TODO
        _flags9: u8,
        /// TODO
        _flags10: u8,
        _pad: u40,

        comptime {
            std.debug.assert(@sizeOf(@This()) == 16);
        }
    };

    const header = try reader.readStruct(ROMHeader);

    if (!std.mem.eql(
        u8,
        std.mem.asBytes(&header.magic),
        "NES\x1a",
    )) return error.InvalidMagic;
    if (header.nes2_id == 2) return error.NES2;

    const mapper_val =
        header.mapper_lower | (@as(u8, header.mapper_upper) << 4);

    std.debug.assert(mapper_val == 0); // only Mapper0 supported

    var ret: @This() = undefined;
    ret.cpu_ram = try util.alloc.create(@TypeOf(ret.cpu_ram.*));
    ret.m = (try Mapper0.create()).any();
    return ret;
}

pub fn deinit(self: *Self) void {
    util.alloc.destroy(self.cpu_ram);
    self.m.deinit();
}
