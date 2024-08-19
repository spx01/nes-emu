const std = @import("std");
const util = @import("util.zig");

m: AnyMapper,
cpu_ram: *[0x800]u8,
cpu: Cpu,

const Self = @This();

const AnyMapper = @import("Mapper.zig");

const page_size = 0x4000;

const log = std.log.scoped(.@"nes-core");

/// NROM
const Mapper0 = struct {
    // Only one page for now
    // TODO
    prg_rom: [page_size]u8,

    // TODO: PPU

    const S = @This();

    pub fn create(prg_data_stream: std.io.AnyReader) !*S {
        // TODO: maybe the mapper should receive the entire ROM file?
        const ret = try util.alloc.create(S);
        errdefer util.alloc.destroy(ret);
        const cnt = try prg_data_stream.read(&ret.prg_rom);
        if (cnt != page_size) return error.ROMData;
        return ret;
    }

    const mirror_mask = 0xbfff;

    pub fn read(self: *S, addr: u16) u8 {
        if (addr < 0x8000) {
            // Maybe RAM, or invalid
            // TODO: open bus behavior?
            @panic("low PRG address");
        }
        const masked = (addr & mirror_mask) - 0x8000;
        return self.prg_rom[masked];
    }

    pub fn write(self: *S, addr: u16, data: u8) void {
        const masked = addr & mirror_mask;
        self.prg_rom[masked] = data;
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

const Cpu = struct {
    a: u8,
    x: u8,
    y: u8,
    pc: u16,
    s: u8,
    p: Flags,

    const Flags = packed struct(u8) {
        /// Carry
        c: u1 = 0,
        /// Zero
        z: u1 = 0,
        /// Interrupt Disable
        i: u1 = 1,
        /// B Flag
        b: u1 = 0,
        _always_1: u1 = 1,
        /// Overflow
        v: u1 = 0,
        /// Negative
        n: u1 = 0,
        /// Pad to 8 bits
        _pad: u1 = 0,
    };

    const S = @This();
    // in case we move this somewhere else
    const Nes = Self;

    /// Reset has to be run as well before reaching the powerup state
    pub fn init() S {
        return .{
            .a = 0,
            .x = 0,
            .y = 0,
            .pc = 0,
            .s = 0,
            .p = .{},
        };
    }

    pub fn reset(self: *S, n: *Nes) void {
        self.p.i = 1;
        // TODO: implement wide reads
        self.pc = n.busRead(0xfffc) | (@as(u16, n.busRead(0xfffd)) << 8);
        self.s = @subWithOverflow(self.s, 3)[0];
    }
};

fn busRead(self: *Self, addr: u16) u8 {
    switch (addr) {
        0...0x1fff => {
            // Read from CPU memory
            const masked = addr & 0x7ff;
            return self.cpu_ram[masked];
        },
        0x2000...0x3fff => {
            // PPU registers
            // TODO
            @panic("PPU registers");
        },
        0x4000...0x4017 => {
            // APU and I/O registers
            // TODO
            @panic("APU and I/O");
        },
        0x4018...0x401f => {
            // Disabled functionality
            @panic("disabled functionality");
        },
        0x4020...0xffff => {
            return self.m.read(addr);
        },
    }
    unreachable;
}

fn busWrite(self: *Self, addr: u16, val: u8) void {
    switch (addr) {
        0...0x1fff => {
            // Read from CPU memory
            const masked = addr & 0x7ff;
            self.cpu_mem[masked] = val;
        },
        0x2000...0x3fff => {
            // PPU registers
            // TODO
            @panic("PPU registers");
        },
        0x4000...0x4017 => {
            // APU and I/O registers
            // TODO
            @panic("APU and I/O");
        },
        0x4018...0x401f => {
            // Disabled functionality
            @panic("disabled functionality");
        },
        0x4020...0xffff => {
            self.m.write(addr, val);
        },
    }
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
    errdefer util.alloc.destroy(ret.cpu_ram);

    ret.m = (try Mapper0.create(reader)).any();
    errdefer ret.m.deinit();

    ret.cpu = Cpu.init();
    ret.cpu.reset(&ret);

    log.info("initialized an NES", .{});
    return ret;
}

pub fn deinit(self: *Self) void {
    util.alloc.destroy(self.cpu_ram);
    self.m.deinit();
}
