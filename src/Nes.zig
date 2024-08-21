const std = @import("std");
const util = @import("util.zig");
const instr = @import("instruction.zig");

m: AnyMapper,
cpu_ram: *[0x800]u8,
cpu: Cpu,

const Self = @This();

const AnyMapper = @import("Mapper.zig");

const page_size = 0x4000;

const log = std.log.scoped(.@"nes-core");
const cpu_log = std.log.scoped(.@"nes-cpu");

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
        /// Decimal
        d: u1 = 0,
        /// B Flag
        b: u1 = 0,
        _always_1: u1 = 1,
        /// Overflow
        v: u1 = 0,
        /// Negative
        n: u1 = 0,

        pub fn val(self: Flags) u8 {
            return @as(u8, @bitCast(self));
        }
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
        self.pc = n.readBusWide(0xfffc);
        self.s -%= 3;
    }

    pub fn log_state(self: *S) void {
        // multiline string literals broken or PEBKAC
        cpu_log.debug(@embedFile("./cpu_state_fmt.txt"), .{
            self.pc,
            self.s,
            self.a,
            self.x,
            self.y,
            self.p.val(),
            if (self.p.c == 1) "C" else "_",
            if (self.p.z == 1) "Z" else "_",
            if (self.p.i == 1) "I" else "_",
            if (self.p.d == 1) "D" else "_",
            if (self.p.v == 1) "V" else "_",
            if (self.p.n == 1) "N" else "_",
        });
    }
};

/// Read directly, don't do anything else (debug/internal)
fn readImpl(self: *Self, addr: u16) u8 {
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

fn readImplWide(self: *Self, addr: u16) u16 {
    const lower = self.readImpl(addr);
    const upper = self.readImpl(addr +% 1);
    return lower | @as(u16, upper) << 8;
}

/// Emulate reading from the bus
fn readBus(self: *Self, addr: u16) u8 {
    return self.readImpl(addr);
}

/// Doesn't deal with page wrapping
fn readBusWide(self: *Self, addr: u16) u16 {
    const lower = self.readBus(addr);
    const upper = self.readBus(addr +% 1);
    return lower | @as(u16, upper) << 8;
}

fn writeBus(self: *Self, addr: u16, val: u8) void {
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
    const ROMHeader = packed struct(u128) {
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
    ret.cpu.log_state();

    for (0..9) |_| {
        _ = ret.cpuFetchDecode();
    }
    return ret;
}

pub fn deinit(self: *Self) void {
    util.alloc.destroy(self.cpu_ram);
    self.m.deinit();
}

pub fn update(self: *Self) void {
    self.cpuExec();
}

fn fetchPc(self: *Self) u8 {
    const ret = self.readBus(self.cpu.pc);
    self.cpu.pc +%= 1;
    return ret;
}

fn fetchPcWide(self: *Self) u16 {
    const ret = self.readBusWide(self.cpu.pc);
    self.cpu.pc +%= 2;
    return ret;
}

fn resolveTargetAddr(
    self: *Self,
    op: instr.Op,
    mode: instr.Mode,
) u16 {
    const c = self.cpu;
    const force_page_cross = op == .sta or op == .stx or op == .sty;
    switch (mode) {
        .implicit, .imm => {
            @panic("mode doesn't resolve to an address");
        },
        .rel => {
            const off = @as(i8, @bitCast(self.fetchPc()));
            return c.pc +% @as(u16, @bitCast(@as(i16, off)));
        },
        .page0 => {
            const off = self.fetchPc();
            return @as(u16, off);
        },
        .abs => {
            const addr = self.fetchPcWide();
            return addr;
        },
        .ind => {
            const iaddr = self.fetchPcWide();
            return self.readBusWide(iaddr);
        },
        .page0_x, .page0_y => {
            const reg_val = if (mode == .abs_x) c.x else c.y;
            return @as(u16, self.fetchPc() +% reg_val);
        },
        .abs_x, .abs_y => {
            const reg_val = if (mode == .abs_x) c.x else c.y;
            var addr = self.fetchPcWide();

            // if page crossing occurs, the CPU performs a dummy read (?)
            // TODO: also waste a cycle when cycle counting is implemented
            // TODO: figure out if my reading of this behavior is correct
            const res = @addWithOverflow(
                @as(u8, @intCast(addr & 0xff)),
                reg_val,
            );
            addr = addr & 0xff00 | res[0];
            // store instructions always do this read, use a parameter (?)
            if (res[1] == 1 or force_page_cross) _ = self.readBus(addr);
            return addr +% (@as(u16, res[1]) << 8);
        },
        .idx_ind => {
            const off = self.fetchPc();
            const base = off +% c.x;
            const lo = self.readBus(base);
            const hi = self.readBus(base +% 1);
            return lo | @as(u16, hi) << 8;
        },
        .ind_idx => {
            const off = self.fetchPc();
            const lo = self.readBus(off);
            const hi = self.readBus(off +% 1);
            var addr = lo | @as(u16, hi) << 8;
            const res = @addWithOverflow(@as(u8, @intCast(addr & 0xff)), c.y);
            addr = addr & 0xff00 | res[0];
            if (res[1] == 1) _ = self.readBus(addr);
            return addr +% (@as(u16, res[1]) << 8);
        },
    }
}

/// Returns an internal representation of the data the instruction operates on
fn cpuFetchDecode(self: *Self) u16 {
    // const c = self.cpu;
    const opcode = self.fetchPc();
    const decoded = instr.decode(opcode);
    const op = decoded[0];
    const m = decoded[1];
    const mname = if (m == .implicit) "" else @tagName(m);
    log.debug("{s} {s}", .{ @tagName(op), mname });
    if (m != .imm and m != .implicit and m != .rel) {
        const addr = self.resolveTargetAddr(op, m);
        log.debug("\taddr: ${x:04}", .{addr});
        return addr;
    } else if (m != .implicit) {
        const byte = self.fetchPc();
        log.debug("\targ: ${x:02}", .{byte});
        return @as(u16, byte);
    } else {
        return 0;
    }
}
