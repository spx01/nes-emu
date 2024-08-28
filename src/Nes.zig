const std = @import("std");
const util = @import("util.zig");
const instr = @import("instruction.zig");

m: AnyMapper,
cpu_ram: *[0x800]u8,
cpu: Cpu,

const Self = @This();

const AnyMapper = @import("Mapper.zig");

const page_size = 0x4000;

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
            .id = .nrom,
            .vt = &.{
                .read = @ptrCast(&S.read),
                .write = @ptrCast(&S.write),
                .deinit = @ptrCast(&S.destroy),
            },
        };
    }
};

const DummyMapper = struct {
    const S = @This();
    pub fn read(_: *allowzero S, _: u16) u8 {
        return 0;
    }
    pub fn write(_: *allowzero S, _: u16, _: u8) void {}
    pub fn any() AnyMapper {
        return .{
            .context = @ptrFromInt(0),
            .id = .dummy,
            .vt = &.{
                .read = @ptrCast(&S.read),
                .write = @ptrCast(&S.write),
                .deinit = null,
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
        /// B Flag; always 0 in memory
        b: u1 = 0,
        /// Always 1 in memory and on stack
        one: u1 = 1,
        /// Overflow
        v: u1 = 0,
        /// Negative
        n: u1 = 0,

        pub fn value(self: Flags) u8 {
            std.debug.assert(self.one == 1 and self.b == 0);
            return @as(u8, @bitCast(self));
        }

        /// Value for stack pushing
        pub fn pushValue(self: Flags, b: u1) u8 {
            std.debug.assert(self.one == 1);
            return @as(u8, @bitCast(self)) | @as(u8, b) << 4;
        }

        /// Updates Z and N flags for a given value
        pub fn updateZn(self: *Flags, val: u8) void {
            self.z = @intFromBool(val == 0);
            self.n = @intCast(val >> 7);
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

    pub fn logState(self: *S) void {
        // multiline string literals broken or PEBKAC
        std.debug.print(@embedFile("./cpu_state_fmt.txt"), .{
            self.pc,
            self.s,
            self.a,
            self.x,
            self.y,
            self.p.value(),
            if (self.p.c == 1) "[C]" else " c ",
            if (self.p.z == 1) "[Z]" else " z ",
            if (self.p.i == 1) "[I]" else " i ",
            if (self.p.d == 1) "[D]" else " d ",
            if (self.p.v == 1) "[V]" else " v ",
            if (self.p.n == 1) "[N]" else " n ",
        });
    }

    /// Log register state for comparison
    pub fn logStateFixed(self: *S, writer: std.io.AnyWriter) void {
        writer.print(
            "A:{X:02} X:{X:02} Y:{X:02} P:{X:02} SP:{X:02}\n",
            .{ self.a, self.x, self.y, self.p.value(), self.s },
        ) catch unreachable;
    }
};

fn pushStack(self: *Self, val: u8) void {
    self.writeBus(0x100 + @as(u16, self.cpu.s), val);
    self.cpu.s -%= 1;
}

fn pushStackWide(self: *Self, val: u16) void {
    self.pushStack(@intCast(val >> 8));
    self.pushStack(@intCast(val & 0xff));
}

fn popStack(self: *Self) u8 {
    self.cpu.s +%= 1;
    const val = self.readBus(0x100 + @as(u16, self.cpu.s));
    return val;
}

fn popStackWide(self: *Self) u16 {
    const lo = self.popStack();
    const hi = self.popStack();
    return lo | @as(u16, hi) << 8;
}

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
            return 0;
            // @panic("PPU registers");
        },
        0x4000...0x4017 => {
            // APU and I/O registers
            // TODO
            return 0;
            // @panic("APU and I/O");
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
            self.cpu_ram[masked] = val;
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

    var ret: Self = undefined;
    ret.cpu_ram = try util.alloc.create(@TypeOf(ret.cpu_ram.*));
    errdefer util.alloc.destroy(ret.cpu_ram);

    ret.m = (try Mapper0.create(reader)).any();
    errdefer ret.m.deinit();

    ret.cpu = Cpu.init();
    ret.cpu.reset(&ret);

    return ret;
}

/// Initialize code straight into CPU RAM and prepare execution at $0
pub fn fromCpuInstructions(data: []const u8) !Self {
    var ret: Self = undefined;

    ret.cpu_ram = try util.alloc.create(@TypeOf(ret.cpu_ram.*));
    errdefer util.alloc.destroy(ret.cpu_ram);

    std.debug.assert(data.len <= ret.cpu_ram.len);
    @memcpy(@as([*]u8, ret.cpu_ram), data);

    ret.m = DummyMapper.any();
    ret.cpu = Cpu.init();
    ret.cpu.reset(&ret);
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

fn fetchTargetAddr(
    self: *Self,
    op: instr.Op,
    mode: instr.Mode,
) ?u16 {
    const c = &self.cpu;
    const force_page_cross = op == .sta or op == .stx or op == .sty;
    switch (mode) {
        .implicit => {
            return null;
        },
        .imm => {
            // the idea is to not do a bus read here, just return the address
            // and increment the PC as if nothing happened, considering a read
            // at the address is going to be done during execution anyways
            // TODO: is this a good approach?
            const addr = c.pc;
            c.pc +%= 1;
            return addr;
        },
        .rel => {
            // TODO: cycle counting for page crossing
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
            if (iaddr & 0xff == 0xff) {
                // the NES doesn't handle page crossing properly for indirect
                // addressing
                const lo = self.readBus(iaddr);
                const hi = self.readBus(iaddr & 0xff00);
                return lo | @as(u16, hi) << 8;
            }
            return self.readBusWide(iaddr);
        },
        inline .page0_x, .page0_y => |m| {
            const reg_val = if (m == .page0_x) c.x else c.y;
            return @as(u16, self.fetchPc() +% reg_val);
        },
        inline .abs_x, .abs_y => |m| {
            const reg_val = if (m == .abs_x) c.x else c.y;
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

/// Fetch representation of instruction argument without advancing PC
fn prefetchArg(self: *Self, mode: instr.Mode) u16 {
    const size = instr.getOperandSize(mode);
    return switch (size) {
        0 => 0,
        1 => self.readImpl(self.cpu.pc),
        2 => self.readImplWide(self.cpu.pc),
        else => unreachable,
    };
}

const FullDecoded = struct {
    op: instr.Op,
    operand: instr.Operand,
    addr: ?u16,
};

/// Returns an internal representation of the data the instruction operates on
fn fetchDecode(self: *Self) FullDecoded {
    const start_pc = self.cpu.pc;
    const opcode = self.fetchPc();
    const decoded = instr.decode(opcode);
    const op = decoded[0];
    const m = decoded[1];
    const arg = self.prefetchArg(m);
    const operand = instr.Operand.fromArg(m, arg);
    const addr = self.fetchTargetAddr(op, operand);

    // _ = start_pc;
    std.debug.print("{x:05}: {s}{s}{}", .{
        start_pc,
        @tagName(op),
        if (operand.size() == 0) "" else " ",
        operand,
    });
    switch (m) {
        .rel => {
            std.debug.print(" = ${x:04}", .{self.cpu.pc +% arg});
        },
        .page0, .abs => {
            std.debug.print(" = ${x:02}", .{self.readImpl(addr.?)});
        },
        .ind => {
            std.debug.print(" = ${x:04}", .{self.readImplWide(addr.?)});
        },
        .page0_x,
        .page0_y,
        .abs_x,
        .abs_y,
        .idx_ind,
        .ind_idx,
        => {
            std.debug.print(" @ ${x:04} = ${x:02}", .{
                addr.?,
                self.readImpl(addr.?),
            });
        },
        else => {},
    }
    std.debug.print("\n", .{});
    return .{
        .op = op,
        .operand = operand,
        .addr = addr,
    };
}

fn writeBusOldNew(self: *Self, addr: u16, old: u8, new: u8) void {
    self.writeBus(addr, old);
    self.writeBus(addr, new);
}

fn exec(self: *Self, d: FullDecoded) void {
    const c = &self.cpu;
    switch (d.op) {
        inline .adc, .sbc => |op| {
            // add/subtract with carry
            const val_orig = self.readBus(d.addr.?);
            const val = if (op == .adc) val_orig else ~val_orig;
            const old = c.a;
            const result = @as(u32, c.a) + val + c.p.c;
            c.a = @intCast(result & 0xff);
            c.p.c = @intCast(result >> 8);
            c.p.v = @intFromBool((c.a ^ old) & ~(old ^ val) & 0x80 != 0);
            c.p.updateZn(c.a);
        },

        inline .@"and", .ora, .eor, .lda => |op| {
            // simple A, M, Z, N operations
            const val = self.readBus(d.addr.?);
            _ = switch (op) {
                .@"and" => c.a &= val,
                .ora => c.a |= val,
                .eor => c.a ^= val,
                .lda => c.a = val,
                else => unreachable,
            };
            c.p.updateZn(c.a);
        },

        inline .asl, .lsr, .rol, .ror => |op| {
            // shift/rotate left/right
            const acc = d.addr == null;
            const val = if (acc) c.a else self.readBus(d.addr.?);
            const res = switch (op) {
                .asl => val << 1,
                .lsr => val >> 1,
                .rol => val << 1 | c.p.c,
                .ror => val >> 1 | @as(u8, c.p.c) << 7,
                else => unreachable,
            };
            c.p.c = @intCast(switch (op) {
                .asl => val >> 7,
                .lsr => val & 1,
                .rol => val >> 7,
                .ror => val & 1,
                else => unreachable,
            });
            // TODO: figure out if
            // https://www.nesdev.org/obelisk-6502-guide/reference.html#ASL
            // is incorrect (zero if A = 0)
            c.p.updateZn(res);
            if (acc) {
                c.a = res;
            } else {
                self.writeBusOldNew(d.addr.?, val, res);
            }
        },

        .bcc => {
            // branch not carry
            if (c.p.c == 0) c.pc = d.addr.?;
        },
        .bcs => {
            // branch if carry
            if (c.p.c == 1) c.pc = d.addr.?;
        },
        .beq => {
            // branch if equal
            if (c.p.z == 1) c.pc = d.addr.?;
        },
        .bmi => {
            // branch if negative
            if (c.p.n == 1) c.pc = d.addr.?;
        },
        .bne => {
            // branch not equal
            if (c.p.z == 0) c.pc = d.addr.?;
        },
        .bpl => {
            // branch not negative
            if (c.p.n == 0) c.pc = d.addr.?;
        },
        .bvc => {
            // branch if not overflow
            if (c.p.v == 0) c.pc = d.addr.?;
        },
        .bvs => {
            // branch if overflow
            if (c.p.v == 1) c.pc = d.addr.?;
        },

        .bit => {
            // bit test
            const val = self.readBus(d.addr.?);
            const res = val & c.a;
            c.p.z = @intFromBool(res == 0);
            c.p.v = @intCast(val >> 6 & 1);
            c.p.n = @intCast(val >> 7 & 1);
        },

        .brk => {
            // TODO: figure out if there is more beahvior to implement for
            // interrupts
            self.pushStackWide(c.pc);
            c.p.i = 1;
            c.p.b = 1;
            self.pushStack(c.p.value());
            c.p.b = 0;
            c.pc = self.readBusWide(0xfffe);
        },

        .clc => {
            // clear carry
            c.p.c = 0;
        },
        .cld => {
            // clear decimal
            c.p.d = 0;
        },
        .cli => {
            // clear interrupt disable
            c.p.i = 0;
        },
        .clv => {
            // clear overflow
            c.p.v = 0;
        },
        .sec => {
            // set carry
            c.p.c = 1;
        },
        .sed => {
            // set decimal
            c.p.d = 1;
        },
        .sei => {
            // set interrupt disable
            c.p.i = 1;
        },

        inline .cmp, .cpx, .cpy => |op| {
            // compare
            const cmp = switch (op) {
                .cmp => c.a,
                .cpx => c.x,
                .cpy => c.y,
                else => unreachable,
            };
            const val = self.readBus(d.addr.?);
            c.p.c = @intFromBool(cmp >= val);
            c.p.updateZn(cmp -% val);
        },

        inline .inc, .dec => |op| {
            // increment/decrement memory
            const val = self.readBus(d.addr.?);
            const res = if (op == .dec) val -% 1 else val +% 1;
            c.p.updateZn(res);
            self.writeBusOldNew(d.addr.?, val, res);
        },

        .dex => {
            // decrement X
            c.x -%= 1;
            c.p.updateZn(c.x);
        },
        .dey => {
            // decrement Y
            c.y -%= 1;
            c.p.updateZn(c.y);
        },
        .inx => {
            // increment X
            c.x +%= 1;
            c.p.updateZn(c.x);
        },
        .iny => {
            // increment Y
            c.y +%= 1;
            c.p.updateZn(c.y);
        },
        .jmp => {
            // jump
            c.pc = d.addr.?;
        },
        .jsr => {
            // jump to subroutine
            self.pushStackWide(c.pc -% 1);
            c.pc = d.addr.?;
        },
        .ldx => {
            // load X
            const val = self.readBus(d.addr.?);
            c.x = val;
            c.p.updateZn(c.x);
        },
        .ldy => {
            // load Y
            const val = self.readBus(d.addr.?);
            c.y = val;
            c.p.updateZn(c.y);
        },
        .nop => {
            // no operation
        },
        .pha => {
            // push A
            self.pushStack(c.a);
        },
        .php => {
            // push P
            self.pushStack(c.p.pushValue(1));
        },
        .pla => {
            // pop A
            c.a = self.popStack();
            c.p.updateZn(c.a);
        },
        .plp => {
            // pop P
            c.p = @bitCast(self.popStack());
            c.p.one = 1;
            c.p.b = 0;
        },
        .rti => {
            // return from interrupt
            c.p = @bitCast(self.popStack());
            c.p.b = 0;
            c.p.one = 1;
            c.pc = self.popStackWide();
        },
        .rts => {
            // return from subroutine
            c.pc = self.popStackWide() +% 1;
        },

        inline .sta, .stx, .sty => |op| {
            // store register
            self.writeBus(d.addr.?, switch (op) {
                .sta => c.a,
                .stx => c.x,
                .sty => c.y,
                else => unreachable,
            });
        },

        .tax => {
            c.x = c.a;
            c.p.updateZn(c.x);
        },
        .tay => {
            c.y = c.a;
            c.p.updateZn(c.y);
        },
        .tsx => {
            c.x = c.s;
            c.p.updateZn(c.x);
        },
        .txa => {
            c.a = c.x;
            c.p.updateZn(c.a);
        },
        .tya => {
            c.a = c.y;
            c.p.updateZn(c.a);
        },
        .txs => {
            c.s = c.x;
            // doesn't update flags
        },

        // illegal instructions
        .lax => {
            var data = d;
            data.op = .lda;
            self.exec(data);
            data.op = .ldx;
            self.exec(data);
        },
        .sax => {
            self.writeBus(d.addr.?, c.a & c.x);
        },
        .dcp => {
            var data = d;
            data.op = .dec;
            self.exec(data);
            data.op = .cmp;
            self.exec(data);
        },
        .isc => {
            var data = d;
            data.op = .inc;
            self.exec(data);
            data.op = .sbc;
            self.exec(data);
        },
        .slo => {
            var data = d;
            data.op = .asl;
            self.exec(data);
            data.op = .ora;
            self.exec(data);
        },
        .rla => {
            var data = d;
            data.op = .rol;
            self.exec(data);
            data.op = .@"and";
            self.exec(data);
        },
        .sre => {
            var data = d;
            data.op = .lsr;
            self.exec(data);
            data.op = .eor;
            self.exec(data);
        },
        .rra => {
            var data = d;
            data.op = .ror;
            self.exec(data);
            data.op = .adc;
            self.exec(data);
        },
        .sbn => {
            var data = d;
            data.op = .sbc;
            self.exec(data);
            data.op = .nop;
            data.operand = .implicit;
            self.exec(data);
        },
        // TODO: more illegal opcodes

        else => {
            std.debug.print("exec: unimplemented\n", .{});
            @panic("unimplemented");
        },
    }
}

pub fn debugStuff(self: *Self) void {
    self.cpu.pc = 0xc000;
    // know when to quit!
    const n_instr: usize = 8991;
    var log_file = std.fs.cwd().createFile(
        "other/my.log",
        .{},
    ) catch unreachable;
    defer log_file.close();
    const w = log_file.writer().any();
    for (0..n_instr) |_| {
        w.print("{X:04} ", .{self.cpu.pc}) catch unreachable;
        self.cpu.logStateFixed(w);
        self.exec(self.fetchDecode());
    }
}
