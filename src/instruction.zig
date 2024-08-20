const std = @import("std");
const log = std.log.scoped(.@"nes-instr");

const Operand = union(enum) {
    implicit: void,

    imm: u8,
    rel: u8,

    page0: u8,
    abs: u16,
    ind: u16,

    // addr = page0(arg + x)
    page0_x: u8,
    page0_y: u8,

    // addr = arg + x
    abs_x: u16,
    abs_y: u16,

    // addr = *page0(arg + x) | *page0(arg + x + 1) << 8
    idx_ind: u8,

    // addr = (*page0(arg) | *page0(arg + 1) << 8) + y
    ind_idx: u8,
};

pub const Mode = std.meta.Tag(Operand);

pub fn getOperandSize(m: Mode) usize {
    const fields = @typeInfo(Mode).Type.Enum.fields;
    inline for (fields) |field| {
        if (field.value == @intFromEnum(m)) {
            return @sizeOf(@field(Operand, field.name));
        }
    }
    unreachable;
}

pub const Op = enum {
    adc,
    ahx,
    aldy,
    alr,
    anc,
    // I will not settle for less
    @"and",
    arr,
    asl,
    axs,
    bcc,
    bcs,
    beq,
    bit,
    bmi,
    bne,
    bpl,
    brk,
    bvc,
    bvs,
    ccpy,
    clc,
    cld,
    cli,
    clv,
    cmp,
    cpx,
    cpy,
    dcp,
    dec,
    dex,
    dey,
    ecpx,
    eor,
    inc,
    inx,
    iny,
    isc,
    jmp,
    jsr,
    las,
    lax,
    lda,
    ldx,
    ldy,
    lsr,
    nop,
    ora,
    pha,
    php,
    pla,
    plp,
    rla,
    rol,
    ror,
    rra,
    rti,
    rts,
    sax,
    sbc,
    sec,
    sed,
    sei,
    shx,
    shy,
    slo,
    sre,
    sta,
    stp,
    stx,
    sty,
    tas,
    tax,
    tay,
    tsx,
    txa,
    txs,
    tya,
    xaa,
};

const Decoded = struct { Op, Mode };

const op_table = [256]Decoded{
    .{ .brk, .implicit },
    .{ .ora, .idx_ind },
    .{ .stp, .implicit },
    .{ .slo, .idx_ind },
    .{ .nop, .page0 },
    .{ .ora, .page0 },
    .{ .asl, .page0 },
    .{ .slo, .page0 },
    .{ .php, .implicit },
    .{ .ora, .imm },
    .{ .asl, .implicit },
    .{ .anc, .imm },
    .{ .nop, .abs },
    .{ .ora, .abs },
    .{ .asl, .abs },
    .{ .slo, .abs },
    .{ .bpl, .rel },
    .{ .ora, .ind_idx },
    .{ .stp, .implicit },
    .{ .slo, .ind_idx },
    .{ .nop, .page0_x },
    .{ .ora, .page0_x },
    .{ .asl, .page0_x },
    .{ .slo, .page0_x },
    .{ .clc, .implicit },
    .{ .ora, .abs_y },
    .{ .nop, .implicit },
    .{ .slo, .abs_y },
    .{ .nop, .abs_x },
    .{ .ora, .abs_x },
    .{ .asl, .abs_x },
    .{ .slo, .abs_x },
    .{ .jsr, .abs },
    .{ .@"and", .idx_ind },
    .{ .stp, .implicit },
    .{ .rla, .idx_ind },
    .{ .bit, .page0 },
    .{ .@"and", .page0 },
    .{ .rol, .page0 },
    .{ .rla, .page0 },
    .{ .plp, .implicit },
    .{ .@"and", .imm },
    .{ .rol, .implicit },
    .{ .anc, .imm },
    .{ .bit, .abs },
    .{ .@"and", .abs },
    .{ .rol, .abs },
    .{ .rla, .abs },
    .{ .bmi, .rel },
    .{ .@"and", .ind_idx },
    .{ .stp, .implicit },
    .{ .rla, .ind_idx },
    .{ .nop, .page0_x },
    .{ .@"and", .page0_x },
    .{ .rol, .page0_x },
    .{ .rla, .page0_x },
    .{ .sec, .implicit },
    .{ .@"and", .abs_y },
    .{ .nop, .implicit },
    .{ .rla, .abs_y },
    .{ .nop, .abs_x },
    .{ .@"and", .abs_x },
    .{ .rol, .abs_x },
    .{ .rla, .abs_x },
    .{ .rti, .implicit },
    .{ .eor, .idx_ind },
    .{ .stp, .implicit },
    .{ .sre, .idx_ind },
    .{ .nop, .page0 },
    .{ .eor, .page0 },
    .{ .lsr, .page0 },
    .{ .sre, .page0 },
    .{ .pha, .implicit },
    .{ .eor, .imm },
    .{ .lsr, .implicit },
    .{ .alr, .imm },
    .{ .jmp, .abs },
    .{ .eor, .abs },
    .{ .lsr, .abs },
    .{ .sre, .abs },
    .{ .bvc, .rel },
    .{ .eor, .ind_idx },
    .{ .stp, .implicit },
    .{ .sre, .ind_idx },
    .{ .nop, .page0_x },
    .{ .eor, .page0_x },
    .{ .lsr, .page0_x },
    .{ .sre, .page0_x },
    .{ .cli, .implicit },
    .{ .eor, .abs_y },
    .{ .nop, .implicit },
    .{ .sre, .abs_y },
    .{ .nop, .abs_x },
    .{ .eor, .abs_x },
    .{ .lsr, .abs_x },
    .{ .sre, .abs_x },
    .{ .rts, .implicit },
    .{ .adc, .idx_ind },
    .{ .stp, .implicit },
    .{ .rra, .idx_ind },
    .{ .nop, .page0 },
    .{ .adc, .page0 },
    .{ .ror, .page0 },
    .{ .rra, .page0 },
    .{ .pla, .implicit },
    .{ .adc, .imm },
    .{ .ror, .implicit },
    .{ .arr, .imm },
    .{ .jmp, .ind },
    .{ .adc, .abs },
    .{ .ror, .abs },
    .{ .rra, .abs },
    .{ .bvs, .rel },
    .{ .adc, .ind_idx },
    .{ .stp, .implicit },
    .{ .rra, .ind_idx },
    .{ .nop, .page0_x },
    .{ .adc, .page0_x },
    .{ .ror, .page0_x },
    .{ .rra, .page0_x },
    .{ .sei, .implicit },
    .{ .adc, .abs_y },
    .{ .nop, .implicit },
    .{ .rra, .abs_y },
    .{ .nop, .abs_x },
    .{ .adc, .abs_x },
    .{ .ror, .abs_x },
    .{ .rra, .abs_x },
    .{ .nop, .imm },
    .{ .sta, .idx_ind },
    .{ .nop, .imm },
    .{ .sax, .idx_ind },
    .{ .sty, .page0 },
    .{ .sta, .page0 },
    .{ .stx, .page0 },
    .{ .sax, .page0 },
    .{ .dey, .implicit },
    .{ .nop, .imm },
    .{ .txa, .implicit },
    .{ .xaa, .imm },
    .{ .sty, .abs },
    .{ .sta, .abs },
    .{ .stx, .abs },
    .{ .sax, .abs },
    .{ .bcc, .rel },
    .{ .sta, .ind_idx },
    .{ .stp, .implicit },
    .{ .ahx, .ind_idx },
    .{ .sty, .page0_x },
    .{ .sta, .page0_x },
    .{ .stx, .page0_y },
    .{ .sax, .page0_y },
    .{ .tya, .implicit },
    .{ .sta, .abs_y },
    .{ .txs, .implicit },
    .{ .tas, .abs_y },
    .{ .shy, .abs_x },
    .{ .sta, .abs_x },
    .{ .shx, .abs_y },
    .{ .ahx, .abs_y },
    .{ .ldy, .imm },
    .{ .lda, .idx_ind },
    .{ .ldx, .imm },
    .{ .lax, .idx_ind },
    .{ .ldy, .page0 },
    .{ .lda, .page0 },
    .{ .ldx, .page0 },
    .{ .lax, .page0 },
    .{ .tay, .implicit },
    .{ .lda, .imm },
    .{ .tax, .implicit },
    .{ .lax, .imm },
    .{ .ldy, .abs },
    .{ .lda, .abs },
    .{ .ldx, .abs },
    .{ .lax, .abs },
    .{ .bcs, .rel },
    .{ .lda, .ind_idx },
    .{ .stp, .implicit },
    .{ .lax, .ind_idx },
    .{ .ldy, .page0_x },
    .{ .lda, .page0_x },
    .{ .ldx, .page0_y },
    .{ .lax, .page0_y },
    .{ .clv, .implicit },
    .{ .lda, .abs_y },
    .{ .tsx, .implicit },
    .{ .las, .abs_y },
    .{ .ldy, .abs_x },
    .{ .lda, .abs_x },
    .{ .ldx, .abs_y },
    .{ .lax, .abs_y },
    .{ .cpy, .imm },
    .{ .cmp, .idx_ind },
    .{ .nop, .imm },
    .{ .dcp, .idx_ind },
    .{ .cpy, .page0 },
    .{ .cmp, .page0 },
    .{ .dec, .page0 },
    .{ .dcp, .page0 },
    .{ .iny, .implicit },
    .{ .cmp, .imm },
    .{ .dex, .implicit },
    .{ .axs, .imm },
    .{ .cpy, .abs },
    .{ .cmp, .abs },
    .{ .dec, .abs },
    .{ .dcp, .abs },
    .{ .bne, .rel },
    .{ .cmp, .ind_idx },
    .{ .stp, .implicit },
    .{ .dcp, .ind_idx },
    .{ .nop, .page0_x },
    .{ .cmp, .page0_x },
    .{ .dec, .page0_x },
    .{ .dcp, .page0_x },
    .{ .cld, .implicit },
    .{ .cmp, .abs_y },
    .{ .nop, .implicit },
    .{ .dcp, .abs_y },
    .{ .nop, .abs_x },
    .{ .cmp, .abs_x },
    .{ .dec, .abs_x },
    .{ .dcp, .abs_x },
    .{ .cpx, .imm },
    .{ .sbc, .idx_ind },
    .{ .nop, .imm },
    .{ .isc, .idx_ind },
    .{ .cpx, .page0 },
    .{ .sbc, .page0 },
    .{ .inc, .page0 },
    .{ .isc, .page0 },
    .{ .inx, .implicit },
    .{ .sbc, .imm },
    .{ .nop, .implicit },
    .{ .sbc, .imm },
    .{ .cpx, .abs },
    .{ .sbc, .abs },
    .{ .inc, .abs },
    .{ .isc, .abs },
    .{ .beq, .rel },
    .{ .sbc, .ind_idx },
    .{ .stp, .implicit },
    .{ .isc, .ind_idx },
    .{ .nop, .page0_x },
    .{ .sbc, .page0_x },
    .{ .inc, .page0_x },
    .{ .isc, .page0_x },
    .{ .sed, .implicit },
    .{ .sbc, .abs_y },
    .{ .nop, .implicit },
    .{ .isc, .abs_y },
    .{ .nop, .abs_x },
    .{ .sbc, .abs_x },
    .{ .inc, .abs_x },
    .{ .isc, .abs_x },
};

comptime {
    // ensure sanity
    const correct_pairs = [_]struct { u8, Decoded }{
        .{ 0, .{ .brk, .implicit } },
        .{ 0x20, .{ .jsr, .abs } },
        .{ 0x80 + 0x11, .{ .sta, .ind_idx } },
    };
    for (correct_pairs) |pair| {
        std.testing.expectEqual(pair[1], op_table[pair[0]]) catch {};
    }
}

pub fn decode(opcode: u8) Decoded {
    return op_table[opcode];
}
