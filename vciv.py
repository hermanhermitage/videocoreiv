import sys
import idaapi
from idaapi import *

class vciv_processor_t(idaapi.processor_t):
  id = 0x8004
  flag = PR_NO_SEGMOVE | PR_USE32 | PR_CNDINSNS
  plnames = [ 'Broadcom Videocore' ]
  psnames = [ 'vciv' ]
  cnbits = 8
  dnbits = 8
  instruc_start = 0
  segreg_size = 0
  tbyte_size = 0
  assembler = {
    'flag': 0,
    'name': "Custom VCIV assembler",
    'origin': ".origin",
    'end': ".end",
    'cmnt': ";",
    'ascsep': "\"",
    'accsep': "'",
    'esccodes': "\"'",
    'a_ascii': ".ascii",
    'a_byte': ".byte",
    'a_word': ".short",
    'a_dword': ".int",
    'a_qword': ".quad",
    'a_oword': ".dquad",
    'a_float': ".float",
    'a_double': ".double",
    'a_bss': ".bss",
    'a_seg': ".seg",
    'a_curip': "__pc__",
    'a_public': ".public",
    'a_weak': ".weak",
    'a_extrn': ".extrn",
    'a_comdef': ".comdef",
    'a_align': ".align",
    'lbrace': "(",
    'rbrace': ")",
    'a_mod': "%",
    'a_band': "&",
    'a_bor': "|",
    'a_xor': "^",
    'a_bnot': "~",
    'a_shl': "<<",
    'a_shr': ">>",
    'a_sizeof_fmt': "size %s"
  }
  return_codes = [ '\x5a\x00' ]

  o_temp0 = 32
  o_temp1 = 33
  o_temp2 = 34
  o_temp3 = 35
  o_temp4 = 36
  o_temp5 = 37
  o_temp6 = 38
  o_temp7 = 39
  o_temp8 = 40
  o_temp9 = 41
  o_temp10 = 42
  o_temp11 = 43
  o_temp12 = 44
  ISA16 = [
    ["halt", [0x0000], [0xffff], CF_STOP, []],
    ["nop", [0x0001], [0xffff], 0, []],
    ["wait", [0x0002], [0xffff], 0, []],
    ["user", [0x0003], [0xffff], 0, []],
    ["sti", [0x0004], [0xffff], 0, []],
    ["cli", [0x0005], [0xffff], 0, []],
    ["clr", [0x0006], [0xffff], 0, []],
    ["inc", [0x0007], [0xffff], 0, []],
    ["chg", [0x0008], [0xffff], 0, []],
    ["dec", [0x0009], [0xffff], 0, []],
    ["rti", [0x000a], [0xffff], 0, []],
    ["swi", [0x0020], [0xffe0], CF_USE1, [[0,5,o_reg]]],
    # ["rts", [0x005a], [0xffff], CF_JUMP | CF_STOP, []],
    ["b", [0x0040], [0xffe0], CF_JUMP | CF_USE1 | CF_STOP, [[0,5,o_reg]]],
    ["bl", [0x0060], [0xffe0], CF_CALL | CF_USE1, [[0,5,o_reg]]],
    ["tbb", [0x0080], [0xffe0], CF_JUMP | CF_STOP | CF_USE1, [[0,5,o_reg]]],
    ["tbh", [0x00a0], [0xffe0], CF_JUMP | CF_STOP | CF_USE1, [[0,5,o_reg]]],
    ["cpuid", [0x00e0], [0xffe0], CF_CHG1, [[0,5,o_reg]]],
    ["swi", [0x01c0], [0xffc0], CF_USE1, [[0,6,o_imm]]],
    ["pop", [0x0200], [0xff80], CF_USE1, [[0,7,o_idpspec0]]],
    ["push", [0x0280], [0xff80], CF_USE1, [[0,7,o_idpspec0]]],
    ["pop", [0x0300], [0xff80], CF_USE1 | CF_JUMP | CF_STOP, [[0,7,o_idpspec0]]],
    ["push", [0x0380], [0xff80], CF_USE1, [[0,7,o_idpspec0]]],
    ["ld", [0x0400], [0xfe00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_temp0]]],
    ["st", [0x0600], [0xfe00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_temp0]]],
    ["ld", [0x0800], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_phrase]]],
    ["st", [0x0900], [0xff00], CF_USE1 | CF_CHG2, [[0,4,o_reg],[4,4,o_phrase]]],
    ["ldh", [0x0a00], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_phrase]]],
    ["sth", [0x0b00], [0xff00], CF_USE1 | CF_CHG2, [[0,4,o_reg],[4,4,o_phrase]]],
    ["ldb", [0x0c00], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_phrase]]],
    ["stb", [0x0d00], [0xff00], CF_USE1 | CF_CHG2, [[0,4,o_reg],[4,4,o_phrase]]],
    ["lds", [0x0e00], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_phrase]]],
    ["sts", [0x0f00], [0xff00], CF_USE1 | CF_CHG2, [[0,4,o_reg],[4,4,o_phrase]]],
    ["lea", [0x1000], [0xf800], CF_CHG1 | CF_USE2, [[0,5,o_reg],[5,6,o_temp0]]],
    ["ld", [0x2000], [0xf000], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,8,o_temp8]]],
    ["st", [0x3000], [0xf000], CF_USE1 | CF_CHG2, [[0,4,o_reg],[4,8,o_temp8]]],
    # ld/st 0x2000
    ["mov", [0x4000], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["cmn", [0x4100], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["add", [0x4200], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["bic", [0x4300], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["mul", [0x4400], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["eor", [0x4500], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["sub", [0x4600], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["and", [0x4700], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["mvn", [0x4800], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["ror", [0x4900], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["cmp", [0x4a00], [0xff00], CF_USE1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["rsb", [0x4b00], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["btst", [0x4c00], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["or", [0x4d00], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["extu", [0x4e00], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["max", [0x4f00], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["bset", [0x5000], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["min", [0x5100], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["bclr", [0x5200], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["adds2", [0x5300], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["bchg", [0x5400], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["adds4", [0x5500], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["adds8", [0x5600], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["adds16", [0x5700], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["exts", [0x5800], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["neg", [0x5900], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["lsr", [0x5a00], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["clz", [0x5b00], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["lsl", [0x5c00], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["brev", [0x5d00], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["asr", [0x5e00], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["abs", [0x5f00], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["mov", [0x6000], [0xfe00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,5,o_imm]]],
    ["add", [0x6200], [0xfe00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,5,o_imm]]],
    ["mul", [0x6400], [0xfe00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,5,o_imm]]],
    ["sub", [0x6600], [0xfe00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,5,o_imm]]],
    ["mvn", [0x6800], [0xfe00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,5,o_imm]]],
    ["cmp", [0x6a00], [0xfe00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,5,o_imm]]],
    ["btst", [0x6c00], [0xfe00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,5,o_imm]]],
    ["extu", [0x6e00], [0xfe00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,5,o_imm]]],
    ["bset", [0x7000], [0xfe00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,5,o_imm]]],
    ["bclr", [0x7200], [0xfe00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,5,o_imm]]],
    ["bchg", [0x7400], [0xfe00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,5,o_imm]]],
    ["adds8", [0x7600], [0xfe00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,5,o_imm]]],
    ["exts", [0x7800], [0xfe00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,5,o_imm]]],
    ["lsr", [0x7a00], [0xfe00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,5,o_imm]]],
    ["lsl", [0x7c00], [0xfe00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,5,o_imm]]],
    ["asr", [0x7e00], [0xfe00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,5,o_imm]]],
  ]
  ISA32 = [
    ["bl", [0x9080, 0x0000], [0xffff, 0x0000], CF_CALL | CF_USE1, [[16,16,o_near]]],
    ["bl", [0x9fff, 0x0000], [0xffff, 0x0000], CF_CALL | CF_USE1, [[16,16,o_near]]], # pos/neg case - offset is probably wider
    #
    ["ld", [0xa200, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp1]]], # 11:5 displ
    ["st", [0xa220, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp1]]], # 11:5 displ
    ["ldh", [0xa240, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp1]]], # 11:5 displ
    ["sth", [0xa260, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp1]]], # 11:5 displ
    ["ldb", [0xa280, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp1]]], # 11:5 displ
    ["stb", [0xa2a0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp1]]], # 11:5 displ
    ["lds", [0xa2c0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp1]]], # 11:5 displ
    ["sts", [0xa2e0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp1]]], # 11:5 displ
    #
    ["ld", [0xa800, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp2]]], # 16:(r24) displ
    ["st", [0xa820, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp2]]], # 16:(r24) displ
    ["ldh", [0xa840, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp2]]], # 16:(r24) displ
    ["sth", [0xa860, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp2]]], # 16:(r24) displ
    ["ldb", [0xa880, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp2]]], # 16:(r24) displ
    ["stb", [0xa8a0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp2]]], # 16:(r24) displ
    ["lds", [0xa8c0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp2]]], # 16:(r24) displ
    ["sts", [0xa8e0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp2]]], # 16:(r24) displ
    ["ld", [0xa900, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp3]]], # 16:(sp) displ
    ["st", [0xa920, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp3]]], # 16:(sp) displ
    ["ldh", [0xa940, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp3]]], # 16:(sp) displ
    ["sth", [0xa960, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp3]]], # 16:(sp) displ
    ["ldb", [0xa980, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp3]]], # 16:(sp) displ
    ["stb", [0xa9a0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp3]]], # 16:(sp) displ
    ["lds", [0xa9c0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp3]]], # 16:(sp) displ
    ["sts", [0xa9e0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp3]]], # 16:(sp) displ
    ["ld", [0xaa00, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp4]]], # 16:(pc) displ
    ["st", [0xaa20, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp4]]], # 16:(pc) displ
    ["ldh", [0xaa40, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp4]]], # 16:(pc) displ
    ["sth", [0xaa60, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp4]]], # 16:(pc) displ
    ["ldb", [0xaa80, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp4]]], # 16:(pc) displ
    ["stb", [0xaaa0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp4]]], # 16:(pc) displ
    ["lds", [0xaac0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp4]]], # 16:(pc) displ
    ["sts", [0xaae0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp4]]], # 16:(pc) displ
    ["ld", [0xab00, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp5]]], # 16:(r0) displ
    ["st", [0xab20, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp5]]], # 16:(r0) displ
    ["ldh", [0xab40, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp5]]], # 16:(r0) displ
    ["sth", [0xab60, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp5]]], # 16:(r0) displ
    ["ldb", [0xab80, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp5]]], # 16:(r0) displ
    ["stb", [0xaba0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp5]]], # 16:(r0) displ
    ["lds", [0xabc0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp5]]], # 16:(r0) displ
    ["sts", [0xabe0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp5]]], # 16:(r0) displ
    #
    ["mov", [0xb000, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm]]],
    ["cmn", [0xb020, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm]]],
    ["add", [0xb040, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm]]],
    ["bic", [0xb060, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm]]],
    ["mul", [0xb080, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm]]],
    ["eor", [0xb0a0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm]]],
    ["sub", [0xb0c0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm]]],
    ["and", [0xb0e0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm]]],
    ["mvn", [0xb100, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm]]],
    ["ror", [0xb120, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm]]],
    ["cmp", [0xb140, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm]]],
    ["rsb", [0xb160, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm]]],
    ["btst", [0xb180, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm]]],
    ["or", [0xb1a0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm]]],
    ["extu", [0xb1c0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm]]],
    ["max", [0xb1e0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm]]],
    ["bset", [0xb200, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm]]],
    ["min", [0xb220, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm]]],
    ["bclr", [0xb240, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm]]],
    ["adds2", [0xb260, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm]]],
    ["bchg", [0xb280, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm]]],
    ["adds4", [0xb2a0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm]]],
    ["adds8", [0xb2c0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm]]],
    ["adds16", [0xb2e0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm]]],
    ["exts", [0xb300, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm]]],
    ["neg", [0xb320, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm]]],
    ["lsr", [0xb340, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm]]],
    ["clz", [0xb360, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm]]],
    ["lsl", [0xb380, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm]]],
    ["brev", [0xb3a0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm]]],
    ["asr", [0xb3c0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm]]],
    ["abs", [0xb3e0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm]]],
    ["lea", [0xb400, 0x0000], [0xfc00, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[0,32,o_temp6]]], # 5.5:16.16 displ
    ["lea", [0xbfe0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[0,32,o_temp6]]], # 5.5:16.16 displ (reg == pc, fixed by pattern)
    #
  ]
  ISA48 = [
    ["lea", [0xe500, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_mem]]],
    ["ld", [0xe600, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_temp9]]], # (16.11||32.16):27.5 displ
    ["st", [0xe620, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_USE1 | CF_CHG2, [[0,5,o_reg],[16,32,o_temp9]]], # (16.11||32.16):27.5 displ
    ["ldh", [0xe640, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_temp9]]], # (16.11||32.16):27.5 displ
    ["sth", [0xe660, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_USE1 | CF_CHG2, [[0,5,o_reg],[16,32,o_temp9]]], # (16.11||32.16):27.5 displ
    ["ldb", [0xe680, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_temp9]]], # (16.11||32.16):27.5 displ
    ["stb", [0xe6a0, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_USE1 | CF_CHG2, [[0,5,o_reg],[16,32,o_temp9]]], # (16.11||32.16):27.5 displ
    ["lds", [0xe6c0, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_temp9]]], # (16.11||32.16):27.5 displ
    ["sts", [0xe6e0, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_USE1 | CF_CHG2, [[0,5,o_reg],[16,32,o_temp9]]], # (16.11||32.16):27.5 displ
    #
    ["mov", [0xe800, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["cmn", [0xe820, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["add", [0xe840, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["bic", [0xe860, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["mul", [0xe880, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["eor", [0xe8a0, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["sub", [0xe8c0, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["and", [0xe8e0, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["mvn", [0xe900, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["ror", [0xe920, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["cmp", [0xe940, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_USE1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["rsb", [0xe960, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_USE1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["btst", [0xe980, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_USE1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["or", [0xe9a0, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["extu", [0xe9c0, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["max", [0xe9e0, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["bset", [0xea00, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["min", [0xea20, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["bclr", [0xea40, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["adds2", [0xea60, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["bchg", [0xea80, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["adds4", [0xeaa0, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["adds8", [0xeac0, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["adds16", [0xeae0, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["exts", [0xeb00, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["neg", [0xeb20, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["lsr", [0xeb40, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_USE1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["clz", [0xeb60, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_USE1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["lsl", [0xeb80, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_USE1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["brev", [0xeba0, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["asr", [0xebc0, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["abs", [0xebe0, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    #
    ["add", [0xec00, 0x0000, 0x0000], [0xfc00, 0x0000, 0x0000], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[5,5,o_reg],[16,32,o_imm]]],
  ]
  ISA80 = [
  ]
  ISACC = [
    [7,
     ["bCC", [0x1800], [0xff80], CF_JUMP | CF_USE1, [[0,7,o_near]]]
    ],
    [8,
     ["addcmpbCC", [0x8000, 0x0000], [0xff00, 0xc000], CF_JUMP | CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4, [[0,4,o_reg],[4,4,o_reg],[26,4,o_reg],[16,10,o_near]]],
     ["addcmpbCC", [0x8000, 0x4000], [0xff00, 0xc000], CF_JUMP | CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4, [[0,4,o_reg],[4,4,o_imm],[26,4,o_reg],[16,10,o_near]]],
     ["addcmpbCC", [0x8000, 0x8000], [0xff00, 0xc000], CF_JUMP | CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4, [[0,4,o_reg],[4,4,o_reg],[24,6,o_imm],[16,8,o_near]]],
     ["addcmpbCC", [0x8000, 0xc000], [0xff00, 0xc000], CF_JUMP | CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4, [[0,4,o_reg],[4,4,o_imm],[24,6,o_imm],[16,8,o_near]]],
    ],
    [8,
     ["bCC", [0x9000, 0x0000], [0xffff, 0x0000], CF_JUMP | CF_USE1, [[16,16,o_near]]]
    ],
    [23,
     ["ldCC", [0xa000, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp7]]], # 16.5:27.5 dual-reg phrase
     ["stCC", [0xa020, 0x0000], [0xffe0, 0x07e0], CF_USE1 | CF_CHG2, [[0,5,o_reg],[16,16,o_temp7]]], # 16.5:27.5 dual-reg phrase
     ["ldhCC", [0xa040, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp7]]], # 16.5:27.5 dual-reg phrase
     ["sthCC", [0xa060, 0x0000], [0xffe0, 0x07e0], CF_USE1 | CF_CHG2, [[0,5,o_reg],[16,16,o_temp7]]], # 16.5:27.5 dual-reg phrase
     ["ldbCC", [0xa080, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp7]]], # 16.5:27.5 dual-reg phrase
     ["stbCC", [0xa0a0, 0x0000], [0xffe0, 0x07e0], CF_USE1 | CF_CHG2, [[0,5,o_reg],[16,16,o_temp7]]], # 16.5:27.5 dual-reg phrase
     ["ldsCC", [0xa0c0, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_temp7]]], # 16.5:27.5 dual-reg phrase
     ["stsCC", [0xa0e0, 0x0000], [0xffe0, 0x07e0], CF_USE1 | CF_CHG2, [[0,5,o_reg],[16,16,o_temp7]]], # 16.5:27.5 dual-reg phrase
    ],
    [23,
     ["ldCC", [0xa400, 0x0000], [0xffe0, 0x07ff], CF_CHG1 | CF_USE2, [[0,5,o_reg],[27,5,o_temp10]]],
     ["stCC", [0xa420, 0x0000], [0xffe0, 0x07ff], CF_USE1 | CF_CHG2, [[0,5,o_reg],[27,5,o_temp10]]],
     ["ldhCC", [0xa440, 0x0000], [0xffe0, 0x07ff], CF_CHG1 | CF_USE2, [[0,5,o_reg],[27,5,o_temp10]]],
     ["sthCC", [0xa460, 0x0000], [0xffe0, 0x07ff], CF_USE1 | CF_CHG2, [[0,5,o_reg],[27,5,o_temp10]]],
     ["ldbCC", [0xa480, 0x0000], [0xffe0, 0x07ff], CF_CHG1 | CF_USE2, [[0,5,o_reg],[27,5,o_temp10]]],
     ["stbCC", [0xa4a0, 0x0000], [0xffe0, 0x07ff], CF_USE1 | CF_CHG2, [[0,5,o_reg],[27,5,o_temp10]]],
     ["ldsCC", [0xa4c0, 0x0000], [0xffe0, 0x07ff], CF_CHG1 | CF_USE2, [[0,5,o_reg],[27,5,o_temp10]]],
     ["stsCC", [0xa4e0, 0x0000], [0xffe0, 0x07ff], CF_USE1 | CF_CHG2, [[0,5,o_reg],[27,5,o_temp10]]],
     ["ldCC", [0xa500, 0x0000], [0xffe0, 0x07ff], CF_CHG1 | CF_USE2, [[0,5,o_reg],[27,5,o_temp11]]],
     ["stCC", [0xa520, 0x0000], [0xffe0, 0x07ff], CF_USE1 | CF_CHG2, [[0,5,o_reg],[27,5,o_temp11]]],
     ["ldhCC", [0xa540, 0x0000], [0xffe0, 0x07ff], CF_CHG1 | CF_USE2, [[0,5,o_reg],[27,5,o_temp11]]],
     ["sthCC", [0xa560, 0x0000], [0xffe0, 0x07ff], CF_USE1 | CF_CHG2, [[0,5,o_reg],[27,5,o_temp11]]],
     ["ldbCC", [0xa580, 0x0000], [0xffe0, 0x07ff], CF_CHG1 | CF_USE2, [[0,5,o_reg],[27,5,o_temp11]]],
     ["stbCC", [0xa5a0, 0x0000], [0xffe0, 0x07ff], CF_USE1 | CF_CHG2, [[0,5,o_reg],[27,5,o_temp11]]],
     ["ldsCC", [0xa5c0, 0x0000], [0xffe0, 0x07ff], CF_CHG1 | CF_USE2, [[0,5,o_reg],[27,5,o_temp11]]],
     ["stsCC", [0xa5e0, 0x0000], [0xffe0, 0x07ff], CF_USE1 | CF_CHG2, [[0,5,o_reg],[27,5,o_temp11]]],
    ],
    [23,
     ["movCC", [0xc000, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["cmnCC", [0xc020, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["addCC", [0xc040, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["bicCC", [0xc060, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["mulCC", [0xc080, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["eorCC", [0xc0a0, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["subCC", [0xc0c0, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["andCC", [0xc0e0, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["mvnCC", [0xc100, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["rorCC", [0xc120, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["cmpCC", [0xc140, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["rsbCC", [0xc160, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["btstCC", [0xc180, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["orCC", [0xc1a0, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["extuCC", [0xc1c0, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["maxCC", [0xc1e0, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["bsetCC", [0xc200, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["minCC", [0xc220, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["bclrCC", [0xc240, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["adds2CC", [0xc260, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["bchgCC", [0xc280, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["adds4CC", [0xc2a0, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["adds8CC", [0xc2c0, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["adds16CC", [0xc2e0, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["extsCC", [0xc300, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["negCC", [0xc320, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["lsrCC", [0xc340, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["clzCC", [0xc360, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["lslCC", [0xc380, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["brevCC", [0xc3a0, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["asrCC", [0xc3c0, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["absCC", [0xc3e0, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
    ],
    [23,
     ["movCC", [0xc000, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm]]],
     ["cmnCC", [0xc020, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm]]],
     ["addCC", [0xc040, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm]]],
     ["bicCC", [0xc060, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm]]],
     ["mulCC", [0xc080, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm]]],
     ["eorCC", [0xc0a0, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm]]],
     ["subCC", [0xc0c0, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm]]],
     ["andCC", [0xc0e0, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm]]],
     ["mvnCC", [0xc100, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm]]],
     ["rorCC", [0xc120, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm]]],
     ["cmpCC", [0xc140, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm]]],
     ["rsbCC", [0xc160, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm]]],
     ["btstCC", [0xc180, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm]]],
     ["orCC", [0xc1a0, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm]]],
     ["extuCC", [0xc1c0, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm]]],
     ["maxCC", [0xc1e0, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm]]],
     ["bsetCC", [0xc200, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm]]],
     ["minCC", [0xc220, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm]]],
     ["bclrCC", [0xc240, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm]]],
     ["adds2CC", [0xc260, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm]]],
     ["bchgCC", [0xc280, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm]]],
     ["adds4CC", [0xc2a0, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm]]],
     ["adds8CC", [0xc2c0, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm]]],
     ["adds16CC", [0xc2e0, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm]]],
     ["extsCC", [0xc300, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm]]],
     ["negCC", [0xc320, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm]]],
     ["lsrCC", [0xc340, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm]]],
     ["clzCC", [0xc360, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm]]],
     ["lslCC", [0xc380, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm]]],
     ["brevCC", [0xc3a0, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm]]],
     ["asrCC", [0xc3c0, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm]]],
     ["absCC", [0xc3e0, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm]]],
    ],
    [23,
     ["mulhd(ss)CC", [0xc400, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["mulhd(ss)CC", [0xc400, 0x0040], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_imm]]],
     ["mulhd(su)CC", [0xc420, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["mulhd(su)CC", [0xc420, 0x0040], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_imm]]],
     ["mulhd(us)CC", [0xc440, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["mulhd(us)CC", [0xc440, 0x0040], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_imm]]],
     ["mulhd(uu)CC", [0xc460, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["mulhd(uu)CC", [0xc460, 0x0040], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_imm]]],
    ],
    [23,
     ["div(s)CC", [0xc480, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["div(s)CC", [0xc480, 0x0040], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_imm]]],
     ["div(su)CC", [0xc4a0, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["div(su)CC", [0xc4a0, 0x0040], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_imm]]],
     ["div(us)CC", [0xc4c0, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["div(us)CC", [0xc4c0, 0x0040], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_imm]]],
     ["div(u)CC", [0xc4e0, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["div(u)CC", [0xc4e0, 0x0040], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_imm]]],
    ],
    [23,
     ["add", [0xc5e0, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_temp12]]],
    ],
  ]
  PUSHPOP_INCL_LRPC = 512
  PREDECR = 1024
  POSTINCR = 2048
  PHRASE_DUALREG = 4096
  BARREL_SHIFT_8 = 8192

  @staticmethod
  def BITFIELD(word, start, width):
    return (word >> start) & ((1 << width) - 1)
  @staticmethod
  def XBITFIELD(wordarray, start, width):
    v = 0
    while ((start + width - 1)>>4) > (start>>4):
      lastbit = (start + width - 1)
      firstbit = (lastbit & ~0xf)
      lastbithere = (start+width-1) & 0xf
      v |= vciv_processor_t.BITFIELD(wordarray[(start+width-1)>>4], 0, (lastbit+1)&0xf) << (firstbit - start)
      width -= (lastbithere+1)
    v |= vciv_processor_t.BITFIELD(wordarray[start>>4], start & 0x0f, width)
    return v
  @staticmethod
  def SXBITFIELD(wordarray, start, width):
    v = vciv_processor_t.XBITFIELD(wordarray, start, width-1)
    sign = vciv_processor_t.XBITFIELD(wordarray, start+width-1, 1)
    if sign != 0:
      v = -(1 << (width-1)) + v
    return v

  def get_frame_retsize(self, func_ea):
    print "get_frame_retsize"
    return 0

  def notify_get_autocmt(self):
    print "notify_get_autocmt"
    return "No Comment"

  def is_align_insn(self, ea):
    print "is_align_insn"
    return 0

  def notify_newfile(self, filename):
    print "notify_newfile"
    pass

  def notify_oldfile(self, filename):
    print "notify_oldfile"
    pass

  def handle_operand(self, op, rw):
    if op.type == o_near:
      if self.cmd.get_canon_feature() & CF_JUMP:
        print "Adding XREFc %x -> %x" % (self.cmd.ea, op.addr)
        ua_add_cref(0, op.addr, fl_JN)
      if self.cmd.get_canon_feature() & CF_CALL:
        print "Adding XREFc %x -> %x" % (self.cmd.ea, op.addr)
        ua_add_cref(0, op.addr, fl_CN)

    if op.type == o_mem:
      ua_dodata2(0, op.addr, op.dtyp)
      ua_add_dref(0, op.addr, (dr_W if rw else dr_R))

    return

  def add_stkvar(self, v, n, flag):
    print "add_stkvar"
    return

  def add_stkpnt(self, phn, v):
    print "add_stkpnt"
    return

  def trace_sp(self):
    print "trace_sp"
    return

  def emu(self):
    # print "emu"
    flags = self.cmd.get_canon_feature()

    if flags & CF_USE1:
      self.handle_operand(self.cmd.Op1, 0)
    if flags & CF_CHG1:
      self.handle_operand(self.cmd.Op1, 1)
    if flags & CF_USE2:
      self.handle_operand(self.cmd.Op2, 0)
    if flags & CF_CHG2:
      self.handle_operand(self.cmd.Op2, 1)
    if flags & CF_USE3:
      self.handle_operand(self.cmd.Op3, 0)
    if flags & CF_CHG3:
      self.handle_operand(self.cmd.Op3, 1)
    if flags & CF_USE4:
      self.handle_operand(self.cmd.Op4, 0)
    if flags & CF_CHG4:
      self.handle_operand(self.cmd.Op4, 1)

    if not (flags & CF_STOP):
      ua_add_cref(0, self.cmd.ea + self.cmd.size, fl_F)

    return 1

  def outop(self, op):
    # print "outop %d" % op.type
    if op.type == o_reg:
      out_register(self.regNames[op.reg])
      if op.specval & self.BARREL_SHIFT_8:
        out_symbol(' ')
        out_symbol('s')
        out_symbol('h')
        out_symbol('l')
        out_symbol(' ')
        out_symbol('8')
    elif op.type == o_imm:
      if op.dtyp == dt_word:
        OutValue(op, OOFW_IMM | OOFW_16)
      else:
        OutValue(op, OOFW_IMM | OOFW_32)
    elif op.type == o_mem:
      OutValue(op, OOF_ADDR)
    elif op.type == o_near:
      out_name_expr(op, op.addr, BADADDR)
    elif op.type == o_displ:
      OutValue(op, OOF_ADDR)
      out_symbol('(')
      out_register(self.regNames[op.phrase])
      out_symbol(')')
    elif op.type == o_phrase:
      if op.specval & self.PREDECR:
        out_symbol('-')
        out_symbol('-')
      out_symbol('(')
      out_register(self.regNames[op.phrase])
      if op.specval & self.PHRASE_DUALREG:
        out_symbol(',')
        out_symbol(' ')
        out_register(self.regNames[op.specval & 31])
      out_symbol(')')
      if op.specval & self.POSTINCR:
        out_symbol('+')
        out_symbol('+')
    elif op.type == o_idpspec0:
      regSS = [ 0, 6, 16, 24 ]
      regS = regSS[op.value >> 5]
      regW = op.value & 0x1f
      out_register(self.regNames[regS])
      if regW > 0:
        out_symbol('-')
        out_register(self.regNames[(regS+regW)&0x1f])
      if op.specval & self.PUSHPOP_INCL_LRPC:
        out_symbol(',')
        out_symbol(' ')
        out_register(self.regNames[26]) # or 31
    else:
      out_symbol('?')
    return True

  def out(self):
    # print "out"
    buf = idaapi.init_output_buffer(128)
    OutMnem()
    if self.cmd.Op1.type != o_void:
      out_one_operand(0)
    if self.cmd.Op2.type != o_void:
      out_symbol(',')
      out_symbol(' ')
      out_one_operand(1)
    if self.cmd.Op3.type != o_void:
      out_symbol(',')
      out_symbol(' ')
      out_one_operand(2)
    if self.cmd.Op4.type != o_void:
      out_symbol(',')
      out_symbol(' ')
      out_one_operand(3)
    term_output_buffer()
    MakeLine(buf)
    return

  def simplify(self):
    # print "simplify"
    return

  def ana(self):
    # print "ana"
    op0 = ua_next_word()
    oplenbits = self.BITFIELD(op0, 8, 8)

    op = [ op0 ]

    if oplenbits < 0x80:
      self.cmd.size = 2
    else:
      op += [ ua_next_word() ]
      if oplenbits < 0xe0:
        self.cmd.size = 4
      else:
        op += [ ua_next_word() ]
        if oplenbits < 0xf8:
          self.cmd.size = 6
        else:
          op += [ ua_next_word() ]
          op += [ ua_next_word() ]
          self.cmd.size = 10

    self.cmd.itype = self.find_insn(op)
    # print "Parsed OP %x (oplenbits %d) to INSN #%d" % ( op0, oplenbits, self.cmd.itype )
    if self.cmd.itype >= self.instruc_end:
      return 0

    args = self.ISA[self.cmd.itype][4]
    if len(args) > 0:
      self.get_arg(op, args[0], self.cmd.Op1)
    if len(args) > 1:
      self.get_arg(op, args[1], self.cmd.Op2)
    if len(args) > 2:
      self.get_arg(op, args[2], self.cmd.Op3)
    if len(args) > 3:
      self.get_arg(op, args[3], self.cmd.Op4)

    return self.cmd.size

  def get_arg(self, op, arg, cmd):
    if len(arg) != 3:
      cmd.type = o_void
    else:
      # print "get_arg %d %d %d => " % (arg[0], arg[1], arg[2])
      boff, bsize, cmd.type = arg
      if cmd.type == o_reg:
        cmd.reg = self.XBITFIELD(op, boff, bsize)
      elif cmd.type == o_imm:
        if bsize <= 16:
          cmd.dtyp = dt_word
        else:
          cmd.dtyp = dt_dword
        cmd.value = self.SXBITFIELD(op, boff, bsize)
      elif cmd.type == o_mem:
        cmd.addr = self.cmd.ea + self.SXBITFIELD(op, boff, bsize)
        cmd.dtyp = dt_dword
      elif cmd.type == o_near:
        cmd.addr = self.cmd.ea + 2 * self.SXBITFIELD(op, boff, bsize)
      elif cmd.type == o_phrase:
        cmd.phrase = self.XBITFIELD(op, boff, bsize)
        cmd.specval = 0
      elif cmd.type == o_idpspec0:	# PUSH/POP regset
        cmd.value = self.XBITFIELD(op, boff, bsize)
        if op[0] & 0x0100:
          cmd.specval = self.PUSHPOP_INCL_LRPC
      elif cmd.type == self.o_temp0:	# 4*0xnnnn(sp)
        cmd.type = o_displ
        cmd.dtyp = dt_dword
        cmd.addr = 4 * self.SXBITFIELD(op, boff, bsize)
        cmd.phrase = 25
        cmd.specval = 0
      elif cmd.type == self.o_temp1:	# 11:5 displ
        cmd.type = o_displ
        cmd.dtyp = dt_dword
        cmd.addr = self.SXBITFIELD(op, boff, bsize-5)
        cmd.phrase = self.XBITFIELD(op, boff+11, 5)
        cmd.specval = 0
      elif (cmd.type >= self.o_temp2) and (cmd.type <= self.o_temp5):	# 16:0(r24) displ
        tempregs = [ 24, 25, 31, 0 ]
        temptype = cmd.type
        cmd.type = o_displ
        cmd.dtyp = dt_dword
        cmd.addr = self.SXBITFIELD(op, boff, bsize)
        cmd.phrase = tempregs[temptype - self.o_temp2]
        cmd.specval = 0
      elif cmd.type == self.o_temp6:	# 5.5:16.16 displ
        cmd.type = o_displ
        cmd.dtyp = dt_dword
        cmd.addr = self.SXBITFIELD(op, 16, 16)
        cmd.phrase = self.XBITFIELD(op, 5, 5)
        cmd.specval = 0
      elif cmd.type == self.o_temp7:	# 16.5:27.5 displ
        cmd.type = o_phrase
        cmd.dtyp = dt_dword
        cmd.phrase = self.XBITFIELD(op, boff, 5)
        cmd.specval = self.PHRASE_DUALREG | self.XBITFIELD(op, boff+11, 5)
      elif cmd.type == self.o_temp8:	# 4:4 displ
        cmd.type = o_displ
        cmd.dtyp = dt_dword
        cmd.addr = 4 * self.SXBITFIELD(op, boff+4, 4)
        cmd.phrase = self.XBITFIELD(op, boff, 4)
        cmd.specval = 0
      elif cmd.type == self.o_temp9:	# loooong displ
        cmd.type = o_displ
        cmd.dtyp = dt_dword
        cmd.addr = (self.SXBITFIELD(op, 16, 11) << 16) | self.XBITFIELD(op, 32, 16)
        cmd.phrase = self.XBITFIELD(op, 27, 5)
        cmd.specval = 0
      elif cmd.type == self.o_temp10 or cmd.type == self.o_temp11:
        cmd.type = o_phrase
        cmd.phrase = self.XBITFIELD(op, boff, bsize)
        if cmd.type == self.o_temp10:
          cmd.specval = self.PREDECR
        else:
          cmd.specval = self.POSTINCR
      elif cmd.type == self.o_temp12: # rNN shl 8
        cmd.type = o_reg
        cmd.reg = self.XBITFIELD(op, boff, bsize)
        cmd.specval = self.BARREL_SHIFT_8
    # print "get_arg %d (%d %d %d)" % (cmd.type, cmd.reg, cmd.value, cmd.addr)

  def notify_init(self, idp):
    print "notify_init"
    # idaapi.cvar.inf.mf = 1
    return 1

  def find_insn(self, op):
    # print "Searching pattern, OP0 is %d, length %d." % ( op[0], len(op) )
    i = 0
    for insn in self.ISA:
      mnem, patt, mask, fl, args = insn
      if len(mask) == len(op):
        opmasked = [ (op[j] & mask[j]) for j in range(len(op)) ]
        # print (op, mask, opmasked )
        if opmasked == patt:
          # print "Found at %d. (OP/MASK/PATT %d/%d/%d)" % (i, op[0], mask[0], patt[0])
          return i
      i += 1
    return self.instruc_end

  def init_isa(self):
    cstr = [ "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "", "f" ]
    self.instruc = [ ]
    i = 0
    for insnpatt in self.ISACC:
      ccshift = insnpatt[0]
      for insn in insnpatt[1:]:
        for c in range(0,16):
          insnmnem = insn[0]
          insnbitpattern = insn[1][:]
          insnbitpattern[(ccshift >> 4)] |= (c << (ccshift & 15))
          xinsn = [ insnmnem.replace("CC", cstr[c]), insnbitpattern, insn[2], insn[3], insn[4] ]
          if c == 14 and xinsn[3] & CF_JUMP:
            xinsn[3] |= CF_STOP
          if len(insnbitpattern) == 1:
            self.ISA16 += [ xinsn ]
          elif len(insnbitpattern) == 2:
            self.ISA32 += [ xinsn ]
          elif len(insnbitpattern) == 3:
            self.ISA48 += [ xinsn ]
          else:
            self.ISA80 += [ xinsn ]
    self.ISA16 += [ [ "UNK16", [0] * 1, [0] * 1, 0, [] ] ]
    self.ISA32 += [ [ "UNK32", [0] * 2, [0] * 2, 0, [] ] ]
    self.ISA48 += [ [ "UNK48", [0] * 3, [0] * 3, 0, [] ] ]
    self.ISA80 += [ [ "UNK80", [0] * 5, [0] * 5, 0, [] ] ]
    self.ISA = self.ISA16 + self.ISA32 + self.ISA48 + self.ISA80
    # print self.ISA
    for insn in self.ISA:
      print insn
      mnem, patt, mask, fl, args = insn
      self.instruc.append( { 'name': mnem, 'feature': fl } )
      i += 1
    return i

  def __init__(self):
    print "__init__"
    idaapi.processor_t.__init__(self)
    self.regNames = [ "r%d" % d for d in range(0, 31) ]
    for d in range(0, 31):
      setattr(self, 'ireg_%d' % d, d)
    self.regNames += [ "rfoo" ]
    setattr(self, 'ireg_foo', 32)
    self.instruc_end = self.init_isa()
    # setattr(self, 'itype_nop', 0)
    self.comments = { }
    self.regFirstSreg = 32
    self.regLastSreg = 32
    self.regCodeSreg = 32
    self.regDataSreg = 32
    self.PTRSIZE = 4
    self.icode_return = 0

def PROCESSOR_ENTRY():
  # print "Constructing VCIV module"
  return vciv_processor_t()
