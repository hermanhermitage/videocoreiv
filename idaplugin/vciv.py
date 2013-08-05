# Broadcom Videocore IV -- IDA Processor Plugin
# ---------------------------------------------
#
# This module is nothing more than videocoreiv.arch brought into a form
# that IDA understands. Some features are still missing - I might add
# them if I find the time.
#
# -- Jan
#
# TODO (by no means exhaustive):
#   - add code xrefs for tbb/tbh (judging heuristically where the table ends?)
#   - add FPU and VRF instructions

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

  o_temp0 = o_last+1
  o_temp1 = o_last+2
  o_temp2 = o_last+3
  o_temp3 = o_last+4
  o_temp4 = o_last+5
  o_temp5 = o_last+6
  o_temp6 = o_last+7
  o_temp7 = o_last+8
  o_temp8 = o_last+9
  o_temp9 = o_last+10
  o_temp10 = o_last+11
  o_temp11 = o_last+12
  o_temp13 = o_last+13
  o_imm_signed = o_last+14
  o_reg_sasl = o_last+15
  o_reg_sasr = o_last+16
  o_imm_signed_sasl = o_last+17
  o_imm_signed_sasr = o_last+18
  o_vrf = o_last+19
  o_vrfa48 = o_last+20
  o_vrfd48 = o_last+21
  o_vrfb48 = o_last+22
  o_vflags = o_last+23
  o_vflags48 = o_last+24
  o_vrfa80 = o_last+25
  o_vrfd80 = o_last+26
  o_vrfb80 = o_last+27
  o_vflags80 = o_last+28
  o_imm10_6 = o_last+29
  o_vecmemdst = o_last+30
  o_vecmemsrc = o_last+31

  #Supplemental flags for operand types
  TF_SHL =		0x40010000  #Operand is shifted left by a specified amount
  
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
    ["rti", [0x000a], [0xffff], CF_STOP, []],
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
    ["cmn", [0x4100], [0xff00], CF_USE1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["add", [0x4200], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["bic", [0x4300], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["mul", [0x4400], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["eor", [0x4500], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["sub", [0x4600], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["and", [0x4700], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["not", [0x4800], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["ror", [0x4900], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["cmp", [0x4a00], [0xff00], CF_USE1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["rsub", [0x4b00], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["btst", [0x4c00], [0xff00], CF_USE1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["or", [0x4d00], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["bmask", [0x4e00], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["max", [0x4f00], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["bset", [0x5000], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["min", [0x5100], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["bclr", [0x5200], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["add", [0x5300], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg|TF_SHL|(1<<8)]]],
    ["bchg", [0x5400], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["add", [0x5500], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg|TF_SHL|(2<<8)]]],
    ["add", [0x5600], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg|TF_SHL|(3<<8)]]],
    ["add", [0x5700], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg|TF_SHL|(4<<8)]]],
    ["signext", [0x5800], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["neg", [0x5900], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["lsr", [0x5a00], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["msb", [0x5b00], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["shl", [0x5c00], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["bitrev", [0x5d00], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["asr", [0x5e00], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["abs", [0x5f00], [0xff00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,4,o_reg]]],
    ["mov", [0x6000], [0xfe00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,5,o_imm]]],
    ["add", [0x6200], [0xfe00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,5,o_imm]]],
    ["mul", [0x6400], [0xfe00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,5,o_imm]]],
    ["sub", [0x6600], [0xfe00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,5,o_imm]]],
    ["not", [0x6800], [0xfe00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,5,o_imm]]],
    ["cmp", [0x6a00], [0xfe00], CF_USE1 | CF_USE2, [[0,4,o_reg],[4,5,o_imm]]],
    ["btst", [0x6c00], [0xfe00], CF_USE1 | CF_USE2, [[0,4,o_reg],[4,5,o_imm]]],
    ["bmask", [0x6e00], [0xfe00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,5,o_imm]]],
    ["bset", [0x7000], [0xfe00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,5,o_imm]]],
    ["bclr", [0x7200], [0xfe00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,5,o_imm]]],
    ["bchg", [0x7400], [0xfe00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,5,o_imm]]],
    ["add", [0x7600], [0xfe00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,5,o_imm|TF_SHL|(3<<8)]]],
    ["signext", [0x7800], [0xfe00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,5,o_imm]]],
    ["lsr", [0x7a00], [0xfe00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,5,o_imm]]],
    ["shl", [0x7c00], [0xfe00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,5,o_imm]]],
    ["asr", [0x7e00], [0xfe00], CF_CHG1 | CF_USE2, [[0,4,o_reg],[4,5,o_imm]]],
  ]
  ISA32 = [
    ["bl", [0x9080, 0x0000], [0xf080, 0x0000], CF_CALL | CF_USE1, [[5,27,o_temp13]]],
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
    ["mov", [0xb000, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm_signed]]],
    ["cmn", [0xb020, 0x0000], [0xffe0, 0x0000], CF_USE1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm_signed]]],
    ["add", [0xb040, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm_signed]]],
    ["bic", [0xb060, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm_signed]]],
    ["mul", [0xb080, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm_signed]]],
    ["eor", [0xb0a0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm_signed]]],
    ["sub", [0xb0c0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm_signed]]],
    ["and", [0xb0e0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm_signed]]],
    ["not", [0xb100, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm_signed]]],
    ["ror", [0xb120, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm_signed]]],
    ["cmp", [0xb140, 0x0000], [0xffe0, 0x0000], CF_USE1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm_signed]]],
    ["rsub", [0xb160, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm_signed]]],
    ["btst", [0xb180, 0x0000], [0xffe0, 0x0000], CF_USE1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm_signed]]],
    ["or", [0xb1a0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm_signed]]],
    ["bmask", [0xb1c0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm_signed]]],
    ["max", [0xb1e0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm_signed]]],
    ["bset", [0xb200, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm_signed]]],
    ["min", [0xb220, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm_signed]]],
    ["bclr", [0xb240, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm_signed]]],
    ["add", [0xb260, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm_signed|TF_SHL|(1<<8)]]],
    ["bchg", [0xb280, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm_signed]]],
    ["add", [0xb2a0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm_signed|TF_SHL|(2<<8)]]],
    ["add", [0xb2c0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm_signed|TF_SHL|(3<<8)]]],
    ["add", [0xb2e0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm_signed|TF_SHL|(4<<8)]]],
    ["signext", [0xb300, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm_signed]]],
    ["neg", [0xb320, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm_signed]]],
    ["lsr", [0xb340, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm_signed]]],
    ["msb", [0xb360, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm_signed]]],
    ["shl", [0xb380, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm_signed]]],
    ["bitrev", [0xb3a0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm_signed]]],
    ["asr", [0xb3c0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm_signed]]],
    ["abs", [0xb3e0, 0x0000], [0xffe0, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,16,o_imm_signed]]],
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
    ["cmn", [0xe820, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_USE1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["add", [0xe840, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["bic", [0xe860, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["mul", [0xe880, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["eor", [0xe8a0, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["sub", [0xe8c0, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["and", [0xe8e0, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["not", [0xe900, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["ror", [0xe920, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["cmp", [0xe940, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_USE1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["rsub", [0xe960, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["btst", [0xe980, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_USE1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["or", [0xe9a0, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["bmask", [0xe9c0, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["max", [0xe9e0, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["bset", [0xea00, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["min", [0xea20, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["bclr", [0xea40, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["add", [0xea60, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm|TF_SHL|(1<<8)]]],
    ["bchg", [0xea80, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["add", [0xeaa0, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm|TF_SHL|(2<<8)]]],
    ["add", [0xeac0, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm|TF_SHL|(3<<8)]]],
    ["add", [0xeae0, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm|TF_SHL|(4<<8)]]],
    ["signext", [0xeb00, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["neg", [0xeb20, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["lsr", [0xeb40, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["msb", [0xeb60, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["shl", [0xeb80, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["bitrev", [0xeba0, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["asr", [0xebc0, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    ["abs", [0xebe0, 0x0000, 0x0000], [0xffe0, 0x0000, 0x0000], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,32,o_imm]]],
    #
    ["add", [0xec00, 0x0000, 0x0000], [0xfc00, 0x0000, 0x0000], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[5,5,o_reg],[16,32,o_imm]]],
  ]
#1111 00 mop:5 width:2 rs:3 d:10 a:10 z0 111 F:1 rb:6   v<mop><width> Rd[+rs], Ra[+rs], (rb) [SETF]
#1111 00 mop:5 width:2 rs:3 d:10 a:10 z0 b:10           v<mop><width> Rd[+rs], Ra[+rs], Rb[+rs]
#1111 00 mop:5 width:2 rs:3 d:10 a:10 z1 P:3 F:1 i:6    v<mop><width> Rd[+rs], Ra[+rs], #i [SETF] [IFZ|IFNZ|IFN|IFNN|IFC|IFNC]
#00000  ld            Load vector from memory.  D[i] = *(rb+i*width)
#00001  lookupmh      Gather values.            D[i] = *(rb+ACCH[i]*width)
#00010  lookupml      Gather values.            D[i] = *(rb+ACC[i]*width)
#
#00100  st            Store vector to memory.   *(rb+i*width) = A[i]
#00101  indexwritemh  Scatter values.           *(rb+ACCH[i]*width) = A[i].
#00110  indexwriteml  Scatter values.           *(rb+ACC[i]*width) = A[i].
#
#Lookup Table - A 1024 byte lookup-table for fast lookups.
#
#01000  readlut       Lookup values in LUT.     D[i] = lut(B[i]*width). eg. readlut V(0,0), -, V(16,0)
#01001  writelut      Write values to LUT.      lut(B[i]*width) = A[i]. eg. writelut 0, V(0,0), (r0)
  ISAV48MEM = [
    ["vWWld", [0xf000, 0x0000, 0x0380], [0xfff8, 0x0000, 0x0780], CF_CHG1 | CF_USE2 | CF_USE3, [[16,10,o_vrfd48],[32,3,o_phrase],[41,1,o_vflags48]]],
    ["vWWlookupmh", [0xf020, 0x0000, 0x0380], [0xfff8, 0x0000, 0x0780], CF_CHG1 | CF_USE2 | CF_USE3, [[16,10,o_vrfd48],[32,3,o_phrase],[41,1,o_vflags48]]],
    ["vWWlookupml", [0xf040, 0x0000, 0x0380], [0xfff8, 0x0000, 0x0780], CF_CHG1 | CF_USE2 | CF_USE3, [[16,10,o_vrfd48],[32,3,o_phrase],[41,1,o_vflags48]]],

    ["vWWst", [0xf080, 0x0000, 0x0380], [0xfff8, 0x0000, 0x0780], CF_USE1 | CF_CHG2 | CF_USE3, [[26,10,o_vrfa48],[32,3,o_phrase],[41,1,o_vflags48]]],
    ["vWWindexwritemh", [0xf0a0, 0x0000, 0x0380], [0xfff8, 0x0000, 0x0780], CF_USE1 | CF_CHG2 | CF_USE3, [[26,10,o_vrfa48],[32,3,o_phrase],[41,1,o_vflags48]]],
    ["vWWindexwriteml", [0xf0c0, 0x0000, 0x0380], [0xfff8, 0x0000, 0x0780], CF_USE1 | CF_CHG2 | CF_USE3, [[26,10,o_vrfa48],[32,3,o_phrase],[41,1,o_vflags48]]],

#    ["vWWld", [0xf000, 0x0000, 0x0380], [0xfff8, 0x0000, 0x0780], CF_CHG1 | CF_USE2, [[22,10,o_vrf],[32,3,o_phrase]]],
#    ["vWWld", [0xf000, 0x0000, 0x0380], [0xfff8, 0x0000, 0x0780], CF_CHG1 | CF_USE2, [[22,10,o_vrf],[32,3,o_phrase]]],
  ]
  ISAV48DAT = [
    ["vPPh", [0xf400, 0x0000, 0x0400], [0xfff8, 0x0000, 0x0400], CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4, [[16,10,o_vrfd48],[26,10,o_vrfa48],[32,6,o_imm],[38,4,o_vflags48]]],
    ["vPPh", [0xf400, 0x0000, 0x0380], [0xfff8, 0x0000, 0x0780], CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4, [[16,10,o_vrfd48],[26,10,o_vrfa48],[32,3,o_reg],[41,1,o_vflags48]]],
    ["vPPh", [0xf400, 0x0000, 0x0000], [0xfff8, 0x0000, 0x0400], CF_CHG1 | CF_USE2 | CF_USE3, [[16,10,o_vrfd48],[26,10,o_vrfa48],[38,10,o_vrfb48]]],
    ["vPPl", [0xf600, 0x0000, 0x0400], [0xfff8, 0x0000, 0x0400], CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4, [[16,10,o_vrfd48],[26,10,o_vrfa48],[32,6,o_imm],[38,4,o_vflags48]]],
    ["vPPl", [0xf600, 0x0000, 0x0380], [0xfff8, 0x0000, 0x0780], CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4, [[16,10,o_vrfd48],[26,10,o_vrfa48],[32,3,o_reg],[41,1,o_vflags48]]],
    ["vPPl", [0xf600, 0x0000, 0x0000], [0xfff8, 0x0000, 0x0400], CF_CHG1 | CF_USE2 | CF_USE3, [[16,10,o_vrfd48],[26,10,o_vrfa48],[38,10,o_vrfb48]]],
  ]
  ISAVEC48 = [
  ]
#1111 10 mop:5 width:2 r:3 1110 rd:6 a:10 F 0 111 l:7 f_d:6 f_a:6 Ra_x:4 P:3 i:7 rs:4 i:2
#1111 10 mop:5 width:2 r:3 d:10 1110 ra:6 F 0 111 l:7 f_d:6 f_a:6 Ra_x:4 P:3 i:7 rs:4 i:2
#1111 10 mop:5 width:2 r:3 d:10 a:10 F 0 b:10 f_d:6 f_a:6 Ra_x:4 P:3 f_i:7 f_b:6
#1111 10 mop:5 width:2 r:3 d:10 a:10 F 1 l:10 f_d:6 f_a:6 Ra_x:4 P:3 f_i:7 j:6

#00000  ld            Load vector from memory.  D[i] = *(rb+i*width)
#00001  lookupmh      Gather values.            D[i] = *(rb+ACCH[i]*width)
#00010  lookupml      Gather values.            D[i] = *(rb+ACC[i]*width)
#
#00100  st            Store vector to memory.   *(rb+i*width) = A[i]
#00101  indexwritemh  Scatter values.           *(rb+ACCH[i]*width) = A[i].
#00110  indexwriteml  Scatter values.           *(rb+ACC[i]*width) = A[i].
#
#Lookup Table - A 1024 byte lookup-table for fast lookups.
#
#01000  readlut       Lookup values in LUT.     D[i] = lut(B[i]*width). eg. readlut V(0,0), -, V(16,0)
#01001  writelut      Write values to LUT.      lut(B[i]*width) = A[i]. eg. writelut 0, V(0,0), (r0)
#  o_vecmemdst = o_last+30
#  o_vecmemsrc = o_last+31
  ISAV80MEM = [
    ["vWWld", [0xf800, 0x0000, 0x0380, 0x0000, 0x0000], [0xfff8, 0x0000, 0x0780, 0x0000, 0x0000], CF_CHG1 | CF_USE2 | CF_USE3, [[16,10,o_vrfd80],[0,0,o_vecmemsrc],[38,4,o_vflags80]]],
    ["vWWlookupmh", [0xf820, 0x0000, 0x0380, 0x0000, 0x0000], [0xfff8, 0x0000, 0x0780, 0x0000, 0x0000], CF_CHG1 | CF_USE2 | CF_USE3, [[16,10,o_vrfd80],[0,0,o_vecmemsrc],[38,4,o_vflags80]]],
    ["vWWlookupml", [0xf840, 0x0000, 0x0380, 0x0000, 0x0000], [0xfff8, 0x0000, 0x0780, 0x0000, 0x0000], CF_CHG1 | CF_USE2 | CF_USE3, [[16,10,o_vrfd80],[0,0,o_vecmemsrc],[38,4,o_vflags80]]],

    ["vWWst", [0xf880, 0x0000, 0x0380, 0x0000, 0x0000], [0xfff8, 0x0000, 0x0780, 0x0000, 0x0000], CF_USE1 | CF_CHG2 | CF_USE3, [[26,10,o_vrfa80],[0,0,o_vecmemdst],[38,4,o_vflags80]]],
    ["vWWindexwritemh", [0xf8a0, 0x0000, 0x0380, 0x0000, 0x0000], [0xfff8, 0x0000, 0x0780, 0x0000, 0x0000], CF_USE1 | CF_CHG2 | CF_USE3, [[26,10,o_vrfa80],[32,3,o_vecmemdst],[38,4,o_vflags80]]],
    ["vWWindexwriteml", [0xf8c0, 0x0000, 0x0380, 0x0000, 0x0000], [0xfff8, 0x0000, 0x0780, 0x0000, 0x0000], CF_USE1 | CF_CHG2 | CF_USE3, [[26,10,o_vrfa80],[32,3,o_vecmemdst],[38,4,o_vflags80]]],

#    ["vWWld", [0xf000, 0x0000, 0x0380], [0xfff8, 0x0000, 0x0780], CF_CHG1 | CF_USE2, [[22,10,o_vrf],[32,3,o_phrase]]],
#    ["vWWld", [0xf000, 0x0000, 0x0380], [0xfff8, 0x0000, 0x0780], CF_CHG1 | CF_USE2, [[22,10,o_vrf],[32,3,o_phrase]]],
  ]
#1111 11 X v:6 r:3 d:10 a:10 F 0 b:10 f_d:6 f_a:6 Ra_x:4 P:3 f_i:7 f_b:6
#1111 11 X v:6 r:3 d:10 a:10 F 1 k:10 f_d:6 f_a:6 Ra_x:4 P:3 f_i:7 j:6
  ISAV80DAT = [
    ["vPPh", [0xfc00, 0x0000, 0x0400, 0x0000, 0x0000], [0xfff8, 0x0000, 0x0400, 0x0000, 0x0000], CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4, [[16,10,o_vrfd80],[26,10,o_vrfa80],[38,10,o_imm10_6],[38,4,o_vflags80]]],
    ["vPPh", [0xfc00, 0x0000, 0x0380, 0x0000, 0x0000], [0xfff8, 0x0000, 0x0780, 0x0000, 0x0000], CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4, [[16,10,o_vrfd80],[26,10,o_vrfa80],[32,3,o_reg],[38,4,o_vflags80]]],
    ["vPPh", [0xfc00, 0x0000, 0x0000, 0x0000, 0x0000], [0xfff8, 0x0000, 0x0400, 0x0000, 0x0000], CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4, [[16,10,o_vrfd80],[26,10,o_vrfa80],[38,10,o_vrfb80],[38,4,o_vflags80]]],
    ["vPPl", [0xfe00, 0x0000, 0x0400, 0x0000, 0x0000], [0xfff8, 0x0000, 0x0400, 0x0000, 0x0000], CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4, [[16,10,o_vrfd80],[26,10,o_vrfa80],[38,10,o_imm10_6],[38,4,o_vflags80]]],
    ["vPPl", [0xfe00, 0x0000, 0x0380, 0x0000, 0x0000], [0xfff8, 0x0000, 0x0780, 0x0000, 0x0000], CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4, [[16,10,o_vrfd80],[26,10,o_vrfa80],[32,3,o_reg],[38,4,o_vflags80]]],
    ["vPPl", [0xfe00, 0x0000, 0x0000, 0x0000, 0x0000], [0xfff8, 0x0000, 0x0400, 0x0000, 0x0000], CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4, [[16,10,o_vrfd80],[26,10,o_vrfa80],[38,10,o_vrfb80],[38,4,o_vflags80]]],
  ]
  ISAVEC80 = [
  ]
  ISACC = [
    [7,
     ["bCC", [0x1800], [0xff80], CF_JUMP | CF_USE1, [[9,7,o_near]]]
    ],
	[8,
     ["bCC", [0x8000, 0x4000], [0xfff0, 0xc000], CF_JUMP | CF_USE1 | CF_USE2 | CF_USE3, [[0,4,o_reg],[26,4,o_reg],[22,10,o_near]]],
     ["bCC", [0x8000, 0xc000], [0xfff0, 0xc000], CF_JUMP | CF_USE1 | CF_USE2 | CF_USE3, [[0,4,o_reg],[24,6,o_imm],[24,8,o_near]]],
	],
    [8,
     ["addcmpbCC", [0x8000, 0x0000], [0xff00, 0xc000], CF_JUMP | CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4, [[0,4,o_reg],[4,4,o_reg],[26,4,o_reg],[22,10,o_near]]],
     ["addcmpbCC", [0x8000, 0x4000], [0xff00, 0xc000], CF_JUMP | CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4, [[0,4,o_reg],[4,4,o_imm_signed],[26,4,o_reg],[22,10,o_near]]],
     ["addcmpbCC", [0x8000, 0x8000], [0xff00, 0xc000], CF_JUMP | CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4, [[0,4,o_reg],[4,4,o_reg],[24,6,o_imm],[24,8,o_near]]],
     ["addcmpbCC", [0x8000, 0xc000], [0xff00, 0xc000], CF_JUMP | CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4, [[0,4,o_reg],[4,4,o_imm_signed],[24,6,o_imm],[24,8,o_near]]],
    ],
    [8,
     ["bCC", [0x9000, 0x0000], [0xff80, 0x0000], CF_JUMP | CF_USE1, [[9,23,o_near]]]
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
     ["movCC", [0xc000, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,5,o_reg]]],
     ["cmnCC", [0xc020, 0x0000], [0xffe0, 0x07e0], CF_USE1 | CF_USE2, [[27,5,o_reg],[16,5,o_reg]]],
     ["addCC", [0xc040, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["bicCC", [0xc060, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["mulCC", [0xc080, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["eorCC", [0xc0a0, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["subCC", [0xc0c0, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["andCC", [0xc0e0, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["notCC", [0xc100, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,5,o_reg]]],
     ["rorCC", [0xc120, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["cmpCC", [0xc140, 0x0000], [0xffe0, 0x07e0], CF_USE1 | CF_USE2, [[27,5,o_reg],[16,5,o_reg]]],
     ["rsubCC", [0xc160, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["btstCC", [0xc180, 0x0000], [0xffe0, 0x07e0], CF_USE1 | CF_USE2, [[27,5,o_reg],[16,5,o_reg]]],
     ["orCC", [0xc1a0, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["bmaskCC", [0xc1c0, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["maxCC", [0xc1e0, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["bsetCC", [0xc200, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["minCC", [0xc220, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["bclrCC", [0xc240, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["addCC", [0xc260, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg|TF_SHL|(1<<8)]]],
     ["bchgCC", [0xc280, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["addCC", [0xc2a0, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg|TF_SHL|(2<<8)]]],
     ["addCC", [0xc2c0, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg|TF_SHL|(3<<8)]]],
     ["addCC", [0xc2e0, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg|TF_SHL|(4<<8)]]],
     ["signextCC", [0xc300, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["negCC", [0xc320, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,5,o_reg]]],
     ["lsrCC", [0xc340, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["msbCC", [0xc360, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,5,o_reg]]],
     ["shlCC", [0xc380, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["bitrevCC", [0xc3a0, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["asrCC", [0xc3c0, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["absCC", [0xc3e0, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,5,o_reg]]],
    ],
	[23,
     ["movCC", [0xc000, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,6,o_imm_signed]]],
     ["cmnCC", [0xc020, 0x0040], [0xffe0, 0x07c0], CF_USE1 | CF_USE2, [[27,5,o_reg],[16,6,o_imm_signed]]],
     ["addCC", [0xc040, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
     ["bicCC", [0xc060, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
     ["mulCC", [0xc080, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
     ["eorCC", [0xc0a0, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
     ["subCC", [0xc0c0, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
     ["andCC", [0xc0e0, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
     ["notCC", [0xc100, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,6,o_imm_signed]]],
     ["rorCC", [0xc120, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
     ["cmpCC", [0xc140, 0x0040], [0xffe0, 0x07c0], CF_USE1 | CF_USE2, [[27,5,o_reg],[16,6,o_imm_signed]]],
     ["rsubCC", [0xc160, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
     ["btstCC", [0xc180, 0x0040], [0xffe0, 0x07c0], CF_USE1 | CF_USE2, [[27,5,o_reg],[16,6,o_imm_signed]]],
     ["orCC", [0xc1a0, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
     ["bmaskCC", [0xc1c0, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
     ["maxCC", [0xc1e0, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
     ["bsetCC", [0xc200, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
     ["minCC", [0xc220, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
     ["bclrCC", [0xc240, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
     ["addCC", [0xc260, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed|TF_SHL|(1<<8)]]],
     ["bchgCC", [0xc280, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
     ["addCC", [0xc2a0, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed|TF_SHL|(2<<8)]]],
     ["addCC", [0xc2c0, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed|TF_SHL|(3<<8)]]],
     ["addCC", [0xc2e0, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed|TF_SHL|(4<<8)]]],
     ["signextCC", [0xc300, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
     ["negCC", [0xc320, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,6,o_imm_signed]]],
     ["lsrCC", [0xc340, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
     ["msbCC", [0xc360, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,6,o_imm_signed]]],
     ["shlCC", [0xc380, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
     ["bitrevCC", [0xc3a0, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
     ["asrCC", [0xc3c0, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
     ["absCC", [0xc3e0, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,6,o_imm_signed]]],
    ],
    [23,
     ["mulhd(ss)CC", [0xc400, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["mulhd(ss)CC", [0xc400, 0x0040], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
     ["mulhd(su)CC", [0xc420, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["mulhd(su)CC", [0xc420, 0x0040], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
     ["mulhd(us)CC", [0xc440, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["mulhd(us)CC", [0xc440, 0x0040], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
     ["mulhd(uu)CC", [0xc460, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["mulhd(uu)CC", [0xc460, 0x0040], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
    ],
    [23,
     ["div(s)CC", [0xc480, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["div(s)CC", [0xc480, 0x0040], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
     ["div(su)CC", [0xc4a0, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["div(su)CC", [0xc4a0, 0x0040], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
     ["div(us)CC", [0xc4c0, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["div(us)CC", [0xc4c0, 0x0040], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
     ["div(u)CC", [0xc4e0, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
     ["div(u)CC", [0xc4e0, 0x0040], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
    ],
    [23,
     ["add", [0xc5e0, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg|TF_SHL|(8<<8)]]],
    ],
	#floating point
	[23,
     ["faddCC", [0xc800, 0x0000], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
	 ["fsubCC", [0xc820, 0x0000], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
	 ["fmulCC", [0xc840, 0x0000], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
	 ["fdivCC", [0xc860, 0x0000], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
	 ["fcmpCC", [0xc880, 0x0000], [0xffe0, 0x07c0], CF_USE1 | CF_USE2, [[27,5,o_reg],[16,5,o_reg]]],
	 ["fabsCC", [0xc8a0, 0x0000], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,5,o_reg]]],
	 ["frsbCC", [0xc8c0, 0x0000], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
	 ["fmaxCC", [0xc8e0, 0x0000], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
	 ["frcpCC", [0xc900, 0x0000], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,5,o_reg]]],
	 ["frsqrtCC", [0xc920, 0x0000], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,5,o_reg]]],
	 ["fnmulCC", [0xc940, 0x0000], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
	 ["fminCC", [0xc960, 0x0000], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
	 ["fceilCC", [0xc980, 0x0000], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,5,o_reg]]],
	 ["ffloorCC", [0xc9a0, 0x0000], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,5,o_reg]]],
	 ["flog2CC", [0xc9c0, 0x0000], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
	 ["fexp2CC", [0xc9e0, 0x0000], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg]]],
	],
	[23,
     ["faddCC", [0xc800, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
	 ["fsubCC", [0xc820, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
	 ["fmulCC", [0xc840, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
	 ["fdivCC", [0xc860, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
	 ["fcmpCC", [0xc880, 0x0040], [0xffe0, 0x07c0], CF_USE1 | CF_USE2, [[27,5,o_reg],[16,6,o_imm_signed]]],
	 ["fabsCC", [0xc8a0, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,6,o_imm_signed]]],
	 ["frsbCC", [0xc8c0, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
	 ["fmaxCC", [0xc8e0, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
	 ["frcpCC", [0xc900, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,6,o_imm_signed]]],
	 ["frsqrtCC", [0xc920, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,6,o_imm_signed]]],
	 ["fnmulCC", [0xc940, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
	 ["fminCC", [0xc960, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
	 ["fceilCC", [0xc980, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,6,o_imm_signed]]],
	 ["ffloorCC", [0xc9a0, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2, [[0,5,o_reg],[16,6,o_imm_signed]]],
	 ["flog2CC", [0xc9c0, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
	 ["fexp2CC", [0xc9e0, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed]]],
	],
	[23,
     ["ftruncCC", [0xca00, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg_sasl]]],
	 ["ftruncCC", [0xca00, 0x0040], [0xffe0, 0x07ff], CF_CHG1 | CF_USE2, [[0,5,o_reg],[27,5,o_reg]]],
	 ["ftruncCC", [0xca00, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed_sasl]]],
	 ["floorCC", [0xca20, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg_sasl]]],
	 ["floorCC", [0xca20, 0x0040], [0xffe0, 0x07ff], CF_CHG1 | CF_USE2, [[0,5,o_reg],[27,5,o_reg]]],
	 ["floorCC", [0xca20, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed_sasl]]],
	 ["fltsCC", [0xca40, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg_sasr]]],
	 ["fltsCC", [0xca40, 0x0040], [0xffe0, 0x07ff], CF_CHG1 | CF_USE2, [[0,5,o_reg],[27,5,o_reg]]],
	 ["fltsCC", [0xca40, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed_sasr]]],
	 ["fltuCC", [0xca60, 0x0000], [0xffe0, 0x07e0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,5,o_reg_sasr]]],
	 ["fltuCC", [0xca60, 0x0040], [0xffe0, 0x07ff], CF_CHG1 | CF_USE2, [[0,5,o_reg],[27,5,o_reg]]],
	 ["fltuCC", [0xca60, 0x0040], [0xffe0, 0x07c0], CF_CHG1 | CF_USE2 | CF_USE3, [[0,5,o_reg],[27,5,o_reg],[16,6,o_imm_signed_sasr]]],
	],
  ]

  #specval
  PUSHPOP_INCL_LRPC			= 0x00000200
  PREDECR					= 0x00000400
  POSTINCR					= 0x00000800
  PHRASE_DUALREG			= 0x00001000
  REG_IS_SHIFTED			= 0x00002000
  USE_AS_SASL				= 0x00004000
  USE_AS_SASR				= 0x00008000
  DISPL_INCREG				= 0x00010000

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

  @staticmethod
  def XBITFIELDLINEAR(wordarray, longData, start, width):
    rightHandStart = len(wordarray)*16-(start+width)
    return int(((longData >> rightHandStart) & ((1<<width)-1)))

  @staticmethod
  def SXBITFIELDLINEAR(wordarray, longData, start, width):
    v = vciv_processor_t.XBITFIELDLINEAR(wordarray, longData, start+1,width-1)
    sign = vciv_processor_t.XBITFIELDLINEAR(wordarray, longData, start,1)
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
        ua_add_cref(0, op.addr, fl_JN)
      if self.cmd.get_canon_feature() & CF_CALL:
        ua_add_cref(0, op.addr, fl_CN)

    # LEA should not always create a DREF...
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

    #VRF specval:
    #SIZE:22-21 DSCRD:20 SCLR:19 VERT:18 X:17-12 Y:11-6 INC_X:5 INC_Y:4 RS:3-0
    if op.type == self.o_vrf:
      if op.specval & 0x00100000:
        out_symbol('-')
        return True
      if op.specval & 0x00040000:
        out_symbol('V')
      else:
        out_symbol('H')
      vec_size = (op.specval >> 21) & 0x00000003
      if vec_size == 0 or vec_size == 1:
        out_symbol('8')
      elif vec_size == 2:
        out_symbol('1')
        out_symbol('6')
      elif vec_size == 3:
        out_symbol('3')
        out_symbol('2')
      out_symbol('(')
      OutLong((op.specval >> 6) & 0x3f, 10)
      if ((op.specval >> 4) & 0x01):
        out_symbol('+')
        out_symbol('+')
      out_symbol(',')
      out_symbol(' ')
      OutLong((op.specval >> 12) & 0x3f, 10)
      if ((op.specval >> 5) & 0x01):
        out_symbol('+')
        out_symbol('+')
      out_symbol(')')
      rs = op.specval & 0x0f
      if rs < 15:
        out_symbol('+')
        out_register(self.regNames[rs])
      return True

    #Vector Flags specval:
    #REP:13-11 ACCSCLR:10-4 IFxx:3-1 SETF:0
    elif op.type == self.o_vflags:
      if op.specval & 0x01:
        out_symbol('S')
        out_symbol('E')
        out_symbol('T')
        out_symbol('F')
        out_symbol(' ')

      ifflags = (op.specval >> 1) & 0x07
      if ifflags == 1:
        out_symbol('N')
        out_symbol('V')
        out_symbol(' ')
      elif ifflags != 0:
        out_symbol('I')
        out_symbol('F')
        if ifflags == 2:
          out_symbol('Z')
        elif ifflags == 3:
          out_symbol('N')
          out_symbol('Z')
        elif ifflags == 4:
          out_symbol('N')
        elif ifflags == 5:
          out_symbol('N')
          out_symbol('N')
        elif ifflags == 6:
          out_symbol('C')
        elif ifflags == 7:
          out_symbol('N')
          out_symbol('C')
        out_symbol(' ')

      vflags = (op.specval >> 4) & 0x007f
      if (vflags & 0x0040):
        #SCALAR WRITEBACK
        agg_type = (vflags >> 3) & 0x07
        if agg_type == 0:
          out_symbol('S')
          out_symbol('U')
          out_symbol('M')
          out_symbol('U')
        elif agg_type == 1:
          out_symbol('S')
          out_symbol('U')
          out_symbol('M')
          out_symbol('S')
        elif agg_type == 3:
          out_symbol('I')
          out_symbol('M')
          out_symbol('I')
          out_symbol('N')
        elif agg_type == 5:
          out_symbol('I')
          out_symbol('M')
          out_symbol('A')
          out_symbol('X')
        else:
          out_symbol('M')
          out_symbol('A')
          out_symbol('X')
        out_symbol(' ')
        out_register(self.regNames[vflags & 0x07])
        out_symbol(' ')
      else:
        #ACCUMULATOR
        if (vflags & 0x0040):
          out_symbol('C')
          out_symbol('L')
          out_symbol('R')
          out_symbol('A')
          out_symbol(' ')
        if (vflags & 0x0020):
          if (vflags & 0x0008):
            out_symbol('S')
          else:
            out_symbol('U')
          if (vflags & 0x0002):   #Writeback
            if (vflags & 0x0001): #Subtract
              out_symbol('D')
              out_symbol('E')
              out_symbol('C')
            else:                 #Add
              out_symbol('A')
              out_symbol('C')
              out_symbol('C')
          else:                   #No Writeback
            if (vflags & 0x0001): #Subtract
              out_symbol('S')
              out_symbol('U')
              out_symbol('B')
            else:                 #Add
              out_symbol('A')
              out_symbol('D')
              out_symbol('D')
          if (vflags & 0x0010):
            out_symbol('H')
          out_symbol(' ')

      repflags = (op.specval >> 11) & 0x07
      if repflags != 0:
        out_symbol('R')
        out_symbol('E')
        out_symbol('P')
        out_symbol(' ')
        if repflags == 7:
          out_register(self.regNames[0])
        else:
          OutLong(1 << repflags, 10)
        out_symbol(' ')

      return True

    elif op.specval & self.USE_AS_SASL:
      out_symbol('s')
      out_symbol('a')
      out_symbol('s')
      out_symbol('l')
      out_symbol(' ')
    elif op.specval & self.USE_AS_SASR:
      out_symbol('s')
      out_symbol('a')
      out_symbol('s')
      out_symbol('r')
      out_symbol(' ')
	
    if op.type == o_reg:
      out_register(self.regNames[op.reg])
      if op.specval & self.REG_IS_SHIFTED:
        out_symbol(' ')
        out_symbol('s')
        out_symbol('h')
        out_symbol('l')
        out_symbol(' ')
        OutLong(op.specval & 0x0F, 10)
    elif op.type == o_imm:
      if op.dtyp == dt_word:
        OutValue(op, OOFW_IMM | OOFW_16)
      else:
        OutValue(op, OOFW_IMM | OOFW_32)
    elif op.type == o_mem:
      r = out_name_expr(op, op.addr, BADADDR)
      if not r:
        out_tagon(COLOR_ERROR)
        OutLong(op.addr, 16)
        out_tagoff(COLOR_ERROR)
        QueueMark(Q_noName, cmd.ea)
    elif op.type == o_near:
      out_name_expr(op, op.addr, BADADDR)
    elif op.type == o_displ:
      if op.addr != 0:
        OutValue(op, OOF_ADDR)
      out_symbol('(')
      out_register(self.regNames[op.phrase])
      if op.specval & self.DISPL_INCREG:
        out_symbol('+')
        out_symbol('=')
        out_register(self.regNames[op.specval & 0x0f])
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
    buf = idaapi.init_output_buffer(512)
    OutMnem()
    if self.cmd.Op1.type != o_void:
      out_one_operand(0)
    if self.cmd.Op2.type != o_void:
      out_symbol(',')
      out_symbol(' ')
      out_one_operand(1)
    if self.cmd.Op3.type != o_void:
      if self.cmd.Op3.type != self.o_vflags:
        out_symbol(',')
      out_symbol(' ')
      out_one_operand(2)
    if self.cmd.Op4.type != o_void:
      if self.cmd.Op4.type != self.o_vflags:
        out_symbol(',')
      out_symbol(' ')
      out_one_operand(3)
    term_output_buffer()
    MakeLine(buf)
    return

  def simplify(self):
    # print "simplify"
    return

  def op_to_val(self,op,cmd_size):
    mix_table = {
      2:[0],          #Scalar16
      4:[0,1],        #Scalar32
      6:[0,2,1],      #Scalar48
      7:[0,1,2],      #Vector48
      10:[0,1,2,3,4]} #Vector80
    v = 0
    for i in mix_table[cmd_size]:
      v = v << 16
      v = v | op[i]
    return v

  def ana(self):
    # print "ana"
    op0 = ua_next_word()
    oplenbits = self.BITFIELD(op0, 8, 8)

    op = [ op0 ]

    lookup_size = 0
    if oplenbits < 0x80:
      lookup_size = 2
    else:
      op += [ ua_next_word() ]
      if oplenbits < 0xe0:
        lookup_size = 4
      else:
        op += [ ua_next_word() ]
        if oplenbits < 0xf0:
          lookup_size = 6  #Scalar48
        elif oplenbits < 0xf8:
          lookup_size = 7  #Vector48
        else:
          op += [ ua_next_word() ]
          op += [ ua_next_word() ]
          lookup_size = 10 #Vector80

    self.cmd.size = lookup_size
    if self.cmd.size == 7:
      self.cmd.size = 6
    op_val = self.op_to_val(op,lookup_size)

    self.cmd.itype = self.find_insn(op)
    # print "Parsed OP %x (oplenbits %d) to INSN #%d" % ( op0, oplenbits, self.cmd.itype )
    if self.cmd.itype >= self.instruc_end:
      return 0

    args = self.ISA[self.cmd.itype][4]
    if len(args) > 0:
      self.get_arg(op, op_val, args[0], self.cmd.Op1)
    if len(args) > 1:
      self.get_arg(op, op_val, args[1], self.cmd.Op2)
    if len(args) > 2:
      self.get_arg(op, op_val, args[2], self.cmd.Op3)
    if len(args) > 3:
      self.get_arg(op, op_val, args[3], self.cmd.Op4)

    return self.cmd.size

  def get_arg(self, op, op_val, arg, cmd):
    if len(arg) != 3:
      cmd.type = o_void
    else:
      # print "get_arg %d %d %d => " % (arg[0], arg[1], arg[2])
      boff, bsize, type = arg
      tflags = 0
      tfdata = 0
      if type & 0x40000000:
        tflags = type & 0x3FFF0000
        tfdata = (type >> 8) & 0xFF
        type &= 0xFF
      cmd.type = type

      if cmd.type == o_reg:
        cmd.reg = self.XBITFIELD(op, boff, bsize)
        if tflags & self.TF_SHL:
          cmd.specval = self.REG_IS_SHIFTED | (tfdata & 0x0F)
      elif cmd.type == o_imm:
        cmd.dtyp = dt_dword
        cmd.value = self.XBITFIELD(op, boff, bsize)
        if tflags & self.TF_SHL:
          cmd.value = cmd.value << (tfdata & 0x0F)
      elif cmd.type == self.o_imm_signed:
        cmd.type = o_imm
        cmd.dtyp = dt_dword
        cmd.value = self.SXBITFIELD(op, boff, bsize)
        if tflags & self.TF_SHL:
          cmd.value = cmd.value << (tfdata & 0x0F)
      elif cmd.type == o_mem:
        cmd.addr = self.cmd.ea + self.SXBITFIELD(op, boff, bsize)
        cmd.dtyp = dt_dword
      elif cmd.type == o_near:
        data_read = self.SXBITFIELDLINEAR(op, op_val, boff, bsize)
        #if boff == 9 and bsize == 23:
        #  print "Read bCC data:",hex(data_read),[hex(x) for x in op]
        cmd.addr = self.cmd.ea + 2 * data_read
      elif cmd.type == o_phrase:
        cmd.phrase = self.XBITFIELD(op, boff, bsize)
        cmd.specval = 0
      elif cmd.type == o_idpspec0:  # PUSH/POP regset
        cmd.value = self.XBITFIELD(op, boff, bsize)
        if op[0] & 0x0100:
          cmd.specval = self.PUSHPOP_INCL_LRPC
      elif cmd.type == self.o_temp0:	# 4*0xnnnn(sp)
        cmd.type = o_displ
        cmd.dtyp = dt_dword
        cmd.addr = 4 * self.XBITFIELD(op, boff, bsize)
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
        cmd.addr = 4 * self.XBITFIELD(op, boff+4, 4)
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
    # print "get_arg %d (%d %d %d)" % (cmd.type, cmd.reg, cmd.value, cmd.addr)
      elif cmd.type == self.o_temp13: # bl 32 bit
        cmd.type = o_near
        raw_data = self.SXBITFIELDLINEAR(op, op_val, boff, bsize)
        diff = ((raw_data >> 1 & (0x7F800000)) | \
                  (raw_data &     0x807FFFFF))
        #print "opcode:",[hex(x) for x in op],hex(op_val),"boff:",boff,"bsize:",bsize,"raw is:",hex(raw_data),"diff is:",hex(diff)
        cmd.addr = self.cmd.ea + 2 * diff
      elif cmd.type == self.o_reg_sasl:
        cmd.type = o_reg
        cmd.specval = self.USE_AS_SASL
      elif cmd.type == self.o_reg_sasr:
        cmd.type = o_reg
        cmd.specval = self.USE_AS_SASR
      elif cmd.type == self.o_imm_signed_sasl or cmd.type == self.o_imm_signed_sasr:
        cmd.type = o_imm
        cmd.dtyp = dt_dword
        cmd.value = self.SXBITFIELD(op, boff, bsize)
        if cmd.type == self.o_imm_signed_sasl:
          cmd.specval = self.USE_AS_SASL
        else:
          cmd.specval = self.USE_AS_SASR
      #VRF specval:
      #SIZE:22-21 DSCRD:20 SCLR:19 VERT:18 X:17-12 Y:11-6 INC_X:5 INC_Y:4 RS:3-0
      elif cmd.type == self.o_vrfa48 or cmd.type == self.o_vrfd48 or cmd.type == self.o_vrfb48:
        tmptype = cmd.type
        cmd.type = self.o_vrf
        cmd_val = self.XBITFIELDLINEAR(op, op_val, boff, bsize)
        if cmd_val >= 0x0380:
          cmd.specval = (1 << 20) #Discard/unused
        else:
          #vertical
          is_vert = self.XBITFIELD(op, 28, 1)
          cmd.specval = (is_vert << 18)
          #scalar register
          use_scalar = 0
          if tmptype == self.o_vrfd48:
            use_scalar = self.XBITFIELD(op, 11, 1)
          else:
            use_scalar = self.BITFIELD(cmd_val, 6, 1)
          rs = 0x0F
          if use_scalar:
            rs = self.XBITFIELD(op, 0, 3)
          cmd.specval |= rs
          #size
          cmd.specval |= ((cmd_val & 0x0300) << 13)
          #coordinates
          x_lookup = [ 0, 16, 32, 48, 0, 32, 0, 0 ]
          x_coord = x_lookup[self.BITFIELD(cmd_val, 7, 3)]
          y_coord = 0
          if is_vert:
            y_coord = cmd_val & 0x0030
            x_coord |= (cmd_val & 0x000f)
          else:
            y_coord = cmd_val & 0x003f
          cmd.specval |= (x_coord << 12)
          cmd.specval |= (y_coord << 6)
      #Vector Flags specval:
      #IFxx:3-1 SETF:0
      elif cmd.type == self.o_vflags48:
        cmd.type = self.o_vflags
        cmd_val = self.XBITFIELDLINEAR(op, op_val, boff, bsize)
        cmd.specval = cmd_val & 0x01
        if bsize > 1:
          ifflags = (cmd_val >> 1) & 0x07
          cmd.specval |= (ifflags << 1)
      elif cmd.type == self.o_imm10_6:
        cmd.type = o_imm
        cmd.dtyp = dt_dword
        cmd.value = (self.XBITFIELDLINEAR(op, op_val, 74, 6) << 10) | self.XBITFIELDLINEAR(op, op_val, 38, 10)
#1111 11 X v:6 r:3 d:10 a:10 F 0 b:10 f_d:6 f_a:6 Ra_x:4 P:3 f_i:7 f_b:6
#1111 11 X v:6 r:3 d:10 a:10 F 1 k:10 f_d:6 f_a:6 Ra_x:4 P:3 f_i:7 j:6
      #VRF specval:
      #SIZE:22-21 DSCRD:20 SCLR:19 VERT:18 X:17-12 Y:11-6 INC_X:5 INC_Y:4 RS:3-0
      elif cmd.type == self.o_vrfa80 or cmd.type == self.o_vrfd80 or cmd.type == self.o_vrfb80:
        tmptype = cmd.type
        cmd.type = self.o_vrf
        cmd_val = self.XBITFIELDLINEAR(op, op_val, boff, bsize)
        if cmd_val >= 0x0380:
          cmd.specval = (1 << 20) #Discard/unused
        else:
          #vertical
          is_vert = self.BITFIELD(cmd_val, 3, 1)
          cmd.specval = (is_vert << 18)
          v_flags = 0
          if tmptype == self.o_vrfd80:
            v_flags = self.XBITFIELDLINEAR(op, op_val, 48, 6)
          elif tmptype == self.o_vrfa80:
            v_flags = self.XBITFIELDLINEAR(op, op_val, 54, 6)
          elif tmptype == self.o_vrfb80:
            v_flags = self.XBITFIELDLINEAR(op, op_val, 74, 6)
          #scalar register
          cmd.specval |= ((v_flags >> 2) & 0x0F)
          #size
          cmd.specval |= ((cmd_val & 0x0300) << 13)
          #coordinates
          x_lookup = [ 0, 16, 32, 48, 0, 32, 0, 0 ]
          x_coord = x_lookup[self.BITFIELD(cmd_val, 7, 3)]
          y_coord = 0
          if tmptype == self.o_vrfa80:
            y_coord = cmd_val & 0x003f
            x_coord |= self.XBITFIELDLINEAR(op, op_val, 60, 4)
          elif is_vert:
            y_coord = cmd_val & 0x0030
            x_coord |= (cmd_val & 0x000f)
          else:
            y_coord = cmd_val & 0x003f
          cmd.specval |= (x_coord << 12)
          cmd.specval |= (y_coord << 6)
          #Increment
          inc_flag = ((v_flags >> 1) & 0x01)
          if is_vert:
            cmd.specval |= (inc_flag << 5)
          else:
            cmd.specval |= (inc_flag << 4)

      #Vector Flags specval:
      #REP:13-11 ACCSCLR:10-4 IFxx:3-1 SETF:0
#1111 11 X v:6 r:3 d:10 a:10 F 0 b:10 f_d:6 f_a:6 Ra_x:4 P:3 f_i:7 f_b:6
#1111 11 X v:6 r:3 d:10 a:10 F 1 k:10 f_d:6 f_a:6 Ra_x:4 P:3 f_i:7 j:6
      elif cmd.type == self.o_vflags80:
        cmd.type = self.o_vflags
        #SETF
        cmd.specval = self.XBITFIELDLINEAR(op, op_val, 36, 1)
        #IFxx
        cmd.specval |= (self.XBITFIELDLINEAR(op, op_val, 64, 3) << 1)
        #ACCSCLR
        cmd.specval |= (self.XBITFIELDLINEAR(op, op_val, 67, 7) << 4)
        #REP
        cmd.specval |= (self.XBITFIELDLINEAR(op, op_val, 13, 3) << 11)

#1111 10 mop:5 width:2 r:3 1110 rd:6 a:10 F 0 111 l:7 f_d:6 f_a:6 Ra_x:4 P:3 i:7 rs:4 i:2
#1111 10 mop:5 width:2 r:3 d:10 1110 ra:6 F 0 111 l:7 f_d:6 f_a:6 Ra_x:4 P:3 i:7 rs:4 i:2
#1111 10 mop:5 width:2 r:3 d:10 a:10 F 0 b:10 f_d:6 f_a:6 Ra_x:4 P:3 f_i:7 f_b:6
#1111 10 mop:5 width:2 r:3 d:10 a:10 F 1 l:10 f_d:6 f_a:6 Ra_x:4 P:3 f_i:7 j:6
      elif cmd.type == self.o_vecmemdst or cmd.type == self.o_vecmemsrc:
        tmptype = cmd.type
        cmd.type = o_displ
        cmd.dtyp = dt_dword
        cmd.addr = (self.SXBITFIELDLINEAR(op, op_val, 78, 2) << 7) | self.XBITFIELDLINEAR(op, op_val, 41, 7)
        cmd.phrase = self.XBITFIELDLINEAR(op, op_val, 74, 4)
        cmd.specval = 0
        increg = 0
        if tmptype == self.o_vecmemdst:
          increg = self.XBITFIELDLINEAR(op, op_val, 48, 4)
        else:
          increg = self.XBITFIELDLINEAR(op, op_val, 54, 4)
        if increg < 15:
          cmd.specval = self.DISPL_INCREG | increg


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

    wstr = [ "8", "16", "32", "" ]
    for insn in self.ISAV48MEM:
      for w in range(0,4):
        insnmnem = insn[0]
        insnbitpattern = insn[1][:]
        insnbitpattern[0] |= (w << 3)
        xinsn = [ insnmnem.replace("WW", wstr[w]), insnbitpattern, insn[2], insn[3], insn[4] ]
        self.ISAVEC48 += [ xinsn ]

    for insn in self.ISAV80MEM:
      for w in range(0,4):
        insnmnem = insn[0]
        insnbitpattern = insn[1][:]
        insnbitpattern[0] |= (w << 3)
        xinsn = [ insnmnem.replace("WW", wstr[w]), insnbitpattern, insn[2], insn[3], insn[4] ]
        self.ISAVEC80 += [ xinsn ]

    pstr = [ "mov", "mask", "even", "odd", "altl", "altu", "brev", "ror", "shl", "asls", "lsr", "asr", "sshl", "op13", "sasl", "sasls",
             "and", "or", "eor", "bic", "popcnt", "msb", "op22", "op23", "min", "max", "dist", "dists", "clamp", "sgn", "op30", "cmpge",
             "add", "adds", "addc", "addsc", "sub", "subs", "subc", "subsc", "rsub", "rsubs", "rsubc", "rsubsc", "op44", "op45", "op46", "op47",
             "mull.ss", "mulls.ss", "mulmd.ss", "mulmds.ss", "mulhd.ss", "mulhd.su", "mulhd.us", "mulhd.uu",
             "mulhdr.ss", "mulhdr.su", "mulhdr.us", "mulhdr.uu", "mulhdt.ss", "mulhdt.su", "op62", "op63" ]
    for insn in self.ISAV48DAT:
      for p in range(0,64):
        insnmnem = insn[0]
        insnbitpattern = insn[1][:]
        insnbitpattern[0] |= (p << 3)
        xinsn = [ insnmnem.replace("PP", pstr[p]), insnbitpattern, insn[2], insn[3], insn[4] ]
        self.ISAVEC48 += [ xinsn ]

    for insn in self.ISAV80DAT:
      for p in range(0,64):
        insnmnem = insn[0]
        insnbitpattern = insn[1][:]
        insnbitpattern[0] |= (p << 3)
        xinsn = [ insnmnem.replace("PP", pstr[p]), insnbitpattern, insn[2], insn[3], insn[4] ]
        self.ISAVEC80 += [ xinsn ]


    self.ISA16 += [ [ "UNK16", [0] * 1, [0] * 1, 0, [] ] ]
    self.ISA32 += [ [ "UNK32", [0] * 2, [0] * 2, 0, [] ] ]
    self.ISA48 += [ [ "UNK48", [0xe000, 0x0000, 0x0000], [0xf000, 0x0000, 0x0000], 0, [] ] ]
    self.ISAVEC48 += [ [ "UNKVEC48", [0xf000, 0x0000, 0x0000], [0xf000, 0x0000, 0x0000], 0, [] ] ]
    self.ISAVEC80 += [ [ "UNKVEC80", [0] * 5, [0] * 5, 0, [] ] ]
    self.ISA = self.ISA16 + self.ISA32 + self.ISA48 + self.ISAVEC48 + self.ISAVEC80
    # print self.ISA
    for insn in self.ISA:
      mnem, patt, mask, fl, args = insn
      self.instruc.append( { 'name': mnem, 'feature': fl } )
      i += 1
    return i

  def __init__(self):
    print "__init__"
    idaapi.processor_t.__init__(self)
    self.regNames = [ "r%d" % d for d in range(0, 24) ] + [ "bs", "sp", "lr", "r27", "xs", "r29", "sr", "pc" ]
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
