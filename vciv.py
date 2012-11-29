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

  ISA = [
    ["halt", [0x0000], [0xffff], CF_STOP, []],
    ["nop", [0x0001], [0xffff], 0, []],
    ["b", [0x0040], [0xffe0], CF_JUMP | CF_USE1, [[0,5,o_reg]]],
    ["bl", [0x0060], [0xffe0], CF_CALL | CF_USE1, [[0,5,o_reg]]],
  ]

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
    v |= vciv_processor_t.BITFIELD(wordarray[start>>4], start, width)
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

  def handle_operand(self, op, isread):
    print "handle_operand"
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
    flags = self.cmd.get_canon_feature()

    if flags & CF_USE1:
      self.handle_operand(self.cmd.Op1, 0)
    if flags & CF_CHG1:
      self.handle_operand(self.cmd.Op1, 1)

    if !(flags & CF_STOP):
      ua_add_cref(0, self.cmd.get_ea() + self.cmd.get_size(), fl_F)

    print "emu"
    return 1

  def outop(self, op):
    print "outop"
    if op.type == o_reg:
      out_register(self.regNames[op.reg])
    elif op.type == o_imm:
      OutValue(0x1332, OOFW_IMM | OOFW_32)
    return True

  def out(self):
    print "out"
    buf = idaapi.init_output_buffer(32)
    OutMnem()
    out_one_operand(0)
    term_output_buffer()
    MakeLine(buf)
    return

  def simplify(self):
    print "simplify"
    return

  def ana(self):
    print "ana"
    op0 = ua_next_word()
    oplenbits = self.BITFIELD(op0, 0, 8)

    op = [ op0 ]

    if oplenbits < 0x80:
      self.cmd.size = 2
    else:
      op += [ ua_next_word() ]
      if oplenbits < 0xe0:
        self.cmd.size = 4
      else:
        op += [ ua_next_word() ]
        if oplenbits < 0xfa:
          self.cmd.size = 6
        else:
          op += [ ua_next_word() ]
          op += [ ua_next_word() ]
          self.cmd.size = 10

    self.cmd.itype = self.find_insn(op)
    print "Parsed OP %x to INSN #%d" % ( op0, self.cmd.itype )
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
      boff, bsize, cmd.type = arg
      if cmd.type == o_reg:
        cmd.reg = self.XBITFIELD(op, boff, bsize)

  def notify_init(self, idp):
    print "notify_init"
    idaapi.cvar.inf.mf = 1
    return 1

  def find_insn(self, op):
    # print "Searching pattern, OP0 is %d, length %d." % ( op[0], len(op) )
    i = 0
    for insn in self.ISA:
      mnem, patt, mask, fl, args = insn
      if len(mask) == len(op):
        opmasked = [ (op[j] & mask[j]) for j in range(len(op)) ]
        if opmasked == patt:
          # print "Found at %d. (OP/MASK/PATT %d/%d/%d)" % (i, op[0], mask[0], patt[0])
          return i
      i += 1
    return self.instruc_end

  def init_isa(self):
    self.instruc = [ ]
    i = 0
    for insn in self.ISA:
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
