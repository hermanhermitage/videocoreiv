//-------------------------------------------------------------------------
// Assembly Tools
//
// This section contains macros/functions to provide simple assembler
// style functionality.  Main is executed to generate a VideoCore IV
// executable image to replace bootcode.bin.
//
//-------------------------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>

static void assemble(void);

static unsigned int __pc__, __resized__, __pass__;
static FILE *       __target__;
static char *       __target_filename__ = "a.bin";

static int quit(char *message, int exitcode) {
  puts(message); exit((unsigned)exitcode); return 0;
}

int main(int argc, char *argv) {
  for(;;) {
    __pc__ = __resized__ = 0;
    assemble();
    __target__ && fclose(__target__) && quit("Assembly Failed: target file failed to close.", 1);
    __target__ && __resized__ && quit("Assembly Failed: binary changed sized during output pass.", 1);
    __target__ && quit("Assembly Succeeded.", 0);
    __resized__ && printf("Pass %d completed, but another pass is required.\n", ++__pass__);
    if (!__resized__) { 
      printf("Pass %d completed, starting output pass.\n", ++__pass__);
      __target__ = fopen(__target_filename__, "wb");
    }
  }
}

// Target generation
/*
#define emitb(x)     do { if(__target__) fputc(x, __target__); __pc__++; } while(0)
#define align(x)     do { for (; __pc__ % x ; ) emitb(0); } while(0)
#define emith(x)     do { align(2); unsigned _ = x; emitb(_&0xff); emitb((_>>8)&0xff); }  while(0)
#define emit(x)      do { align(4); unsigned _ = x; emitb(_&0xff); emitb((_>>8)&0xff); emitb((_>>16)&0xff); emitb((_>>24)&0xff); }  while(0)

#define emit1(x)     emith(x)
#define emit2(x,y)   do { emit1(x); emit1(y); } while(0)
#define emit3(x,y,z) do { emit1(x); emit1(y); emit1(z); } while(0)

#define fillb(size, value) do { int i; for(i=0; i<size; i+=2) emit1(value|(value<<8)); } while(0) 

#define dcb(x)  emitb(x)
#define dch(x)  emit1(x)
#define dc(x)   emit(x)
#define dcf(x)  do { float f = (x); emit(*(unsigned int *)&f) } while 

#define string(x)    do { char string[] = x; int i; for(i=0; i<sizeof string; i++) emitb(string[i]); } while(0)
*/
typedef unsigned int u32;

void emitb(u32 x)     { if(__target__) fputc(x, __target__); __pc__++; } 
void align(u32 x)     { for (; __pc__ % x ; ) emitb(0); }
void emith(u32 x)     { align(2); unsigned _ = x; emitb(_&0xff); emitb((_>>8)&0xff); }
void emit(u32 x)      { align(4); unsigned _ = x; emitb(_&0xff); emitb((_>>8)&0xff); emitb((_>>16)&0xff); emitb((_>>24)&0xff); }

void emit1(u32 x)     { emith(x); }
void emit2(u32 x, u32 y)   { emit1(x); emit1(y); } 
void emit3(u32 x, u32 y, u32 z) { emit1(x); emit1(z); emit1(y); } 

void fillb(u32 size, u32 value)  { int i; for(i=0; i<size; i+=2) emit1(value|(value<<8)); }  

void dcb(u32 x)  { emitb(x); }
void dch(u32 x)  { emit1(x); }
void dc(u32 x)   { emit(x); }
void dcf(float x)  { float f = (x); emit(*(unsigned int *)&f); } 

#define string(x)    do { char string[] = x; int i; for(i=0; i<sizeof string; i++) emitb(string[i]); } while(0)

// Directives
#define equ(name, value)  unsigned int name = value
#define declare(name)     static int name
#define global(name)      declare(name)
#define static(name)      declare(name)

#define label(name)       do { __resized__ |= (name != __pc__); name = __pc__; } while(0)

// Sections


// Registers
const int r0 = 0, r1 = 1, r2 = 2, r3 = 3, r4 = 4, r5 = 5, r6 = 6, r7 = 7,
    r8 = 8, r9 = 9, r10 = 10, r11 = 11, r12 = 12, r13 = 13, r14 = 14, r15 = 15,
    r16 = 16, r17 = 17, r18 = 18, r19 = 19, r20 = 20, r21 = 21, r22 = 22, r23 = 23,
    r24 = 24, r25 = 25, r26 = 26, r27 = 27, r28 = 28, r29 = 29, r30 = 30, r31 = 31;
const int cb = 24, sp = 25, lr = 26, sr = 30, pc = 31;

// Instructions

#include "videocoreiv.h"

//#define pcrel(label)  (((label)-__pc__)/2)
int pcrel(unsigned int target) {
  return (target > __pc__ ? target-__pc__ : -(__pc__-target));
}

// Generic forms

#define bl_o(x) bl_o27(x)

void bc_o(enum table_c c,  unsigned int target) {
  int offset = pcrel(target)/2;
  if (offset>=-64 && offset<=63)
    bc_o7(c, offset);
  else
    bc_o23(c, offset);
}

void op(int op, int rd, int rs) {
  if ((rd>=0) && (rd<16) && (rs>=0) && (rs<16)) {
    p_rd_rs(op, rd, rs);
  }
  else if ((rd>=0) && (rd<32) && (rs>=0) && (rs<32)) {
    p_c_rd_ra_rb(op, c_, rd, rd, rs);
  }
  else {
    quit("Invalid register to register operation", 1);
  }
}

void opi(int op, int d, int u) {
  if (((op&1)==0) && (u>=0) && (u<32)) {
    q_rd_u(op>>1, d, u);
  }
  else if ((u>=-32767) && (u<=32768)) {
    p_rd_i(op, d, u);
  }
  else {
    p_rd_u(op, d, u);
  }
}


void lea_rd_o_rs(int rd, int o, int rs) {
  if ((rs==sp) && ((o&3)==0) && (o>=-32*4) && (o<32*4)) {
    lea_rd_o6_sp(rd, o/4);
  }
  else if ((rs==pc) && (o>=-32768) && (o<32768)) {
    lea_rd_o16_pc(rd, o);
  }
  else if ((o>=-32768) && (o<32768)) {
    lea_rd_i_rs(rd, o, rs);
  }
  else if ((rs==pc)) {
    lea_rd_o32_pc(rd, o);
  }
  else {
    quit("Invalid lea operation", 1);
  }
}

void lea_rd_o_pc(int rd, int offset) {
  if (offset>=-32768 && offset<=32767)
    lea_rd_o16_pc(rd, offset);
  else 
    lea_rd_o32_pc(rd, offset);
}

void lea_rd_u(int rd, unsigned int u) {
  int o = pcrel(u);
  lea_rd_o_pc(rd, o);
}


void ld_w_rd_o_rs(enum table_w w, int rd, int o, int rs) {
  if ((w==w_) && (rs==sp) && ((o&3)==0) && (o>=-16*4) && (o<=15*4)) {
    ld_rd_o5_sp(rd, o/4);
  }
  else if ((rs>=r0) && (rs<=r15) && (rd>=r0) && (rd<=r15) && (o==0)) {
    ld_w_rd_rs(w, rd, rs);
  }
  else if ((w==w_) && (rs>=r0) && (rs<=r15) && (rd>=r0) && (rd<=r15) && ((o&3)==0) && (o>=0) && (o<=15*4)) {
    ld_rd_u_rs(rd, o/4, rs);
  }
  else if ((rs==r24) && (o>=-32768) && (o<=32767)) {
    ld_w_rd_o16_r24(w, rd, o);
  }
  else if ((rs==sp) && (o>=-32768) && (o<=32767)) {
    ld_w_rd_o16_sp(w, rd, o);
  }
  else if ((rs==pc) && (o>=-32768) && (o<=32767)) {
    ld_w_rd_o16_pc(w, rd, o);
  }
  else if ((rs==r0) && (o>=-32768) && (o<=32767)) {
    ld_w_rd_o16_r0(w, rd, o);
  }
  else if ((o>=-1024) && (o<=1023)) {
    ld_w_rd_o12_rs(w, rd, o, rs);
  }
  else if ((o>=-(1<<26)) && (o<(1<<26)) && (rs==pc)) {
    ld_w_rd_o27_pc(w, rd, o);
  }
  else if ((o>=-(1<<26)) && (o<(1<<26))) {
    ld_w_rd_o27_rs(w, rd, o, rs);
  }
  else {
    quit("Invalid offset in ld_w_rd_o_rs operation", 1);
  }
}

void st_w_rd_o_rs(enum table_w w, int rd, int o, int rs) {
  if ((w==w_) && (rs==sp) && ((o&3)==0) && (o>=-16*4) && (o<=15*4)) {
    st_rd_o5_sp(rd, o/4);
  }
  else if ((rs>=r0) && (rs<=r15) && (rd>=r0) && (rd<=r15) && (o==0)) {
    st_w_rd_rs(w, rd, rs);
  }
  else if ((w==w_) && (rs>=r0) && (rs<=r15) && (rd>=r0) && (rd<=r15) && ((o&3)==0) && (o>=0) && (o<=15*4)) {
    st_rd_u_rs(rd, o/4, rs);
  }
  else if ((rs==r24) && (o>=-32768) && (o<=32767)) {
    st_w_rd_o16_r24(w, rd, o);
  }
  else if ((rs==sp) && (o>=-32768) && (o<=32767)) {
    st_w_rd_o16_sp(w, rd, o);
  }
  else if ((rs==pc) && (o>=-32768) && (o<=32767)) {
    st_w_rd_o16_pc(w, rd, o);
  }
  else if ((rs==r0) && (o>=-32768) && (o<=32767)) {
    st_w_rd_o16_r0(w, rd, o);
  }
  else if ((o>=-1024) && (o<=1023)) {
    st_w_rd_o12_rs(w, rd, o, rs);
  }
  else if ((o>=-(1<<26)) && (o<(1<<26)) && (rs==pc)) {
    st_w_rd_o27_pc(w, rd, o);
  }
  else if ((o>=-(1<<26)) && (o<(1<<26))) {
    st_w_rd_o27_rs(w, rd, o, rs);
  }
  else {
    quit("Invalid offset in st_w_rd_o_rs operation", 1);
  }
}

void ld_w_rd_u(enum table_w w, int rd, unsigned int target) {
  int o = pcrel(target);
  ld_w_rd_o_rs(w, rd, o, pc);
}

void st_w_rd_u(enum table_w w, int rd, unsigned int target) {
  int o = pcrel(target);
  st_w_rd_o_rs(w, rd, o, pc);
}

#define ld_rd_rs(reg1, reg2)   ld_rd_u_rs(reg1, 0, reg2)
#define ldb_rd_rs(reg1, reg2)  ld_w_rd_rs(w_b, reg1, reg2)
#define ldh_rd_rs(reg1, reg2)  ld_w_rd_rs(w_h, reg1, reg2)
#define ldsh_rd_rs(reg1, reg2) ld_w_rd_rs(w_sh, reg1, reg2)

#define st_rd_rs(reg1, reg2)  st_rd_u_rs(reg1, 0, reg2)
#define stb_rd_rs(reg1, reg2) st_w_rd_rs(w_b, reg1, reg2)
#define sth_rd_rs(reg1, reg2) st_w_rd_rs(w_h, reg1, reg2)

#define ldb_rd_u(rd, u) ld_w_rd_u(w_b, rd, u)
#define ldh_rd_u(rd, u) ld_w_rd_u(w_h, rd, u)
#define ld_rd_u(rd, u) ld_w_rd_u(w_, rd, u)
#define ldsh_rd_u(rd, u) ld_w_rd_u(w_sh, rd, u)

#define stb_rd_u(rd, u) st_w_rd_u(w_b, rd, u)
#define sth_rd_u(rd, u) st_w_rd_u(w_h, rd, u)
#define st_rd_u(rd, u) st_w_rd_u(w_, rd, u)

#define ldb_rd_o_rs(rd, o, rs) ld_w_rd_o_rs(w_b, rd, o, rs)
#define ldh_rd_o_rs(rd, o, rs) ld_w_rd_o_rs(w_h, rd, o, rs)
#define ld_rd_o_rs(rd, o, rs) ld_w_rd_o_rs(w_, rd, o, rs)
#define ldsh_rd_o_rs(rd, o, rs) ld_w_rd_o_rs(w_sh, rd, o, rs)

#define stb_rd_o_rs(rd, o, rs) st_w_rd_o_rs(w_b, rd, o, rs)
#define sth_rd_o_rs(rd, o, rs) st_w_rd_o_rs(w_h, rd, o, rs)
#define st_rd_o_rs(rd, o, rs) st_w_rd_o_rs(w_, rd, o, rs)

#define ld_w_rd_dec_rs(w, rd, rs) ld_w_c_rd_dec_rs(w, c_, rd, rs)
#define st_w_rd_dec_rs(w, rd, rs) st_w_c_rd_dec_rs(w, c_, rd, rs)
#define ld_w_rd_rs_inc(w, rd, rs) ld_w_c_rd_rs_inc(w, c_, rd, rs)
#define st_w_rd_rs_inc(w, rd, rs) st_w_c_rd_rs_inc(w, c_, rd, rs)

#define ldb_rd_dec_rs(rd, rs) ld_w_rd_dec_rs(w_b, rd, rs)
#define ldh_rd_dec_rs(rd, rs) ld_w_rd_dec_rs(w_h, rd, rs)
#define ld_rd_dec_rs(rd, rs) ld_w_rd_dec_rs(w_, rd, rs)
#define ldsh_rd_dec_rs(rd, rs) ld_w_rd_dec_rs(w_sh, rd, rs)

#define ldb_rd_rs_inc(rd, rs) ld_w_rd_rs_inc(w_b, rd, rs)
#define ldh_rd_rs_inc(rd, rs) ld_w_rd_rs_inc(w_h, rd, rs)
#define ld_rd_rs_inc(rd, rs) ld_w_rd_rs_inc(w_, rd, rs)
#define ldsh_rd_rs_inc(rd, rs) ld_w_rd_rs_inc(w_sh, rd, rs)

#define stb_rd_dec_rs(rd, rs) st_w_rd_dec_rs(w_b, rd, rs)
#define sth_rd_dec_rs(rd, rs) st_w_rd_dec_rs(w_h, rd, rs)
#define st_rd_dec_rs(rd, rs) st_w_rd_dec_rs(w_, rd, rs)
#define stsh_rd_dec_rs(rd, rs) st_w_rd_dec_rs(w_sh, rd, rs)

#define stb_rd_rs_inc(rd, rs) st_w_rd_rs_inc(w_b, rd, rs)
#define sth_rd_rs_inc(rd, rs) st_w_rd_rs_inc(w_h, rd, rs)
#define st_rd_rs_inc(rd, rs) st_w_rd_rs_inc(w_, rd, rs)
#define stsh_rd_rs_inc(rd, rs) st_w_rd_rs_inc(w_sh, rd, rs)

// arithmetic/logical register to register

#define mov(reg, reg2)      op(p_mov, reg, reg2)
#define cmn(reg, reg2)      op(p_cmn, reg, reg2)
#define add(reg, reg2)      op(p_add, reg, reg2)
#define bic(reg, reg2)      op(p_bic, reg, reg2)

#define mul(reg, reg2)      op(p_mul, reg, reg2)
#define eor(reg, reg2)      op(p_eor, reg, reg2)
#define sub(reg, reg2)      op(p_sub, reg, reg2)
#define and(reg, reg2)      op(p_and, reg, reg2)

#define mvn(reg, reg2)      op(p_mvn, reg, reg2)
#define ror(reg, reg2)      op(p_ror, reg, reg2)
#define cmp(reg, reg2)      op(p_cmp, reg, reg2)
#define rsb(reg, reg2)      op(p_rsb, reg, reg2)

#define btst(reg, reg2)     op(p_btst, reg, reg2)
#define or(reg, reg2)       op(p_or, reg, reg2)
#define extu(reg, reg2)     op(p_extu, reg, reg2)
#define max(reg, reg2)      op(p_max, reg, reg2)

#define bset(reg, reg2)     op(p_bset, reg, reg2)
#define min(reg, reg2)      op(p_min, reg, reg2)
#define bclr(reg, reg2)     op(p_bclr, reg, reg2)
#define adds2(reg, reg2)    op(p_adds2, reg, reg2)

#define bchg(reg, reg2)     op(p_bchg, reg, reg2)
#define adds4(reg, reg2)    op(p_adds4, reg, reg2)
#define adds8(reg, reg2)    op(p_adds8, reg, reg2)
#define adds16(reg, reg2)   op(p_adds16, reg, reg2)

#define exts(reg, reg2)     op(p_exts, reg, reg2)
#define neg(reg, reg2)      op(p_neg, reg, reg2)
#define lsr(reg, reg2)      op(p_lsr, reg, reg2)
#define clz(reg, reg2)      op(p_clz, reg, reg2)

#define lsl(reg, reg2)      op(p_lsl, reg, reg2)
#define brev(reg, reg2)     op(p_brev, reg, reg2)
#define asr(reg, reg2)      op(p_asr, reg, reg2)
#define abs(reg, reg2)      op(p_abs, reg, reg2)

#define divs(rd, ra, rb)    divs_c_rd_ra_rb(c_, rd, ra, rb)

// arithmetic/logical with immediate

#define movi(reg, imm)      opi(p_mov, reg, imm)
#define cmni(reg, imm)      opi(p_cmn, reg, imm)
#define addi(reg, imm)      opi(p_add, reg, imm)
#define bici(reg, imm)      opi(p_bic, reg, imm)

#define muli(reg, imm)      opi(p_mul, reg, imm)
#define eori(reg, imm)      opi(p_eor, reg, imm)
#define subi(reg, imm)      opi(p_sub, reg, imm)
#define andi(reg, imm)      opi(p_and, reg, imm)

#define mvni(reg, imm)      opi(p_mvn, reg, imm)
#define rori(reg, imm)      opi(p_ror, reg, imm)
#define cmpi(reg, imm)      opi(p_cmp, reg, imm)
#define rsbi(reg, imm)      opi(p_rsb, reg, imm)

#define btsti(reg, imm)     opi(p_btst, reg, imm)
#define ori(reg, imm)       opi(p_or, reg, imm)
#define extui(reg, imm)     opi(p_extu, reg, imm)
#define maxi(reg, imm)      opi(p_max, reg, imm)

#define bseti(reg, imm)     opi(p_bset, reg, imm)
#define mini(reg, imm)      opi(p_min, reg, imm)
#define bclri(reg, imm)     opi(p_bclr, reg, imm)
#define adds2i(reg, imm)    opi(p_adds2, reg, imm)

#define bchgi(reg, imm)     opi(p_bchg, reg, imm)
#define adds4i(reg, imm)    opi(p_adds4, reg, imm)
#define adds8i(reg, imm)    opi(p_adds8, reg, imm)
#define adds16i(reg, imm)   opi(p_adds16, reg, imm)

#define extsi(reg, imm)     opi(p_exts, reg, imm)
#define negi(reg, imm)      opi(p_neg, reg, imm)
#define lsri(reg, imm)      opi(p_lsr, reg, imm)
#define clzi(reg, imm)      opi(p_clz, reg, imm)

#define lsli(reg, imm)      opi(p_lsl, reg, imm)
#define brevi(reg, imm)     opi(p_brev, reg, imm)
#define asri(reg, imm)      opi(p_asr, reg, imm)
#define absi(reg, imm)      opi(p_abs, reg, imm)


// Unconditional branches

#define beq(label)          bc_o(c_eq, label)
#define bne(label)          bc_o(c_ne, label)
#define bcs(label)          bc_o(c_cs, label)
#define blo(label)          bc_o(c_lo, label)
#define bcc(label)          bc_o(c_cc, label)
#define bhs(label)          bc_o(c_hs, label)

#define bmi(label)          bc_o(c_mi, label)
#define bpl(label)          bc_o(c_pl, label)
#define bvs(label)          bc_o(c_vs, label)
#define bvc(label)          bc_o(c_vc, label)

#define bhi(label)          bc_o(c_hi, label)
#define bls(label)          bc_o(c_ls, label)
#define bge(label)          bc_o(c_ge, label)
#define blt(label)          bc_o(c_lt, label)

#define bgt(label)          bc_o(c_gt, label)
#define ble(label)          bc_o(c_le, label)
#define bra(label)          bc_o(c_, label)
#define bf(label)           bc_o(c_f, label)

#define b(label)            bc_o(c_, label)

// Load/Store
 
#define ld(reg1, reg2)      ld_rd_u_rs(reg1, 0, reg2)
#define st(reg1, reg2)      st_rd_u_rs(reg1, 0, reg2)

#define ldb(reg1, reg2)     ld_w_rd_rs(w_b, reg1, reg2)
#define stb(reg1, reg2)     st_w_rd_rs(w_b, reg1, reg2)

#define st_off(reg1, off, reg2) st_rd_u_rs(reg1, off/4, reg2)

#define ldq(reg1, reg2)     ld_w_rd_rs(0, reg1, reg2)
#define ldqw(w, reg1, reg2) ld_w_rd_rs(w, reg1, reg2)


// 32 bit instructions
#define bl(label)           bl_o(pcrel(label)/2)

#define lea(reg, label)     lea_rd_o_pc(reg, pcrel(label))

#define movsp(reg)          p_c_rd_ra_rb(p_mov, c_, reg, 0, sp)
#define movs(reg, regs)     p_c_rd_ra_rb(p_mov, c_, reg, 0, regs)

// 48 bit instructions


// Compatibility
#define cpuid(reg) emit1(0x00e0|(reg))
#define shri(ra, imm)       emit1(0x7a00|(ra)|(((imm)&0x1f)<<4))
#define shli(ra, imm)       emit1(0x7c00|(ra)|(((imm)&0x1f)<<4))

#define START(filename) void assemble(void) { __target_filename__ = filename;
#define END   }

