/* Target-dependent code for the Z80.

   Copyright (C) 1986-2020 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include "defs.h"
#include "arch-utils.h"
#include "dis-asm.h"
#include "frame.h"
#include "frame-unwind.h"
#include "frame-base.h"
#include "trad-frame.h"
#include "gdbcmd.h"
#include "gdbcore.h"
#include "gdbtypes.h"
#include "inferior.h"
#include "objfiles.h"
#include "symfile.h"

#include "z80-tdep.h"

/* You need to define __gdb_break_handler symbol pointing to the breakpoint
   handler. Value of the symbol will be used to determine instruction for
   software breakpoint. If __gdb_break_handler points to one of standard RST
   addresses (0x00, 0x08, 0x10,... 0x38) then RST __gdb_break_handler
   instruction will be used, else CALL __gdb_break_handler
;breakpoint handler
	.globl	__gdb_break_handler
	.org	8
__gdb_break_handler:
	jp	_debug_swbreak
*/

/* meaning of terms "previous" and "next":
   previous frame - frame of callee, which is called by current function
   current frame - frame of current function which has called callee
   next frame - frame of caller, which has called current function
*/

struct gdbarch_tdep
{
  /* Number of bytes used for address:
      2 bytes for all Z80 family
      3 bytes for eZ80 CPUs operating in ADL mode */
  int addr_length;

  /* Type for void.  */
  struct type *void_type;
  /* Type for a function returning void.  */
  struct type *func_void_type;
  /* Type for a pointer to a function.  Used for the type of PC.  */
  struct type *pc_type;
};

/* At any time stack frame contains following parts:
   [<current PC>]
   [<temporaries, y bytes>]
   [<local variables, x bytes>
   <next frame FP>]
   [<saved state (critical or interrupt functions), 2 or 10 bytes>]
   In simplest case <next PC> is pointer to the call instruction
   (or call __call_hl). There are more difficult cases: interrupt handler or
   push/ret and jp; but they are untrackable.
*/

struct z80_unwind_cache
{
  /* The previous frame's inner most stack address (SP after call executed),
     it is current frame's frame_id */
  CORE_ADDR prev_sp;

  /* Size of the frame, prev_sp + size = next_frame.prev_sp */
  ULONGEST size;

  /* size of saved state (including frame pointer and return address),
     assume: prev_sp + size = IX + state_size */
  ULONGEST state_size; 

  struct {
    int called:1;	/* there is return address on stack */
    int load_args:1;	/* prologues loads args using POPs */
    int fp_sdcc:1;	/* prologue saves and adjusts frame pointer IX */
    int interrupt:1;	/* __interrupt handler */
    int critical:1;	/* __critical function */
  } prologue_type;
  /* Table indicating the location of each and every register.  */
  struct trad_frame_saved_reg *saved_regs;
};

/* Constants */

extern 
initialize_file_ftype _initialize_z80_tdep;

/* Return the name of register REGNUM.  */
static const char *
z80_register_name (struct gdbarch *gdbarch, int regnum)
{
  static const char *register_names[] =
  {
    /* 24 bit on eZ80, else 16 bit */
    "af", "bc", "de", "hl", "ix", "iy", "sp", "pc",
    "ir", "mbst", "af_", "bc_", "de_", "hl_",
    /* eZ80 only */
    "sps", "spl"
  };

  if (regnum >= 0 && regnum < ARRAY_SIZE (register_names))
    return register_names[regnum];

  return NULL;
}

/* Return the type of a register specified by the architecture.  Only
   the register cache should call this function directly; others should
   use "register_type". */
static struct type *
z80_register_type (struct gdbarch *gdbarch, int reg_nr)
{
  return builtin_type (gdbarch)->builtin_data_ptr;
}

/* next 2 functions check buffer for instruction. If it is pop/push rr, then it
   returns register number:
     0x10 - BC
     0x11 - DE
     0x12 - HL
     0x13 - AF
     0x22 - IX
     0x32 - IY */
static int
z80_is_pop_rr (const gdb_byte buf[], int *size)
{
  switch (buf[0])
    {
    case 0xc1:
      *size = 1;
      return Z80_BC_REGNUM | 0x100;
    case 0xd1:
      *size = 1;
      return Z80_DE_REGNUM | 0x100;
    case 0xe1:
      *size = 1;
      return Z80_HL_REGNUM | 0x100;
    case 0xf1:
      *size = 1;
      return Z80_AF_REGNUM | 0x100;
    case 0xdd:
      *size = 2;
      return (buf[1] == 0xe1) ? (Z80_IX_REGNUM | 0x100) : 0;
    case 0xfd:
      *size = 2;
      return (buf[1] == 0xe1) ? (Z80_IY_REGNUM | 0x100) : 0;
    }
  *size = 0;
  return 0;
}

static int
z80_is_push_rr (const gdb_byte buf[], int *size)
{
  switch (buf[0])
    {
    case 0xc5:
      *size = 1;
      return Z80_BC_REGNUM | 0x100;
    case 0xd5:
      *size = 1;
      return Z80_DE_REGNUM | 0x100;
    case 0xe5:
      *size = 1;
      return Z80_HL_REGNUM | 0x100;
    case 0xf5:
      *size = 1;
      return Z80_AF_REGNUM | 0x100;
    case 0xdd:
      *size = 2;
      return (buf[1] == 0xe5) ? (Z80_IX_REGNUM | 0x100) : 0;
    case 0xfd:
      *size = 2;
      return (buf[1] == 0xe5) ? (Z80_IY_REGNUM | 0x100) : 0;
    }
  *size = 0;
  return 0;
}

/* Function: z80_scan_prologue
        
   This function decodes a function prologue to determine:
     1) the size of the stack frame
     2) which registers are saved on it
     3) the offsets of saved regs
   This information is stored in the z80_unwind_cache structure.
   Small SDCC functions may just load args using POP instructions in prologue:
	pop	af
	pop	de
	pop	hl
	pop	bc
	push	bc
	push	hl
	push	de
	push	af
   SDCC function prologue may have up to 3 sections (all are optional):
     1) save state
       a) __critical functions:
	ld	a,i
	di
	push	af
       b) __interrupt (both int and nmi) functions:
	push	af
	push	bc
	push	de
	push	hl
	push	iy
     2) save and adjust frame pointer
       a) call to special function (size optimization)
	call	___sdcc_enter_ix
       b) inline (speed optimization)
	push	ix
	ld	ix, #0
	add	ix, sp
     3) allocate local variables
       a) via series of PUSH AF and optional DEC SP (size optimization)
	push	af
	...
	push	af
	dec	sp	;optional, if allocated odd numbers of bytes
       b) via SP decrements
	dec	sp
	...
	dec	sp
       c) via addition (for large frames: 5+ for speed and 9+ for size opt.)
	ld	hl, #xxxx	;size of stack frame
	add	hl, sp
	ld	sp, hl
       d) same, but using register IY (arrays or for __z88dk_fastcall functions)
	ld	iy, #xxxx	;size of stack frame
	add	iy, sp
	ld	sp, iy
       e) same as c, but for eZ80
	lea	hl, ix - #nn
	ld	sp, hl
       f) same as d, but for eZ80
	lea	iy, ix - #nn
	ld	sp, iy
*/

static int
z80_scan_prologue (struct gdbarch *gdbarch, CORE_ADDR pc_beg, CORE_ADDR pc_end,
                   struct z80_unwind_cache *info)
{
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  int addr_len = gdbarch_tdep (gdbarch)->addr_length;
  gdb_byte prologue[32]; /* max prologue is 24 bytes: __interrupt with local array */
  int pos = 0;
  int len;
  int reg;
  CORE_ADDR value;

  len = pc_end - pc_beg;
  if (len > (int)sizeof(prologue))
    len = sizeof(prologue);

  read_memory (pc_beg, prologue, len);

  /* stage0: check for series of POPs and then PUSHs */
  if ((reg = z80_is_pop_rr(prologue, &pos)))
    {
      int i;
      int size = pos;
      gdb_byte regs[8]; /* Z80 have only 6 register pairs */
      regs[0] = reg & 0xff;
      for (i = 1; i < 8 && (regs[i] = z80_is_pop_rr (&prologue[pos], &size));
	   ++i, pos += size);
      /* now we expect series of PUSHs in reverse order */
      for (--i; i >= 0 && regs[i] == z80_is_push_rr (&prologue[pos], &size);
	   --i, pos += size);
      if (i == -1 && pos > 0)
	info->prolog_type.load_args = 1;
      else
	pos = 0;
    }
  /* stage1: check for __interrupt handlers and __critical functions */
  else if (!memcmp (&prologue[pos], "\355\127\363\365", 4))
    { /* ld a, i; di; push af */
      info->prologue_type.critical = 1;
      pos += 4;
      info->state_size += addr_len;
    }
  else if (!memcmp (&prologue[pos], "\365\305\325\345\375\345", 6))
    { /* push af; push bc; push de; push hl; push iy */
      info->prologue_type.interrupt = 1;
      pos += 6;
      info->state_size += addr_len * 5;
    }

  /* stage2: check for FP saving scheme */
  if (prologue[pos] == 0xcd) /* call nn */
    {
      struct bound_minimal_symbol msymbol;
      msymbol = lookup_minimal_symbol ("__sdcc_enter_ix", NULL, NULL);
      if (!msymbol.minsym)
        break;
      value = BMSYMBOL_VALUE_ADDRESS (msymbol);
      if (value == extract_unsigned_integer (&prologue[pos+1, addr_len, byte_order))
	{
	  pos += 1 + addr_len;
	  info->prologue_type.fp_sdcc = 1;
	}
    }
  else if (!memcmp (&prologue[pos], "\335\345\335\041\000\000", 4+addr_len) &&
           !memcmp (&prologue[pos+4+addr_len], "\335\071\335\371", 4))
    { /* push ix; ld ix, #0; add ix, sp; ld sp, ix */
      pos += 4 + addr_len + 4;
      info->prologue_type.fp_sdcc = 1;
    }

  /* stage3: check for local variables allocation */
  switch (prologue[pos])
    {
      case 0xf5: /* push af */
	info->size = 0;
	while (prologue[pos] == 0xf5)
	  {
	    info->size += addr_len;
	    pos++;
	  }
	if (prologue[pos] == 0x3b) /* dec sp */
	  {
	    info->size++;
	    pos++;
	  }
	break;
      case 0x3b: /* dec sp */
	info->size = 0;
	while (prologue[pos] == 0x3b)
	  {
	    info->size++;
	    pos++;
	  }
	break;
      case 0x21: /*ld hl, -nn */
	if (prologue[pos+addr_len] == 0x39 && prologue[pos+addr_len] >= 0x80 &&
	    prologue[pos+addr_len+1] == 0xf9)
	  { /* add hl, sp; ld sp, hl */
	    info->size = -extract_signed_integer(&prologue[pos+1], addr_len, byte_order);
	    pos += 1 + addr_len + 2;
	  }
	break;
      case 0xfd: /* ld iy, -nn */
	if (prologue[pos+1] == 0x21 && prologue[pos+1+addr_len] >= 0x80 &&
	    !memcmp (&prologue[pos+2+addr_len], "\375\071\375\371", 4))
	  {
	    info->size = -extract_signed_integer(&prologue[pos+2], addr_len, byte_order);
	    pos += 2 + addr_len + 4;
	  }
	break;
      case 0xed: /* check for lea xx, ix - n */
	switch (prologue[pos+1])
	  {
	  case 0x22: /* lea hl, ix - n */
	    if (prologue[pos+2] >= 0x80 && prologue[pos+3] == 0xf9)
	      { /* ld sp, hl */
		info->size = -extract_signed_integer(&prologue[pos+2], 1, byte_order);
		pos += 4;
	      }
	    break;
	  case 0x55: /* lea iy, ix - n */
	    if (prologue[pos+2] >= 0x80 && prologue[pos+3] == 0xfd &&
		prologue[pos+4] == 0xf9)
	      { /* ld sp, iy */
		info->size = -extract_signed_integer(&prologue[pos+2], 1, byte_order);
		pos += 5;
	      }
	    break;
	  }
	  break;
    }
  len = 0;
  //info->saved_regs[Z80_PC_REGNUM].addr = len++

  if (info->prologue_type.interrupt)
    {
      info->saved_regs[Z80_AF_REGNUM].addr = len++
      info->saved_regs[Z80_BC_REGNUM].addr = len++;
      info->saved_regs[Z80_DE_REGNUM].addr = len++;
      info->saved_regs[Z80_HL_REGNUM].addr = len++;
      info->saved_regs[Z80_IY_REGNUM].addr = len++;
    }

  if (info->prologue_type.critical)
    len++; /* just skip IFF2 saved state */

  if (info->prologue_type.fp_sdcc)
    info->saved_regs[Z80_IX_REGNUM].addr = len++;

  info->state_size += len * addr_len;

  return pc_beg + pos;
}

/* TODO: find description */
static int
z80_skip_prologue (struct gdbarch *gdbarch, CORE_ADDR pc)
{
  CORE_ADDR func_addr, func_end;
  CORE_ADDR prologue_end;

  if (!find_pc_partial_function (pc, NULL, &func_addr, &func_end))
    return pc;

  prologue_end = skip_prologue_using_sal (gdbarch, func_addr);
  if (prologue_end != 0)
    return std::max (pc, prologue_end);

  {
    struct z80_unwind_cache info = {0};
    struct trad_frame_saved_reg saved_regs[Z80_NUM_REGS];

    info.saved_regs = saved_regs;

    /* Need to run the prologue scanner to figure out if the function has a
       prologue.  */

    prologue_end = z80_scan_prologue (gdbarch, func_addr, func_end, &info);

    if (info.prologue_type.fp_sdcc || info.prologue_type.interrupt ||
	info.prologue_type.critical)
      return std::max (pc, prologue_end);
  }

  if (prologue_end != 0)
    {
      struct symtab_and_line prologue_sal = find_pc_line (func_addr, 0);
      struct compunit_symtab *compunit = SYMTAB_COMPUNIT (prologue_sal.symtab);
      const char *debug_format = COMPUNIT_DEBUGFORMAT (compunit);

      if (debug_format != NULL && 
	  !strncasecmp ("dwarf", debug_format, strlen("dwarf")))
	return std::max (pc, prologue_end);
    }

  return pc;
}

/* Return the return-value convention that will be used by FUNCTION
   to return a value of type VALTYPE.  FUNCTION may be NULL in which
   case the return convention is computed based only on VALTYPE.

   If READBUF is not NULL, extract the return value and save it in this buffer.

   If WRITEBUF is not NULL, it contains a return value which will be
   stored into the appropriate register.  This can be used when we want
   to force the value returned by a function (see the "return" command
   for instance). */
static enum return_value_convention
z80_return_value (struct gdbarch *gdbarch, struct value *function,
                  struct type *valtype, struct regcache *regcache,
                  gdb_byte *readbuf, const gdb_byte *writebuf)
{
  /* Byte are returned in L, word in HL, dword in DEHL. */
  int len = TYPE_LENGTH (valtype);

  if ((TYPE_CODE (valtype) == TYPE_CODE_STRUCT
       || TYPE_CODE (valtype) == TYPE_CODE_UNION
       || TYPE_CODE (valtype) == TYPE_CODE_ARRAY)
      && len > 4)
    return RETURN_VALUE_STRUCT_CONVENTION;

  if (writebuf != NULL)
    {
      regcache->cooked_write (R_HL*2 + 0, writebuf + 0);
      if (len > 1)
	{
	  regcache->cooked_write (R_HL*2 + 1, writebuf + 1);
	  if (len > 2)
	    {
	      regcache->cooked_write (R_DE*2 + 0, writebuf + 2);
	      regcache->cooked_write (R_DE*2 + 1, writebuf + 3);
	    }
	}
    }

  if (readbuf != NULL)
    {
      regcache->cooked_read (R_HL*2 + 0, readbuf + 0);
      if (len > 1)
	{
	  regcache->cooked_read (R_HL*2 + 1, readbuf + 1);
	  if (len > 2)
	    {
	      regcache->cooked_read (R_DE*2 + 0, readbuf + 2);
	      regcache->cooked_read (R_DE*2 + 1, readbuf + 3);
	    }
	}
    }

  return RETURN_VALUE_REGISTER_CONVENTION;
}

/* function unwinds current stack frame and returns next one */
static struct z80_unwind_cache *
z80_frame_unwind_cache (struct frame_info *this_frame,
                        void **this_prologue_cache)
{
  CORE_ADDR start_pc, current_pc;
  ULONGEST this_base;
  int i;
  gdb_byte buf[sizeof(void*)];
  struct z80_unwind_cache *info;
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);
  int addr_len = gdbarch_tdep (gdbarch)->addr_length;

  if (*this_prologue_cache)
    return (struct z80_unwind_cache *) *this_prologue_cache;

  info = FRAME_OBSTACK_ZALLOC (struct z80_unwind_cache);
  memset (info, 0, sizeof (*info));
  info->saved_regs = trad_frame_alloc_saved_regs (this_frame);
  *this_prologue_cache = info;

  start_pc = get_frame_func (this_frame);
  current_pc = get_frame_pc (this_frame);
  if ((start_pc > 0) && (start_pc <= current_pc))
    z80_scan_prologue (get_frame_arch (this_frame),
                       start_pc, current_pc, info);

  if (info->prologue_type.fp_sdcc)
    {
      /*  with SDCC standard prologue IX points to the end of current frame
	  (where previous frame pointer and state are saved) */
      this_base = get_frame_register_unsigned (this_frame, Z80_IX_REGNUM);
      info->prev_sp = this_base + info->size;
    }
  else
    {
      CORE_ADDR addr;
      CORE_ADDR sp;
      CORE_ADDR sp_mask = (1 << gdbarch_ptr_bit(gdbarch)) - 1;
      enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
      gbd_byte buf[8];
      /* Assume that the FP is this frame's SP but with that pushed
         stack space added back.  */
      this_base = get_frame_register_unsigned (this_frame, Z80_SP_REGNUM);
      sp = this_base + info->size;
      for (;; ++sp)
	{
	  sp &= sp_mask;
	  if (sp < this_base)
	    { /*overflow, looks like end of stack */
	      sp = this_base + info->size;
	      break;
	    }
	  /* find return address */
	  read_memory (sp, buf, addr_len);
	  addr = extract_unsigned_integer(buf, addr_len, byte_order);
	  read_memory (addr-addr_len-1, buf, addr_len+1);
	  if (buf[0] == 0xcd || (buf[0] & 0307) == 0304) /* Is it CALL */
            { /* CALL nn or CALL cc,nn */
	      static const char *names[] =
		{
		  "__sdcc_call_ix", "__sdcc_call_iy", "__sdcc_call_hl"
		};
	      addr = extract_unsigned_integer(buf+1, addr_len, byte_order);
	      if (addr == start_pc)
		break; /* found */
	      for (i = sizeof(names)/sizeof(*names)-1; i >= 0; --i)
		{
		  struct bound_minimal_symbol msymbol;
		  msymbol = lookup_minimal_symbol (names[i], NULL, NULL);
		  if (!msymbol.minsym)
		    continue;
		  if (addr == BMSYMBOL_VALUE_ADDRESS (msymbol))
		    break;
		}
	      if (i >= 0)
		break;
	      continue;
            }
	  else
	    continue; /* it is not call_nn, call_cc_nn */
	  
	}
      info->prev_sp = sp;
    }

  /* Adjust all the saved registers so that they contain addresses and not
     offsets.  */
  for (i = 0; i < gdbarch_num_regs (gdbarch) - 1; i++)
    if (info->saved_regs[i].addr > 0)
      info->saved_regs[i].addr = info->prev_sp -
			info->saved_regs[i].addr * addr_len;

  /* Except for the startup code, the return PC is always saved on
     the stack and is at the base of the frame.  */
  info->saved_regs[R_PC].addr = info->prev_sp;

  /* The previous frame's SP needed to be computed.  Save the computed
     value.  */
  trad_frame_set_value (info->saved_regs, R_SP,
                        info->prev_sp + addr_len);
}

/* TODO: find description */
static const unsigned char *
z80_breakpoint_from_pc (struct gdbarch *gdbarch, CORE_ADDR * pcptr, int *lenptr)
{
  unsigned char break_insn[5];
  static int break_insn_len = -1;
  if (break_insn_len == -1)
    {
      struct bound_minimal_symbol bh = 
		lookup_minimal_symbol ("__gdb_break_handler", NULL, NULL);
      if (bh.minsym)
	{
	  unsigned char *p = &break_insn[0];
	  CORE_ADDR addr = BMSYMBOL_VALUE_ADDRESS (bh);
	  /* Check __gdb_break_handler address */
	  if ((addr & 070) == addr)
	    { /* it is just one of RST n */
	      *p++ = addr | 0307;
	    }
	  else if (gdbarch_bfd_arch_info (gdbarch)->mach == bfd_mach_ez80_adl)
	   { /* eZ80 in ADL or mixed mode */
	     //*p++ = 0x5b; /* .LIL */
	     *p++ = 0xcd; /* CALL */
	     *p++ = (addr >> 0) & 0xff;
	     *p++ = (addr >> 8) & 0xff;
	     *p++ = (addr >> 16) & 0xff;
	   }
	  else
	   { /* Z80 call to any address */
	     *p++ = 0xcd; /* CALL */
	     *p++ = (addr >> 0) & 0xff;
	     *p++ = (addr >> 8) & 0xff;
	   }
	  break_insn_len = p - &break_insn[0];
	}
      else /* __gdb_break_handler is not defined - assume RST 8 */
	{
	  break_insn[0] = 0xcf; /* RST 8 */
	  break_insn_len = 1;
	}
    }
  *lenptr = break_insn_len;
  return &break_insn[0];
}

/* Given a GDB frame, determine the address of the calling function's
   frame.  This will be used to create a new GDB frame struct.  */
static void
z80_frame_this_id (struct frame_info *next_frame, void **this_cache,
		   struct frame_id *this_id)
{
  struct z80_unwind_cache *info
    = z80_frame_unwind_cache (this_frame, this_cache);
  CORE_ADDR base;
  CORE_ADDR func;
  struct frame_id id;

  /* The FUNC is easy.  */
  func = get_frame_func (this_frame);

  /* Hopefully the prologue analysis either correctly determined the
     frame's base (which is the SP from the previous frame), or set
     that base to "NULL".  */
  base = info->prev_sp;
  if (base == 0)
    return;

  id = frame_id_build (base, func);
  *this_id = id;
}


static struct value *
z80_frame_prev_register (struct frame_info *this_frame,
			 void **this_cache, int regnum)
{
  return NULL;
}

/* Return the breakpoint kind for this target based on *PCPTR. */
/*static int
z80_breakpoint_kind_from_pc (struct gdbarch *gdbarch, CORE_ADDR *pcptr)
{
}*/

/* Return the software breakpoint from KIND.  KIND can have target
   specific meaning like the Z0 kind parameter.
   SIZE is set to the software breakpoint's length in memory. */
/*static const gdb_byte *
z80_sw_breakpoint_from_kind(struct gdbarch *gdbarch, int kind, int *size)
{
}*/

/* TODO: find description */
/*static int
z80_adjust_breakpoint_address (struct gdbarch *gdbarch, CORE_ADDR bpaddr)
{
}*/

/* Return a vector of addresses on which the software single step
   breakpoints should be inserted.  NULL means software single step is
   not used.
   Only one breakpoint address will be returned: conditional branches
   will be always evaluated. */
static std::vector<CORE_ADDR>
z80_software_single_step (struct gdbarch *gdbarch, struct regcache *regcache)
{
  gdb_byte buf[6];
  CORE_ADDR pc;
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  regcache->cooked_read (Z80_PC_REGNUM, buf);
  pc = extract_typed_address(buf, builtin_type (gdbarch)->builtin_func_ptr);
  read_memory (pc, buf, sizeof(buf));
}

#if 0 /* it is for non-stop debugging mode */
/* Copy the instruction at FROM to TO, and make any adjustments
   necessary to single-step it at that address.

   REGS holds the state the thread's registers will have before
   executing the copied instruction; the PC in REGS will refer to FROM,
   not the copy at TO.  The caller should update it to point at TO later.

   Return a pointer to data of the architecture's choice to be passed
   to gdbarch_displaced_step_fixup.  Or, return NULL to indicate that
   the instruction's effects have been completely simulated, with the
   resulting state written back to REGS.

   For a general explanation of displaced stepping and how GDB uses it,
   see the comments in infrun.c.

   The TO area is only guaranteed to have space for
   gdbarch_max_insn_length (arch) bytes, so this function must not
   write more bytes than that to that area.

   If you do not provide this function, GDB assumes that the
   architecture does not support displaced stepping.

   If the instruction cannot execute out of line, return NULL.  The
   core falls back to stepping past the instruction in-line instead in
   that case. */
static struct displaced_step_closure *
z80_displaced_step_copy_insn (struct gdbarch *gdbarch, CORE_ADDR from,
			      CORE_ADDR to, struct regcache *regs)
{
}


/* Return true if GDB should use hardware single-stepping to execute
   the displaced instruction identified by CLOSURE.  If false,
   GDB will simply restart execution at the displaced instruction
   location, and it is up to the target to ensure GDB will receive
   control again (e.g. by placing a software breakpoint instruction
   into the displaced instruction buffer).

   The default implementation returns false on all targets that
   provide a gdbarch_software_single_step routine, and true otherwise. */
static int
z80_displaced_step_hw_singlestep (struct gdbarch *gdbarch,
				  struct displaced_step_closure *closure)
{
}

/* Fix up the state resulting from successfully single-stepping a
   displaced instruction, to give the result we would have gotten from
   stepping the instruction in its original location.

   REGS is the register state resulting from single-stepping the
   displaced instruction.
   
   CLOSURE is the result from the matching call to
   gdbarch_displaced_step_copy_insn.
   
   If you provide gdbarch_displaced_step_copy_insn.but not this
   function, then GDB assumes that no fixup is needed after
   single-stepping the instruction.

   For a general explanation of displaced stepping and how GDB uses it,
   see the comments in infrun.c. */
static void
z80_displaced_step_fixup (struct gdbarch *gdbarch,
			  struct displaced_step_closure *closure,
			  CORE_ADDR from, CORE_ADDR to, struct regcache *regs)
{
}

/* Return the address of an appropriate place to put displaced
   instructions while we step over them.  There need only be one such
   place, since we're only stepping one thread over a breakpoint at a
   time.

   For a general explanation of displaced stepping and how GDB uses it,
   see the comments in infrun.c. */
   
static int
z80_displaced_step_location (struct gdbarch *gdbarch)
{
}
#endif

/* Refresh overlay mapped state for section OSECT. */
static void 
z80_overlay_update (struct gdbarch *gdbarch, struct obj_section *osect)
{
}

/* Signal translation: translate inferior's signal (target's) number
   into GDB's representation.  The implementation of this method must
   be host independent.  IOW, don't rely on symbols of the NAT_FILE
   header (the nm-*.h files), the host <signal.h> header, or similar
   headers.  This is mainly used when cross-debugging core files ---
   "Live" targets hide the translation behind the target interface
   (target_wait, target_resume, etc.). */
static enum gdb_signal
z80_gdb_signal_from_target (struct gdbarch *gdbarch, int signo)
{
}

/* Signal translation: translate the GDB's internal signal number into
   the inferior's signal (target's) representation.  The implementation
   of this method must be host independent.  IOW, don't rely on symbols
   of the NAT_FILE header (the nm-*.h files), the host <signal.h>
   header, or similar headers.
   Return the target signal number if found, or -1 if the GDB internal
   signal number is invalid. */
static int
z80_gdb_signal_to_target (struct gdbarch *gdbarch, enum gdb_signal signal)
{
}

/* Return non-zero if the instruction at ADDR is a call; zero otherwise. */
static int
z80_insn_is_call (struct gdbarch *gdbarch, CORE_ADDR addr)
{
}

/* Return non-zero if the instruction at ADDR is a return; zero otherwise. */
static int
z80_insn_is_ret (struct gdbarch *gdbarch, CORE_ADDR addr)
{
}

/* Return non-zero if the instruction at ADDR is a jump; zero otherwise. */
static int
z80_insn_is_jump (struct gdbarch *gdbarch, CORE_ADDR addr)
{
}

static const struct frame_unwind
z80_frame_unwind =
{
  NORMAL_FRAME,
  default_frame_unwind_stop_reason,
  z80_frame_this_id,
  z80_frame_prev_register,
  NULL, /*unwind_data*/
  default_frame_sniffer
  /*dealloc_cache*/
  /*prev_arch*/
};

/* Initialize the gdbarch struct for the Z80 arch */
static struct gdbarch *
z80_gdbarch_init (struct gdbarch_info info, struct gdbarch_list *arches)
{
  struct gdbarch *gdbarch;
  struct gdbarch_tdep *tdep;
  struct gdbarch_list *best_arch;
  unsigned long mach = info.bfd_arch_info->mach;

  /* If there is already a candidate, use it.  */
  for (best_arch = gdbarch_list_lookup_by_info (arches, &info);
       best_arch != NULL;
       best_arch = gdbarch_list_lookup_by_info (best_arch->next, &info))
    {
      if (mach == gdbarch_bfd_arch_info (best_arch->gdbarch)->mach)
        return best_arch->gdbarch;
    }

  /* None found, create a new architecture from the information provided.  */
  tdep = XCNEW (struct gdbarch_tdep);
  gdbarch = gdbarch_alloc (&info, tdep);

  if (mach == bfd_mach_ez80_adl)
    {
      tdep->addr_length = 3;
      set_gdbarch_max_insn_length (gdbarch, 6);
    }
  else
    {
      tdep->addr_length = 2;
      set_gdbarch_max_insn_length (gdbarch, 4);
    }

  /* Create a type for PC.  We can't use builtin types here, as they may not
     be defined.  */
  tdep->void_type = arch_type (gdbarch, TYPE_CODE_VOID, TARGET_CHAR_BIT,
                               "void");
  tdep->func_void_type = make_function_type (tdep->void_type, NULL);
  tdep->pc_type = arch_pointer_type (gdbarch,
				     tdep->addr_length * TARGET_CHAR_BIT,
				     NULL, tdep->func_void_type);

  set_gdbarch_short_bit (gdbarch, TARGET_CHAR_BIT);
  set_gdbarch_int_bit (gdbarch, 2 * TARGET_CHAR_BIT);
  set_gdbarch_long_bit (gdbarch, 4 * TARGET_CHAR_BIT);
  set_gdbarch_ptr_bit (gdbarch, tdep->addr_length * TARGET_CHAR_BIT);
  set_gdbarch_addr_bit (gdbarch, tdep->addr_length * TARGET_CHAR_BIT);

  set_gdbarch_num_regs (gdbarch, (mach == bfd_mach_ez80_adl) ? EZ80_NUM_REGS
							     : Z80_NUM_REGS);
  set_gdbarch_sp_regnum (gdbarch, R_SP);
  set_gdbarch_pc_regnum (gdbarch, R_PC);

  set_gdbarch_register_name (gdbarch, z80_register_name);
  set_gdbarch_register_type (gdbarch, z80_register_type);

  /* TODO: get FP type from binary (extra flags required) */
  set_gdbarch_float_bit (gdbarch, 4 * TARGET_CHAR_BIT);
  set_gdbarch_double_bit (gdbarch, 4 * TARGET_CHAR_BIT);
  set_gdbarch_long_double_bit (gdbarch, 4 * TARGET_CHAR_BIT);
  set_gdbarch_float_format (gdbarch, floatformats_ieee_single);
  set_gdbarch_double_format (gdbarch, floatformats_ieee_single);
  set_gdbarch_long_double_format (gdbarch, floatformats_ieee_single);

  set_gdbarch_return_value (gdbarch, z80_return_value);

  set_gdbarch_skip_prologue (gdbarch, z80_skip_prologue);
  set_gdbarch_inner_than (gdbarch, core_addr_lessthan); // falling stack
  set_gdbarch_unwind_pc (gdbarch, z80_unwind_pc);

  set_gdbarch_breakpoint_from_pc (gdbarch, z80_breakpoint_from_pc);

  frame_unwind_append_unwinder (gdbarch, &z80_frame_unwind);

  return gdbarch;
}

void
_initialize_z80_tdep (void)
{
  register_gdbarch_init (bfd_arch_z80, z80_gdbarch_init);
}

struct insn_context
{
  struct gdbarch *gdbarch;
  struct regcache *regcache;
  int simulate;  /* non null, if instruction should simulated */
  int insn_long; /* SIS/LIS (0) or SIL/LIL (1) */
  int exec_long; /* SIS/SIL (0) or LIS/LIL (1) */
  CORE_ADDR pc;
  CORE_ADDR sp;  /* for stack trace */
  int pos;
  gdb_byte code[6];
};

enum instruction_type
{
  insn_default,
  insn_pref_adl,
  insn_pref_ed,
  insn_pref_idx,
  insn_djnz_d,
  insn_jr_d,
  insn_jr_cc_d,
  insn_jp_nn,
  insn_jp_rr,
  insn_jp_cc_nn,
  insn_rst_n,
  insn_ret,
  insn_ret_cc,
  insn_push_rr,
  insn_pop_rr,
  insn_dec_sp,
  insn_inc_sp,
  insn_ld_sp_nn,
  insn_ld_sp_6nn9, /* ld sp, (nn) */
  insn_ld_sp_rr,
  insn_force_nop /* invalid opcode prefix */
};

struct insn_info
{
  gdb_byte opcode;
  gdb_byte mask;
  gdb_byte size;
  enum instruction_type type;
  CORE_ADDR (*fp)(struct insn_context *ctx, const struct insn_info *info);
} ;

/* PSEUDO EVAL FUNCTIONS, returns size of instruction, 0 force NOP */
static int pe_main     (struct insn_context *ctx, const struct insn_info *info);
static int pref_ed     (struct insn_context *ctx, const struct insn_info *info);
static int pref_ind    (struct insn_context *ctx, const struct insn_info *info);
static int pref_ez80   (struct insn_context *ctx, const struct insn_info *info);
static int pe_djnz     (struct insn_context *ctx, const struct insn_info *info);
static int pe_jp_nn    (struct insn_context *ctx, const struct insn_info *info);
static int pe_jp_cc_nn (struct insn_context *ctx, const struct insn_info *info);
static int pe_jp_hl    (struct insn_context *ctx, const struct insn_info *info);
static int pe_jp_ii    (struct insn_context *ctx, const struct insn_info *info);
static int pe_jr       (struct insn_context *ctx, const struct insn_info *info);
static int pe_jr_cc    (struct insn_context *ctx, const struct insn_info *info);
static int pe_ret      (struct insn_context *ctx, const struct insn_info *info);
static int pe_ret_cc   (struct insn_context *ctx, const struct insn_info *info);
static int pe_rst      (struct insn_context *ctx, const struct insn_info *info);
static int pe_dummy    (struct insn_context *ctx, const struct insn_info *info);
/* end of pseudo eval functions */
static int check_cc (int flags, int cond);

/* Table to disassemble machine codes without prefix.  */
static const struct insn_info
ez80_main_insn_table[] =
{
  { 0100, 0377, 0, insn_pref_adl }, //eZ80 mode prefix
  { 0111, 0377, 0, insn_pref_adl }, //eZ80 mode prefix
  { 0122, 0377, 0, insn_pref_adl }, //eZ80 mode prefix
  { 0133, 0377, 0, insn_pref_adl }, //eZ80 mode prefix
/* here common Z80/eZ80 opcodes */
  { 0000, 0367, 1, insn_default  }, //"nop", "ex af,af'"
  { 0061, 0277, 1, insn_ld_sp_nn }, //"ld sp,nn"
  { 0001, 0317, 3, insn_default  }, //"ld rr,nn"
  { 0002, 0347, 3, insn_default  }, //"ld (rr),a", "ld a,(rr)"
  { 0063, 0377, 1, insn_inc_sp   }, //"inc sp"
  { 0073, 0377, 1, insn_dec_sp   }, //"dec sp"
  { 0003, 0303, 1, insn_default  }, //"inc rr", "dec rr", ...
  { 0004, 0307, 1, insn_default  }, //"inc/dec r/(hl)"
  { 0006, 0307, 2, insn_default  }, //"ld r,n", "ld (hl),n"
  { 0020, 0377, 2, insn_djnz_d   }, //"djnz dis"
  { 0030, 0377, 2, insn_jr_d     }, //"jr dis"
  { 0040, 0337, 2, insn_jr_cc_d  }, //"jr cc,dis"
  { 0100, 0300, 1, insn_default  }, //"ld r,r", "halt"
  { 0200, 0300, 1, insn_default  }, //"alu_op a,r"
  { 0300, 0307, 1, insn_ret_cc   }, //"ret cc"
  { 0301, 0317, 1, insn_pop_rr   }, //"pop rr"
  { 0302, 0307, 3, insn_jp_cc_nn }, //"jp cc,nn"
  { 0303, 0377, 3, insn_jp_nn    }, //"jp nn"
  { 0304, 0307, 3, insn_jp_cc_nn }, //"call cc,nn"
  { 0305, 0317, 1, insn_push_rr  }, //"push rr"
  { 0306, 0307, 2, insn_default  }, //"alu_op a,n"
  { 0307, 0307, 1, insn_rst_n,   }, //"rst n"
  { 0311, 0377, 1, insn_ret      }, //"ret"
  { 0313, 0377, 2, insn_default  }, //CB prefix
  { 0315, 0377, 3, insn_jp_nn    }, //"call nn"
  { 0323, 0367, 2, insn_default  }, //"out (n),a", "in a,(n)"
  { 0335, 0337, 0, insn_pref_idx }, //DD/FD prefix
  { 0351, 0377, 1, insn_jp_rr    }, //"jp (hl)"
  { 0355, 0377, 0, insn_pref_ed  }, //ED prefix
  { 0371, 0377, 1, insn_ld_sp_rr }, //"ld sp,hl"
  { 0000, 0000, 1, insn_default  }  //others
} ;

static const struct insn_info
ez80_adl_main_insn_table[] =
{
  { 0000, 0367, 1, insn_default  }, //"nop", "ex af,af'"
  { 0001, 0317, 4, insn_default  }, //"ld rr,nn"
  { 0002, 0347, 4, insn_default  }, //"ld (rr),a", "ld a,(rr)"
  { 0063, 0377, 1, insn_inc_sp   }, //"inc sp"
  { 0073, 0377, 1, insn_dec_sp   }, //"dec sp"
  { 0003, 0303, 1, insn_default  }, //"inc rr", "dec rr", ...
  { 0004, 0307, 1, insn_default  }, //"inc/dec r/(hl)"
  { 0006, 0307, 2, insn_default  }, //"ld r,n", "ld (hl),n"
  { 0020, 0377, 2, insn_djnz     }, //"djnz dis"
  { 0030, 0377, 2, insn_jr       }, //"jr dis"
  { 0040, 0337, 2, insn_jr_cc    }, //"jr cc,dis"
  { 0100, 0377, 0, insn_pref_adl }, //eZ80 mode prefix
  { 0111, 0377, 0, insn_pref_adl }, //eZ80 mode prefix
  { 0122, 0377, 0, insn_pref_adl }, //eZ80 mode prefix
  { 0133, 0377, 0, insn_pref_adl }, //eZ80 mode prefix
  { 0100, 0300, 1, insn_default  }, //"ld r,r", "halt"
  { 0200, 0300, 1, insn_default  }, //"alu_op a,r"
  { 0300, 0307, 1, insn_ret_cc   }, //"ret cc"
  { 0301, 0317, 1, insn_pop_rr   }, //"pop rr"
  { 0302, 0307, 4, insn_jp_cc_nn }, //"jp cc,nn"
  { 0303, 0377, 4, insn_jp_nn    }, //"jp nn"
  { 0304, 0307, 4, insn_jp_cc_nn }, //"call cc,nn"
  { 0305, 0317, 1, insn_push_rr  }, //"push rr"
  { 0306, 0307, 2, insn_default  }, //"alu_op a,n"
  { 0307, 0307, 1, insn_rst      }, //"rst n"
  { 0311, 0377, 1, insn_ret      }, //"ret"
  { 0313, 0377, 2, insn_default  }, //CB prefix
  { 0315, 0377, 4, insn_jp_nn    }, //"call nn"
  { 0323, 0367, 2, insn_default  }, //"out (n),a", "in a,(n)"
  { 0335, 0337, 0, insn_pref_idx }, //DD/FD prefix
  { 0351, 0377, 1, insn_jp_rr    }, //"jp (hl)"
  { 0355, 0377, 0, insn_pref_ed  }, //ED prefix
  { 0371, 0377, 1, insn_ld_sp_rr }, //"ld sp,hl"
  { 0000, 0000, 1, insn_default  }  //others
} ;

/* ED prefix opcodes table.
   Note the instruction length does include the ED prefix (+ 1 byte)
*/
static const struct insn_info
ez80_ed_insn_table[] =
{
  /* eZ80 only instructions */
  { 0002, 0366, 3, insn_default    }, //"lea rr,ii+d"
  { 0124, 0376, 3, insn_default    }, //"lea ix,iy+d", "lea iy,ix+d"
  { 0145, 0377, 3, insn_default    }, //"pea ix+d"
  { 0146, 0377, 3, insn_default    }, //"pea iy+d"
  { 0164, 0377, 3, insn_default    }, //"tstio n"
  /* Z180/eZ80 only instructions */
  { 0060, 0376, 2, insn_default    }, //not an instruction
  { 0000, 0306, 3, insn_default    }, //"in0 r,(n)", "out0 (n),r"
  { 0144, 0377, 3, insn_default    }, //"tst a, n"
  /* common instructions */
  { 0173, 0377, 4, insn_ld_sp_6nn9 }, //"ld sp,(nn)"
  { 0103, 0307, 4, insn_default    }, //"ld (nn),rr", "ld rr,(nn)"
  { 0105, 0317, 2, insn_ret        }, //"retn", "reti"
  { 0000, 0000, 2, insn_default    }
};

static const struct insn_info
ez80_adl_ed_insn_table[] =
{
  { 0002, 0366, 3, insn_default }, //"lea rr,ii+d"
  { 0124, 0376, 3, insn_default }, //"lea ix,iy+d", "lea iy,ix+d"
  { 0145, 0377, 3, insn_default }, //"pea ix+d"
  { 0146, 0377, 3, insn_default }, //"pea iy+d"
  { 0164, 0377, 3, insn_default }, //"tstio n"
  { 0060, 0376, 2, insn_default }, //not an instruction
  { 0000, 0306, 3, insn_default }, //"in0 r,(n)", "out0 (n),r"
  { 0144, 0377, 3, insn_default }, //"tst a, n"
  { 0173, 0377, 5, insn_ld_sp_6nn9 }, //"ld sp,(nn)"
  { 0103, 0307, 5, insn_default }, //"ld (nn),rr", "ld rr,(nn)"
  { 0105, 0317, 2, insn_ret     }, //"retn", "reti"
  { 0000, 0000, 2, insn_default }
};

/* table for FD and DD prefixed instructions */
static const struct insn_info 
ez80_ddfd_insn_table[] =
{
  /* ez80 only instructions */
  { 0007, 0307, 3, insn_default }, //"ld rr,(ii+d)"
  { 0061, 0377, 3, insn_default }, //"ld ii,(ii+d)"
  /* common instructions */
  { 0011, 0367, 2, insn_default }, //"add ii,rr"
  { 0041, 0377, 4, insn_default }, //"ld ii,nn"
  { 0042, 0367, 4, insn_default }, //"ld (nn),ii", "ld ii,(nn)"
  { 0043, 0367, 2, insn_default }, //"inc ii", "dec ii"
  { 0044, 0366, 2, insn_default }, //"inc/dec iih/iil"
  { 0046, 0367, 3, insn_default }, //"ld iih,n", "ld iil,n"
  { 0064, 0376, 3, insn_default }, //"inc (ii+d)", "dec (ii+d)"
  { 0066, 0377, 4, insn_default }, //"ld (ii+d),n"
  { 0166, 0377, 0, insn_default }, //not an instruction
  { 0160, 0370, 3, insn_default }, //"ld (ii+d),r"
  { 0104, 0306, 2, insn_default }, //"ld r,iih", "ld r,iil"
  { 0106, 0307, 3, insn_default }, //"ld r,(ii+d)"
  { 0140, 0360, 2, insn_default }, //"ld iih,r", "ld iil,r"
  { 0204, 0306, 2, insn_default }, //"alu_op a,iih", "alu_op a,iil"
  { 0206, 0307, 3, insn_default }, //"alu_op a,(ii+d)"
  { 0313, 0377, 4, insn_default }, //DD/FD CB dd oo instructions
  { 0341, 0373, 2, insn_default }, //"pop ii", "push ii"
  { 0343, 0377, 2, insn_default }, //"ex (sp),ii"
  { 0351, 0377, 2, insn_jp_rr   }, //"jp (ii)"
  { 0371, 0377, 2, insn_sp_rr   }, //"ld sp,ii"
  { 0000, 0000, 0, insn_default }  //not an instruction

static const struct insn_info 
ez80_adl_ddfd_insn_table[] =
{
  { 0007, 0307, 3, insn_default }, //"ld rr,(ii+d)"
  { 0061, 0377, 3, insn_default }, //"ld ii,(ii+d)"
  { 0011, 0367, 2, insn_default }, //"add ii,rr"
  { 0041, 0377, 5, insn_default }, //"ld ii,nn"
  { 0042, 0367, 5, insn_default }, //"ld (nn),ii", "ld ii,(nn)"
  { 0043, 0367, 2, insn_default }, //"inc ii", "dec ii"
  { 0044, 0366, 2, insn_default }, //"inc/dec iih/iil"
  { 0046, 0367, 3, insn_default }, //"ld iih,n", "ld iil,n"
  { 0064, 0376, 3, insn_default }, //"inc (ii+d)", "dec (ii+d)"
  { 0066, 0377, 4, insn_default }, //"ld (ii+d),n"
  { 0166, 0377, 0, insn_default }, //not an instruction
  { 0160, 0370, 3, insn_default }, //"ld (ii+d),r"
  { 0104, 0306, 2, insn_default }, //"ld r,iih", "ld r,iil"
  { 0106, 0307, 3, insn_default }, //"ld r,(ii+d)"
  { 0140, 0360, 2, insn_default }, //"ld iih,r", "ld iil,r"
  { 0204, 0306, 2, insn_default }, //"alu_op a,iih", "alu_op a,iil"
  { 0206, 0307, 3, insn_default }, //"alu_op a,(ii+d)"
  { 0313, 0377, 4, insn_default }, //DD/FD CB dd oo instructions
  { 0341, 0373, 2, insn_default }, //"pop ii", "push ii"
  { 0343, 0377, 2, insn_default }, //"ex (sp),ii"
  { 0351, 0377, 2, insn_jp_rr   }, //"jp (ii)"
  { 0371, 0377, 2, insn_sp_rr   }, //"ld sp,ii"
  { 0000, 0000, 0, insn_default }  //not an instruction
};

static int 
z80_process_insn_info_table (struct insn_context *ctx, const struct insn_info *item)
{
  gdb_byte insn = ctx->buf[ctx->pos];
  for (; item->opcode != (insn & item->mask); ++item)
    ;
  return item->fn (ctx, item);
}

static int
z80_get_insn_size (struct insn_context *ctx)
{
  const struct insn_info *table;
  switch (gdbarch_bfd_arch_info (ctx->gdbarch)->mach)
    {
    case bfd_mach_ez80_adl:
    case bfd_mach_ez80:
      table = ctx->insn_long ? ez80_adl_main_insn_table : ez80_main_insn_table;
      break;
    default:
      table = &ez80_main_insn_table[4];
      break;
    }

  return z80_process_insn_info_table (ctx, table);
}

static int
pref_ed (struct insn_context *ctx, const struct insn_info *info)
{
  const struct insn_info *table;
  switch (gdbarch_bfd_arch_info (ctx->gdbarch)->mach)
    {
    case bfd_mach_ez80_adl:
      table = ez80_adl_ed_insn_table;
      break;
    case bfd_mach_ez80:
      table = ez80_ed_insn_table;
      break;
    case bfd_mach_ez180:
      table = &ez80_ed_insn_table[5];
      break;
    default:
      table = &ez80_ed_insn_table[8];
      break;
    }

  ctx->pos++;
  return z80_process_insn_info_table (ctx, table);
}

static int pref_ind (struct insn_context *ctx, const struct insn_info *info)
{
  const struct insn_info *table;
  switch (gdbarch_bfd_arch_info (ctx->gdbarch)->mach)
    {
    case bfd_mach_ez80_adl:
      table = ez80_adl_ddfd_insn_table;
      break;
    case bfd_mach_ez80:
      table = ez80_ddfd_insn_table;
      break;
    default:
      table = &ez80_ddfd_insn_table[2];
      break;
    }

  ctx->pos++;
  return z80_process_insn_info_table (ctx, table);
}

static int
pref_ez80 (struct insn_context *ctx, const struct insn_info *info)
{
  const struct insn_info *table;
  switch (ctx->buf[ctx->pos])
    {
    case 0x40: /* SIS */
    case 0x49: /* LIS */
      ctx->march = bfd_mach_ez80; /* short instruction mode */
      break;
    case 0x52: /* LIS */
    case 0x5b: /* LIL */
      ctx->march = bfd_mach_ez80_adl; /* long instruction mode */
      break;
    default: /* impossible */
      return 0; /* force NOP */
    }

  switch (ctx->buf[ctx->pos+1])
    {
    case 0x40: /* SIS */
    case 0x49: /* LIS */
    case 0x52: /* LIS */
    case 0x5b: /* LIL */
      return 0; /* force NOP for double memory mode prefix */
    }
 
  ctx->pos++;
  return z80_get_insn_size (ctx);
}

static int
pe_djnz (struct insn_context *ctx, const struct insn_info *info)
{
  ULONGEST bc;
  ULONGEST b;
  regcache_cooked_read_unsigned (ctx->regcache, Z80_BC_REGNUM, &bc);
  b = bc & 0xff00;
  b -= 0x100;
  ctx->pc += ctx->pos + info->size;
  if (b == 0)
    ctx->pc += extract_signed_integer (&ctx->code[ctx->pos+1], 1,
				       ctx->byte_order);
  if (ctx->simulate)
    {
      b &= 0xff00;
      bc ^= b;
      bc &= ~(ULONGEST)0xff00;
      bc ^= b;
      regcache_cooked_write_unsigned (ctx->regcache, Z80_BC_REGNUM, bc);
    }
  return ctx->pos + info->size;
}

static int
pe_jp_nn (struct insn_context *ctx, const struct insn_info *info)
{
  ctx->pc = extract_unsigned_integer (&ctx->code[ctx->pos+1], info->size - 1,
				      ctx->byte_order);
  return ctx->pos + info->size;
}

static int
pe_jp_cc_nn (struct insn_context *ctx, const struct insn_info *info)
{
  UNLONGEST af;
  regcache_cooked_read_unsigned (ctx->regcache, Z80_AF_REGNUM, &af);
  if (check_cc (af, ctx->insn[ctx->size] & 0070))
    ctx->pc = extract_unsigned_integer (&ctx->code[ctx->pos+1], info->size-1,
					ctx->byte_order);
  else
    ctx->pc += ctx->pos + info->size;
  return ctx->pos + info->size;
}

static int
pe_jp_hl (struct insn_context *ctx, const struct insn_info *info)
{
  UNLONGEST hl;
  regcache_cooked_read_unsigned (ctx->regcache, Z80_HL_REGNUM, &hl);
  ctx->pc = hl;

  return ctx->pos + info->size;
}

static int
pe_jp_ii (struct insn_context *ctx, const struct insn_info *info)
{
  ULONGEST dst = ctx->insn[ctx->pos-1];
  regcache_cooked_read_unsigned (ctx->regcache,
				 (dst == 0xdd) ? Z80_IX_REGNUM : Z80_IY_REGNUM,
				 &dst);
  ctx->pc = dst;

  return ctx->pos + info->size;
}

static int
pe_jr (struct insn_context *ctx, const struct insn_info *info)
{
  ctx->pc += ctx->pos + info->size;
  ctx->pc += extract_signed_integer (&ctx->code[ctx->pos+1], 1,
				     ctx->byte_order);
  return ctx->pos + info->size;
}

static int
pe_jr_cc (struct insn_context *ctx, const struct insn_info *info)
{
  UNLONGEST af;
  regcache_cooked_read_unsigned (ctx->regcache, Z80_AF_REGNUM, &af);
  ctx->pc += ctx->pos + info->size;
  if (check_cc (af, (ctx->insn[ctx->pos] & 0070) - 0040))
    ctx->pc += extract_signed_integer (&ctx->code[ctx->pos+1], 1,
				       ctx->byte_order);
  return ctx->pos + info->size;
}

static int
pe_ret (struct insn_context *ctx, const struct insn_info *info);
{
  /* FIXME: add eZ80 support */
  UNLONGEST sp;
  gdb_byte buf[3];
  regcache_cooked_read_unsigned (ctx->regcache, Z80_SP_REGNUM, &sp);
  read_memory (sp, buf, 2);
  sp += 2;
  ctx->pc = extract_unsigned_integer (buf, 2, ctx->byte_order);
  if (ctx->simulate)
    {
      b &= 0xff00;
      bc ^= b;
      bc &= ~(ULONGEST)0xff00;
      bc ^= b;
      regcache_cooked_write_unsigned (ctx->regcache, Z80_BC_REGNUM, bc);
    }
  ctx->
}

static int
pe_ret_cc (struct insn_context *ctx, const struct insn_info *info)
{
}

static int
pe_rst (struct insn_context *ctx, const struct insn_info *info)
{
}

static int
pe_dummy (struct insn_context *ctx, const struct insn_info *info)
{
}

static int
cc_holds(gdb_byte cond_code)
{
}

