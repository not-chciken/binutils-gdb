/* Target-dependent code for the Z80.

   Copyright (C) 2002-2020 Free Software Foundation, Inc.

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

#ifndef Z80_TDEP_H
#define Z80_TDEP_H

/* Register pair constants
   Order optimized for gdb-stub implementation
   Most of register pairs are 16 bit length on Z80 and
   24 bit on eZ80 in ADL or MADL modes */
#define Z80_AF_REGNUM	0
#define Z80_BC_REGNUM	1
#define Z80_DE_REGNUM	2
#define Z80_HL_REGNUM	3
#define Z80_SP_REGNUM	4	/* SPL on eZ80 CPU */
#define Z80_PC_REGNUM	5
#define Z80_IX_REGNUM	6
#define Z80_IY_REGNUM	7
#define Z80_AFA_REGNUM	8
#define Z80_BCA_REGNUM	9
#define Z80_DEA_REGNUM	10
#define Z80_HLA_REGNUM	11
#define Z80_IR_REGNUM	12
/* eZ80 only registers */
#define Z80_SPS_REGNUM	13	/* SPS register of eZ80 CPU */

#define Z80_NUM_REGS	13
#define Z80_REG_BYTES	(Z80_NUM_REGS*2)

#define EZ80_NUM_REGS	(Z80_NUM_REGS + 1)
#define EZ80_REG_BYTES	(EZ80_NUM_REGS*3)

#endif /* z80-tdep.h */
