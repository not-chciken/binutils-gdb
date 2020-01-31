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
#define Z80_IX_REGNUM	4
#define Z80_IY_REGNUM	5
#define Z80_SP_REGNUM	6
#define Z80_PC_REGNUM	7
#define Z80_AFa_REGNUM	8
#define Z80_BCa_REGNUM	9
#define Z80_DEa_REGNUM	10
#define Z80_HLa_REGNUM	11
#define Z80_IR_REGNUM	12
#define Z80_MBST_REGNUM	13	/* see note below */
/* eZ80 only registers */
#define Z80_SPS_REGNUM	14	/* SPS register of eZ80 CPU */
#define Z80_SPL_REGNUM	15	/* SPL register of eZ80 CPU */

/*
 MBST:
   bit0: IFF1 (useful for simulators)
   bit1: IFF2
   bit2: ADL (eZ80 only)
   bit3-7: always 0
   bit8-15: eZ80 register MB
   bit15-23: always 0 (eZ80 ADL mode only)
*/

#define Z80_NUM_REGS	14
#define Z80_REG_BYTES	(Z80_NUM_REGS*2)

#define EZ80_NUM_REGS	(Z80_NUM_REGS + 2)
#define EZ80_REG_BYTES	(EZ80_NUM_REGS*3)

#endif /* z80-tdep.h */
