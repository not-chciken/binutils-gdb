/******************************************************************************\
                             Configuration
\******************************************************************************/
/* Comment this line out if software breakpoints are unsupported.
   If you have special function to toggle software breakpoints, then provide
   here name of these function. Expected prototype:
       int toggle_swbreak(int set, void *addr);
   function must return 0 on success. */
//#define DBG_SWBREAK toggle_swbreak
#define DBG_SWBREAK

/* Define if one of standard RST handlers is used as software
   breakpoint entry point */
//#define DBG_SWBREAK_RST 0x08

/* if platform supports hardware breakpoints then define following two macros
   by names of functions. Fuctions must have next prototypes:
     int toggle_hwbreak(int set, void *addr);
   function must return 0 on success. */
//#define DBG_HWBREAK toggle_hwbreak

/* if platform supports hardware watchpoints then define all or some of
   following macros by names of functions. Fuctions prototypes:
     int toggle_watch(int set, void *addr, size_t size);  // memory write watch
     int toggle_rwatch(int set, void *addr, size_t size); // memory read watch
     int toggle_awatch(int set, void *addr, size_t size); // memory access watch
   function must return 0 on success. */
//#define DBG_WWATCH toggle_watch
//#define DBG_RWATCH toggle_rwatch
//#define DBG_AWATCH toggle_awatch

/* Size of hardware breakpoint. Required to correct PC. */
#define DBG_HWBREAK_SIZE 0

/* Define following macro if you need custom memory read/write routine.
   Function should return non-zero on success, and zero on failure
   (for example, write to ROM area).
   Useful with overlays (bank switching).
   Do not forget to define:
   _ovly_table - overlay table
   _novlys - number of items in _ovly_table
   or
   _ovly_region_table - overlay regions table
   _novly_regions - number of items in _ovly_region_table

   _ovly_debug_prepare - function is called before overlay mapping
   _ovly_debug_event - function is called after overlay mapping
 */
//#define DBG_MEMCPY memcpy

/* define dedicated stack size if required */
//#define DBG_STACK_SIZE 256

/* max GDB packet size
   should be much more that DBG_STACK_SIZE because it will be allocated on stack
*/
#define DBG_PACKET_SIZE 150

/* Uncomment if required to use trampoline when resuming operation.
   Useful with dedicated stack when stack pointer do not point to the stack or
   stack is not writable */
//#define DBG_USE_TRAMPOLINE

/* Uncomment following macro to enable debug printing to debugger console */
//#define DBG_PRINT

#define DBG_NMI_EX EX_HWBREAK
#define DBG_INT_EX EX_SIGINT
/******************************************************************************\
                             Public Interface
\******************************************************************************/

/* Enter to debug mode from software or hardware breakpoint.
   Assume address of next instruction after breakpoint call is on top of stack.
   Do JP _debug_swbreak or JP _debug_hwbreak from RST handler, for example.
 */
void debug_swbreak (void);
void debug_hwbreak (void);

/* Jump to this function from NMI handler. Just replace RETN instruction by
 * JP _debug_nmi
 */
void debug_nmi (void);

/* Jump to this function from INT handler. Just replace EI+RETI instructions by
 * JP _debug_int
 */
void debug_int (void);

#define EX_SWBREAK	0	/* sw breakpoint */
#define EX_HWBREAK	-1	/* hw breakpoint */
#define EX_WWATCH	-2	/* memory write watch */
#define EX_RWATCH	-3	/* memory read watch */
#define EX_AWATCH	-4	/* memory access watch */
#define EX_SIGINT	2
#define EX_SIGTRAP	5
#define EX_SIGABRT	6
#define EX_SIGBUS	10
#define EX_SIGSEGV	11
/* or any standard *nix signal value */

/* Enter to debug mode (after receiving BREAK from GDB)
 * Assume:
 *   PC = (SP+0)
 *   SIG= (SP+2)
 *   SP = SP+4
 */
void debug_exception (int ex);

/* Prints to debugger console. */
void debug_print(const char *str);
/******************************************************************************\
                              Required functions
\******************************************************************************/

extern int getDebugChar (void);
extern void putDebugChar (int ch);

#ifdef DBG_SWBREAK
#define DO_EXPAND(VAL)  VAL ## 123456
#define EXPAND(VAL)     DO_EXPAND(VAL)

#if EXPAND(DBG_SWBREAK) != 123456
#define DBG_SWBREAK_PROC DBG_SWBREAK
extern int DBG_SWBREAK(int set, void *addr);
#endif

#undef EXPAND
#undef DO_EXPAND
#endif /* DBG_SWBREAK */

#ifdef DBG_HWBREAK
extern int DBG_HWBREAK(int set, void *addr);
#endif

#ifdef DBG_MEMCPY
extern void *DBG_MEMCPY (void *dest, const void *src, size_t n);
#endif

#ifdef DBG_WWATCH
extern int DBG_WWATCH(int set, void *addr, size_t size);
#endif

#ifdef DBG_RWATCH
extern int DBG_RWATCH(int set, void *addr, size_t size);
#endif

#ifdef DBG_AWATCH
extern int DBG_AWATCH(int set, void *addr, size_t size);
#endif

/******************************************************************************\
                               IMPLEMENTATION
\******************************************************************************/

#include <string.h>

#ifndef NULL
# define NULL (void*)0
#endif

typedef unsigned char byte;
typedef unsigned short word;

/* CPU state */
#ifdef __SDCC_ez80_adl
# define REG_SIZE 3
#else
# define REG_SIZE 2
#endif /* __SDCC_ez80_adl */

#define R_AF    (0*REG_SIZE)
#define R_BC    (1*REG_SIZE)
#define R_DE    (2*REG_SIZE)
#define R_HL    (3*REG_SIZE)
#define R_SP    (4*REG_SIZE)
#define R_PC    (5*REG_SIZE)

#ifndef __SDCC_gbz80
#define R_IX    (6*REG_SIZE)
#define R_IY    (7*REG_SIZE)
#define R_AF_   (8*REG_SIZE)
#define R_BC_   (9*REG_SIZE)
#define R_DE_   (10*REG_SIZE)
#define R_HL_   (11*REG_SIZE)
#define R_IR    (12*REG_SIZE)

#ifdef __SDCC_ez80_adl
#define R_SPS   (13*REG_SIZE)
#define NUMREGBYTES (14*REG_SIZE)
#else
#define NUMREGBYTES (13*REG_SIZE)
#endif /* __SDCC_ez80_adl */
#else
#define NUMREGBYTES (6*REG_SIZE)
#define FASTCALL
#endif /*__SDCC_gbz80 */
static byte state[NUMREGBYTES];

#if DBG_PACKET_SIZE < (NUMREGBYTES*2+3)
#error "Too small DBG_PACKET_SIZE"
#endif

#ifndef FASTCALL
#define FASTCALL __z88dk_fastcall
#endif

/* dedicated stack */
#ifdef DBG_STACK_SIZE

#define LOAD_SP	ld	sp, #_stack + DBG_STACK_SIZE

static char stack[DBG_STACK_SIZE];

#else

#undef DBG_USE_TRAMPOLINE
#define LOAD_SP

#endif

static signed char sigval;

static void stub_main (int sigval, int pc_adj);
static char high_hex (byte v) FASTCALL;
static char low_hex (byte v) FASTCALL;
static char put_packet_info (const char *buffer) FASTCALL;
static void save_cpu_state (void);
static void rest_cpu_state (void);

/******************************************************************************/
#ifdef DBG_SWBREAK
#ifdef DBG_SWBREAK_RST
#define DBG_SWBREAK_SIZE 1
#else
#define DBG_SWBREAK_SIZE 3
#endif
void debug_swbreak (void) __naked
{
	__asm
	ld	(#_state + R_SP), sp
	LOAD_SP
	call	_save_cpu_state
	ld	hl, #-DBG_SWBREAK_SIZE
	push	hl
	ld	hl, #EX_SWBREAK
	push	hl
	call	_stub_main
	.globl	_break_handler
#ifdef DBG_SWBREAK_RST
_break_handler = DBG_SWBREAK_RST
#else
_break_handler = _debug_swbreak
#endif
	__endasm;
}
#endif /* DBG_SWBREAK */
/******************************************************************************/
#ifdef DBG_HWBREAK
#ifndef DBG_HWBREAK_SIZE
#define DBG_HWBREAK_SIZE 0
#endif /* DBG_HWBREAK_SIZE */
void debug_hwbreak (void) __naked
{
	__asm
	ld	(#_state + R_SP), sp
	LOAD_SP
	call	_save_cpu_state
	ld	hl, #-DBG_HWBREAK_SIZE
	push	hl
	ld	hl, #EX_HWBREAK
	push	hl
	call	_stub_main
	__endasm;
}
#endif /* DBG_HWBREAK_SET */
/******************************************************************************/
void debug_exception (int ex) __naked
{
	__asm
	ld	(#_state + R_SP), sp
	LOAD_SP
	call	_save_cpu_state
	ld	hl, #0
	push	hl
#ifdef __SDCC_gbz80
	ld	hl, #_state + R_SP
	ld	a, (hl+)
	ld	h, (hl)
	ld	l, a
#else
	ld	hl, (#_state + R_SP)
#endif
	inc	hl
	inc	hl
	ld	e, (hl)
	inc	hl
	ld	d, (hl)
	push	de
	call	_stub_main
	__endasm;
	(void)ex;
}
/******************************************************************************/
#ifndef __SDCC_gbz80
void debug_nmi(void) __naked
{
	__asm
	ld	(#_state + R_SP), sp
	LOAD_SP
	call	_save_cpu_state
	ld	hl, #0	;pc_adj
	push	hl
	ld	hl, #DBG_NMI_EX
	push	hl
	ld	hl, #_stub_main
	push	hl
	push	hl
	retn
	__endasm;
}
#endif
/******************************************************************************/
void debug_int(void) __naked
{
	__asm
	ld	(#_state + R_SP), sp
	LOAD_SP
	call	_save_cpu_state
	ld	hl, #0	;pc_adj
	push	hl
	ld	hl, #DBG_INT_EX
	push	hl
	ld	hl, #_stub_main
	push	hl
	push	hl
	reti
	__endasm;
}
/******************************************************************************/
#ifdef DBG_PRINT
void debug_print(const char *str)
{
	putDebugChar ('$');
	putDebugChar ('O');
	char csum = 'O' + put_packet_info (str);
	putDebugChar ('#');
	putDebugChar (high_hex (csum));
	putDebugChar (low_hex (csum));
}
#endif /* DBG_PRINT */
/******************************************************************************/
static void store_pc_sp (int pc_adj) FASTCALL;
#define get_reg_value(mem) (*(void* const*)(mem))
#define set_reg_value(mem,val) do { (*(void**)(mem) = (val)); } while (0)
static char* byte2hex(char *buf, byte val);
static int hex2int (const char **buf) FASTCALL;
static void get_packet (char *buffer);
static void put_packet (const char *buffer);
static void process (char *buffer) FASTCALL;

static void
stub_main (int ex, int pc_adj)
{
	char buffer[DBG_PACKET_SIZE+1];
	sigval = (signed char)ex;
	store_pc_sp (pc_adj);

	/* after starting gdb_stub must always return stop reason */
	*buffer = '?';
	for (;;) {
		process (buffer);
		put_packet (buffer);
		get_packet (buffer);
	}
}

static void
get_packet (char *buffer)
{
	byte csum;
	char ch;
	char *p;
	byte esc;
#if DBG_PACKET_SIZE <= 256
	byte count; /* it is OK to use up to 256 here */
#else
	unsigned count;
#endif
	for (;;) {
		/* wait for packet start character */
		while (getDebugChar () != '$');
retry:
		csum = 0;
		esc = 0;
		p = buffer;
		count = DBG_PACKET_SIZE;
		do {
			ch = getDebugChar ();
			if (ch == '$')
				goto retry;
			if (ch == '#')
				break;
			csum += ch;
			if (ch != '}') {
				*p++ = ch ^ esc;
				esc = 0;
				--count;
			} else
				esc = 0x20;
		} while (count != 0);

		*p = '\0';
		if (ch == '#' && /* packet is not too large */
			getDebugChar () == high_hex (csum) &&
			getDebugChar () == low_hex (csum)) {
			break;
		} else
			putDebugChar ('-');
	}
	putDebugChar ('+');
}

static
void put_packet (const char *buffer)
{
	/*  $<packet info>#<checksum>. */
	do {
		putDebugChar ('$');
		char checksum = put_packet_info (buffer);
		putDebugChar ('#');
		putDebugChar (high_hex(checksum));
		putDebugChar (low_hex(checksum));

	} while (getDebugChar () != '+');
}

static
char put_packet_info (const char *src) FASTCALL
{
	char ch;
	char checksum = 0;
	for (;;) {
		ch = *src++;
		if (ch == '\0')
			break;
		if (ch == '}' || ch == '*' || ch == '#' || ch == '$') {
			/* escape special characters */
			putDebugChar ('}');
			checksum += '}';
			ch ^= 0x20;
		}
		putDebugChar (ch);
		checksum += ch;
	}
	return checksum;
}

static void
store_pc_sp (int pc_adj) FASTCALL
{
	byte *sp = get_reg_value (&state[R_SP]);
	byte *pc = get_reg_value (sp);
	pc += pc_adj;
	set_reg_value (&state[R_PC], pc);
	set_reg_value (&state[R_SP], sp + REG_SIZE);
}

static char *mem2hex(char *buf, const byte *mem, unsigned bytes);
static char *hex2mem(byte *mem, const char *buf, unsigned bytes);

/* Command processors. Takes pointer to buffer (begins from command symbol),
   modifies buffer, returns: -1 - empty response (ignore), 0 - success,
   positive: error code. */

static signed char
process_question (char *p) FASTCALL
{
	*p++ = 'T';
	p = byte2hex (p, sigval <= 0 ? EX_SIGTRAP : (byte)sigval);
#if defined(DBG_SWBREAK_PROC) || defined(DBG_HWBREAK) || defined(DBG_WWATCH) || defined(DBG_RWATCH) || defined(DBG_AWATCH)
	switch (ex) {
#ifdef DBG_SWBREAK_PROC
	case EX_SWBREAK:
		strcpy (p, " swbreak:");
		return;
#endif
#ifdef DBG_HWBREAK
	case EX_HWBREAK:
		strcpy (p, " hwbreak:");
		return;
#endif
#ifdef DBG_WWATCH
	case EX_WWATCH:
		strcpy (p, " watch:");
		break;
#endif
#ifdef DBG_RWATCH
	case EX_RWATCH:
		strcpy (p, " rwatch:");
		break;
#endif
#ifdef DBG_AWATCH
	case EX_AWATCH:
		strcpy (p, " awatch:");
		break;
#endif
	}
	for (; *p != '\0'; p++);
	/* TODO: add support for watchpoint address */
	*p++ = '0';
	*p++ = '0';
#endif /* DBG_HWBREAK, DBG_WWATCH, DBG_RWATCH, DBG_AWATCH */
	*p++ = '\0';
	return 0;
}

#define STRING2(x) #x
#define STRING1(x) STRING2(x)
#define STRING(x) STRING1(x)

static signed char
process_q (char *buffer) FASTCALL
{
	static const char supported[] =
		"PacketSize=" STRING(DBG_PACKET_SIZE)
#ifdef DBG_SWBREAK_PROC
		";swbreak+"
#endif
#ifdef DBG_HWBREAK
		";hwbreak+"
#endif
	;
	if (strncmp(buffer + 1, "Supported", 9) == 0) {
		memcpy (buffer, supported, sizeof(supported));
		return 0;
	}
	*buffer = '\0';
	return -1;
}

static signed char
process_g (char *buffer) FASTCALL
{
	buffer = mem2hex (buffer, state, NUMREGBYTES);
	*buffer = '\0';
	return 0;
}

static signed char
process_G (char *buffer) FASTCALL
{
	hex2mem (state, &buffer[1], NUMREGBYTES);
	/* OK response */
	*buffer = '\0';
	return 0;
}

static signed char
process_m (char *buffer) FASTCALL
{/* mAA..AA,LLLL  Read LLLL bytes at address AA..AA */
	char *p = &buffer[1];
	byte *addr = (void*)hex2int(&p);
	if (*p++ != ',')
		return 1;
	unsigned len = (unsigned)hex2int(&p);
	if (len == 0)
		return 2;
	if (len > DBG_PACKET_SIZE/2)
		return 3;
	p = buffer;
#ifdef GDB_MEMCPY
	do {
		byte tmp[16];
		unsigned tlen = sizeof(tmp);
		if (tlen > len)
			tlen = len;
		if (!GDB_MEMCPY(tmp, addr, tlen))
			return 4;
		p = mem2hex (p, tmp, tlen);
		addr += tlen;
		len -= tlen;
	} while (len);
#else
	p = mem2hex (p, addr, len);
#endif
	*p = '\0';
	return 0;
}

static signed char
process_M (char *buffer) FASTCALL
{/* MAA..AA,LLLL: Write LLLL bytes at address AA.AA return OK */
	char *p = &buffer[1];
	byte *addr = (void*)hex2int(&p);
	if (*p != ',')
		return 1;
	++p;
	unsigned len = (unsigned)hex2int(&p);
	if (*p++ != ':')
		return 2;
	if (len == 0)
		goto end;
	if (len*2 + (p - buffer) > DBG_PACKET_SIZE)
		return 3;
#ifdef GDB_MEMCPY
	do {
		byte tmp[16];
		unsigned tlen = sizeof(tmp);
		if (tlen > len)
			tlen = len;
		p = hex2mem (tmp, p, tlen);
		if (!GDB_MEMCPY(addr, tmp, tlen))
			return 4;
		addr += tlen;
		len -= tlen;
	} while (len);
#else
	hex2mem (addr, p, len);
#endif
end:
	/* OK response */
	*buffer = '\0';
	return 0;
}

static signed char
process_X (char *buffer) FASTCALL
{/* XAA..AA,LLLL: Write LLLL binary bytes at address AA.AA return OK */
	char *p = &buffer[1];
	byte *addr = (void*)hex2int(&p);
	if (*p != ',')
		return 1;
	++p;
	unsigned len = (unsigned)hex2int(&p);
	if (*p++ != ':')
		return 2;
	if (len == 0)
		goto end;
	if (len + (p - buffer) > DBG_PACKET_SIZE)
		return 3;
#ifdef GDB_MEMCPY
	if (!GDB_MEMCPY(addr, p, len))
		return 4;
#else
	memcpy (addr, p, len);
#endif
end:
	/* OK response */
	*buffer = '\0';
	return 0;
}

//static int process_s (char *buffer) FASTCALL;

static signed char
process_c (char *buffer) FASTCALL
{/* 'cAAAA' - Continue at address AAAA(optional) */
	const char *p = &buffer[1];
	if (*p != '\0') {
		void *addr = (void*)hex2int(&p);
		set_reg_value (&state[R_PC], addr);
	}
	rest_cpu_state ();
	//not reached
	return 0;
}

static signed char
process_k (char *buffer) FASTCALL
{/* 'k' - Kill the program */
	__asm
	rst	0	;TODO: make proper program restart
	__endasm;
	/* OK response */
	*buffer = '\0';
	return 0;
}

static signed char
process_zZ (char *buffer) FASTCALL
{ /* insert/remove breakpoint */
#if defined(DBG_SWBREAK_PROC) || defined(DBG_HWBREAK) || defined(DBG_WWATCH) || defined(DBG_RWATCH) || defined(DBG_AWATCH)
	const int set = (*buffer == 'Z');
	const char *p = &buffer[3];
	void *addr = (void*)hex2int(&p);
	if (*p != ',')
		return 2;
	p++;
	int kind = (void*)hex2int(&p);
	switch (buffer[1]) {
#ifdef DBG_SWBREAK_PROC
	case '0': /* sw break */
		return DBG_SWBREAK_PROC(set, addr);
#endif
#ifdef DBG_HWBREAK
	case '1': /* hw break */
		return DBG_HWBREAK(set, addr);
#endif
#ifdef DBG_WWATCH
	case '2': /* write watch */
		return DBG_WWATCH(set, addr, kind);
#endif
#ifdef DBG_RWATCH
	case '3': /* read watch */
		return DBG_RWATCH(set, addr, kind);
#endif
#ifdef DBG_AWATCH
	case '4': /* access watch */
		return DBG_AWATCH(set, addr, kind);
#endif
	default:;
	}
#endif
	(void)buffer;
	return -1;
}

static signed char
do_process (char *buffer) FASTCALL
{
	switch (*buffer) {
	case '?': return process_question (buffer);
	case 'G': return process_G (buffer);
	case 'K': return process_k (buffer);
	case 'M': return process_M (buffer);
	case 'X': return process_X (buffer);
	case 'Z': return process_zZ (buffer);
	case 'c': return process_c (buffer);
	case 'g': return process_g (buffer);
	case 'm': return process_m (buffer);
	case 'q': return process_q (buffer);
//	case 's': return process_s (buffer);
	case 'z': return process_zZ (buffer);
	default:  return -1; /* empty response */
	}
}

static void
process (char *buffer) FASTCALL
{
	signed char err = do_process (buffer);
	if (err > 0) {
		char *p = buffer;
		*p++ = 'E';
		p = byte2hex (p, err);
		*p = '\0';
	} else if (err < 0)
		*buffer = '\0';
	else if (*buffer == '\0') {
		char *p = buffer;
		*p++ = 'O';
		*p++ = 'K';
		*p = '\0';
	}
}

static char *
byte2hex (char *p, byte v)
{
	*p++ = high_hex (v);
	*p++ = low_hex (v);
	return p;
}

static signed char
hex2val (unsigned char hex) FASTCALL
{
	if (hex <= '9')
		return hex - '0';
	hex &= 0xdf; /* make uppercase */
	hex -= 'A' - 10;
	return (hex >= 10 && hex < 16) ? hex : -1;
}

static int
hex2byte (const char *p) FASTCALL
{
	signed char h = hex2val (p[0]);
	signed char l = hex2val (p[1]);
	if (h < 0 || l < 0)
		return -1;
	return (byte)((byte)h << 4) | (byte)l;
}

static int
hex2int (const char **buf) FASTCALL
{
	word r = 0;
	for (;; (*buf)++) {
		signed char a = hex2val(**buf);
		if (a < 0)
			break;
		r <<= 4;
		r += (byte)a;
	}
	return (int)r;
}

static char 
high_hex (byte v) FASTCALL
{
	return low_hex(v >> 4);
}

static char
low_hex (byte v) FASTCALL
{
/*	__asm
	ld	a, l
	and	a, #0x0f
	add	a, #0x90
	daa
	adc	a, #0x40
	daa
	ld	l, a
	__endasm;
	(void)v;*/
	v &= 0x0f;
	v += '0';
	if (v < '9'+1)
		return v;
	return v + 'a' - '0' - 10;
}

/* convert the memory, pointed to by mem into hex, placing result in buf */
/* return a pointer to the last char put in buf (null) */
static char *
mem2hex (char *buf, const byte *mem, unsigned bytes)
{
	if (bytes != 0) {
		do {
			buf = byte2hex (buf, *mem++);
		} while (--bytes);
	}
	*buf = 0;
	return buf;
}

/* convert the hex array pointed to by buf into binary, to be placed in mem */
/* return a pointer to the character after the last byte written */

static const char *
hex2mem (byte *mem, const char *buf, unsigned bytes)
{
	if (bytes != 0) {
		do {
			*mem++ = hex2byte (buf);
			buf += 2;
		} while (--bytes);
	}
	return buf;
}

#ifdef __SDCC_gbz80
/* saves all state.except PC and SP */
static
void save_cpu_state() __naked
{
	__asm
	push	af
	ld	a, l
	ld	(#_state + R_HL + 0), a
	ld	a, h
	ld	(#_state + R_HL + 1), a
	ld	hl, #_state + R_HL - 1
	ld	(hl), d
	dec	hl
	ld	(hl), e
	dec	hl
	ld	(hl), b
	dec	hl
	ld	(hl), c
	dec	hl
	pop	bc
	ld	(hl), b
	dec	hl
	ld	(hl), c
	ret
	__endasm;
}

/* restore CPU state and continue execution */
static
void rest_cpu_state() __naked
{
	__asm
;restore SP
	ld	a, (#_state + R_SP + 0)
	ld	l,a
	ld	a, (#_state + R_SP + 1)
	ld	h,a
	ld	sp, hl
;push PC value as return address
	ld	a, (#_state + R_PC + 0)
	ld	l, a
	ld	a, (#_state + R_PC + 1)
	ld	h, a
	push	hl
;restore registers
	ld	hl, #_state + R_AF
	ld	c, (hl)
	inc	hl
	ld	b, (hl)
	inc	hl
	push	bc
	ld	c, (hl)
	inc	hl
	ld	b, (hl)
	inc	hl
	ld	e, (hl)
	inc	hl
	ld	d, (hl)
	inc	hl
	ld	a, (hl)
	inc	hl
	ld	h, (hl)
	ld	l, a
	pop	af
	ret
	__endasm;
}
#else
/* saves all state.except PC and SP */
static
void save_cpu_state() __naked
{
	__asm
	ld	(#_state + R_HL), hl
	ld	(#_state + R_DE), de
	ld	(#_state + R_BC), bc
	push	af
	pop	hl
	ld	(#_state + R_AF), hl
	ld	a, r	;R is increased by 7 or by 8 if called via RST
	ld	l, a
	sub	a, #7
	xor	a, l
	and	a, #0x7f
	xor	a, l
#ifdef __SDCC_ez80_adl
	ld	hl, i
	ex	de, hl
	ld	hl, #_state + R_IR
	ld	(hl), a
	inc	hl
	ld	(hl), e
	inc	hl
	ld	(hl), d
	ld	a, MB
	ld	(#_state + R_AF+2), a
#else
	ld	l, a
	ld	a, i
	ld	h, a
	ld	(#_state + R_IR), hl
#endif /* __SDCC_ez80_adl */
	ld	(#_state + R_IX), ix
	ld	(#_state + R_IY), iy
	ex	af, af'	;'
	exx
	ld	(#_state + R_HL_), hl
	ld	(#_state + R_DE_), de
	ld	(#_state + R_BC_), bc
	push	af
	pop	hl
	ld	(#_state + R_AF_), hl
	ret
	__endasm;
}

/* restore CPU state and continue execution */
static
void rest_cpu_state() __naked
{
	__asm
#ifdef DBG_USE_TRAMPOLINE
	ld	sp, _stack + DBG_STACK_SIZE
	ld	hl, (#_state + R_PC)
	push	hl	/* resume address */
#ifdef __SDCC_ez80_adl
	ld	hl, 0xc30000 ; use 0xc34000 for jp.s
#else
	ld	hl, 0xc300
#endif
	push	hl	/* JP opcode */
#endif /* DBG_USE_TRAMPOLINE */
	ld	hl, (#_state + R_AF_)
	push	hl
	pop	af
	ld	bc, (#_state + R_BC_)
	ld	de, (#_state + R_DE_)
	ld	hl, (#_state + R_HL_)
	exx
	ex	af, af'	;'
	ld	iy, (#_state + R_IY)
	ld	ix, (#_state + R_IX)
#ifdef __SDCC_ez80_adl
	ld	a, (#_state + R_AF + 2)
	ld	MB, a
	ld	hl, (#_state + R_IR + 1) ;I register
	ld	i, hl
	ld	a, (#_state + R_IR + 0) ; R register
	ld	l, a
#else
	ld	hl, (#_state + R_IR)
	ld	a, h
	ld	i, a
	ld	a, l
#endif /* __SDCC_ez80_adl */
	sub	a, #10	;number of M1 cycles after ld r,a
	xor	a, l
	and	a, #0x7f
	xor	a, l
	ld	r, a
	ld	de, (#_state + R_DE)
	ld	bc, (#_state + R_BC)
	ld	hl, (#_state + R_AF)
	push	hl
	pop	af
	ld	sp, (#_state + R_SP)
#ifndef DBG_USE_TRAMPOLINE
	ld	hl, (#_state + R_PC)
	push	hl
	ld	hl, (#_state + R_HL)
	ret
#else
	ld	hl, (#_state + R_HL)
#ifdef __SDCC_ez80_adl
	jp	#_stack + DBG_STACK_SIZE - 4
#else
	jp	#_stack + DBG_STACK_SIZE - 3
#endif
#endif /* DBG_USE_TRAMPOLINE */
	__endasm;
}
#endif /* __SDCC_gbz80 */
