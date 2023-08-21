#ifndef _FELINK_DEV_USERCONF_
#define _FELINK_DEV_USERCONF_

#define FELINK_DEFAULT_NAME  "fldev0"
#define FELINK_TYPE  0x0000

#define FELINK_ARCH  FELINK_C51
#define FELINK_ARM   1
#define FELINK_C51   2

#define FELINK_BUF_SIZE FELINK_RECOMMENDED_BUF_SIZE

#define uECC_CURVE uECC_secp160r1

#define uECC_SQUARE_FUNC 0
#if FELINK_ARCH == FELINK_C51
  #define FELINK_ATTR_ALIGN
  #define FELINK_C51_REENTRANT reentrant
  #define FELINK_BIG_ENDIAN
  #define __STDC_VERSION__	198900L
  #define uECC_WORD_SIZE 1
  #define uECC_PLATFORM uECC_arch_other
  #define uECC_ASM uECC_asm_none
  #define asm_clear 0
  #define asm_isZero 0
  #define asm_testBit 0
  #define asm_numBits 0
  #define asm_set 0
  #define asm_cmp 0
  #define asm_rshift0 0
  #define asm_rshift1 0
  #define asm_add 0
  #define asm_sub 0
  #define asm_mult 0
  #define asm_square 0
  #define asm_modAdd 0
  #define asm_modSub 0
  #define asm_modSub_fast 0
  #define asm_mmod_fast 0
  #define asm_modInv 0
#elif FELINK_ARCH == FELINK_ARM
  #define FELINK_ATTR_ALIGN __attribute__((aligned (4)))
  #define FELINK_C51_REENTRANT
  #undef FELINK_BIG_ENDIAN
#else
  #define FELINK_ATTR_ALIGN
  #define FELINK_C51_REENTRANT
  #undef FELINK_BIG_ENDIAN
#endif

#endif // !_FELINK_DEV_USERCON
