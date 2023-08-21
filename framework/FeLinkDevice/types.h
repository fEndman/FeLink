#ifndef _FELINK_DEV_TYPES_
#define _FELINK_DEV_TYPES_

#include "userconf.h"

/* 16-bit or 32-bit */
typedef int             FLSINT;
typedef unsigned int    FLUINT;
/* 8-bit */
typedef unsigned char   FLU8;
/* 16-bit */
typedef short           FLS16;
typedef unsigned short  FLU16;
/* 32-bit */
#if FELINK_ARCH == FELINK_C51
typedef long            FLS32;
typedef unsigned long   FLU32;
#else
typedef int             FLS32;
typedef unsigned int    FLU32;
#endif

#endif // !_FELINK_DEV_TYPES_
