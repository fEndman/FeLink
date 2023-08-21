#ifndef _FELINK_DEV_TYPES_
#define _FELINK_DEV_TYPES_

#include "userconf.h"

/* 16-bit or 32-bit */
typedef int             flsint;
typedef unsigned int    fluint;
/* 8-bit */
typedef unsigned char   flu8;
/* 16-bit */
typedef short           fls16;
typedef unsigned short  flu16;
/* 32-bit */
#if FELINK_ARCH == FELINK_C51
typedef long            fls32;
typedef unsigned long   flu32;
#else
typedef int             fls32;
typedef unsigned int    flu32;
#endif

#endif // !_FELINK_DEV_TYPES_
