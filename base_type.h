
#ifndef __BASE_TYPE_DEF_H__
#define __BASE_TYPE_DEF_H__ 1

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif
//#define WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef HANDLE	HDEV;

#define __func__ __FUNCTION__

#else /* linux */
#include <stdbool.h>
#include <stddef.h>

#ifdef DRIVER_SDKEY
typedef int		HDEV;
#endif

typedef void*	HANDLE;
typedef short BOOL;

#define _GNU_SOURCE
#define __USE_GNU

#endif

typedef unsigned char	 u8;
typedef unsigned short	u16;
typedef unsigned int	 u32;
typedef unsigned long ULONG;
typedef unsigned char BYTE;
typedef char * LPSTR;
typedef unsigned long DWORD;
typedef unsigned char * PBYTE;
typedef int INT_PTR;

#define NULL_PTR ((void *)0)

//#include <xchar.h>

#endif /* __BASE_TYPE_DEF_H__ */
