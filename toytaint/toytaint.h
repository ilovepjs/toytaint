#ifndef TOYTAINT_H_
#define TOYTAINT_H_

#include "valgrind.h"
#include <sys/syscall.h>

typedef enum {
	VG_USERREQ__TOYTAINT_MAKE_MEM_TAINTED,
	VG_USERREQ__TOYTAINT_MAKE_MEM_UNTAINTED
} Vg_ToytaintClientRequest;

// Tainting/Untainting memory
#define TT_MAKE_MEM_TAINTED(addr, size) \
		VALGRIND_DO_CLIENT_REQUEST_STMT(VG_USERREQ__TOYTAINT_MAKE_MEM_TAINTED,addr,size,0,0,0); \

#define TT_MAKE_MEM_UNTAINTED(addr, size) \
		VALGRIND_DO_CLIENT_REQUEST_STMT(VG_USERREQ__TOYTAINT_MAKE_MEM_UNTAINTED,addr,size,0,0,0); \

#endif 

/* TOYTAINT_H_ */
