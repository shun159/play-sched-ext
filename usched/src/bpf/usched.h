// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
//
#ifndef __USCHED_H
#define __USCHED_H

#include <stdbool.h>
#ifndef __kptr
#ifdef __KERNEL__
#error "__kptr_ref not defined in the kernel"
#endif
#define __kptr
#endif

#endif
