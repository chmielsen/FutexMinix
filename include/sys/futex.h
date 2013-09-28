#ifndef _SYS_FUTEX_H
#define _SYS_FUTEX_H

#include <sys/types.h>

typedef struct {
    /* futex ID */
    long id;
    /* 
     * val==0 - futex free
     * val==1 - futex locked, but noone is waiting
     * val==2 - futex locked, someone is waiting
     */
    short val;
} futex_t;

/* Futex initialize and destroy functions */
_PROTOTYPE( int futex_init, (futex_t *futex));
_PROTOTYPE( int futex_destroy, (futex_t *futex));

/* Lock and unlock futex */
_PROTOTYPE( int futex_lock, (futex_t *futex));
_PROTOTYPE( int futex_unlock, (futex_t *futex));

#endif /* _SYS_FUTEX_H */
