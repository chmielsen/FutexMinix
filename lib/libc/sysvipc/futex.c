/* 
 * Author: Wojciech Chmiel 305187
 * This file contains implementation of library
 * functions handling futices.
 * Solution is following the pattern of "mutex3"
 * showed in "Futex Are Tricky", by Ulrich Drepper
 */
#define _SYSTEM 1
#define _MINIX 1

#include <minix/com.h>
#include <minix/config.h>
#include <minix/ipc.h>
#include <minix/endpoint.h>
#include <minix/sysutil.h>
#include <minix/const.h>
#include <minix/type.h>
#include <minix/rs.h>

#include <lib.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/futex.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>

PRIVATE int get_ipc_endpt(endpoint_t *pt)
{
    return minix_rs_lookup("ipc", pt);
}

/* initialising futex */
PUBLIC int futex_init(futex_t *f) 
{
    message m;
    endpoint_t ipc_pt;
    
    if(get_ipc_endpt(&ipc_pt) != OK) {
        errno = ENOSYS;
        return -1;
    }
    if(_syscall(ipc_pt, IPC_FUTINIT, &m) != OK) {
        errno = ENOSYS;
        return -1;
    }
    f->id = m.FUTEX_ID;
    f->val = 0;
    return OK;
}

/* destroying futex */
PUBLIC int futex_destroy(futex_t *f)
{
    message m;
    endpoint_t ipc_pt;
    
    if(get_ipc_endpt(&ipc_pt) != OK) {
        errno = ENOSYS;
        return -1;
    }
    m.FUTEX_ID = f->id;
    return _syscall(ipc_pt, IPC_FUTDESTROY, &m);
}

/* process is waiting on futex */
PRIVATE int futex_wait(futex_t *f) {
    message m;
    endpoint_t ipc_pt;

    if(get_ipc_endpt(&ipc_pt) != OK) {
        errno = ENOSYS;
        return -1;
    }
    m.FUTEX_ID = f->id;
    m.FUTEX_VALADR = (long)&f->val;
    return _syscall(ipc_pt, IPC_FUTLOCKADD, &m);
}

/* locking futex, syscall is not necessary if futex
 * was free
 */
PUBLIC int futex_lock(futex_t *f)
{
    int ret, c;

    ret = OK;
    if((c = __sync_val_compare_and_swap(&(f->val), 0, 1)) != 0) {
        if(c != 2)
            c = __sync_lock_test_and_set(&(f->val), 2);
        while(c != 0) {
            ret = futex_wait(f);
            if(ret < 0) break;
            c = __sync_lock_test_and_set(&(f->val), 2);
        }
    }
    return ret;
}

/* waking up one process waiting on futex */
PRIVATE int futex_wake(futex_t *f)
{
    message m;
    endpoint_t ipc_pt;
    
    if(get_ipc_endpt(&ipc_pt) != OK) {
        errno = ENOSYS;
        return -1;
    }
    m.FUTEX_ID = f->id;
    return _syscall(ipc_pt, IPC_FUTUNLOCKWAKE, &m);

}

/* unlocking futex, syscall is not necessary if 
 * noone is waiting
 */
PUBLIC int futex_unlock(futex_t *f)
{
    int r = 0;
    if(__sync_fetch_and_add(&f->val, -1) != 1) {
        f->val = 0;
        r = futex_wake(f);
    }
    return r;
}
