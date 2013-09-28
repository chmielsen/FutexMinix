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

PUBLIC int futex_debug(void)
{
    message m;
    endpoint_t ipc_pt;
    get_ipc_endpt(&ipc_pt);
    _syscall(ipc_pt, IPC_FUTDEBUG, &m);
    return 0;
}

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
    f->val = m.FUTEX_VAL;
    return OK;
}

PUBLIC int futex_destroy(futex_t *f)
{
    message m;
    endpoint_t ipc_pt;
    
    if(get_ipc_endpt(&ipc_pt) != OK) {
        errno = ENOSYS;
        return -1;
    }
    m.FUTEX_ID = f->id;
    m.FUTEX_VAL = f->val;
    return _syscall(ipc_pt, IPC_FUTDESTROY, &m);
}

PUBLIC int futex_lock(futex_t *f)
{
    message m;
    endpoint_t ipc_pt;
    int c;
    if(get_ipc_endpt(&ipc_pt) != OK) {
        errno = ENOSYS;
        return -1;
    }
    m.FUTEX_ID = f->id;
    m.FUTEX_VAL = f->val;
    
    if((c = __sync_val_compare_and_swap(&f->val, 0, 1)) != 0) {
        if(c != 2)
            c = __sync_lock_test_and_set(&f->val, 2);
            while(c != 0){
                if(f->val == 2)
                    _syscall(ipc_pt, IPC_FUTLOCKADD, &m);
                c = __sync_lock_test_and_set(&f->val, 2);
        }
    }
    return OK;
}

PUBLIC int futex_unlock(futex_t *f)
{
    message m;
    endpoint_t ipc_pt;
    int r= 0;
    
    if(get_ipc_endpt(&ipc_pt) != OK) {
        errno = ENOSYS;
        return -1;
    }
    m.FUTEX_ID  = f->id;
    m.FUTEX_VAL = f->val;
 
    if(__sync_fetch_and_add(&f->val, -1) != 1) {
        f->val = 0;
        r = _syscall(ipc_pt, IPC_FUTUNLOCKWAKE, &m);
    }
    return r;
}
