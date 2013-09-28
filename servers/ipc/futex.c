/* 
 * This file is containing an implementation
 * of syscalls used in operating on futices.
 * Big part of it is desgined to behave like
 * semaphores.
 */

#include "inc.h"

/* Constants are defined here, 
 * so it's easier to find them
 */
/* maximum futex # */
#define FUTMNI 2048
/* maximum futex ID */
#define MAXID 1000000000L

/* list of waiting processes */
struct waiting  {
    endpoint_t who;
};

/* in-server futex structure */
typedef struct {
    long id;                /* id is corresponding to futex_t id */
    unsigned short futcnt;  /* # waiting on futex */
    struct waiting* list;   /* processes waiting on futex */
} fut_struct;

/* array of active futices */
PRIVATE fut_struct fut_list[FUTMNI];
/* number of active futices */
PRIVATE int fut_list_nr = 0;
/* last given ID */
PRIVATE long fut_last_id = 0;

/* finding futex with given id,
 *  NULL if not found
 */
PRIVATE fut_struct* fut_find_id(long id)
{
    int i;

    for(i = 0; i < fut_list_nr; i++)
        if(fut_list[i].id == id)
            return fut_list + i; 
    return NULL;
}


/* getting new id for futex */
PRIVATE long fut_new_id(void)
{
    long new_id = fut_last_id + 1;
    
    while(fut_find_id(new_id) != NULL)
        ++new_id % MAXID;
    return new_id;
}

/*=========================================================================
 *          do_futinit          *
 *=========================================================================*/
/* initliasing futex */
PUBLIC int do_futinit(message* m)
{
    fut_struct* fut;
    long new_id = fut_new_id();

    fut_last_id = new_id;
    m->FUTEX_ID  = new_id;
    fut = &fut_list[fut_list_nr];
    memset(fut, 0, sizeof(fut_struct));
    fut->id = new_id;
    fut->futcnt = 0;
    fut->list = NULL;
    fut_list_nr++;
    return OK;
}

/* removing futex from the fut_list */
PRIVATE void remove_futex(fut_struct *fut)
{
    int i;

    if(fut->list != NULL)
        free(fut->list);
    for(i = 0; i < fut_list_nr; i++)
        if(&fut_list[i] == fut)
            break;
    if(i < fut_list_nr && --fut_list_nr != i)
        fut_list[i] = fut_list[fut_list_nr];
}


/*=========================================================================
 *          do_futdestroy          *
 *=========================================================================*/
/* destroying futex, if any processes are sleeping
 * wake them 
 */
PUBLIC int do_futdestroy(message* m)
{
    long id;
    int i;
    fut_struct* fut;
    endpoint_t who;

    id = m->FUTEX_ID;
    m->m_type = -1;
    fut = fut_find_id(id);
    if(fut->futcnt > 0) {
        for(i = 0; i < fut->futcnt; i++) {
            who = fut->list[i].who;
            sendnb(who, m);
        }
    }
    remove_futex(fut);
    return OK;
}


/*=========================================================================
 *          do_futlockadd          *
 *=========================================================================*/
/* locking futex and adding process to
 * waiting queue
 */
PUBLIC int do_futlockadd(message *m)
{
    fut_struct *fut;
    short val, *futex_val;
    long id = m->FUTEX_ID;

    futex_val = (short*)m->FUTEX_VALADR;
    if(sys_datacopy(who_e, (vir_bytes)m->FUTEX_VALADR,
        SELF_E, (vir_bytes)&val, sizeof(short)) != OK)
        return -1;
    if(val != 2) {
        /* someone has stolen futex, we have to wait again :( */
        m->m_type = 0;
        sendnb(who_e, m);
        return 0;
    }
    fut = fut_find_id(id);
    fut->futcnt++;
    fut->list = realloc(fut->list, sizeof(struct waiting) * fut->futcnt);
    if(!fut->list) {
        printf("IPC: futex waiting list lost");
        return -1;
    }
    fut->list[fut->futcnt - 1].who = who_e;
    return OK;
}



/*=========================================================================
 *          do_futunlockwake          *
 *=========================================================================*/
/* unlocking futex and waking up a process */
PUBLIC int do_futunlockwake(message *m)
{
    fut_struct* fut;
    endpoint_t who;
    long id = m->FUTEX_ID;

    fut = fut_find_id(id);
    m->m_type = OK;
    if(fut->futcnt > 0) {
        /* waking up one process, policy: FIFO */
        who = fut->list[0].who;
        memmove(fut->list, fut->list + 1,
                sizeof(struct waiting) * (fut->futcnt - 1));
        --fut->futcnt;
        sendnb(who, m); 
    }
    return OK;
}
