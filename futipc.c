#include "inc.h"


/* maximum futex # */
#define FUTMNI 2056
#define MAXID 1000000000L

struct waiting  {
    endpoint_t who;
    int val;
};

typedef struct {
    long id;                /* id is corresponding to futex_t id */
    unsigned short futcnt;  /* # waiting on futex */
    struct waiting* list;   /* processes waiting on futex */
} fut_struct;

PRIVATE fut_struct fut_list[FUTMNI];
PRIVATE int fut_list_nr = 0;
PRIVATE long fut_last_id = 0;
PRIVATE long syscallcnt = 0;

PUBLIC int do_futdebug(void)
{
    int i;
    printf("Wywolan systemowych: %ld\n", syscallcnt);
    printf("Zadeklarowanych %d futeksow.\n", fut_list_nr);
    for(i = 0; i < fut_list_nr; i++) {
        printf("ID: %d, czekajacych procesow: %d, ", fut_list[i].id, fut_list[i].futcnt);
        if(fut_list[i].list == NULL)
            printf("pamiec: NULL\n");
        else printf("pamiec: OK\n");
    }
    return OK;
}

PRIVATE fut_struct* fut_find_id(long id)
{
    int i;
    for(i = 0; i < fut_list_nr; i++)
        if(fut_list[i].id == id)
            return fut_list + i; 
    return NULL;
}

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
PUBLIC int do_futinit(message* m)
{
    fut_struct* fut;
    long new_id = fut_new_id();

    syscallcnt++;
    fut_last_id = new_id;
    m->FUTEX_ID  = new_id;
    m->FUTEX_VAL = 0;
    fut = &fut_list[fut_list_nr];
    memset(fut, 0, sizeof(fut_struct));
    fut->id = new_id;
    fut->futcnt = 0;
    fut->list = NULL;
    fut_list_nr++;
    return OK;
}

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
PUBLIC int do_futdestroy(message* m)
{
    long id;
    fut_struct* fut;

    syscallcnt++;
    id = m->FUTEX_ID;
    fut = fut_find_id(id);
    if(fut->futcnt > 0)
        return -1;
    remove_futex(fut);
    return OK;
}


/*=========================================================================
 *          do_futlockadd          *
 *=========================================================================*/
PUBLIC int do_futlockadd(message *m)
{
    fut_struct *fut;
    long id = m->FUTEX_ID;

    syscallcnt++;
    fut = fut_find_id(id);
    fut->futcnt++;
    fut->list = realloc(fut->list, sizeof(struct waiting) * fut->futcnt);
    if(!fut->list) {
        printf("IPC: futex waiting list lost");
        return -1;
    }
    fut->list[fut->futcnt - 1].who = who_e;
    return 0;
}



/*=========================================================================
 *          do_futunlockwake          *
 *=========================================================================*/
PUBLIC int do_futunlockwake(message *m)
{
    fut_struct* fut;
    endpoint_t who;
    long id = m->FUTEX_ID;

    syscallcnt++;
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
    sendnb(who_e, m);
}

