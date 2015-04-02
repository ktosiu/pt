#include "pt_include.h"

typedef void *(*_ST_THREAD_PROC)(void *arg);

_ST_THREAD_PROC _pt_st_thread[] = {
    pt_diam_thread,
	pt_m3ua_thread,
	pt_sccp_thread,
    pt_task_thread,
};

void pt_create_st_thread(void)
{
    pt_uint32_t i;

    for (i = 0; i < PT_ARRAY_SIZE(_pt_st_thread); i++)
        st_thread_create(_pt_st_thread[i], NULL, 0, 0);
}

void pt_st_thread_init(void)
{
    if (st_init() < 0) {
        PT_LOG(PTLOG_ERROR, "st_init failed!\n");
        exit(1);
    }

    pt_create_st_thread();
}

