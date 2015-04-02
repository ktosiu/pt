#include "pt_include.h"
#include <pthread.h>
#include "./lib/ots-1.2/interface.h"

struct proc_method_s *pmf = NULL; /*functions from core*/
pthread_t _st_thread_id;
char _cfg[(1 << 20)];
long _total_send;
long _already_send;
long _count_send;

typedef void *(_THREAD_FUNC)(void *);
int pt_ots_create_thread(
                _THREAD_FUNC thread_func, 	/* thread function addr */
                void *parg, 		    /* function arg */
                unsigned int stack, 	/* function stack size */
                pthread_t* thread_id)	/* return thread id */
{
	pthread_attr_t thread_attr;

	pthread_attr_init(&thread_attr);
	
#ifdef THREAD_TYPE_DETACHED
    pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
#else
    pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_JOINABLE);
#endif
	
	pthread_attr_setscope(&thread_attr, PTHREAD_SCOPE_SYSTEM);
	if (stack > 0)
	{
		pthread_attr_setstacksize(&thread_attr, stack);
	}
	
	if (0 != pthread_create(thread_id, &thread_attr, (void *(*)(void *))thread_func, parg)) 
	{
        return -0xff;
	} 
	else 
	{
        return 0;
	}
}

void pt_ots_destory_thread(pthread_t thread_id)
{
#ifdef THREAD_TYPE_DETACHED
    /* 如果创建的是分离线程，休眠一会等待子线程优雅地结束 */
    Sleep(1000);
#else
    /* 如果创建的是非分离线程，等待子线程结束 */
    pthread_join(thread_id, NULL);
#endif
}

void pt_ots_send_msg(unsigned long seq)
{
    pt_uc_msgflow_t *msgflow;
    pt_uc_inst_t *inst;
    pt_uc_msg_t *msg;
    list_head_t *pos;

    list_for_each(pos, &list_msgflow) {
        msgflow = list_entry(pos, pt_uc_msgflow_t, node);
        if (list_empty(&msgflow->list_inst))
            continue;
        inst = list_entry(msgflow->list_inst.next, pt_uc_inst_t, node);
        if (list_empty(&inst->list_msg))
            continue;
        msg = list_entry(inst->list_msg.next, pt_uc_msg_t, node);
        if (msg->msg_type == MSG_TYPE_DIM) {
            if (msg->msg_action != MSG_ACTION_SEND)
                continue;
            if (!pt_diam_get_cmd_flg_R(msg->msg_data, msg->msg_data_len))
                continue;
            PT_LOG(PTLOG_DEBUG, "send msgflow_name = %s, inst_name = %s, msg_name = %s, seq = %lu.", 
                    msgflow->msgflow_name, inst->inst_name, msg->msg_name, seq);
            pt_task_send_diam_arg_msg(msg, seq);
        } else {
            ;
        }
    }
}

typedef struct {
    list_head_t node;
    int _kvp_key;
    long *_kvp_count;
}_ots_kvp_t;


LIST_HEAD(list_ots_kvp);

void pt_ots_create_kvp(char *key, long *count)
{
    _ots_kvp_t *ots_kvp;

    ots_kvp = pt_malloc(sizeof(_ots_kvp_t));
    if (ots_kvp == NULL) {
        PT_LOG(PTLOG_ERROR, "malloc kvp failed!");
        return;
    }

    ots_kvp->_kvp_key = pmf->_openKVP(key, TYPE_LONG, KVP_COUNT_TPS);
    ots_kvp->_kvp_count = count;
    list_add_tail(&ots_kvp->node, &list_ots_kvp);
}

void pt_ots_create_kvp_run(void)
{
    pt_ots_create_kvp("0_ots_run", &_total_send); 
}

void pt_ots_create_kvp_msg(void)
{
    char strbuf[256];
    pt_uc_msgflow_t *msgflow;
    pt_uc_inst_t *inst;
    pt_uc_msg_t *msg;
    list_head_t *msgflow_pos;
    list_head_t *inst_pos;
    list_head_t *msg_pos;
    int i;

    i = 0;
    list_for_each(msgflow_pos, &list_msgflow) {
        msgflow = list_entry(msgflow_pos, pt_uc_msgflow_t, node);
        list_for_each(inst_pos, &msgflow->list_inst) {
            inst = list_entry(inst_pos, pt_uc_inst_t, node);
            list_for_each(msg_pos, &inst->list_msg) {
                i++;
                msg = list_entry(msg_pos, pt_uc_msg_t, node);
                sprintf(strbuf, "%d_%s_success", i, msg->msg_name);
                pt_ots_create_kvp(strbuf, (long *)&msg->msg_stat_success);
                /*
                sprintf(strbuf, "%d_%s_fail", i, msg->msg_name);
                pt_ots_create_kvp(strbuf, (long *)&msg->msg_stat_fail);
                sprintf(strbuf, "%d_%s_timeout", i, msg->msg_name);
                pt_ots_create_kvp(strbuf, (long *)&msg->msg_stat_timeout);
                */
            }
        }
    }
}

void pt_ots_open_kvp(void)
{
    pt_ots_create_kvp_run();
    pt_ots_create_kvp_msg();
}

void pt_ots_update_kvp(void)
{
    _ots_kvp_t *ots_kvp;
    list_head_t *pos;
    list_for_each(pos, &list_ots_kvp) {
        ots_kvp = list_entry(pos, _ots_kvp_t, node);
        pmf->_setKVP(ots_kvp->_kvp_key, TYPE_LONG, *ots_kvp->_kvp_count);
    }
}

void pt_ots_close_kvp(void)
{
    _ots_kvp_t *ots_kvp;

    while (!list_empty(&list_ots_kvp)) {
        ots_kvp = list_entry(list_ots_kvp.next, _ots_kvp_t, node);
        pmf->_closeKVP(ots_kvp->_kvp_key);
        list_del(&ots_kvp->node);
        pt_free(ots_kvp);
    }
}

void *pt_ots_st_l_thread(void *arg)
{
    long interval_send;
    pt_diam_dump();
    pt_uc_dump();

    pt_ots_open_kvp(); 

    if (_count_send == 0)
        _count_send = 1;

    for (;;) {
        interval_send = 3000;
        while (_already_send < _total_send && interval_send > 0) {
            pt_ots_send_msg(_already_send % _count_send);
            _already_send++;
            interval_send--;
            PT_LOG(PTLOG_DEBUG, "send %lu/%lu, --pid = %lu --tid = %lu.", 
                    _already_send, _total_send, pt_getpid(), pt_gettid());
        }
        st_usleep(50000);/*50ms*/
        pt_ots_update_kvp();
    }
}

void *pt_ots_st_p_thread(void *arg)
{
    pt_st_thread_init();

    if (pt_xml_load_ots(_cfg, strlen(_cfg)) < 0) {
        PT_LOG(PTLOG_ERROR, "load cfg failed!");
        return NULL;
    }

    _count_send = pt_xml_load_ots_count(_cfg, strlen(_cfg));

    st_thread_create(pt_ots_st_l_thread, NULL, 0, 0);

    for (;;) {
        st_usleep(1000000);
    }
    return NULL;
}

static int pt_ots_mod_init(const char *cfg, int size)
{
    PT_LOG(PTLOG_DEBUG, "load cfg(%d):\n%s", size, cfg);
    strncpy(_cfg, cfg, sizeof(_cfg));

    return 0;
}

static void pt_ots_mod_destroy(void)
{
    pt_ots_destory_thread(_st_thread_id);
}

static int pt_ots_init(struct proc_method_s *method)
{
    if (_st_thread_id != 0) {
        PT_LOG(PTLOG_ERROR, "already inited, --pid = %lu --tid = %lu.", 
                pt_getpid(), pt_gettid());
        return 0;
    }

    pmf = method;
    _total_send = 0;
    _already_send = 0;

    if (pt_ots_create_thread(pt_ots_st_p_thread, NULL, 0, &_st_thread_id) < 0) {
        PT_LOG(PTLOG_ERROR, "create st thread failed!");
        return -0xfe;
    }

    PT_LOG(PTLOG_DEBUG, "init ok, --pid = %lu --tid = %lu.", 
                pt_getpid(), pt_gettid());

    return 0;
}

static int pt_ots_run(void* param)
{ 
    pmf->_status(0);
    _total_send++;
    PT_LOG(PTLOG_DEBUG, "run %lu/%lu.", _already_send, _total_send);
    return 0;
}

static void pt_ots_exit(void)
{
    pt_ots_close_kvp();
    PT_LOG(PTLOG_DEBUG, "exit ok.");
}

static proc_export_t  pt_ots_proc = {
    pt_ots_init,
    pt_ots_run,    
    pt_ots_exit
};

static char *pt_ots_state_meanings[] = {"send"};    

struct module_exports exports = {
	"pt_ots",
	"0.0.1",
	"standard",
	TYPE_RELOAD,
    1,
    pt_ots_state_meanings,
	pt_ots_mod_init,
	NULL,
	pt_ots_mod_destroy,
	&pt_ots_proc
};

/* OTS 内部协商 */
int get_ifversion(void)
{ 
    return VERSION_2; 
}

