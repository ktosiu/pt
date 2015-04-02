#include "pt_include.h"

pt_pid_t self_pid;
pt_task_pdb_t *pdb_res;
LIST_HEAD(list_pdb_free);
LIST_HEAD(list_pdb_used);

#define _MAX_PDB  10000

void pt_task_int_pdb() 
{
    pt_uint32_t i;
    
    pdb_res = pt_malloc(_MAX_PDB * sizeof(pt_task_pdb_t));
    
    for (i = 0; i < _MAX_PDB; i++)
        list_add_tail(&pdb_res[i].node, &list_pdb_free);
}

pt_task_pdb_t *pt_task_locate_pdb(pt_uint32_t pdb_index, pt_uint32_t pdb_sn)
{
    if (pdb_index >= _MAX_PDB || pdb_res[pdb_index]._sn != pdb_sn)
        return NULL;

    return &pdb_res[pdb_index];
}

pt_task_pdb_t *pt_task_alloc_pdb()
{
    pt_task_pdb_t *pdb;

    if (list_empty(&list_pdb_free)) {
        pdb = list_entry(list_pdb_used.next, pt_task_pdb_t, node);
        pdb->msg->msg_stat_timeout++;
    } else {
        pdb = list_entry(list_pdb_free.next, pt_task_pdb_t, node);
    }

    list_del(&pdb->node);
    list_add_tail(&pdb->node, &list_pdb_used);

    /**/
    pdb->ss7_local_invokeinfo_num = 0;
    pdb->ss7_peer_invokeinfo_num = 0;

    pdb->_index = (pt_uint16_t)(pdb - pdb_res);
    pdb->_sn = (pt_uint16_t)st_utime();

    return pdb;
}

void pt_task_free_pdb(pt_task_pdb_t *pdb)
{
    list_del(&pdb->node);
    list_add_tail(&pdb->node, &list_pdb_free);

    pdb->_sn = 0;
}

#define _PDB_AGEING_TIME 6000000
void pt_task_ageing_pdb(void)
{
    pt_task_pdb_t *pdb;
    st_utime_t current;

    current = st_utime();
    while (!list_empty(&list_pdb_used)) {
        pdb = list_entry(list_pdb_used.next, pt_task_pdb_t, node);
        if (current - pdb->send_time < _PDB_AGEING_TIME)
            break;

        pdb->msg->msg_stat_timeout++;
        pt_task_free_pdb(pdb);
    }
}

void pt_task_calc_rtt(pt_task_pdb_t *pdb)
{
    st_utime_t rtt;

    rtt = (st_utime() - pdb->send_time) / 1000;

    if (rtt > pdb->msg->msg_stat_maxrtt)
        pdb->msg->msg_stat_maxrtt = rtt;

    if (rtt < pdb->msg->msg_stat_minrtt || pdb->msg->msg_stat_minrtt == 0)
        pdb->msg->msg_stat_minrtt = rtt;

    pdb->msg->msg_stat_totalrttnum++;
    pdb->msg->msg_stat_totalrtt += rtt;
}

void pt_task_calc_rate(pt_uc_msgflow_t *msgflow, pt_uint32_t usecond)
{
    pt_uc_inst_t *inst;
    pt_uc_msg_t *msg;
    list_head_t *pos_inst;
    list_head_t *pos_msg;
    pt_uint64_t interval_count;

    list_for_each(pos_inst, &msgflow->list_inst) {
        inst = list_entry(pos_inst, pt_uc_inst_t, node);
        list_for_each(pos_msg, &inst->list_msg) {
            msg = list_entry(pos_msg, pt_uc_msg_t, node);
            if (usecond > 0) {
                interval_count = msg->msg_stat_total - msg->msg_stat_totallast;
                msg->msg_stat_rate = (interval_count * 1000000)/usecond;
            } else {
                msg->msg_stat_rate = 0;
            }

            msg->msg_stat_totallast = msg->msg_stat_total;
        }
    }
}

void pt_task_reset_stat(pt_uc_msgflow_t *msgflow)
{
    pt_uc_inst_t *inst;
    pt_uc_msg_t *msg;
    list_head_t *pos_inst;
    list_head_t *pos_msg;

    msgflow->execute_times = 0;
    msgflow->execute_count = 0;

    list_for_each(pos_inst, &msgflow->list_inst) {
        inst = list_entry(pos_inst, pt_uc_inst_t, node);
        list_for_each(pos_msg, &inst->list_msg) {
            msg = list_entry(pos_msg, pt_uc_msg_t, node);

            msg->msg_stat_totallast = 0;
            msg->msg_stat_total = 0;
            msg->msg_stat_rate = 0;
            msg->msg_stat_success = 0;
            msg->msg_stat_fail = 0;
            msg->msg_stat_timeout = 0;
            msg->msg_stat_maxrtt = 0;
            msg->msg_stat_minrtt = 0;
            msg->msg_stat_totalrtt = 0;
            msg->msg_stat_totalrttnum = 0;
        }
    }
}

pt_bool_t pt_task_last_msg(pt_uc_msg_t *msg)
{
    return msg->node.next == &msg->inst->list_msg;
}

pt_bool_t pt_task_last_inst(pt_uc_inst_t *inst)
{
    return inst->node.next == &inst->msgflow->list_inst;
}

pt_int32_t pt_task_send_msg(pt_uc_msg_t *msg, pt_uint64_t seq)
{
    PT_LOG(PTLOG_DEBUG, "msg_name = %s, msg_type = %d, seq = %lu.",
        msg->msg_name, msg->msg_type, seq);

    if (msg->msg_type == MSG_TYPE_DIM) {
        return pt_task_send_diam_arg_msg(msg, seq);
    }
    else {
        return pt_task_send_ss7_begin_msg(msg, seq);
    }
}

#define _DURATION ((pt_uint32_t)20000) /*mi·cro·sec·ond*/
#define _INTERVAL ((pt_uint32_t)(1000000/_DURATION))
void *pt_task_send_thread(void *arg)
{
    pt_uint64_t i, j;
    pt_uint64_t interval_rate;
    pt_uint64_t interval_cover;
    pt_uint64_t interval_count;
    pt_uc_msgflow_t *msgflow;
    pt_uc_msg_t *msg;
    st_utime_t last_time;
    st_utime_t accumulate_time;
    pt_uint64_t erratum;        

    msg = (pt_uc_msg_t *)arg;
    msgflow = msg->inst->msgflow;

    if (msgflow->delay)
        st_usleep((st_utime_t)msgflow->delay * 1000);

    last_time = st_utime();
    accumulate_time = last_time;

    for (;;) {
        interval_rate = (pt_uint64_t)(msgflow->rate / _INTERVAL);
        interval_cover = (pt_uint64_t)(msgflow->rate % _INTERVAL);
        interval_count = interval_rate;

        /*由于usleep的误差, 对发送消息进行速率进行校正*/
        if (msgflow->rate > 0) {
            erratum  = 1000000 / msgflow->rate;
            if (last_time > accumulate_time && last_time - accumulate_time >= erratum) {
                interval_cover += ((last_time - accumulate_time) + (erratum >> 1))/erratum;
                accumulate_time = last_time;
            }
        }

        for (i = 0; i < _INTERVAL && msgflow->execute_times < msgflow->times; i++) {
            st_usleep(_DURATION);

            if (msgflow->runing_state == PAUSE)
                continue;

            if (msgflow->runing_state == STOP)
                break;
            
            if (i == (_INTERVAL - 1))
                interval_count += interval_cover;

            for (j = 0; j < interval_count && msgflow->execute_times < msgflow->times; j++) {
                if (pt_task_send_msg(msg, msgflow->execute_count) < 0)
                    break;
                
                msgflow->execute_count++;

                if (msgflow->execute_count == msgflow->count) {
                    msgflow->execute_count = 0;
                    msgflow->execute_times++;
                }
            }
        }

        if (msgflow->execute_times == msgflow->times) {
            PT_LOG(PTLOG_INFO, "execute over, msgflow_name = %s, times = %lu, execute_times = %lu",
                msgflow->msgflow_name, msgflow->times, msgflow->execute_times);
            break;
        }

        last_time = st_utime();
        accumulate_time += 1000000;

        if (msgflow->runing_state == STOP) 
            break;
    }

    msgflow->runing_state = STOP;
    msgflow->st_thread = NULL;

    return NULL;
}

void *pt_task_thread(void *arg)
{
    list_head_t *pos;
    pt_uc_msgflow_t *msgflow;

    pt_task_int_pdb();
    pt_diam_register_up(pt_task_recv_diam_msg);
    pt_sccp_register_up(pt_task_recv_ss7_msg);
    self_pid = pt_getpid();

    for (;;) {
        st_usleep(1000000);
        list_for_each(pos, &list_msgflow) {
            msgflow = list_entry(pos, pt_uc_msgflow_t, node);
            pt_task_calc_rate(msgflow, 1000000);
        }
        pt_task_ageing_pdb();
    }

    return NULL;
}

void pt_task_start(pt_uc_msgflow_id_t msgflow_id, pt_uint64_t count, pt_uint64_t rate, 
            pt_uint64_t times, pt_uint32_t delay)
{
    list_head_t *pos;
    pt_uc_msgflow_t *msgflow;
    pt_uc_inst_t *inst;
    pt_uc_msg_t *msg;

    list_for_each(pos, &list_msgflow) {
        msgflow = list_entry(pos, pt_uc_msgflow_t, node);
        if (msgflow_id != msgflow)
            continue;

        if (msgflow->runing_state == RUNING || msgflow->runing_state == PAUSE) {
            PT_LOG(PTLOG_ERROR, "already in executing, runing_state = %d, sgflow_name = %s.", 
                msgflow->runing_state, msgflow->msgflow_name);
            break;
        }

        if (list_empty(&msgflow->list_inst)) {
            PT_LOG(PTLOG_ERROR, "empty inst list, msgflow_name = %s", msgflow->msgflow_name);
            break;
        }
        
        inst = list_entry(msgflow->list_inst.next, pt_uc_inst_t, node);
        if (list_empty(&inst->list_msg)) {
            PT_LOG(PTLOG_ERROR, "empty msg list, inst_name = %s.", inst->inst_name);
            break;
        }
        
        msg = list_entry(inst->list_msg.next, pt_uc_msg_t, node);
        if (msg->msg_action != MSG_ACTION_SEND) {
            PT_LOG(PTLOG_ERROR, "is recv msg, msgname = %s.", msg->msg_name);
            break;
        }

        /*add_msgflow和start流程同时设置delay时,以start为准*/
        if (delay != 0)
            msgflow->delay = delay;

        msgflow->rate  = rate;
        msgflow->count = count;
        msgflow->times = times;

        pt_task_reset_stat(msgflow);

        msgflow->st_thread = st_thread_create(pt_task_send_thread, (void *)msg, 0, 0);
        if (msgflow->st_thread == NULL)
            PT_LOG(PTLOG_ERROR, "create st thread failed, msgflow_name = %s, inst_name = %s.",
                msgflow->msgflow_name, inst->inst_name);

        msgflow->runing_state = RUNING;
        PT_LOG(PTLOG_INFO, "msgflow execute, msgflow_name = %s.", msgflow->msgflow_name);
        break;
    }

    if (pos == &list_msgflow)
        PT_LOG(PTLOG_ERROR, "invalid msgflow_id = %p\n", msgflow_id);
}

void pt_task_stop(pt_uc_msgflow_id_t msgflow_id)
{
    list_head_t *pos;
    pt_uc_msgflow_t *msgflow;

    list_for_each(pos, &list_msgflow) {
        msgflow = list_entry(pos, pt_uc_msgflow_t, node);
        if (msgflow_id != msgflow)
            continue;
        msgflow->runing_state = STOP;
        break;
    }

    if (pos == &list_msgflow) {
        PT_LOG(PTLOG_ERROR, "invalid msgflow_id = %p\n", msgflow_id);
    }
}

void pt_task_pause(pt_uc_msgflow_id_t msgflow_id)
{
    list_head_t *pos;
    pt_uc_msgflow_t *msgflow;

    list_for_each(pos, &list_msgflow) {
        msgflow = list_entry(pos, pt_uc_msgflow_t, node);
        if (msgflow_id != msgflow)
            continue;

        if (msgflow->runing_state != RUNING) {
            PT_LOG(PTLOG_ERROR, "msgflow is not in RUNING, runing_state = %d.", 
                msgflow->runing_state);
            break;
        }
        
        msgflow->runing_state = PAUSE;
        break;
    }

    if (pos == &list_msgflow)
        PT_LOG(PTLOG_ERROR, "invalid msgflow_id = %p\n", msgflow_id);
}

void pt_task_continue(pt_uc_msgflow_id_t msgflow_id)
{
    list_head_t *pos;
    pt_uc_msgflow_t *msgflow;

    list_for_each(pos, &list_msgflow) {
        msgflow = list_entry(pos, pt_uc_msgflow_t, node);
        if (msgflow_id != msgflow)
            continue;

        if (msgflow->runing_state != PAUSE) {
            PT_LOG(PTLOG_ERROR, "msgflow is not in PAUSE, runing_state = %d.", 
                msgflow->runing_state);
            break;
        }
        
        msgflow->runing_state = RUNING;
        break;
    }

    if (pos == &list_msgflow)
        PT_LOG(PTLOG_ERROR, "invalid msgflow_id = %p\n", msgflow_id);
}

void pt_task_update(pt_uc_msgflow_id_t msgflow_id, pt_uint64_t count, pt_uint64_t rate, pt_uint64_t times)
{
    list_head_t *pos;
    pt_uc_msgflow_t *msgflow;

    list_for_each(pos, &list_msgflow) {
        msgflow = list_entry(pos, pt_uc_msgflow_t, node);
        if (msgflow_id != msgflow)
            continue;

        if (msgflow->runing_state != RUNING) {
            PT_LOG(PTLOG_ERROR, "msgflow is not in RUNING, runing_state = %d.", 
                msgflow->runing_state);
            break;
        }
        msgflow->rate  = rate;
        msgflow->count = count;
        msgflow->times = times;
        break;
    }

    if (pos == &list_msgflow)
        PT_LOG(PTLOG_ERROR, "invalid msgflow_id = %p\n", msgflow_id);
}

