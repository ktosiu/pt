#include "pt_include.h"

LIST_HEAD(list_msgflow);

pt_uc_msgflow_t *pt_uc_alloc_msgflow(void)
{
    pt_uc_msgflow_t *msgflow;

    msgflow = pt_malloc(sizeof(pt_uc_msgflow_t));
    if (msgflow == NULL) {
        PT_LOG(PTLOG_ERROR, "pt_malloc msgflow failed!");
        return NULL;
    }
    memset(msgflow, 0, sizeof(pt_uc_msgflow_t));
    INIT_LIST_HEAD(&msgflow->list_inst);

    list_add_tail(&msgflow->node, &list_msgflow);

    return msgflow;
}

void pt_uc_free_msgflow(pt_uc_msgflow_t *msgflow)
{
    list_del(&msgflow->node);

    pt_free(msgflow->msgflow_name);
    pt_free(msgflow);
}

pt_uc_msgflow_id_t pt_uc_locate_msgflow(char *msgflow_name)
{
    list_head_t *pos;
    pt_uc_msgflow_t *msgflow;

    list_for_each(pos, &list_msgflow) {
        msgflow = list_entry(pos, pt_uc_msgflow_t, node);

        if (strlen(msgflow->msgflow_name) != strlen(msgflow_name))
            continue;

        if (strcmp(msgflow->msgflow_name, msgflow_name))
            continue;

        return msgflow;
    }

    return NULL;
}

pt_uc_inst_t *pt_uc_alloc_inst(pt_uc_msgflow_t *msgflow)
{
    pt_uc_inst_t *inst;

    inst = pt_malloc(sizeof(pt_uc_inst_t));
    if (inst == NULL) {
        PT_LOG(PTLOG_ERROR, "pt_malloc inst failed!");
        return NULL;
    }
    memset(inst, 0, sizeof(pt_uc_inst_t));
    inst->msgflow = msgflow;
    INIT_LIST_HEAD(&inst->list_msg);

    list_add_tail(&inst->node, &msgflow->list_inst);

    return inst;
}

void pt_uc_free_inst(pt_uc_inst_t *inst)
{
    list_del(&inst->node);

    pt_free(inst->inst_name);
    pt_free(inst);
}

pt_uc_msg_t *pt_uc_alloc_msg(pt_uc_inst_t *inst)
{
    pt_uc_msg_t *msg;

    msg = pt_malloc(sizeof(pt_uc_msg_t));
    if (msg == NULL) {
        PT_LOG(PTLOG_ERROR, "pt_malloc msg failed!");
        return NULL;
    }
    memset(msg, 0, sizeof(pt_uc_msg_t));
    msg->inst = inst;

    INIT_LIST_HEAD(&msg->list_msg_uid);
    INIT_LIST_HEAD(&msg->list_msg_replace);
    INIT_LIST_HEAD(&msg->list_msg_condition);

    list_add_tail(&msg->node, &inst->list_msg);

    return msg;
}

void pt_uc_free_msg(pt_uc_msg_t *msg)
{
    pt_uc_matchinfo_t *matchinfo;

    list_del(&msg->node);

    while (!list_empty(&msg->list_msg_uid)) {
        matchinfo = list_entry(msg->list_msg_uid.next, pt_uc_matchinfo_t, node);
        list_del(&matchinfo->node);
        pt_free(matchinfo);
    }

    while (!list_empty(&msg->list_msg_replace)) {
        matchinfo = list_entry(msg->list_msg_replace.next, pt_uc_matchinfo_t, node);
        list_del(&matchinfo->node);
        pt_free(matchinfo);
    }

    while (!list_empty(&msg->list_msg_condition)) {
        matchinfo = list_entry(msg->list_msg_condition.next, pt_uc_matchinfo_t, node);
        list_del(&matchinfo->node);
        pt_free(matchinfo);
    }

    pt_free(msg->msg_name);
    pt_free(msg);
}

pt_uc_msg_id_t pt_uc_add_msg(pt_uc_inst_id_t inst_id,
                    pt_char_t *msg_name, pt_int32_t msg_action, pt_int32_t msg_type,
                    pt_uint8_t *msg_data, pt_int32_t msg_data_len)
{
    pt_uc_msg_t *msg;

    msg = pt_uc_alloc_msg(inst_id);
    if (msg != NULL) {
        msg->msg_name = pt_strdup(msg_name);
        msg->msg_action = msg_action;
        msg->msg_type = msg_type;

        msg->msg_data_len = msg_data_len;
        memcpy(msg->msg_data, msg_data, (pt_uint32_t)msg_data_len);
    }

    return msg;
}

void pt_uc_del_msg(pt_uc_msg_id_t msg_id)
{
    pt_uc_msg_t *msg;

    msg = msg_id;

    pt_uc_free_msg(msg);
}

void pt_uc_set_msg_linkid(pt_uc_msg_id_t msg_id, pt_uint32_t msg_link_id)
{
    pt_uc_msg_t *msg;

    msg = msg_id;

    msg->msg_link_id = msg_link_id;
}

void pt_uc_set_msg_param_ss7(pt_uc_msg_id_t msg_id,
                pt_uint8_t acver, pt_uint8_t acvalue, pt_uint8_t comptype, pt_uint8_t opcode,
                pt_char_t *cda_code, pt_uint8_t cda_ssn, pt_char_t *cga_code, pt_uint8_t cga_ssn)
{
    pt_uc_msg_t *msg;

    msg = msg_id;
    msg->msg_ss7_acver = acver;
    msg->msg_ss7_acvalue = acvalue;
    msg->msg_ss7_comptype = comptype;
    msg->msg_ss7_opcode = opcode;
    msg->msg_ss7_cda_ssn = cda_ssn;
    msg->msg_ss7_cga_ssn = cga_ssn;
    pt_str2bcds(cda_code, (pt_int32_t)strlen(cda_code), msg->msg_ss7_cda_code, NULL);
    pt_str2bcds(cga_code, (pt_int32_t)strlen(cga_code), msg->msg_ss7_cga_code, NULL);
}

void pt_uc_add_matchinfo(list_head_t *plist,
                pt_int32_t data_type, pt_char_t *data, pt_int32_t data_len,
                pt_char_t *strtag)
{
    pt_uc_matchinfo_t *matchinfo;

    matchinfo = pt_malloc(sizeof(pt_uc_matchinfo_t));
    if (matchinfo == NULL) {
        PT_LOG(PTLOG_ERROR, "malloc uid buffer failed!");
        return;
    }
    memset(matchinfo, 0, sizeof(pt_uc_matchinfo_t));

    strcpy(matchinfo->tag, strtag);
    matchinfo->data_type = data_type;
    memcpy(matchinfo->data, data, (pt_uint32_t)data_len);
    matchinfo->data_len = data_len;

    list_add_tail(&matchinfo->node, plist);
}

void pt_uc_add_msg_uid(pt_uc_msg_id_t msg_id,
                pt_int32_t uid_type, pt_char_t *uid, pt_int32_t uid_len,
                pt_char_t *strtag)
{
    pt_uc_add_matchinfo(&((pt_uc_msg_t *)msg_id)->list_msg_uid,
            uid_type, uid, uid_len, strtag);
}

void pt_uc_add_msg_replace(pt_uc_msg_id_t msg_id,
                pt_int32_t replace_type, pt_char_t *replace, pt_int32_t replace_len,
                pt_char_t *strtag)
{
    pt_uc_add_matchinfo(&((pt_uc_msg_t *)msg_id)->list_msg_replace,
            replace_type, replace, replace_len, strtag);
}

void pt_uc_add_msg_condition(pt_uc_msg_id_t msg_id,
                pt_int32_t condition_type, pt_char_t *condition, pt_int32_t condition_len,
                pt_char_t *strtag)
{
    pt_uc_add_matchinfo(&((pt_uc_msg_t *)msg_id)->list_msg_condition,
                condition_type, condition, condition_len, strtag);
}

pt_uc_inst_id_t pt_uc_add_inst(pt_uc_msgflow_id_t msgflow_id, pt_char_t *inst_name)
{
    pt_uc_inst_t *inst;

    inst = pt_uc_alloc_inst(msgflow_id);
    if (inst != NULL)
        inst->inst_name = pt_strdup(inst_name);

    return inst;
}

void pt_uc_del_inst(pt_uc_inst_id_t inst_id)
{
    pt_uc_inst_t *inst;
    pt_uc_msg_t *msg;

    inst = inst_id;
    while (!list_empty(&inst->list_msg)) {
        msg = list_entry(inst->list_msg.next, pt_uc_msg_t, node);
        pt_uc_del_msg(msg);
    }

    pt_uc_free_inst(inst);
}

pt_uc_msgflow_id_t pt_uc_add_msgflow(pt_char_t *msgflow_name, pt_uint32_t delay)
{
    pt_uc_msgflow_t *msgflow;

    msgflow = pt_uc_alloc_msgflow();
    if (msgflow != NULL)
        msgflow->msgflow_name = pt_strdup(msgflow_name);

    msgflow->delay = delay;

    return msgflow;
}

void pt_uc_del_msgflow(pt_uc_msgflow_id_t msgflow_id)
{
    pt_uc_msgflow_t *msgflow;
    pt_uc_inst_t *inst;

    msgflow = msgflow_id;
    while (!list_empty(&msgflow->list_inst)) {
        inst = list_entry(msgflow->list_inst.next, pt_uc_inst_t, node);
        pt_uc_del_inst(inst);
    }

    pt_uc_free_msgflow(msgflow);
}

void pt_uc_res_reset(void)
{
    pt_uc_msgflow_t *msgflow;
    while (!list_empty(&list_msgflow)) {
        msgflow = list_entry(list_msgflow.next, pt_uc_msgflow_t, node);
        pt_uc_del_msgflow(msgflow);
    }
}

void pt_uc_dump()
{
    pt_uc_msgflow_t *msgflow;
    pt_uc_inst_t *inst;
    pt_uc_msg_t *msg;
    list_head_t *pos_msgflow;
    list_head_t *pos_inst;
    list_head_t *pos_msg;

    printf("\n%-16s  %-16s  %-12s  %-10s  %-9s  %-12s  %-9s  %-12s  %-10s  %-10s  %-10s  %-10s\n",
           "msgflow_name",
           "inst_name",
           "msg_name",
           "msg_action",
           "stat_rate",
           "stat_success",
           "stat_fail",
           "stat_timeout",
           "maxrtt(ms)",
           "minrtt(ms)",
           "advrtt(ms)",
           "exec_state"
           );
    list_for_each(pos_msgflow, &list_msgflow) {
        msgflow = list_entry(pos_msgflow, pt_uc_msgflow_t, node);
        list_for_each(pos_inst, &msgflow->list_inst) {
            inst = list_entry(pos_inst, pt_uc_inst_t, node);
            list_for_each(pos_msg, &inst->list_msg) {
                msg = list_entry(pos_msg, pt_uc_msg_t, node);
                printf("%-16s  %-16s  %-12s  %-10d  %-9lu  %-12lu  %-9lu  %-12lu  %-10lu  %-10lu  %-10lu  %-10d\n",
                    msgflow->msgflow_name,
                    inst->inst_name,
                    msg->msg_name,
                    msg->msg_action,
                    msg->msg_stat_rate,
                    msg->msg_stat_success,
                    msg->msg_stat_fail,
                    msg->msg_stat_timeout,
                    msg->msg_stat_maxrtt,
                    msg->msg_stat_minrtt,
                    msg->msg_stat_totalrtt/(msg->msg_stat_totalrttnum + 1),
                    msgflow->runing_state
                    );
            }
        }
    }
    printf("\n");
}

