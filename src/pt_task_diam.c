#include "pt_include.h"

void pt_task_update_diam_endtoend(pt_uc_msg_t *msg, pt_uint32_t endtoend)
{
    pt_diam_set_cmd_endtoend(msg->msg_data, msg->msg_data_len, endtoend);
}

void pt_task_update_diam_hopbyhop(pt_uc_msg_t *msg, pt_uint32_t hopbyhop)
{
    pt_diam_set_cmd_hopbyhop(msg->msg_data, msg->msg_data_len, hopbyhop);
}

/*直接替换用例中的SID*/
void pt_task_update_diam_sid(pt_uc_msg_t *msg, pt_char_t *sid, pt_int32_t sid_len)
{
    pt_diam_set_avp_data(msg->msg_data, &msg->msg_data_len, "263[1]", sid, sid_len);
}

/*根据用例中的sid和seq生成SID*/
void pt_task_update_diam_sid_with_seq(pt_uc_msg_t *msg,
                            pt_char_t *sid, pt_int32_t sid_len, pt_uint64_t seq)
{
    pt_int32_t strbuf_len;
    pt_char_t strbuf[256];
    pt_char_t *pctmp;

    strncpy(strbuf, sid, (pt_uint32_t)sid_len);
    strbuf_len = sid_len;

    /*删除多余\0*/
    while (strbuf_len > 0 && strbuf[strbuf_len - 1] == 0)
        strbuf_len--;
    strbuf[strbuf_len] = 0;

    pctmp = strstr(strbuf, ";pid");
    if (pctmp != NULL)
        strbuf_len = (pt_int32_t)(pctmp - strbuf);

    strbuf_len += sprintf(&strbuf[strbuf_len], ";pid%ld;%08ld", self_pid, seq);
    pt_task_update_diam_sid(msg, strbuf, strbuf_len);
}

/*
 * 只取AVP内容第一段数字递增
 * eg. sip:460010000000000@pt.com --> 460010000000000
 * eg. 460010000000000@pt.com --> 460010000000000
 * eg. 460010000000000 --> 460010000000000
 */
void pt_task_update_diam_str_uid(pt_uc_msg_t *msg, pt_uint64_t seq, pt_uc_matchinfo_t *diam_uid)
{
    pt_int32_t uid_len;
    pt_int32_t i;
    pt_char_t uid[128];
    pt_char_t str_seq[32];
    pt_char_t str_uid[128];
    pt_char_t str_prefix[128];
    pt_char_t str_result[128];
    pt_char_t *pstr;

    pstr = diam_uid->data;
    for(i = 0; pstr[i]; i++) {
        if (isdigit(pstr[i]))
            break;
        str_prefix[i] = pstr[i];
    }
    str_prefix[i] = 0;

    pstr += i;
    for(i = 0; pstr[i]; i++) {
        if (!isdigit(pstr[i]))
            break;
        str_uid[i] = pstr[i];
    }
    str_uid[i] = 0;

    pstr += i;

    sprintf(str_seq, "%ld", seq);
    pt_str_add(str_seq, str_uid, str_result, 10);
    /*uid构造*/
    uid_len = sprintf(uid, "%s%s%s", str_prefix, str_result, pstr);

    pt_diam_set_avp_data(msg->msg_data, &msg->msg_data_len, diam_uid->tag, uid, uid_len);
}

void pt_task_update_diam_bytes_uid(pt_uc_msg_t *msg, pt_uint64_t seq, pt_uc_matchinfo_t *diam_uid)
{
    pt_int32_t uid_len;
    pt_char_t uid[128];
    pt_char_t str_seq[32];
    pt_int32_t str_uid_len;
    pt_char_t str_uid[128];
    pt_char_t str_result[128];

    sprintf(str_seq, "%lx", seq);

    str_uid_len = sizeof(str_uid);
    pt_bytes2str((pt_uint8_t *)diam_uid->data, diam_uid->data_len, str_uid, &str_uid_len);

    pt_str_add(str_seq, str_uid, str_result, 16);

    uid_len = sizeof(uid);
    pt_str2bytes(str_result, (pt_int32_t)strlen(str_result), (pt_uint8_t *)uid, &uid_len);

    pt_diam_set_avp_data(msg->msg_data, &msg->msg_data_len, diam_uid->tag, uid, uid_len);
}

void pt_task_update_diam_bcd_uid(pt_uc_msg_t *msg, pt_uint64_t seq, pt_uc_matchinfo_t *diam_uid)
{
    ;
}

void pt_task_update_diam_uid_with_seq(pt_uc_msg_t *msg, pt_uint64_t seq)
{
    list_head_t *diam_uid_pos;
    pt_uc_matchinfo_t *diam_uid;

    list_for_each(diam_uid_pos, &msg->list_msg_uid) {
        diam_uid = list_entry(diam_uid_pos, pt_uc_matchinfo_t, node);
        switch(diam_uid->data_type) {
        case PT_UC_DATA_STR:
            pt_task_update_diam_str_uid(msg, seq, diam_uid);
            break;
        case PT_UC_DATA_IPV4:
        case PT_UC_DATA_IPV6:
        case PT_UC_DATA_BYTE:
            pt_task_update_diam_bytes_uid(msg, seq, diam_uid);
            break;
        case PT_UC_DATA_BCD:
            pt_task_update_diam_bcd_uid(msg, seq, diam_uid);
            break;
        default:
            break;
        }
    }
}

void pt_task_update_diam_uid_with_msgdata(pt_uc_msg_t *msg, pt_uint8_t *msg_data, pt_int32_t msg_data_len)
{
    list_head_t *diam_uid_pos;
    pt_uc_matchinfo_t *diam_uid;
    pt_int32_t pos;
    pt_uint8_t *avp_data;
    pt_int32_t avp_data_len;

    list_for_each(diam_uid_pos, &msg->list_msg_uid) {
        diam_uid = list_entry(diam_uid_pos, pt_uc_matchinfo_t, node);
        pos = pt_diam_get_avp_pos(msg_data, msg_data_len, diam_uid->tag, NULL);
        if (pos < 0)
            continue;

        avp_data = pt_diam_get_avp_data(msg_data, pos);
        avp_data_len = pt_diam_get_avp_data_len(msg_data, pos);
        pt_diam_set_avp_data(msg->msg_data,
                &msg->msg_data_len,
                diam_uid->tag,
                avp_data,
                avp_data_len);
    }
}

/*对于replace接口,只调用一次*/
void pt_task_update_diam_replace(pt_uc_msg_t *msg)
{
    list_head_t *diam_replace_pos;
    pt_uc_matchinfo_t *diam_replace;

    if (msg->msg_stat_total > 0)
        return;

    list_for_each(diam_replace_pos, &msg->list_msg_replace) {
        diam_replace = list_entry(diam_replace_pos, pt_uc_matchinfo_t, node);
        pt_diam_set_avp_data(msg->msg_data,
                &msg->msg_data_len,
                diam_replace->tag,
                diam_replace->data,
                diam_replace->data_len);
    }
}

pt_bool_t pt_task_match_diam_msg(pt_uc_msg_t *msg, pt_uint8_t *data, pt_int32_t len)
{
    list_head_t *diam_condition_pos;
    pt_uc_matchinfo_t *diam_condition;
    pt_int32_t pos;;

    if (msg->msg_action != MSG_ACTION_RECEIVE)
        return PT_FALSE;

    if (pt_diam_get_cmd_code(data, len) != pt_diam_get_cmd_code(msg->msg_data, msg->msg_data_len))
        return PT_FALSE;

    if (pt_diam_get_cmd_flg_R(data, len) != pt_diam_get_cmd_flg_R(msg->msg_data, msg->msg_data_len))
        return PT_FALSE;

    /*自定义条件*/
    list_for_each(diam_condition_pos, &msg->list_msg_condition) {
        diam_condition = list_entry(diam_condition_pos, pt_uc_matchinfo_t, node);
        pos = pt_diam_get_avp_pos(data, len, diam_condition->tag, NULL);
        if (pos < 0)
            return PT_FALSE;

        if (diam_condition->data_len != pt_diam_get_avp_data_len(data, pos))
            return PT_FALSE;

        if (memcmp(diam_condition->data, pt_diam_get_avp_data(data, pos),
                    (pt_uint32_t)diam_condition->data_len))
            return PT_FALSE;
    }

    return PT_TRUE;
}

pt_uc_msg_t *pt_task_next_diam_send_arg_msg(pt_uc_msg_t *ack_msg)
{
    pt_uc_msg_t *arg_msg;
    pt_uc_inst_t *arg_inst;
    if (!pt_task_last_msg(ack_msg)) {
        arg_msg = list_entry(ack_msg->node.next, pt_uc_msg_t, node);
        if (arg_msg->msg_action != MSG_ACTION_SEND &&
            pt_diam_get_cmd_flg_R(arg_msg->msg_data, arg_msg->msg_data_len)) {
            return arg_msg;
        }
    }

    arg_inst = ack_msg->inst;
    while (!pt_task_last_inst(arg_inst)) {
        arg_inst = list_entry(arg_inst->node.next, pt_uc_inst_t, node);
        arg_msg = list_entry(arg_inst->list_msg.next, pt_uc_msg_t, node);
        if (arg_msg->msg_action == MSG_ACTION_SEND &&
            pt_diam_get_cmd_flg_R(arg_msg->msg_data, arg_msg->msg_data_len)) {
            return arg_msg;
        }
    };

    return NULL;
}

pt_uc_msg_t *pt_task_next_diam_send_ack_msg(pt_uc_msg_t *arg_msg)
{
    pt_uc_msg_t *ack_msg;

    if (pt_task_last_msg(arg_msg))
        return NULL;

    ack_msg = list_entry(arg_msg->node.next, pt_uc_msg_t, node);
    if (ack_msg->msg_action != MSG_ACTION_SEND)
        return NULL;

    if (pt_diam_get_cmd_flg_R(ack_msg->msg_data, ack_msg->msg_data_len))
        return NULL;

    if (pt_diam_get_cmd_appid(ack_msg->msg_data, ack_msg->msg_data_len) !=
        pt_diam_get_cmd_appid(arg_msg->msg_data, arg_msg->msg_data_len))
        return NULL;

    if (pt_diam_get_cmd_code(ack_msg->msg_data, ack_msg->msg_data_len) !=
        pt_diam_get_cmd_code(arg_msg->msg_data, arg_msg->msg_data_len))
        return NULL;

    return ack_msg;
}

pt_uc_msg_t *pt_task_next_diam_recv_ack_msg(pt_uc_msg_t *arg_msg)
{
    pt_uc_msg_t *ack_msg;
    if (pt_task_last_msg(arg_msg))
        return NULL;

    ack_msg = list_entry(arg_msg->node.next, pt_uc_msg_t, node);
    if (ack_msg->msg_action != MSG_ACTION_RECEIVE)
        return NULL;

    if (pt_diam_get_cmd_flg_R(ack_msg->msg_data, ack_msg->msg_data_len))
        return NULL;

    if (pt_diam_get_cmd_appid(ack_msg->msg_data, ack_msg->msg_data_len) !=
        pt_diam_get_cmd_appid(arg_msg->msg_data, arg_msg->msg_data_len))
        return NULL;

    if (pt_diam_get_cmd_code(ack_msg->msg_data, ack_msg->msg_data_len) !=
        pt_diam_get_cmd_code(arg_msg->msg_data, arg_msg->msg_data_len))
        return NULL;

    return ack_msg;
}

pt_uc_msg_t *pt_task_this_diam_recv_arg_msg(pt_uint8_t *data, pt_int32_t len)
{
    pt_uc_msgflow_t *msgflow;
    pt_uc_inst_t *inst;
    pt_uc_msg_t *msg;
    list_head_t *pos_msgflow;
    list_head_t *pos_inst;
    list_head_t *pos_msg;

    list_for_each(pos_msgflow, &list_msgflow) {
        msgflow = list_entry(pos_msgflow, pt_uc_msgflow_t, node);
        list_for_each(pos_inst, &msgflow->list_inst) {
            inst = list_entry(pos_inst, pt_uc_inst_t, node);
            list_for_each(pos_msg, &inst->list_msg) {
                msg = list_entry(pos_msg, pt_uc_msg_t, node);
                if (pt_task_match_diam_msg(msg, data, len))
                    return msg;
            }
        }
    }

    return NULL;
}

pt_int32_t pt_task_get_diam_msg_sid(pt_uint8_t *msg, pt_int32_t msg_len,
                            pt_char_t **ppsid, pt_int32_t *psidlen)
{
    pt_int32_t pos;
    pt_uint8_t *cmd_data;
    pt_int32_t cmd_data_len;

    cmd_data = pt_diam_get_cmd_data(msg, msg_len);
    cmd_data_len = pt_diam_get_cmd_data_len(msg, msg_len);

    pos = pt_diam_get_avp_pos_from_cmd_data(cmd_data, cmd_data_len, 263, 1);
    *ppsid = (pt_char_t *)pt_diam_get_avp_data(cmd_data, pos);
    *psidlen = pt_diam_get_avp_data_len(cmd_data, pos);

    return 0;
}

pt_int32_t pt_task_get_diam_ack_msg_returecode(pt_uint8_t *msg,
                            pt_int32_t msg_len, pt_uint32_t *preturecode)
{
    pt_int32_t pos;
    pt_uint8_t *cmd_data;
    pt_int32_t cmd_data_len;

    cmd_data = pt_diam_get_cmd_data(msg, msg_len);
    cmd_data_len = pt_diam_get_cmd_data_len(msg, msg_len);

    pos = pt_diam_get_avp_pos_from_cmd_data(cmd_data, cmd_data_len, 268, 1);
    if (pos < 0) {
        pos = pt_diam_get_avp_pos_from_cmd_data(cmd_data, cmd_data_len, 297, 1);
        if (pos < 0)
            return -1;
        cmd_data = pt_diam_get_avp_data(cmd_data, pos);
        cmd_data_len = pt_diam_get_avp_data_len(cmd_data, pos);
        pos = pt_diam_get_avp_pos_from_cmd_data(cmd_data, cmd_data_len, 298, 1);
        if (pos < 0)
            return -1;
    }

    *preturecode = pt_ntohl(*(pt_uint32_t *)pt_diam_get_avp_data(cmd_data, pos));
    return 0;
}

pt_int32_t pt_task_send_diam_ack_msg(pt_uc_msg_t *ack_msg, diam_conn_t *diam_conn,
                            pt_uint8_t *arg_data, pt_int32_t arg_len)
{
    pt_uint32_t etoe;
    pt_uint32_t hbyh;
    pt_char_t *sid;
    pt_int32_t sid_len;

    /* update etoe hbyh */
    etoe = pt_diam_get_cmd_endtoend(arg_data, arg_len);
    hbyh = pt_diam_get_cmd_hopbyhop(arg_data, arg_len);
    pt_task_update_diam_endtoend(ack_msg, etoe);
    pt_task_update_diam_hopbyhop(ack_msg, hbyh);

    /* update sid */
    pt_task_get_diam_msg_sid(arg_data, arg_len, &sid, &sid_len);
    pt_task_update_diam_sid(ack_msg, sid, sid_len);

    /* update user defined avp */
    pt_task_update_diam_uid_with_msgdata(ack_msg, arg_data, arg_len);
    pt_task_update_diam_replace(ack_msg);

    ack_msg->msg_stat_total++;
    if (pt_diam_send_data_to_conn(diam_conn, ack_msg->msg_data, ack_msg->msg_data_len) < 0)
        ack_msg->msg_stat_fail++;
    else
        ack_msg->msg_stat_success++;

    return 0;
}

pt_int32_t pt_task_send_diam_arg_msg(pt_uc_msg_t *arg_msg, pt_uint64_t seq)
{
    pt_task_pdb_t *pdb;
    diam_conn_t *diam_conn;
    pt_char_t *sid;
    pt_int32_t sid_len;

    pdb = pt_task_alloc_pdb();
    pdb->seq = seq;
    pdb->msg = arg_msg;
    pdb->send_time = st_utime();

    diam_conn = pt_diam_obtain_overload_conn(arg_msg->msg_link_id);
    if (NULL == diam_conn) {
        PT_LOG(PTLOG_INFO, "locate diam_conn failed, msg_link_id = %u!", arg_msg->msg_link_id);
        pt_task_free_pdb(pdb);
        return -0xff;
    }

    /* update etoe hbyh */
    pt_task_update_diam_endtoend(arg_msg, pdb->_sn);
    pt_task_update_diam_hopbyhop(arg_msg, pdb->_index);

    /* update user defined avp */
    pt_task_update_diam_uid_with_seq(arg_msg, pdb->seq);
    pt_task_update_diam_replace(arg_msg);

    /* update sid */
    pt_task_get_diam_msg_sid(arg_msg->msg_data, arg_msg->msg_data_len, &sid, &sid_len);
    pt_task_update_diam_sid_with_seq(arg_msg, sid, sid_len, pdb->seq);

    arg_msg->msg_stat_total++;
    if (pt_diam_send_data_to_conn(diam_conn, arg_msg->msg_data, arg_msg->msg_data_len) < 0) {
        arg_msg->msg_stat_fail++;
        pt_task_free_pdb(pdb);
        return -0xff;
    } else {
        arg_msg->msg_stat_success++;
    }

    pdb->msg = pt_task_next_diam_recv_ack_msg(arg_msg);
    if (pdb->msg == NULL) {
        pt_task_free_pdb(pdb);
    }

    return 0;
}

void pt_task_recv_diam_ack_msg(diam_conn_t *diam_conn, pt_uint8_t *data, pt_int32_t len)
{
    pt_uint32_t pdb_index;
    pt_uint32_t pdb_sn;
    pt_task_pdb_t *pdb;
    pt_uc_msg_t *ack_msg;
    pt_uc_msg_t *arg_msg;
    pt_uint32_t returecode;

    pdb_index = pt_diam_get_cmd_hopbyhop(data, len);
    pdb_sn = pt_diam_get_cmd_endtoend(data, len);
    pdb = pt_task_locate_pdb(pdb_index, pdb_sn);
    if (pdb == NULL ) {
        PT_LOG(PTLOG_INFO, "recv invalid msg pdb = %p, pdb_index = %u, pdb_sn = %u!",
            pdb, pdb_index, pdb_sn);
        return;
    }

    if (!pt_task_match_diam_msg(pdb->msg, data, len))
        PT_LOG(PTLOG_INFO, "match diam msg failed, msg_name = %s.", pdb->msg->msg_name);

    ack_msg = pdb->msg;
    ack_msg->msg_stat_total++;
    if (pt_task_get_diam_ack_msg_returecode(data, len, &returecode) == 0 && returecode >= 3000)
        ack_msg->msg_stat_fail++;
    else
        ack_msg->msg_stat_success++;
    pt_task_calc_rtt(pdb);

    /*存在后续主发请求消息*/
    arg_msg = pt_task_next_diam_send_arg_msg(ack_msg);
    if (arg_msg != NULL) {
        PT_LOG(PTLOG_INFO, "there is next arg msg, msg_name = %s.", arg_msg->msg_name);
        pt_task_send_diam_arg_msg(arg_msg, pdb->seq);
    }

    pt_task_free_pdb(pdb);
}

void pt_task_recv_diam_arg_msg(diam_conn_t *diam_conn, pt_uint8_t *data, pt_int32_t len)
{
    pt_uc_msg_t *arg_msg;
    pt_uc_msg_t *ack_msg;

    arg_msg = pt_task_this_diam_recv_arg_msg(data, len);
    if (arg_msg == NULL) {
        PT_LOG(PTLOG_ERROR, "recv invalid arg_msg!");
        return;
    }

    arg_msg->msg_stat_total++;
    arg_msg->msg_stat_success++;

    ack_msg = pt_task_next_diam_send_ack_msg(arg_msg);
    if (ack_msg == NULL)
        return;

    pt_task_send_diam_ack_msg(ack_msg, diam_conn, data, len);
}

void pt_task_recv_diam_msg(diam_conn_t *diam_conn, pt_uint8_t *data, pt_int32_t len)
{
    PT_LOG(PTLOG_INFO, "recv diam_msg cmdcode = %u, R = %d",
            pt_diam_get_cmd_code(data, len), pt_diam_get_cmd_flg_R(data, len));

    if (pt_diam_get_cmd_flg_R(data, len))
        pt_task_recv_diam_arg_msg(diam_conn, data, len);
    else
        pt_task_recv_diam_ack_msg(diam_conn, data, len);
}

