#include "pt_include.h"

/*lint -e732 -e734 -e679*/

static sccp_up_msg_t _recv_sccp_up_msg;
static sccp_up_msg_t _send_sccp_up_msg;
static gtcap_msg_t _recv_gtcap_msg;
static gtcap_msg_t _send_gtcap_msg;
static pt_int32_t _task_ss7_buf_len;
static pt_uint8_t _task_ss7_buf[MAX_SS7_MSG];

void pt_task_update_ss7_str_uid(pt_uc_msg_t *msg, pt_uint64_t seq, pt_uc_matchinfo_t *ss7_uid)
{
    ;
}

void pt_task_update_ss7_bytes_uid(pt_uc_msg_t *msg, pt_uint64_t seq, pt_uc_matchinfo_t *ss7_uid)
{
    pt_int32_t pos;
    pt_uint32_t t;
    pt_int32_t l;
    pt_int32_t uid_len;
    pt_char_t uid[128];
    pt_char_t str_seq[32];
    pt_int32_t str_uid_len;
    pt_char_t str_uid[128];
    pt_char_t str_result[128];

    pos = pt_asn1_code_tag_pos(ss7_uid->tag, msg->msg_data, msg->msg_data_len);
    if (pos < 0) {
        PT_LOG(PTLOG_DEBUG, "there is not tag = %#x in msg_data", ss7_uid->tag);
        return;
    }

    pos = pt_asn1_decode_tl(msg->msg_data + pos, pos, &t, &l);

    sprintf(str_seq, "%lx", seq);

    str_uid_len = sizeof(str_uid);
    pt_bytes2str((pt_uint8_t *)ss7_uid->data, ss7_uid->data_len, str_uid, &str_uid_len);

    pt_str_add(str_seq, str_uid, str_result, 16);

    uid_len = sizeof(uid);
    pt_str2bytes(str_result, (pt_int32_t)strlen(str_result), (pt_uint8_t *)uid, &uid_len);

    if (uid_len < l)
        memcpy(msg->msg_data + pos + l - uid_len, uid, (pt_uint32_t)uid_len);
    else
        memcpy(msg->msg_data + pos, &uid[uid_len - l], (pt_uint32_t)uid_len);
}

void pt_task_update_ss7_bcd_uid(pt_uc_msg_t *msg, pt_uint64_t seq, pt_uc_matchinfo_t *ss7_uid)
{
    pt_int32_t pos;
    pt_uint32_t t;
    pt_int32_t l;
    pt_int32_t uid_len;
    pt_char_t uid[128];
    pt_char_t str_seq[32];
    pt_int32_t str_uid_len;
    pt_char_t str_uid[128];
    pt_char_t str_result[128];

    pos = pt_asn1_code_tag_pos(ss7_uid->tag, msg->msg_data, msg->msg_data_len);
    if (pos < 0) {
        PT_LOG(PTLOG_DEBUG, "there is not tag = %#x in msg_data", ss7_uid->tag);
        return;
    }

    pos = pt_asn1_decode_tl(msg->msg_data, pos, &t, &l);

    sprintf(str_seq, "%lx", seq);

    str_uid_len = sizeof(str_uid);
    pt_bcds2str((pt_uint8_t *)ss7_uid->data,
            pt_bcdlen((pt_uint8_t *)ss7_uid->data), str_uid, &str_uid_len);

    pt_str_add(str_seq, str_uid, str_result, 10);

    uid_len = sizeof(uid);
    pt_str2bcds(str_result, (pt_int32_t)strlen(str_result), (pt_uint8_t *)uid, &uid_len);

    if (uid_len < l)
        memcpy(msg->msg_data + pos + l - uid_len, uid, (pt_uint32_t)uid_len);
    else
        memcpy(msg->msg_data + pos, &uid[uid_len - l], (pt_uint32_t)uid_len);
}

void pt_task_update_ss7_uid_with_seq(pt_uc_msg_t *msg, pt_uint64_t seq)
{
    list_head_t *ss7_uid_pos;
    pt_uc_matchinfo_t *ss7_uid;

    list_for_each(ss7_uid_pos, &msg->list_msg_uid) {
        ss7_uid = list_entry(ss7_uid_pos, pt_uc_matchinfo_t, node);
        switch(ss7_uid->data_type) {
        case PT_UC_DATA_STR:
            pt_task_update_ss7_str_uid(msg, seq, ss7_uid);
            break;
        case PT_UC_DATA_IPV4:
        case PT_UC_DATA_IPV6:
        case PT_UC_DATA_BYTE:
            pt_task_update_ss7_bytes_uid(msg, seq, ss7_uid);
            break;
        case PT_UC_DATA_BCD:
            pt_task_update_ss7_bcd_uid(msg, seq, ss7_uid);
            break;
        default:
            break;
        }
    }
}

pt_bool_t pt_task_is_ss7_cdma_msg(pt_uc_msg_t *msg)
{
    return msg->msg_data[0] == 0xf2;
}

pt_bool_t pt_task_is_ss7_arg_msg(pt_uc_msg_t *msg)
{
    return msg->msg_ss7_comptype == PT_UC_MSG_SS7_INVOKE;
}

pt_bool_t pt_task_is_ss7_ack_msg(pt_uc_msg_t *msg)
{
    return msg->msg_ss7_comptype == PT_UC_MSG_SS7_RESPOSE;
}

void pt_task_set_ss7_tran_id(pt_task_pdb_t *pdb, gtcap_tran_id_t *tran_id)
{
    pt_uint16_t hword;
    pt_uint16_t lword;
    pt_uint32_t id;

    hword = (pt_uint16_t)pdb->_index;
    lword = (pt_uint16_t)pdb->_sn;

    id = ((pt_uint32_t)hword << 16) | lword;

    tran_id->len = 4;
    memcpy(tran_id->id, &id, 4);
}

pt_uint8_t pt_task_gtcap_msg_invokeid(gtcap_msg_t *gtcap_msg)
{
    pt_uint8_t invokeid = 0xff;

    if (gtcap_msg->m_type == GTCAP_BEGIN_TAG_TYPE)
        invokeid = gtcap_msg->m_begin.comp.invoke_id;
    else if (gtcap_msg->m_type == GTCAP_END_TAG_TYPE)
        invokeid = gtcap_msg->m_end.comp.invoke_id;
    else if (gtcap_msg->m_type == GTCAP_CONTINUE_TAG_TYPE)
        invokeid = gtcap_msg->m_cont.comp.invoke_id;

    return invokeid;
}

pt_task_pdb_t *pt_task_locate_ss7_pdb(gtcap_msg_t *gtcap_msg)
{
    gtcap_tran_id_t *tran_id;
    pt_uint16_t hword;
    pt_uint16_t lword;
    pt_uint32_t id;

    tran_id = NULL;
    if (gtcap_msg->m_type == GTCAP_CONTINUE_TAG_TYPE)
        tran_id = &gtcap_msg->m_cont.dest_id;
    else if (gtcap_msg->m_type == GTCAP_END_TAG_TYPE)
        tran_id = &gtcap_msg->m_end.dest_id;
    else if (gtcap_msg->m_type == GTCAP_END_TAG_TYPE)
        tran_id = &gtcap_msg->m_abort.dest_id;
    else
        tran_id = NULL;

    if (tran_id == NULL)
        return NULL;

    memcpy(&id, tran_id->id, 4);
    hword = id >> 16;
    lword = id & 0xffff;

    return pt_task_locate_pdb(hword, lword);
}

pt_task_ss7_invokeinfo_t *
pt_task_ss7_local_invokeinfo_locate(pt_task_pdb_t *pdb, pt_uint8_t invokeid)
{
    pt_uint32_t i;

    for (i = 0; i < pdb->ss7_local_invokeinfo_num; i++) {
         if(pdb->ss7_local_invokeinfo[i].ss7_invokeid == invokeid)
            return &pdb->ss7_local_invokeinfo[i];
    }

    return NULL;
}

pt_task_ss7_invokeinfo_t *
pt_task_ss7_local_invokeinfo_locate_by_opcode(pt_task_pdb_t *pdb, pt_uint8_t opcode)
{
    pt_uint32_t i;

    for (i = 0; i < pdb->ss7_local_invokeinfo_num; i++) {
         if(pdb->ss7_local_invokeinfo[i].ss7_opcode == opcode)
            return &pdb->ss7_local_invokeinfo[i];
    }

    return NULL;
}

pt_task_ss7_invokeinfo_t *
pt_task_ss7_local_invokeinfo_alloc(pt_task_pdb_t *pdb, pt_uint8_t opcode)
{
    pt_task_ss7_invokeinfo_t *ss7_invokeinfo;

    if (pdb->ss7_local_invokeinfo_num >= PT_ARRAY_SIZE(pdb->ss7_local_invokeinfo))
        return NULL;

    ss7_invokeinfo = &pdb->ss7_local_invokeinfo[pdb->ss7_local_invokeinfo_num++];
    ss7_invokeinfo->ss7_utime = st_utime();
    ss7_invokeinfo->ss7_invokeid = 1;
    ss7_invokeinfo->ss7_opcode = opcode;

    return ss7_invokeinfo;
}

pt_task_ss7_invokeinfo_t *
pt_task_ss7_peer_invokeinfo_locate(pt_task_pdb_t *pdb, pt_uint8_t invokeid)
{
    pt_uint32_t i;

    for (i = 0; i < pdb->ss7_peer_invokeinfo_num; i++) {
         if(pdb->ss7_peer_invokeinfo[i].ss7_invokeid == invokeid)
            return &pdb->ss7_peer_invokeinfo[i];
    }

    return NULL;
}

pt_task_ss7_invokeinfo_t *
pt_task_ss7_peer_invokeinfo_locate_by_opcode(pt_task_pdb_t *pdb, pt_uint8_t opcode)
{
    pt_uint32_t i;

    for (i = 0; i < pdb->ss7_peer_invokeinfo_num; i++) {
         if(pdb->ss7_peer_invokeinfo[i].ss7_opcode == opcode)
            return &pdb->ss7_peer_invokeinfo[i];
    }

    return NULL;
}

pt_task_ss7_invokeinfo_t *
pt_task_ss7_peer_invokeinfo_alloc(pt_task_pdb_t *pdb, pt_uint8_t opcode)
{
    pt_task_ss7_invokeinfo_t *ss7_invokeinfo;

    if (pdb->ss7_peer_invokeinfo_num >= PT_ARRAY_SIZE(pdb->ss7_peer_invokeinfo))
        return NULL;

    ss7_invokeinfo = &pdb->ss7_peer_invokeinfo[pdb->ss7_peer_invokeinfo_num++];
    ss7_invokeinfo->ss7_utime = st_utime();
    ss7_invokeinfo->ss7_invokeid = 1;
    ss7_invokeinfo->ss7_opcode = opcode;

    return ss7_invokeinfo;
}

/*ss7消息只支持opcode匹配*/
pt_bool_t pt_task_match_ss7_msg(pt_uc_msg_t *msg, pt_uint8_t opcode)
{
    if (msg->msg_action != MSG_ACTION_RECEIVE)
        return PT_FALSE;

    if (msg->msg_ss7_opcode != opcode)
        return PT_FALSE;

    return PT_TRUE;
}

/*全用例集查找接收begin消息*/
pt_uc_msg_t *pt_task_this_ss7_recv_begin_msg(pt_uint8_t opcode)
{
    pt_uc_msgflow_t *msgflow;
    pt_uc_inst_t *inst;
    pt_uc_msg_t *msg;
    list_head_t *pos_msgflow;
    list_head_t *pos_inst;

    list_for_each(pos_msgflow, &list_msgflow) {
        msgflow = list_entry(pos_msgflow, pt_uc_msgflow_t, node);
        list_for_each(pos_inst, &msgflow->list_inst) {
            inst = list_entry(pos_inst, pt_uc_inst_t, node);
            msg = list_entry(inst->list_msg.next, pt_uc_msg_t, node);
            if (pt_task_match_ss7_msg(msg, opcode))
                return msg;
        }
    }

    return NULL;
}

/*同inst内查找接收msg*/
pt_uc_msg_t *pt_task_this_ss7_recv_msg(pt_uc_msg_t *current_msg, pt_uint8_t opcode)
{
    pt_uc_inst_t *inst;
    pt_uc_msg_t *msg;
    list_head_t *pos;

    inst = current_msg->inst;
    for (pos = &current_msg->node; pos != &inst->list_msg; pos = pos->next) {
        msg = list_entry(pos, pt_uc_msg_t, node);
        if (pt_task_match_ss7_msg(msg, opcode))
            return msg;
    }

    return NULL;
}

/*获取同此msgflow内的inst后续发送begin消息*/
pt_uc_msg_t *pt_task_next_ss7_begin_msg(pt_uc_msg_t *current_msg)
{
    pt_uc_msgflow_t *msgflow;
    pt_uc_inst_t *inst;
    pt_uc_msg_t *msg;
    list_head_t *pos;

    if (pt_task_last_inst(current_msg->inst))
        return NULL;

    msgflow = current_msg->inst->msgflow;
    pos = current_msg->inst->node.next;
    for (; pos != &msgflow->list_inst; pos = pos->next) {
        inst = list_entry(pos, pt_uc_inst_t, node);
        msg = list_entry(inst->list_msg.next, pt_uc_msg_t, node);
        if (msg->msg_action == MSG_ACTION_SEND && pt_task_is_ss7_arg_msg(msg)) {
            return msg;
        }
    }

    return NULL;
}

/*获取同inst内的后续发送消息*/
pt_uc_msg_t *pt_task_next_ss7_send_msg(pt_uc_msg_t *current_msg)
{
    pt_uc_msg_t *next_msg;

    if (pt_task_last_msg(current_msg))
        return NULL;

    next_msg = list_entry(current_msg->node.next, pt_uc_msg_t, node);
    if (next_msg->msg_action != MSG_ACTION_SEND)
        return NULL;

    return next_msg;
}

pt_uc_msg_t *pt_task_next_ss7_recv_msg(pt_uc_msg_t *current_msg)
{
    pt_uc_msg_t *next_msg;

    if (pt_task_last_msg(current_msg))
        return NULL;

    next_msg = list_entry(current_msg->node.next, pt_uc_msg_t, node);
    if (next_msg->msg_action != MSG_ACTION_RECEIVE)
        return NULL;

    return next_msg;
}

pt_int32_t pt_task_send_ss7_end_msg(m3ua_asp_t *m3ua_asp, pt_task_pdb_t *pdb,
                            pt_uc_msg_t *end_msg, pt_uint64_t seq)
{
    pt_task_ss7_invokeinfo_t *ss7_invokeinfo;

    ss7_invokeinfo = pt_task_ss7_peer_invokeinfo_locate_by_opcode(pdb, end_msg->msg_ss7_opcode);
    if (ss7_invokeinfo == NULL) {
        PT_LOG(PTLOG_DEBUG, "locate peer invokeinfo failed!");
        return -0xff;
    }

    _send_gtcap_msg.m_type = GTCAP_END_TAG_TYPE;

    /*dlginfo&traninfo*/
    if (_recv_gtcap_msg.m_type == GTCAP_BEGIN_TAG_TYPE) {
        _send_gtcap_msg.m_end.dest_id = _recv_gtcap_msg.m_begin.orig_id;
        if (_recv_gtcap_msg.m_begin.dlg_flg != 0) {
            _send_gtcap_msg.m_end.dlg_flg = 1;
            _send_gtcap_msg.m_end.dlg.dlg_type = DLG_TYPE_AARE;
            _send_gtcap_msg.m_end.dlg.e_ac_ver = _recv_gtcap_msg.m_begin.dlg.q_ac_ver;
            _send_gtcap_msg.m_end.dlg.e_ac_val = _recv_gtcap_msg.m_begin.dlg.q_ac_val;
            _send_gtcap_msg.m_end.dlg.e_result = 0;
            _send_gtcap_msg.m_end.dlg.user_info_flg = 0;
        }
    } else if (_recv_gtcap_msg.m_type == GTCAP_CONTINUE_TAG_TYPE) {
        _send_gtcap_msg.m_end.dest_id = _recv_gtcap_msg.m_cont.orig_id;
        _send_gtcap_msg.m_end.dlg_flg = 0;
    } else {
        PT_LOG(PTLOG_DEBUG, "invalide m_type = %d!", _recv_gtcap_msg.m_type);
        return -0xfe;
    }

    /*compinfo*/
    _send_gtcap_msg.m_end.comp_flg = 1;
    _send_gtcap_msg.m_end.comp.comp_type = GCOMP_TYPE_RESULT;
    _send_gtcap_msg.m_end.comp.invoke_id = ss7_invokeinfo->ss7_invokeid;
    if (end_msg->msg_data_len > 0) {
        _send_gtcap_msg.m_end.comp.r_op_code_flg = 1;
        _send_gtcap_msg.m_end.comp.r_op_code = ss7_invokeinfo->ss7_opcode;
        _send_gtcap_msg.m_end.comp.para_len = end_msg->msg_data_len;
        memcpy(_send_gtcap_msg.m_end.comp.para, end_msg->msg_data, end_msg->msg_data_len);
    } else {
        _send_gtcap_msg.m_end.comp.r_op_code_flg = 0;
        _send_gtcap_msg.m_end.comp.para_len = 0;
    }

    /*encode&sendmsg*/
    _task_ss7_buf_len = sizeof(_task_ss7_buf);
    if (-1 == pt_gtcap_encode(&_send_gtcap_msg, _task_ss7_buf, &_task_ss7_buf_len)) {
        PT_LOG(PTLOG_DEBUG, "gtcap encode failed!");
        return -0xfe;
    }

    PT_LOG(PTLOG_DEBUG, "send end msg to sccp, %s-%s",
            pt_addr_a(&m3ua_asp->conn_item.local_addr[0]),
            pt_addr_a(&m3ua_asp->conn_item.remote_addr[0]));

    _send_sccp_up_msg.cda = _recv_sccp_up_msg.cga;
    _send_sccp_up_msg.cga = _recv_sccp_up_msg.cda;

    _send_sccp_up_msg.pdata = _task_ss7_buf + sizeof(_task_ss7_buf) - _task_ss7_buf_len;
    _send_sccp_up_msg.data_len = _task_ss7_buf_len;

    m3ua_asp->seq = pt_sccp_get_sls();

    /*stat&send*/
    end_msg->msg_stat_total++;
    if (pt_sccp_send_data_to_m3ua(m3ua_asp, &_send_sccp_up_msg) < 0)
        end_msg->msg_stat_fail++;
    else
        end_msg->msg_stat_success++;

    return -0x88;
}

pt_int32_t pt_task_send_ss7_cont_arg_msg(m3ua_asp_t *m3ua_asp, pt_task_pdb_t *pdb,
                            pt_uc_msg_t *cont_msg, pt_uint64_t seq)
{
    pt_task_ss7_invokeinfo_t *ss7_invokeinfo;

    ss7_invokeinfo = pt_task_ss7_local_invokeinfo_locate_by_opcode(pdb, cont_msg->msg_ss7_opcode);
    if (ss7_invokeinfo == NULL) {
        ss7_invokeinfo = pt_task_ss7_local_invokeinfo_alloc(pdb, cont_msg->msg_ss7_opcode);
        if (ss7_invokeinfo == NULL) {
            PT_LOG(PTLOG_DEBUG, "alloc local invokeinfo failed!");
            return -0xff;
        }
    } else {
        ss7_invokeinfo->ss7_utime = st_utime();
        ss7_invokeinfo->ss7_invokeid++;
    }

    _send_gtcap_msg.m_type = GTCAP_CONTINUE_TAG_TYPE;

    /*dlginfo&traninfo*/
    pt_task_set_ss7_tran_id(pdb, &_send_gtcap_msg.m_cont.orig_id);
    if (_recv_gtcap_msg.m_type == GTCAP_BEGIN_TAG_TYPE) {
        _send_gtcap_msg.m_cont.dest_id = _recv_gtcap_msg.m_begin.orig_id;
        if (_recv_gtcap_msg.m_begin.dlg_flg != 0) {
            _send_gtcap_msg.m_cont.dlg_flg = 1;
            _send_gtcap_msg.m_cont.dlg.dlg_type = DLG_TYPE_AARE;
            _send_gtcap_msg.m_cont.dlg.e_ac_ver = _recv_gtcap_msg.m_begin.dlg.q_ac_ver;
            _send_gtcap_msg.m_cont.dlg.e_ac_val = _recv_gtcap_msg.m_begin.dlg.q_ac_val;
            _send_gtcap_msg.m_cont.dlg.e_result = 0;
            _send_gtcap_msg.m_cont.dlg.user_info_flg = 0;
        }
    } else if (_recv_gtcap_msg.m_type == GTCAP_CONTINUE_TAG_TYPE) {
        _send_gtcap_msg.m_cont.dest_id = _recv_gtcap_msg.m_cont.orig_id;
        _send_gtcap_msg.m_cont.dlg_flg = 0;
    } else {
        PT_LOG(PTLOG_DEBUG, "invalide m_type = %d!", _recv_gtcap_msg.m_type);
        return -0xfe;
    }

    /*compinfo*/
    _send_gtcap_msg.m_cont.comp_flg = 1;
    _send_gtcap_msg.m_cont.comp.comp_type = GCOMP_TYPE_INVOKE;
    _send_gtcap_msg.m_cont.comp.invoke_id = ss7_invokeinfo->ss7_invokeid;
    _send_gtcap_msg.m_cont.comp.i_link_id_flg = 0;
    _send_gtcap_msg.m_cont.comp.i_op_code = ss7_invokeinfo->ss7_opcode;
    _send_gtcap_msg.m_cont.comp.para_len = cont_msg->msg_data_len;
    memcpy(_send_gtcap_msg.m_cont.comp.para, cont_msg->msg_data, cont_msg->msg_data_len);

    /*encode&sendmsg*/
    _task_ss7_buf_len = sizeof(_task_ss7_buf);
    if (-1 == pt_gtcap_encode(&_send_gtcap_msg, _task_ss7_buf, &_task_ss7_buf_len)) {
        PT_LOG(PTLOG_DEBUG, "gtcap encode failed!");
        return -0xfe;
    }

    _send_sccp_up_msg.cda = _recv_sccp_up_msg.cga;
    _send_sccp_up_msg.cga = _recv_sccp_up_msg.cda;

    _send_sccp_up_msg.pdata = _task_ss7_buf + sizeof(_task_ss7_buf) - _task_ss7_buf_len;
    _send_sccp_up_msg.data_len = _task_ss7_buf_len;

    m3ua_asp->seq = pt_sccp_get_sls();
    /*stat&send*/
    cont_msg->msg_stat_total++;
    if (pt_sccp_send_data_to_m3ua(m3ua_asp, &_send_sccp_up_msg) < 0)
        cont_msg->msg_stat_fail++;
    else
        cont_msg->msg_stat_success++;

    return 0;
}

pt_int32_t pt_task_send_ss7_cont_ack_msg(m3ua_asp_t *m3ua_asp, pt_task_pdb_t *pdb,
                            pt_uc_msg_t *cont_msg, pt_uint64_t seq)
{
    pt_task_ss7_invokeinfo_t *ss7_invokeinfo;

    ss7_invokeinfo = pt_task_ss7_peer_invokeinfo_locate_by_opcode(pdb, cont_msg->msg_ss7_opcode);
    if (ss7_invokeinfo == NULL) {
        PT_LOG(PTLOG_DEBUG, "locate peer invokeinfo failed!");
        return -0xff;
    }

    if (_recv_gtcap_msg.m_type == GTCAP_BEGIN_TAG_TYPE) {
        _send_gtcap_msg.m_cont.dest_id = _recv_gtcap_msg.m_begin.orig_id;
        if (_recv_gtcap_msg.m_begin.dlg_flg != 0) {
            _send_gtcap_msg.m_cont.dlg_flg = 1;
            _send_gtcap_msg.m_cont.dlg.dlg_type = DLG_TYPE_AARE;
            _send_gtcap_msg.m_cont.dlg.e_ac_ver = _recv_gtcap_msg.m_begin.dlg.q_ac_ver;
            _send_gtcap_msg.m_cont.dlg.e_ac_val = _recv_gtcap_msg.m_begin.dlg.q_ac_val;
            _send_gtcap_msg.m_cont.dlg.e_result = 0;
            _send_gtcap_msg.m_cont.dlg.user_info_flg = 0;
        }
    } else if (_recv_gtcap_msg.m_type == GTCAP_CONTINUE_TAG_TYPE) {
        _send_gtcap_msg.m_cont.dest_id = _recv_gtcap_msg.m_cont.orig_id;
        _send_gtcap_msg.m_cont.dlg_flg = 0;
    } else {
        PT_LOG(PTLOG_DEBUG, "invalide m_type = %d!", _recv_gtcap_msg.m_type);
        return -0xfe;
    }

    _send_gtcap_msg.m_cont.comp_flg = 1;
    _send_gtcap_msg.m_cont.comp.comp_type = GCOMP_TYPE_RESULT;
    _send_gtcap_msg.m_cont.comp.invoke_id = ss7_invokeinfo->ss7_invokeid;
    if (cont_msg->msg_data_len > 0) {
        _send_gtcap_msg.m_cont.comp.r_op_code_flg = 0;
        _send_gtcap_msg.m_cont.comp.r_op_code = ss7_invokeinfo->ss7_opcode;
        _send_gtcap_msg.m_cont.comp.para_len = cont_msg->msg_data_len;
        memcpy(_send_gtcap_msg.m_cont.comp.para, cont_msg->msg_data, cont_msg->msg_data_len);
    } else {
        _send_gtcap_msg.m_cont.comp.r_op_code_flg = 0;
        _send_gtcap_msg.m_cont.comp.para_len = 0;
    }

    /*encode&sendmsg*/
    _task_ss7_buf_len = sizeof(_task_ss7_buf);
    if (-1 == pt_gtcap_encode(&_send_gtcap_msg, _task_ss7_buf, &_task_ss7_buf_len)) {
        PT_LOG(PTLOG_DEBUG, "gtcap encode failed!");
        return -0xfe;
    }

    _send_sccp_up_msg.cda = _recv_sccp_up_msg.cga;
    _send_sccp_up_msg.cga = _recv_sccp_up_msg.cda;

    _send_sccp_up_msg.pdata = _task_ss7_buf + sizeof(_task_ss7_buf) - _task_ss7_buf_len;
    _send_sccp_up_msg.data_len = _task_ss7_buf_len;

    m3ua_asp->seq = pt_sccp_get_sls();

    /*stat&send*/
    cont_msg->msg_stat_total++;
    if (pt_sccp_send_data_to_m3ua(m3ua_asp, &_send_sccp_up_msg) < 0)
        cont_msg->msg_stat_fail++;
    else
        cont_msg->msg_stat_success++;

    return 0;
}

pt_int32_t pt_task_send_ss7_cont_msg(m3ua_asp_t *m3ua_asp, pt_task_pdb_t *pdb,
                            pt_uc_msg_t *cont_msg, pt_uint64_t seq)
{
    pt_int32_t result = -1;

    if (cont_msg->msg_ss7_comptype == PT_UC_MSG_SS7_INVOKE)
        result = pt_task_send_ss7_cont_arg_msg(m3ua_asp, pdb, cont_msg, seq);
    else if (cont_msg->msg_ss7_comptype == PT_UC_MSG_SS7_RESPOSE)
        result = pt_task_send_ss7_cont_ack_msg(m3ua_asp, pdb, cont_msg, seq);

    PT_LOG(PTLOG_DEBUG, "send cont msg to sccp, %s-%s",
            pt_addr_a(&m3ua_asp->conn_item.local_addr[0]),
            pt_addr_a(&m3ua_asp->conn_item.remote_addr[0]));

    if (result < 0)
        return -0xff;

    pdb->msg = pt_task_next_ss7_recv_msg(cont_msg);
    if (pdb->msg == NULL) {
        PT_LOG(PTLOG_DEBUG, "there are not msgs...");
        return -0xfe;
    }

    return 0;
}

pt_int32_t pt_task_send_ss7_begin_msg(pt_uc_msg_t *begin_msg, pt_uint64_t seq)
{
    pt_task_pdb_t *pdb;
    m3ua_asp_t *m3ua_asp;
    pt_task_ss7_invokeinfo_t *ss7_invokeinfo;

    pdb = pt_task_alloc_pdb();
    pdb->send_time = st_utime();
    pdb->seq = seq;
    ss7_invokeinfo = pt_task_ss7_local_invokeinfo_alloc(pdb, begin_msg->msg_ss7_opcode);

    _send_gtcap_msg.m_type = GTCAP_BEGIN_TAG_TYPE;

    /*更新用户标识*/
    pt_task_update_ss7_uid_with_seq(begin_msg, pdb->seq);

    /*dlginfo&traninfo*/
    pt_task_set_ss7_tran_id(pdb, &_send_gtcap_msg.m_begin.orig_id);
    if (begin_msg->msg_ss7_acver > 1) {
        _send_gtcap_msg.m_begin.dlg_flg = 1;
        _send_gtcap_msg.m_begin.dlg.dlg_type = DLG_TYPE_AARQ;
        _send_gtcap_msg.m_begin.dlg.q_ac_ver = begin_msg->msg_ss7_acver;
        _send_gtcap_msg.m_begin.dlg.q_ac_val = begin_msg->msg_ss7_acvalue;
        _send_gtcap_msg.m_begin.dlg.user_info_flg = 0;
    }

    /*compinfo*/
    _send_gtcap_msg.m_begin.comp_flg = 1;
    _send_gtcap_msg.m_begin.comp.comp_type = GCOMP_TYPE_INVOKE;
    _send_gtcap_msg.m_begin.comp.invoke_id = ss7_invokeinfo->ss7_invokeid;
    _send_gtcap_msg.m_begin.comp.i_link_id_flg = 0;
    _send_gtcap_msg.m_begin.comp.i_op_code = ss7_invokeinfo->ss7_opcode;
    _send_gtcap_msg.m_begin.comp.para_len = begin_msg->msg_data_len;
    memcpy(_send_gtcap_msg.m_begin.comp.para, begin_msg->msg_data, begin_msg->msg_data_len);

    /*encode&sendmsg*/
    _task_ss7_buf_len = sizeof(_task_ss7_buf);
    if (-1 == pt_gtcap_encode(&_send_gtcap_msg, _task_ss7_buf, &_task_ss7_buf_len)) {
        PT_LOG(PTLOG_ERROR, "gtcap encode failed!");
        pt_task_free_pdb(pdb);
        return -0xff;
    }

    m3ua_asp = pt_m3ua_obtain_overload_asp(begin_msg->msg_link_id);
    if (m3ua_asp == NULL) {
        pt_task_free_pdb(pdb);
        PT_LOG(PTLOG_ERROR, "get asp failed, msg_link_id = %u!", begin_msg->msg_link_id);
        return -0xfe;
    }

    PT_LOG(PTLOG_DEBUG, "send begin msg to sccp, %s-%s",
            pt_addr_a(&m3ua_asp->conn_item.local_addr[0]),
            pt_addr_a(&m3ua_asp->conn_item.remote_addr[0]));

    pt_sccp_make_address(begin_msg->msg_ss7_cda_code,
                         begin_msg->msg_ss7_cda_ssn,
                         &_send_sccp_up_msg.cda);
    pt_sccp_make_address(begin_msg->msg_ss7_cga_code,
                         begin_msg->msg_ss7_cga_ssn,
                         &_send_sccp_up_msg.cga);

    _send_sccp_up_msg.pdata = _task_ss7_buf + sizeof(_task_ss7_buf) - _task_ss7_buf_len;
    _send_sccp_up_msg.data_len = _task_ss7_buf_len;

    m3ua_asp->seq = pt_sccp_get_sls();

    /*stat&send*/
    begin_msg->msg_stat_total++;
    if (pt_sccp_send_data_to_m3ua(m3ua_asp, &_send_sccp_up_msg) < 0)
        begin_msg->msg_stat_fail++;
    else
        begin_msg->msg_stat_success++;

    pdb->msg = pt_task_next_ss7_recv_msg(begin_msg);
    if (pdb->msg == NULL){
        PT_LOG(PTLOG_DEBUG, "there are not msgs...");
        pt_task_free_pdb(pdb);
        return -0xfd;
    }

    return 0;
}

pt_int32_t pt_task_recv_ss7_abort_msg(m3ua_asp_t *m3ua_asp, pt_task_pdb_t *pdb)
{
    return -0xff;
}

pt_int32_t pt_task_recv_ss7_end_msg(m3ua_asp_t *m3ua_asp, pt_task_pdb_t *pdb)
{
    pt_task_ss7_invokeinfo_t *ss7_invokeinfo;
    pt_uint8_t invokeid;
    pt_uc_msg_t *next_msg;

    invokeid = pt_task_gtcap_msg_invokeid(&_recv_gtcap_msg);
    ss7_invokeinfo = pt_task_ss7_local_invokeinfo_locate(pdb, invokeid);
    if (ss7_invokeinfo == NULL) {
        PT_LOG(PTLOG_DEBUG, "locate local invokeinfo failed!");
        return -0xff;
    }

    pdb->msg = pt_task_this_ss7_recv_msg(pdb->msg, ss7_invokeinfo->ss7_opcode);
    if (pdb->msg == NULL) {
        PT_LOG(PTLOG_DEBUG, "get recv msg failed, opcode = %d!", ss7_invokeinfo->ss7_opcode);
        return -0xfe;
    }

    pdb->msg->msg_stat_total++;
    if (_recv_gtcap_msg.m_end.comp.comp_type == GCOMP_TYPE_ERROR)
        pdb->msg->msg_stat_fail++;
    else
        pdb->msg->msg_stat_success++;
    pdb->send_time = ss7_invokeinfo->ss7_utime;
    pt_task_calc_rtt(pdb);

    /*触发后续流程*/
    next_msg = pt_task_next_ss7_begin_msg(pdb->msg);
    if (next_msg != NULL)
        pt_task_send_ss7_begin_msg(next_msg, pdb->seq);

    return -0x88;
}

/*暂支持一来一回的cont, burst方式不支持*/
pt_int32_t pt_task_recv_ss7_cont_arg_msg(m3ua_asp_t *m3ua_asp, pt_task_pdb_t *pdb)
{
    pt_uc_msg_t *next_msg;
    pt_task_ss7_invokeinfo_t *ss7_invokeinfo;

    ss7_invokeinfo = pt_task_ss7_peer_invokeinfo_locate_by_opcode(pdb,
                                _recv_gtcap_msg.m_cont.comp.i_op_code);
    if (ss7_invokeinfo == NULL) {
        ss7_invokeinfo = pt_task_ss7_peer_invokeinfo_alloc(pdb,
                                _recv_gtcap_msg.m_cont.comp.i_op_code);
        if (ss7_invokeinfo == NULL) {
            PT_LOG(PTLOG_DEBUG, "allock peer invokeinfo failed!");
            return -0xff;
        }
    }
    ss7_invokeinfo->ss7_invokeid = _recv_gtcap_msg.m_cont.comp.invoke_id;
    ss7_invokeinfo->ss7_utime = st_utime();

    pdb->msg = pt_task_this_ss7_recv_msg(pdb->msg, ss7_invokeinfo->ss7_opcode);
    if (pdb->msg == NULL) {
        PT_LOG(PTLOG_DEBUG, "get recv msg failed, opcode = %d!", ss7_invokeinfo->ss7_opcode);
        return -0xfe;
    }

    pdb->msg->msg_stat_total++;
    pdb->msg->msg_stat_success++;

    next_msg = pt_task_next_ss7_send_msg(pdb->msg);
    if (next_msg == NULL) {
        PT_LOG(PTLOG_DEBUG, "there are not msgs...");
        return -0xfd;
    }

    if (pt_task_last_msg(next_msg) && pt_task_is_ss7_ack_msg(next_msg))
        return pt_task_send_ss7_end_msg(m3ua_asp, pdb, next_msg, pdb->seq);
    else
        return pt_task_send_ss7_cont_msg(m3ua_asp, pdb, next_msg, pdb->seq);
}

pt_int32_t pt_task_recv_ss7_cont_ack_msg(m3ua_asp_t *m3ua_asp, pt_task_pdb_t *pdb)
{
    pt_uc_msg_t *next_msg;
    pt_task_ss7_invokeinfo_t *ss7_invokeinfo;
    pt_uint8_t invokeid;

    invokeid = pt_task_gtcap_msg_invokeid(&_recv_gtcap_msg);
    ss7_invokeinfo = pt_task_ss7_local_invokeinfo_locate(pdb, invokeid);
    if (ss7_invokeinfo == NULL) {
        PT_LOG(PTLOG_DEBUG, "locate local invokeinfo failed!");
        return -0xff;
    }

    pdb->msg = pt_task_this_ss7_recv_msg(pdb->msg, ss7_invokeinfo->ss7_opcode);
    if (pdb->msg == NULL) {
        PT_LOG(PTLOG_DEBUG, "get recv msg failed, opcode = %d!", ss7_invokeinfo->ss7_opcode);
        return -0xfe;
    }

    pdb->msg->msg_stat_total++;
    pdb->msg->msg_stat_success++;
    pdb->send_time = ss7_invokeinfo->ss7_utime;
    pt_task_calc_rtt(pdb);

    next_msg = pt_task_next_ss7_send_msg(pdb->msg);
    if (next_msg == NULL) {
        PT_LOG(PTLOG_DEBUG, "there are not msgs...");
        return -0xfd;
    }

    if (pt_task_last_msg(next_msg) && pt_task_is_ss7_ack_msg(next_msg))
        return pt_task_send_ss7_end_msg(m3ua_asp, pdb, next_msg, pdb->seq);
    else
        return pt_task_send_ss7_cont_msg(m3ua_asp, pdb, next_msg, pdb->seq);
}

pt_int32_t pt_task_recv_ss7_cont_msg(m3ua_asp_t *m3ua_asp, pt_task_pdb_t *pdb)
{
    if (_recv_gtcap_msg.m_cont.comp.comp_type == GCOMP_TYPE_INVOKE)
        return pt_task_recv_ss7_cont_arg_msg(m3ua_asp, pdb);
    else if (_recv_gtcap_msg.m_cont.comp.comp_type == GCOMP_TYPE_RESULT)
        return pt_task_recv_ss7_cont_ack_msg(m3ua_asp, pdb);

    return -0xff;
}

pt_int32_t pt_task_recv_ss7_begin_msg(m3ua_asp_t *m3ua_asp, pt_task_pdb_t *pdb)
{
    pt_uc_msg_t *begin_msg;
    pt_uc_msg_t *next_msg;
    pt_task_ss7_invokeinfo_t *ss7_invokeinfo;

    begin_msg = pt_task_this_ss7_recv_begin_msg(_recv_gtcap_msg.m_begin.comp.i_op_code);
    if (begin_msg == NULL) {
        PT_LOG(PTLOG_ERROR, "recv invalid begin_msg!");
        return -0xff;
    }

    ss7_invokeinfo = pt_task_ss7_peer_invokeinfo_alloc(pdb,
                                    _recv_gtcap_msg.m_begin.comp.i_op_code);
    if (ss7_invokeinfo == NULL) {
        PT_LOG(PTLOG_DEBUG, "alloc peer invokeinfo failed!");
        return -0xfe;
    }

    begin_msg->msg_stat_total++;
    begin_msg->msg_stat_success++;

    next_msg = pt_task_next_ss7_send_msg(begin_msg);
    if (next_msg == NULL) {
        PT_LOG(PTLOG_DEBUG, "there are not msgs...");
        return -0xfd;
    }

    if (pt_task_last_msg(next_msg) && pt_task_is_ss7_ack_msg(next_msg))
        return pt_task_send_ss7_end_msg(m3ua_asp, pdb, next_msg, pdb->seq);
    else
        return pt_task_send_ss7_cont_msg(m3ua_asp, pdb, next_msg, pdb->seq);
}

void pt_task_recv_ss7_msg(m3ua_asp_t *m3ua_asp, sccp_up_msg_t *up_msg)
{
    pt_task_pdb_t *pdb;
    pt_int32_t result = -1;

    if (-1 == pt_gtcap_decode(up_msg->pdata, up_msg->data_len, &_recv_gtcap_msg)) {
        PT_LOG(PTLOG_DEBUG, "gtcap decode failed!");
        return;
    }
    _recv_sccp_up_msg = *up_msg;

    PT_LOG(PTLOG_DEBUG, "recv msg from sccp, msgtype = %#04x, %s-%s",
            _recv_gtcap_msg.m_type,
            pt_addr_a(&m3ua_asp->conn_item.local_addr[0]),
            pt_addr_a(&m3ua_asp->conn_item.remote_addr[0]));

    if (_recv_gtcap_msg.m_type == GTCAP_BEGIN_TAG_TYPE) {
        pdb = pt_task_alloc_pdb();
        pdb->send_time = st_utime();
    } else {
        pdb = pt_task_locate_ss7_pdb(&_recv_gtcap_msg);
    }

    if (pdb == NULL) {
        PT_LOG(PTLOG_DEBUG, "pdb == NULL, m_type = %d!", _recv_gtcap_msg.m_type);
        return;
    }

    switch (_recv_gtcap_msg.m_type) {
    case GTCAP_BEGIN_TAG_TYPE:
        result = pt_task_recv_ss7_begin_msg(m3ua_asp, pdb);
        break;
    case GTCAP_END_TAG_TYPE:
        result = pt_task_recv_ss7_end_msg(m3ua_asp, pdb);
        break;
    case GTCAP_CONTINUE_TAG_TYPE:
        result = pt_task_recv_ss7_cont_msg(m3ua_asp, pdb);
        break;
    case GTCAP_ABORT_TAG_TYPE:
        result = pt_task_recv_ss7_abort_msg(m3ua_asp, pdb);
        break;
    default:
        break;
    }

    if (result < 0)
        pt_task_free_pdb(pdb);
}

