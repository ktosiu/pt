#include "pt_include.h"

/*lint -e749*/

static pt_uint8_t _m3ua_buf[(10 * 1024)];
static pt_uint16_t _m3ua_buf_len;
static _M3UA_UP_RECV _m3ua_up_recv;

LIST_HEAD(list_ss7office);

ss7office_t *pt_m3ua_ss7office_alloc(void)
{
    ss7office_t *ss7office;

    ss7office = pt_malloc(sizeof(ss7office_t));
    if (ss7office == NULL)
        return NULL;
    memset(ss7office, 0, sizeof(ss7office_t));

    INIT_LIST_HEAD(&ss7office->list_m3ua_as);

    list_add_tail(&ss7office->node, &list_ss7office);

    return ss7office;
}

void pt_m3ua_ss7office_free(ss7office_t *ss7office)
{
    list_del(&ss7office->node);
    pt_free(ss7office);
}

ss7office_t *pt_m3ua_ss7office_locate(pt_uint32_t officeid)
{
    ss7office_t *ss7office;
    list_head_t *pos;

    list_for_each(pos, &list_ss7office) {
        ss7office = list_entry(pos, ss7office_t, node);
        if (ss7office->officeid == officeid) {
            return ss7office;
        }
    }

    return NULL;
}

m3ua_as_t *pt_m3ua_as_alloc(ss7office_t *ss7office)
{
    m3ua_as_t *m3ua_as;

    m3ua_as = pt_malloc(sizeof(m3ua_as_t));
    if (m3ua_as == NULL) {
        return NULL;
    }
    memset(m3ua_as, 0, sizeof(m3ua_as_t));

    m3ua_as->ss7office = ss7office;

    INIT_LIST_HEAD(&m3ua_as->list_m3ua_asp);

    list_add_tail(&m3ua_as->node, &ss7office->list_m3ua_as);

    return m3ua_as;
}

void pt_m3ua_as_free(m3ua_as_t *m3ua_as)
{
    list_del(&m3ua_as->node);
    pt_free(m3ua_as);
}

m3ua_asp_t *pt_m3ua_asp_alloc(m3ua_as_t *m3ua_as)
{
    m3ua_asp_t *m3ua_asp;

    m3ua_asp = pt_malloc(sizeof(m3ua_asp_t));
    if (m3ua_asp == NULL) {
        return NULL;
    }
    memset(m3ua_asp, 0, sizeof(m3ua_asp_t));

    m3ua_asp->m3ua_as = m3ua_as;

    list_add_tail(&m3ua_asp->node, &m3ua_as->list_m3ua_asp);

    return m3ua_asp;
}

void pt_m3ua_asp_free(m3ua_asp_t *m3ua_asp)
{
    list_del(&m3ua_asp->node);
    pt_free(m3ua_asp);
}

pt_int32_t pt_m3ua_as_status(m3ua_as_t *m3ua_as)
{
    return m3ua_as->as_status;
}

pt_int32_t pt_m3ua_asp_status(m3ua_asp_t *m3ua_asp)
{
    return m3ua_asp->asp_status;
}

pt_int32_t pt_m3ua_asp_conn_status(m3ua_asp_t *m3ua_asp)
{
    return m3ua_asp->conn_status;
}

pt_int32_t pt_m3ua_ss7office_status(ss7office_t *ss7office)
{
    return ss7office->office_status;
}

m3ua_asp_t *pt_m3ua_obtain_spe_asp(ss7office_t *ss7office)
{
    m3ua_as_t *m3ua_as;
    m3ua_asp_t *m3ua_asp;
    list_head_t *pos_as;
    list_head_t *pos_asp;

    list_for_each(pos_as, &ss7office->list_m3ua_as) {
        m3ua_as = list_entry(pos_as, m3ua_as_t, node);
        if (pt_m3ua_as_status(m3ua_as) == M3UA_AS_AC) {
            list_del(&m3ua_as->node);
            list_add_tail(&m3ua_as->node, &ss7office->list_m3ua_as);
            list_for_each(pos_asp, &m3ua_as->list_m3ua_asp) {
                m3ua_asp = list_entry(pos_asp, m3ua_asp_t, node);
                if (pt_m3ua_asp_status(m3ua_asp) == M3UA_ASP_AC) {
                    list_del(&m3ua_asp->node);
                    list_add_tail(&m3ua_asp->node, &m3ua_as->list_m3ua_asp);
                    return m3ua_asp;
                }
                return NULL;
            }
        }
    }

    return NULL;
}

m3ua_asp_t *pt_m3ua_obtain_any_asp(void)
{
    ss7office_t *ss7office;
    m3ua_asp_t  *m3ua_asp;
    list_head_t *pos;

    list_for_each(pos, &list_ss7office) {
        ss7office = list_entry(pos, ss7office_t, node);
        m3ua_asp = pt_m3ua_obtain_spe_asp(ss7office);
        if (m3ua_asp != NULL) {
            list_del(&ss7office->node);
            list_add_tail(&ss7office->node, &list_ss7office);
            return m3ua_asp;
        }
    }

    return NULL;
}

m3ua_asp_t *pt_m3ua_obtain_overload_asp(pt_uint32_t officeid)
{
    ss7office_t *ss7office;

    if (officeid == 0) {
        return pt_m3ua_obtain_any_asp();
    } else {
        ss7office = pt_m3ua_ss7office_locate(officeid);
        if (ss7office != NULL)
            return pt_m3ua_obtain_spe_asp(ss7office);
    }

    return NULL;
}

m3ua_as_useage_e pt_m3ua_as_useage(m3ua_as_t *m3ua_as)
{
    return m3ua_as->useage;
}

/*
 * 对于m3ua来讲 i)控制消息从sctp stream '0' 发出 ii)非控制消息从sctp非stream '0' 发出
 */
pt_int32_t pt_m3ua_send_data_to_conn(m3ua_asp_t *m3ua_asp, pt_uint8_t *in, pt_int32_t len)
{
    PT_LOG(PTLOG_DEBUG, "diam send data to conn, conn_id = %p, in = %p, len = %d", 
            m3ua_asp->conn_id, in, len);
    m3ua_asp->stat_send++;

    return pt_conn_send(m3ua_asp->conn_id, m3ua_asp->seq, in, (pt_uint32_t)len);
}

pt_int32_t pt_m3ua_mgmt_err(m3ua_asp_t *m3ua_asp, void *in, pt_int32_t len)
{
    return 0;
}

pt_int32_t pt_m3ua_mgmt_ntfy(m3ua_asp_t *m3ua_asp, void *in, pt_int32_t len)
{
    return 0;
}

pt_int32_t pt_m3ua_tran_data(m3ua_asp_t *m3ua_asp, void *in, pt_int32_t len)
{
    if (_m3ua_up_recv == NULL) {
        PT_LOG(PTLOG_ERROR, "there is not up recv function!");
        return -1;
    }

    _m3ua_up_recv(m3ua_asp, in, len);
    return 0;
}

pt_int32_t pt_m3ua_ssnm_duna(m3ua_asp_t *m3ua_asp, void *in, pt_int32_t len)
{
    return 0;
}

pt_int32_t pt_m3ua_ssnm_dava(m3ua_asp_t *m3ua_asp, void *in, pt_int32_t len)
{
    return 0;
}

pt_int32_t pt_m3ua_ssnm_daud(m3ua_asp_t *m3ua_asp, void *in, pt_int32_t len)
{
    return 0;
}

pt_int32_t pt_m3ua_ssnm_scon(m3ua_asp_t *m3ua_asp, void *in, pt_int32_t len)
{
    return 0;
}

pt_int32_t pt_m3ua_ssnm_dupu(m3ua_asp_t *m3ua_asp, void *in, pt_int32_t len)
{
    return 0;
}

pt_int32_t pt_m3ua_ssnm_drst(m3ua_asp_t *m3ua_asp, void *in, pt_int32_t len)
{
    return 0;
}

pt_int32_t pt_m3ua_aspsm_aspup(m3ua_asp_t *m3ua_asp, void *in, pt_int32_t len)
{
    m3ua_asp_up_ack_t msg = {0};

    if (-1 ==pt_m3ua_encode(M3UA_ASPSM_ASPUPACK, (void *)&msg, _m3ua_buf, &_m3ua_buf_len)) {
        return -1;
    }

    m3ua_asp->asp_status = M3UA_ASP_IA;
    m3ua_asp->seq = 0;

    return pt_m3ua_send_data_to_conn(m3ua_asp, _m3ua_buf, _m3ua_buf_len);
}

pt_int32_t pt_m3ua_aspsm_aspupack(m3ua_asp_t *m3ua_asp, void *in, pt_int32_t len)
{
    m3ua_asp->asp_status = M3UA_ASP_IA;
    return 0;
}

pt_int32_t pt_m3ua_aspsm_aspdn(m3ua_asp_t *m3ua_asp, void *in, pt_int32_t len)
{
    return 0;
}

pt_int32_t pt_m3ua_aspsm_aspdnack(m3ua_asp_t *m3ua_asp, void *in, pt_int32_t len)
{
    return 0;
}

pt_int32_t pt_m3ua_aspsm_beat(m3ua_asp_t *m3ua_asp, void *in, pt_int32_t len)
{
    return 0;
}

pt_int32_t pt_m3ua_aspsm_beatack(m3ua_asp_t *m3ua_asp, void *in, pt_int32_t len)
{
    return 0;
}

pt_int32_t pt_m3ua_asptm_aspac(m3ua_asp_t *m3ua_asp, void *in, pt_int32_t len)
{
    m3ua_asp_ac_ack_t msg = {0};

    if (-1 == pt_m3ua_encode(M3UA_ASPTM_ASPACACK, (void *)&msg, _m3ua_buf, &_m3ua_buf_len))
    {
        return -1;
    }
    
    m3ua_asp->asp_status = M3UA_ASP_AC;
    m3ua_asp->seq = 0;

    return pt_m3ua_send_data_to_conn(m3ua_asp, _m3ua_buf, _m3ua_buf_len);
}

pt_int32_t pt_m3ua_asptm_aspacack(m3ua_asp_t *m3ua_asp, void *buf, pt_int32_t len)
{
    m3ua_asp->asp_status = M3UA_ASP_AC;
    return 0;
}

pt_int32_t pt_m3ua_asptm_aspia(m3ua_asp_t *m3ua_asp, void *in, pt_int32_t len)
{
    return 0;
}

pt_int32_t pt_m3ua_asptm_aspiaack(m3ua_asp_t *m3ua_asp, void *in, pt_int32_t len)
{
    return 0;
}

pt_int32_t pt_m3ua_rkm_regreq(m3ua_asp_t *m3ua_asp, void *in, pt_int32_t len)
{
    return 0;
}

pt_int32_t pt_m3ua_rkm_regrsp(m3ua_asp_t *m3ua_asp, void *in, pt_int32_t len)
{
    return 0;
}

pt_int32_t pt_m3ua_rkm_deregreq(m3ua_asp_t *m3ua_asp, void *in, pt_int32_t len)
{
    return 0;
}

pt_int32_t pt_m3ua_rkm_deregrsp(m3ua_asp_t *m3ua_asp, void *in, pt_int32_t len)
{
    return 0;
}

/* message class & message type map table*/
static const pt_int32_t _m3ua_msg_mapping[6] = {0, 1, 2, 8, 14, 18};
typedef pt_int32_t(*_M3UA_MSG_FUNC)(m3ua_asp_t *, void *, pt_int32_t);
static const _M3UA_MSG_FUNC _m3ua_msg_func[] =
{
    /*mc-mt     msg handle func*/
    /*0-0*/     pt_m3ua_mgmt_err,
    /*0-1*/     pt_m3ua_mgmt_ntfy,

    /*1-1*/     pt_m3ua_tran_data,

    /*2-1*/     pt_m3ua_ssnm_duna,
    /*2-2*/     pt_m3ua_ssnm_dava,
    /*2-3*/     pt_m3ua_ssnm_daud,
    /*2-4*/     pt_m3ua_ssnm_scon,
    /*2-5*/     pt_m3ua_ssnm_dupu,
    /*2-6*/     pt_m3ua_ssnm_drst,

    /*3-1*/     pt_m3ua_aspsm_aspup,
    /*3-2*/     pt_m3ua_aspsm_aspdn,
    /*3-3*/     pt_m3ua_aspsm_beat,
    /*3-4*/     pt_m3ua_aspsm_aspupack,
    /*3-5*/     pt_m3ua_aspsm_aspdnack,
    /*3-6*/     pt_m3ua_aspsm_beatack,

    /*4-1*/     pt_m3ua_asptm_aspac,
    /*4-2*/     pt_m3ua_asptm_aspia,
    /*4-3*/     pt_m3ua_asptm_aspacack,
    /*4-4*/     pt_m3ua_asptm_aspiaack,

    /*5-1*/     pt_m3ua_rkm_regreq,
    /*5-2*/     pt_m3ua_rkm_regrsp,
    /*5-3*/     pt_m3ua_rkm_deregreq,
    /*5-4*/     pt_m3ua_rkm_deregrsp,
};

pt_int32_t pt_m3ua_recv_msg_notify(m3ua_asp_t *m3ua_asp, pt_conn_msg_notify_t *conn_msg_notify)
{
    PT_LOG(PTLOG_DEBUG, "recv notify msg, conn_id = %p, status = %d!", 
        conn_msg_notify->conn_id, conn_msg_notify->conn_status);

    m3ua_asp->conn_status = conn_msg_notify->conn_status;
    if (m3ua_asp->conn_status != PT_STATUS_ESTABLISHED) {
        m3ua_asp->asp_status = M3UA_ASP_DOWN;
    } 
    return 0;
}

pt_int32_t pt_m3ua_recv_msg_data(m3ua_asp_t *m3ua_asp, pt_conn_msg_data_t *conn_msg_data)
{
    m3ua_common_header_t msg_header;
    pt_int32_t i;

    memcpy(&msg_header, conn_msg_data->data, sizeof(msg_header));

    PT_LOG(PTLOG_DEBUG, "recv data msg, conn_id = %p, msg_class = %u, msg_type = %u!", 
         conn_msg_data->conn_id, msg_header.msg_class, msg_header.msg_type);

    i = _m3ua_msg_mapping[msg_header.msg_class] + msg_header.msg_type;

    return _m3ua_msg_func[i](m3ua_asp, conn_msg_data->data, conn_msg_data->len);
}

pt_int32_t pt_m3ua_recv_msg(m3ua_asp_t *m3ua_asp, pt_conn_msg_t *conn_msg)
{
    pt_int32_t rtn;
    
    m3ua_asp->stat_recv++;

    PT_LOG(PTLOG_DEBUG, "recvmsg, %s-%s", 
            pt_addr_a(&m3ua_asp->conn_item.local_addr[0]),
            pt_addr_a(&m3ua_asp->conn_item.remote_addr[0]));
    
    if (conn_msg->msg_type == PT_CONN_MSG_NOTIFY) {
        rtn = pt_m3ua_recv_msg_notify(m3ua_asp, &conn_msg->msg.msg_notify);
    } else if (conn_msg->msg_type == PT_CONN_MSG_DATA) {
        rtn = pt_m3ua_recv_msg_data(m3ua_asp, &conn_msg->msg.msg_data);
    } else {
        PT_LOG(PTLOG_ERROR, "recv invalid msg, msg_type = %d!", conn_msg->msg_type);
        rtn = -0xfe; 
    }

    return rtn;
}


pt_int32_t pt_m3ua_up_asp(m3ua_asp_t *m3ua_asp)
{
    m3ua_asp_up_t msg = {0};

    m3ua_asp->asp_status = M3UA_ASP_WAIT_IA;

    /*
    msg.asp_identifier_flg = 1;
    msg.asp_identifier = tcb->as_asp[asp_index].asp.aspid;
    */

    if (-1 == pt_m3ua_encode(M3UA_ASPSM_ASPUP, (void *)&msg, _m3ua_buf, &_m3ua_buf_len))
    {
        return -1;
    }
    m3ua_asp->seq = 0;

    PT_LOG(PTLOG_DEBUG, "up asp, %s-%s", 
            pt_addr_a(&m3ua_asp->conn_item.local_addr[0]),
            pt_addr_a(&m3ua_asp->conn_item.remote_addr[0]));

    return pt_m3ua_send_data_to_conn(m3ua_asp, _m3ua_buf, _m3ua_buf_len);
}

pt_int32_t pt_m3ua_ac_asp(m3ua_asp_t *m3ua_asp)
{
    m3ua_asp_ac_t msg = {0};

    m3ua_asp->asp_status = M3UA_ASP_WAIT_AC;

    msg.traffic_mode_flg    = 1;
    msg.traffic_mode        = m3ua_asp->m3ua_as->mode;
    msg.route_context_flg   = m3ua_asp->m3ua_as->route_context_flag;
    msg.route_context       = m3ua_asp->m3ua_as->route_context;

    if (-1 == pt_m3ua_encode(M3UA_ASPTM_ASPAC, (void *)&msg, _m3ua_buf, &_m3ua_buf_len))
    {
        return -1;
    }
    m3ua_asp->seq = 0;

    PT_LOG(PTLOG_DEBUG, "active asp, %s-%s", 
            pt_addr_a(&m3ua_asp->conn_item.local_addr[0]),
            pt_addr_a(&m3ua_asp->conn_item.remote_addr[0]));

    return pt_m3ua_send_data_to_conn(m3ua_asp, _m3ua_buf, _m3ua_buf_len);
}

void pt_m3ua_up_all_asp(m3ua_as_t *m3ua_as)
{
    m3ua_asp_t *m3ua_asp;
    list_head_t *pos;

    list_for_each(pos, &m3ua_as->list_m3ua_asp)
    {
        m3ua_asp = list_entry(pos, m3ua_asp_t, node);
        if (pt_m3ua_asp_conn_status(m3ua_asp) == PT_STATUS_ESTABLISHED &&
            (pt_m3ua_asp_status(m3ua_asp) == M3UA_ASP_DOWN ||
            pt_m3ua_asp_status(m3ua_asp) == M3UA_ASP_WAIT_IA) &&
            pt_m3ua_as_useage(m3ua_as) == M3UA_AS_CLIENT)
        {
            pt_m3ua_up_asp(m3ua_asp);
        }
    }
}

void pt_m3ua_ac_all_asp(m3ua_as_t *m3ua_as)
{
    m3ua_asp_t *m3ua_asp;
    list_head_t *pos;

    list_for_each(pos, &m3ua_as->list_m3ua_asp)
    {
        m3ua_asp = list_entry(pos, m3ua_asp_t, node);
        if (pt_m3ua_asp_conn_status(m3ua_asp) == PT_STATUS_ESTABLISHED &&
            (pt_m3ua_asp_status(m3ua_asp) == M3UA_ASP_IA ||
             pt_m3ua_asp_status(m3ua_asp) == M3UA_ASP_WAIT_AC) &&
            pt_m3ua_as_useage(m3ua_as) == M3UA_AS_CLIENT)
        {
            pt_m3ua_ac_asp(m3ua_asp);
        }
    }
}

void pt_m3ua_update_ss7office_status(ss7office_t *ss7office)
{
    list_head_t *pos;
    m3ua_as_t *m3ua_as;
    pt_uint32_t i = 0;

    list_for_each(pos, &ss7office->list_m3ua_as) {
        m3ua_as = list_entry(pos, m3ua_as_t, node);
        if (m3ua_as->as_status == M3UA_AS_AC)
            i++;
    }

    if (i > 0)
        ss7office->office_status = SS7OFFICE_ACTIVE;
    else
        ss7office->office_status = SS7OFFICE_INACTIVE;
}

void pt_m3ua_update_as_status(m3ua_as_t *m3ua_as)
{
    list_head_t *pos;
    m3ua_asp_t *m3ua_asp;
    pt_uint32_t i = 0;

    list_for_each(pos, &m3ua_as->list_m3ua_asp) {
        m3ua_asp = list_entry(pos, m3ua_asp_t, node);
        if (m3ua_asp->asp_status == M3UA_ASP_AC)
            i++;
    }

    if (i >= m3ua_as->n)
        m3ua_as->as_status = M3UA_AS_AC;
    else if (i > 0)
        m3ua_as->as_status = M3UA_AS_IA;
    else
        m3ua_as->as_status = M3UA_AS_DOWN;
}

void pt_m3ua_monitor(void)
{
    ss7office_t *ss7office;
    m3ua_as_t *m3ua_as;
    list_head_t *pos_ss7office;
    list_head_t *pos_m3ua_as;

    list_for_each(pos_ss7office, &list_ss7office) {
        ss7office = list_entry(pos_ss7office, ss7office_t, node);
        list_for_each(pos_m3ua_as, &ss7office->list_m3ua_as) {
            m3ua_as = list_entry(pos_m3ua_as, m3ua_as_t, node);
            pt_m3ua_up_all_asp(m3ua_as);
            pt_m3ua_ac_all_asp(m3ua_as);

            pt_m3ua_update_as_status(m3ua_as);
        }
        pt_m3ua_update_ss7office_status(ss7office);
    }
}

void *pt_m3ua_thread(void *arg)
{
    for (;;) {
        st_usleep(100000);
        pt_m3ua_monitor();
    }
}

void pt_m3ua_format_spc(pt_char_t *str_spc, pt_uint8_t bin_spc[3])
{
    memset(bin_spc, 0, 3);

    bin_spc[0] = (pt_uint8_t)atoi(str_spc);

    str_spc = strchr(str_spc, '.');
    if (str_spc == NULL)
        return;
    str_spc++;
    bin_spc[1] = (pt_uint8_t)atoi(str_spc);

    str_spc = strchr(str_spc, '.');
    if (str_spc == NULL)
        return;
    str_spc++;
    bin_spc[2] = (pt_uint8_t)atoi(str_spc);
}

ss7office_id_t pt_m3ua_add_ss7office(pt_uint32_t officeid, 
                        pt_uint8_t spc_type, pt_char_t *dpc, pt_char_t *opc)
{
    ss7office_t *ss7office;

    ss7office = pt_m3ua_ss7office_alloc();
    if (ss7office == NULL)
        return NULL;

    ss7office->officeid = officeid;
    ss7office->spc_type = spc_type;
    pt_m3ua_format_spc(dpc, ss7office->dpc);
    pt_m3ua_format_spc(opc, ss7office->opc);

    return ss7office;
}

m3ua_as_id_t pt_m3ua_add_as(ss7office_id_t ss7office_id,
                        m3ua_as_useage_e useage, pt_uint32_t n, pt_uint32_t mode, 
                        pt_uint8_t netapp_flag, pt_uint32_t netapp,
                        pt_uint8_t route_context_flag, pt_uint32_t route_context)
{
    m3ua_as_t *m3ua_as;

    m3ua_as = pt_m3ua_as_alloc(ss7office_id);
    if (m3ua_as == NULL)
        return m3ua_as;

    m3ua_as->useage = useage;
    m3ua_as->n = n;
    m3ua_as->mode = mode;
    m3ua_as->netapp_flag = netapp_flag;
    m3ua_as->netapp = netapp;
    m3ua_as->route_context_flag = route_context_flag;
    m3ua_as->route_context = route_context;

    return m3ua_as;
}

m3ua_asp_id_t pt_m3ua_add_asp(m3ua_as_id_t m3ua_as_id, 
                        pt_int32_t protocol, pt_int32_t service,
                        pt_char_t *local_ip, pt_uint16_t local_port,
                        pt_char_t *remote_ip, pt_uint16_t remote_port)
{
    m3ua_asp_t *m3ua_asp;

    m3ua_asp = pt_m3ua_asp_alloc(m3ua_as_id);
    if (m3ua_asp == NULL)
        return NULL;

    m3ua_asp->conn_item.protocol = protocol;
    m3ua_asp->conn_item.service= service;
    m3ua_asp->conn_item.local_addr_num = 1;
    m3ua_asp->conn_item.remote_addr_num = 1;
    if (strchr(local_ip, '.')) {
        pt_addr_n(PT_AF_INET, local_ip, local_port, &m3ua_asp->conn_item.local_addr[0]);
        pt_addr_n(PT_AF_INET, remote_ip, remote_port, &m3ua_asp->conn_item.remote_addr[0]);
    } else {
        pt_addr_n(PT_AF_INET6, local_ip, local_port, &m3ua_asp->conn_item.local_addr[0]);
        pt_addr_n(PT_AF_INET6, remote_ip, remote_port, &m3ua_asp->conn_item.remote_addr[0]);
    }

    m3ua_asp->conn_item.sctp_ppid = PT_SCTP_PPID_M3UA;
    m3ua_asp->conn_item.handle_data_func = (_PT_HANDLE_DATA)pt_m3ua_recv_msg;
    m3ua_asp->conn_item.handle_data_func_arg = m3ua_asp;
    m3ua_asp->conn_id = pt_conn_add(&m3ua_asp->conn_item);

    return m3ua_asp;
}

void pt_m3ua_dump()
{
    ss7office_t *ss7office;
    m3ua_as_t *m3ua_as;
    m3ua_asp_t *m3ua_asp;
    list_head_t *pos_ss7office;
    list_head_t *pos_m3ua_as;
    list_head_t *pos_m3ua_asp;

    printf("\n%-8s  "
           "%-9s  %-4s  %-7s  %-9s  %-16s  "
           "%-12s  %-11s  %-20s  %-20s  %-15s  %-10s  %s/%s\n",
           "officeid",
           "as_useage",
           "as_n",
           "as_mode",
           "as_netapp",
           "as_route_context",
           "asp_protocol",
           "asp_service",
           "asp_local_addr",
           "asp_remote_addr",
           "asp_conn_status",
           "asp_status",
           "asp_send",
           "asp_recv"
           );

    list_for_each(pos_ss7office, &list_ss7office) {
        ss7office = list_entry(pos_ss7office, ss7office_t, node);
        list_for_each(pos_m3ua_as, &ss7office->list_m3ua_as) {
            m3ua_as = list_entry(pos_m3ua_as, m3ua_as_t, node);
            list_for_each(pos_m3ua_asp, &m3ua_as->list_m3ua_asp) {
                m3ua_asp = list_entry(pos_m3ua_asp, m3ua_asp_t, node);
                printf("%-8d  "
                       "%-9d  %-4d  %-7d  %-9d  %-16d  "
                       "%-12d  %-11d  %-20s  %-20s  %-15d  %-10d  %lu/%lu\n",
                       ss7office->officeid,
                       m3ua_as->useage,
                       m3ua_as->n,
                       m3ua_as->mode,
                       m3ua_as->netapp,
                       m3ua_as->route_context,
                       m3ua_asp->conn_item.protocol, 
                       m3ua_asp->conn_item.service, 
                       pt_addr_a(&m3ua_asp->conn_item.local_addr[0]), 
                       pt_addr_a(&m3ua_asp->conn_item.remote_addr[0]), 
                       m3ua_asp->conn_status,
                       m3ua_asp->asp_status,
                       m3ua_asp->stat_send,
                       m3ua_asp->stat_recv);
            }
        }
    }
}

void pt_m3ua_register_up(_M3UA_UP_RECV func)
{
    _m3ua_up_recv = func;
}

