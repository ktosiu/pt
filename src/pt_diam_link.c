#include "pt_include.h"

static _DIAM_UP_RECV _diam_up_recv;

LIST_HEAD(list_diam_link);

diam_conn_t *pt_diam_conn_alloc(diam_link_t *diam_link)
{
    diam_conn_t *diam_conn;

    diam_conn = pt_malloc(sizeof(diam_conn_t));
    if (diam_conn == NULL) {
        return NULL;
    }
    memset(diam_conn, 0, sizeof(diam_conn_t));

    diam_conn->conn_id = NULL;
    diam_conn->conn_status = PT_STATUS_CLOSE;
    diam_conn->link_status = DIAM_CLOSED;
    diam_conn->time = 0;

    diam_conn->diam_link = diam_link;

    list_add_tail(&diam_conn->node, &diam_link->list_conn);

    return diam_conn;
}

void pt_diam_conn_free(diam_conn_t *diam_conn)
{
    list_del(&diam_conn->node);

    pt_free(diam_conn);
}

diam_conn_t *pt_diam_conn_locate(diam_link_t *diam_link, pt_conn_id_t conn_id)
{
    diam_conn_t *diam_conn;
    list_head_t *pos;

    list_for_each(pos, &diam_link->list_conn) {
        diam_conn = list_entry(pos, diam_conn_t, node);
        if (diam_conn->conn_id == conn_id) {
            return diam_conn;
        }
    }

    return NULL;
}

diam_link_t *pt_diam_link_alloc(void)
{
    diam_link_t *diam_link;

    diam_link = pt_malloc(sizeof(diam_link_t));
    if (diam_link == NULL) {
        return NULL;
    }
    memset(diam_link, 0, sizeof(diam_link_t));

    INIT_LIST_HEAD(&diam_link->list_conn);

    list_add_tail(&diam_link->node, &list_diam_link);

    return diam_link;
}

void pt_diam_link_free(diam_link_t *diam_link)
{
    list_del(&diam_link->node);

    pt_free(diam_link);
}

diam_link_t *pt_diam_link_locate(pt_uint32_t link_id)
{
    diam_link_t *diam_link;
    list_head_t *pos;

    list_for_each(pos, &list_diam_link) {
        diam_link = list_entry(pos, diam_link_t, node);
        if (diam_link->link_id == link_id) {
            return diam_link;
        }
    }

    return NULL;
}

diam_link_status_e pt_diam_conn_status(diam_conn_t *diam_conn)
{
    return diam_conn->link_status;
}

pt_int32_t pt_diam_send_data_to_conn(diam_conn_t *diam_conn, pt_uint8_t *in, pt_int32_t len)
{
    PT_LOG(PTLOG_DEBUG, "diam send data to conn, conn_id = %p, in = %p, len = %d", 
            diam_conn->conn_id, in, len);
    diam_conn->stat_send++;

    return pt_conn_send(diam_conn->conn_id, diam_conn->seq++, in, (pt_uint32_t)len);
}

diam_conn_t *pt_diam_obtain_spe_link_conn(diam_link_t *diam_link)
{
    diam_conn_t *diam_conn;
    list_head_t *pos;

    diam_conn = NULL;
    list_for_each(pos, &diam_link->list_conn) {
        diam_conn = list_entry(pos, diam_conn_t, node);
        if (pt_diam_conn_status(diam_conn) == DIAM_OPEN) {
            list_del(&diam_conn->node);
            list_add_tail(&diam_conn->node, &diam_link->list_conn);
            return diam_conn;
        }
    }

    return NULL;
}

diam_conn_t *pt_diam_obtain_any_link_conn(void)
{
    diam_link_t *diam_link;
    diam_conn_t *diam_conn;
    list_head_t *pos;

    list_for_each(pos, &list_diam_link) {
        diam_link = list_entry(pos, diam_link_t, node);
        diam_conn = pt_diam_obtain_spe_link_conn(diam_link);
        if (diam_conn != NULL) {
            list_del(&diam_link->node);
            list_add_tail(&diam_link->node, &list_diam_link);
            return diam_conn;
        }
    }

    return NULL;
}

diam_conn_t *pt_diam_obtain_overload_conn(pt_uint32_t link_id)
{
    diam_link_t *diam_link;

    if (link_id == 0) {
        return pt_diam_obtain_any_link_conn();
    } else {
        diam_link = pt_diam_link_locate(link_id);
        if (diam_link != NULL)
            return pt_diam_obtain_spe_link_conn(diam_link);
    }

    return NULL;
}

void pt_diam_init_msg_head(diam_head_t *diam_head, pt_uint8_t cmd_flg, pt_uint32_t cmd_code)
{
    static pt_uint32_t hopbyhop = 0;
    static pt_uint32_t endtoend = 0;

    diam_head->version = 1;
    diam_head->msg_len = 0;
    diam_head->cmd_flg = cmd_flg;
    diam_head->cmd_code = cmd_code;
    diam_head->app_id = 0;
    diam_head->h_by_h_id = hopbyhop++;
    diam_head->e_to_e_id = endtoend++;
}

void pt_diam_send_ce(diam_conn_t *diam_conn)
{
    pt_uint8_t buf[1024] = {0};
    pt_int32_t pos = 0;
    list_head_t *groups;
    diam_msg_t msg;

    INIT_LIST_HEAD(&msg.avps);

    pt_diam_init_msg_head(&msg.diam_head, DIAM_CMD_FLG_R, 257);

    pt_diam_add_avp_str(&msg.avps, 264, AVP_FLAG_M, diam_conn->diam_link->diam_info.local_host_name);
    pt_diam_add_avp_str(&msg.avps, 296, AVP_FLAG_M, diam_conn->diam_link->diam_info.local_realm);
    pt_diam_add_avp_addr(&msg.avps, 257, AVP_FLAG_M, pt_addr_a(&diam_conn->conn_item.local_addr[0]));
    pt_diam_add_avp_uint32(&msg.avps, 266, AVP_FLAG_M, DIM_VENDOR_ZTE);
    pt_diam_add_avp_str(&msg.avps, 269, AVP_FLAG_NULL, "PT");
    pt_diam_add_avp_uint32(&msg.avps, 278, AVP_FLAG_M, 0);
    pt_diam_add_avp_uint32(&msg.avps, 265, AVP_FLAG_M, DIM_VENDOR_3GPP);
    pt_diam_add_avp_uint32(&msg.avps, 258, AVP_FLAG_M, DIM_APPID_RELAY);
    pt_diam_add_avp_uint32(&msg.avps, 258, AVP_FLAG_M, 4);
    pt_diam_add_avp_groups(&msg.avps, 260, AVP_FLAG_M, &groups);
    pt_diam_add_avp_uint32(groups, 266, AVP_FLAG_M, DIM_VENDOR_3GPP);
    pt_diam_add_avp_uint32(groups, 258, AVP_FLAG_M, DIM_APPID_RELAY);
    pt_diam_add_avp_uint32(&msg.avps, 267, AVP_FLAG_NULL, 0);

    pos = pt_diam_encode_msg(&msg, buf, pos);

    if (-1 == pos)
    {
        return;
    }

    pt_diam_send_data_to_conn(diam_conn, buf, (pt_uint16_t)pos);
    diam_conn->time = DIM_CE_INTERVAL;

    pt_diam_prn_msg(&msg);

    pt_diam_del_avps(&msg.avps);
}

void pt_diam_send_dw(diam_conn_t *diam_conn)
{
    pt_uint8_t buf[1024] = {0};
    pt_int32_t pos = 0;
    diam_msg_t msg;

    INIT_LIST_HEAD(&msg.avps);

    pt_diam_init_msg_head(&msg.diam_head, DIAM_CMD_FLG_R, 280);

    pt_diam_add_avp_str(&msg.avps, 264, AVP_FLAG_M, diam_conn->diam_link->diam_info.local_host_name);
    pt_diam_add_avp_str(&msg.avps, 296, AVP_FLAG_M, diam_conn->diam_link->diam_info.local_realm);
    pt_diam_add_avp_uint32(&msg.avps, 278, AVP_FLAG_M, 0);

    pos = pt_diam_encode_msg(&msg, buf, pos);

    if (-1 == pos)
    {
        return;
    }

    pt_diam_send_data_to_conn(diam_conn, buf, (pt_uint16_t)pos);
    diam_conn->time = DIM_DW_INTERVAL;

    pt_diam_prn_msg(&msg);

    pt_diam_del_avps(&msg.avps);
}

void pt_diam_recv_ce(diam_conn_t *diam_conn, pt_uint8_t *in, pt_int32_t len)
{
    pt_uint8_t buf[1024] = {0};
    pt_int32_t pos = 0;
    list_head_t *groups;
    diam_msg_t msg;
    diam_head_t diam_head;

    if (-1 == pt_diam_decode_diam_head(in, 0, &diam_head))
    {
        return;
    }

    INIT_LIST_HEAD(&msg.avps);

    if (diam_head.cmd_flg & DIAM_CMD_FLG_R)
    {
        msg.diam_head = diam_head;
        msg.diam_head.cmd_flg = AVP_FLAG_NULL;
        msg.diam_head.msg_len = 0;

        pt_diam_add_avp_uint32(&msg.avps, 268, AVP_FLAG_M, DIM_RETURN_OK);
        pt_diam_add_avp_str(&msg.avps, 264, AVP_FLAG_M, diam_conn->diam_link->diam_info.local_host_name);
        pt_diam_add_avp_str(&msg.avps, 296, AVP_FLAG_M, diam_conn->diam_link->diam_info.local_realm);
        pt_diam_add_avp_addr(&msg.avps, 257, AVP_FLAG_M, pt_addr_a(&diam_conn->conn_item.local_addr[0]));
        pt_diam_add_avp_uint32(&msg.avps, 266, AVP_FLAG_M, DIM_VENDOR_ZTE);
        pt_diam_add_avp_str(&msg.avps, 269, AVP_FLAG_NULL, "PT");
        pt_diam_add_avp_uint32(&msg.avps, 278, AVP_FLAG_M, 0);
        pt_diam_add_avp_uint32(&msg.avps, 265, AVP_FLAG_M, DIM_VENDOR_3GPP);
        pt_diam_add_avp_uint32(&msg.avps, 258, AVP_FLAG_M, DIM_APPID_RELAY);
        pt_diam_add_avp_uint32(&msg.avps, 258, AVP_FLAG_M, 4);
        pt_diam_add_avp_groups(&msg.avps, 260, AVP_FLAG_M, &groups);
        pt_diam_add_avp_uint32(groups, 266, AVP_FLAG_M, DIM_VENDOR_3GPP);
        pt_diam_add_avp_uint32(groups, 258, AVP_FLAG_M, DIM_APPID_RELAY);
        pt_diam_add_avp_uint32(&msg.avps, 267, AVP_FLAG_NULL, 0);

        pt_diam_prn_msg(&msg);

        pos = pt_diam_encode_msg(&msg, buf, pos);

        if (-1 == pos)
        {
            return;
        }

        pt_diam_send_data_to_conn(diam_conn, buf, (pt_uint16_t)pos);

        pt_diam_prn_msg(&msg);

        pt_diam_del_avps(&msg.avps);
    }
    else
    {
        pt_diam_send_dw(diam_conn);
    }

    diam_conn->link_status = DIAM_OPEN;
}

void pt_diam_recv_dw(diam_conn_t *diam_conn, pt_uint8_t *in, pt_int32_t len)
{
    pt_uint8_t buf[1024] = {0};
    pt_int32_t pos = 0;
    diam_msg_t msg;
    diam_head_t diam_head;

    if (-1 == pt_diam_decode_diam_head(in, 0, &diam_head))
    {
        return;
    }

    INIT_LIST_HEAD(&msg.avps);

    if (diam_head.cmd_flg & DIAM_CMD_FLG_R)
    {
        msg.diam_head = diam_head;
        msg.diam_head.cmd_flg = DIAM_CMD_FLG_NULL;
        msg.diam_head.msg_len = 0;

        pt_diam_add_avp_uint32(&msg.avps, 268, AVP_FLAG_M, 2001);
        pt_diam_add_avp_str(&msg.avps, 264, AVP_FLAG_M, diam_conn->diam_link->diam_info.local_host_name);
        pt_diam_add_avp_str(&msg.avps, 296, AVP_FLAG_M, diam_conn->diam_link->diam_info.local_realm);
        pt_diam_add_avp_uint32(&msg.avps, 278, AVP_FLAG_M, 0);

        pos = pt_diam_encode_msg(&msg, buf, pos);

        if (-1 == pos)
        {
            return;
        }

        pt_diam_send_data_to_conn(diam_conn, buf, (pt_uint16_t)pos);

        pt_diam_prn_msg(&msg);

        pt_diam_del_avps(&msg.avps);
    }
}

/* cli send cer immediate and svr delay send cer when recv conn up notify */ 
pt_int32_t pt_diam_recv_msg_notify(diam_conn_t *diam_conn, pt_conn_msg_notify_t *conn_msg_notify)
{
    PT_LOG(PTLOG_DEBUG, "recv notify msg, link_id = %u, conn_id = %p, status = %d!", 
        diam_conn->diam_link->link_id, conn_msg_notify->conn_id, conn_msg_notify->conn_status);

    diam_conn->conn_status = conn_msg_notify->conn_status;
    if (diam_conn->conn_status != PT_STATUS_ESTABLISHED) {
        diam_conn->link_status = DIAM_CLOSED;
    } else if (diam_conn->conn_item.service == PT_SERVICE_SRV) {
        diam_conn->time = DIM_CE_INTERVAL;
    } else {
        diam_conn->time = 0;
    }

    return 0;
}

pt_int32_t pt_diam_recv_msg_data(diam_conn_t *diam_conn, pt_conn_msg_data_t *conn_msg_data)
{
    pt_uint8_t *data;
    pt_int32_t len;
    pt_uint32_t cmdcode;

    data = conn_msg_data->data;
    len = conn_msg_data->len;
    cmdcode = pt_diam_get_cmd_code(data, len);

    PT_LOG(PTLOG_DEBUG, "recv data msg, link_id = %u, conn_id = %p, "
                        "cmdcode = %u, data = %p, len = %u!", 
        diam_conn->diam_link->link_id, conn_msg_data->conn_id, cmdcode, data, len);
    
    switch (cmdcode)
    {
        case DIAM_COM_CMD_AS:
            break;

        case DIAM_COM_CMD_AC:
            break;

        case DIAM_COM_CMD_CE:
            pt_diam_recv_ce(diam_conn, data, len);
            break;

        case DIAM_COM_CMD_DW:
            pt_diam_recv_dw(diam_conn, data, len);
            break;

        case DIAM_COM_CMD_DP:
            break;

        case DIAM_COM_CMD_RA:
            break;

        case DIAM_COM_CMD_ST:
            break;

        default:
            if (_diam_up_recv != NULL)
                _diam_up_recv(diam_conn, data, len);
            diam_conn->time = DIM_DW_INTERVAL;
            break;
    }

    return 0;
}

pt_int32_t pt_diam_recv_msg(diam_conn_t *diam_conn, pt_conn_msg_t *conn_msg)
{
    pt_int32_t rtn;
    
    diam_conn->stat_recv++;
    
    if (conn_msg->msg_type == PT_CONN_MSG_NOTIFY) {
        rtn = pt_diam_recv_msg_notify(diam_conn, &conn_msg->msg.msg_notify);
    } else if (conn_msg->msg_type == PT_CONN_MSG_DATA) {
        rtn = pt_diam_recv_msg_data(diam_conn, &conn_msg->msg.msg_data);
    } else {
        PT_LOG(PTLOG_ERROR, "recv invalid msg, msg_type = %d!", conn_msg->msg_type);
        rtn = -0xfe; 
    }

    return rtn;
}


void pt_diam_timeout(diam_conn_t *diam_conn)
{
    diam_conn->time--;

    /*第一次立即发*/
    if (diam_conn->time > 0)
    {
        return;
    }

    switch (pt_diam_conn_status(diam_conn))
    {
        case DIAM_CLOSED:
            pt_diam_send_ce(diam_conn);
            break;

        case DIAM_OPEN:
            pt_diam_send_dw(diam_conn);
            break;

        default:
            break;
    }
}

void pt_diam_monitor_link(void)
{
    diam_link_t *diam_link;
    diam_conn_t *diam_conn;
    list_head_t *pos_link;
    list_head_t *pos_conn;
    
    list_for_each(pos_link, &list_diam_link) {
        diam_link = list_entry(pos_link, diam_link_t, node);
        list_for_each(pos_conn, &diam_link->list_conn) {
            diam_conn = list_entry(pos_conn, diam_conn_t, node);
            if (diam_conn->conn_status == PT_STATUS_ESTABLISHED) {
                pt_diam_timeout(diam_conn);
            }
        }
    }
}

void *pt_diam_thread(void *arg)
{
    for (;;) {
        st_usleep(100000);
        pt_diam_monitor_link();
    }
}

diam_conn_id_t pt_diam_add_conn(diam_link_id_t diam_link_id, 
                    pt_int32_t protocol, pt_int32_t service,
                    pt_char_t *local_ip, pt_uint16_t local_port,
                    pt_char_t *remote_ip, pt_uint16_t remote_port)
{
    diam_link_t *diam_link;
    diam_conn_t *diam_conn;

    diam_link = diam_link_id;
    diam_conn = pt_diam_conn_alloc(diam_link);
    if (diam_conn == NULL)
        return NULL;

    diam_conn->conn_item.protocol = protocol;
    diam_conn->conn_item.service= service;
    diam_conn->conn_item.local_addr_num = 1;
    diam_conn->conn_item.remote_addr_num = 1;
    if (strchr(local_ip, '.')) {
        pt_addr_n(PT_AF_INET, local_ip, local_port, &diam_conn->conn_item.local_addr[0]);
        pt_addr_n(PT_AF_INET, remote_ip, remote_port, &diam_conn->conn_item.remote_addr[0]);
    } else {
        pt_addr_n(PT_AF_INET6, local_ip, local_port, &diam_conn->conn_item.local_addr[0]);
        pt_addr_n(PT_AF_INET6, remote_ip, remote_port, &diam_conn->conn_item.remote_addr[0]);
    }

    diam_conn->conn_item.sctp_ppid = PT_SCTP_PPID_DIAM;
    
    diam_conn->conn_item.handle_data_func = (_PT_HANDLE_DATA)pt_diam_recv_msg;
    diam_conn->conn_item.handle_data_func_arg = diam_conn;
    diam_conn->conn_id = pt_conn_add(&diam_conn->conn_item);

    return diam_conn;
}

void pt_diam_del_conn(diam_conn_id_t diam_conn_id)
{
    diam_conn_t *diam_conn;
    
    diam_conn = diam_conn_id;
    pt_conn_del(diam_conn->conn_id);
    pt_diam_conn_free(diam_conn);
}

diam_link_id_t pt_diam_add_link(pt_uint32_t link_id, 
                    pt_char_t *local_host_name, pt_char_t *local_realm,
                    pt_char_t *remote_host_name, pt_char_t *remote_realm)
{
    diam_link_t *diam_link;

    if (pt_diam_link_locate(link_id) != NULL)
        return NULL;
    
    diam_link = pt_diam_link_alloc();
    if (diam_link == NULL)
        return NULL;

    /*tcp*/
    diam_link->link_id = link_id;
    strcpy(diam_link->diam_info.local_host_name, local_host_name);
    strcpy(diam_link->diam_info.local_realm, local_realm);

    strcpy(diam_link->diam_info.remote_host_name, remote_host_name);
    strcpy(diam_link->diam_info.remote_realm, remote_realm);

    return diam_link;
}

void pt_diam_del_link(diam_link_id_t diam_link_id)
{
    diam_link_t *diam_link;
    diam_conn_t *diam_conn;

    diam_link = diam_link_id;
    
    while (!list_empty(&diam_link->list_conn)) {
        diam_conn = list_entry(diam_link->list_conn.next, diam_conn_t, node);
        pt_diam_del_conn(diam_conn);
    }

    pt_diam_link_free(diam_link);
}

void pt_diam_dump(void)
{
    diam_link_t *diam_link;
    diam_conn_t *diam_conn;
    list_head_t *pos_link;
    list_head_t *pos_conn;

    printf("\n%-7s  %-18s  %-12s  %-18s  %-12s  %-8s  %-7s  %-20s  %-20s  %-11s  %-11s  %s/%s\n",
           "link_id",
           "local_host",
           "local_realm",
           "remote_host",
           "remote_realm",
           "protocol",
           "service",
           "local_addr",
           "remote_addr",
           "conn_status",
           "link_status",
           "send",
           "recv"
           );
    
    list_for_each(pos_link, &list_diam_link) {
        diam_link = list_entry(pos_link, diam_link_t, node);
        list_for_each(pos_conn, &diam_link->list_conn) {
            diam_conn = list_entry(pos_conn, diam_conn_t, node);
            printf("%-7u  %-18s  %-12s  %-18s  %-12s  %-8d  %-7d  %-20s  %-20s  %-11d  %-11d  %lu/%lu\n",
                   diam_link->link_id,
                   diam_link->diam_info.local_host_name,
                   diam_link->diam_info.local_realm,
                   diam_link->diam_info.remote_host_name,
                   diam_link->diam_info.remote_realm,
                   diam_conn->conn_item.protocol, 
                   diam_conn->conn_item.service, 
                   pt_addr_a(&diam_conn->conn_item.local_addr[0]), 
                   pt_addr_a(&diam_conn->conn_item.remote_addr[0]), 
                   diam_conn->conn_status,
                   diam_conn->link_status,
                   diam_conn->stat_send,
                   diam_conn->stat_recv
                   );
        }
    }
    printf("\n");
}

void pt_diam_register_up(_DIAM_UP_RECV func)
{
    _diam_up_recv = func;
}

