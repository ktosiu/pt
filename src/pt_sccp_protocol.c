#include "pt_include.h"

/*lint -e578*/
pt_uint8_t _sccp_buf[SCCP_MAX_DATA];
pt_uint16_t _sccp_buf_len;
static _SCCP_UP_RECV _sccp_up_recv;

#define MAX_XUDT_BUF 1000
static xudt_buf_t _xudt_buf[MAX_XUDT_BUF];

LIST_HEAD(list_xudt_buf_free);
LIST_HEAD(list_xudt_buf_used);

void pt_sccp_xudt_buf_init(void)
{
    pt_uint16_t i;

    for (i = 0; i < MAX_XUDT_BUF; i++)
        list_add_tail(&_xudt_buf[i].node, &list_xudt_buf_free);
}

xudt_buf_t *pt_sccp_xudt_buf_alloc(sccp_ref_t sccp_ref)
{
    xudt_buf_t *xudt_buf;
    if (list_empty(&list_xudt_buf_free)) {
        return NULL;
    }

    xudt_buf = list_entry(list_xudt_buf_free.next, xudt_buf_t, node);

    list_del(&xudt_buf->node);
    list_add(&xudt_buf->node, &list_xudt_buf_used); /*add recent buf to list head*/

    xudt_buf->time = st_utime(); /*ns*/
    memcpy(xudt_buf->sccp_ref, sccp_ref, sizeof(sccp_ref_t));
    xudt_buf->data_len = 0;

    return xudt_buf;
}

void pt_sccp_xudt_buf_free(xudt_buf_t *xudt_buf)
{
    list_del(&xudt_buf->node);
    list_add_tail(&xudt_buf->node, &list_xudt_buf_free);
}

xudt_buf_t *pt_sccp_xudt_buf_locate(sccp_ref_t sccp_ref)
{
    xudt_buf_t *xudt_buf;
    list_head_t *pos;

    list_for_each(pos, &list_xudt_buf_used) {
        xudt_buf = list_entry(pos, xudt_buf_t, node);
        if (memcmp(sccp_ref, xudt_buf->sccp_ref, sizeof(sccp_ref_t)) == 0)
            return xudt_buf;
    }

    return NULL;
}

#define _XUDT_BUF_AGEING_TIME 800000
void pt_sccp_ageing_xudt_buf()
{
    xudt_buf_t *xudt_buf;
    st_utime_t current;

    current = st_utime();
    while(!list_empty(&list_xudt_buf_used)) {
        xudt_buf = list_entry(list_xudt_buf_used.next, xudt_buf_t, node);
        if (current - xudt_buf->time < _XUDT_BUF_AGEING_TIME)
            break;

        pt_sccp_xudt_buf_free(xudt_buf);
    }
}

pt_uint8_t pt_sccp_get_sls(void)
{
	static pt_uint8_t sls = 0;

	return (sls++ % 15) + 1;
}

void pt_sccp_make_address(pt_uint8_t gtcode[11], pt_uint8_t ssn, sccp_address_t *gt)
{
    gt->tag_spc = 0;
    gt->tag_ssn = 1;
    gt->tag_gt = 4;
    gt->tag_route = 0;
    gt->spare = 0;
    gt->ssn = ssn;
    gt->gt.gt4.trans_type = 0;
    if (pt_bcdlen(gtcode) & 1)
        gt->gt.gt4.code_design = 1;
    else
        gt->gt.gt4.code_design = 2;
    gt->gt.gt4.code_plan = 1;
    gt->gt.gt4.tag_addr = 4;
    gt->gt.gt4.free = 0;
    memcpy(gt->gt.gt4.code, gtcode, sizeof(sccp_gt_code));
}

void pt_sccp_set_m3ua_data_info(m3ua_asp_t *m3ua_asp, m3ua_payload_data_t *m3ua_data_msg)
{
    ss7office_t *ss7office;
    m3ua_as_t *m3ua_as;

    m3ua_as = m3ua_asp->m3ua_as;
    ss7office = m3ua_asp->m3ua_as->ss7office;

    m3ua_data_msg->netapp_flg = m3ua_as->netapp_flag;
    m3ua_data_msg->netapp = m3ua_as->netapp;
    m3ua_data_msg->route_context_flg = m3ua_as->route_context_flag;
    m3ua_data_msg->route_context = m3ua_as->route_context;
    m3ua_data_msg->correlation_id_flg = 0;

    m3ua_data_msg->protocol_data.si = 3;
    m3ua_data_msg->protocol_data.ni = 2;
    m3ua_data_msg->protocol_data.mp = 0;
    m3ua_data_msg->protocol_data.sls = m3ua_asp->seq % 16;
    m3ua_data_msg->protocol_data.opc.mask = 0;
    m3ua_data_msg->protocol_data.dpc.mask = 0;
    memcpy(m3ua_data_msg->protocol_data.opc.pc, ss7office->opc, 3);
    memcpy(m3ua_data_msg->protocol_data.dpc.pc, ss7office->dpc, 3);
}

void pt_sccp_scmg_sst(m3ua_asp_t *m3ua_asp, sccp_udt_t *udt_ind)
{
    m3ua_payload_data_t m3ua_data_msg;
    sccp_udt_t   udt_req;

    udt_req.msg_type = 0x09;
    udt_req.protocol_type = udt_ind->protocol_type;
    udt_req.return_opt = udt_ind->return_opt;
    udt_req.cda = udt_ind->cga;
    udt_req.cga = udt_ind->cda;
    udt_req.tag = 1;
    udt_req.data.scmg.scmg_type = 0x01;
    udt_req.data.scmg.ssn = udt_ind->data.scmg.ssn;
    udt_req.data.scmg.smi = 0;
    memcpy(udt_req.data.scmg.dpc, udt_ind->data.scmg.dpc, 3);

    if (-1 == pt_sccp_encode(m3ua_asp,
                         &udt_req,
                         m3ua_data_msg.protocol_data.data,
                         &m3ua_data_msg.protocol_data.num)) {
        PT_LOG(PTLOG_ERROR, "sccp encode failed!");
        return;
    }

    /*TODO set m3ua parameter*/
    pt_sccp_set_m3ua_data_info(m3ua_asp, &m3ua_data_msg);

    if (-1 == pt_m3ua_encode(M3UA_TRAN_DATA, &m3ua_data_msg, _sccp_buf, &_sccp_buf_len)) {
        return;
    }

    pt_m3ua_send_data_to_conn(m3ua_asp, _sccp_buf, _sccp_buf_len);
}

void pt_sccp_scmg_ind(m3ua_asp_t *m3ua_asp, sccp_udt_t *udt_ind)
{
    switch (udt_ind->data.scmg.scmg_type)
    {
        case 0x01:/*SSA*/
            break;

        case 0x02:/*SSP*/
            break;

        case 0x03:/*SST*/
            pt_sccp_scmg_sst(m3ua_asp, udt_ind);
            break;

        case 0x04:/*SOR*/
            break;

        case 0x05:/*SOG*/
            break;

        case 0x06:/*SSC*/
            break;

        default:
            break;
    }
}

void pt_sccp_udt_ind(m3ua_asp_t *m3ua_asp, sccp_udt_t *udt_ind)
{
    sccp_up_msg_t up_msg;

    if (_sccp_up_recv == NULL) {
        PT_LOG(PTLOG_ERROR, "there is not up recv function!");
        return;
    }

    up_msg.cda = udt_ind->cda;
    up_msg.cga = udt_ind->cga;
    up_msg.data_len = udt_ind->len_ud;
    up_msg.pdata = udt_ind->data.ud;

    _sccp_up_recv(m3ua_asp, &up_msg);
}

void pt_sccp_xudt_ind(m3ua_asp_t *m3ua_asp, sccp_xudt_t *xudt_ind)
{
    xudt_buf_t *xudt_buf;
    sccp_up_msg_t up_msg;

    /*
    if (0 == xudt_ind->tag_segment
        || 1 == xudt_ind->segment.first_ind
        && 0 == xudt_ind->segment.remain_segment)
    {
        return;
    }
    */

    if (xudt_ind->segment.first_ind == 1)
        xudt_buf = pt_sccp_xudt_buf_alloc(xudt_ind->segment.reference);
    else
        xudt_buf = pt_sccp_xudt_buf_locate(xudt_ind->segment.reference);

    if (xudt_buf == NULL) {
        PT_LOG(PTLOG_ERROR, "get xudt_buf failed first_ind = %d!",
                xudt_ind->segment.first_ind);
        return;
    }

    memcpy(&xudt_buf->data[xudt_buf->data_len], &xudt_ind->data, xudt_ind->len_ud);
    xudt_buf->data_len += xudt_ind->len_ud;

    if (0 == xudt_ind->segment.remain_segment)
    {
        pt_sccp_xudt_buf_free(xudt_buf);

        if (_sccp_up_recv == NULL) {
            PT_LOG(PTLOG_ERROR, "there is not up recv function!");
            return;
        }

        up_msg.cda = xudt_ind->cda;
        up_msg.cga = xudt_ind->cga;
        up_msg.data_len = xudt_buf->data_len;
        up_msg.pdata = xudt_buf->data;

        _sccp_up_recv(m3ua_asp, &up_msg);
    }
}

void pt_sccp_recv_msg(m3ua_asp_t *m3ua_asp, pt_uint8_t *in, pt_int32_t len)
{
    m3ua_payload_data_t m3ua_data_msg;
    sccp_msg_u sccp_msg;
    pt_uint8_t sccp_msg_type;

    PT_LOG(PTLOG_DEBUG, "recv msg from m3ua, %s-%s",
            pt_addr_a(&m3ua_asp->conn_item.local_addr[0]),
            pt_addr_a(&m3ua_asp->conn_item.remote_addr[0]));

    if (-1 == pt_m3ua_decode(M3UA_TRAN_DATA, in, (pt_uint16_t)len, &m3ua_data_msg)) {
        PT_LOG(PTLOG_ERROR, "m3ua decode failed!");
        return;
    }

    if (m3ua_data_msg.protocol_data.si != 3) {
        PT_LOG(PTLOG_ERROR, "invalid m3ua protocol data si = %d!",
                m3ua_data_msg.protocol_data.si);
        return;
    }

    if (-1 == pt_sccp_decode(m3ua_asp,
                        m3ua_data_msg.protocol_data.data,
                        m3ua_data_msg.protocol_data.num,
                        &sccp_msg)) {
        PT_LOG(PTLOG_ERROR, "sccp decode failed!");
        return;
    }

    sccp_msg_type = *(m3ua_data_msg.protocol_data.data);
    if (sccp_msg_type == 0x09) {
        if (sccp_msg.udt.tag == 1)
            pt_sccp_scmg_ind(m3ua_asp, &sccp_msg.udt);
        else
            pt_sccp_udt_ind(m3ua_asp, &sccp_msg.udt);
    } else if (sccp_msg_type == 0x11) {
        pt_sccp_xudt_ind(m3ua_asp, &sccp_msg.xudt);
    }
}

pt_int32_t pt_sccp_invoke_udt(m3ua_asp_t *m3ua_asp, sccp_up_msg_t *up_msg)
{
    sccp_udt_t  udt_req;
    m3ua_payload_data_t m3ua_data_msg;

    /*TODO set sccp parameter*/
    udt_req.msg_type = SCCP_MSG_UDT;
    udt_req.return_opt = 8;
    udt_req.protocol_type = 1;

    udt_req.cda = up_msg->cda;
    udt_req.cga = up_msg->cga;

    udt_req.tag = 0;
    udt_req.len_ud = (pt_uint8_t)up_msg->data_len;
    memcpy(udt_req.data.ud, up_msg->pdata, udt_req.len_ud);

    if (-1 == pt_sccp_encode(m3ua_asp,
                         &udt_req,
                         m3ua_data_msg.protocol_data.data,
                         &m3ua_data_msg.protocol_data.num)) {
        PT_LOG(PTLOG_ERROR, "sccp encode failed!");
        return -1;
    }

    /*TODO set m3ua parameter*/
    pt_sccp_set_m3ua_data_info(m3ua_asp, &m3ua_data_msg);

    if (-1 == pt_m3ua_encode(M3UA_TRAN_DATA, &m3ua_data_msg, _sccp_buf, &_sccp_buf_len)) {
        return -1;
    }

    return pt_m3ua_send_data_to_conn(m3ua_asp, _sccp_buf, _sccp_buf_len);
}

pt_uint8_t *pt_sccp_xudt_reference(void)
{
    static pt_uint8_t ref[3] = {0};
    pt_uint16_t *pindex;

    pindex = (pt_uint16_t *)&ref[0];

    (*pindex)++;
    ref[2] = 1;

    return ref;
}

pt_int32_t pt_sccp_invoke_xudt(m3ua_asp_t *m3ua_asp, sccp_up_msg_t *up_msg)
{
    sccp_xudt_t xudt_req;
    m3ua_payload_data_t m3ua_data_msg;
    pt_int32_t ltmp;
    pt_uint8_t *ptmp;

    ptmp = up_msg->pdata;
    ltmp = up_msg->data_len;

    /*TODO set sccp parameter*/
    xudt_req.msg_type = SCCP_MSG_XUDT;
    xudt_req.return_opt = 8;
    xudt_req.protocol_type = 1;
    xudt_req.hop_counter = 15;

    xudt_req.cda = up_msg->cda;
    xudt_req.cga = up_msg->cga;

    xudt_req.tag = 0;
    xudt_req.tag_segment = 1;
    xudt_req.segment.sequence_option = 1;
    xudt_req.segment.first_ind = 1;
    xudt_req.segment.remain_segment =
                (pt_uint8_t)(ltmp / SCCP_XUDT_LEN + (ltmp % SCCP_XUDT_LEN ? 1 : 0));
    memcpy(xudt_req.segment.reference, pt_sccp_xudt_reference(), 3);

    do
    {
        xudt_req.segment.remain_segment -= 1;
        xudt_req.len_ud = (pt_uint8_t)(ltmp > SCCP_XUDT_LEN ? SCCP_XUDT_LEN : ltmp);
        memcpy(xudt_req.data.ud, ptmp, xudt_req.len_ud);
        if (-1 == pt_sccp_encode(m3ua_asp,
                            &xudt_req,
                            m3ua_data_msg.protocol_data.data,
                            &m3ua_data_msg.protocol_data.num)) {
            PT_LOG(PTLOG_ERROR, "sccp encode failed!");
            return -1;
        }


        /*TODO set m3ua parameter*/
        pt_sccp_set_m3ua_data_info(m3ua_asp, &m3ua_data_msg);

        if (-1 == pt_m3ua_encode(M3UA_TRAN_DATA, &m3ua_data_msg, _sccp_buf, &_sccp_buf_len)) {
            return -1;
        }

        if (pt_m3ua_send_data_to_conn(m3ua_asp, _sccp_buf, _sccp_buf_len) < 0)
            return -1;

        xudt_req.segment.first_ind = 0;
        ptmp += xudt_req.len_ud;
        ltmp -= xudt_req.len_ud;
    } while (xudt_req.segment.remain_segment != 0);

    return 0;
}

pt_int32_t pt_sccp_send_data_to_m3ua(m3ua_asp_t *m3ua_asp, sccp_up_msg_t *up_msg)
{
    PT_LOG(PTLOG_DEBUG, "send msg to m3ua, %s-%s",
            pt_addr_a(&m3ua_asp->conn_item.local_addr[0]),
            pt_addr_a(&m3ua_asp->conn_item.remote_addr[0]));

    if (up_msg->data_len > SCCP_XUDT_LEN)
        return pt_sccp_invoke_xudt(m3ua_asp, up_msg);
    else
        return pt_sccp_invoke_udt(m3ua_asp, up_msg);
}

void *pt_sccp_thread(void *arg)
{
    pt_sccp_xudt_buf_init();
    pt_m3ua_register_up(pt_sccp_recv_msg);

    for (;;) {
        st_usleep(100000);
        pt_sccp_ageing_xudt_buf();
    }
}

void pt_sccp_register_up(_SCCP_UP_RECV func)
{
    _sccp_up_recv = func;
}

