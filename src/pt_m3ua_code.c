#include "pt_include.h"

/*lint -e734 -e732 -e578*/

static pt_int32_t pt_m3ua_encode_uchar(pt_uint8_t data, void *buf, pt_int32_t pos)
{
    *((pt_uint8_t *)buf + pos) = data;
    return pos += 1;
}

static pt_int32_t pt_m3ua_encode_ushort(pt_uint16_t data, void *buf, pt_int32_t pos)
{
    data = pt_htons(data);
    memcpy((pt_uint8_t *)buf + pos, &data, 2);
    return pos += 2;
}

static pt_int32_t pt_m3ua_encode_uint(pt_uint32_t data, void *buf, pt_int32_t pos)
{
    data = pt_htonl(data);
    memcpy((pt_uint8_t *)buf + pos, &data, 4);
    return pos += 4;
}

static pt_int32_t pt_m3ua_encode_uchar_array(pt_uint8_t *data, pt_int32_t len, void *buf, pt_int32_t pos)
{
    memcpy((pt_uint8_t *)buf + pos, data, len);
    pos += len;

    /*rfc4666 3.2*/
    if (pos & 0x3) {
        *(pt_uint32_t*)((pt_uint8_t *)buf + pos) = 0;
        pos = (pos + 3) & (~3);
    }

    return pos;
}

static pt_int32_t pt_m3ua_encode_asp_identifier(pt_uint32_t asp_identifier, void *buf, pt_int32_t pos)
{
    pt_uint16_t tag = 0x0011;
    pt_uint16_t len = 0x0008;

    pos = pt_m3ua_encode_ushort(tag, buf, pos);
    CHECK_RESULT(pos);

    pos = pt_m3ua_encode_ushort(len, buf, pos);
    CHECK_RESULT(pos);

    pos = pt_m3ua_encode_uint(asp_identifier, buf, pos);
    CHECK_RESULT(pos);

    return pos;
}

static pt_int32_t pt_m3ua_encode_info_string(m3ua_info_string_t info_string, void *buf, pt_int32_t pos)
{
    pt_uint16_t tag = 0x0004;
    pt_uint16_t len = 4 + info_string.num;

    pos = pt_m3ua_encode_ushort(tag, buf, pos);
    CHECK_RESULT(pos);

    pos = pt_m3ua_encode_ushort(len, buf, pos);
    CHECK_RESULT(pos);

    pos = pt_m3ua_encode_uchar_array(info_string.info, info_string.num, buf, pos);
    CHECK_RESULT(pos);

    return pos;
}

static pt_int32_t pt_m3ua_encode_traffic_mode(pt_uint32_t traffic_mode, void *buf, pt_int32_t pos)
{
    pt_uint16_t tag = 0x000b;
    pt_uint16_t len = 0x0008;

    pos = pt_m3ua_encode_ushort(tag, buf, pos);
    CHECK_RESULT(pos);

    pos = pt_m3ua_encode_ushort(len, buf, pos);
    CHECK_RESULT(pos);

    pos = pt_m3ua_encode_uint(traffic_mode, buf, pos);
    CHECK_RESULT(pos);

    return pos;
}

static pt_int32_t pt_m3ua_encode_route_context(pt_uint32_t route_context, void *buf, pt_int32_t pos)
{
    pt_uint16_t tag = 0x0006;
    pt_uint16_t len = 0x0008;

    pos = pt_m3ua_encode_ushort(tag, buf, pos);
    CHECK_RESULT(pos);

    pos = pt_m3ua_encode_ushort(len, buf, pos);
    CHECK_RESULT(pos);

    pos = pt_m3ua_encode_uint(route_context, buf, pos);
    CHECK_RESULT(pos);

    return pos;
}

static pt_int32_t pt_m3ua_encode_net_app(pt_uint32_t net_app, void *buf, pt_int32_t pos)
{
    pt_uint16_t tag = 0x0200;
    pt_uint16_t len = 0x0008;

    pos = pt_m3ua_encode_ushort(tag, buf, pos);
    CHECK_RESULT(pos);

    pos = pt_m3ua_encode_ushort(len, buf, pos);
    CHECK_RESULT(pos);

    pos = pt_m3ua_encode_uint(net_app, buf, pos);
    CHECK_RESULT(pos);

    return pos;
}

static pt_int32_t pt_m3ua_encode_correlation_id(pt_uint32_t correlation_id, void *buf, pt_int32_t pos)
{
    pt_uint16_t tag = 0x0013;
    pt_uint16_t len = 0x0008;

    pos = pt_m3ua_encode_ushort(tag, buf, pos);
    CHECK_RESULT(pos);

    pos = pt_m3ua_encode_ushort(len, buf, pos);
    CHECK_RESULT(pos);

    pos = pt_m3ua_encode_uint(correlation_id, buf, pos);
    CHECK_RESULT(pos);

    return pos;
}

static pt_int32_t pt_m3ua_encode_protocol_data(m3ua_protocol_data_t *protocol_data, void *buf, pt_int32_t pos)
{
    pt_uint16_t tag = 0x0210;
    pt_uint16_t len = 0x0010 + protocol_data->num;

    pos = pt_m3ua_encode_ushort(tag, buf, pos);
    CHECK_RESULT(pos);

    pos = pt_m3ua_encode_ushort(len, buf, pos);
    CHECK_RESULT(pos);

    pos = pt_m3ua_encode_uchar_array((pt_uint8_t *)&protocol_data->opc, 4, buf, pos);
    CHECK_RESULT(pos);

    pos = pt_m3ua_encode_uchar_array((pt_uint8_t *)&protocol_data->dpc, 4, buf, pos);
    CHECK_RESULT(pos);

    pos = pt_m3ua_encode_uchar(protocol_data->si, buf, pos);
    CHECK_RESULT(pos);

    pos = pt_m3ua_encode_uchar(protocol_data->ni, buf, pos);
    CHECK_RESULT(pos);

    pos = pt_m3ua_encode_uchar(protocol_data->mp, buf, pos);
    CHECK_RESULT(pos);

    pos = pt_m3ua_encode_uchar(protocol_data->sls, buf, pos);
    CHECK_RESULT(pos);

    pos = pt_m3ua_encode_uchar_array(protocol_data->data, protocol_data->num, buf, pos);
    CHECK_RESULT(pos);

    return pos;
}

static pt_int32_t pt_m3ua_encode_common_header(pt_uint8_t mc_mt, void *out, pt_int32_t pos)
{
    m3ua_common_header_t header;

    header.version      = M3UA_RELEASE_ONE;
    header.reserved     = 0;
    header.msg_class    = mc_mt >> 4;
    header.msg_type     = mc_mt & 0x0f;
    header.msg_len      = pt_htonl((pt_uint32_t)pos);;/*ÁÙÊ±ÖÃ0*/

    memcpy((pt_uint8_t *)out, &header, sizeof(header));

    return pos;
}

static pt_int32_t pt_m3ua_encode_data(void *msg_struct, void *out, pt_uint16_t *len)
{
    m3ua_payload_data_t *msg = (m3ua_payload_data_t *)msg_struct;
    pt_int32_t pos = 8; /*jump common header*/

    if (msg->netapp_flg)
    {
        pos = pt_m3ua_encode_net_app(msg->netapp, out, pos);
        CHECK_RESULT(pos);
    }

    if (msg->route_context_flg)
    {
        pos = pt_m3ua_encode_route_context(msg->route_context, out, pos);
        CHECK_RESULT(pos);
    }

    pos = pt_m3ua_encode_protocol_data(&msg->protocol_data, out, pos);
    CHECK_RESULT(pos);

    if (msg->correlation_id_flg)
    {
        pos = pt_m3ua_encode_correlation_id(msg->correlation_id, out, pos);
        CHECK_RESULT(pos);
    }

    pos = pt_m3ua_encode_common_header(M3UA_TRAN_DATA, out, pos);
    CHECK_RESULT(pos);

    *len = (pt_uint16_t)pos;

    return pos;
}

static pt_int32_t pt_m3ua_encode_asp_up(void *msg_struct, void *out, pt_uint16_t *len)
{
    m3ua_asp_up_t *msg = (m3ua_asp_up_t *)msg_struct;
    pt_int32_t pos = 8; /*jump common header*/

    if (msg->asp_identifier_flg)
    {
        pos = pt_m3ua_encode_asp_identifier(msg->asp_identifier, out, pos);
        CHECK_RESULT(pos);
    }

    if (msg->info_string_flg)
    {
        pos = pt_m3ua_encode_info_string(msg->info_string, out, pos);
        CHECK_RESULT(pos);
    }

    pos = pt_m3ua_encode_common_header(M3UA_ASPSM_ASPUP, out, pos);
    CHECK_RESULT(pos);

    *len = (pt_uint16_t)pos;

    return pos;
}

static pt_int32_t pt_m3ua_encode_asp_up_ack(void *msg_struct, void *out, pt_uint16_t *len)
{
    m3ua_asp_up_ack_t *msg = (m3ua_asp_up_ack_t *)msg_struct;
    pt_int32_t pos = 8; /*jump common header*/

    if (msg->info_string_flg)
    {
        pos = pt_m3ua_encode_info_string(msg->info_string, out, pos);
        CHECK_RESULT(pos);
    }

    pos = pt_m3ua_encode_common_header(M3UA_ASPSM_ASPUPACK, out, pos);
    CHECK_RESULT(pos);

    *len = (pt_uint16_t)pos;

    return pos;
}

static pt_int32_t pt_m3ua_encode_asp_ac(void *msg_struct, void *out, pt_uint16_t *len)
{
    m3ua_asp_ac_t *msg = (m3ua_asp_ac_t *)msg_struct;
    pt_int32_t pos = 8; /*jump common header*/

    if (msg->traffic_mode_flg)
    {
        pos = pt_m3ua_encode_traffic_mode(msg->traffic_mode, out, pos);
        CHECK_RESULT(pos);
    }

    if (msg->route_context_flg)
    {
        pos = pt_m3ua_encode_route_context(msg->route_context, out, pos);
        CHECK_RESULT(pos);
    }

    if (msg->info_string_flg)
    {
        pos = pt_m3ua_encode_info_string(msg->info_string, out, pos);
        CHECK_RESULT(pos);
    }

    pos = pt_m3ua_encode_common_header(M3UA_ASPTM_ASPAC, out, pos);
    CHECK_RESULT(pos);

    *len = (pt_uint16_t)pos;

    return pos;
}


static pt_int32_t pt_m3ua_encode_asp_acack(void *msg_struct, void *out, pt_uint16_t *len)
{
    m3ua_asp_ac_ack_t *msg = (m3ua_asp_ac_ack_t *)msg_struct;
    pt_int32_t pos = 8; /*jump common header*/

    if (msg->traffic_mode_flg)
    {
        pos = pt_m3ua_encode_traffic_mode(msg->traffic_mode, out, pos);
        CHECK_RESULT(pos);
    }

    if (msg->route_context_flg)
    {
        pos = pt_m3ua_encode_route_context(msg->route_context, out, pos);
        CHECK_RESULT(pos);
    }

    if (msg->info_string_flg)
    {
        pos = pt_m3ua_encode_info_string(msg->info_string, out, pos);
        CHECK_RESULT(pos);
    }

    pos = pt_m3ua_encode_common_header(M3UA_ASPTM_ASPACACK, out, pos);
    CHECK_RESULT(pos);

    *len = (pt_uint16_t)pos;

    return pos;
}

static pt_uint16_t pt_m3ua_decode_get_id(void *buf)
{
    return pt_ntohs(*((pt_uint16_t *)buf));
}

static pt_int32_t pt_m3ua_decode_uchar(void *buf, pt_int32_t pos, pt_uint8_t *data)
{
    *data = *((pt_uint8_t *)buf + pos);
    return pos += 1;
}

static pt_int32_t pt_m3ua_decode_ushort(void *buf, pt_int32_t pos, pt_uint16_t *data)
{
    memcpy(data, (pt_uint8_t *)buf + pos, 2);
    *data = pt_ntohs(*data);
    return pos += 2;
}

static pt_int32_t pt_m3ua_decode_uint(void *buf, pt_int32_t pos, pt_uint32_t *data)
{
    memcpy(data, (pt_uint8_t *)buf + pos, 4);
    *data = pt_ntohl(*data);
    return pos += 4;
}

static pt_int32_t pt_m3ua_decode_uchar_array(void *buf, pt_int32_t len, pt_int32_t pos, pt_uint8_t *data)
{
    memcpy(data, (pt_uint8_t *)buf + pos, len);
    return pos += len;
}

static pt_int32_t pt_m3ua_decode_route_context(void *buf, pt_int32_t pos, pt_uint32_t *route_context)
{
    pos += 4;

    pos = pt_m3ua_decode_uint(buf, pos, route_context);
    CHECK_RESULT(pos);

    return pos;
}

static pt_int32_t pt_m3ua_decode_net_app(void *buf, pt_int32_t pos, pt_uint32_t *net_app)
{
    pos += 4;

    pos = pt_m3ua_decode_uint(buf, pos, net_app);
    CHECK_RESULT(pos);
    return pos;
}

static pt_int32_t pt_m3ua_decode_correlation_id(void *buf, pt_int32_t pos, pt_uint32_t *correlation_id)
{
    pos += 4;

    pos = pt_m3ua_decode_uint(buf, pos, correlation_id);
    CHECK_RESULT(pos);

    return pos;
}

static pt_int32_t pt_m3ua_decode_protocol_data(void *buf, pt_int32_t pos, m3ua_protocol_data_t *protocol_data)
{
    pt_uint16_t protocol_data_len;

    pos += 2;

    pos = pt_m3ua_decode_ushort(buf, pos, &protocol_data_len);
    CHECK_RESULT(pos);

    protocol_data->num = protocol_data_len - 9;

    pos = pt_m3ua_decode_uchar_array(buf, 4, pos, (pt_uint8_t *)&protocol_data->opc);
    CHECK_RESULT(pos);

    pos = pt_m3ua_decode_uchar_array(buf, 4, pos, (pt_uint8_t *)&protocol_data->dpc);
    CHECK_RESULT(pos);

    pos = pt_m3ua_decode_uchar(buf, pos, &protocol_data->si);
    CHECK_RESULT(pos);

    pos = pt_m3ua_decode_uchar(buf, pos, &protocol_data->ni);
    CHECK_RESULT(pos);

    pos = pt_m3ua_decode_uchar(buf, pos, &protocol_data->mp);
    CHECK_RESULT(pos);

    pos = pt_m3ua_decode_uchar(buf, pos, &protocol_data->sls);
    CHECK_RESULT(pos);

    pos = pt_m3ua_decode_uchar_array(buf, protocol_data->num, pos, protocol_data->data);
    CHECK_RESULT(pos);

    return pos;
}


static pt_int32_t pt_m3ua_decode_data(void *in, pt_uint16_t len, void *msg_struct)
{
    m3ua_payload_data_t *msg = (m3ua_payload_data_t *)msg_struct;
    pt_int32_t pos = 8; /*ignore commonheader*/

    if (pt_m3ua_decode_get_id((pt_uint8_t *)in + pos) == 0x0200)
    {
        msg->netapp_flg = 1;
        pos = pt_m3ua_decode_net_app(in, pos, &msg->netapp);
        CHECK_RESULT(pos);
    }

    if (pt_m3ua_decode_get_id((pt_uint8_t *)in + pos) == 0x0006)
    {
        msg->route_context_flg = 1;
        pos = pt_m3ua_decode_route_context(in, pos, &msg->route_context);
        CHECK_RESULT(pos);
    }

    pos = pt_m3ua_decode_protocol_data(in, pos, &msg->protocol_data);
    CHECK_RESULT(pos);

    /*option*/
    if (pos >= len && pt_m3ua_decode_get_id((pt_uint8_t *)in + pos) == 0x0013)
    {
        msg->correlation_id_flg = 1;
        pos = pt_m3ua_decode_correlation_id(in, pos, &msg->correlation_id);
        CHECK_RESULT(pos);
    }

    return 0;
}

/* message class & message type map table*/
static const pt_uint8_t mt_encode_index_beg[6] = {0, 1, 2, 8, 14, 18};
typedef pt_int32_t(*M3UA_ENCODE_FUNC)(void *msg_struct, void *out, pt_uint16_t *len);
static const M3UA_ENCODE_FUNC m3ua_encode_func[] =
{
    /*mc-mt     msg handle func*/
    /*0-0*/     NULL,
    /*0-1*/     NULL,

    /*1-1*/     pt_m3ua_encode_data,

    /*2-1*/     NULL,
    /*2-2*/     NULL,
    /*2-3*/     NULL,
    /*2-4*/     NULL,
    /*2-5*/     NULL,
    /*2-6*/     NULL,

    /*3-1*/     pt_m3ua_encode_asp_up,
    /*3-2*/     NULL,
    /*3-3*/     NULL,
    /*3-4*/     pt_m3ua_encode_asp_up_ack,
    /*3-5*/     NULL,
    /*3-6*/     NULL,

    /*4-1*/     pt_m3ua_encode_asp_ac,
    /*4-2*/     NULL,
    /*4-3*/     pt_m3ua_encode_asp_acack,
    /*4-4*/     NULL,

    /*5-1*/     NULL,
    /*5-2*/     NULL,
    /*5-3*/     NULL,
    /*5-4*/     NULL,
};

pt_int32_t pt_m3ua_encode(pt_uint8_t mc_mt, void *msg_struct, void *out, pt_uint16_t *len)
{
    pt_uint8_t index;

    index = mt_encode_index_beg[mc_mt >> 4] + (mc_mt & 0x0f);

    if (!m3ua_encode_func[index])
    {
        return -1;
    }

    return m3ua_encode_func[index](msg_struct, out, len);
}

static const pt_uint8_t mt_decode_index_beg[6] = {0, 1, 2, 8, 14, 18};
typedef pt_int32_t(*M3UA_DECODE_FUNC)(void *out, pt_uint16_t len, void *msg_struct);
static const M3UA_DECODE_FUNC m3ua_decode_func[] =
{
    /*mc-mt     msg handle func*/
    /*0-0*/     NULL,
    /*0-1*/     NULL,

    /*1-1*/     pt_m3ua_decode_data,

    /*2-1*/     NULL,
    /*2-2*/     NULL,
    /*2-3*/     NULL,
    /*2-4*/     NULL,
    /*2-5*/     NULL,
    /*2-6*/     NULL,

    /*3-1*/     NULL,
    /*3-2*/     NULL,
    /*3-3*/     NULL,
    /*3-4*/     NULL,
    /*3-5*/     NULL,
    /*3-6*/     NULL,

    /*4-1*/     NULL,
    /*4-2*/     NULL,
    /*4-3*/     NULL,
    /*4-4*/     NULL,

    /*5-1*/     NULL,
    /*5-2*/     NULL,
    /*5-3*/     NULL,
    /*5-4*/     NULL,
};

pt_int32_t pt_m3ua_decode(pt_uint8_t mc_mt, void *out, pt_uint16_t len, void *msg_struct)
{
    pt_uint8_t index;

    index = mt_decode_index_beg[mc_mt >> 4] + (mc_mt & 0x0f);

    if (!m3ua_decode_func[index])
    {
        return -1;
    }

    return m3ua_decode_func[index](out, len, msg_struct);
}



