#include "pt_include.h"
#include "pt_diam.h"

pt_int32_t pt_diam_encode_octs(pt_uint8_t *octs, pt_uint8_t len, void *buf, pt_int32_t pos)
{
    pt_uint32_t i;

    for (i = 0; i < len; i++)
    {
        *(((pt_uint8_t *)buf + pos + len - 1) - i) = *(octs + i);
    }

    return pos + len;
}

pt_int32_t pt_diam_encode_utf8string(pt_char_t *octet_string, void *buf, pt_int32_t pos)
{
    memcpy((pt_uint8_t *)buf + pos, octet_string, strlen(octet_string));

    return (pos + (pt_int32_t)strlen(octet_string));
}

pt_int32_t pt_diam_encode_unsigned32(pt_uint32_t unsigned32, void *buf, pt_int32_t pos)
{
    pos = pt_diam_encode_octs((pt_uint8_t *)&unsigned32, 4, buf, pos);

    return pos;
}

pt_int32_t pt_diam_encode_groups(list_head_t *groups, void *buf, pt_int32_t pos)
{
    diam_buf_t  *diam_buf;
    list_head_t *list_pos;

    list_for_each(list_pos, groups)
    {
        diam_buf = list_entry(list_pos, diam_buf_t, list);

        pos = pt_diam_encode_avp(&diam_buf->avp, buf, pos);
        CHECK_RESULT(pos);
    }

    return pos;
}

pt_int32_t pt_diam_encode_address(avp_address_t *address, void *buf, pt_int32_t pos)
{
    pos = pt_diam_encode_octs((pt_uint8_t *)&address->family, 2, buf, pos);
    CHECK_RESULT(pos);

    pos = pt_diam_encode_octs((pt_uint8_t *)&address->ip.ipv4, 4, buf, pos);
    CHECK_RESULT(pos);

    return pos;
}

pt_int32_t pt_diam_encode_binary(avp_binary_t *binary, void *buf, pt_int32_t pos)
{
    memcpy((pt_uint8_t *)buf + pos, binary->data, binary->len);
    pos += binary->len;

    return pos;
}

pt_int32_t pt_diam_encode_diam_head(diam_head_t *diam_head, void *buf, pt_int32_t pos)
{
    pt_uint32_t octs;

    octs = diam_head->version;
    pos = pt_diam_encode_octs((pt_uint8_t *)&octs, 1, buf, pos);
    CHECK_RESULT(pos);

    octs = diam_head->msg_len;
    pos = pt_diam_encode_octs((pt_uint8_t *)&octs, 3, buf, pos);
    CHECK_RESULT(pos);

    octs = diam_head->cmd_flg;
    pos = pt_diam_encode_octs((pt_uint8_t *)&octs, 1, buf, pos);
    CHECK_RESULT(pos);

    octs = diam_head->cmd_code;
    pos = pt_diam_encode_octs((pt_uint8_t *)&octs, 3, buf, pos);
    CHECK_RESULT(pos);

    pos = pt_diam_encode_octs((pt_uint8_t *)&diam_head->app_id, 4, buf, pos);
    CHECK_RESULT(pos);

    pos = pt_diam_encode_octs((pt_uint8_t *)&diam_head->h_by_h_id, 4, buf, pos);
    CHECK_RESULT(pos);

    pos = pt_diam_encode_octs((pt_uint8_t *)&diam_head->e_to_e_id, 4, buf, pos);
    CHECK_RESULT(pos);

    return pos;
}

pt_int32_t pt_diam_encode_avp_head(avp_head_t *avp_head, void *buf, pt_int32_t pos)
{
    pt_uint32_t octs;

    pos = pt_diam_encode_octs((pt_uint8_t *)&avp_head->avp_code, 4, buf, pos);
    CHECK_RESULT(pos);

    octs = avp_head->avp_flg;
    pos = pt_diam_encode_octs((pt_uint8_t *)&octs, 1, buf, pos);
    CHECK_RESULT(pos);

    octs = avp_head->avp_len;
    pos = pt_diam_encode_octs((pt_uint8_t *)&octs, 3, buf, pos);
    CHECK_RESULT(pos);

    if (AVP_FLAG_V & avp_head->avp_flg)
    {
        pos = pt_diam_encode_octs((pt_uint8_t *)&avp_head->vendor_id, 4, buf, pos);
        CHECK_RESULT(pos);
    }

    return pos;
}

pt_int32_t pt_diam_encode_avp_data(avp_data_t *avp_data, void *buf, pt_int32_t pos)
{
    switch (avp_data->format)
    {
        case AVP_FORMAT_UTF8STRING:
            pos = pt_diam_encode_utf8string(avp_data->value.octet_string, buf, pos);
            break;

        case AVP_FORMAT_UNINTEGER32:
            pos = pt_diam_encode_unsigned32(avp_data->value.unsigned32, buf, pos);
            break;

        case AVP_FORMAT_GROUPS:
            pos = pt_diam_encode_groups(&avp_data->value.groups, buf, pos);
            break;

        case AVP_FORMAT_ADDRESS:
            pos = pt_diam_encode_address(&avp_data->value.address, buf, pos);
            break;

        case AVP_FORMAT_OCTERSTRING:
            pos = pt_diam_encode_binary(&avp_data->value.binary, buf, pos);
            break;

        default:
            pos = -1;
            break;
    }

    return pos;
}

pt_int32_t pt_diam_encode_avp(avp_t *avp, void *buf, pt_int32_t pos)
{
    pt_int32_t tmp = pos;
    pt_uint32_t octs;

    pos = pt_diam_encode_avp_head(&avp->avp_head, buf, pos);
    CHECK_RESULT(pos);

    pos = pt_diam_encode_avp_data(&avp->data, buf, pos);
    CHECK_RESULT(pos);

    octs = avp->avp_head.avp_len = (pt_uint32_t)(pos - tmp);
    tmp = pt_diam_encode_octs((pt_uint8_t *)&octs, 3, buf, tmp + 5);
    CHECK_RESULT(tmp);

    tmp = avp->avp_head.avp_len % 4;

    if (tmp)
    {
        pos += 4 - tmp;
    }

    return pos;
}

pt_int32_t pt_diam_encode_msg(diam_msg_t *msg, void *buf, pt_int32_t pos)
{
    diam_buf_t  *diam_buf;
    list_head_t *list_pos;
    pt_int32_t tmp = pos;
    pt_uint32_t octs;

    pos = pt_diam_encode_diam_head(&msg->diam_head, buf, pos);
    CHECK_RESULT(pos);

    list_for_each(list_pos, &msg->avps)
    {
        diam_buf = list_entry(list_pos, diam_buf_t, list);

        pos = pt_diam_encode_avp(&diam_buf->avp, buf, pos);
        CHECK_RESULT(pos);
    }

    octs = msg->diam_head.msg_len = (pt_uint32_t)(pos - tmp);
    tmp = pt_diam_encode_octs((pt_uint8_t *)&octs, 3, buf, tmp + 1);
    CHECK_RESULT(tmp);

    return pos;
}

pt_int32_t pt_diam_decode_octs(void *buf, pt_int32_t pos, pt_uint8_t *octs, pt_uint8_t len)
{
    pt_uint8_t i;

    for (i = 0; i < len; i++)
    {
        *(octs + i) = *(((pt_uint8_t *)buf + pos + len - 1) - i);
    }

    return pos + len;
}

pt_int32_t pt_diam_decode_diam_head(void *buf, pt_int32_t pos, diam_head_t *diam_head)
{
    pt_uint32_t octs;

    pos = pt_diam_decode_octs(buf, pos, (pt_uint8_t *)&octs, 1);
    CHECK_RESULT(pos);
    diam_head->version = octs;

    pos = pt_diam_decode_octs(buf, pos, (pt_uint8_t *)&octs, 3);
    CHECK_RESULT(pos);
    diam_head->msg_len = octs;

    pos = pt_diam_decode_octs(buf, pos, (pt_uint8_t *)&octs, 1);
    CHECK_RESULT(pos);
    diam_head->cmd_flg = octs;

    pos = pt_diam_decode_octs(buf, pos, (pt_uint8_t *)&octs, 3);
    CHECK_RESULT(pos);
    diam_head->cmd_code = octs;

    pos = pt_diam_decode_octs(buf, pos, (pt_uint8_t *)&diam_head->app_id, 4);
    CHECK_RESULT(pos);

    pos = pt_diam_decode_octs(buf, pos, (pt_uint8_t *)&diam_head->h_by_h_id, 4);
    CHECK_RESULT(pos);

    pos = pt_diam_decode_octs(buf, pos, (pt_uint8_t *)&diam_head->e_to_e_id, 4);
    CHECK_RESULT(pos);

    return pos;
}

pt_int32_t pt_diam_decode_avp_head(void *buf, pt_int32_t pos, avp_head_t *avp_head)
{
    pt_uint32_t octs;

    pos = pt_diam_decode_octs(buf, pos, (pt_uint8_t *)&avp_head->avp_code, 4);
    CHECK_RESULT(pos);

    pos = pt_diam_decode_octs(buf, pos, (pt_uint8_t *)&octs, 1);
    CHECK_RESULT(pos);
    avp_head->avp_flg = octs;

    pos = pt_diam_decode_octs(buf, pos, (pt_uint8_t *)&octs, 3);
    CHECK_RESULT(pos);
    avp_head->avp_len = octs;

    if (AVP_FLAG_V & avp_head->avp_flg)
    {
        pos = pt_diam_decode_octs(buf, pos, (pt_uint8_t *)&avp_head->vendor_id, 4);
        CHECK_RESULT(pos);
    }

    return pos;
}


