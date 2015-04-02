#include "pt_include.h"

/*lint -save -e715 -e701*/

void pt_diam_prn_avps(list_head_t *avps)
{
    diam_buf_t  *buf;
    list_head_t *pos;

    list_for_each(pos, avps)
    {
        buf = list_entry(pos, diam_buf_t, list);
        PT_LOG(PTLOG_DEBUG,"avp:");
        PT_LOG(PTLOG_DEBUG,"avp-code: %d", buf->avp.avp_head.avp_code);
        PT_LOG(PTLOG_DEBUG,"avp-flg: %#x", buf->avp.avp_head.avp_flg);
        PT_LOG(PTLOG_DEBUG,"avp-len: %d", buf->avp.avp_head.avp_len);

        if (buf->avp.avp_head.avp_flg & AVP_FLAG_V)
        {
            PT_LOG(PTLOG_DEBUG,"vendor-id: %d", buf->avp.avp_head.vendor_id);
        }

        switch (buf->avp.data.format)
        {
            case AVP_FORMAT_UTF8STRING:
                PT_LOG(PTLOG_DEBUG,"avp-data: %s", buf->avp.data.value.octet_string);
                break;

            case AVP_FORMAT_UNINTEGER32:
                PT_LOG(PTLOG_DEBUG,"avp-data: %#x", buf->avp.data.value.unsigned32);
                break;

            case AVP_FORMAT_GROUPS:
                pt_diam_prn_avps(&buf->avp.data.value.groups);
                break;

            case AVP_FORMAT_ADDRESS:
                /* PT_LOG(PTLOG_DEBUG,"avp-data: %s", OSS_INET_NTOA(buf->avp.data.value.address.ip.ipv4)); */
                break;

            default:
                PT_LOG(PTLOG_DEBUG,"avp-data: unknown data format");
                break;
        }
    }
}

void pt_diam_prn_msg(diam_msg_t *msg)
{
#ifdef _DEBUG
    PT_LOG(PTLOG_DEBUG,"Diameter Protocol");
    PT_LOG(PTLOG_DEBUG,"Version: %#x", msg->diam_head.version);
    PT_LOG(PTLOG_DEBUG,"Length: %d", msg->diam_head.msg_len);
    PT_LOG(PTLOG_DEBUG,"Flags: %#x", msg->diam_head.cmd_flg);
    PT_LOG(PTLOG_DEBUG,"Command Code:%d", msg->diam_head.cmd_code);
    PT_LOG(PTLOG_DEBUG,"Application Id:%d", msg->diam_head.app_id);
    PT_LOG(PTLOG_DEBUG,"Hop-by-Hop Identifier:%d", msg->diam_head.h_by_h_id);
    PT_LOG(PTLOG_DEBUG,"End-to-End Identifier:%d", msg->diam_head.e_to_e_id);

    pt_diam_prn_avps(&msg->avps);
#endif
}

diam_buf_t *pt_diam_alloc_avpbuf(pt_size_t size)
{
    return pt_malloc(size);
}

void pt_diam_free_avpbuf(diam_buf_t *buf)
{
    pt_free(buf);
}

pt_int32_t pt_diam_add_avp(list_head_t *avps, avp_t *avp)
{
    diam_buf_t *buf = pt_diam_alloc_avpbuf(sizeof(diam_buf_t));

    if (NULL == buf)
    {
        return -1;
    }

    buf->avp = *avp;

    if (NULL == avps)
    {
        return -1;
    }
    else
    {
        list_add_tail(&buf->list, avps);
    }

    return 0;
}

pt_int32_t pt_diam_init_avp_groups(list_head_t *avps, list_head_t **groups)
{
    diam_buf_t  *buf = list_entry(avps->prev, diam_buf_t, list);

    *groups = &buf->avp.data.value.groups;

    INIT_LIST_HEAD(*groups);

    return 0;
}

pt_int32_t pt_diam_add_avp_ex(list_head_t *avps, avp_t *avp, list_head_t **groups)
{
    diam_buf_t *buf = buf = pt_diam_alloc_avpbuf(sizeof(diam_buf_t));

    if (NULL == buf)
    {
        return -1;
    }

    buf->avp = *avp;

    if (NULL == avps)
    {
        return -1;
    }
    else
    {
        list_add_tail(&buf->list, avps);
    }

    return pt_diam_init_avp_groups(avps, groups);
}

void pt_diam_set_avp_uint32(pt_uint32_t avp_code, pt_uint8_t avp_flg, pt_uint32_t uint32, avp_t *avp)
{
    avp->avp_head.avp_code = avp_code;
    avp->avp_head.avp_flg = avp_flg;
    avp->data.format = AVP_FORMAT_UNINTEGER32;
    avp->data.value.unsigned32 = uint32;
}

pt_int32_t pt_diam_add_avp_uint32(list_head_t *avps, pt_uint32_t avp_code, pt_uint8_t avp_flg, pt_uint32_t uint32)
{
    avp_t avp = {{0},};

    pt_diam_set_avp_uint32(avp_code, avp_flg, uint32, &avp);

    return pt_diam_add_avp(avps, &avp);
}

void pt_diam_set_avp_str(pt_uint32_t avp_code, pt_uint8_t avp_flg, pt_char_t *str, avp_t *avp)
{
    avp->avp_head.avp_code = avp_code;
    avp->avp_head.avp_flg = avp_flg;
    avp->data.format = AVP_FORMAT_UTF8STRING;
    strcpy(avp->data.value.octet_string, str);
}

pt_int32_t pt_diam_add_avp_str(list_head_t *avps, pt_uint32_t avp_code, pt_uint8_t avp_flg, pt_char_t *str)
{
    avp_t avp = {{0},};

    pt_diam_set_avp_str(avp_code, avp_flg, str, &avp);

    return pt_diam_add_avp(avps, &avp);
}

void pt_diam_set_avp_groups(pt_uint32_t avp_code, pt_uint8_t avp_flg, avp_t *avp)
{
    avp->avp_head.avp_code = avp_code;
    avp->avp_head.avp_flg = avp_flg;
    avp->data.format = AVP_FORMAT_GROUPS;
}

pt_int32_t pt_diam_add_avp_groups(list_head_t *avps, pt_uint32_t avp_code, pt_uint8_t avp_flg, list_head_t **groups)
{
    avp_t avp = {{0},};

    pt_diam_set_avp_groups(avp_code, avp_flg, &avp);

    if (-1 == pt_diam_add_avp(avps, &avp))
    {
        return -1;
    }

    return pt_diam_init_avp_groups(avps, groups);
}

void pt_diam_set_avp_addr(pt_uint32_t avp_code, pt_uint8_t avp_flg, pt_char_t *ip, avp_t *avp)
{
    avp->avp_head.avp_code = avp_code;
    avp->avp_head.avp_flg = avp_flg;
    avp->data.format = AVP_FORMAT_ADDRESS;
    avp->data.value.address.family = 0x0001;
    pt_inet_pton(PT_AF_INET, ip, &avp->data.value.address.ip.ipv4);
}

pt_int32_t pt_diam_add_avp_addr(list_head_t *avps, pt_uint32_t avp_code, pt_uint8_t avp_flg, pt_char_t *ip)
{
    avp_t avp = {{0},};

    pt_diam_set_avp_addr(avp_code, avp_flg, ip, &avp);

    return pt_diam_add_avp(avps, &avp);
}

pt_int32_t pt_diam_del_avps(list_head_t *avps)
{
    diam_buf_t  *buf;

	while(!list_empty(avps))
    {
        buf = list_entry(avps->next, diam_buf_t, list);
        if (AVP_FORMAT_GROUPS == buf->avp.data.format)
        {
            return pt_diam_del_avps(&buf->avp.data.value.groups);
        }
		list_del(&buf->list);
        
        pt_diam_free_avpbuf(buf);
    }

    return 0;
}

pt_uint8_t *pt_diam_get_cmd_data(pt_uint8_t *code, pt_int32_t len)
{
    return &code[DIM_HDR_LEN];
}

pt_int32_t pt_diam_get_cmd_len(pt_uint8_t *code, pt_int32_t len)
{
    return code[1] << 16 | code[2] << 8 | code[3];
}

pt_int32_t pt_diam_get_cmd_data_len(pt_uint8_t *code, pt_int32_t len)
{
    return pt_diam_get_cmd_len(code, len) - DIM_HDR_LEN;
}

pt_uint32_t pt_diam_get_cmd_code(pt_uint8_t *code, pt_int32_t len)
{
    return code[5] << 16 | code[6] << 8 | code[7];
}

pt_uint8_t pt_diam_get_cmd_ver(pt_uint8_t *code, pt_int32_t len)
{
    return code[0];
}

pt_uint8_t pt_diam_get_cmd_flg(pt_uint8_t *code, pt_int32_t len)
{
    return code[4];
}

pt_bool_t pt_diam_get_cmd_flg_R(pt_uint8_t *code, pt_int32_t len)
{
    return code[4] & DIAM_CMD_FLG_R;
}

pt_bool_t pt_diam_get_cmd_flg_P(pt_uint8_t *code, pt_int32_t len)
{
    return code[4] & DIAM_CMD_FLG_P;
}

pt_bool_t pt_diam_get_cmd_flg_E(pt_uint8_t *code, pt_int32_t len)
{
    return code[4] & DIAM_CMD_FLG_E;
}

pt_bool_t pt_diam_get_cmd_flg_T(pt_uint8_t *code, pt_int32_t len)
{
    return code[4] & DIAM_CMD_FLG_T;
}

pt_uint32_t pt_diam_get_cmd_appid(pt_uint8_t *code, pt_int32_t len)
{
    return code[8] << 24 | code[9] << 16 | code[10] << 8 | code[11];
}

pt_uint32_t pt_diam_get_cmd_hopbyhop(pt_uint8_t *code, pt_int32_t len)
{
    return code[12] << 24 | code[13] << 16 | code[14] << 8 | code[15];
}

pt_uint32_t pt_diam_get_cmd_endtoend(pt_uint8_t *code, pt_int32_t len)
{
    return code[16] << 24 | code[17] << 16 | code[18] << 8 | code[19];
}

void pt_diam_set_cmd_hopbyhop(pt_uint8_t *code, pt_int32_t len, pt_uint32_t hopbyhop)
{
    *((pt_uint32_t *)&code[12]) = pt_htonl(hopbyhop);
}

void pt_diam_set_cmd_endtoend(pt_uint8_t *code, pt_int32_t len, pt_uint32_t endtoend)
{
    *((pt_uint32_t *)&code[16]) = pt_htonl(endtoend);
}

pt_uint32_t pt_diam_get_avp_code(pt_uint8_t *code, pt_int32_t pos)
{
    return (pt_uint32_t)pt_ntohl(*(pt_uint32_t *)(code + pos));
}

pt_uint32_t pt_diam_get_avp_flg(pt_uint8_t *code, pt_int32_t pos)
{
    return (code + pos)[4];
}

pt_uint32_t pt_diam_get_avp_flg_V(pt_uint8_t *code, pt_int32_t pos)
{
    return (code + pos)[4] & AVP_FLAG_V;
}

pt_uint32_t pt_diam_get_avp_flg_M(pt_uint8_t *code, pt_int32_t pos)
{
    return (code + pos)[4] & AVP_FLAG_M;
}

pt_uint32_t pt_diam_get_avp_flg_P(pt_uint8_t *code, pt_int32_t pos)
{
    return (code + pos)[4] & AVP_FLAG_P;
}

pt_int32_t pt_diam_get_avp_len(pt_uint8_t *code, pt_int32_t pos)
{
    return (code + pos)[5] << 16 | (code + pos)[6] << 8 | (code + pos)[7];
}

pt_uint8_t *pt_diam_get_avp_data(pt_uint8_t *code, pt_int32_t pos)
{
    pt_uint8_t *avp_data;

    avp_data = &code[pos];
    if (pt_diam_get_avp_flg_V(code, pos))
        avp_data += 12;
    else
        avp_data += 8;
    
    return avp_data;
}

pt_int32_t pt_diam_get_avp_data_len(pt_uint8_t *code, pt_int32_t pos)
{
    pt_int32_t avp_len;

    avp_len = pt_diam_get_avp_len(code, pos);

    avp_len -= 8;
    if (pt_diam_get_avp_flg_V(code, pos))
    {
        avp_len -= 4;
    }

    return avp_len;
}

/*获取一层AVP位置*/
pt_int32_t pt_diam_get_avp_pos_from_cmd_data(pt_uint8_t *cmd_data, pt_int32_t cmd_data_len, 
                pt_uint32_t avp_code, pt_uint32_t avp_position)
{
    pt_uint32_t i;
    pt_int32_t pos;

    for (pos = 0, i = 0; pos < cmd_data_len; ) {
        if (pt_diam_get_avp_code(cmd_data, pos) == avp_code && ++i >= avp_position) 
            return pos;

        pos += pt_diam_get_avp_len(cmd_data, pos);
        pos = (pos + 3) & (~3);
    }

    return -1;
}

/*获取多层AVP位置*/
pt_int32_t pt_diam_get_avp_pos(pt_uint8_t *code, pt_int32_t len, avp_condition_t *avp_condition)
{
    pt_int32_t pos;
    pt_int32_t avp_pos;
    pt_uint32_t i;
    pt_int32_t cmd_data_len;
    pt_uint8_t *cmd_data;

    cmd_data_len = pt_diam_get_cmd_data_len(code, len);
    cmd_data = pt_diam_get_cmd_data(code, len);

    pos = DIM_HDR_LEN;
    for (i = 0; i < avp_condition->avp_level_num; i++) {
        avp_pos = pt_diam_get_avp_pos_from_cmd_data(cmd_data, cmd_data_len, 
                        avp_condition->avp_code[i], avp_condition->avp_position[i]);
        if (avp_pos < 0) {
            return -1;
        }
        pos += avp_pos;
        avp_condition->avp_pos[i] = pos;
        
        cmd_data_len = pt_diam_get_avp_len(code, pos);
        cmd_data = pt_diam_get_avp_data(code, pos);
        
        if (pt_diam_get_avp_flg_V(code, pos))
            pos += 12;
        else
            pos += 8;
    }
    
    return avp_condition->avp_pos[i - 1];   
}

pt_int32_t pt_diam_del_avp(pt_uint8_t *code, pt_int32_t *len, avp_condition_t *avp_condition)
{
    pt_int32_t tmp;
    pt_int32_t pos;
    pt_uint32_t avp_level;
    pt_int32_t avp_offset;
    
    if (pt_diam_get_avp_pos(code, *len, avp_condition) < 0) 
        return -1;

    avp_level = avp_condition->avp_level_num;
    avp_level--;
    pos = avp_condition->avp_pos[avp_level];

    avp_offset = (pt_diam_get_avp_len(code, pos) + 3) & (~3);
    memmove(&code[pos], &code[pos + avp_offset], /*lint !e679*/
        (pt_uint32_t)(*len - (pos + avp_offset)));

    /*update parent avp len*/
    while (avp_level > 0) {
        avp_level--;
        pos = avp_condition->avp_pos[avp_level];

        tmp = pt_diam_get_avp_len(code, pos) - avp_offset;
        
        pt_diam_encode_octs((pt_uint8_t *)&tmp, 3, code, pos + 5);
    }

    /*update msg len*/
    *len -= avp_offset;
    tmp = (pt_int32_t)*len;
    pt_diam_encode_octs((pt_uint8_t *)&tmp, 3, code, 1);

    return 0;
}

pt_int32_t pt_diam_set_avp_data(pt_uint8_t *code, pt_int32_t *len, avp_condition_t *avp_condition, 
                            void *avp_data, pt_int32_t avp_data_len)

{
    pt_int32_t tmp;
    pt_int32_t pos;
    pt_uint32_t avp_level;
    pt_uint8_t *old_avp_data;
    pt_int32_t old_avp_offset;
    pt_int32_t new_avp_offset;
    
    if (pt_diam_get_avp_pos(code, *len, avp_condition) < 0) 
        return -1;

    /*alignment avp data*/
    avp_level = avp_condition->avp_level_num;
    avp_level--;
    pos = avp_condition->avp_pos[avp_level];

    old_avp_offset = (pt_diam_get_avp_len(code, pos) + 3) & (~3);

    new_avp_offset = (pt_int32_t)(8 + avp_data_len + 3) & (~3);
    if (pt_diam_get_avp_flg_V(code, pos)) 
         new_avp_offset += 4;

    if (old_avp_offset != new_avp_offset) {
        memmove(&code[pos + new_avp_offset], &code[pos + old_avp_offset],/*lint !e679*/
            (pt_uint32_t)(*len - (pos + old_avp_offset)));
    }

    /*update avp data*/
    old_avp_data = pt_diam_get_avp_data(code, pos);
    memmove(old_avp_data, avp_data, (pt_uint32_t)avp_data_len);
    if (avp_data_len & 0x3)
        memset(&old_avp_data[avp_data_len], 0, 4 - (avp_data_len & 0x3));

    /*update avp len*/
    tmp = (pt_int32_t)avp_data_len + 8;
    if (pt_diam_get_avp_flg_V(code, pos)) 
         tmp += 4;
    pt_diam_encode_octs((pt_uint8_t *)&tmp, 3, code, pos + 5);

    if (old_avp_offset == new_avp_offset)
        return 0;

    /*update parent avp len*/
    while (avp_level > 0) {
        avp_level--;
        pos = avp_condition->avp_pos[avp_level];

        tmp = pt_diam_get_avp_len(code, pos) + (new_avp_offset - old_avp_offset);
        
        pt_diam_encode_octs((pt_uint8_t *)&tmp, 3, code, pos + 5);
    }

    /*update msg len*/
    *len += (new_avp_offset - old_avp_offset);
    tmp = (pt_int32_t)*len;
    pt_diam_encode_octs((pt_uint8_t *)&tmp, 3, code, 1);
    
    return 0;
}

