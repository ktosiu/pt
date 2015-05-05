#include "pt_include.h"

/*lint -e732 -e774*/

static pt_int32_t pt_sccp_gt_code_len(sccp_gt_code gt_code)
{
    pt_uint16_t i;

    for (i = 0; i < SCCP_CODE_NUMBER; i++)
    {
        if (gt_code[i].low == 0xf)
        {
            return i;
        }

        if (gt_code[i].high == 0xf)
        {
            return (i + 1);
        }
    }
	
	return i;
}

static pt_int32_t pt_sccp_encode_gt1(sccp_gt1_t *sccp_gt1, void *buf, pt_int32_t pos)
{
    pt_int32_t gt_code_len;
    
    *((pt_uint8_t *)buf + pos++) = sccp_gt1->tag_addr;
    
    gt_code_len = pt_sccp_gt_code_len(sccp_gt1->code);
    CHECK_RESULT(gt_code_len);
    
    memcpy((pt_uint8_t *)buf + pos, sccp_gt1->code, gt_code_len);
    
    pos += gt_code_len;
    
    return pos;
}

static pt_int32_t pt_sccp_encode_gt2(sccp_gt2_t *sccp_gt2, void *buf, pt_int32_t pos)
{
    pt_int32_t gt_code_len;
    
    *((pt_uint8_t *)buf + pos++) = sccp_gt2->trans_type;
    
    gt_code_len = pt_sccp_gt_code_len(sccp_gt2->code);
    CHECK_RESULT(gt_code_len);
    
    memcpy((pt_uint8_t *)buf + pos, sccp_gt2->code, gt_code_len);
    
    pos += gt_code_len;
    
    return pos;
}

static pt_int32_t pt_sccp_encode_gt3(sccp_gt3_t *sccp_gt3, void *buf, pt_int32_t pos)
{
    pt_int32_t gt_code_len;
    
    *((pt_uint8_t *)buf + pos++) = sccp_gt3->trans_type;
    *((pt_uint8_t *)buf + pos++) = sccp_gt3->code_plan << 4 | sccp_gt3->code_design;
    
    gt_code_len = pt_sccp_gt_code_len(sccp_gt3->code);
    CHECK_RESULT(gt_code_len);
    
    memcpy((pt_uint8_t *)buf + pos, sccp_gt3->code, gt_code_len);
    
    pos += gt_code_len;
    
    return pos;
}

static pt_int32_t pt_sccp_encode_gt4(sccp_gt4_t *sccp_gt4, void *buf, pt_int32_t pos)
{
    pt_int32_t gt_code_len;

    *((pt_uint8_t *)buf + pos++) = sccp_gt4->trans_type;
    *((pt_uint8_t *)buf + pos++) = sccp_gt4->code_plan << 4 | sccp_gt4->code_design;
    *((pt_uint8_t *)buf + pos++) = sccp_gt4->tag_addr;

    gt_code_len = pt_sccp_gt_code_len(sccp_gt4->code);
    CHECK_RESULT(gt_code_len);

    memcpy((pt_uint8_t *)buf + pos, sccp_gt4->code, gt_code_len);

    pos += gt_code_len;

    return pos;
}

static pt_int32_t pt_sccp_encode_spc(pt_uint8_t pc_type, sccp_spc_t spc, void *buf, pt_int32_t pos)
{
	if (pc_type==14)
	{
		memcpy((pt_uint8_t *)buf + pos, &spc[1], 2);
		pos += 2;
	}
	else
	{
		memcpy((pt_uint8_t *)buf + pos, &spc[0], 3);
		pos += 3;
	}
    

    return pos;
}

static pt_int32_t pt_sccp_encode_address(pt_uint8_t pc_type, sccp_address_t *sccp_address, void *buf, pt_int32_t pos)
{
    *((pt_uint8_t *)buf + pos++) = *((pt_uint8_t*)sccp_address);

    if (sccp_address->tag_spc)
    {
        pos = pt_sccp_encode_spc(pc_type, sccp_address->dpc, buf, pos);
    }

    if (sccp_address->tag_ssn)
    {
        *((pt_uint8_t *)buf + pos++) = sccp_address->ssn;
    }

    switch (sccp_address->tag_gt)
    {
        case 0:
            break;

        case 1:
            pos = pt_sccp_encode_gt1(&sccp_address->gt.gt1, buf, pos);
            break;

        case 2:
            pos = pt_sccp_encode_gt2(&sccp_address->gt.gt2, buf, pos);
            break;

        case 3:
            pos = pt_sccp_encode_gt3(&sccp_address->gt.gt3, buf, pos);
            break;

        case 4:
            pos = pt_sccp_encode_gt4(&sccp_address->gt.gt4, buf, pos);
            break;

        default:
            pos = -1;
            break;
    }

    return pos;
}

pt_int32_t pt_sccp_encode_scmg(pt_uint8_t pc_type, sccp_scmg_t *scmg, void *buf, pt_int32_t pos)
{
    *((pt_uint8_t *)buf + pos++) = scmg->scmg_type;
    *((pt_uint8_t *)buf + pos++) = scmg->ssn;

    pos = pt_sccp_encode_spc(pc_type, scmg->dpc, buf, pos);

    *((pt_uint8_t *)buf + pos++) = scmg->smi;

    if (scmg->scmg_type == 0x06)
    {
        *((pt_uint8_t *)buf + pos++) = scmg->cong_level;
    }

    return pos;
}

pt_int32_t pt_sccp_encode_segment(sccp_segment_t *segment, void *buf, pt_int32_t pos)
{
    pt_uint8_t *tmp;

    *((pt_uint8_t *)buf + pos++) = 0x10;
    *((pt_uint8_t *)buf + pos++) = 4;

    tmp = (pt_uint8_t *)buf + pos++;

    *tmp = 0;
    *tmp |= segment->first_ind << 7;
    *tmp |= segment->sequence_option << 6;
    *tmp |= segment->remain_segment;

    memcpy((pt_uint8_t *)buf + pos, segment->reference, 3);

    pos += 3;

    return pos;
}

pt_int32_t pt_sccp_encode_udt(pt_uint8_t pc_type, void *msg_struct, void *out, pt_uint16_t *len)
{
    sccp_udt_t *msg = (sccp_udt_t *)msg_struct;
    pt_int32_t pos = 0, p_1, p_2, p_3, tmp;
    pt_uint8_t* p;

    *((pt_uint8_t *)out + pos++) = msg->msg_type;
    *((pt_uint8_t *)out + pos++) = msg->return_opt << 4 | msg->protocol_type;

    pos += 3;

    p_1 = 3;

    p = (pt_uint8_t *)out + pos++;
    tmp = pos;
    pos = pt_sccp_encode_address(pc_type, &msg->cda, out, pos);
    CHECK_RESULT(pos);

    *p = (pt_uint8_t)(pos - tmp);
    p_2 = (*p + 1) + 2;

    p = (pt_uint8_t *)out + pos++;
    tmp = pos;
    pos = pt_sccp_encode_address(pc_type, &msg->cga, out, pos);
    CHECK_RESULT(pos);

    *p = (pt_uint8_t)(pos - tmp);
    p_3 = (*p + 1) + (p_2 - 2) + 1;

    *((pt_uint8_t *)out + 2) = (pt_uint8_t)p_1;
    *((pt_uint8_t *)out + 3) = (pt_uint8_t)p_2;
    *((pt_uint8_t *)out + 4) = (pt_uint8_t)p_3;

    if (0 == msg->tag)
    {
        *((pt_uint8_t *)out + pos++) = msg->len_ud;
        memcpy((pt_uint8_t *)out + pos, msg->data.ud, msg->len_ud);
        pos += msg->len_ud;
    }
    else
    {
        *((pt_uint8_t *)out + pos++) = 6;
        pos = pt_sccp_encode_scmg(pc_type, &msg->data.scmg, out, pos);
    }

    *len = (pt_uint16_t)pos;

    return pos;
}

pt_int32_t pt_sccp_encode_xudt_by_pointer(pt_uint8_t pc_type, void *msg_struct, void *out, pt_uint16_t *len)
{
    sccp_xudt_t *msg = (sccp_xudt_t *)msg_struct;
    pt_int32_t pos = 0, p_1, p_2, p_3, p_4, tmp;
    pt_uint8_t* p;

    *((pt_uint8_t *)out + pos++) = msg->msg_type;
    *((pt_uint8_t *)out + pos++) = msg->return_opt << 4 | msg->protocol_type;
    *((pt_uint8_t *)out + pos++) = msg->hop_counter;
	
	/*point*/
    pos += 4;
	
	/*p_4*/
	p_4 = 1;
	tmp = pos;
	pos = pt_sccp_encode_segment(&msg->segment, out, pos);
    CHECK_RESULT(pos);
    *((pt_uint8_t *)out + pos++) = 0; /*end option parameter*/
	
	/*p_1*/
    p_1 = (pos - tmp) + 4;
    p = (pt_uint8_t *)out + pos++;
    tmp = pos;
    pos = pt_sccp_encode_address(pc_type, &msg->cda, out, pos);
    CHECK_RESULT(pos);
    *p = (pt_uint8_t)(pos - tmp);
	
	/*p_2*/
    p_2 = (*p + 1) + (p_1 - 4) + 3;
    p = (pt_uint8_t *)out + pos++;
    tmp = pos;
    pos = pt_sccp_encode_address(pc_type, &msg->cga, out, pos);
    CHECK_RESULT(pos);
    *p = (pt_uint8_t)(pos - tmp);
	
	/*p_3*/
    p_3 = (*p + 1) + (p_2 - 3) + 2;
    tmp = pos;
    if (0 == msg->tag)
    {
        *((pt_uint8_t *)out + pos++) = msg->len_ud;
        memcpy((pt_uint8_t *)out + pos, msg->data.ud, msg->len_ud);
        pos += msg->len_ud;
    }
    else
    {
        *((pt_uint8_t *)out + pos++) = 6;
        pos = pt_sccp_encode_scmg(pc_type, &msg->data.scmg, out, pos);
    }
	
	/*update point*/
    *((pt_uint8_t *)out + 3) = (pt_uint8_t)p_1;
    *((pt_uint8_t *)out + 4) = (pt_uint8_t)p_2;
    *((pt_uint8_t *)out + 5) = (pt_uint8_t)p_3;
    *((pt_uint8_t *)out + 6) = (pt_uint8_t)p_4;

    *len = (pt_uint16_t)pos;

    return pos;
}


pt_int32_t pt_sccp_encode_xudt_by_normal(pt_uint8_t pc_type, void *msg_struct, void *out, pt_uint16_t *len)
{
    sccp_xudt_t *msg = (sccp_xudt_t *)msg_struct;
    pt_int32_t pos = 0, p_1, p_2, p_3, p_4, tmp;
    pt_uint8_t* p;
    
    *((pt_uint8_t *)out + pos++) = msg->msg_type;
    *((pt_uint8_t *)out + pos++) = msg->return_opt << 4 | msg->protocol_type;
    *((pt_uint8_t *)out + pos++) = msg->hop_counter;
    
    pos += 4;
    
    p_1 = 4;
    
    p = (pt_uint8_t *)out + pos++;
    tmp = pos;
    pos = pt_sccp_encode_address(pc_type, &msg->cda, out, pos);
    CHECK_RESULT(pos);
    
    *p = (pt_uint8_t)(pos - tmp);
    p_2 = (*p + 1) + 3;
    
    p = (pt_uint8_t *)out + pos++;
    tmp = pos;
    pos = pt_sccp_encode_address(pc_type, &msg->cga, out, pos);
    CHECK_RESULT(pos);
    
    *p = (pt_uint8_t)(pos - tmp);
    p_3 = (*p + 1) + (p_2 - 3) + 2;
    
    tmp = pos;
    
    if (0 == msg->tag)
    {
        *((pt_uint8_t *)out + pos++) = msg->len_ud;
        memcpy((pt_uint8_t *)out + pos, msg->data.ud, msg->len_ud);
        pos += msg->len_ud;
    }
    else
    {
        *((pt_uint8_t *)out + pos++) = 6;
        pos = pt_sccp_encode_scmg(pc_type, &msg->data.scmg, out, pos);
    }
    
    p_4 = (pos - tmp) + (p_3 - 2) + 1;
    
    *((pt_uint8_t *)out + 3) = (pt_uint8_t)p_1;
    *((pt_uint8_t *)out + 4) = (pt_uint8_t)p_2;
    *((pt_uint8_t *)out + 5) = (pt_uint8_t)p_3;
    *((pt_uint8_t *)out + 6) = (pt_uint8_t)p_4;
    
    pos = pt_sccp_encode_segment(&msg->segment, out, pos);
    CHECK_RESULT(pos);
    
    *((pt_uint8_t *)out + pos++) = 0; /*end option parameter*/
    
    *len = (pt_uint16_t)pos;
    
    return pos;
}

pt_int32_t pt_sccp_encode_xudt(pt_uint8_t pc_type, void *msg_struct, void *out, pt_uint16_t *len)
{
    if(1)
        return pt_sccp_encode_xudt_by_normal(pc_type, msg_struct, out, len);
    else if(0)
        return pt_sccp_encode_xudt_by_pointer(pc_type, msg_struct, out, len);
    else
        return -1;
}

static pt_int32_t pt_sccp_decode_gt1(void *buf, pt_int32_t len, pt_int32_t pos, sccp_gt1_t *sccp_gt1)
{
    sccp_gt1->tag_addr    = *((pt_uint8_t *)buf + pos++);
    
    memset(sccp_gt1->code, 0xff, sizeof(sccp_gt1->code));
    
    memcpy(sccp_gt1->code, (pt_uint8_t *)buf + pos, len - 1);
    
    pos += len - 1;
    
    return pos;
}

static pt_int32_t pt_sccp_decode_gt2(void *buf, pt_int32_t len, pt_int32_t pos, sccp_gt2_t *sccp_gt2)
{
    sccp_gt2->trans_type  = *((pt_uint8_t *)buf + pos++);
    
    memset(sccp_gt2->code, 0xff, sizeof(sccp_gt2->code));
    
    memcpy(sccp_gt2->code, (pt_uint8_t *)buf + pos, len - 1);
    
    pos += len - 1;
    
    return pos;
}

static pt_int32_t pt_sccp_decode_gt3(void *buf, pt_int32_t len, pt_int32_t pos, sccp_gt3_t *sccp_gt3)
{
    sccp_gt3->trans_type  = *((pt_uint8_t *)buf + pos++);
    sccp_gt3->code_plan   = *((pt_uint8_t *)buf + pos) >> 4;
    sccp_gt3->code_design = *((pt_uint8_t *)buf + pos++) & 0xf;
    
    memset(sccp_gt3->code, 0xff, sizeof(sccp_gt3->code));
    
    memcpy(sccp_gt3->code, (pt_uint8_t *)buf + pos, len - 2);
    
    pos += len - 2;
    
    return pos;
}

static pt_int32_t pt_sccp_decode_gt4(void *buf, pt_int32_t len, pt_int32_t pos, sccp_gt4_t *sccp_gt4)
{
    sccp_gt4->trans_type  = *((pt_uint8_t *)buf + pos++);
    sccp_gt4->code_plan   = *((pt_uint8_t *)buf + pos) >> 4;
    sccp_gt4->code_design = *((pt_uint8_t *)buf + pos++) & 0xf;
    sccp_gt4->tag_addr    = *((pt_uint8_t *)buf + pos++);

    memset(sccp_gt4->code, 0xff, sizeof(sccp_gt4->code));

    memcpy(sccp_gt4->code, (pt_uint8_t *)buf + pos, len - 3);

    pos += len - 3;

    return pos;
}

static pt_int32_t pt_sccp_decode_spc(pt_uint8_t pc_type, void *buf, pt_int32_t pos, sccp_spc_t spc)
{
	if (pc_type==14)
	{
		memcpy(&spc[1], (pt_uint8_t *)buf + pos, 2);
		pos += 2;
	}
	else
	{
		memcpy(&spc[0], (pt_uint8_t *)buf + pos, 3);
		pos += 3;
	}

    return pos;
}

static pt_int32_t pt_sccp_decode_address(pt_uint8_t pc_type, void *buf, pt_int32_t len, pt_int32_t pos, sccp_address_t *sccp_address)
{
    pt_int32_t tmp = pos;

    *((pt_uint8_t*)sccp_address) = *((pt_uint8_t *)buf + pos++);

    if (sccp_address->tag_spc)
    {
        pos = pt_sccp_decode_spc(pc_type, buf, pos, sccp_address->dpc);
    }
    else
    {
        memset(sccp_address->dpc, 0, sizeof(sccp_address->dpc));
    }

    if (sccp_address->tag_ssn)
    {
        sccp_address->ssn = *((pt_uint8_t *)buf + pos++);
    }

    tmp = len - (pos - tmp);
    CHECK_RESULT(tmp);
    switch (sccp_address->tag_gt)
    {
        case 0:
            break;

        case 1:
            pos = pt_sccp_decode_gt1(buf, tmp, pos, &sccp_address->gt.gt1);
            break;

        case 2:
            pos = pt_sccp_decode_gt2(buf, tmp, pos, &sccp_address->gt.gt2);
            break;

        case 3:
            pos = pt_sccp_decode_gt3(buf, tmp, pos, &sccp_address->gt.gt3);
            break;

        case 4:
            pos = pt_sccp_decode_gt4(buf, tmp, pos, &sccp_address->gt.gt4);
            break;

        default:
            pos = -1;
            break;
    }

    return pos;
}

pt_int32_t pt_sccp_decode_scmg(pt_uint8_t pc_type, void *buf, pt_int32_t pos, sccp_scmg_t *scmg)
{
    scmg->scmg_type = *((pt_uint8_t *)buf + pos++);
    scmg->ssn = *((pt_uint8_t *)buf + pos++);

    pos = pt_sccp_decode_spc(pc_type, buf, pos, scmg->dpc);

    scmg->smi = *((pt_uint8_t *)buf + pos++) & 0x3;

    if (scmg->scmg_type == 0x06)
    {
        scmg->cong_level = *((pt_uint8_t *)buf + pos++) & 0xf;
    }

    return pos;
}

pt_int32_t pt_sccp_decode_segment(void *buf, pt_int32_t pos, sccp_segment_t *segment)
{
    pt_uint8_t tmp; ;

    pos += 2;/*id+len*/

    tmp = *((pt_uint8_t *)buf + pos++);

    segment->first_ind = (tmp & 0x80) >> 7;
    segment->sequence_option = (tmp & 0x40) >> 6;
    segment->remain_segment = tmp & 0x0f;

    memcpy(segment->reference, (pt_uint8_t *)buf + pos, 3);

    pos += 3;

    return pos;
}

pt_int32_t pt_sccp_decode_udt(pt_uint8_t pc_type, void *in, pt_uint16_t len, void *msg_struct)
{
    sccp_udt_t *msg = (sccp_udt_t *)msg_struct;
    pt_int32_t pos = 0, tmp;

    msg->msg_type = *((pt_uint8_t *)in + pos++);
    msg->return_opt = *((pt_uint8_t *)in + pos) >> 4;
    msg->protocol_type = *((pt_uint8_t *)in + pos++) & 0xf;
    
    /*p_1, p_2, p_3*/
    pos += 3;

    tmp = *((pt_uint8_t *)in + pos++);
    pos = pt_sccp_decode_address(pc_type, in, tmp, pos, &msg->cda);
    CHECK_RESULT(pos);

    tmp = *((pt_uint8_t *)in + pos++);
    pos = pt_sccp_decode_address(pc_type, in, tmp, pos, &msg->cga);
    CHECK_RESULT(pos);

    if (1 == msg->cda.ssn)
    {
        msg->tag = 1;
    }
    else
    {
        msg->tag = 0;
    }

    if (0 == msg->tag)
    {
        msg->len_ud = *((pt_uint8_t *)in + pos++);
        memcpy(msg->data.ud, (pt_uint8_t *)in + pos, msg->len_ud);
        pos += msg->len_ud;
    }
    else
    {
        tmp = *((pt_uint8_t *)in + pos++);
        pos = pt_sccp_decode_scmg(pc_type, in, pos, &msg->data.scmg);
        CHECK_RESULT(pos);
    }

    return pos;
}

pt_int32_t pt_sccp_decode_xudt(pt_uint8_t pc_type, void *in, pt_uint16_t len, void *msg_struct)
{
    sccp_xudt_t *msg = (sccp_xudt_t *)msg_struct;
    pt_int32_t pos = 0, tmp;

    msg->msg_type = *((pt_uint8_t *)in + pos++);
    msg->return_opt = *((pt_uint8_t *)in + pos) >> 4;
    msg->protocol_type = *((pt_uint8_t *)in + pos++) & 0xf;
    msg->hop_counter = *((pt_uint8_t *)in + pos++);

    /*p_1, p_2, p_3*/
    pos += 3;

    if (*(pt_uint8_t*)in > 3)
    {
        /*p_4*/
        pos++;
    }

    tmp = *((pt_uint8_t *)in + pos++);
    pos = pt_sccp_decode_address(pc_type, in, tmp, pos, &msg->cda);
    CHECK_RESULT(pos);

    tmp = *((pt_uint8_t *)in + pos++);
    pos = pt_sccp_decode_address(pc_type, in, tmp, pos, &msg->cga);
    CHECK_RESULT(pos);

    if (1 == msg->cda.ssn)
    {
        msg->tag = 1;
    }
    else
    {
        msg->tag = 0;
    }

    if (0 == msg->tag)
    {
        msg->len_ud = *((pt_uint8_t *)in + pos++);
        memcpy(msg->data.ud, (pt_uint8_t *)in + pos, msg->len_ud);
        pos += msg->len_ud;
    }
    else
    {
        tmp = *((pt_uint8_t *)in + pos++);
        pos = pt_sccp_decode_scmg(pc_type, in, pos, &msg->data.scmg);
        CHECK_RESULT(pos);
    }

    if (*(pt_uint8_t*)in > 3)
    {
        if (*((pt_uint8_t *)in + pos) == 0x10) /*Segmentation parameter name*/
        {
            pos = pt_sccp_decode_segment(in, pos, &msg->segment);
            CHECK_RESULT(pos);
            msg->tag_segment = 1;
        }
    }

    return pos;
}

pt_int32_t pt_sccp_encode(m3ua_asp_t *m3ua_asp, void *msg_struct, void *out, pt_uint16_t *len)
{
	pt_uint8_t msg_type = *((pt_uint8_t *)msg_struct);
    pt_int32_t res = -1;
	pt_uint8_t pc_type;
	
    pc_type = m3ua_asp->m3ua_as->ss7office->spc_type;

    if (msg_type == SCCP_MSG_UDT)
    {
        res = pt_sccp_encode_udt(pc_type, msg_struct, out, len);
    }
    else if (msg_type == SCCP_MSG_XUDT)
    {
        res = pt_sccp_encode_xudt(pc_type, msg_struct, out, len);
    }

    return res;
}

pt_int32_t pt_sccp_decode(m3ua_asp_t *m3ua_asp, void *in, pt_uint16_t len, void *msg_struct)
{
    pt_uint8_t msg_type = *((pt_uint8_t *)in);
    pt_int32_t res = -1;
	pt_uint8_t pc_type;

    pc_type = m3ua_asp->m3ua_as->ss7office->spc_type;

    if (msg_type == SCCP_MSG_UDT)
    {
        res = pt_sccp_decode_udt(pc_type, in, len, msg_struct);
    }
    else if (msg_type == SCCP_MSG_XUDT)
    {
        res = pt_sccp_decode_xudt(pc_type, in, len, msg_struct);
    }

    return res;
}
