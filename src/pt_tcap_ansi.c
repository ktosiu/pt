#include "pt_include.h"

/*lint -e732 -e734*/

static pt_int32_t pt_ctcap_encode_invoke_comp(ctcap_comp_t *comp, void *buf, pt_int32_t pos)
{
    pt_int32_t tmp = pos;
    pt_uint8_t    opcode[2];

    /*parameter*/
    pos = pt_asn1_encode_v(comp->para_len, comp->para, buf, pos);
    CHECK_RESULT(pos);

    /*op code*/
    opcode[0] = 0x09;
    opcode[1] = comp->i_op_code;
    
    pos = pt_asn1_encode_tlv(0xd1, 2, opcode, buf, pos);
    CHECK_RESULT(pos);

    /*comp id*/
    pos = pt_asn1_encode_tlv(0xcf, 1, &comp->comp_id, buf, pos);
    CHECK_RESULT(pos);

    /*invoke component len&tag*/
    pos = pt_asn1_encode_tl(0xe9, (pt_uint16_t)(tmp - pos), buf, pos);
    CHECK_RESULT(pos);

    return pos;
}

static pt_int32_t pt_ctcap_encode_result_comp(ctcap_comp_t *comp, void *buf, pt_int32_t pos)
{
    pt_int32_t tmp = pos;
    
    /*parameter*/
    pos = pt_asn1_encode_v(comp->para_len, comp->para, buf, pos);
    CHECK_RESULT(pos);

    /*comp id*/
    pos = pt_asn1_encode_tlv(0xcf, 1, &comp->comp_id, buf, pos);
    CHECK_RESULT(pos);

    /*result component len&tag*/
    pos = pt_asn1_encode_tl(0xea, (pt_uint16_t)(tmp - pos), buf, pos);
    CHECK_RESULT(pos);
    
    return pos;
}

static pt_int32_t pt_ctcap_encode_error_comp(ctcap_comp_t *comp, void *buf, pt_int32_t pos)
{
    pt_int32_t tmp = pos;
    
    /*parameter*/
    pos = pt_asn1_encode_v(comp->para_len, comp->para, buf, pos);
    CHECK_RESULT(pos);

    /*error code*/
    pos = pt_asn1_encode_tlv(0xd4, 1, &comp->e_error_code, buf, pos);
    CHECK_RESULT(pos);

    /*comp id*/
    pos = pt_asn1_encode_tlv(0xcf, 1, &comp->comp_id, buf, pos);
    CHECK_RESULT(pos);

    /*error component len&tag*/
    pos = pt_asn1_encode_tl(0xeb, (pt_uint16_t)(tmp - pos), buf, pos);
    CHECK_RESULT(pos);

    return pos;
}

static pt_int32_t pt_ctcap_encode_comp(ctcap_comp_t *comp, void *buf, pt_int32_t pos)
{
    pt_int32_t tmp = pos;
    
    if (comp->comp_type == CCOMP_TYPE_INVOKE)
    {
        pos = pt_ctcap_encode_invoke_comp(comp, buf, pos);
    }
    else if (comp->comp_type == CCOMP_TYPE_RESULT)
    {
        pos = pt_ctcap_encode_result_comp(comp, buf, pos);
    }
    else if (comp->comp_type == CCOMP_TYPE_ERROR)
    {
        pos = pt_ctcap_encode_error_comp(comp, buf, pos);
    }
    else 
    {
        pos = -1;
    }

    /*component len&tag*/
    pos = pt_asn1_encode_tl(0xe8, (pt_uint16_t)(tmp - pos), buf, pos);
    CHECK_RESULT(pos);

    return pos;
}

static pt_int32_t pt_ctcap_encode_tran_id(ctcap_tran_id_t *orig_id, ctcap_tran_id_t *dest_id, void *buf, pt_int32_t pos)
{
    pt_int32_t l = 0;

    if (dest_id!=NULL)
    {
        pos = pt_asn1_encode_v(sizeof(ctcap_tran_id_t), dest_id, buf, pos);
        CHECK_RESULT(pos);

        l += (pt_int32_t)sizeof(ctcap_tran_id_t);
    }
    
    if (orig_id!=NULL)
    {
        pos = pt_asn1_encode_v(sizeof(ctcap_tran_id_t), orig_id, buf, pos);
        CHECK_RESULT(pos);

        l += (pt_int32_t)sizeof(ctcap_tran_id_t);
    }
    
    pos = pt_asn1_encode_tl(0xc7, l, buf, pos);
    CHECK_RESULT(pos);

    return pos;
}

static pt_int32_t pt_ctcap_encode_unidir(void *msg_struct, void *out, pt_int32_t *len)
{
    ctcap_unidir_t *msg = (ctcap_unidir_t *)msg_struct;
    pt_int32_t pos = *len;

    /*component*/
    pos = pt_ctcap_encode_comp(&msg->comp, out, pos);
    CHECK_RESULT(pos);
    
    /*tran orig id*/
    pos = pt_ctcap_encode_tran_id(NULL, NULL, out, pos);
    CHECK_RESULT(pos);

    /*unidir msg type len&tag*/
    pos = pt_asn1_encode_tl(0xe1, (pt_uint16_t)(*len - pos), out, pos);
    CHECK_RESULT(pos);
    
    *len = *len - (pt_uint16_t)pos;

    return pos;
}

static pt_int32_t pt_ctcap_encode_query(void *msg_struct, void *out, pt_int32_t *len)
{
    ctcap_query_t *msg = (ctcap_query_t *)msg_struct;
    pt_int32_t pos = *len;

    /*component*/
    pos = pt_ctcap_encode_comp(&msg->comp, out, pos);
    CHECK_RESULT(pos);

    /*tran orig id*/
    pos = pt_ctcap_encode_tran_id(&msg->orig_id, NULL, out, pos);
    CHECK_RESULT(pos);

    /*query msg type len&tag*/
    pos = pt_asn1_encode_tl(0xe2, (pt_uint16_t)(*len - pos), out, pos);
    CHECK_RESULT(pos);
    
    *len = *len - (pt_uint16_t)pos;

    return pos;
}

static pt_int32_t pt_ctcap_encode_response(void *msg_struct, void *out, pt_int32_t *len)
{
    ctcap_response_t *msg = (ctcap_response_t *)msg_struct;
    pt_int32_t pos = *len;

    /*component*/
    pos = pt_ctcap_encode_comp(&msg->comp, out, pos);
    CHECK_RESULT(pos);

    /*tran dest id*/
    pos = pt_ctcap_encode_tran_id(NULL, &msg->dest_id, out, pos);
    CHECK_RESULT(pos);

    /*response msg type len&tag*/
    pos = pt_asn1_encode_tl(0xe4, (pt_uint16_t)(*len - pos), out, pos);
    CHECK_RESULT(pos);
    
    *len = *len - (pt_uint16_t)pos;

    return pos;
}

static pt_int32_t pt_ctcap_encode_cont(void *msg_struct, void *out, pt_int32_t *len)
{
    ctcap_cont_t *msg = (ctcap_cont_t *)msg_struct;
    pt_int32_t pos = *len;

    /*component*/
    pos = pt_ctcap_encode_comp(&msg->comp, out, pos);
    CHECK_RESULT(pos);

    /*tran orig dest id*/
    pos = pt_ctcap_encode_tran_id(&msg->orig_id, &msg->dest_id, out, pos);
    CHECK_RESULT(pos);

    /*cont msg type len&tag*/
    pos = pt_asn1_encode_tl(0xe5, (pt_uint16_t)(*len - pos), out, pos);
    CHECK_RESULT(pos);
    
    *len = *len - (pt_uint16_t)pos;

    return pos;
}

static pt_int32_t pt_ctcap_encode_abort(void *msg_struct, void *out, pt_int32_t *len)
{
    ctcap_abort_t *msg = (ctcap_abort_t *)msg_struct;
    pt_int32_t pos = *len;

    pos = pt_asn1_encode_tlv(msg->abort_type, 1, &msg->abort_cause, out, pos);
    CHECK_RESULT(pos);

    /*tran orig dest id*/
    pos = pt_ctcap_encode_tran_id(NULL, &msg->dest_id, out, pos);
    CHECK_RESULT(pos);

    /*cont msg type len&tag*/
    pos = pt_asn1_encode_tl(0xf6, (pt_uint16_t)(*len - pos), out, pos);
    CHECK_RESULT(pos);

    *len = *len - (pt_uint16_t)pos;

    return pos;
}

static pt_int32_t pt_ctcap_decode_invoke_comp(void *buf, pt_int32_t pos, ctcap_comp_t *comp)
{
    pt_uint32_t t;
    pt_int32_t l;
    pt_uint8_t opcode[2];

    /*invoke component len&tag*/
    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) != 0xe9)
    {
        return -1;
    }
    
    pos = pt_asn1_decode_tl(buf, pos, &t, &l);
    CHECK_RESULT(pos);

    comp->para_len = l - 7;
    
    /*comp id*/
    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) != 0xcf)
    {
        return -1;
    }

    pos = pt_asn1_decode_tlv(buf, pos, &t, &l, &comp->comp_id);
    CHECK_RESULT(pos);

    /*op code*/
	t = pt_asn1_code_tag((pt_uint8_t *)buf + pos);
    if (t != 0xd1 && t != 0xd0)
    {
        return -1;
    }

    pos = pt_asn1_decode_tlv(buf, pos, &t, &l, opcode);
    CHECK_RESULT(pos);
    
    comp->i_op_code = opcode[1];

    /*parameter*/
    pos = pt_asn1_decode_v(buf, pos, comp->para_len, comp->para);
    CHECK_RESULT(pos);
    
    return pos;
}

static pt_int32_t pt_ctcap_decode_result_comp(void *buf, pt_int32_t pos, ctcap_comp_t *comp)
{
    pt_uint32_t t;
    pt_int32_t l;

    /*result component len&tag*/
    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) != 0xea)
    {
        return -1;
    }
    
    pos = pt_asn1_decode_tl(buf, pos, &t, &l);
    CHECK_RESULT(pos);

    comp->para_len = l - 3;

    /*comp id*/
    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) != 0xcf)
    {
        return -1;
    }

    pos = pt_asn1_decode_tlv(buf, pos, &t, &l, &comp->comp_id);
    CHECK_RESULT(pos);

    /*parameter*/
    pos = pt_asn1_decode_v(buf, pos, comp->para_len, comp->para);
    CHECK_RESULT(pos);
    
    return 0;
}

static pt_int32_t pt_ctcap_decode_error_comp(void *buf, pt_int32_t pos, ctcap_comp_t *comp)
{
    pt_uint32_t t;
    pt_int32_t l;

    /*invoke component len&tag*/
    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) != 0xeb)
    {
        return -1;
    }
    
    pos = pt_asn1_decode_tl(buf, pos, &t, &l);
    CHECK_RESULT(pos);

    comp->para_len = l - 6;
    
    /*comp id*/
    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) != 0xcf)
    {
        return -1;
    }

    pos = pt_asn1_decode_tlv(buf, pos, &t, &l, &comp->comp_id);
    CHECK_RESULT(pos);

    /*error code*/
	t = pt_asn1_code_tag((pt_uint8_t *)buf + pos);
    if (t != 0xd4 && t != 0xd3)
    {
        return -1;
    }

    pos = pt_asn1_decode_tlv(buf, pos, &t, &l, &comp->e_error_code);
    CHECK_RESULT(pos);

    /*parameter*/
    pos = pt_asn1_decode_v(buf, pos, comp->para_len, comp->para);
    CHECK_RESULT(pos);
    
    return pos;
}

static pt_int32_t pt_ctcap_decode_comp(void *buf, pt_int32_t pos, ctcap_comp_t *comp)
{
    pt_uint32_t t;
    pt_int32_t l;

    /*Component Sequence Id&len*/
    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) != 0xe8)
    {
        return -1;
    }

    pos = pt_asn1_decode_tl(buf, pos, &t, &l);
    CHECK_RESULT(pos);

    /*invoke component len&tag*/
    comp->comp_type = pt_asn1_code_tag((pt_uint8_t *)buf + pos);
    if (comp->comp_type == CCOMP_TYPE_INVOKE)/*invoke*/
    {
        pos = pt_ctcap_decode_invoke_comp(buf, pos, comp);
    }
    else if (comp->comp_type == CCOMP_TYPE_RESULT)/*result*/
    {
        pos = pt_ctcap_decode_result_comp(buf, pos, comp);
    }
    else if (comp->comp_type == CCOMP_TYPE_ERROR)/*error*/
    {
        pos = pt_ctcap_decode_error_comp(buf, pos, comp);
    }
    else
    {
        return -1;
    }
    CHECK_RESULT(pos);

    return pos;
}


static pt_int32_t pt_ctcap_decode_tran_id(void *buf, pt_int32_t pos, ctcap_tran_id_t *orig_id, ctcap_tran_id_t *dest_id)
{
    pt_uint32_t t;
    pt_int32_t l;

    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) != 0xc7)
    {
        return -1;
    }

    pos = pt_asn1_decode_tl(buf, pos, &t, &l);
    CHECK_RESULT(pos);

    if (l == 4 && orig_id)
    {
        pos = pt_asn1_decode_v(buf, pos, l, orig_id);
    }
    else if (l == 4 && dest_id)
    {
        pos = pt_asn1_decode_v(buf, pos, l, dest_id);
    }
    else if (l == 8 && orig_id && dest_id)
    {
        pos = pt_asn1_decode_v(buf, pos, 4, orig_id);
        CHECK_RESULT(pos);

        pos = pt_asn1_decode_v(buf, pos, 4, dest_id);
    }
    else if (l == 0)
    {
        ;
    }
    else
    {
        pos = -1;
    }
    CHECK_RESULT(pos);

    return pos;
}

static pt_int32_t pt_ctcap_decode_unidir(void *in, pt_int32_t len, void *msg_struct)
{
    ctcap_unidir_t *msg = (ctcap_unidir_t *)msg_struct;
    pt_int32_t pos = 0;
    pt_uint32_t t;
    pt_int32_t l;

    if (pt_asn1_code_tag(in) != 0xe1)
    {
        return -1;
    }

    pos = pt_asn1_decode_tl(in, pos, &t, &l);
    CHECK_RESULT(pos);

    /*tran orig id*/
    pos = pt_ctcap_decode_tran_id(in, pos, NULL, NULL);
    CHECK_RESULT(pos);

    /*component*/
    pos = pt_ctcap_decode_comp(in, pos, &msg->comp);
    CHECK_RESULT(pos);

    return pos;
}

static pt_int32_t pt_ctcap_decode_query(void *in, pt_int32_t len, void *msg_struct)
{
    ctcap_query_t *msg = (ctcap_query_t *)msg_struct;
    pt_int32_t pos = 0;
    pt_uint32_t t;
    pt_int32_t l;
	
	t = pt_asn1_code_tag(in);
    if (t != 0xe2 && t != 0xe3)
    {
        return -1;
    }

    pos = pt_asn1_decode_tl(in, pos, &t, &l);
    CHECK_RESULT(pos);

    /*tran orig id*/
    pos = pt_ctcap_decode_tran_id(in, pos, &msg->orig_id, NULL);
    CHECK_RESULT(pos);

    /*component*/
    pos = pt_ctcap_decode_comp(in, pos, &msg->comp);
    CHECK_RESULT(pos);

    return pos;
}

static pt_int32_t pt_ctcap_decode_response(void *in, pt_int32_t len, void *msg_struct)
{
    ctcap_response_t *msg = (ctcap_response_t *)msg_struct;
    pt_int32_t pos = 0;
    pt_uint32_t t;
    pt_int32_t l;

    if (pt_asn1_code_tag(in) != 0xe4)
    {
        return -1;
    }
    
    pos = pt_asn1_decode_tl(in, pos, &t, &l);
    CHECK_RESULT(pos);

    /*dest dest id*/
    pos = pt_ctcap_decode_tran_id(in, pos, NULL, &msg->dest_id);
    CHECK_RESULT(pos);

    /*component*/
    pos = pt_ctcap_decode_comp(in, pos, &msg->comp);
    CHECK_RESULT(pos);

    return pos;
}

static pt_int32_t pt_ctcap_decode_cont(void *in, pt_int32_t len, void *msg_struct)
{
    ctcap_cont_t *msg = (ctcap_cont_t *)msg_struct;
    pt_int32_t pos = 0;
    pt_uint32_t t;
    pt_int32_t l;
	
	t = pt_asn1_code_tag(in);
    if (t != 0xe5 && t!= 0xe6)
    {
        return -1;
    }

    pos = pt_asn1_decode_tl(in, pos, &t, &l);
    CHECK_RESULT(pos);

    /*orig dest id*/
    pos = pt_ctcap_decode_tran_id(in, pos, &msg->orig_id, &msg->dest_id);
    CHECK_RESULT(pos);

    /*component*/
    pos = pt_ctcap_decode_comp(in, pos, &msg->comp);
    CHECK_RESULT(pos);

    return pos;
}

static pt_int32_t pt_ctcap_decode_abort(void *in, pt_int32_t len, void *msg_struct)
{
    ctcap_abort_t *msg = (ctcap_abort_t *)msg_struct;
    pt_int32_t pos = 0;
    pt_uint32_t t;
    pt_int32_t l;

    if (pt_asn1_code_tag(in) != 0xf6)
    {
        return -1;
    }

    pos = pt_asn1_decode_tl(in, pos, &t, &l);
    CHECK_RESULT(pos);

    /*dest id*/
    pos = pt_ctcap_decode_tran_id(in, pos, NULL, &msg->dest_id);
    CHECK_RESULT(pos);

    pos = pt_asn1_decode_tlv(in, pos, &msg->abort_type, &l, &msg->abort_cause);
    CHECK_RESULT(pos);

    return pos;
}

typedef pt_int32_t(*CTCAP_ENCODE_FUNC)(void *msg_struct, void *out, pt_int32_t *len);
static const CTCAP_ENCODE_FUNC ctcap_encode_func[] =
{
    /*CTCAP_UNIDIR_TYPE*/       pt_ctcap_encode_unidir,
    /*CTCAP_BEGIN_TYPE*/        pt_ctcap_encode_query,
    /*CTCAP_END_TYPE*/          pt_ctcap_encode_response,
    /*CTCAP_CONT_TYPE*/         pt_ctcap_encode_cont,
    /*CTCAP_ABORT_TYPE*/        pt_ctcap_encode_abort,
};

pt_int32_t pt_ctcap_encode(pt_uint32_t type, void *msg_struct, void *out, pt_int32_t *len)
{
    return ctcap_encode_func[type](msg_struct, out, len);
}

typedef pt_int32_t(*CTCAP_DECODE_FUNC)(void *in, pt_int32_t len, void *msg_struct);
static const CTCAP_DECODE_FUNC ctcap_decode_func[] =
{
    /*CTCAP_UNIDIR_TYPE*/       pt_ctcap_decode_unidir,
    /*CTCAP_BEGIN_TYPE*/        pt_ctcap_decode_query,
    /*CTCAP_END_TYPE*/          pt_ctcap_decode_response,
    /*CTCAP_CONT_TYPE*/         pt_ctcap_decode_cont,
    /*CTCAP_ABORT_TYPE*/        pt_ctcap_decode_abort,
};

pt_int32_t pt_ctcap_decode(pt_uint32_t type, void *in, pt_int32_t len, void *msg_struct)
{
    return ctcap_decode_func[type](in, len, msg_struct);
}

void pt_ctcap_set_invoke_comp(pt_uint8_t comp_id, pt_uint8_t op_code, pt_uint8_t *para, pt_int32_t len, ctcap_comp_t *comp)
{
    comp->comp_type = CCOMP_TYPE_INVOKE;
    comp->comp_id   = comp_id;
    comp->i_op_code = op_code;
    comp->para_len  = len;

    memcpy(comp->para, para, len);
}

void pt_ctcap_set_result_comp(pt_uint8_t comp_id, pt_uint8_t *para, pt_int32_t len, ctcap_comp_t *comp)
{
    comp->comp_type = CCOMP_TYPE_RESULT;
    comp->comp_id   = comp_id;
    comp->para_len  = len;
    
    memcpy(comp->para, para, len);
}

void pt_ctcap_set_error_comp(pt_uint8_t comp_id, pt_uint8_t error_code, pt_uint8_t *para, pt_int32_t len, ctcap_comp_t *comp)
{
    comp->comp_type = CCOMP_TYPE_RESULT;
    comp->comp_id   = comp_id;
    comp->e_error_code = error_code;
    comp->para_len  = len;
    
    memcpy(comp->para, para, len);
}


