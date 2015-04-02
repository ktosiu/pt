#include "pt_include.h"
#include "pt_asn1.h"
#include "pt_tcap_itu.h"

static pt_bool_t g_sup_indef = PT_FALSE;

static pt_int32_t pt_gtcap_encode_invoke_comp(gtcap_comp_t *comp, void *buf, pt_int32_t pos)
{
    pt_int32_t tmp = pos;

    if (comp->para_len > 0)
    {
        /*parameter*/
        pos = pt_asn1_encode_v(comp->para_len, comp->para, buf, pos);
        CHECK_RESULT(pos);
    }

    /*op code*/
    pos = pt_asn1_encode_tlv(0x02, 1, &comp->type.invoke.op_code, buf, pos);
    CHECK_RESULT(pos);

    /*link id*/
    if (comp->type.invoke.link_id_flg)
    {
        pos = pt_asn1_encode_tlv(0x80, 1, &comp->type.invoke.link_id, buf, pos);
        CHECK_RESULT(pos);
    }

    /*invoke id*/
    pos = pt_asn1_encode_tlv(0x02, 1, &comp->invoke_id, buf, pos);
    CHECK_RESULT(pos);

    /*invoke component len&tag*/
    if (g_sup_indef)
    {
        pos = pt_asn1_encode_tl_indef(0xa1, (pt_uint16_t)(tmp - pos), buf, pos);
    }
    else
    {
        pos = pt_asn1_encode_tl(0xa1, (pt_uint16_t)(tmp - pos), buf, pos);
    }
    CHECK_RESULT(pos);

    return pos;
}

static pt_int32_t pt_gtcap_encode_result_comp(gtcap_comp_t *comp, void *buf, pt_int32_t pos)
{
    pt_int32_t tmp = pos;

    if (comp->para_len > 0)
    {
        /*parameter*/
        pos = pt_asn1_encode_v(comp->para_len, comp->para, buf, pos);
        CHECK_RESULT(pos);

        /*op code*/
        pos = pt_asn1_encode_tlv(0x02, 1, &comp->type.result.op_code, buf, pos);
        CHECK_RESULT(pos);

        /*sequencelen&tag*/
        if (g_sup_indef)
        {
            pos = pt_asn1_encode_tl_indef(0x30, (pt_uint16_t)(tmp - pos), buf, pos);
        }
        else
        {
            pos = pt_asn1_encode_tl(0x30, (pt_uint16_t)(tmp - pos), buf, pos);
        }
        CHECK_RESULT(pos);
    }

    /*invoke id*/
    pos = pt_asn1_encode_tlv(0x02, 1, &comp->invoke_id, buf, pos);
    CHECK_RESULT(pos);

    /*result component len&tag*/
    if (g_sup_indef)
    {
        pos = pt_asn1_encode_tl_indef(0xa2, (pt_uint16_t)(tmp - pos), buf, pos);
    }
    else
    {
        pos = pt_asn1_encode_tl(0xa2, (pt_uint16_t)(tmp - pos), buf, pos);
    }
    CHECK_RESULT(pos);

    return pos;
}

static pt_int32_t pt_gtcap_encode_error_comp(gtcap_comp_t *comp, void *buf, pt_int32_t pos)
{
    pt_int32_t tmp = pos;

    if (comp->para_len > 0)
    {
        /*parameter*/
        pos = pt_asn1_encode_v(comp->para_len, comp->para, buf, pos);
        CHECK_RESULT(pos);
    }

    /*error code*/
    pos = pt_asn1_encode_tlv(0x02, 1, &comp->type.error.error_code, buf, pos);
    CHECK_RESULT(pos);

    /*invoke id*/
    pos = pt_asn1_encode_tlv(0x02, 1, &comp->invoke_id, buf, pos);
    CHECK_RESULT(pos);

    /*error component len&tag*/
    if (g_sup_indef)
    {
        pos = pt_asn1_encode_tl_indef(0xa3, (pt_uint16_t)(tmp - pos), buf, pos);
    }
    else
    {
        pos = pt_asn1_encode_tl(0xa3, (pt_uint16_t)(tmp - pos), buf, pos);
    }
    CHECK_RESULT(pos);

    return pos;
}

static pt_int32_t pt_gtcap_encode_reject_comp(gtcap_comp_t *comp, void *buf, pt_int32_t pos)
{
    pt_int32_t tmp = pos;
    
    /*problem code returnResultProblem*/
    pos = pt_asn1_encode_tlv(0x82, 1, &comp->type.reject.problem_code, buf, pos);
    CHECK_RESULT(pos);
    
    /*invoke id*/
    pos = pt_asn1_encode_tlv(0x02, 1, &comp->invoke_id, buf, pos);
    CHECK_RESULT(pos);
    
    /*reject component len&tag*/
    if (g_sup_indef)
    {
        pos = pt_asn1_encode_tl_indef(0xa4, (pt_uint16_t)(tmp - pos), buf, pos);
    }
    else
    {
        pos = pt_asn1_encode_tl(0xa4, (pt_uint16_t)(tmp - pos), buf, pos);
    }
    CHECK_RESULT(pos);
    
    return pos;
}

static pt_int32_t pt_gtcap_encode_comp_buf(gtcap_comp_t *comp, void *buf, pt_int32_t pos)
{
	if (comp->comp_type == GCOMP_TYPE_INVOKE)
    {
        pos = pt_gtcap_encode_invoke_comp(comp, buf, pos);
    }
    else if (comp->comp_type == GCOMP_TYPE_RESULT
        || comp->comp_type == GCOMP_TYPE_RESULT_NL)
    {
        pos = pt_gtcap_encode_result_comp(comp, buf, pos);
    }
    else if (comp->comp_type == GCOMP_TYPE_ERROR)
    {
        pos = pt_gtcap_encode_error_comp(comp, buf, pos);
    }
    else if (comp->comp_type == GCOMP_TYPE_REJECT)
    {
        pos = pt_gtcap_encode_reject_comp(comp, buf, pos);
    }
    else 
    {
        return -1;
    }
    CHECK_RESULT(pos);

	return pos;
}

static pt_int32_t pt_gtcap_encode_comp(gtcap_comp_t *comp, gtcap_comp_t *comp_ex, void *buf, pt_int32_t pos)
{
    pt_int32_t tmp = pos;

	if (comp==NULL && comp_ex==NULL)
	{
		return pos;
	}
	
	/*component buf*/
	if (comp_ex!=NULL)
	{
		pos = pt_gtcap_encode_comp_buf(comp_ex, buf, pos);
		CHECK_RESULT(pos);
	}
    
    if (comp!=NULL)
	{
		pos = pt_gtcap_encode_comp_buf(comp, buf, pos);
		CHECK_RESULT(pos);
	}


    /*component len&tag*/
    if (g_sup_indef)
    {
        pos = pt_asn1_encode_tl_indef(0x6c, (pt_uint16_t)(tmp - pos), buf, pos);
    }
    else
    {
        pos = pt_asn1_encode_tl(0x6c, (pt_uint16_t)(tmp - pos), buf, pos);
    }
    CHECK_RESULT(pos);

    return pos;
}

static pt_int32_t pt_gtcap_encode_user_info(gtcap_user_info_t *user_info, void *buf, pt_int32_t pos)
{
    if (g_sup_indef)
    {
        pos = pt_asn1_encode_tlv_indef(0xbe, user_info->info_len, user_info->info, buf, pos);
    }
    else
    {
        pos = pt_asn1_encode_tlv(0xbe, user_info->info_len, user_info->info, buf, pos);
    }
    CHECK_RESULT(pos);

    return pos;
}

static pt_int32_t pt_gtcap_encode_aarq_dlg(gtcap_dlg_t *dlg, void *buf, pt_int32_t pos)
{
    pt_uint8_t app_context_name[7] = {4, 0, 0, 1, 0, 0/*ac value*/, 0/*ac version*/};
    pt_uint8_t protocol_version[2] = {0x07, 0x80};

    pt_int32_t tmp = pos;

    /*user info*/
    if (dlg->user_info_flg != 0)
    {
        pos = pt_gtcap_encode_user_info(&dlg->user_info, buf, pos);
        CHECK_RESULT(pos);
    }

    /*application context name*/
    app_context_name[5] = dlg->type.aarq.ac_value;
    app_context_name[6] = dlg->type.aarq.ac_version;
    
    pos = pt_asn1_encode_tlv(0x06, sizeof(app_context_name), app_context_name, buf, pos);
    CHECK_RESULT(pos);

    /*application context name len&tag*/
    if (g_sup_indef)
    {
        pos = pt_asn1_encode_tl_indef(0xa1, sizeof(app_context_name) + 2, buf, pos);
    }
    else
    {
        pos = pt_asn1_encode_tl(0xa1, sizeof(app_context_name) + 2, buf, pos);
    }
    CHECK_RESULT(pos);

    /*protocol version*/
    pos = pt_asn1_encode_tlv(0x80, sizeof(protocol_version), protocol_version, buf, pos);
    CHECK_RESULT(pos);

    /*AARQ len&tag*/
    if (g_sup_indef)
    {
        pos = pt_asn1_encode_tl_indef(0x60, (pt_uint16_t)(tmp - pos), buf, pos);
    }
    else
    {
        pos = pt_asn1_encode_tl(0x60, (pt_uint16_t)(tmp - pos), buf, pos);
    }
    CHECK_RESULT(pos);

    return pos;
}

static pt_int32_t pt_gtcap_encode_aare_dlg(gtcap_dlg_t *dlg, void *buf, pt_int32_t pos)
{
    pt_uint8_t app_context_name[7] = {4, 0, 0, 1, 0, 0/*ac value*/, 0/*ac version*/};
    pt_uint8_t protocol_version[2] = {0x07, 0x80};

    pt_int32_t tmp = pos;

    /*user info*/
    if (dlg->user_info_flg != 0)
    {
        pos = pt_gtcap_encode_user_info(&dlg->user_info, buf, pos);
        CHECK_RESULT(pos);
    }
    
    /*diagnostic*/
    pos = pt_asn1_encode_tlv(0x02, 1, &dlg->type.aare.diagnostic, buf, pos);
    CHECK_RESULT(pos);

    if (g_sup_indef)
    {
        pos = pt_asn1_encode_tl_indef(0xa1, 3, buf, pos);
    }
    else
    {
        pos = pt_asn1_encode_tl(0xa1, 3, buf, pos);
    }
    CHECK_RESULT(pos);
    
    if (g_sup_indef)
    {
        pos = pt_asn1_encode_tl_indef(0xa3, 5, buf, pos);
    }
    else
    {
        pos = pt_asn1_encode_tl(0xa3, 5, buf, pos);
    }
    CHECK_RESULT(pos);

    /*result*/
    pos = pt_asn1_encode_tlv(0x02, 1, &dlg->type.aare.result, buf, pos);
    CHECK_RESULT(pos);
    
    if (g_sup_indef)
    {
        pos = pt_asn1_encode_tl_indef(0xa2, 3, buf, pos);
    }
    else
    {
        pos = pt_asn1_encode_tl(0xa2, 3, buf, pos);
    }
    CHECK_RESULT(pos);

    /*application context name*/
    app_context_name[5] = dlg->type.aare.ac_value;
    app_context_name[6] = dlg->type.aare.ac_version;
    
    pos = pt_asn1_encode_tlv(0x06, sizeof(app_context_name), app_context_name, buf, pos);
    CHECK_RESULT(pos);

    /*application context name len&tag*/
    if (g_sup_indef)
    {
        pos = pt_asn1_encode_tl_indef(0xa1, sizeof(app_context_name) + 2, buf, pos);
    }
    else
    {
        pos = pt_asn1_encode_tl(0xa1, sizeof(app_context_name) + 2, buf, pos);
    }
    CHECK_RESULT(pos);

    /*protocol version*/
    pos = pt_asn1_encode_tlv(0x80, sizeof(protocol_version), protocol_version, buf, pos);
    CHECK_RESULT(pos);

    /*AARE len&tag*/
    if (g_sup_indef)
    {
        pos = pt_asn1_encode_tl_indef(0x61, (pt_uint16_t)(tmp - pos), buf, pos);
    }
    else
    {
        pos = pt_asn1_encode_tl(0x61, (pt_uint16_t)(tmp - pos), buf, pos);
    }
    
    CHECK_RESULT(pos);

    return pos;
}

static pt_int32_t pt_gtcap_encode_abrt_dlg(gtcap_dlg_t *dlg, void *buf, pt_int32_t pos)
{
    pt_int32_t tmp = pos;

    /*user info*/
    if (dlg->user_info_flg != 0)
    {
        pos = pt_gtcap_encode_user_info(&dlg->user_info, buf, pos);
        CHECK_RESULT(pos);
    }

    /*src abort*/
    pos = pt_asn1_encode_tlv(0x80, 1, &dlg->type.abrt.abort_src, buf, pos);
    CHECK_RESULT(pos);

    /*ABRT tag&len*/
    if (g_sup_indef)
    {
        pos = pt_asn1_encode_tl_indef(0x64, (pt_uint16_t)(tmp - pos), buf, pos);
    }
    else
    {
        pos = pt_asn1_encode_tl(0x64, (pt_uint16_t)(tmp - pos), buf, pos);
    }
    
    CHECK_RESULT(pos);
    
    return pos;
}

static pt_int32_t pt_gtcap_encode_dlg(gtcap_dlg_t *dlg, void *buf, pt_int32_t pos)
{
    pt_uint8_t dialogue_as_id[7] = {0x00, 0x11, 0x86, 0x05, 0x01, 0x01, 0x01};
    pt_int32_t tmp = pos;
    
    if (dlg->dlg_type == DLG_TYPE_AARQ)
    {
        if (dlg->q_ac_ver == 1)
        {
            return pos;
        }
        pos = pt_gtcap_encode_aarq_dlg(dlg, buf, pos);
    }
    else if (dlg->dlg_type == DLG_TYPE_AARE)
    {
        if (dlg->e_ac_ver == 1 && dlg->e_diagnostic != USER_AC_NOT_SUPPORT)
        {
            return pos;
        }
        pos = pt_gtcap_encode_aare_dlg(dlg, buf, pos);
    }
    else if (dlg->dlg_type == DLG_TYPE_ABRT)
    {
        pos = pt_gtcap_encode_abrt_dlg(dlg, buf, pos);
    }
    else
    {
        return -1;
    }

    /*single-ASN.1-type len&tag*/
    if (g_sup_indef)
    {
        pos = pt_asn1_encode_tl_indef(0xa0, (pt_uint16_t)(tmp - pos), buf, pos);
    }
    else
    {
        pos = pt_asn1_encode_tl(0xa0, (pt_uint16_t)(tmp - pos), buf, pos);
    }
    CHECK_RESULT(pos);

    /*dialogue-as-id*/
    pos = pt_asn1_encode_tlv(0x06, sizeof(dialogue_as_id), dialogue_as_id, buf, pos);
    CHECK_RESULT(pos);

    /*external len&tag*/
    if (g_sup_indef)
    {
        pos = pt_asn1_encode_tl_indef(0x28, (pt_uint16_t)(tmp - pos), buf, pos);
    }
    else
    {
        pos = pt_asn1_encode_tl(0x28, (pt_uint16_t)(tmp - pos), buf, pos);
    }
    CHECK_RESULT(pos);

    /*dialogue portion len&tag*/
    if (g_sup_indef)
    {
        pos = pt_asn1_encode_tl_indef(0x6b, (pt_uint16_t)(tmp - pos), buf, pos);
    }
    else
    {
        pos = pt_asn1_encode_tl(0x6b, (pt_uint16_t)(tmp - pos), buf, pos);
    }
    CHECK_RESULT(pos);

    return pos;
}

static pt_int32_t pt_gtcap_encode_tran_id(pt_uint8_t id_tag, gtcap_tran_id_t *tran_id, void *buf, pt_int32_t pos)
{
    pos = pt_asn1_encode_tlv(id_tag, tran_id->len, tran_id->id, buf, pos);
    CHECK_RESULT(pos);

    return pos;
}

static pt_int32_t pt_gtcap_encode_begin(void *msg_struct, void *out, pt_uint16_t *len)
{
    gtcap_begin_t *msg = (gtcap_begin_t *)msg_struct;
    pt_int32_t pos = *len;

    /*component**/
    if (msg->comp_flg || msg->comp_ex_flg)
    {
        pos = pt_gtcap_encode_comp(msg->comp_flg?&msg->comp:NULL, 
								msg->comp_ex_flg?&msg->comp_ex:NULL,
								out, pos);
        CHECK_RESULT(pos);
    }

    /*dialogue*/
    if (msg->dlg_flg)
    {
        pos = pt_gtcap_encode_dlg(&msg->dlg, out, pos);
        CHECK_RESULT(pos);
    }

    /*begin header**/

    /*tran orig id*/
    pos = pt_gtcap_encode_tran_id(0x48, &msg->orig_id, out, pos);
    CHECK_RESULT(pos);

    /*begin msg type len&tag*/
    if (g_sup_indef)
    {
        pos = pt_asn1_encode_tl_indef(0x62, (pt_uint16_t)(*len - pos), out, pos);
    }
    else
    {
        pos = pt_asn1_encode_tl(0x62, (pt_uint16_t)(*len - pos), out, pos);
    }
    
    CHECK_RESULT(pos);
    
    *len = *len - (pt_uint16_t)pos;

    return pos;
}

static pt_int32_t pt_gtcap_encode_end(void *msg_struct, void *out, pt_uint16_t *len)
{
    gtcap_end_t *msg = (gtcap_end_t *)msg_struct;
    pt_int32_t pos = *len;
	
    /*component*/
    if (msg->comp_flg || msg->comp_ex_flg)
    {
        pos = pt_gtcap_encode_comp(msg->comp_flg?&msg->comp:NULL, 
								msg->comp_ex_flg?&msg->comp_ex:NULL,
								out, pos);
        CHECK_RESULT(pos);
    }

    /*dialogue*/
    if (msg->dlg_flg)
    {
        pos = pt_gtcap_encode_dlg(&msg->dlg, out, pos);
        CHECK_RESULT(pos);
    }

    /*tran dest id*/
    pos = pt_gtcap_encode_tran_id(0x49, &msg->dest_id, out, pos);
    CHECK_RESULT(pos);

    /*end msg type len&tag*/
    if (g_sup_indef)
    {
        pos = pt_asn1_encode_tl_indef(0x64, (pt_uint16_t)(*len - pos), out, pos);
    } 
    else
    {
        pos = pt_asn1_encode_tl(0x64, (pt_uint16_t)(*len - pos), out, pos);
    }
    
    CHECK_RESULT(pos);

    *len = *len - (pt_uint16_t)pos;

    return pos;
}

static pt_int32_t pt_gtcap_encode_cont(void *msg_struct, void *out, pt_uint16_t *len)
{
    gtcap_cont_t *msg = (gtcap_cont_t *)msg_struct;
    pt_int32_t pos = *len;
	
    /*component*/
    if (msg->comp_flg || msg->comp_ex_flg)
    {
        pos = pt_gtcap_encode_comp(msg->comp_flg?&msg->comp:NULL, 
								msg->comp_ex_flg?&msg->comp_ex:NULL,
								out, pos);
        CHECK_RESULT(pos);
    }

    /*dialogue*/
    if (msg->dlg_flg)
    {
        pos = pt_gtcap_encode_dlg(&msg->dlg, out, pos);
        CHECK_RESULT(pos);
    }

    /*cont header*/

    /*tran dest id*/
    pos = pt_gtcap_encode_tran_id(0x49, &msg->dest_id, out, pos);
    CHECK_RESULT(pos);

    /*tran orig id*/
    pos = pt_gtcap_encode_tran_id(0x48, &msg->orig_id, out, pos);
    CHECK_RESULT(pos);

    /*cont msg type len&tag*/
    if (g_sup_indef)
    {
        pos = pt_asn1_encode_tl_indef(0x65, (pt_uint16_t)(*len - pos), out, pos);
    } 
    else
    {
        pos = pt_asn1_encode_tl(0x65, (pt_uint16_t)(*len - pos), out, pos);
    }
    CHECK_RESULT(pos);

    *len = *len - (pt_uint16_t)pos;

    return pos;
}

static pt_int32_t pt_gtcap_encode_abort(void *msg_struct, void *out, pt_uint16_t *len)
{
    gtcap_abort_t *msg = (gtcap_abort_t *)msg_struct;
    pt_int32_t pos = *len;

    if (msg->p_abort_cause_flg)
    {
        pos = pt_asn1_encode_tlv(0x4a, 1, &msg->p_abort_cause, out, pos);
    }
    else if (msg->dlg_flg)
    {
        pos = pt_gtcap_encode_dlg(&msg->dlg, out, pos);
    }
    CHECK_RESULT(pos);

    /*tran dest id*/
    pos = pt_gtcap_encode_tran_id(0x49, &msg->dest_id, out, pos);
    CHECK_RESULT(pos);

    /*abort msg type len&tag*/
    if (g_sup_indef)
    {
        pos = pt_asn1_encode_tl_indef(0x67, (pt_uint16_t)(*len - pos), out, pos);
    } 
    else
    {
        pos = pt_asn1_encode_tl(0x67, (pt_uint16_t)(*len - pos), out, pos);
    }
    
    CHECK_RESULT(pos);

    *len = *len - (pt_uint16_t)pos;

    return pos;
}

static pt_int32_t pt_gtcap_decode_invoke_comp(void *buf, pt_int32_t pos, gtcap_comp_t *comp)
{
    pt_int32_t tmp;
    pt_uint8_t t;
    pt_uint16_t l, invoke_len;

    /*invoke component len&tag*/
    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) != 0xa1)
    {
        return -1;
    }
    
    pos = pt_asn1_decode_tl(buf, pos, &t, &l);
    CHECK_RESULT(pos);
    
    tmp = pos;
    invoke_len = l;

    /*invoke id*/
    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) != 0x02)
    {
        return -1;
    }

    pos = pt_asn1_decode_tlv(buf, pos, &t, &l, &comp->invoke_id);
    CHECK_RESULT(pos);


    /*link id*/
    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) == 0x80)
    {
        pos = pt_asn1_decode_tlv(buf, pos, &t, &l, &comp->type.invoke.link_id);
        CHECK_RESULT(pos);
    
        comp->type.invoke.link_id_flg = 1;
    }

    /*op code*/
    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) != 0x02)
    {
        return -1;
    }

    pos = pt_asn1_decode_tlv(buf, pos, &t, &l, &comp->type.invoke.op_code);
    CHECK_RESULT(pos);

    /*para*/
    if (invoke_len - (pos-tmp) > 0)
    {
        comp->para_len = invoke_len - (pt_uint16_t)(pos-tmp);
        
        pos = pt_asn1_decode_v(buf, pos, comp->para_len, comp->para);
        CHECK_RESULT(pos);
    }
    
    return pos;
}

static pt_int32_t pt_gtcap_decode_result_comp(void *buf, pt_int32_t pos, gtcap_comp_t *comp)
{
    pt_int32_t tmp;
    pt_uint8_t t;
    pt_uint16_t l, invoke_len;

    /*result component len&tag*/
    t = pt_asn1_code_tag((pt_uint8_t *)buf + pos);
    if (t != 0xa2 && t != 0xa7)
    {
        return -1;
    }

    pos = pt_asn1_decode_tl(buf, pos, &t, &l);
    CHECK_RESULT(pos);
    
    tmp = pos;
    invoke_len = l;

    /*invoke id*/
    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) != 0x02)
    {
        return -1;
    }

    pos = pt_asn1_decode_tlv(buf, pos, &t, &l, &comp->invoke_id);
    CHECK_RESULT(pos);

    /*sequence tag&len*/
    if (invoke_len - (pos - tmp) > 0)
    {
        if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) != 0x30)
        {
            return -1;
        }

        pos = pt_asn1_decode_tl(buf, pos, &t, &l);
        CHECK_RESULT(pos);
    }

    /*op-code*/
    if (invoke_len - (pos - tmp) > 0)
    {
        if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) == 0x02)
        {
            pos = pt_asn1_decode_tlv(buf, pos, &t, &l, &comp->type.result.op_code);
            CHECK_RESULT(pos);

            comp->type.result.op_code_flg = 1;
        }
    }

    /*param*/
    if (invoke_len - (pos - tmp) > 0)
    {
        comp->para_len = invoke_len - (pt_uint16_t)(pos - tmp);
        
        pos = pt_asn1_decode_v(buf, pos, comp->para_len, comp->para);
        CHECK_RESULT(pos);
    }

    return pos;
}

static pt_int32_t pt_gtcap_decode_error_comp(void *buf, pt_int32_t pos, gtcap_comp_t *comp)
{
    pt_int32_t tmp;
    pt_uint8_t t;
    pt_uint16_t l, invoke_len;

    /*error component len&tag*/
    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) != 0xa3)
    {
        return -1;
    }

    pos = pt_asn1_decode_tl(buf, pos, &t, &l);
    CHECK_RESULT(pos);
    
    tmp = pos;
    invoke_len = l;

    /*invoke id*/
    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) != 0x02)
    {
        return -1;
    }

    pos = pt_asn1_decode_tlv(buf, pos, &t, &l, &comp->invoke_id);
    CHECK_RESULT(pos);

    /*error code*/
    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) != 0x02)
    {
        return -1;
    }

    pos = pt_asn1_decode_tlv(buf, pos, &t, &l, &comp->type.error.error_code);
    CHECK_RESULT(pos);

    /*param*/
    if (invoke_len - (pos - tmp) > 0)
    {
        comp->para_len = invoke_len - (pt_uint16_t)(pos - tmp);
        
        pos = pt_asn1_decode_v(buf, pos, comp->para_len, comp->para);
        CHECK_RESULT(pos);
    }

    return pos;
}

static pt_int32_t pt_gtcap_decode_reject_comp(void *buf, pt_int32_t pos, gtcap_comp_t *comp)
{
    pt_uint8_t t;
    pt_uint16_t l;
    
    /*reject component len&tag*/
    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) != 0xa4)
    {
        return -1;
    }
    
    pos = pt_asn1_decode_tl(buf, pos, &t, &l);
    CHECK_RESULT(pos);
    
    /*invoke id*/
    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) != 0x02)
    {
        return -1;
    }
    
    pos = pt_asn1_decode_tlv(buf, pos, &t, &l, &comp->invoke_id);
    CHECK_RESULT(pos);
    
    /*problem code*/
    t = pt_asn1_code_tag((pt_uint8_t *)buf + pos);
    if (t != 0x80 && t != 0x81 && t != 0x82 && t != 0x83)
    {
        return -1;
    }
    
    pos = pt_asn1_decode_tlv(buf, pos, &t, &l, &comp->type.reject.problem_code);
    CHECK_RESULT(pos);
   
    return pos;
}

pt_int32_t pt_gtcap_decode_comp_item(void *buf, pt_int32_t pos, gtcap_comp_t *comp)
{
	comp->comp_type = pt_asn1_code_tag((pt_uint8_t *)buf + pos);
    if (comp->comp_type == GCOMP_TYPE_INVOKE)/*invoke*/
    {
        pos = pt_gtcap_decode_invoke_comp(buf, pos, comp);
    }
    else if (comp->comp_type == GCOMP_TYPE_RESULT
        || comp->comp_type == GCOMP_TYPE_RESULT_NL)/*result*/
    {
        pos = pt_gtcap_decode_result_comp(buf, pos, comp);
    }
    else if (comp->comp_type == GCOMP_TYPE_ERROR)/*error*/
    {
        pos = pt_gtcap_decode_error_comp(buf, pos, comp);
    }
    else if (comp->comp_type == GCOMP_TYPE_REJECT)
    {
        pos = pt_gtcap_decode_reject_comp(buf, pos, comp);
    }
    else
    {
        return -1;
    }
    CHECK_RESULT(pos);

	return pos;
}

static pt_int32_t pt_gtcap_decode_comp(void *buf, pt_int32_t pos, gtcap_comp_t *comp)
{
    pt_uint8_t t;
    pt_uint16_t l;
    
    /*component len&tag*/
    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) != 0x6c)
    {
        return -1;
    }

    pos = pt_asn1_decode_tl(buf, pos, &t, &l);
    CHECK_RESULT(pos);

    pos = pt_gtcap_decode_comp_item(buf, pos, comp);
	CHECK_RESULT(pos);
    
    return pos;
}

static pt_int32_t pt_gtcap_decode_user_info(void *buf, pt_int32_t pos, gtcap_user_info_t *user_info)
{
    pt_uint8_t t;
    
    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) != 0xbe)
    {
        return -1;
    }
    
    pos = pt_asn1_decode_tlv(buf, pos, &t, &user_info->info_len, user_info->info);
    CHECK_RESULT(pos);

    return pos;
}

static pt_int32_t pt_gtcap_decode_aarq_dlg(void *buf, pt_int32_t pos, gtcap_dlg_t *dlg)
{
    pt_int32_t tmp;
    pt_uint8_t t;
    pt_uint16_t l, dlg_len;

    /*AARQ len&tag*/
    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) != 0x60)
    {
        return -1;
    }

    pos = pt_asn1_decode_tl(buf, pos, &t, &l);
    CHECK_RESULT(pos);

    tmp = pos;
    dlg_len = l;

    /*protocol version*/
    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) == 0x80)
    {
        pos = pt_asn1_decode_tl(buf, pos, &t, &l);
        CHECK_RESULT(pos);

        pos += l;
    }

    /*application context name len&tag*/
    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) != 0xa1)
    {
        return -1;
    }

    pos = pt_asn1_decode_tl(buf, pos, &t, &l);
    CHECK_RESULT(pos);

    /*application context name*/
    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) != 0x06)
    {
        return -1;
    }

    pos = pt_asn1_decode_tl(buf, pos, &t, &l);
    CHECK_RESULT(pos);

    dlg->type.aarq.ac_value = *((pt_uint8_t *)buf + pos + (l - 2));
    dlg->type.aarq.ac_version = *((pt_uint8_t *)buf + pos + (l - 1));

    pos += l;
    
    /*user info*/
    if (dlg_len - (pos-tmp) > 0)
    {
        pos = pt_gtcap_decode_user_info(buf, pos, &dlg->user_info);
        CHECK_RESULT(pos);

        dlg->user_info_flg = 1;
    }

    return pos;
}

static pt_int32_t pt_gtcap_decode_aare_dlg(void *buf, pt_int32_t pos, gtcap_dlg_t *dlg)
{
    pt_int32_t tmp;
    pt_uint8_t t;
    pt_uint16_t l, dlg_len;

    /*AARE len&tag*/
    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) != 0x61)
    {
        return -1;
    }

    pos = pt_asn1_decode_tl(buf, pos, &t, &l);
    CHECK_RESULT(pos);

    tmp = pos;
    dlg_len = l;

    /*protocol version*/
    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) == 0x80)
    {
        pos = pt_asn1_decode_tl(buf, pos, &t, &l);
        CHECK_RESULT(pos);

        pos += l;
    }

    /*application context name len&tag*/
    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) != 0xa1)
    {
        return -1;
    }

    pos = pt_asn1_decode_tl(buf, pos, &t, &l);
    CHECK_RESULT(pos);

    /*application context name*/
    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) != 0x06)
    {
        return -1;
    }

    pos = pt_asn1_decode_tl(buf, pos, &t, &l);
    CHECK_RESULT(pos);

    dlg->type.aare.ac_value = *((pt_uint8_t *)buf + pos + (l - 2));
    dlg->type.aare.ac_version = *((pt_uint8_t *)buf + pos + (l - 1));

    pos += l;

    /*result*/
    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) != 0xa2)
    {
        return -1;
    }

    pos = pt_asn1_decode_tl(buf, pos, &t, &l);
    CHECK_RESULT(pos);

    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) != 0x02)
    {
        return -1;
    }
    pos = pt_asn1_decode_tlv(buf, pos, &t, &l, &dlg->type.aare.result);
    CHECK_RESULT(pos);

    /*diagnostic*/
    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) != 0xa3)
    {
        return -1;
    }

    pos = pt_asn1_decode_tl(buf, pos, &t, &l);
    CHECK_RESULT(pos);
    
    t = pt_asn1_code_tag((pt_uint8_t *)buf + pos);
    if (t != 0xa1 && t != 0xa2) /*user-provider*/
    {
        return -1;
    }
    
    pos = pt_asn1_decode_tl(buf, pos, &t, &l);
    CHECK_RESULT(pos);

    pos = pt_asn1_decode_tlv(buf, pos, &t, &l, &dlg->type.aare.diagnostic);
    CHECK_RESULT(pos);

    /*user info*/
    if (dlg_len - (pos-tmp) > 0)
    {
        pos = pt_gtcap_decode_user_info(buf, pos, &dlg->user_info);
        CHECK_RESULT(pos);

        dlg->user_info_flg = 1;
    }

    return pos;
}

static pt_int32_t pt_gtcap_decode_abort_dlg(void *buf, pt_int32_t pos, gtcap_dlg_t *dlg)
{
    pt_int32_t tmp;
    pt_uint8_t t;
    pt_uint16_t l, dlg_len;

    /*ABRT len&tag*/
    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) != 0x64)
    {
        return -1;
    }

    pos = pt_asn1_decode_tl(buf, pos, &t, &l);
    CHECK_RESULT(pos);

    tmp = pos;
    dlg_len = l;

    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) != 0x80)
    {
        return -1;
    }
    pos = pt_asn1_decode_tlv(buf, pos, &t, &l, &dlg->type.abrt.abort_src);
    CHECK_RESULT(pos);

    /*user info*/
    if (dlg_len - (pos-tmp) > 0)
    {
        pos = pt_gtcap_decode_user_info(buf, pos, &dlg->user_info);
        CHECK_RESULT(pos);

        dlg->user_info_flg = 1;
    }

    return pos;
}

static pt_int32_t pt_gtcap_decode_dlg(void *buf, pt_int32_t pos, gtcap_dlg_t *dlg)
{
    pt_uint8_t t;
    pt_uint16_t l;
    
    /*dialogue portion len&tag*/
    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) != 0x6b)
    {
        return -1;
    }

    pos = pt_asn1_decode_tl(buf, pos, &t, &l);
    CHECK_RESULT(pos);

    /*external len&tag*/
    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) != 0x28)
    {
        return -1;
    }

    pos = pt_asn1_decode_tl(buf, pos, &t, &l);
    CHECK_RESULT(pos);

    /*dialogue-as-id*/
    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) != 0x06)
    {
        return -1;
    }

    pos = pt_asn1_decode_tl(buf, pos, &t, &l);
    CHECK_RESULT(pos);
    
    pos += l;

    /*single-ASN.1-type len&tag*/
    if (pt_asn1_code_tag((pt_uint8_t *)buf + pos) != 0xa0)
    {
        return -1;
    }

    pos = pt_asn1_decode_tl(buf, pos, &t, &l);
    CHECK_RESULT(pos);

    t = pt_asn1_code_tag((pt_uint8_t *)buf + pos);
    if (t == DLG_TYPE_AARQ)/*AARQ PDU*/
    {
        dlg->dlg_type = DLG_TYPE_AARQ;
        
        pos = pt_gtcap_decode_aarq_dlg(buf, pos, dlg);
    }
    else if (t == DLG_TYPE_AARE)/*AARE PDU*/
    {
        dlg->dlg_type = DLG_TYPE_AARE;
        
        pos = pt_gtcap_decode_aare_dlg(buf, pos, dlg);
    }
    else if (t == DLG_TYPE_ABRT)/*ABORT PDU*/
    {
        dlg->dlg_type = DLG_TYPE_ABRT;
        
        pos = pt_gtcap_decode_abort_dlg(buf, pos, dlg);
    }
    else
    {
        return -1;
    }
    CHECK_RESULT(pos);

    return pos;
}

static pt_int32_t pt_gtcap_decode_tran_id(void *buf, pt_int32_t pos, gtcap_tran_id_t *tran_id)
{
    pt_uint8_t t;
    pt_uint16_t l;
    
    t = pt_asn1_code_tag((pt_uint8_t *)buf + pos);
    if (t != 0x48 && t != 0x49)
    {
        return -1;
    }

    pos = pt_asn1_decode_tlv(buf, pos, &t, &l, tran_id->id);
    CHECK_RESULT(pos);

    tran_id->len = (pt_uint8_t)l;

    return pos;
}

static pt_int32_t pt_gtcap_decode_begin(void *in, pt_uint16_t len, void *msg_struct)
{
    gtcap_begin_t *msg = (gtcap_begin_t *)msg_struct;
    pt_int32_t pos = 0;
    pt_uint8_t t;
    pt_uint16_t l;

    /*begin*/
    if (pt_asn1_code_tag((pt_uint8_t *)in + pos) != 0x62)
    {
        return -1;
    }

    pos = pt_asn1_decode_tl(in, pos, &t, &l);
    CHECK_RESULT(pos);

    /*tran orig id*/
    pos = pt_gtcap_decode_tran_id(in, pos, &msg->orig_id);
    CHECK_RESULT(pos);

    if (pos >= len)
    {
        return pos;
    }

    /*dialogue*/
    t = pt_asn1_code_tag((pt_uint8_t *)in + pos);
    if (t == 0x6b)
    {
        pos = pt_gtcap_decode_dlg(in, pos, &msg->dlg);
        CHECK_RESULT(pos);

        msg->dlg_flg = 1;
    }

    if (pos >= len)
    {
        return pos;
    }

    /*component**/
    pos = pt_gtcap_decode_comp(in, pos, &msg->comp);
    CHECK_RESULT(pos);

    msg->comp_flg = 1;

    return pos;
}

static pt_int32_t pt_gtcap_decode_end(void *in, pt_uint16_t len, void *msg_struct)
{
    gtcap_end_t *msg = (gtcap_end_t *)msg_struct;
    pt_int32_t pos = 0;
    pt_uint8_t t;
    pt_uint16_t l;

    /*end*/
    if (pt_asn1_code_tag((pt_uint8_t *)in + pos) != 0x64)
    {
        return -1;
    }

    pos = pt_asn1_decode_tl(in, pos, &t, &l);
    CHECK_RESULT(pos);

    /*tran dest id*/
    pos = pt_gtcap_decode_tran_id(in, pos, &msg->dest_id);
    CHECK_RESULT(pos);

    if (pos >= len)
    {
        return pos;
    }

    /*dialogue*/
    t = pt_asn1_code_tag((pt_uint8_t *)in + pos);
    if (t == 0x6b)
    {
        pos = pt_gtcap_decode_dlg(in, pos, &msg->dlg);
        CHECK_RESULT(pos);

        msg->dlg_flg = 1;
    }

    if (pos >= len)
    {
        return pos;
    }

    /*component*/
    pos = pt_gtcap_decode_comp(in, pos, &msg->comp);
    CHECK_RESULT(pos);

    msg->comp_flg = 1;

    return pos;
}


pt_int32_t pt_gtcap_decode_cont(void *in, pt_uint16_t len, void *msg_struct)
{
    gtcap_cont_t *msg = (gtcap_cont_t *)msg_struct;
    pt_int32_t pos = 0;
    pt_uint8_t t;
    pt_uint16_t l;

    /*continue*/
    if (pt_asn1_code_tag((pt_uint8_t *)in + pos) != 0x65)
    {
        return -1;
    }

    pos = pt_asn1_decode_tl(in, pos, &t, &l);
    CHECK_RESULT(pos);
    
    /*tran orig id*/
    pos = pt_gtcap_decode_tran_id(in, pos, &msg->orig_id);
    CHECK_RESULT(pos);

    /*tran dest id*/
    pos = pt_gtcap_decode_tran_id(in, pos, &msg->dest_id);
    CHECK_RESULT(pos);

    if (pos >= len)
    {
        return pos;
    }

    /*dialogue*/
    t = pt_asn1_code_tag((pt_uint8_t *)in + pos);
    if (t == 0x6b)
    {
        pos = pt_gtcap_decode_dlg(in, pos, &msg->dlg);
        CHECK_RESULT(pos);

        msg->dlg_flg = 1;
    }

    if (pos >= len)
    {
        return pos;
    }

    /*component len&tag*/
    pos = pt_gtcap_decode_comp(in, pos, &msg->comp);
    CHECK_RESULT(pos);

    msg->comp_flg = 1;

    return pos;
}

pt_int32_t pt_gtcap_decode_abort(void *in, pt_uint16_t len, void *msg_struct)
{
    gtcap_abort_t *msg = (gtcap_abort_t *)msg_struct;
    pt_int32_t pos = 0;
    pt_uint8_t t;
    pt_uint16_t l;

    /*abort*/
    if (pt_asn1_code_tag((pt_uint8_t *)in + pos) != 0x67)
    {
        return -1;
    }

    pos = pt_asn1_decode_tl(in, pos, &t, &l);
    CHECK_RESULT(pos);

    /*tran dest id*/
    pos = pt_gtcap_decode_tran_id(in, pos, &msg->dest_id);
    CHECK_RESULT(pos);

    if (pos >= len)
    {
        return pos;
    }
    
    if (pt_asn1_code_tag((pt_uint8_t *)in + pos) == 0x4a)/*p-abort*/
    {
        pos = pt_asn1_decode_tlv(in, pos, &t, &l, &msg->p_abort_cause);
        CHECK_RESULT(pos);

        msg->p_abort_cause_flg = 1;
    }
    else/*dialogue*/
    {
        pos = pt_gtcap_decode_dlg(in, pos, &msg->dlg);
        CHECK_RESULT(pos);

        msg->dlg_flg = 1;
    }

    return pos;
}

static const pt_uint8_t _gtcap_code_mapping[] = 
{
    GTCAP_BEGIN_TAG_TYPE, 
    GTCAP_END_TAG_TYPE, 
    GTCAP_CONTINUE_TAG_TYPE, 
    GTCAP_ABORT_TAG_TYPE
};

typedef pt_int32_t(*_GTCAP_ENCODE_FUNC)(void *msg_struct, void *out, pt_uint16_t *len);
static const _GTCAP_ENCODE_FUNC _gtcap_encode_func[] =
{
    /*GTCAP_BEGIN_TYPE*/        pt_gtcap_encode_begin,
    /*GTCAP_END_TYPE*/          pt_gtcap_encode_end,
    /*GTCAP_CONT_TYPE*/         pt_gtcap_encode_cont,
    /*GTCAP_ABORT_TYPE*/        pt_gtcap_encode_abort,
};

pt_int32_t pt_gtcap_encode(gtcap_msg_t *gtcap_msg, void *out, pt_uint16_t *len)
{
    pt_int32_t i;

    for (i = 0; i < PT_ARRAY_SIZE(_gtcap_code_mapping); i++)
        if (_gtcap_code_mapping[i] == gtcap_msg->m_type)
            return _gtcap_encode_func[i](&gtcap_msg->msg, out, len);

    return -1;
}

typedef pt_int32_t(*_GTCAP_DECODE_FUNC)(void *in, pt_uint16_t len, void *msg_struct);
static const _GTCAP_DECODE_FUNC _gtcap_decode_func[] =
{
    /*GTCAP_BEGIN_TYPE*/        pt_gtcap_decode_begin,
    /*GTCAP_END_TYPE*/          pt_gtcap_decode_end,
    /*GTCAP_CONT_TYPE*/         pt_gtcap_decode_cont,
    /*GTCAP_ABORT_TYPE*/        pt_gtcap_decode_abort,
};

pt_int32_t pt_gtcap_decode(void *in, pt_uint16_t len, gtcap_msg_t *gtcap_msg)
{
    pt_int32_t i;

    gtcap_msg->m_type = *(pt_uint8_t *)in;

    for (i = 0; i < PT_ARRAY_SIZE(_gtcap_code_mapping); i++)
        if (_gtcap_code_mapping[i] == gtcap_msg->m_type)
            return _gtcap_decode_func[i](in, len, &gtcap_msg->msg);

    return -1;
}

void pt_gtcap_set_invoke_comp(pt_uint8_t invk_id, pt_uint8_t op_code, pt_uint8_t *para, pt_uint16_t len, gtcap_comp_t *comp)
{
    comp->comp_type     = GCOMP_TYPE_INVOKE;
    comp->invoke_id     = invk_id;
    comp->i_link_id_flg = 0;
    comp->i_op_code     = op_code;
    comp->para_len      = len;
    memcpy(comp->para, para, len);
}

void pt_gtcap_set_result_comp(pt_uint8_t invk_id, pt_uint8_t op_code, pt_uint8_t *para, pt_uint16_t len, gtcap_comp_t *comp)
{
    comp->comp_type     = GCOMP_TYPE_RESULT;
    comp->invoke_id     = invk_id;
    comp->r_op_code     = op_code;
    comp->para_len      = len;
    memcpy(comp->para, para, len);
}

void pt_gtcap_set_error_comp(pt_uint8_t invk_id, pt_uint8_t error_code, pt_uint8_t *para, pt_uint16_t len, gtcap_comp_t *comp)
{
    comp->comp_type     = GCOMP_TYPE_ERROR;
    comp->invoke_id     = invk_id;
    comp->e_error_code  = error_code;
    comp->para_len      = len;
    memcpy(comp->para, para, len);
}

void pt_gtcap_set_aarq_dlg(pt_uint8_t ac_ver, pt_uint8_t ac_val, pt_uint8_t *user_info, pt_uint16_t len, gtcap_dlg_t *dlg)
{
    dlg->dlg_type = DLG_TYPE_AARQ;

    dlg->q_ac_ver = ac_ver;
    dlg->q_ac_val = ac_val;

    if (user_info != NULL)
    {
        dlg->user_info_flg = 1;
        dlg->user_info.info_len = len;
        memcpy(dlg->user_info.info, user_info, len);
    }
    else
    {
        dlg->user_info_flg = 0;
    }
}

void pt_gtcap_set_aare_dlg(pt_uint8_t ac_ver, pt_uint8_t ac_val, pt_uint8_t result, pt_uint8_t diagnostic, gtcap_dlg_t *dlg)
{
    dlg->dlg_type = DLG_TYPE_AARE;

    dlg->e_ac_ver = ac_ver;
    dlg->e_ac_val = ac_val;
    dlg->e_result = result;
    dlg->e_diagnostic = diagnostic;

    dlg->user_info_flg = 0;
}

void pt_gtcap_set_abrt_dlg(pt_uint8_t abrt_src, pt_uint8_t *user_info, pt_uint16_t len, gtcap_dlg_t *dlg)
{
    dlg->dlg_type = DLG_TYPE_ABRT;

    dlg->t_abort_src = abrt_src;

    if (user_info != NULL)
    {
        dlg->user_info_flg = 1;
        dlg->user_info.info_len = len;
        memcpy(dlg->user_info.info, user_info, len);
    }
    else
    {
        dlg->user_info_flg = 0;
    }
}

pt_int32_t pt_gmap_encode_addr_num(map_addr_t *addr, void *buf, pt_int32_t pos)
{
    pt_uint16_t len;

    len = (addr->num+1)>>1;
    
    pos = pt_asn1_encode_v(len, addr->isdn, buf, pos);
    CHECK_RESULT(pos);
    
    return pos;
}

pt_int32_t pt_gmap_encode_addr_attribute(map_addr_t *addr, void *buf, pt_int32_t pos)
{
    pos = pt_asn1_encode_v(1, addr, buf, pos);
    CHECK_RESULT(pos);

    return pos;
}

pt_int32_t pt_gmap_encode_addr(map_addr_t *addr, void *buf, pt_int32_t pos)
{
    pos = pt_gmap_encode_addr_num(addr, buf, pos);
    CHECK_RESULT(pos);
    
    pos = pt_gmap_encode_addr_attribute(addr, buf, pos);
    CHECK_RESULT(pos);

    return pos;
}

pt_int32_t pt_gmap_encode_dpdu_open(map_dpdu_open_t *open, gtcap_user_info_t *user_info, pt_int32_t pos)
{
    pt_int32_t tmp;
    
    if (open->ais_info_flg && open->ais_info.vlrnum_flg)
    {
        tmp = pos;
        
        pos = pt_gmap_encode_addr(&open->ais_info.vlrnum, user_info->info, pos);
        CHECK_RESULT(pos);
        
        pos = pt_asn1_encode_tl(0x83, (pt_uint16_t)(tmp-pos), user_info->info, pos);
        CHECK_RESULT(pos);
    }

    if (open->ais_info_flg && open->ais_info.msisdn_flg)
    {
        tmp = pos;
        
        pos = pt_gmap_encode_addr(&open->ais_info.msisdn, user_info->info, pos);
        CHECK_RESULT(pos);
        
        pos = pt_asn1_encode_tl(0x82, (pt_uint16_t)(tmp-pos), user_info->info, pos);
        CHECK_RESULT(pos);
    }
    
    if (open->orig_ref_flg)
    {
        tmp = pos;
        
        pos = pt_gmap_encode_addr(&open->orig_ref, user_info->info, pos);
        CHECK_RESULT(pos);

        pos = pt_asn1_encode_tl(0x81, (pt_uint16_t)(tmp-pos), user_info->info, pos);
        CHECK_RESULT(pos);
    }

    if (open->dest_ref_flg)
    {
        tmp = pos;
        
        if (open->ais_imsi_flg)
        {
            pos = pt_gmap_encode_addr_num(&open->dest_ref, user_info->info, pos);
        }
        else
        {
            pos = pt_gmap_encode_addr(&open->dest_ref, user_info->info, pos);
        }
        CHECK_RESULT(pos);
        
        pos = pt_asn1_encode_tl(0x80, (pt_uint16_t)(tmp-pos), user_info->info, pos);
        CHECK_RESULT(pos);
    }

    return pos;
}

pt_int32_t pt_gmap_encode_dpdu(map_dpdu_t *dpdu, gtcap_user_info_t *user_info)
{
    pt_int32_t pos = INFO_MAX_LEN;
    pt_uint8_t direct_ref[7] = {4, 0, 0, 1, 1, 1, 1};

    switch (dpdu->type)
    {
        case MAP_DPDU_OPEN:
        {
            pos = pt_gmap_encode_dpdu_open(&dpdu->unit.open, user_info, pos);
            CHECK_RESULT(pos);
            break;
        }
        
        case MAP_DPDU_ACCEPT:
        case MAP_DPDU_CLOSE:
        {
            break;
        }
        
        case MAP_DPDU_REFUSE:
        {
            pos = pt_asn1_encode_tlv(0x0a, 1, &dpdu->unit.refuse, user_info->info, pos);
            CHECK_RESULT(pos);
            break;
        }
        
        case MAP_DPDU_UABORT:
        {
            if (dpdu->unit.uabort.type == DPDU_UABORT_RES_UNAV
                || dpdu->unit.uabort.type == DPDU_UABORT_APP)
            {
                pos = pt_asn1_encode_tlv(dpdu->unit.uabort.type, 1, 
                        &dpdu->unit.uabort.reason, user_info->info, pos);
            }
            else
            {
                pos = pt_asn1_encode_tl(dpdu->unit.uabort.type, 0,
                        user_info->info, pos);
            }
            CHECK_RESULT(pos);
            break;
        }
        
        case MAP_DPDU_PABORT:
        {
            pos = pt_asn1_encode_tlv(0x0a, 1, &dpdu->unit.pabort, user_info->info, pos);
            CHECK_RESULT(pos);
            break;
        }
        
        default:
        {
            return -1;
        }
    }
    
    if (g_sup_indef)
    {
        pos = pt_asn1_encode_tl_indef(dpdu->type, (pt_uint16_t)(INFO_MAX_LEN-pos), user_info->info, pos);
    }
    else
    {
        pos = pt_asn1_encode_tl(dpdu->type, (pt_uint16_t)(INFO_MAX_LEN-pos), user_info->info, pos);
    }
    CHECK_RESULT(pos);

    pos = pt_asn1_encode_tl(0xa0, (pt_uint16_t)(INFO_MAX_LEN-pos), user_info->info, pos);
    CHECK_RESULT(pos);

    pos = pt_asn1_encode_tlv(0x06, 7, direct_ref, user_info->info, pos);
    CHECK_RESULT(pos);
    
    if (g_sup_indef)
    {
        pos = pt_asn1_encode_tl_indef(0x28, (pt_uint16_t)(INFO_MAX_LEN-pos), user_info->info, pos);
    }
    else
    {
        pos = pt_asn1_encode_tl(0x28, (pt_uint16_t)(INFO_MAX_LEN-pos), user_info->info, pos);
    }
    CHECK_RESULT(pos);

    user_info->info_len = (pt_uint16_t)(INFO_MAX_LEN-pos);

    memmove(user_info->info, user_info->info+pos, user_info->info_len);
    
    return pos;
}

pt_int32_t pt_gmap_decode_addr_nature(void *buf, pt_int32_t pos, pt_uint16_t len, map_addr_t *addr)
{
	pos = pt_asn1_decode_v(buf, pos, len, addr);
    CHECK_RESULT(pos);

	return pos;
}

pt_int32_t pt_gmap_decode_addr_num(void *buf, pt_int32_t pos, pt_uint16_t len, map_addr_t *addr)
{
    pos = pt_asn1_decode_v(buf, pos, len, addr->isdn);
    CHECK_RESULT(pos);

    addr->num = (pt_uint8_t)(len*2);
    if ((addr->isdn[len-1]&0xf0) == 0xf0)
    {
        addr->num--;
    }
	return pos;
}
pt_int32_t pt_gmap_decode_addr(void *buf, pt_int32_t pos, pt_uint16_t len, map_addr_t *addr)
{
	pos = pt_gmap_decode_addr_nature(buf, pos, 1, addr);
	CHECK_RESULT(pos);
	len -= 1;
    pos = pt_gmap_decode_addr_num(buf, pos, len, addr);
    CHECK_RESULT(pos);

    return pos;
}

pt_int32_t pt_gmap_decode_dpdu_open(gtcap_user_info_t *user_info, pt_int32_t pos, void *dpdu_open)
{
    pt_uint8_t   tag;
    pt_uint16_t len;
    
    map_dpdu_open_t *open = (map_dpdu_open_t *)dpdu_open;

    if (pos<user_info->info_len && 0x80 == pt_asn1_code_tag(user_info->info + pos))
    {
        pos = pt_asn1_decode_tl(user_info->info, pos, &tag, &len);
        CHECK_RESULT(pos);

		if (1)
		{
        	pos = pt_gmap_decode_addr(user_info->info, pos, len, &open->dest_ref);
		}
		else
		{
			pos = pt_gmap_decode_addr_num(user_info->info, pos, len, &open->dest_ref);
			open->ais_imsi_flg = 1;
		}
        CHECK_RESULT(pos);
        
        open->dest_ref_flg = 1;
    }

    if (pos<user_info->info_len && 0x81 == pt_asn1_code_tag(user_info->info + pos))
    {
        pos = pt_asn1_decode_tl(user_info->info, pos, &tag, &len);
        CHECK_RESULT(pos);

        pos = pt_gmap_decode_addr(user_info->info, pos, len, &open->orig_ref);
        CHECK_RESULT(pos);

        open->orig_ref_flg = 1;
    }
	if (pos<user_info->info_len && 0x82 == pt_asn1_code_tag(user_info->info + pos))
	{
		pos = pt_asn1_decode_tl(user_info->info, pos, &tag, &len);
        CHECK_RESULT(pos);
		
        pos = pt_gmap_decode_addr(user_info->info, pos, len, &open->ais_info.msisdn);
        CHECK_RESULT(pos);
		
		open->ais_info.msisdn_flg = 1;
		open->ais_info_flg = 1;
	}
	if (pos<user_info->info_len && 0x83 == pt_asn1_code_tag(user_info->info + pos))
	{
		pos = pt_asn1_decode_tl(user_info->info, pos, &tag, &len);
        CHECK_RESULT(pos);
		
        pos = pt_gmap_decode_addr(user_info->info, pos, len, &open->ais_info.vlrnum);
        CHECK_RESULT(pos);
		
		open->ais_info.vlrnum_flg = 1;
		open->ais_info_flg = 1;
    }

    return pos;
}

pt_int32_t pt_gmap_decode_dpdu(gtcap_user_info_t *user_info, map_dpdu_t *dpdu)
{
    pt_int32_t pos;
    pt_uint8_t tag;
    pt_uint16_t len;
    
    pos = pt_asn1_decode_tl(user_info->info, 0, &tag, &len);
    CHECK_RESULT(pos);

    tag = pt_asn1_code_tag(user_info->info + pos);
    if (tag == 0x06)/*direct ref*/
    {
        pos = pt_asn1_decode_tl(user_info->info, pos, &tag, &len);
        CHECK_RESULT(pos);

        pos += len;
    }
    
    pos = pt_asn1_decode_tl(user_info->info, pos, &tag, &len);/*0xa0*/
    CHECK_RESULT(pos);

    pos = pt_asn1_decode_tl(user_info->info, pos, &tag, &len);
    CHECK_RESULT(pos);
    
    dpdu->type = tag;
    switch (dpdu->type)
    {
    case MAP_DPDU_OPEN:
        pos = pt_gmap_decode_dpdu_open(user_info, pos, &dpdu->unit.open);
        CHECK_RESULT(pos);
        break;

    case MAP_DPDU_ACCEPT:
    case MAP_DPDU_CLOSE:
        break;
    
    case MAP_DPDU_REFUSE:
    case MAP_DPDU_PABORT:
        pos = pt_asn1_decode_tlv(user_info->info, pos, &tag, &len, &dpdu->unit);
        CHECK_RESULT(pos);
        break;

    case MAP_DPDU_UABORT:
        tag = pt_asn1_code_tag(user_info->info + pos);
        if (tag == DPDU_UABORT_RES_UNAV || tag == DPDU_UABORT_APP)
        {
            pos = pt_asn1_decode_tlv(user_info->info, pos, 
                    &dpdu->unit.uabort.type, &len, &dpdu->unit.uabort.reason);
        }
        else
        {
            pos = pt_asn1_decode_tl(user_info->info, pos, 
                    &dpdu->unit.uabort.type, &len);
        }
        CHECK_RESULT(pos);
        break;

    default:
        return -1;
    }

    return pos;
}

