#ifndef _GTCAP_CODE_H_
#define _GTCAP_CODE_H_

/*消息类型标签*/
#define       GTCAP_UNI_TAG_TYPE				(pt_uint8_t)0x61   /*01100001*/
#define       GTCAP_BEGIN_TAG_TYPE				(pt_uint8_t)0x62   /*01100010*/
#define       GTCAP_END_TAG_TYPE				(pt_uint8_t)0x64   /*01100100*/
#define       GTCAP_CONTINUE_TAG_TYPE			(pt_uint8_t)0x65   /*01100101*/
#define       GTCAP_ABORT_TAG_TYPE				(pt_uint8_t)0x67   /*01100111*/

typedef struct gtcap_tran_id_tag
{
    pt_uint8_t len;
    pt_uint8_t id[4];
} gtcap_tran_id_t;

#define GTCAP_MAX_DATA          MAX_SS7_MSG

#define GCOMP_TYPE_INVOKE       0xa1
#define GCOMP_TYPE_RESULT       0xa2
#define GCOMP_TYPE_ERROR        0xa3
#define GCOMP_TYPE_REJECT       0xa4
#define GCOMP_TYPE_RESULT_NL    0xa7
typedef struct gtcap_comp_tag
{
    pt_uint8_t comp_type;
    
    pt_uint8_t invoke_id;

    union {
        struct {
            pt_uint8_t link_id_flg;
            pt_uint8_t link_id;

            pt_uint8_t op_code;
        }invoke;
        
        struct {
            pt_uint8_t op_code_flg;
            pt_uint8_t op_code;
        }result;

        struct {
            pt_uint8_t error_code;
        }error;

        struct {
            pt_uint8_t problem_code;
        }reject;
    }type;

#define i_link_id_flg type.invoke.link_id_flg
#define i_link_id type.invoke.link_id
#define i_op_code type.invoke.op_code
#define r_op_code_flg type.result.op_code_flg
#define r_op_code type.result.op_code
#define e_error_code type.error.error_code
#define j_problem_code type.reject.problem_code

    pt_uint16_t para_len;
    pt_uint8_t para[GTCAP_MAX_DATA];
} gtcap_comp_t;

#define INFO_MAX_LEN    231
typedef struct gtcap_user_info_tag
{
    pt_uint16_t              info_len;
    pt_uint8_t                info[INFO_MAX_LEN];
}gtcap_user_info_t;

#define DLG_TYPE_AARQ           0x60
#define DLG_TYPE_AARE           0x61
#define DLG_TYPE_ABRT           0x64
/*diagnostic*/
#define USER_NULL               0
#define USER_NO_REASON_GIVE     1
#define USER_AC_NOT_SUPPORT     2
#define PROVIDER_NULL           0
#define PROVIDER_NO_REASON_GIVE 1
#define PROVIDER_NO_COMMON_DLG  2
/*result*/
#define RESULT_ACCEPTED         0
#define RESULT_REJECT_PERMANENT 1
typedef struct gtcap_dlg_tag
{
    pt_uint8_t dlg_type;

    union {
        struct {
            pt_uint8_t ac_version;
            pt_uint8_t ac_value;
        }aarq;

        struct {
            pt_uint8_t ac_version;
            pt_uint8_t ac_value;
            
            pt_uint8_t result;
            pt_uint8_t diagnostic;
        }aare;

        struct {
            pt_uint8_t abort_src;
        }abrt;
    }type;

#define q_ac_ver type.aarq.ac_version
#define q_ac_val type.aarq.ac_value
#define e_ac_ver type.aare.ac_version
#define e_ac_val type.aare.ac_value
#define e_result type.aare.result
#define e_diagnostic type.aare.diagnostic
#define t_abort_src type.abrt.abort_src

    pt_uint8_t          user_info_flg;
    gtcap_user_info_t   user_info;
} gtcap_dlg_t;

typedef struct gtcap_begin_tag
{
    gtcap_tran_id_t     orig_id;

    pt_uint8_t          dlg_flg;
    gtcap_dlg_t         dlg;

    pt_uint8_t          comp_flg;
    gtcap_comp_t        comp;

	pt_uint8_t		    comp_ex_flg;
	gtcap_comp_t        comp_ex;
} gtcap_begin_t;

typedef struct gtcap_end_tag
{
    gtcap_tran_id_t     dest_id;

    pt_uint8_t          dlg_flg;
    gtcap_dlg_t         dlg;

    pt_uint8_t          comp_flg;
    gtcap_comp_t        comp;

	pt_uint8_t		    comp_ex_flg;
	gtcap_comp_t        comp_ex;
} gtcap_end_t;


typedef struct gtcap_cont_tag
{
    gtcap_tran_id_t     orig_id;
    gtcap_tran_id_t     dest_id;

    pt_uint8_t          dlg_flg;
    gtcap_dlg_t         dlg;

    pt_uint8_t          comp_flg;
    gtcap_comp_t        comp;

	pt_uint8_t			comp_ex_flg;
	gtcap_comp_t        comp_ex;
} gtcap_cont_t;

typedef struct gtcap_abort_tag
{
    gtcap_tran_id_t     dest_id;

    pt_uint8_t          p_abort_cause_flg;
    pt_uint8_t          p_abort_cause;

    pt_uint8_t          dlg_flg;
    gtcap_dlg_t         dlg;
}gtcap_abort_t;

typedef struct {
    pt_uint8_t m_type;

    union {
        gtcap_begin_t   begin;
        gtcap_end_t     end;
        gtcap_cont_t    cont;
        gtcap_abort_t   abort;
    }msg;

#define m_begin msg.begin
#define m_end msg.end
#define m_cont msg.cont
#define m_abort msg.abort

}gtcap_msg_t;

#define GTCAP_BEGIN_TYPE        0
#define GTCAP_END_TYPE          1
#define GTCAP_CONT_TYPE         2
#define GTCAP_ABORT_TYPE        3
#define GTCAP_UNKNOWN_TYPE		0xFF

#ifdef __cplusplus
extern "C" {
#endif
    pt_int32_t pt_gtcap_decode_comp_item(void *buf, pt_int32_t pos, gtcap_comp_t *comp);
    pt_int32_t pt_gtcap_encode(gtcap_msg_t *gtcap_msg, void *out, pt_uint16_t *len);
    pt_int32_t pt_gtcap_decode(void *in, pt_uint16_t len, gtcap_msg_t *gtcap_msg);

	void pt_gtcap_set_invoke_comp(pt_uint8_t invk_id, pt_uint8_t op_code, pt_uint8_t *para, pt_uint16_t len, gtcap_comp_t *comp);
	void pt_gtcap_set_result_comp(pt_uint8_t invk_id, pt_uint8_t op_code, pt_uint8_t *para, pt_uint16_t len, gtcap_comp_t *comp);
	void pt_gtcap_set_error_comp(pt_uint8_t invk_id, pt_uint8_t error_code, pt_uint8_t *para, pt_uint16_t len, gtcap_comp_t *comp);
	void pt_gtcap_set_aarq_dlg(pt_uint8_t ac_ver, pt_uint8_t ac_val, pt_uint8_t *user_info, pt_uint16_t len, gtcap_dlg_t *dlg);
	void pt_gtcap_set_aare_dlg(pt_uint8_t ac_ver, pt_uint8_t ac_val, pt_uint8_t result, pt_uint8_t diagnostic, gtcap_dlg_t *dlg);
	void pt_gtcap_set_abrt_dlg(pt_uint8_t abrt_src, pt_uint8_t *user_info, pt_uint16_t len, gtcap_dlg_t *dlg);

#ifdef __cplusplus
};
#endif

#define mAddrStrLen_M 19

typedef struct map_addr_tag
{
	pt_uint8_t    num_plan    :4;
	pt_uint8_t    nature      :3;
	pt_uint8_t    ext         :1;
    
	pt_uint8_t	num;
	pt_uint8_t	isdn[mAddrStrLen_M];
}map_addr_t;

typedef struct {
    pt_uint8_t  msisdn_flg;
    map_addr_t  msisdn;            /*CHI MSISDN*/ /*ENG MSISDN*/
    pt_uint8_t  vlrnum_flg;
    map_addr_t  vlrnum;
}ais_info_t;

typedef struct map_dpdu_open_tag
{
    pt_uint8_t  dest_ref_flg;
    map_addr_t  dest_ref;

    pt_uint8_t  orig_ref_flg;
    map_addr_t  orig_ref;

    /*AIS USSD*/
    pt_uint8_t  ais_imsi_flg;
    pt_uint8_t  ais_info_flg;
    ais_info_t  ais_info;
}map_dpdu_open_t;

#define DPDU_UABORT_SPEC        0x80
#define DPDU_UABORT_RES_LIMIT   0x81
#define DPDU_UABORT_RES_UNAV    0x82
#define DPDU_UABORT_APP         0x83
typedef struct map_dpdu_uabort_tag
{
    pt_uint8_t        type;
    pt_uint8_t        reason;
}map_dpdu_uabort_t;

#define MAP_DPDU_OPEN   0xa0
#define MAP_DPDU_ACCEPT 0xa1
#define MAP_DPDU_CLOSE  0xa2
#define MAP_DPDU_REFUSE 0xa3
#define MAP_DPDU_UABORT 0xa4
#define MAP_DPDU_PABORT 0xa5

#define NO_REA_GIVEN    0
#define INVALID_DES_REF 1
#define INVALID_ORI_REF 2
typedef struct map_dpdu_tag
{
    pt_uint8_t        type;
    union {
        map_dpdu_open_t     open;
        pt_uint8_t          accept;
        pt_uint8_t          close;
        pt_uint8_t          refuse;
        map_dpdu_uabort_t   uabort;
        pt_uint8_t          pabort;
    }unit;
    
#define m_open unit.open
#define m_accept unit.accept
#define m_close unit.close
#define m_refuse unit.refuse
#define m_uabort unit.uabort
#define m_pabort unit.pabort

}map_dpdu_t;
#ifdef __cplusplus
extern "C" {
#endif

pt_int32_t pt_map_encode_dpdu(map_dpdu_t *dpdu, gtcap_user_info_t *user_info);
pt_int32_t pt_map_decode_dpdu(gtcap_user_info_t *user_info, map_dpdu_t *dpdu);

#ifdef __cplusplus
};
#endif

#endif

