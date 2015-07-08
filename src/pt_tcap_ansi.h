#ifndef _CTCAP_CODE_H_
#define _CTCAP_CODE_H_

#define       UNI_TAG_TYPE         0xe1   
#define       QRY_WITH_TAG_TYPE    0xe2   
#define       QRY_WITHOUT_TAG_TYPE 0xe3   
#define       RES_TAG_TYPE         0xe4  
#define       CON_WITH_TAG_TYPE    0xe5   
#define       CON_WITHOUT_TAG_TYPE 0xe6
#define       ABORT_TAG_TYPE       0xf6

typedef struct ctcap_tran_id_tag
{
    pt_uint8_t id[4];
} ctcap_tran_id_t;

#define CTCAP_MAX_DATA          (10 * 1024)

#define CCOMP_TYPE_INVOKE   0xe9
#define CCOMP_TYPE_RESULT   0xea
#define CCOMP_TYPE_ERROR    0xeb
#define CCOMP_TYPE_REJECT   0xec
typedef struct ctcap_comp_tag
{
    pt_uint32_t       comp_type;

    pt_uint8_t        comp_id;

    union {
        struct {
            pt_uint8_t op_code;
        }invoke;

        struct {
            pt_uint8_t resv;
        }response;

        struct {
            pt_uint8_t error_code;
        }error;

        struct {
            pt_uint8_t problem_code;
        }reject;
    }type;

#define i_op_code type.invoke.op_code
#define e_error_code type.error.error_code
#define u_comp_type type.invoke.op_code         // express each of types
    pt_uint16_t      para_len;
    pt_uint8_t       para[CTCAP_MAX_DATA];
} ctcap_comp_t;

typedef struct ctcap_unidir_tag
{
    ctcap_comp_t        comp;
}ctcap_unidir_t;

typedef struct ctcap_query_tag
{
    ctcap_tran_id_t     orig_id;

    ctcap_comp_t        comp;
} ctcap_query_t;

typedef struct ctcap_response_tag
{
    ctcap_tran_id_t     dest_id;

    ctcap_comp_t        comp;
} ctcap_response_t;

typedef struct ctcap_cont_tag
{
    ctcap_tran_id_t     orig_id;
    ctcap_tran_id_t     dest_id;

    ctcap_comp_t        comp;
} ctcap_cont_t;

#define C_P_ABORT       0xd7
#define C_U_ABORT       0xd8
typedef struct ctcap_abort_tag
{
    ctcap_tran_id_t     dest_id;

    pt_uint32_t         abort_type;
    pt_uint8_t          abort_cause;
}ctcap_abort_t;

#define CTCAP_UNIDIR_TYPE       0
#define CTCAP_BEGIN_TYPE        1
#define CTCAP_END_TYPE          2
#define CTCAP_CONT_TYPE         3
#define CTCAP_ABORT_TYPE        4
#define CTCAP_UNKNOWN_TYPE		0xFF

#ifdef __cplusplus
extern "C" {
#endif

pt_int32_t pt_ctcap_encode(pt_uint32_t type, void *msg_struct, void *out, pt_int32_t *len);
pt_int32_t pt_ctcap_decode(pt_uint32_t type, void *in, pt_int32_t len, void *msg_struct);

void pt_ctcap_set_invoke_comp(pt_uint8_t comp_id, pt_uint8_t op_code, pt_uint8_t *para, pt_int32_t len, ctcap_comp_t *comp);
void pt_ctcap_set_result_comp(pt_uint8_t comp_id, pt_uint8_t *para, pt_int32_t len, ctcap_comp_t *comp);
void pt_ctcap_set_error_comp(pt_uint8_t comp_id, pt_uint8_t error_code, pt_uint8_t *para, pt_int32_t len, ctcap_comp_t *comp);

#ifdef __cplusplus
};
#endif

#endif

