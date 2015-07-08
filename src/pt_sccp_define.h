#ifndef _PT_SCCP_DEFINE_H_
#define _PT_SCCP_DEFINE_H_

/****************************ITU 713***************************/

#define SCCP_XUDT_LEN       220

#define SCCP_MSG_UDT        0x09
#define SCCP_MSG_XUDT       0x11

#define SCCP_SCMG_SSA       1
#define SCCP_SCMG_SSP       2
#define SCCP_SCMG_SST       3
#define SCCP_SCMG_SOR       4
#define SCCP_SCMG_SOG       5
#define SCCP_SCMG_SSC       6

#define SCCP_MAX_UDT        255
#define SCCP_MAX_UDTS       255
#define SCCP_MAX_XUDT       254
#define SCCP_MAX_XUDTS      254

typedef pt_uint8_t   sccp_ref_t[3];
typedef pt_uint8_t   sccp_spc_t[3];

typedef struct
{
    pt_uint8_t      low  : 4;
    pt_uint8_t      high : 4;
} byte_addr;

#define SCCP_CODE_NUMBER    11
typedef byte_addr sccp_gt_code[SCCP_CODE_NUMBER];

typedef struct sccp_gt1_tag
{
    pt_uint8_t            tag_addr : 7;
    pt_uint8_t            tag_oe   : 1;
    sccp_gt_code          code;
} sccp_gt1_t;

typedef struct sccp_gt2_tag
{
    pt_uint8_t            trans_type;
    sccp_gt_code    code;
} sccp_gt2_t;

typedef struct sccp_gt3_tag
{
    pt_uint8_t            trans_type;
    pt_uint8_t            code_design  : 4;
    pt_uint8_t            code_plan    : 4;
    sccp_gt_code    code;
} sccp_gt3_t;

typedef struct
{
    pt_uint8_t            trans_type;
    pt_uint8_t            code_design : 4;
    pt_uint8_t            code_plan   : 4;
    pt_uint8_t            tag_addr    : 7;
    pt_uint8_t            free        : 1;
    sccp_gt_code          code;
} sccp_gt4_t;

typedef struct sccp_address_tag
{
    pt_uint8_t            tag_spc   : 1;
    pt_uint8_t            tag_ssn   : 1;
    pt_uint8_t            tag_gt    : 4;
    pt_uint8_t            tag_route : 1;
    pt_uint8_t            spare     : 1;

    sccp_spc_t            dpc;
    pt_uint8_t            ssn;
    union
    {
        sccp_gt1_t    gt1;
        sccp_gt2_t    gt2;
        sccp_gt3_t    gt3;
        sccp_gt4_t    gt4;
    } gt;
} sccp_address_t;

typedef struct sccp_segment_tag
{
    pt_uint8_t        remain_segment  : 4;
    pt_uint8_t        free            : 2;
    pt_uint8_t        sequence_option : 1;
    pt_uint8_t        first_ind       : 1;
    sccp_ref_t        reference ;
} sccp_segment_t;

typedef struct sccp_scmg_tag
{
    pt_uint8_t        scmg_type;
    pt_uint8_t        ssn;
    sccp_spc_t        dpc;
    pt_uint8_t        smi;
    pt_uint8_t        cong_level;
} sccp_scmg_t;

typedef struct sccp_udt_tag
{
    pt_uint8_t            msg_type;
    pt_uint8_t            protocol_type : 4;
    pt_uint8_t            return_opt    : 4;
    sccp_address_t        cda;
    sccp_address_t        cga;
    pt_uint8_t            tag;
    pt_uint8_t            len_ud;
    union
    {
        pt_uint8_t        ud[SCCP_MAX_UDT];
        sccp_scmg_t       scmg;
    } data;
} sccp_udt_t;

typedef struct sccp_udts_tag
{
    pt_uint8_t            msg_type;
    pt_uint8_t            return_reason;
    sccp_address_t        cda;
    sccp_address_t        cga;
    pt_uint8_t            len_ud;
    pt_uint8_t            ud[SCCP_MAX_UDTS];
} sccp_udts_t;

typedef struct sccp_xudt_tag
{
    pt_uint8_t            msg_type;
    pt_uint8_t            protocol_type : 4;
    pt_uint8_t            return_opt    : 4;
    pt_uint8_t            hop_counter;
    sccp_address_t        cda;
    sccp_address_t        cga;
    pt_uint8_t            tag_segment;
    sccp_segment_t        segment;
    pt_uint8_t            tag;
    pt_uint8_t            len_ud;
    union
    {
        pt_uint8_t        ud[SCCP_MAX_XUDT];
        sccp_scmg_t       scmg;
    } data;
} sccp_xudt_t;

typedef struct sccp_xudts_tag
{
    pt_uint8_t            msg_type;
    pt_uint8_t            return_reason;
    pt_uint8_t            ucPriority;
    pt_uint8_t            hop_counter;
    sccp_address_t        cda;
    sccp_address_t        cga;
    pt_uint8_t            tag_segment;
    sccp_segment_t        segment;
    pt_uint8_t            len_ud;
    pt_uint8_t            ud[SCCP_MAX_XUDTS];
} sccp_xudts_t;

typedef union
{
    sccp_udt_t      udt;
    sccp_udts_t     udts;
    sccp_xudt_t     xudt;
    sccp_xudts_t    xudts;
} sccp_msg_u;

#define SCCP_MAX_DATA MAX_SS7_MSG
typedef struct xudt_buf_tag
{
    st_utime_t      time;
    list_head_t     node;

    sccp_ref_t      sccp_ref;

    pt_int32_t      data_len;
    pt_uint8_t      data[SCCP_MAX_DATA];
} xudt_buf_t;

typedef struct
{
    sccp_address_t  cda;
    sccp_address_t  cga;

    pt_int32_t      data_len;
    pt_uint8_t      *pdata;
} sccp_up_msg_t;

#endif

