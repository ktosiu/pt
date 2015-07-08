#ifndef _DIAM_DEFINE_H_
#define _DIAM_DEFINE_H_

typedef void* diam_link_id_t;
typedef void* diam_conn_id_t;

#define DIM_RETURN_OK       (pt_uint32_t)2001

#define DIM_VENDOR_BASE         (pt_uint32_t)0
#define DIM_VENDOR_ZTE          (pt_uint32_t)3902
#define DIM_VENDOR_3GPP         (pt_uint32_t)10415
#define DIM_VENDOR_HUAWEI       (pt_uint32_t)2011
#define DIM_VENDOR_CT           (pt_uint32_t)81000
#define DIM_VENDOR_ETSI         (pt_uint32_t)13019
#define DIM_VENDOR_WiMAX        (pt_uint32_t)24757

#define DIM_APPID_BASE          (pt_uint32_t)0
#define DIM_APPID_3GPP_R5_CxDx  (pt_uint32_t)16777216
#define DIM_APPID_3GPP_R5_Sh    (pt_uint32_t)16777217
#define DIM_APPID_3GPP_R5_Gq    (pt_uint32_t)16777222
#define DIM_APPID_3GPP_R6_Rf    (pt_uint32_t)3
#define DIM_APPID_E2            (pt_uint32_t)16777231
#define DIM_APPID_E4            (pt_uint32_t)16777231
#define DIM_APPID_SP            (pt_uint32_t)16777231
#define DIM_APPID_SPNew         (pt_uint32_t)16777232
#define DIM_APPID_RELAY         (pt_uint32_t)0xffffffff

#define DIM_DW_INTERVAL         300
#define DIM_CE_INTERVAL         50

#define DIM_HDR_LEN             20
#define DIM_MAX_AVP_DATA_LEN	1024

typedef enum
{
    AVP_FORMAT_UTF8STRING = 1,
    AVP_FORMAT_INTEGER32,
    AVP_FORMAT_INTEGER64,
    AVP_FORMAT_UNINTEGER32,
    AVP_FORMAT_UNINTEGER64,
    AVP_FORMAT_FLOAT32,
    AVP_FORMAT_FLOAT64,
    AVP_FORMAT_GROUPS,
    AVP_FORMAT_ADDRESS,
    AVP_FORMAT_OCTERSTRING,
} avp_format_e;

typedef struct avp_address_tag
{
    pt_uint16_t  family;
    union
    {
        pt_uint32_t  ipv4;
        pt_uint8_t    ipv6[16];
    } ip;
} avp_address_t;

typedef struct avp_binary_tag
{
    pt_uint32_t   len;
    pt_uint8_t    data[DIM_MAX_AVP_DATA_LEN];
} avp_binary_t;

typedef struct avp_data_tag
{
    avp_format_e format;
    union
    {
        pt_char_t    octet_string[128];
        pt_int32_t integer32;
        pt_int32_t integer64[2];
        pt_uint32_t  unsigned32;
        pt_uint32_t  unsigned64[2];
        pt_float_t   float32;
        pt_double_t  float64;
        list_head_t groups;
        avp_address_t address;
        avp_binary_t binary;
    } value;
} avp_data_t;

#define DIAM_COM_CMD_AS     274u
#define DIAM_COM_CMD_AC     271u
#define DIAM_COM_CMD_CE     257u
#define DIAM_COM_CMD_DW     280u
#define DIAM_COM_CMD_DP     282u
#define DIAM_COM_CMD_RA     258u
#define DIAM_COM_CMD_ST     275u

#define DIAM_CMD_FLG_NULL   0x00
#define DIAM_CMD_FLG_R      0x80
#define DIAM_CMD_FLG_P      0x40
#define DIAM_CMD_FLG_E      0x20
#define DIAM_CMD_FLG_T      0x10
typedef struct diam_head_tag
{
    pt_uint32_t  version : 8;
    pt_uint32_t  msg_len : 24;
    pt_uint32_t  cmd_flg : 8;
    pt_uint32_t  cmd_code: 24;
    pt_uint32_t  app_id;
    pt_uint32_t  h_by_h_id;
    pt_uint32_t  e_to_e_id;
} diam_head_t;

typedef struct diam_msg_tag
{
    diam_head_t diam_head;
    list_head_t avps;
} diam_msg_t;

#define AVP_FLAG_NULL  0x00
#define AVP_FLAG_V     0x80
#define AVP_FLAG_M     0x40
#define AVP_FLAG_P     0x20
typedef struct avp_head_tag
{
    pt_uint32_t  avp_code;
    pt_uint32_t  avp_flg : 8;
    pt_uint32_t  avp_len : 24;
    pt_uint32_t  vendor_id;
} avp_head_t;

typedef struct avp_tag
{
    avp_head_t avp_head;
    avp_data_t data;
} avp_t;

typedef struct diam_buf_tag
{
    list_head_t   list;
    avp_t         avp;
} diam_buf_t;


#define DIAM_MAX_LEVEL 5
typedef struct {
    pt_uint32_t tag_num;
    pt_uint32_t tag[DIAM_MAX_LEVEL];
    pt_uint32_t tag_pos[DIAM_MAX_LEVEL];

    /*通过API获取tag在码流中的位置*/
    pt_int32_t  code_pos[DIAM_MAX_LEVEL];
} diam_condition_t;


typedef struct diam_cfg_info_tag
{
    pt_char_t       local_host_name[128];
    pt_char_t       local_realm[128];

    pt_char_t       remote_host_name[128];
    pt_char_t       remote_realm[128];
} diam_info_t;

typedef enum 
{
    DIAM_CLOSED,
    DIAM_OPEN,
}diam_link_status_e;


#define DIAM_MAX_NAME_LEN     128
#define DIAM_MAX_REALM_LEN    128
typedef struct diam_link_tag
{
    list_head_t         node;
    
    pt_uint32_t         link_id;

    diam_info_t         diam_info;
    
    list_head_t         list_conn;
} diam_link_t;

typedef struct diam_bear_info_tag
{
    list_head_t         node;
    pt_conn_item_t      conn_item;

    pt_conn_id_t        conn_id;
    pt_conn_status_e    conn_status;
    diam_link_status_e  link_status;

    diam_link_t         *diam_link;

    /*sctp时消息流负荷分担*/
    pt_uint32_t         seq;

    /*CER/DWR计次*/
    pt_int32_t          time; /*多少个100ms*/

    /*statistic*/
    pt_uint64_t         stat_recv;
    pt_uint64_t         stat_send;
} diam_conn_t;

#endif

