#ifndef _PT_M3UA_DEFINE_H_
#define _PT_M3UA_DEFINE_H_

#define MAX_SS7_MSG 2048 

#define M3UA_RELEASE_ONE    1

/*Message Class&Message Type high 4bits-mc, low 4bits-mt*/
#define M3UA_MGMT_ERR       (pt_uint8_t)0x00
#define M3UA_MGMT_NTFY      (pt_uint8_t)0x01

#define M3UA_TRAN_DATA      (pt_uint8_t)0x11

#define M3UA_SSNM_DUNA      (pt_uint8_t)0x21
#define M3UA_SSNM_DAVA      (pt_uint8_t)0x22
#define M3UA_SSNM_DAUD      (pt_uint8_t)0x23
#define M3UA_SSNM_SCON      (pt_uint8_t)0x24
#define M3UA_SSNM_DUPU      (pt_uint8_t)0x25
#define M3UA_SSNM_DRST      (pt_uint8_t)0x26

#define M3UA_ASPSM_ASPUP    (pt_uint8_t)0x31
#define M3UA_ASPSM_ASPDN    (pt_uint8_t)0x32
#define M3UA_ASPSM_BEAT     (pt_uint8_t)0x33
#define M3UA_ASPSM_ASPUPACK (pt_uint8_t)0x34
#define M3UA_ASPSM_ASPDNACK (pt_uint8_t)0x35
#define M3UA_ASPSM_BEATACK  (pt_uint8_t)0x36

#define M3UA_ASPTM_ASPAC    (pt_uint8_t)0x41
#define M3UA_ASPTM_ASPIA    (pt_uint8_t)0x42
#define M3UA_ASPTM_ASPACACK (pt_uint8_t)0x43
#define M3UA_ASPTM_ASPIAACK (pt_uint8_t)0x44

#define M3UA_RKM_REGREQ     (pt_uint8_t)0x51
#define M3UA_RKM_REGRSP     (pt_uint8_t)0x52
#define M3UA_RKM_DEREGREQ   (pt_uint8_t)0x53
#define M3UA_RKM_DEREGRSP   (pt_uint8_t)0x54

// M3UA user type
#define M3UA_USER_NONE      (pt_uint8_t)0
#define M3UA_USER_SCCP      (pt_uint8_t)3
#define M3UA_USER_ISUP      (pt_uint8_t)5

typedef struct m3ua_common_header_tag
{
    pt_uint8_t   version;
    pt_uint8_t   reserved;
    pt_uint8_t   msg_class;
    pt_uint8_t   msg_type;
    pt_uint32_t  msg_len;
} m3ua_common_header_t;

#define M3UA_MAX_INFO       255
typedef struct m3ua_info_string_tag
{
    pt_uint16_t  num;
    pt_uint8_t   info[M3UA_MAX_INFO];
} m3ua_info_string_t;

typedef struct m3ua_pc_tag
{
    pt_uint8_t   mask;
    pt_uint8_t   pc[3];
} m3ua_pc_t;

#define M3UA_MAX_DATA MAX_SS7_MSG
typedef struct m3ua_protocol_data_tag
{
    m3ua_pc_t    opc;
    m3ua_pc_t    dpc;
    pt_uint8_t   si;
    pt_uint8_t   ni;
    pt_uint8_t   mp;
    pt_uint8_t   sls;
    pt_uint16_t  num;
    pt_uint8_t   data[M3UA_MAX_DATA];
} m3ua_protocol_data_t;

typedef struct m3ua_payload_data_tag
{
    pt_uint8_t              netapp_flg;
    pt_uint32_t             netapp;
    pt_uint8_t              route_context_flg;
    pt_uint32_t             route_context;
    m3ua_protocol_data_t    protocol_data;
    pt_uint8_t              correlation_id_flg;
    pt_uint32_t             correlation_id;
} m3ua_payload_data_t;

typedef struct m3ua_asp_up_tag
{
    pt_uint8_t             asp_identifier_flg;
    pt_uint32_t            asp_identifier;
    pt_uint8_t             info_string_flg;
    m3ua_info_string_t     info_string;
} m3ua_asp_up_t;

typedef struct m3ua_asp_up_ack_tag
{
    pt_uint8_t             info_string_flg;
    m3ua_info_string_t     info_string;
} m3ua_asp_up_ack_t;

typedef struct m3ua_asp_ac_tag
{
    pt_uint8_t             traffic_mode_flg;
    pt_uint32_t            traffic_mode;
    pt_uint8_t             route_context_flg;
    pt_uint32_t            route_context;
    pt_uint8_t             info_string_flg;
    m3ua_info_string_t     info_string;
} m3ua_asp_ac_t;

typedef struct m3ua_asp_ac_ack_tag
{
    pt_uint8_t             traffic_mode_flg;
    pt_uint32_t            traffic_mode;
    pt_uint8_t             route_context_flg;
    pt_uint32_t            route_context;
    pt_uint8_t             info_string_flg;
    m3ua_info_string_t     info_string;
} m3ua_asp_ac_ack_t;

#define M3UA_MAX_DIAG_INFO      255
typedef struct m3ua_diag_info_tag
{
    pt_uint8_t   num;
    pt_uint8_t   info[M3UA_MAX_INFO];
} m3ua_diag_info_t;

#define M3UA_MAX_PC             4
typedef struct m3ua_error_tag
{
    pt_uint32_t            error_code;
    pt_uint8_t             route_context_flg;
    pt_uint32_t            route_context;
    pt_uint8_t             info_string_flg;
    m3ua_info_string_t     info_string;
    pt_uint16_t            pc_num;
    m3ua_pc_t              pc[M3UA_MAX_PC];
    pt_uint8_t             netapp_flg;
    pt_uint32_t            netapp;
    pt_uint8_t             diag_info_flg;
    m3ua_diag_info_t       diag_info[M3UA_MAX_DIAG_INFO];
} m3ua_error_t;

/*inter struct*/
#define M3UA_PROTOCOL   3

typedef void* ss7office_id_t;
typedef void* m3ua_asp_id_t;
typedef void* m3ua_as_id_t;

typedef enum {
    SS7OFFICE_INACTIVE,
    SS7OFFICE_ACTIVE
}ss7office_status_e;

typedef struct {
    list_head_t         node;
    pt_uint32_t         officeid;
    pt_uint8_t          spc_type;
    pt_uint8_t          dpc[3];
    pt_uint8_t          opc[3];

    ss7office_status_e  office_status;

    list_head_t         list_m3ua_as;
}ss7office_t;

typedef enum {
	M3UA_AS_DOWN,
	M3UA_AS_IA,
	M3UA_AS_AC,     
	M3UA_AS_PENDING
}m3ua_as_status_e;

typedef enum {
    M3UA_AS_CLIENT = 1,
    M3UA_AS_SERVER
}m3ua_as_useage_e;

#define M3UA_TRAFFIC_OVERLOAD  1
#define M3UA_TRAFFIC_LOADSHARE 2 
#define M3UA_TRAFFIC_BROADCAST 3
typedef struct {
    list_head_t         node;
    m3ua_as_useage_e    useage;
    pt_uint32_t         n;
    pt_uint32_t         mode;
    pt_uint8_t          netapp_flag;
    pt_uint32_t         netapp;
    pt_uint8_t          route_context_flag;
    pt_uint32_t         route_context;
    m3ua_as_status_e    as_status;

    ss7office_t         *ss7office;
    
    list_head_t         list_m3ua_asp;
}m3ua_as_t;

typedef enum {
	M3UA_ASP_DOWN,
	M3UA_ASP_WAIT_IA,
	M3UA_ASP_IA,     
	M3UA_ASP_WAIT_AC,
	M3UA_ASP_AC     
}m3ua_asp_status_e;

typedef struct {
    list_head_t         node;
    pt_conn_item_t      conn_item;

    pt_conn_id_t        conn_id;
    pt_conn_status_e    conn_status;
    m3ua_asp_status_e   asp_status;

    m3ua_as_t           *m3ua_as;

    /*msg loadshare seq*/
    pt_uint32_t         seq;

    /*statistic*/
    pt_uint64_t         stat_recv;
    pt_uint64_t         stat_send; 
}m3ua_asp_t;

#endif

