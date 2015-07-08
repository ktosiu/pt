#ifndef _PT_CONN_H
#define _PT_CONN_H

typedef void* pt_conn_id_t;

typedef enum
{
    PT_PROTOCOL_TCP  = 6,
    PT_PROTOCOL_SCTP = 132,
}pt_conn_protocol_e;

typedef enum
{
    PT_SERVICE_CLI = 1,
    PT_SERVICE_SRV,
}pt_conn_service_e;

typedef enum
{
    PT_STATUS_CLOSE,
    PT_STATUS_LISTENING,
    PT_STATUS_CONNECTING,
    PT_STATUS_ESTABLISHED,
}pt_conn_status_e;

#define PT_MAX_ADDR_NUM 4
typedef struct pt_conn_instance_s
{
    list_head_t             node;

    list_head_t             list_tcb;

    pt_conn_protocol_e      protocol;
    pt_conn_service_e       service;

    pt_int32_t              af;
    pt_socklen_t            addrlen;

    pt_uint32_t             local_addr_num;
    pt_sockaddr_storage_t   local_addr[PT_MAX_ADDR_NUM];

    st_netfd_t              st_nfd;
    st_thread_t             st_thread;
}pt_conn_instance_t;

typedef struct pt_conn_msg_data_s {
    pt_conn_id_t            conn_id;
    pt_int32_t              len;
    pt_uint8_t              *data;
}pt_conn_msg_data_t;

typedef struct pt_conn_msg_notify_s {
    pt_conn_id_t            conn_id;
    pt_conn_status_e        conn_status;
}pt_conn_msg_notify_t;

typedef enum {
    PT_CONN_MSG_NOTIFY,
    PT_CONN_MSG_DATA,
}pt_conn_msg_type_e;

typedef struct pt_conn_msg_s {
    pt_conn_msg_type_e          msg_type;
    union {
        pt_conn_id_t            msg_conn_id;
        pt_conn_msg_data_t      msg_data;
        pt_conn_msg_notify_t    msg_notify;
    }msg;
}pt_conn_msg_t;

typedef pt_int32_t (*_PT_HANDLE_DATA)(void *arg, pt_conn_msg_t *conn_msg);

typedef struct pt_conn_tcb_s
{
    list_head_t             node;

    pt_uint32_t             remote_addr_num;
    pt_sockaddr_storage_t   remote_addr[PT_MAX_ADDR_NUM];

    st_netfd_t              st_nfd;
    st_thread_t             st_thread;

    pt_uint32_t             sctp_ppid;
    sctp_assoc_t            sctp_assoc_id;
    pt_int32_t              sctp_status;
    pt_conn_status_e        sk_status;

    _PT_HANDLE_DATA         handle_data_func;
    void *                  handle_data_func_arg;

    /*load share seq*/
    pt_uint32_t             seq;

    /*attaching instance*/
    pt_conn_instance_t      *instance;
}pt_conn_tcb_t;

/*
 * sockaddr functions
 */
pt_uint16_t pt_addr_af(pt_sockaddr_storage_t *addr);
pt_char_t *pt_addr_a(pt_sockaddr_storage_t *addr);
void pt_addr_n(pt_uint16_t af, pt_char_t *src, pt_uint16_t port, pt_sockaddr_storage_t *sockaddr);
pt_bool_t pt_addr_eq(pt_sockaddr_storage_t *addr_src, pt_sockaddr_storage_t *addr_dst);
pt_int32_t pt_addr_ne(pt_sockaddr_storage_t *addr_src, pt_sockaddr_storage_t *add_dst);

#define PT_SCTP_PPID_M3UA  3
#define PT_SCTP_PPID_DIAM  46
typedef struct pt_conn_item_s
{
    pt_conn_protocol_e      protocol;
    pt_conn_service_e       service;

    pt_uint32_t             local_addr_num;
    pt_sockaddr_storage_t   local_addr[PT_MAX_ADDR_NUM];

    pt_uint32_t             remote_addr_num;
    pt_sockaddr_storage_t   remote_addr[PT_MAX_ADDR_NUM];

    pt_uint32_t             sctp_ppid;

    _PT_HANDLE_DATA         handle_data_func;
    void *                  handle_data_func_arg;
}pt_conn_item_t;

/*
 * conn api
 */
extern pt_conn_id_t pt_conn_add(pt_conn_item_t *conn);
extern void pt_conn_del(pt_conn_id_t conn_id);
extern pt_conn_status_e pt_conn_status(pt_conn_id_t conn_id);
extern pt_int32_t pt_conn_send(pt_conn_id_t conn_id, pt_uint32_t seq, pt_uint8_t *data, pt_uint32_t len);

#endif /*_PT_CONN_H*/

