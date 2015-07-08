#ifndef _PT_TCP_H
#define _PT_TCP_H

st_netfd_t pt_tcp_open_instance(pt_conn_instance_t *instance);
void pt_tcp_close(pt_conn_tcb_t *tcb);
void pt_tcp_connected(pt_conn_tcb_t *tcb);
void pt_tcp_accpeted(pt_conn_tcb_t *tcb);
pt_int32_t pt_tcp_sendmsg(pt_conn_tcb_t *tcb, pt_uint8_t *data, pt_uint32_t len);

#endif

