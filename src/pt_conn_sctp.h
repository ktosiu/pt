#ifndef _PT_SCTP_H
#define _PT_SCTP_H

st_netfd_t pt_sctp_open_instance(pt_conn_instance_t *instance);
void pt_sctp_up(pt_conn_tcb_t *tcb);
void pt_sctp_close(pt_conn_tcb_t *tcb);
void pt_sctp_connected(pt_conn_tcb_t *tcb);
void pt_sctp_accpeted(pt_conn_tcb_t *tcb);
pt_int32_t pt_sctp_sendmsg(pt_conn_tcb_t *tcb, pt_uint8_t *data, pt_uint32_t len);

#endif
