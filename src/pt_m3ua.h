#ifndef _PT_M3UA_H_
#define _PT_M3UA_H_
#include "pt_m3ua_define.h"


pt_int32_t pt_m3ua_encode(pt_uint8_t mc_mt, void *msg_struct, void *out, pt_uint16_t *len);
pt_int32_t pt_m3ua_decode(pt_uint8_t mc_mt, void *out, pt_uint16_t len, void *msg_struct);
pt_int32_t pt_m3ua_log(pt_char_t *str);

/*
 * m3ua api
 */
void *pt_m3ua_thread(void *arg);

ss7office_id_t pt_m3ua_add_ss7office(pt_uint32_t officeid, 
                        pt_uint8_t spc_type, pt_char_t *dpc, pt_char_t *opc);
m3ua_as_id_t pt_m3ua_add_as(ss7office_id_t ss7office_id,
                        m3ua_as_useage_e useage, pt_uint32_t n, pt_uint32_t mode, 
                        pt_uint8_t netapp_flag, pt_uint32_t netapp,
                        pt_uint8_t route_context_flag, pt_uint32_t route_context);
m3ua_asp_id_t pt_m3ua_add_asp(m3ua_as_id_t m3ua_as_id, 
                        pt_int32_t protocol, pt_int32_t service,
                        pt_char_t *local_ip, pt_uint16_t local_port,
                        pt_char_t *remote_ip, pt_uint16_t remote_port);

void pt_m3ua_dump();
typedef void (*_M3UA_UP_RECV)(m3ua_asp_t *, pt_uint8_t *, pt_int32_t);
void pt_m3ua_register_up(_M3UA_UP_RECV func);

m3ua_asp_t *pt_m3ua_obtain_overload_asp(pt_uint32_t officeid);
pt_int32_t pt_m3ua_send_data_to_conn(m3ua_asp_t *m3ua_asp, pt_uint8_t *in, pt_int32_t len);

#endif
