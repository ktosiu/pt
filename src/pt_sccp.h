#ifndef _PT_SCCP_H_
#define _PT_SCCP_H_
#include "pt_sccp_define.h"

pt_int32_t pt_sccp_encode(m3ua_asp_t *m3ua_asp, void *msg_struct, void *out, pt_uint16_t *len);
pt_int32_t pt_sccp_decode(m3ua_asp_t *m3ua_asp, void *in, pt_uint16_t len, void *msg_struct);

/* sccp api */
pt_uint8_t pt_sccp_get_sls(void);
void pt_sccp_make_address(pt_uint8_t gtcode[11], pt_uint8_t ssn, sccp_address_t *gt);
pt_int32_t pt_sccp_send_data_to_m3ua(m3ua_asp_t *m3ua_asp, sccp_up_msg_t *up_msg);

typedef void (*_SCCP_UP_RECV)(m3ua_asp_t *, sccp_up_msg_t *up_msg);
void pt_sccp_register_up(_SCCP_UP_RECV func);
void *pt_sccp_thread(void *arg);

#endif

