#ifndef _DIAM_H_
#define _DIAM_H_
#include "pt_diam_define.h"

/*diam_protocol.c*/
void pt_diam_prn_msg(diam_msg_t *msg);
pt_int32_t pt_diam_add_avp_str(list_head_t *avps, pt_uint32_t avp_code, pt_uint8_t avp_flg, pt_char_t *str);
pt_int32_t pt_diam_add_avp_addr(list_head_t *avps, pt_uint32_t avp_code, pt_uint8_t avp_flg, pt_char_t *ip);
pt_int32_t pt_diam_add_avp_uint32(list_head_t *avps, pt_uint32_t avp_code, pt_uint8_t avp_flg, pt_uint32_t uint32);
pt_int32_t pt_diam_add_avp_groups(list_head_t *avps, pt_uint32_t avp_code, pt_uint8_t avp_flg, list_head_t **groups);
pt_int32_t pt_diam_del_avps(list_head_t *avps);

pt_uint8_t pt_diam_get_cmd_ver(pt_uint8_t *code, pt_int32_t len);
pt_int32_t pt_diam_get_cmd_len(pt_uint8_t *code, pt_int32_t len);
pt_uint8_t pt_diam_get_cmd_flg(pt_uint8_t *code, pt_int32_t len);
pt_bool_t pt_diam_get_cmd_flg_R(pt_uint8_t *code, pt_int32_t len);
pt_bool_t pt_diam_get_cmd_flg_P(pt_uint8_t *code, pt_int32_t len);
pt_bool_t pt_diam_get_cmd_flg_E(pt_uint8_t *code, pt_int32_t len);
pt_bool_t pt_diam_get_cmd_flg_T(pt_uint8_t *code, pt_int32_t len);
pt_uint32_t pt_diam_get_cmd_code(pt_uint8_t *code, pt_int32_t len);
pt_uint32_t pt_diam_get_cmd_appid(pt_uint8_t *code, pt_int32_t len);
pt_uint32_t pt_diam_get_cmd_hopbyhop(pt_uint8_t *code, pt_int32_t len);
pt_uint32_t pt_diam_get_cmd_endtoend(pt_uint8_t *code, pt_int32_t len);
pt_uint8_t *pt_diam_get_cmd_data(pt_uint8_t *code, pt_int32_t len);
pt_int32_t pt_diam_get_cmd_data_len(pt_uint8_t *code, pt_int32_t len);
void pt_diam_set_cmd_hopbyhop(pt_uint8_t *code, pt_int32_t len, pt_uint32_t hopbyhop);
void pt_diam_set_cmd_endtoend(pt_uint8_t *code, pt_int32_t len, pt_uint32_t endtoend);

pt_uint8_t *pt_diam_get_avp_data(pt_uint8_t *code, pt_int32_t pos);
pt_int32_t pt_diam_get_avp_data_len(pt_uint8_t *code, pt_int32_t pos);
pt_int32_t pt_diam_get_avp_pos_from_cmd_data(pt_uint8_t *cmd_data, pt_int32_t cmd_len, pt_uint32_t avp_code, pt_uint32_t avp_position);

pt_int32_t pt_diam_del_avp(pt_uint8_t *code, pt_int32_t *len, avp_condition_t *avp_condition);
pt_int32_t pt_diam_get_avp_pos(pt_uint8_t *code, pt_int32_t len, avp_condition_t *avp_condition);
pt_int32_t pt_diam_set_avp_data(pt_uint8_t *code, pt_int32_t *len, avp_condition_t *avp_condition, void *avp_value, pt_int32_t avp_value_len);

/*diam_link.c*/
diam_conn_t *pt_diam_obtain_overload_conn(pt_uint32_t link_id);
pt_int32_t pt_diam_send_data_to_conn(diam_conn_t *diam_conn, pt_uint8_t *in, pt_int32_t len);
void pt_diam_dump(void);
void *pt_diam_thread(void *arg);

diam_conn_id_t pt_diam_add_conn(diam_link_id_t diam_link_id, 
                    pt_int32_t protocol, pt_int32_t service,
                    pt_char_t *local_ip, pt_uint16_t local_port,
                    pt_char_t *remote_ip, pt_uint16_t remote_port);

diam_link_id_t pt_diam_add_link(pt_uint32_t link_id, 
                    pt_char_t *local_host_name, pt_char_t *local_realm,
                    pt_char_t *remote_host_name, pt_char_t *remote_realm);

typedef void (*_DIAM_UP_RECV)(diam_conn_t *diam_conn, pt_uint8_t *data, pt_int32_t);
void pt_diam_register_up(_DIAM_UP_RECV func);

/*diam_code.c*/
pt_int32_t pt_diam_encode_msg(diam_msg_t *msg, void *buf, pt_int32_t pos);
pt_int32_t pt_diam_encode_avp(avp_t *avp, void *buf, pt_int32_t pos);
pt_int32_t pt_diam_encode_octs(pt_uint8_t *octs, pt_uint8_t octs_len, void *buf, pt_int32_t pos);
pt_int32_t pt_diam_decode_avp_head(void *buf, pt_int32_t pos, avp_head_t *avp_head);
pt_int32_t pt_diam_decode_diam_head(void *buf, pt_int32_t pos, diam_head_t *diam_head);

#endif
