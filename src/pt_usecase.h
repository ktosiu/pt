#ifndef _PT_USECASE_H_
#define _PT_USECASE_H_

typedef void* pt_uc_msgflow_id_t;
typedef void* pt_uc_inst_id_t;
typedef void* pt_uc_msg_id_t;

typedef enum {
    STOP,
    RUNNING,
    PAUSE,
}pt_uc_runing_sate_e;

typedef struct pt_uc_msgflow_s {
    list_head_t node;

    pt_char_t   *msgflow_name;
    pt_uint32_t delay;/*msec*/

    list_head_t list_inst;

    pt_uint64_t rate;
    pt_uint64_t count;
    pt_uint64_t times;

    pt_uint64_t execute_count;
    pt_uint64_t execute_times;

    pt_uc_runing_sate_e runing_state;

    st_thread_t st_thread;
}pt_uc_msgflow_t;

typedef struct pt_uc_inst_s {
    list_head_t node;
    
    pt_char_t   *inst_name;

    list_head_t list_msg;

    pt_uc_msgflow_t *msgflow;
}pt_uc_inst_t;

typedef enum {
    MSG_ACTION_SEND,
    MSG_ACTION_RECEIVE,
}pt_uc_msg_action_e;

typedef enum {
    MSG_TYPE_DIM,
    MSG_TYPE_SS7,
}pt_uc_msg_type_e;

typedef enum {
    PT_UC_DATA_STR,
    PT_UC_DATA_IPV4,
    PT_UC_DATA_IPV6,
    PT_UC_DATA_BYTE,
    PT_UC_DATA_BCD,
}pt_uc_data_type;

typedef struct {
    list_head_t         node;

    pt_char_t           tag[128];
    pt_uc_data_type     data_type;
    pt_int32_t          data_len;
    pt_char_t           data[1024];
}pt_uc_matchinfo_t;

#define PT_UC_MSG_SS7_INVOKE    0
#define PT_UC_MSG_SS7_RESPOSE   1
typedef struct pt_uc_msg_s {
    list_head_t                 node;

    pt_char_t                   *msg_name;

    pt_uint32_t                 msg_link_id;
    pt_uc_msg_action_e          msg_action;

    pt_uc_msg_type_e            msg_type;

    /*ss7相关*/
    pt_uint8_t                  msg_ss7_acver;
    pt_uint8_t                  msg_ss7_acvalue;
    pt_uint8_t                  msg_ss7_comptype;
    pt_uint8_t                  msg_ss7_opcode;
    pt_uint8_t                  msg_ss7_cda_code[11];
    pt_uint8_t                  msg_ss7_cda_ssn;
    pt_uint8_t                  msg_ss7_cga_code[11];
    pt_uint8_t                  msg_ss7_cga_ssn;

    /*been used match msg & modify msg*/
    list_head_t                 list_msg_condition;
    list_head_t                 list_msg_uid;
    list_head_t                 list_msg_replace;

    /*msg data*/
    pt_int32_t                  msg_data_len;
    pt_uint8_t                  msg_data[(1024 * 32)];

    /*statistic*/
    pt_uint64_t                 msg_stat_totallast;
    pt_uint64_t                 msg_stat_total;
    pt_uint64_t                 msg_stat_rate;
    pt_uint64_t                 msg_stat_success;
    pt_uint64_t                 msg_stat_fail;
    pt_uint64_t                 msg_stat_timeout;
    pt_uint64_t                 msg_stat_maxrtt;
    pt_uint64_t                 msg_stat_minrtt;
    pt_uint64_t                 msg_stat_totalrtt;
    pt_uint64_t                 msg_stat_totalrttnum;

    pt_uc_inst_t                *inst;
}pt_uc_msg_t;

extern list_head_t list_msgflow;
void pt_uc_dump();
pt_uc_msgflow_id_t pt_uc_locate_msgflow(char *msgflow_name);

pt_uc_msgflow_id_t pt_uc_add_msgflow(pt_char_t *msgflow_name, pt_uint32_t delay);
pt_uc_inst_id_t pt_uc_add_inst(pt_uc_msgflow_id_t msgflow_id, pt_char_t *inst_name);
pt_uc_msg_id_t pt_uc_add_msg(pt_uc_inst_id_t inst_id, 
                    pt_char_t *msg_name, pt_int32_t msg_action, pt_int32_t msg_type, 
                    pt_uint8_t *msg_data, pt_int32_t msg_data_len);
void pt_uc_set_msg_linkid(pt_uc_msg_id_t msg_id, pt_uint32_t msg_link_id);
void pt_uc_set_msg_param_ss7(pt_uc_msg_id_t msg_id, 
                pt_uint8_t acver, pt_uint8_t acvalue, pt_uint8_t comptype, pt_uint8_t opcode,
                pt_char_t *cda_code, pt_uint8_t cda_ssn, pt_char_t *cga_code, pt_uint8_t cga_ssn);
void pt_uc_add_msg_uid(pt_uc_msg_id_t msg_id, 
                pt_int32_t uid_type, pt_char_t *uid, pt_int32_t uid_len, 
                pt_char_t *strtag);
void pt_uc_add_msg_replace(pt_uc_msg_id_t msg_id, 
                pt_int32_t replace_type, pt_char_t *replace, pt_int32_t replace_len, 
                pt_char_t *strtag);
void pt_uc_add_msg_condition(pt_uc_msg_id_t msg_id, 
                pt_int32_t condition_type, pt_char_t *condition, pt_int32_t condition_len, 
                pt_char_t *strtag);

#endif /*_PT_USECASE_H_*/

