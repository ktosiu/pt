#ifndef _PT_TASK_H
#define _PT_TASK_H

/*lint -e715*/
typedef struct {
    pt_uint32_t link_type; /*0-diam 1-m3ua*/
    pt_uint32_t link_id;
    pt_uint8_t link_sls;
    pt_uint8_t *data; 
    pt_uint32_t len;
}pt_task_data_t;

typedef struct {
    pt_uint8_t ss7_opcode;
    pt_uint8_t ss7_invokeid;
    st_utime_t ss7_utime;
}pt_task_ss7_invokeinfo_t;

typedef struct {
    list_head_t node;

    pt_uc_msg_t *msg;

    pt_uint64_t seq;

    pt_uint32_t              ss7_peer_invokeinfo_num;
    pt_task_ss7_invokeinfo_t ss7_peer_invokeinfo[8];

    pt_uint32_t              ss7_local_invokeinfo_num;
    pt_task_ss7_invokeinfo_t ss7_local_invokeinfo[8];
    
    st_utime_t  send_time;

    pt_uint32_t _index;
    pt_uint32_t _sn;
}pt_task_pdb_t;

/*diam*/
void pt_task_recv_diam_msg(diam_conn_t *diam_conn, pt_uint8_t *data, pt_int32_t len);
pt_int32_t pt_task_send_diam_arg_msg(pt_uc_msg_t *msg, pt_uint64_t seq);

/*ss7*/
void pt_task_recv_ss7_msg(m3ua_asp_t *m3ua_asp, sccp_up_msg_t *up_msg);
pt_int32_t pt_task_send_ss7_begin_msg(pt_uc_msg_t *begin_msg, pt_uint64_t seq);

/*task*/
extern pt_pid_t self_pid;
void *pt_task_thread(void *arg);
pt_task_pdb_t *pt_task_locate_pdb(pt_uint32_t pdb_index, pt_uint32_t pdb_sn);
pt_task_pdb_t *pt_task_alloc_pdb();
void pt_task_free_pdb(pt_task_pdb_t *pdb);
void pt_task_calc_rtt(pt_task_pdb_t *pdb);
pt_bool_t pt_task_last_msg(pt_uc_msg_t *msg);
pt_bool_t pt_task_last_inst(pt_uc_inst_t *inst);

/*interface*/
void pt_task_start(pt_uc_msgflow_id_t msgflow_id, pt_uint64_t count, pt_uint64_t rate, 
            pt_uint64_t times, pt_uint32_t delay); 
void pt_task_stop(pt_uc_msgflow_id_t msgflow_id);
void pt_task_pause(pt_uc_msgflow_id_t msgflow_id);
void pt_task_continue(pt_uc_msgflow_id_t msgflow_id);
void pt_task_update(pt_uc_msgflow_id_t msgflow_id, pt_uint64_t count, 
            pt_uint64_t rate, pt_uint64_t times);


#endif /*_PT_TASK_H*/

