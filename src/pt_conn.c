#include "pt_include.h"

/*lint -save -e740*/

LIST_HEAD(list_instance);

pt_conn_instance_t *pt_conn_alloc_instance(pt_conn_protocol_e protocol, 
                                           pt_conn_service_e service, 
                                           pt_sockaddr_storage_t local_addr[PT_MAX_ADDR_NUM], 
                                           pt_uint32_t local_addr_num)
{
    pt_conn_instance_t *instance;

    instance = pt_malloc(sizeof(pt_conn_instance_t));
    if (instance == NULL) {
        PT_LOG(PTLOG_ERROR, "pt_malloc instance failed!");
        return NULL;
    }
    memset(instance, 0, sizeof(pt_conn_instance_t));

    INIT_LIST_HEAD(&instance->list_tcb);

    instance->protocol = protocol;
    instance->service = service;
    instance->af = pt_addr_af(&local_addr[0]);
    instance->addrlen = PT_ADDRLEN_IN;

    instance->local_addr_num = local_addr_num;
    memcpy(instance->local_addr, local_addr, 
        sizeof(pt_sockaddr_storage_t) * local_addr_num);

    instance->st_nfd = NULL;
    instance->st_thread = NULL;

    list_add_tail(&instance->node, &list_instance);

    return instance;
}

void pt_conn_free_instance(pt_conn_instance_t *instance)
{
    list_del(&instance->node);
    
    pt_free(instance);
}

pt_conn_instance_t *pt_conn_locate_instance(pt_conn_protocol_e protocol, 
                        pt_conn_service_e service, 
                        pt_sockaddr_storage_t local_addr[PT_MAX_ADDR_NUM], 
                        pt_uint32_t local_addr_num)
{
    pt_conn_instance_t *instance;
    list_head_t *pos_instance;
    pt_uint32_t i;

    list_for_each(pos_instance, &list_instance) {
        instance = list_entry(pos_instance, pt_conn_instance_t, node);
        if (instance->protocol != protocol) {
            continue;
        }
        if (instance->service != service) {
            continue;
        }
        if (instance->local_addr_num != local_addr_num) {
            continue;
        }

        for (i = 0; i < local_addr_num; i++) {
            if (!pt_addr_eq(&local_addr[i], &instance->local_addr[i])) {
                break;
            }
        }

        if (i < local_addr_num) {
            continue;
        }

        return instance;
    }

    return NULL;
}

pt_conn_tcb_t *pt_conn_alloc_tcb(pt_conn_instance_t *instance, 
                     pt_sockaddr_storage_t *remote_addr,
                     pt_uint32_t remote_addr_num, 
                     pt_uint32_t sctp_ppid,
                     _PT_HANDLE_DATA handle_data_func,
                     void *handle_data_func_arg)
{
    pt_conn_tcb_t *tcb;

    tcb = (pt_conn_tcb_t *)pt_malloc(sizeof(pt_conn_tcb_t));
    if (tcb == NULL) {
        PT_LOG(PTLOG_ERROR, "pt_malloc tcb failed!");
        return PT_FALSE;
    }
    memset(tcb, 0, sizeof(pt_conn_tcb_t));

    tcb->remote_addr_num = remote_addr_num;
    memcpy(tcb->remote_addr, remote_addr, 
        sizeof(pt_sockaddr_storage_t) * remote_addr_num);

    tcb->st_nfd = NULL;
    tcb->st_thread = NULL;

    tcb->sctp_ppid = sctp_ppid;
    tcb->sctp_assoc_id = 0;
    tcb->sk_status = PT_STATUS_CLOSE;
    tcb->instance = instance;

    tcb->handle_data_func = handle_data_func;
    tcb->handle_data_func_arg = handle_data_func_arg;

    list_add_tail(&tcb->node, &instance->list_tcb);

    return tcb;
}

void pt_conn_free_tcb(pt_conn_tcb_t *tcb) 
{
    list_del(&tcb->node);
    pt_free(tcb);
}

pt_conn_tcb_t *pt_conn_locate_tcb(pt_conn_instance_t *instance, 
                      pt_sockaddr_storage_t *remote_addr,
                      pt_uint32_t remote_addr_num)
{
    pt_conn_tcb_t *tcb;
    list_head_t *pos_tcb;
    pt_uint32_t i;

    list_for_each(pos_tcb, &instance->list_tcb)  {
        tcb = list_entry(pos_tcb, pt_conn_tcb_t, node);

        for (i = 0; i < remote_addr_num; i++) {
            if (pt_addr_ne(&remote_addr[i], &tcb->remote_addr[i])) {
                break;
            }
        }

        if (i == remote_addr_num) {
            return tcb;
        }
    }

    return NULL;
}

st_netfd_t pt_conn_open_instance(pt_conn_instance_t *instance)
{
    if (instance->st_nfd == NULL) {
        PT_LOG(PTLOG_DEBUG, "*%s, protocol = %d, service = %d.", 
            pt_addr_a(&instance->local_addr[0]), 
            instance->protocol, 
            instance->service);
        
        if (instance->protocol == PT_PROTOCOL_SCTP) {
            instance->st_nfd = pt_sctp_open_instance(instance);
        } else {
            instance->st_nfd = pt_tcp_open_instance(instance);
        }
        
        if (instance->st_nfd == NULL) {
            PT_LOG(PTLOG_ERROR, "open_instance failed!");
        }
    }

    return instance->st_nfd;
}

void pt_conn_accpet(pt_conn_instance_t *instance)
{
    pt_conn_tcb_t *tcb;
    pt_sockaddr_storage_t sockaddr;
    pt_socklen_t addrlen;
    st_netfd_t st_nfd;
        
    addrlen = instance->addrlen;
    st_nfd = st_accept(instance->st_nfd, (pt_sockaddr_t *)&sockaddr, 
                    (int *)&addrlen, ST_UTIME_NO_TIMEOUT);
    if (st_nfd == NULL){
        return;
    }

    tcb = pt_conn_locate_tcb(instance, &sockaddr, 1);
    if (tcb != NULL && tcb->instance->protocol == PT_PROTOCOL_SCTP) {
        tcb->st_nfd = st_nfd;
        pt_sctp_accpeted(tcb);
    } else if (tcb != NULL && tcb->instance->protocol == PT_PROTOCOL_TCP) {
        tcb->st_nfd = st_nfd;
        pt_tcp_accpeted(tcb);
    } else {
        PT_LOG(PTLOG_INFO, "*%s <-> *%s, protocol = %d, match failed, tcb = %p!", 
            pt_addr_a(&instance->local_addr[0]), 
            pt_addr_a(&sockaddr), 
            instance->protocol, 
            tcb);
        st_netfd_close(st_nfd);
        return;
    }
    PT_LOG(PTLOG_INFO, "*%s <-> *%s, protocol = %d, accepted successful.", 
        pt_addr_a(&instance->local_addr[0]), 
        pt_addr_a(&sockaddr), 
        instance->protocol);
}

void pt_conn_connect(pt_conn_instance_t *instance)
{
    pt_int32_t rtn;
    pt_conn_tcb_t *tcb;

    tcb = list_entry(instance->list_tcb.next, pt_conn_tcb_t, node);
    
    rtn = st_connect(instance->st_nfd, (pt_sockaddr_t *)&tcb->remote_addr[0], 
                (int)instance->addrlen, ST_UTIME_NO_TIMEOUT);
    if (rtn < 0 && errno != 106/*already connected*/) {
        PT_LOG(PTLOG_INFO, "*%s <-> *%s, protocol = %d, connected failed, reason = %s.", 
            pt_addr_a(&instance->local_addr[0]), 
            pt_addr_a(&tcb->remote_addr[0]), 
            instance->protocol, 
            strerror(errno));
        return;
    }

    PT_LOG(PTLOG_INFO, "*%s <-> *%s, protocol = %d, connected successful.", 
        pt_addr_a(&instance->local_addr[0]), 
        pt_addr_a(&tcb->remote_addr[0]), 
        instance->protocol);

    tcb->st_nfd = instance->st_nfd;
    if(tcb->instance->protocol == PT_PROTOCOL_SCTP) {
        pt_sctp_connected(tcb);
    } else {
        pt_tcp_connected(tcb);
    }
}

void *pt_conn_monitor_instance(void *arg)
{
    pt_conn_instance_t *instance;
    pt_conn_tcb_t *tcb;

    instance = (pt_conn_instance_t *)arg;

    if (list_empty(&instance->list_tcb)) {
        PT_LOG(PTLOG_ERROR, "list_tcb is empty");
        return NULL;
    }

    tcb = list_entry(instance->list_tcb.next, pt_conn_tcb_t, node);

    for (;;)  {
        if (NULL == pt_conn_open_instance(instance)) {
            PT_LOG(PTLOG_ERROR, "open instance failed!");
        } else if (instance->service == PT_SERVICE_CLI && 
                (tcb->sk_status != PT_STATUS_ESTABLISHED && 
                 tcb->sk_status != PT_STATUS_CONNECTING)) {
            pt_conn_connect(instance);
        } else if (instance->service == PT_SERVICE_SRV) {
            pt_conn_accpet(instance);
        }
        st_sleep(1);
    }
}

pt_conn_id_t pt_conn_add(pt_conn_item_t *conn)
{
    pt_conn_instance_t *instance;
    pt_conn_tcb_t *tcb;

    instance = NULL;
    if (conn->service == PT_SERVICE_SRV) {
        instance = pt_conn_locate_instance(conn->protocol, conn->service, 
                                        conn->local_addr, conn->local_addr_num);
    } 

    if (instance == NULL) {
        instance = pt_conn_alloc_instance(conn->protocol, conn->service, 
                                        conn->local_addr, conn->local_addr_num);
    }
    
    tcb = pt_conn_alloc_tcb(instance, conn->remote_addr, conn->remote_addr_num, conn->sctp_ppid,
                        conn->handle_data_func, conn->handle_data_func_arg);

    if (instance->st_thread == NULL) {
        instance->st_thread = st_thread_create(pt_conn_monitor_instance, 
                                            (void *)instance, 0, 0);
    }

    return tcb;
}

void pt_conn_del(pt_conn_id_t conn_id)
{
    pt_conn_tcb_t *tcb;

    tcb = conn_id;

        
    /*暂时无法解决ST线程删除问题*/
}

pt_int32_t pt_conn_send(pt_conn_id_t *conn_id, pt_uint32_t seq, pt_uint8_t *data, pt_uint32_t len)
{
    pt_conn_tcb_t *tcb;

    tcb = (pt_conn_tcb_t *)conn_id;
    tcb->seq = seq;

    if (tcb->instance->protocol == PT_PROTOCOL_SCTP) {
        return pt_sctp_send(tcb, data, len);
    } else if (tcb->instance->protocol == PT_PROTOCOL_TCP) {
        return pt_tcp_send(tcb, data, len);
    }

    return -1;
}

pt_conn_status_e pt_conn_status(pt_conn_id_t conn_id)
{
    pt_conn_tcb_t *tcb;

    tcb = conn_id;

    return tcb->sk_status;
}

void pt_conn_dump_instance(void)
{
    ;
}

void pt_conn_res_reset()
{
    pt_conn_instance_t *instance;
    pt_conn_tcb_t *tcb;
        
    while (!list_empty(&list_instance)) {
        instance = list_entry(list_instance.next, pt_conn_instance_t, node);
        while (!list_empty(&instance->list_tcb)) {
            tcb = list_entry(instance->list_tcb.next, pt_conn_tcb_t, node);
            pt_conn_free_tcb(tcb);
        }
        pt_conn_free_instance(instance);
    }
}

