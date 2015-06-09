#include "pt_include.h"

/*lint -save -e715 -e740*/

void pt_sctp_setsockopt_ruseaddr(pt_int32_t skfd)
{
    pt_bool_t opt = 1;

    if (pt_setsockopt(skfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        PT_LOG(PTLOG_ERROR, "set failed(%s)", strerror(errno));
    }
}

void pt_sctp_setsockopt_linger(pt_int32_t skfd)
{
    struct linger opt = {PT_FALSE, };

    if (pt_setsockopt(skfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        PT_LOG(PTLOG_ERROR, "set failed(%s)", strerror(errno));
    }
}

void pt_sctp_setsockopt_rcvbuf(pt_int32_t skfd)
{
    int opt = 1 << 21;

    if (pt_setsockopt(skfd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt))) {
        PT_LOG(PTLOG_ERROR, "set failed(%s)", strerror(errno));
    }
}

void pt_sctp_setsockopt_sndbuf(pt_int32_t skfd)
{
    int opt = 1 << 21;

    if (pt_setsockopt(skfd, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(opt))) {
        PT_LOG(PTLOG_ERROR, "set failed(%s)", strerror(errno));
    }
}

void pt_sctp_setsockopt_event(pt_int32_t skfd)
{
    struct sctp_event_subscribe opt = {0};
    opt.sctp_data_io_event = 1;
    opt.sctp_association_event = 1;
    opt.sctp_shutdown_event = 1;
    opt.sctp_send_failure_event = 1;

    if (pt_setsockopt(skfd, IPPROTO_SCTP, SCTP_EVENTS, &opt, sizeof(opt))) {
        PT_LOG(PTLOG_ERROR, "set failed %d!", strerror(errno));
    }
}

void pt_sctp_setsockopt_initmsg(pt_int32_t skfd)
{
    struct sctp_initmsg opt = {0};

    opt.sinit_num_ostreams = 16;
    opt.sinit_max_instreams = 16;

    if (pt_setsockopt(skfd, IPPROTO_SCTP, SCTP_INITMSG, &opt, sizeof(opt))) {
        PT_LOG(PTLOG_ERROR, "set failed(%s)!", strerror(errno));
    }
}

void pt_sctp_setsockopt_rtoinfo(pt_int32_t skfd)
{
    struct sctp_rtoinfo opt = {0};

    opt.srto_initial = 500;
    opt.srto_min = 500;
    opt.srto_max = 3000;

    if (pt_setsockopt(skfd, IPPROTO_SCTP, SCTP_RTOINFO, &opt, sizeof(opt))) {
        PT_LOG(PTLOG_ERROR, "set failed(%s)!", strerror(errno));
    }
}

void pt_sctp_setsockopt_assocparams(pt_int32_t skfd)
{
    struct sctp_assocparams opt = {0};

    opt.sasoc_asocmaxrxt = 3;
    if (pt_setsockopt(skfd, IPPROTO_SCTP, SCTP_ASSOCINFO, &opt, sizeof(opt))) {
        PT_LOG(PTLOG_ERROR, "set failed(%s)!", strerror(errno));
    }
}

void pt_sctp_setsockopt_paddrparams(pt_int32_t skfd, pt_sockaddr_storage_t *addr)
{
    struct sctp_paddrparams opt = {0};
    opt.spp_address = *addr;
    opt.spp_flags += SPP_HB_ENABLE;
    opt.spp_hbinterval = 5000;
    opt.spp_pathmaxrxt = 2;

    if (pt_setsockopt(skfd, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS, &opt, sizeof(opt))) {
        PT_LOG(PTLOG_ERROR, "set failed(%s)!", strerror(errno));
    }
}

pt_int32_t pt_sctp_event_assoc_change(struct sctp_assoc_change *sac, pt_conn_tcb_t *tcb)
{
    PT_LOG(PTLOG_INFO, "assoc_change: state=%hu, error=%hu, instr=%hu outstr=%hu.",
            sac->sac_state, sac->sac_error,
            sac->sac_inbound_streams, sac->sac_outbound_streams);

    tcb->sctp_status = sac->sac_state;

    if (sac->sac_state == SCTP_COMM_UP) {
        tcb->sctp_assoc_id = sac->sac_assoc_id;
        pt_sctp_up(tcb);
    } else if (sac->sac_state == SCTP_COMM_LOST) {
        pt_sctp_close(tcb);
        tcb->sctp_assoc_id = 0;
        return -1;
    }
    return 0;
}

pt_int32_t pt_sctp_event_send_failed(struct sctp_send_failed *ssf, pt_conn_tcb_t *tcb)
{
    PT_LOG(PTLOG_INFO, "sendfailed: len=%hu err=%d", ssf->ssf_length, ssf->ssf_error);
    return 0;
}

pt_int32_t pt_sctp_handle_event(pt_conn_tcb_t *tcb, void *data, pt_int32_t len)
{
    pt_int32_t rtn;
    union sctp_notification *snp;

    snp = data;

    PT_LOG(PTLOG_INFO, "*%s <-> *%s, notify event, sn_type = %#x, sn_flags = %u, "
                        "data= %p, len = %d.",
                        pt_addr_a(&tcb->instance->local_addr[0]),
                        pt_addr_a(&tcb->remote_addr[0]),
                        snp->sn_header.sn_type,
                        snp->sn_header.sn_flags,
                        data,
                        len);
    rtn = 0;
    switch (snp->sn_header.sn_type) {
        case SCTP_ASSOC_CHANGE:
            rtn = pt_sctp_event_assoc_change(&snp->sn_assoc_change, tcb);
            break;

        case SCTP_SEND_FAILED:
            rtn = pt_sctp_event_send_failed(&snp->sn_send_failed, tcb);
            break;

        case SCTP_PEER_ADDR_CHANGE:
            break;

        case SCTP_REMOTE_ERROR:
            break;

        case SCTP_SHUTDOWN_EVENT:
            PT_LOG(PTLOG_DEBUG, "shutdown event");
            break;

        default:
            PT_LOG(PTLOG_DEBUG, "unknown type: %hu", snp->sn_header.sn_type);
            break;
    };

    return rtn;
}

pt_int32_t pt_sctp_handle_data(pt_conn_tcb_t *tcb, void *data, pt_int32_t len)
{
    pt_conn_msg_t conn_msg;

    PT_LOG(PTLOG_DEBUG, "*%s <-> *%s, recv data = %p len = %d, sctp_assoc_id = %d.",
                        pt_addr_a(&tcb->instance->local_addr[0]),
                        pt_addr_a(&tcb->remote_addr[0]),
                        data,
                        len,
                        tcb->sctp_assoc_id);

    if (!tcb->handle_data_func) {
        return -0xff;
    }

    conn_msg.msg_type = PT_CONN_MSG_DATA;
    conn_msg.msg.msg_data.conn_id = tcb;
    conn_msg.msg.msg_data.len = len;
    conn_msg.msg.msg_data.data = data;

    return tcb->handle_data_func(tcb->handle_data_func_arg, &conn_msg);
}

pt_int32_t pt_stcp_handle_notify(pt_conn_tcb_t *tcb, void *data, pt_int32_t len)
{
    pt_conn_msg_t conn_msg;

    if (!tcb->handle_data_func) {
        return -0xff;
    }

    conn_msg.msg_type = PT_CONN_MSG_NOTIFY;
    conn_msg.msg.msg_notify.conn_id = tcb;
    conn_msg.msg.msg_notify.conn_status = tcb->sk_status;

    return tcb->handle_data_func(tcb->handle_data_func_arg, &conn_msg);
}

st_netfd_t pt_sctp_open_instance(pt_conn_instance_t *instance)
{
    int skfd;

    skfd = pt_socket(instance->af, PT_SOCK_STREAM, PT_PROTOCOL_SCTP);
    if (skfd < 0) {
        PT_LOG(PTLOG_ERROR, "pt_socket failed(%s)", strerror(errno));
        return NULL;
    }

    pt_sctp_setsockopt_ruseaddr(skfd);

    if (pt_bind(skfd, (pt_sockaddr_t *)&instance->local_addr[0], instance->addrlen) < 0) {
        PT_LOG(PTLOG_ERROR, "pt_bind failed(%s)", strerror(errno));
        pt_close(skfd);
        return NULL;
    }

    if (instance->service == PT_SERVICE_SRV) {
        if (pt_listen(skfd, 256) < 0) {
            PT_LOG(PTLOG_ERROR, "pt_listen failed(%s)", strerror(errno));
            pt_close(skfd);
            return NULL;
        }
    }

    instance->st_nfd = st_netfd_open_socket(skfd);
    if (instance->st_nfd == NULL) {
        PT_LOG(PTLOG_ERROR, "st_netfd_open_socket failed!");
        return NULL;
    }

    pt_sctp_setsockopt_linger(skfd);
    pt_sctp_setsockopt_rcvbuf(skfd);
    pt_sctp_setsockopt_sndbuf(skfd);
    pt_sctp_setsockopt_initmsg(skfd);
    pt_sctp_setsockopt_rtoinfo(skfd);
    pt_sctp_setsockopt_assocparams(skfd);
    pt_sctp_setsockopt_event(skfd);

    return instance->st_nfd;
}

void pt_sctp_up(pt_conn_tcb_t *tcb)
{
    pt_stcp_handle_notify(tcb, NULL, 0);
}

void pt_sctp_close(pt_conn_tcb_t *tcb)
{
    st_netfd_close(tcb->st_nfd);
    tcb->st_nfd = NULL;

    PT_LOG(PTLOG_ERROR, "*%s <-> *%s, service = %d.",
        pt_addr_a(&tcb->instance->local_addr[0]),
        pt_addr_a(&tcb->remote_addr[0]),
        tcb->instance->service);
    if (tcb->instance->service == PT_SERVICE_CLI) {
        tcb->instance->st_nfd = NULL;
    }
    tcb->sk_status = PT_STATUS_CLOSE;

    pt_stcp_handle_notify(tcb, NULL, 0);
}

pt_uint8_t _pt_sctp_recvbuf[1 << 15];

void *pt_sctp_recvmsg(void *arg)
{
    pt_conn_tcb_t *tcb;
    pt_msghdr_t inmsg;
    pt_iover_t iov;
    pt_uint8_t incmsg[CMSG_SPACE(sizeof(sctp_cmsg_data_t))];
    pt_int32_t flag = 0;
    pt_int32_t count;

    tcb = (pt_conn_tcb_t *)arg;

    memset(&inmsg, 0, sizeof(inmsg));

    iov.iov_base = _pt_sctp_recvbuf;
    iov.iov_len = sizeof(_pt_sctp_recvbuf);
    inmsg.msg_iov = &iov;
    inmsg.msg_iovlen = 1;
    inmsg.msg_control = incmsg;
    inmsg.msg_controllen = sizeof(incmsg);

    for (;;) {
        count = st_recvmsg(tcb->st_nfd, &inmsg, flag, ST_UTIME_NO_TIMEOUT);
        if (count > 0) {
            PT_LOG(PTLOG_DEBUG, "*%s <-> *%s, recv msg, sctp_assoc_id = %d.",
                                pt_addr_a(&tcb->instance->local_addr[0]),
                                pt_addr_a(&tcb->remote_addr[0]),
                                tcb->sctp_assoc_id);
            if (inmsg.msg_flags & MSG_NOTIFICATION) {
                pt_sctp_handle_event(tcb, _pt_sctp_recvbuf, count);
            } else {
                pt_sctp_handle_data(tcb, _pt_sctp_recvbuf, count);
            }
        }
        else
        {
            PT_LOG(PTLOG_ERROR, "pt_conn_data_thread recvmsg failed %s!", strerror(errno));
            pt_sctp_close(tcb);
        }

        if (tcb->sk_status != PT_STATUS_ESTABLISHED) {
            break;
        }
    }

    return NULL;
}

pt_int32_t pt_sctp_send(pt_conn_tcb_t *tcb, pt_uint8_t *data, pt_uint32_t len)
{
    pt_msghdr_t outmsg;
    pt_iover_t iov;
    sctp_cmsg_data_t *sinfo;
    pt_uint8_t incmsg[CMSG_SPACE(sizeof(sctp_cmsg_data_t))];
    struct cmsghdr *cmsg;
    pt_int32_t flag = 0;

    memset(&outmsg, 0, sizeof(outmsg));

    iov.iov_base = data;
    iov.iov_len = len;
    outmsg.msg_iov = &iov;
    outmsg.msg_iovlen = 1;
    outmsg.msg_control = incmsg;
    outmsg.msg_controllen = sizeof(incmsg);

    cmsg = CMSG_FIRSTHDR(&outmsg);
    cmsg->cmsg_level = IPPROTO_SCTP;
    cmsg->cmsg_type = SCTP_SNDRCV;
    cmsg->cmsg_len = CMSG_LEN(sizeof(sctp_cmsg_data_t));
    outmsg.msg_controllen = cmsg->cmsg_len;
	sinfo = (sctp_cmsg_data_t *)CMSG_DATA(cmsg);
    memset(sinfo, 0x00, sizeof(sctp_cmsg_data_t));
    sinfo->sndrcv.sinfo_ppid = pt_htonl(tcb->sctp_ppid);
    sinfo->sndrcv.sinfo_stream = tcb->seq % 16;

	flag = MSG_NOSIGNAL;

    PT_LOG(PTLOG_DEBUG, "*%s <-> *%s, send msg, data = %p len = %d, "
                        "sctp_assoc_id = %d, streamid = %d.",
                        pt_addr_a(&tcb->instance->local_addr[0]),
                        pt_addr_a(&tcb->remote_addr[0]),
                        data,
                        len,
                        tcb->sctp_assoc_id,
                        sinfo->sndrcv.sinfo_stream);

    return st_sendmsg(tcb->st_nfd, &outmsg, flag, ST_UTIME_NO_TIMEOUT);
}

/*
 * client connect successful
 */
void pt_sctp_connected(pt_conn_tcb_t *tcb)
{
    pt_sctp_setsockopt_paddrparams(st_netfd_fileno(tcb->st_nfd), &tcb->remote_addr[0]);

    tcb->st_thread = st_thread_create(pt_sctp_recvmsg, (void *)tcb, 0, 0);

    tcb->sk_status = PT_STATUS_ESTABLISHED;
}

/*
 * server accepet successful
 */

void pt_sctp_accpeted(pt_conn_tcb_t *tcb)
{
    pt_sctp_setsockopt_paddrparams(st_netfd_fileno(tcb->st_nfd), &tcb->remote_addr[0]);

    tcb->st_thread = st_thread_create(pt_sctp_recvmsg, (void *)tcb, 0, 0);

    tcb->sk_status = PT_STATUS_ESTABLISHED;
}


