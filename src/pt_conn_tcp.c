#include "pt_include.h"

/*lint -save -e715 -e740*/

void pt_tcp_setsockopt_ruseaddr(pt_int32_t skfd)
{
    pt_bool_t opt = 1;

    if (pt_setsockopt(skfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        PT_LOG(PTLOG_ERROR, "set failed(%s)", strerror(errno));
    }
}

void pt_tcp_setsockopt_linger(pt_int32_t skfd)
{
    struct linger opt = {PT_FALSE, };

    if (pt_setsockopt(skfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        PT_LOG(PTLOG_ERROR, "set failed(%s)", strerror(errno));
    }
}

void pt_tcp_setsockopt_rcvbuf(pt_int32_t skfd)
{
    int opt = 1 << 21;

    if (pt_setsockopt(skfd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt))) {
        PT_LOG(PTLOG_ERROR, "set failed(%s)", strerror(errno));
    }
}

void pt_tcp_setsockopt_sndbuf(pt_int32_t skfd)
{
    int opt = 1 << 21;

    if (pt_setsockopt(skfd, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(opt))) {
        PT_LOG(PTLOG_ERROR, "set failed(%s)", strerror(errno));
    }
}

pt_int32_t pt_tcp_handle_data(pt_conn_tcb_t *tcb, void *data, pt_int32_t len)
{
    pt_conn_msg_t conn_msg;

    PT_LOG(PTLOG_DEBUG, "*%s <-> *%s, recv data = %p len = %d",
                        pt_addr_a(&tcb->instance->local_addr[0]),
                        pt_addr_a(&tcb->remote_addr[0]),
                        data,
                        len);

    if (!tcb->handle_data_func) {
        return -0xff;
    }

    conn_msg.msg_type = PT_CONN_MSG_DATA;
    conn_msg.msg.msg_data.conn_id = tcb;
    conn_msg.msg.msg_data.len = len;
    conn_msg.msg.msg_data.data = data;

    return tcb->handle_data_func(tcb->handle_data_func_arg, &conn_msg);
}

pt_int32_t pt_tcp_handle_notify(pt_conn_tcb_t *tcb, void *data, pt_int32_t len)
{
    pt_conn_msg_t conn_msg;

    conn_msg.msg_type = PT_CONN_MSG_NOTIFY;
    conn_msg.msg.msg_notify.conn_id = tcb;
    conn_msg.msg.msg_notify.conn_status = tcb->sk_status;

    return tcb->handle_data_func(tcb->handle_data_func_arg, &conn_msg);
}

st_netfd_t pt_tcp_open_instance(pt_conn_instance_t *instance)
{
    int skfd;

    skfd = pt_socket(instance->af, PT_SOCK_STREAM, PT_PROTOCOL_TCP);
    if (skfd < 0) {
        PT_LOG(PTLOG_ERROR, "pt_socket failed(%s)", strerror(errno));
        return NULL;
    }

    pt_tcp_setsockopt_ruseaddr(skfd);

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

    pt_tcp_setsockopt_linger(skfd);
    pt_tcp_setsockopt_rcvbuf(skfd);
    pt_tcp_setsockopt_sndbuf(skfd);

    return instance->st_nfd;
}

void pt_tcp_close(pt_conn_tcb_t *tcb)
{
    st_netfd_close(tcb->st_nfd);
    tcb->st_nfd = NULL;

    if (tcb->instance->service == PT_SERVICE_CLI) {
        tcb->instance->st_nfd = NULL;
    }
    tcb->sk_status = PT_STATUS_CLOSE;

    pt_tcp_handle_notify(tcb, NULL, 0);
}

pt_uint8_t _pt_tcp_recvbuf[1 << 15];

void *pt_tcp_recvmsg(void *arg)
{
    pt_conn_tcb_t *tcb;
    pt_msghdr_t inmsg;
    pt_iover_t iov;
    pt_int32_t flag = 0;
    pt_int32_t count;

    tcb = (pt_conn_tcb_t *)arg;

    memset(&inmsg, 0, sizeof(inmsg));

    iov.iov_base = _pt_tcp_recvbuf;
    iov.iov_len = sizeof(_pt_tcp_recvbuf);
    inmsg.msg_iov = &iov;
    inmsg.msg_iovlen = 1;

    for (;;) {
        count = st_recvmsg(tcb->st_nfd, &inmsg, flag, ST_UTIME_NO_TIMEOUT);
        if (count > 0) {
            pt_tcp_handle_data(tcb, _pt_tcp_recvbuf, count);
        } else {
            PT_LOG(PTLOG_ERROR, "pt_conn_data_thread recvmsg failed %s!", strerror(errno));
            pt_tcp_close(tcb);
        }

        if (tcb->sk_status != PT_STATUS_ESTABLISHED) {
            break;
        }
    }

    return NULL;
}

/*
 * client connect successful
 */
void pt_tcp_connected(pt_conn_tcb_t *tcb)
{
    tcb->st_thread = st_thread_create(pt_tcp_recvmsg, (void *)tcb, 0, 0);
    tcb->sk_status = PT_STATUS_ESTABLISHED;

    pt_tcp_handle_notify(tcb, NULL, 0);
}

/*
 * server accepet successful
 */

void pt_tcp_accpeted(pt_conn_tcb_t *tcb)
{
    tcb->st_thread = st_thread_create(pt_tcp_recvmsg, (void *)tcb, 0, 0);
    tcb->sk_status = PT_STATUS_ESTABLISHED;

    pt_tcp_handle_notify(tcb, NULL, 0);
}

pt_int32_t pt_tcp_send(pt_conn_tcb_t *tcb, pt_uint8_t *data, pt_uint32_t len)
{
    pt_msghdr_t outmsg;
    pt_iover_t iov;
    pt_int32_t flag = 0;

    memset(&outmsg, 0, sizeof(outmsg));

    iov.iov_base = data;
    iov.iov_len = len;
    outmsg.msg_iov = &iov;
    outmsg.msg_iovlen = 1;

	flag = MSG_NOSIGNAL;

    return st_sendmsg(tcb->st_nfd, &outmsg, flag, ST_UTIME_NO_TIMEOUT);
}


