#include "pt_include.h"

/*lint -save -e740*/

void *pt_malloc(pt_size_t size)
{
    return malloc(size);
}

void pt_free(void *p)
{
    free(p);
}

pt_char_t *pt_strdup(pt_char_t *str)
{
    return strdup(str);
}

pt_char_t *pt_basename(const pt_char_t *filename)
{
    pt_char_t *p = strrchr (filename, '/');
    return p ? p + 1 : (char *) filename;
}

pt_int32_t pt_inet_pton(pt_uint16_t af, const pt_char_t *src, void *dst)
{
    return inet_pton(af, src, dst);
}

const pt_char_t *pt_inet_ntop(pt_uint16_t af, const void *src, pt_char_t *dst, pt_socklen_t size)
{
    return inet_ntop(af, src, dst, size);
}

pt_uint16_t pt_htons(pt_uint16_t x)
{
    return htons(x);
}

pt_uint16_t pt_ntohs(pt_uint16_t x)
{
    return ntohs(x);
}

pt_uint32_t pt_htonl(pt_uint32_t x)
{
    return htonl(x);
}

pt_uint32_t pt_ntohl(pt_uint32_t x)
{
    return ntohl(x);
}

pt_int32_t pt_socket(pt_int32_t domain, pt_int32_t type, pt_int32_t protocol)
{
    return socket(domain, type, protocol);
}

pt_int32_t pt_bind(pt_int32_t sockfd, const pt_sockaddr_t *addr, pt_socklen_t addrlen)
{
    return bind(sockfd, addr, addrlen);
}

pt_int32_t pt_close(pt_int32_t sockfd)
{
    return close(sockfd);
}

pt_int32_t pt_listen(pt_int32_t sockfd, pt_int32_t backlog)
{
    return listen(sockfd, backlog);
}

pt_int32_t pt_getpeername(pt_int32_t sockfd, pt_sockaddr_t *addr, pt_socklen_t *addrlen)
{
    return getpeername(sockfd, addr, addrlen);
}

pt_int32_t pt_setsockopt(pt_int32_t sockfd, pt_int32_t level, pt_int32_t optname, 
                const void *optval, pt_socklen_t optlen)
{
    return setsockopt(sockfd, level, optname, optval, optlen);
}

pt_int32_t pt_getsockopt(pt_int32_t sockfd, pt_int32_t level, pt_int32_t optname, 
                void *optval, pt_socklen_t *optlen)
{
    return getsockopt(sockfd, level, optname, optval, optlen);
}

pt_pid_t pt_gettid()
{
    return syscall(__NR_gettid);
}

pt_pid_t pt_getpid()
{
    return getpid();
}

pt_int64_t pt_setaffinity(pt_pid_t tid, pt_uint64_t cpuid)
{
    cpu_set_t cpuset;

    memset(&cpuset, 0, sizeof(cpu_set_t));

    if (tid == 0)
        tid = pt_gettid();

    CPU_SET(cpuid, &cpuset);
    return sched_setaffinity((int)tid, sizeof(cpu_set_t), &cpuset);
}

