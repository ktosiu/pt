#ifndef _PT_OS_H
#define _PT_OS_H
                                                        
#include <stdlib.h>
#include <signal.h>                                                                    
#include <string.h>                                                                    
#include <errno.h>                                                                     
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <netinet/in.h> 
#include <netinet/sctp.h>   
                                  
#include <arpa/inet.h>  
#define __USE_GNU
#include <sched.h>                                                                     
#include <netdb.h>                                                                     
#include <fcntl.h> 

typedef size_t         pt_size_t;

typedef unsigned char  pt_uint8_t;
typedef unsigned short pt_uint16_t;
typedef unsigned int   pt_uint32_t;
typedef unsigned long  pt_uint64_t;


typedef char   pt_char_t;
typedef char   pt_int8_t;
typedef short  pt_int16_t;
typedef int    pt_int32_t;
typedef long   pt_int64_t;
typedef float  pt_float_t;
typedef double pt_double_t;


#define PT_TRUE  1
#define PT_FALSE 0
typedef int   pt_bool_t;
typedef long  pt_pid_t; 

#define PT_SOCK_STREAM SOCK_STREAM

#define PT_AF_INET   AF_INET
#define PT_AF_INET6  AF_INET6

typedef struct sockaddr         pt_sockaddr_t;
typedef struct sockaddr_in      pt_sockaddr_in_t;
typedef struct sockaddr_in6     pt_sockaddr_in6_t;
typedef struct sockaddr_storage pt_sockaddr_storage_t;
typedef socklen_t               pt_socklen_t;
typedef struct msghdr           pt_msghdr_t;
typedef struct iovec            pt_iover_t;

#define PT_ADDRLEN_IN  sizeof(pt_sockaddr_in_t)
#define PT_ADDRLEN_IN6 sizeof(pt_sockaddr_in6_t)

#define PT_ARRAY_SIZE(a) (sizeof((a))/sizeof(((a)[0])))

void *pt_malloc(pt_size_t size);
void pt_free(void *p);

/*string*/
pt_char_t *pt_strdup(pt_char_t *str);

pt_char_t *pt_basename(const pt_char_t *filename);
pt_int32_t pt_inet_pton(pt_uint16_t af, const pt_char_t *src, void *dst);
const pt_char_t *pt_inet_ntop(pt_uint16_t af, const void *src, pt_char_t *dst, pt_socklen_t size);
pt_uint16_t pt_htons(pt_uint16_t x);
pt_uint16_t pt_ntohs(pt_uint16_t x);
pt_uint32_t pt_htonl(pt_uint32_t x);
pt_uint32_t pt_ntohl(pt_uint32_t x);
pt_int32_t pt_socket(pt_int32_t domain, pt_int32_t type, pt_int32_t protocol);
pt_int32_t pt_bind(pt_int32_t sockfd, const pt_sockaddr_t *addr, pt_socklen_t addrlen);
pt_int32_t pt_close(pt_int32_t sockfd);
pt_int32_t pt_listen(pt_int32_t sockfd, pt_int32_t backlog);
pt_int32_t pt_getpeername(pt_int32_t sockfd, pt_sockaddr_t *addr, pt_socklen_t *addrlen);
pt_int32_t pt_setsockopt(pt_int32_t sockfd, pt_int32_t level, pt_int32_t optname, 
                    const void *optval, pt_socklen_t optlen);
pt_int32_t pt_getsockopt(pt_int32_t sockfd, pt_int32_t level, pt_int32_t optname, 
                    void *optval, pt_socklen_t *optlen);
pt_pid_t pt_gettid();
pt_pid_t pt_getpid();
pt_int64_t pt_setaffinity(pt_pid_t tid, pt_uint64_t cpuid);

#endif /*_PT_OS_H*/

