#include "pt_include.h"
/*lint -e740*/
pt_uint16_t pt_addr_af(pt_sockaddr_storage_t *addr)
{
    return ((pt_sockaddr_t *)addr)->sa_family;
}

/*
 * max 8 addr line print.
 */
pt_char_t *pt_addr_a(pt_sockaddr_storage_t *addr)
{
    #define _MAX_ADDR_BUF 64
    #define _MAX_ADDR_NUM 8
    
    pt_uint16_t af;
    pt_sockaddr_in_t *sockaddr_in;
    pt_sockaddr_in6_t *sockaddr_in6;
    static pt_uint32_t addr_pos = 0;
    static pt_char_t addr_buf[_MAX_ADDR_NUM][_MAX_ADDR_BUF];
    pt_char_t   *addr_str;
    pt_uint16_t addr_port;

    addr_str = &addr_buf[addr_pos][0];
    
    af = pt_addr_af(addr);
    if (af == PT_AF_INET) {
        sockaddr_in = (pt_sockaddr_in_t *)addr;

        pt_inet_ntop(af, &sockaddr_in->sin_addr, addr_str, _MAX_ADDR_BUF);
        addr_port = pt_ntohs(sockaddr_in->sin_port);

        sprintf(addr_str, "%s:%u", addr_str, addr_port); /*lint !e464*/
        
    } else if (af == PT_AF_INET6) {
        sockaddr_in6 = (pt_sockaddr_in6_t *)addr;
        
        pt_inet_ntop(af, &sockaddr_in6->sin6_addr, addr_str, _MAX_ADDR_BUF);
        addr_port = pt_ntohs(sockaddr_in6->sin6_port);
        
        sprintf(addr_str, "%s:%u", addr_str, addr_port); /*lint !e464*/
    }
    else {
        sprintf(addr_str, "invalide af = %d!", af);
    }

    addr_pos = (addr_pos + 1) % _MAX_ADDR_NUM;

    return addr_str;
}

void pt_addr_n(pt_uint16_t af, pt_char_t *src, pt_uint16_t port, pt_sockaddr_storage_t *sockaddr)
{
    pt_sockaddr_in_t *pt_sockaddr_in;
    pt_sockaddr_in6_t *pt_sockaddr_in6;

    if (af == PT_AF_INET)
    {
        pt_sockaddr_in = (pt_sockaddr_in_t *)sockaddr;
        pt_sockaddr_in->sin_family = af;
        pt_sockaddr_in->sin_port = pt_htons(port);
        pt_inet_pton(af, src, &pt_sockaddr_in->sin_addr);    
    }
    else
    {
        pt_sockaddr_in6 = (pt_sockaddr_in6_t *)sockaddr;
        pt_sockaddr_in6->sin6_family = af;
        pt_sockaddr_in6->sin6_port = pt_htons(port);
        pt_inet_pton(af, src, &pt_sockaddr_in6->sin6_addr);    
    }
}

pt_bool_t pt_addr_eq(pt_sockaddr_storage_t *addr_src, pt_sockaddr_storage_t *addr_dst)
{
    pt_sockaddr_in_t *sockaddr_in_src;
    pt_sockaddr_in_t *sockaddr_in_dst;
    pt_sockaddr_in6_t *sockaddr_in6_src;
    pt_sockaddr_in6_t *sockaddr_in6_dst;

    if (pt_addr_af(addr_src) == PT_AF_INET) {
        sockaddr_in_src = (pt_sockaddr_in_t *)addr_src;
        sockaddr_in_dst = (pt_sockaddr_in_t *)addr_dst;

        if (sockaddr_in_src->sin_port != sockaddr_in_dst->sin_port) {
            return PT_FALSE;
        }
            
        
        if (0 != memcmp(&sockaddr_in_src->sin_addr, &sockaddr_in_dst->sin_addr, 
                            sizeof(sockaddr_in_dst->sin_addr))) {
            return PT_FALSE;
        }
        
    } else {
        sockaddr_in6_src = (pt_sockaddr_in6_t *)addr_src;
        sockaddr_in6_dst = (pt_sockaddr_in6_t *)addr_dst;

        if (sockaddr_in6_src->sin6_port != sockaddr_in6_dst->sin6_port) {
            return PT_FALSE;
        }
            
        
        if (0 != memcmp(&sockaddr_in6_src->sin6_addr, &sockaddr_in6_dst->sin6_addr, 
                            sizeof(sockaddr_in6_dst->sin6_addr))) {
            return PT_FALSE;
        }
    }

    return PT_TRUE;
}

pt_int32_t pt_addr_ne(pt_sockaddr_storage_t *addr_src, pt_sockaddr_storage_t *add_dst)
{
    return !pt_addr_eq(addr_src, add_dst);
}

static pt_char_t pt_char_add(pt_char_t char1, pt_char_t char2, pt_int32_t *carry, pt_int32_t base)
{
    pt_char_t a, b, c;
    static pt_char_t hex_table[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 
                               'a', 'b', 'c', 'd', 'e', 'f'};

    a = (pt_char_t)tolower(char1);
    b = (pt_char_t)tolower(char2);

    if (isdigit(a) && (base == 10 || base == 16))
        a = a - '0';
    else if (isxdigit(a) && base == 16)
        a = (a - 'a') + 0xa;
    else
        a = 0;

    if (isdigit(b) && (base == 10 || base == 16))
        b = b - '0';
    else if (isxdigit(a) && base == 16)
        b = (b - 'a') + 0xa;
    else
        b = 0;

    c = (pt_char_t)(a + b + *carry);

    *carry = (c >= base);

    return hex_table[(c % base)];
}

pt_char_t *pt_str_add(pt_char_t *str1, pt_char_t *str2, pt_char_t *result, pt_int32_t base)
{
    pt_int32_t carry;
    pt_uint32_t i, j;
    pt_uint32_t index_str1, index_str2;
    pt_char_t char1, char2;

    index_str1 = (pt_uint32_t)strlen(str1);
    index_str2 = (pt_uint32_t)strlen(str2);

    carry = 0;
    i = 0;
    while (index_str1 > 0 || index_str2 > 0 || carry) {
        char1 = '0', char2 = '0';
        if (index_str1 > 0)
            char1 = str1[--index_str1];
        if (index_str2 > 0)
            char2 = str2[--index_str2];
        result[i++] = pt_char_add(char1, char2, &carry, base);
    }

    /*revert result*/
    for (j = 0; j < ((pt_uint32_t)i >> 1); j++) {
        char1 = result[j];
        char2 = result[(i - j) - 1];
        result[j] = char2;
        result[(i - j) - 1] = char1;
    }

    result[i] = 0;

    return result;
}

pt_char_t *pt_bytes2str(pt_uint8_t *bytes, pt_int32_t bytes_len, pt_char_t *str, pt_int32_t *str_len)
{
    pt_int32_t i, j;

    for (i = 0, j = 0; i < bytes_len; i++, j += 2) {
        sprintf(&str[j], "%02x", bytes[i]);
    }

    if (str_len != NULL)
        *str_len = j;

    return str;
}

pt_uint8_t *pt_str2bytes(pt_char_t *str, pt_int32_t str_len, pt_uint8_t *bytes, pt_int32_t *bytes_len)
{
    pt_int32_t i, j;
    pt_char_t tmp[3];

    if (str_len & 1) {
        str++;
        str_len--;
    }

    tmp[2] = 0;
    for (i = 0, j = 0; i < str_len; i += 2, j++) {
        tmp[0] = str[i];
        tmp[1] = str[i + 1]; /*lint !e679*/
        bytes[j] = (pt_uint8_t)strtoul(tmp, NULL, 16);
    }

    if (bytes_len != NULL)
        *bytes_len = j;

    return bytes;
}

pt_char_t *pt_bcds2str(pt_uint8_t *bcds, pt_int32_t bcds_len, pt_char_t *str, pt_int32_t *str_len)
{
    pt_int32_t i, j;

    for (i = 0, j = 0; i < bcds_len; i++) {
        if ((i & 1) == 0)
            str[j] = (bcds[i / 2] & 0xf) + '0';
        else 
            str[j] = (bcds[i / 2] >> 4) + '0';
        j++;
    }

    str[j] = 0;
    if (str_len != NULL)
        *str_len = j;

    return str;
}

pt_uint8_t *pt_str2bcds(pt_char_t *str, pt_int32_t str_len, pt_uint8_t *bcds, pt_int32_t *bcds_len)
{
    pt_int32_t i, j;

    for (i = 0, j = 0; i < str_len; i++) {
        if (str[i] < '0' || str[i] > '9')
            break;

        if ((i & 1) == 0) {
            bcds[(i / 2)] = 0xff;
            bcds[(i / 2)] &= (str[i] - '0') | 0xf0;
        }
        else {
            bcds[(i / 2)] &= ((pt_uint8_t)(str[i] - '0') << 4) | 0xf;
            bcds[(i / 2) + 1] = 0xff;
        }
        j++;
    }

    bcds[j / 2] |= 0xf0;
    if (bcds_len != NULL)
        *bcds_len = (pt_uint32_t)(j + 1) >> 1;

    return bcds;
}

pt_int32_t pt_bcdlen(pt_uint8_t *bcds)
{
    pt_int32_t i, j;

    for (i = 0, j = 0;;i++) {
        if ((bcds[i] & 0xf) == 0xf)
            break;
        j++;
        if ((bcds[i] & 0xf0) == 0xf0)
            break;
        j++;
    }
    return j;
}

