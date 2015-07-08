#ifndef _PT_FUNC_H_
#define _PT_FUNC_H_

extern pt_uint16_t pt_addr_af(pt_sockaddr_storage_t *addr);
extern pt_char_t *pt_addr_a(pt_sockaddr_storage_t *addr);
extern void pt_addr_n(pt_uint16_t af, pt_char_t *src, pt_uint16_t port, pt_sockaddr_storage_t *sockaddr);
extern pt_bool_t pt_addr_eq(pt_sockaddr_storage_t *addr_src, pt_sockaddr_storage_t *addr_dst);
extern pt_int32_t pt_addr_ne(pt_sockaddr_storage_t *addr_src, pt_sockaddr_storage_t *add_dst);
extern pt_char_t *pt_str_add(pt_char_t *str1, pt_char_t *str2, pt_char_t *result, pt_int32_t base);
extern pt_char_t *pt_bytes2str(pt_uint8_t *bytes, pt_int32_t bytes_len, pt_char_t *str, pt_int32_t *str_len);
extern pt_uint8_t *pt_str2bytes(pt_char_t *str, pt_int32_t str_len, pt_uint8_t *bytes, pt_int32_t *bytes_len);
extern pt_char_t *pt_bcds2str(pt_uint8_t *bcds, pt_int32_t bcds_len, pt_char_t *str, pt_int32_t *str_len);
extern pt_uint8_t *pt_str2bcds(pt_char_t *str, pt_int32_t str_len, pt_uint8_t *bcds, pt_int32_t *bcds_len);
extern pt_int32_t pt_bcdlen(pt_uint8_t *bcds);

#define CHECK_RESULT(x) \
    do\
    {\
        if (x < 0)\
        {\
            PT_LOG(PTLOG_ERROR, "LINE:%d result(%d)", __LINE__, x);\
            return x;\
        }\
    }while(0)

#endif /*_PT_FUNC_H_*/

