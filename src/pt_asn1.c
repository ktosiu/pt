#include "pt_include.h"

pt_int32_t pt_asn1_encode_len(pt_int32_t len, void *buf, pt_int32_t pos)
{
    if (len < 128)
    {
        *((pt_uint8_t *)buf + (--pos)) = (pt_uint8_t)len;
    }
    else if (len < 256)
    {
        *((pt_uint8_t *)buf + (--pos)) = (pt_uint8_t)len;
        *((pt_uint8_t *)buf + (--pos)) = 0x81;
    }
    else
    {
        *((pt_uint8_t *)buf + (--pos)) = (pt_uint8_t)((len & 0xff));
        *((pt_uint8_t *)buf + (--pos)) = (pt_uint8_t)((len & 0xff00) >> 8);
        *((pt_uint8_t *)buf + (--pos)) = 0x82;
    }

    return pos;
}

pt_int32_t pt_asn1_encode_len_indef(pt_int32_t len, void *buf, pt_int32_t pos)
{
    if (len != 0x80)
    {
        return -1;    
    }

    *((pt_uint8_t *)buf + (--pos)) = (pt_uint8_t)len;

    return pos;
}

pt_int32_t pt_asn1_encode_tag(pt_uint32_t t, void *buf, pt_int32_t pos)
{
    pt_bool_t longtag = PT_FALSE;

    if ((t & 0xff000000) > 0) {
        *((pt_uint8_t *)buf + (--pos)) = (pt_uint8_t)((t & 0xff000000) >> 24);
        longtag = PT_TRUE;
    }

    if ((t & 0x00ff0000) > 0 || longtag) {
        *((pt_uint8_t *)buf + (--pos)) = (pt_uint8_t)((t & 0x00ff0000) >> 16);
        longtag = PT_TRUE;
    }

    if ((t & 0x0000ff00) > 0 || longtag) {
        *((pt_uint8_t *)buf + (--pos)) = (pt_uint8_t)((t & 0x0000ff00) >> 8);
        longtag = PT_TRUE;
    }

    if ((t & 0x000000ff) > 0 || longtag) {
        *((pt_uint8_t *)buf + (--pos)) = (pt_uint8_t)(t & 0x000000ff);
        longtag = PT_TRUE;
    }

    return pos;
}

pt_int32_t pt_asn1_encode_tl(pt_uint32_t t, pt_int32_t l, void *buf, pt_int32_t pos)
{
    pos = pt_asn1_encode_len(l, buf, pos);
    CHECK_RESULT(pos);
    
    pos = pt_asn1_encode_tag(t, buf, pos);
    CHECK_RESULT(pos);

    return pos;
}

pt_int32_t pt_asn1_encode_v(pt_int32_t l, void *v, void *buf, pt_int32_t pos)
{
    pos -= l;
    CHECK_RESULT(pos);

    memcpy((pt_uint8_t *)buf + pos, v, (pt_uint32_t)l);

    return pos;
}

pt_int32_t pt_asn1_encode_tlv(pt_uint32_t t, pt_int32_t l, void *v, void *buf, pt_int32_t pos)
{
    pos = pt_asn1_encode_v(l, v, buf, pos);
    CHECK_RESULT(pos);

    pos = pt_asn1_encode_tl(t, l, buf, pos);
    CHECK_RESULT(pos);

    return pos;
}

pt_int32_t pt_asn1_encode_eoc_indef(pt_int32_t l, void *buf, pt_int32_t pos)
{
    memmove((pt_uint8_t *)buf + pos - 2, (pt_uint8_t *)buf + pos, (pt_uint32_t)l);
    pos -= 2;

    *((pt_uint8_t*)buf + pos + l) = 0x00;
    *((pt_uint8_t*)buf + pos + l + 1) = 0x00;

    return pos;
}

pt_int32_t pt_asn1_encode_tl_indef(pt_uint32_t t, pt_int32_t l, void *buf, pt_int32_t pos)
{
    pos = pt_asn1_encode_eoc_indef(l, buf, pos);
    CHECK_RESULT(pos);

    pos = pt_asn1_encode_len_indef(0x80, buf, pos);
    CHECK_RESULT(pos);
    
    pos = pt_asn1_encode_tag(t, buf, pos);
    CHECK_RESULT(pos);
    
    return pos;
}

pt_int32_t pt_asn1_encode_tlv_indef(pt_uint32_t t, pt_int32_t l, void *v, void *buf, pt_int32_t pos)
{
    pos = pt_asn1_encode_v(l, v, buf, pos);
    CHECK_RESULT(pos);
    
    pos = pt_asn1_encode_tl_indef(t, l, buf, pos);
    CHECK_RESULT(pos);
    
    return pos;
}

pt_int32_t pt_asn1_decode_len(void *buf, pt_int32_t pos, pt_int32_t *len)
{
    pt_uint8_t tmp = *((pt_uint8_t *)buf + pos);

    if (tmp < 128)
    {
        *len = *((pt_uint8_t *)buf + pos++);
    }
    else if (tmp == 0x81)
    {
        pos++;
        *len = *((pt_uint8_t *)buf + pos++);
    }
    else if (tmp == 0x82)
    {
        pos++;
        *len = *((pt_uint8_t *)buf + pos++) * 256;
        *len += *((pt_uint8_t *)buf + pos++);
    }
    else
    {
        return -1;
    }

    return pos;
}

pt_int32_t pt_asn1_decode_tag(void *buf, pt_int32_t pos, pt_uint32_t *t)
{
    *t = *((pt_uint8_t *)buf + pos++);
    if ((*t & 0x1f) == 0x1f) {
        for(; *((pt_uint8_t *)buf + pos) & 0x80; pos++)
            *t = (*t << 8) | *((pt_uint8_t *)buf + pos);
    }
        
    return pos;
}

pt_int32_t pt_asn1_decode_tl(void *buf, pt_int32_t pos, pt_uint32_t *t, pt_int32_t *l)
{
    pos = pt_asn1_decode_tag(buf, pos, t);
    CHECK_RESULT(pos);

    pos = pt_asn1_decode_len(buf, pos, l);
    CHECK_RESULT(pos);

    return pos;
}

pt_int32_t pt_asn1_decode_v(void *buf, pt_int32_t pos, pt_int32_t l, void *v)
{
    memcpy(v, (pt_uint8_t*)buf+pos, (pt_uint32_t)l);
    pos += l;

    return pos;
}

pt_int32_t pt_asn1_decode_tlv(void *buf, pt_int32_t pos, pt_uint32_t *t, pt_int32_t *l, void *v)
{
    pos = pt_asn1_decode_tl(buf, pos, t, l);
    CHECK_RESULT(pos);

    pos = pt_asn1_decode_v(buf, pos, *l, v);
    CHECK_RESULT(pos);

    return pos;
}

pt_uint32_t pt_asn1_code_tag(void *buf)
{
    pt_uint32_t t;
    pt_int32_t pos;

    t = *(pt_uint8_t *)buf;
    if ((t & 0x1f) == 0x1f) {
        for(pos = 1; *((pt_uint8_t *)buf + pos) & 0x80; pos++)
            t = (t << 8) | *((pt_uint8_t *)buf + pos);
    }
        
    return t;
}

pt_int32_t pt_asn1_code_tag_pos(pt_uint32_t tag, pt_uint8_t *code, pt_int32_t len)
{
    pt_int32_t pos = 0, tmp;
    pt_uint32_t t;
    pt_int32_t l;

    while (pos < len) {
        tmp = pos;

        pos = pt_asn1_decode_tl(code, pos, &t, &l);
        if (tag == t)
            return tmp;

        if (t & 0x20) {
            tmp = pos;

            /*嵌套递归*/
            pos = pt_asn1_code_tag_pos(tag, code + pos, l);
            if (-1 != pos)
                return tmp + pos;

            pos = tmp;
        }

        pos += l;
    }

    return -1;
}

