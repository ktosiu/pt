#ifndef _asn1_H_
#define _asn1_H_

pt_int32_t pt_asn1_encode_tl(pt_uint8_t t, pt_uint16_t l, void *buf, pt_int32_t pos);
pt_int32_t pt_asn1_encode_v(pt_uint16_t l, void *v, void *buf, pt_int32_t pos);
pt_int32_t pt_asn1_encode_tlv(pt_uint8_t t, pt_uint16_t l, void *v, void *buf, pt_int32_t pos);
pt_int32_t pt_asn1_encode_tl_indef(pt_uint8_t t, pt_uint16_t l, void *buf, pt_int32_t pos);
pt_int32_t pt_asn1_encode_tlv_indef(pt_uint8_t t, pt_uint16_t l, void *v, void *buf, pt_int32_t pos);

pt_int32_t pt_asn1_decode_tl(void *buf, pt_int32_t pos, pt_uint8_t *t, pt_uint16_t *l);
pt_int32_t pt_asn1_decode_v(void *buf, pt_int32_t pos, pt_uint16_t l, void *v);
pt_int32_t pt_asn1_decode_tlv(void *buf, pt_int32_t pos, pt_uint8_t *t, pt_uint16_t *l, void *v);

pt_uint8_t pt_asn1_code_tag(void *buf);

#endif

