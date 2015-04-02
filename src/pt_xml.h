#ifndef _PT_XML_H
#define _PT_XML_H

pt_int32_t pt_xml_load_cfg(pt_char_t *docname);
pt_int32_t pt_xml_load_uc(pt_char_t *docname);
pt_int32_t pt_xml_load_exec(pt_char_t *docname);
pt_int32_t pt_xml_load_ots(const pt_char_t *cfg, pt_int32_t size);
pt_int32_t pt_xml_load_ots_count(const pt_char_t *cfg, pt_int32_t size);

#endif /*_PT_XML_H*/

