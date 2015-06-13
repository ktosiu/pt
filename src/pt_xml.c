#include "pt_include.h"
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

void pt_xml_load_cfg_diamlink_conn(xmlDocPtr doc, xmlNodePtr cur, diam_link_id_t diam_link_id)
{
    xmlChar *prop;
    pt_int32_t protocol = -1;
    pt_int32_t service = -1;
    pt_char_t localip[128] = {0};
    pt_uint16_t localport = 0;
    pt_char_t remoteip[128] = {0};
    pt_uint16_t remoteport = 0;

    prop = xmlGetProp(cur, (const xmlChar *)"protocol");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is protocol = %s.", (pt_char_t *)prop);
        if (xmlStrEqual(prop, (const xmlChar *)"sctp"))
            protocol = PT_PROTOCOL_SCTP;
        else
            protocol = PT_PROTOCOL_TCP;

        xmlFree(prop);
    }

    prop = xmlGetProp(cur, (const xmlChar *)"service");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is service = %s.", (pt_char_t *)prop);
        if (xmlStrEqual(prop, (const xmlChar *)"client"))
            service = PT_SERVICE_CLI;
        else
            service = PT_SERVICE_SRV;

        xmlFree(prop);
    }

    prop = xmlGetProp(cur, (const xmlChar *)"localip");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is localip = %s.", (pt_char_t *)prop);
        strcpy(localip, (pt_char_t *)prop);
        xmlFree(prop);
    }

    prop = xmlGetProp(cur, (const xmlChar *)"localport");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is localport = %s.", (pt_char_t *)prop);
        localport = (pt_uint16_t)atoi((pt_char_t *)prop);
        xmlFree(prop);
    }

    prop = xmlGetProp(cur, (const xmlChar *)"remoteip");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is remoteip = %s.", (pt_char_t *)prop);
        strcpy(remoteip, (pt_char_t *)prop);
        xmlFree(prop);
    }

    prop = xmlGetProp(cur, (const xmlChar *)"remoteport");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is remoteport = %s.", (pt_char_t *)prop);
        remoteport = (pt_uint16_t)atoi((pt_char_t *)prop);
        xmlFree(prop);
    }

    pt_diam_add_conn(diam_link_id, protocol, service, localip, localport, remoteip, remoteport);
}

void pt_xml_load_cfg_diamlink(xmlDocPtr doc, xmlNodePtr cur)
{
    xmlChar *prop;
    pt_uint32_t linkid = (pt_uint32_t)-1;
    pt_char_t localhost[128] = {0};
    pt_char_t localrealm[128] = {0};
    pt_char_t remotehost[128] = {0};
    pt_char_t remoterealm[128] = {0};
    diam_link_id_t diam_link_id;

    prop = xmlGetProp(cur, (const xmlChar *)"linkid");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is linkid = %s.", (pt_char_t *)prop);
        linkid = atoi((pt_char_t *)prop);
        xmlFree(prop);
    }

    prop = xmlGetProp(cur, (const xmlChar *)"localhost");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is localhost = %s.", (pt_char_t *)prop);
        strcpy(localhost, (pt_char_t *)prop);
        xmlFree(prop);
    }

    prop = xmlGetProp(cur, (const xmlChar *)"localrealm");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is localrealm = %s.", (pt_char_t *)prop);
        strcpy(localrealm, (pt_char_t *)prop);
        xmlFree(prop);
    }

    prop = xmlGetProp(cur, (const xmlChar *)"remotehost");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is remotehost = %s.", (pt_char_t *)prop);
        strcpy(remotehost, (pt_char_t *)prop);
        xmlFree(prop);
    }

    prop = xmlGetProp(cur, (const xmlChar *)"remoterealm");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is remoterealm = %s.", (pt_char_t *)prop);
        strcpy(remoterealm, (pt_char_t *)prop);
        xmlFree(prop);
    }

    diam_link_id = pt_diam_add_link(linkid, localhost, localrealm, remotehost, remoterealm);

    cur = cur->xmlChildrenNode;
    while (cur != NULL) {
        if (xmlStrEqual(cur->name, (const xmlChar *)"diamconn")) {
            PT_LOG(PTLOG_DEBUG, "load diamlink_conn.");
            pt_xml_load_cfg_diamlink_conn(doc, cur, diam_link_id);
        }
        cur = cur->next;
    }
}

void pt_xml_load_cfg_ss7office_as_asp(xmlDocPtr doc, xmlNodePtr cur, m3ua_as_id_t m3ua_as_id)
{
    xmlChar *prop;
    pt_int32_t protocol = -1;
    pt_int32_t service = -1;
    pt_char_t localip[128] = {0};
    pt_uint16_t localport = 0;
    pt_char_t remoteip[128] = {0};
    pt_uint16_t remoteport = 0;

    prop = xmlGetProp(cur, (const xmlChar *)"protocol");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is protocol = %s.", (pt_char_t *)prop);
        if (xmlStrEqual(prop, (const xmlChar *)"sctp"))
            protocol = PT_PROTOCOL_SCTP;
        else
            protocol = PT_PROTOCOL_TCP;

        xmlFree(prop);
    }

    prop = xmlGetProp(cur, (const xmlChar *)"service");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is service = %s.", (pt_char_t *)prop);
        if (xmlStrEqual(prop, (const xmlChar *)"client"))
            service = PT_SERVICE_CLI;
        else
            service = PT_SERVICE_SRV;

        xmlFree(prop);
    }

    prop = xmlGetProp(cur, (const xmlChar *)"localip");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is localip = %s.", (pt_char_t *)prop);
        strcpy(localip, (pt_char_t *)prop);
        xmlFree(prop);
    }

    prop = xmlGetProp(cur, (const xmlChar *)"localport");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is localport = %s.", (pt_char_t *)prop);
        localport = (pt_uint16_t)atoi((pt_char_t *)prop);
        xmlFree(prop);
    }

    prop = xmlGetProp(cur, (const xmlChar *)"remoteip");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is remoteip = %s.", (pt_char_t *)prop);
        strcpy(remoteip, (pt_char_t *)prop);
        xmlFree(prop);
    }

    prop = xmlGetProp(cur, (const xmlChar *)"remoteport");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is remoteport = %s.", (pt_char_t *)prop);
        remoteport = (pt_uint16_t)atoi((pt_char_t *)prop);
        xmlFree(prop);
    }

    pt_m3ua_add_asp(m3ua_as_id, protocol, service, localip, localport, remoteip, remoteport);
}

void pt_xml_load_cfg_ss7office_as(xmlDocPtr doc, xmlNodePtr cur, ss7office_id_t ss7office_id)
{
    xmlChar *prop;
    pt_int32_t useage = -1;
    pt_uint32_t n = 1;
    pt_uint32_t mode = 1;
    pt_uint8_t netapp_flag = 0;
    pt_uint32_t netapp = 0;
    pt_uint8_t route_context_flag = 0;
    pt_uint32_t route_context = 0;
    m3ua_as_id_t m3ua_as_id;

    prop = xmlGetProp(cur, (const xmlChar *)"service");
    if (prop != NULL) {
        if (xmlStrEqual(prop, (const xmlChar *)"client"))
            useage = M3UA_AS_CLIENT;
        else/* if (xmlStrEqual(prop, (const xmlChar *)"server"))*/
            useage = M3UA_AS_SERVER;
        xmlFree(prop);
    }

    prop = xmlGetProp(cur, (const xmlChar *)"n");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is n = %s.", (pt_char_t *)prop);
        n = atoi((pt_char_t *)prop);
        xmlFree(prop);
    }

    prop = xmlGetProp(cur, (const xmlChar *)"mode");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is mode = %s.", (pt_char_t *)prop);
        if (xmlStrEqual(prop, (const xmlChar *)"loadshare"))
            mode = M3UA_TRAFFIC_LOADSHARE;
        else if (xmlStrEqual(prop, (const xmlChar *)"overload"))
            mode = M3UA_TRAFFIC_OVERLOAD;
        else if (xmlStrEqual(prop, (const xmlChar *)"broadcast"))
            mode = M3UA_TRAFFIC_BROADCAST;
        xmlFree(prop);
    }

    prop = xmlGetProp(cur, (const xmlChar *)"netapp");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is netapp = %s.", (pt_char_t *)prop);
        netapp_flag = 1;
        netapp = atoi((pt_char_t *)prop);
        xmlFree(prop);
    }

    prop = xmlGetProp(cur, (const xmlChar *)"route_context");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is route_context = %s.", (pt_char_t *)prop);
        route_context_flag = 1;
        route_context = atoi((pt_char_t *)prop);
        xmlFree(prop);
    }

    m3ua_as_id = pt_m3ua_add_as(ss7office_id,
                        useage, n, mode,
                        netapp_flag, netapp,
                        route_context_flag, route_context);

    cur = cur->xmlChildrenNode;
    while (cur != NULL) {
        if (xmlStrEqual(cur->name, (const xmlChar *)"asp")) {
            PT_LOG(PTLOG_DEBUG, "load asp.");
            pt_xml_load_cfg_ss7office_as_asp(doc, cur, m3ua_as_id);
        }
        cur = cur->next;
    }
}

void pt_xml_load_cfg_ss7office(xmlDocPtr doc, xmlNodePtr cur)
{
    xmlChar *prop;
    pt_uint32_t officeid = (pt_uint32_t)-1;
    pt_uint8_t spctype = 24;
    pt_char_t dpc[64] = {0};
    pt_char_t opc[64] = {0};
    ss7office_id_t ss7office_id;

    prop = xmlGetProp(cur, (const xmlChar *)"officeid");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is officeid = %s.", (pt_char_t *)prop);
        officeid = atoi((pt_char_t *)prop);
        xmlFree(prop);
    }

    prop = xmlGetProp(cur, (const xmlChar *)"spctype");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is spctype = %s.", (pt_char_t *)prop);
        spctype = atoi((pt_char_t *)prop);
        xmlFree(prop);
    }

    prop = xmlGetProp(cur, (const xmlChar *)"opc");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is opc = %s.", (pt_char_t *)prop);
        strcpy(opc, (pt_char_t *)prop);
        xmlFree(prop);
    }

    prop = xmlGetProp(cur, (const xmlChar *)"dpc");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is dpc = %s.", (pt_char_t *)prop);
        strcpy(dpc, (pt_char_t *)prop);
        xmlFree(prop);
    }

    ss7office_id = pt_m3ua_add_ss7office(officeid, spctype, dpc, opc);

    cur = cur->xmlChildrenNode;
    while (cur != NULL) {
        if (xmlStrEqual(cur->name, (const xmlChar *)"as")) {
            PT_LOG(PTLOG_DEBUG, "load as.");
            pt_xml_load_cfg_ss7office_as(doc, cur, ss7office_id);
        }
        cur = cur->next;
    }
}

pt_int32_t pt_xml_load_cfg_link(xmlDocPtr doc, xmlNodePtr cur)
{
    cur = cur->xmlChildrenNode;
    while (cur != NULL) {
        if (xmlStrEqual(cur->name, (const xmlChar *)"diamlink")) {
            PT_LOG(PTLOG_DEBUG, "load diamlink.");
            pt_xml_load_cfg_diamlink(doc, cur);
        } else if (xmlStrEqual(cur->name, (const xmlChar *)"ss7office")) {
            PT_LOG(PTLOG_DEBUG, "load ss7office.");
            pt_xml_load_cfg_ss7office(doc, cur);
        }
        cur = cur->next;
    }

    return 0;
}

pt_int32_t pt_xml_load_cfg(pt_char_t *docname)
{
    xmlDocPtr doc;
    xmlNodePtr cur;

    doc = xmlParseFile(docname);
    if (doc == NULL ) {
        PT_LOG(PTLOG_ERROR, "parse file failed, docname = %s!", docname);
        return - 0xff;
    }

    cur = xmlDocGetRootElement(doc);
    if (cur == NULL) {
        PT_LOG(PTLOG_ERROR, "get root element failed, docname = %s!", docname);
        xmlFreeDoc(doc);
        return -0xfe;
    }

    if (!xmlStrEqual(cur->name, (const xmlChar *) "cfg")) {
        PT_LOG(PTLOG_ERROR, "there is not cfg tag, docname = %s!", docname);
        xmlFreeDoc(doc);
        return -0xfd;
    }

    cur = cur->xmlChildrenNode;
    while (cur != NULL) {
        if (xmlStrEqual(cur->name, (const xmlChar *)"link")) {
            PT_LOG(PTLOG_DEBUG, "load link.");
            pt_xml_load_cfg_link(doc, cur);
            break;
        }
        cur = cur->next;
    }

    xmlFreeDoc(doc);
    return 0;
}

pt_int32_t pt_xml_load_exec_param(xmlDocPtr doc, xmlNodePtr cur)
{
    xmlChar *prop;
    pt_char_t msgflow_name[64] = {0};
    pt_char_t action[64] = {0};
    pt_uint64_t count = 0;
    pt_uint64_t rate = 0;
    pt_uint64_t times = 0;
    pt_uint32_t delay = 0;
    pt_uc_msgflow_id_t msgflow_id;

    prop = xmlGetProp(cur, (const xmlChar *)"msgflow");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is msgflow = %s.", (pt_char_t *)prop);
        strcpy(msgflow_name, (pt_char_t *)prop);
        xmlFree(prop);
    }

    prop = xmlGetProp(cur, (const xmlChar *)"action");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is action = %s.", (pt_char_t *)prop);
        strcpy(action, (pt_char_t *)prop);
        xmlFree(prop);
    }

    prop = xmlGetProp(cur, (const xmlChar *)"count");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is count = %s.", (pt_char_t *)prop);
        count = atoi((pt_char_t *)prop);
        xmlFree(prop);
    }

    prop = xmlGetProp(cur, (const xmlChar *)"rate");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is rate = %s.", (pt_char_t *)prop);
        rate = atoi((pt_char_t *)prop);
        xmlFree(prop);
    }

    prop = xmlGetProp(cur, (const xmlChar *)"times");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is times = %s.", (pt_char_t *)prop);
        times = atoi((pt_char_t *)prop);
        xmlFree(prop);
    }

    prop = xmlGetProp(cur, (const xmlChar *)"delay");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is delay = %s.", (pt_char_t *)prop);
        delay = atoi((pt_char_t *)prop);
        xmlFree(prop);
    }

    msgflow_id = pt_uc_locate_msgflow(msgflow_name);
    if (msgflow_id == NULL) {
        PT_LOG(PTLOG_ERROR, "locate msgflow id faile name = %s.", msgflow_name);
        return -0xff;
    }

    if (xmlStrEqual((const xmlChar *)"start", (const xmlChar *)action))
        pt_task_start(msgflow_id, count, rate, times, delay);
    else if (xmlStrEqual((const xmlChar *)"stop", (const xmlChar *)action))
        pt_task_stop(msgflow_id);
    else if (xmlStrEqual((const xmlChar *)"pause", (const xmlChar *)action))
        pt_task_pause(msgflow_id);
    else if (xmlStrEqual((const xmlChar *)"continue", (const xmlChar *)action))
        pt_task_continue(msgflow_id);
    else if (xmlStrEqual((const xmlChar *)"update", (const xmlChar *)action))
        pt_task_update(msgflow_id, count, rate, times);

    return 0;
}

pt_int32_t pt_xml_load_exec_execute(xmlDocPtr doc, xmlNodePtr cur)
{

    cur = cur->xmlChildrenNode;
    while (cur != NULL) {
        if (xmlStrEqual(cur->name, (const xmlChar *)"param")) {
            PT_LOG(PTLOG_DEBUG, "load param.");
            pt_xml_load_exec_param(doc, cur);
        }
        cur = cur->next;
    }

    return 0;
}

pt_int32_t pt_xml_load_exec(pt_char_t *docname)
{
    xmlDocPtr doc;
    xmlNodePtr cur;

    doc = xmlParseFile(docname);
    if (doc == NULL ) {
        PT_LOG(PTLOG_ERROR, "parse file failed, docname = %s!", docname);
        return - 0xff;
    }

    cur = xmlDocGetRootElement(doc);
    if (cur == NULL) {
        PT_LOG(PTLOG_ERROR, "get root element failed, docname = %s!", docname);
        xmlFreeDoc(doc);
        return -0xfe;
    }

    if (!xmlStrEqual(cur->name, (const xmlChar *) "cfg")) {
        PT_LOG(PTLOG_ERROR, "there is not cfg tag, docname = %s!", docname);
        xmlFreeDoc(doc);
        return -0xfd;
    }

    cur = cur->xmlChildrenNode;
    while (cur != NULL) {
        if (xmlStrEqual(cur->name, (const xmlChar *)"exec")) {
            PT_LOG(PTLOG_DEBUG, "load exec.");
            pt_xml_load_exec_execute(doc, cur);
            break;
        }
        cur = cur->next;
    }

    xmlFreeDoc(doc);
    return 0;
}

static pt_int32_t pt_xml_load_uc_matchinfo(xmlDocPtr doc, xmlNodePtr cur,
                        pt_char_t *strtag, pt_int32_t *type, pt_uint8_t *data, pt_int32_t *data_len)
{
    xmlChar *prop;
    prop = xmlGetProp(cur, (const xmlChar *)"tag");
    if (prop == NULL) {
        PT_LOG(PTLOG_ERROR, "there is not tag tag.");
        return -0xff;
    }
    strcpy(strtag, (pt_char_t *)prop);
    xmlFree(prop);

    prop = xmlGetProp(cur, (const xmlChar *)"type");
    if (prop == NULL) {
        PT_LOG(PTLOG_ERROR, "there is not type tag.");
        return -0xff;
    }
    if (xmlStrEqual(prop, (const xmlChar *)"str"))
        *type = PT_UC_DATA_STR;
    else if (xmlStrEqual(prop, (const xmlChar *)"ipv4"))
        *type = PT_UC_DATA_IPV4;
    else if (xmlStrEqual(prop, (const xmlChar *)"ipv6"))
        *type = PT_UC_DATA_IPV6;
    else if (xmlStrEqual(prop, (const xmlChar *)"bcd"))
        *type = PT_UC_DATA_BCD;
    else /*if (xmlStrEqual(prop, (const xmlChar *)"byte"))*/
        *type = PT_UC_DATA_BYTE;
    xmlFree(prop);

    prop = xmlGetProp(cur, (const xmlChar *)"data");
    if (prop == NULL) {
        PT_LOG(PTLOG_ERROR, "there is not data tag.");
        return -0xff;
    }
    if (*type == PT_UC_DATA_STR) {
        strcpy((pt_char_t *)data, (pt_char_t *)prop);
        *data_len = strlen((pt_char_t *)data);
    } else if (*type == PT_UC_DATA_BCD){
        *data_len = sizeof(data);
        pt_str2bcds((pt_char_t *)prop, xmlStrlen(prop), data, data_len);
    } else {
        *data_len = sizeof(data);
        pt_str2bytes((pt_char_t *)prop, xmlStrlen(prop), data, data_len);
    }
    xmlFree(prop);

    return 0;
}

pt_int32_t pt_xml_load_uc_msg_uid(xmlDocPtr doc, xmlNodePtr cur, pt_uc_msg_id_t msg_id)
{
    pt_char_t strtag[64];
    pt_int32_t type;
    pt_uint8_t data[1024];
    pt_int32_t data_len;

    if (pt_xml_load_uc_matchinfo(doc, cur, strtag, &type, data, &data_len) < 0) {
        PT_LOG(PTLOG_ERROR, "load uid failed!");
        return -0xff;
    }

    pt_uc_add_msg_uid(msg_id, type, (pt_char_t *)data, data_len, strtag);

    return 0;
}

pt_int32_t pt_xml_load_uc_msg_replace(xmlDocPtr doc, xmlNodePtr cur, pt_uc_msg_id_t msg_id)
{
    pt_char_t strtag[64];
    pt_int32_t type;
    pt_uint8_t data[1024];
    pt_int32_t data_len;

    if (pt_xml_load_uc_matchinfo(doc, cur, strtag, &type, data, &data_len) < 0) {
        PT_LOG(PTLOG_ERROR, "load replace failed!");
        return -0xff;
    }

    pt_uc_add_msg_replace(msg_id, type, (pt_char_t *)data, data_len, strtag);

    return 0;
}

pt_int32_t pt_xml_load_uc_msg_condition(xmlDocPtr doc, xmlNodePtr cur, pt_uc_msg_id_t msg_id)
{
    pt_char_t strtag[64];
    pt_int32_t type;
    pt_uint8_t data[1024];
    pt_int32_t data_len;

    if (pt_xml_load_uc_matchinfo(doc, cur, strtag, &type, data, &data_len) < 0) {
        PT_LOG(PTLOG_ERROR, "load replace failed!");
        return -0xff;
    }

    pt_uc_add_msg_condition(msg_id, type, (pt_char_t *)data, data_len, strtag);

    return 0;
}

pt_int32_t pt_xml_load_uc_diam_msg_para(xmlDocPtr doc, xmlNodePtr cur, pt_uc_msg_id_t msg_id)
{
    xmlChar *prop;
    pt_uint32_t msg_linkid = 0;

    prop = xmlGetProp(cur, (const xmlChar *)"linkid");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is linkid = %s.", (pt_char_t *)prop);
        msg_linkid = atoi((pt_char_t *)prop);
        xmlFree(prop);
    }

    pt_uc_set_msg_linkid(msg_id, msg_linkid);

    cur = cur->xmlChildrenNode;
    while (cur != NULL) {
        if (xmlStrEqual(cur->name, (const xmlChar *)"uid")) {
            PT_LOG(PTLOG_DEBUG, "load msg uid.");
            pt_xml_load_uc_msg_uid(doc, cur, msg_id);
        } else if (xmlStrEqual(cur->name, (const xmlChar *)"replace")) {
            PT_LOG(PTLOG_DEBUG, "load msg replace.");
            pt_xml_load_uc_msg_replace(doc, cur, msg_id);
        } else if (xmlStrEqual(cur->name, (const xmlChar *)"condition")) {
            PT_LOG(PTLOG_DEBUG, "load msg condition.");
            pt_xml_load_uc_msg_condition(doc, cur, msg_id);
        }
        cur = cur->next;
    }

    return 0;
}

pt_int32_t pt_xml_load_uc_ss7_msg_para(xmlDocPtr doc, xmlNodePtr cur, pt_uc_msg_id_t msg_id)
{
    xmlChar *prop;
    pt_uint8_t acver = 0;
    pt_uint8_t acvalue = 0;
    pt_uint8_t comptype = 0;
    pt_uint8_t opcode = 0;
    pt_char_t cda_code[64] = {0};
    pt_uint8_t cda_ssn = 0;
    pt_char_t cga_code[64] = {0};
    pt_uint8_t cga_ssn = 0;
    pt_uint32_t msg_linkid = 0;

    prop = xmlGetProp(cur, (const xmlChar *)"officeid");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is officeid = %s.", (pt_char_t *)prop);
        msg_linkid = atoi((pt_char_t *)prop);
        xmlFree(prop);
    }

    pt_uc_set_msg_linkid(msg_id, msg_linkid);

    prop = xmlGetProp(cur, (const xmlChar *)"acver");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is acver = %s.", (pt_char_t *)prop);
        acver = atoi((pt_char_t *)prop);
        xmlFree(prop);
    }

    prop = xmlGetProp(cur, (const xmlChar *)"acvalue");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is acvalue = %s.", (pt_char_t *)prop);
        acvalue = atoi((pt_char_t *)prop);
        xmlFree(prop);
    }

    prop = xmlGetProp(cur, (const xmlChar *)"opcode");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is opcode = %s.", (pt_char_t *)prop);
        opcode = atoi((pt_char_t *)prop);
        xmlFree(prop);
    }

    prop = xmlGetProp(cur, (const xmlChar *)"comptype");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is comptype = %s.", (pt_char_t *)prop);
        if (xmlStrEqual(prop, (const xmlChar *)"ack"))
            comptype = 1;
        else
            comptype = 0;
        xmlFree(prop);
    }

    prop = xmlGetProp(cur, (const xmlChar *)"cda_code");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is cda_code = %s.", (pt_char_t *)prop);
        strcpy(cda_code, (pt_char_t *)prop);
        xmlFree(prop);
    }

    prop = xmlGetProp(cur, (const xmlChar *)"cda_ssn");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is cda_ssn = %s.", (pt_char_t *)prop);
        cda_ssn = atoi((pt_char_t *)prop);
        xmlFree(prop);
    }

    prop = xmlGetProp(cur, (const xmlChar *)"cga_code");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is cga_code = %s.", (pt_char_t *)prop);
        strcpy(cga_code, (pt_char_t *)prop);
        xmlFree(prop);
    }

    prop = xmlGetProp(cur, (const xmlChar *)"cga_ssn");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is cga_ssn = %s.", (pt_char_t *)prop);
        cga_ssn = atoi((pt_char_t *)prop);
        xmlFree(prop);
    }

    pt_uc_set_msg_param_ss7(msg_id, acver, acvalue, comptype, opcode,
                    cda_code, cda_ssn, cga_code, cga_ssn);

    cur = cur->xmlChildrenNode;
    while (cur != NULL) {
        if (xmlStrEqual(cur->name, (const xmlChar *)"uid")) {
            PT_LOG(PTLOG_DEBUG, "load msg uid.");
            pt_xml_load_uc_msg_uid(doc, cur, msg_id);
        } else if (xmlStrEqual(cur->name, (const xmlChar *)"replace")) {
            PT_LOG(PTLOG_DEBUG, "load msg replace.");
            pt_xml_load_uc_msg_replace(doc, cur, msg_id);
        } else if (xmlStrEqual(cur->name, (const xmlChar *)"condition")) {
            PT_LOG(PTLOG_DEBUG, "load msg condition.");
            pt_xml_load_uc_msg_condition(doc, cur, msg_id);
        }
        cur = cur->next;
    }

    return 0;
}

pt_int32_t pt_xml_load_uc_msg(xmlDocPtr doc, xmlNodePtr cur, pt_uc_inst_id_t inst_id)
{
    xmlChar *prop;
    pt_char_t *msg_name;
    pt_int32_t msg_action;
    pt_int32_t msg_type;
    pt_uint8_t msg_data[(32 * 1024)] = {0};
    pt_int32_t msg_data_len;
    pt_uc_msg_id_t msg_id;

    prop = xmlGetProp(cur, (const xmlChar *)"action");
    if (prop == NULL) {
        PT_LOG(PTLOG_ERROR, "there is not action tag.");
        return -0xff;
    }
    if (xmlStrEqual(prop, (const xmlChar *)"send"))
        msg_action = MSG_ACTION_SEND;
    else/* if (xmlStrEqual(prop, (const xmlChar *)"recv"))*/
        msg_action = MSG_ACTION_RECEIVE;
    xmlFree(prop);

    prop = xmlGetProp(cur, (const xmlChar *)"type");
    if (prop == NULL) {
        PT_LOG(PTLOG_ERROR, "there is not type tag.");
        return -0xfe;
    }
    if (xmlStrEqual(prop, (const xmlChar *)"diam"))
        msg_type = MSG_TYPE_DIM;
    else/* if (xmlStrEqual(prop, (const xmlChar *)"ss7"))*/
        msg_type = MSG_TYPE_SS7;
    xmlFree(prop);

    prop = xmlGetProp(cur, (const xmlChar *)"data");
    if (prop == NULL) {
        PT_LOG(PTLOG_ERROR, "there is not data tag.");
        return -0xfd;
    }
    msg_data_len = sizeof(msg_data);
    pt_str2bytes((pt_char_t *)prop, xmlStrlen(prop), msg_data, &msg_data_len);
    xmlFree(prop);

    prop = xmlGetProp(cur, (const xmlChar *)"name");
    if (prop == NULL) {
        PT_LOG(PTLOG_ERROR, "there is not name = %s.");
        return -0xfc;
    }
    PT_LOG(PTLOG_DEBUG, "there is name = %s.", ((pt_char_t *)prop));
    msg_name = (pt_char_t *)prop;
    msg_id = pt_uc_add_msg(inst_id, msg_name, msg_action, msg_type, msg_data, msg_data_len);
    xmlFree(prop);
    if (msg_id == NULL) {
        PT_LOG(PTLOG_ERROR, "add msg failed!");
        return -0xfc;
    }

    /*load msg parameter*/
    if (msg_type == MSG_TYPE_DIM)
        return pt_xml_load_uc_diam_msg_para(doc, cur, msg_id);
    else
        return pt_xml_load_uc_ss7_msg_para(doc, cur, msg_id);
}

pt_int32_t pt_xml_load_uc_inst(xmlDocPtr doc, xmlNodePtr cur, pt_uc_msgflow_id_t msgflow_id)
{
    xmlChar *prop;
    pt_char_t *inst_name;
    pt_uc_inst_id_t inst_id;

    prop = xmlGetProp(cur, (const xmlChar *)"name");
    if (prop == NULL) {
        PT_LOG(PTLOG_ERROR, "there is not names.");
        return -0xff;
    }
    PT_LOG(PTLOG_DEBUG, "there is name = %s.", (pt_char_t *)prop);
    inst_name = (pt_char_t *)prop;
    inst_id = pt_uc_add_inst(msgflow_id, inst_name);
    xmlFree(prop);
    if (NULL == inst_id) {
        PT_LOG(PTLOG_ERROR, "add msg inst failed!");
        return -0xfe;
    }

    cur = cur->xmlChildrenNode;
    while (cur != NULL) {
        if (xmlStrEqual(cur->name, (const xmlChar *)"msg")) {
            PT_LOG(PTLOG_DEBUG, "load msg in inst.");
            pt_xml_load_uc_msg(doc, cur, inst_id);
        }
        cur = cur->next;
    }

    return 0;
}

pt_int32_t pt_xml_load_uc_msgflow(xmlDocPtr doc, xmlNodePtr cur)
{
    xmlChar *prop;
    pt_char_t *msgflow_name;
    pt_uint32_t delay = 0;
    pt_uc_msgflow_id_t msgflow_id;

    prop = xmlGetProp(cur, (const xmlChar *)"delay");
    if (prop != NULL) {
        PT_LOG(PTLOG_DEBUG, "there is delay = %s.", (pt_char_t *)prop);
        delay = atoi((pt_char_t *)prop);
        xmlFree(prop);
    }

    prop = xmlGetProp(cur, (const xmlChar *)"name");
    if (prop == NULL) {
        PT_LOG(PTLOG_ERROR, "there is not name.");
        return -0xff;
    }
    PT_LOG(PTLOG_DEBUG, "there is name = %s.", (pt_char_t *)prop);
    msgflow_name = (pt_char_t *)prop;
    msgflow_id = pt_uc_add_msgflow(msgflow_name, delay);
    xmlFree(prop);
    if (NULL == msgflow_id) {
        PT_LOG(PTLOG_DEBUG, "add msg flow faileds!");
        return -0xfe;
    }

    cur = cur->xmlChildrenNode;
    while (cur != NULL) {
        if ((xmlStrEqual(cur->name, (const xmlChar *)"inst"))) {
            PT_LOG(PTLOG_DEBUG, "load inst in msgflow.");
            pt_xml_load_uc_inst(doc, cur, msgflow_id);
        }
        cur = cur->next;
    }

    return 0;
}

pt_int32_t pt_xml_load_uc_usecase(xmlDocPtr doc, xmlNodePtr cur)
{
    cur = cur->xmlChildrenNode;
    while (cur != NULL) {
        if ((xmlStrEqual(cur->name, (const xmlChar *)"msgflow"))) {
            PT_LOG(PTLOG_DEBUG, "load msgflow.");
            pt_xml_load_uc_msgflow(doc, cur);
        }
        cur = cur->next;
    }

    return 0;
}

pt_int32_t pt_xml_load_uc(pt_char_t *docname)
{
    xmlDocPtr doc;
    xmlNodePtr cur;

    doc = xmlParseFile(docname);
    if (doc == NULL ) {
        PT_LOG(PTLOG_ERROR, "parse file failed, docname = %s!", docname);
        return - 0xff;
    }

    cur = xmlDocGetRootElement(doc);
    if (cur == NULL) {
        PT_LOG(PTLOG_ERROR, "get root element failed, docname = %s!", docname);
        xmlFreeDoc(doc);
        return -0xfe;
    }

    if (!xmlStrEqual(cur->name, (const xmlChar *) "cfg")) {
        PT_LOG(PTLOG_ERROR, "there is not cfg tag, docname = %s!", docname);
        xmlFreeDoc(doc);
        return -0xfd;
    }

    cur = cur->xmlChildrenNode;
    while (cur != NULL) {
        if (xmlStrEqual(cur->name, (const xmlChar *)"usecase")) {
            PT_LOG(PTLOG_DEBUG, "load uc.");
            pt_xml_load_uc_usecase(doc, cur);
            break;
        }
        cur = cur->next;
    }

    xmlFreeDoc(doc);
    return 0;
}

pt_int32_t pt_xml_load_ots(const pt_char_t *cfg, pt_int32_t size)
{
    xmlDocPtr doc;
    xmlNodePtr cur = NULL;
    xmlChar *prop;

    doc = xmlReadMemory(cfg, size, "utf8", NULL, 0);
    if(doc == NULL) {
        PT_LOG(PTLOG_ERROR, "read memory failed!");
        return -0xff;
    }

    cur = xmlDocGetRootElement(doc);
    if(cur == NULL) {
        PT_LOG(PTLOG_ERROR, "get root element failed!");
        xmlFreeDoc(doc);
        return -0xfe;
    }

    if(!xmlStrEqual(cur->name, (const xmlChar *)"config")) {
        PT_LOG(PTLOG_ERROR, "there is not config tag!");
        xmlFreeDoc(doc);
        return -0xfd;
    }

    cur = cur->xmlChildrenNode;
    while (cur != NULL) {
        if (xmlStrEqual(cur->name, (const xmlChar *)"link")) {
            PT_LOG(PTLOG_DEBUG, "load link.");
            pt_xml_load_cfg_link(doc, cur);
        } else if (xmlStrEqual(cur->name, (const xmlChar *)"usecase")) {
            prop = xmlGetProp(cur, (const xmlChar *)"filepath");
            if (prop != NULL) {
                PT_LOG(PTLOG_DEBUG, "there is filepath = %s.", (pt_char_t *)prop);
                pt_xml_load_uc((pt_char_t *)prop);
                xmlFree(prop);
            }
        }
        cur = cur->next;
    }

    xmlFreeDoc(doc);
    return 0;
}

/*加载OTS一轮执行多少用户数*/
pt_int32_t pt_xml_load_ots_count(const pt_char_t *cfg, pt_int32_t size)
{
    xmlDocPtr doc;
    xmlNodePtr cur = NULL;
    xmlChar *prop;
    pt_int32_t count;

    count = 0;
    do {
        doc = xmlReadMemory(cfg, size, "utf8", NULL, 0);
        if(doc == NULL) {
            PT_LOG(PTLOG_ERROR, "read memory failed!");
            break;
        }

        cur = xmlDocGetRootElement(doc);
        if(cur == NULL) {
            PT_LOG(PTLOG_ERROR, "get root element failed!");
            xmlFreeDoc(doc);
            break;
        }

        if(!xmlStrEqual(cur->name, (const xmlChar *)"config")) {
            PT_LOG(PTLOG_ERROR, "there is not config tag!");
            xmlFreeDoc(doc);
            break;
        }

        cur = cur->xmlChildrenNode;
        while (cur != NULL) {
            if (xmlStrEqual(cur->name, (const xmlChar *)"usecase")) {
                prop = xmlGetProp(cur, (const xmlChar *)"count");
                if (prop != NULL) {
                    count = atoi((pt_char_t *)prop);
                    xmlFree(prop);
                }
            }
            cur = cur->next;
        }
        xmlFreeDoc(doc);
    } while (0);

    return count;
}
