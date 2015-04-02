#ifndef _PT_LOG_H
#define _PT_LOG_H

typedef enum
{
    PTLOG_DEBUG,
    PTLOG_INFO,
    PTLOG_ERROR,
    PTLOG_INVALID,
}pt_log_level_e;

typedef struct pt_loginfo_s
{
    pt_uint8_t      *level;
    pt_int32_t      line;
    pt_uint8_t      *file;
    pt_uint8_t      *func;
}pt_loginfo_t;

extern pt_log_level_e _log_level;

void pt_log_set_level(pt_log_level_e log_level);
void pt_log(pt_loginfo_t *pt_loginfo, pt_char_t *format, ...);

#define PT_LOG(_level, _format...)\
    do {\
        pt_loginfo_t _pt_loginfo;\
        if (_level < _log_level) {\
            break;\
        }\
        _pt_loginfo.level = (pt_uint8_t *)#_level;\
        _pt_loginfo.line  = (pt_int32_t)__LINE__;\
        _pt_loginfo.file  = (pt_uint8_t *)__FILE__;\
        _pt_loginfo.func  = (pt_uint8_t *)__func__;\
        pt_log(&_pt_loginfo, ##_format);\
    }while(0)

#endif /*_PT_LOG_H*/
