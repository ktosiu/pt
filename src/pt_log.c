#include "pt_include.h"

pt_char_t *pt_tstamp(void)
{
    static pt_char_t str[32];
    struct tm *tmp;
    st_utime_t currt;
    st_utime_t currt_sec;
    st_utime_t currt_usec;

    currt = st_utime();
    currt_sec = currt / 1000000;
    currt_usec = currt % 1000000;
    
    tmp = localtime((const time_t *)&currt_sec);
    sprintf(str, "%d/%02d/%02d %02d:%02d:%02d.%03llu",
          1900 + tmp->tm_year, tmp->tm_mon, tmp->tm_mday, tmp->tm_hour,
          tmp->tm_min, tmp->tm_sec, currt_usec/1000);

    return str;
}

pt_log_level_e _log_level = PTLOG_ERROR;

void pt_log_set_level(pt_log_level_e log_level)
{
    _log_level = log_level;
}

void pt_log(pt_loginfo_t *pt_loginfo, pt_char_t *format, ...)
{
    pt_char_t buf[512];
    va_list ap;
    
    va_start(ap, format);
    vsprintf(buf, format, ap);
    va_end(ap);
    
    fprintf(stderr, "[%s] %-11s: %s: %s\n", 
        pt_tstamp(), pt_loginfo->level, pt_loginfo->func, buf);
}

