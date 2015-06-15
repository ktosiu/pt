#--变量定义
set(SRC_PT
    pt_conn.c     
    pt_conn_sctp.c
    pt_conn_tcp.c 
    pt_diam_code.c
    pt_diam_link.c
    pt_diam_protocol.c
    pt_m3ua_code.c
    pt_m3ua_protocol.c
    pt_sccp_code.c
    pt_sccp_protocol.c
    pt_asn1.c     
    pt_tcap_itu.c 
    pt_tcap_ansi.c
    pt_func.c     
    pt_log.c      
    pt_os.c       
    pt_rbtree.c   
    pt_task.c     
    pt_task_diam.c
    pt_task_ss7.c 
    pt_usecase.c  
    pt_xml.c      
    pt_st_thread.c
    )

set(SRC_IF_OTS
    pt_if_ots.c
    )

set(SRC_MAIN
    pt_main.c
    )

#--头文件搜索路径
include_directories("/usr/include/libxml2")

#--编译选项
add_definitions("-fPIC")

#--生成文件
add_library(pt_static STATIC ${SRC_PT})
add_library(pt_ots SHARED ${SRC_IF_OTS})
add_executable(pt ${SRC_MAIN})

#--lib依赖
find_library(LIBST NAMES st PATHS third/st-1.9/obj/)
target_link_libraries(pt pt_static ${LIBST} xml2)
target_link_libraries(pt_ots pt_static ${LIBST} xml2)

