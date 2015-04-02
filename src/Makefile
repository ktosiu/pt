MAKE		= gmake
CC 			= gcc
LD			= ld
RM			= rm -rf
ECHO		= echo
MKDIR   	= mkdir

ifeq ($(_VER_TYPE), DBG)
_ST_TYPE	= "DBG"
CFLAGS		= -g -Wall -fPIC
else
_ST_TYPE	= "OPT"
CFLAGS		= -O2 -Wall -fPIC
endif

OBJ_PATH  	= obj
SRC_PATH    = .
INC_PATH	= $(addprefix -I, $(SRC_PATH)) -I /usr/include/libxml2

SRC_PT		= \
		      pt_conn.c          \
			  pt_conn_sctp.c  	 \
			  pt_conn_tcp.c      \
		      pt_diam_code.c     \
		      pt_diam_link.c     \
		      pt_diam_protocol.c \
		      pt_m3ua_code.c     \
		      pt_m3ua_protocol.c \
		      pt_sccp_code.c     \
		      pt_sccp_protocol.c \
		      pt_asn1.c          \
		      pt_tcap_itu.c      \
		      pt_tcap_ansi.c     \
		      pt_func.c          \
		      pt_log.c           \
		      pt_os.c            \
		      pt_rbtree.c        \
			  pt_task.c          \
		      pt_task_diam.c     \
		      pt_task_ss7.c      \
		      pt_usecase.c       \
		      pt_xml.c           \
			  pt_st_thread.c

SRC_IF_OTS	= \
		      pt_if_ots.c         

SRC_MAIN	= \
		      pt_main.c           

SRC_EXE    	= $(SRC_PT) $(SRC_MAIN)
OBJ_EXE    	= $(addprefix $(OBJ_PATH)/, $(SRC_EXE:.c=.o))
OUT_EXE     = $(addprefix $(OBJ_PATH)/, pt.out)

SRC_OTS    	= $(SRC_PT) $(SRC_IF_OTS)
OBJ_OTS    	= $(addprefix $(OBJ_PATH)/, $(SRC_OTS:.c=.o))
OUT_OTS     = $(addprefix $(OBJ_PATH)/, pt_ots.so)

vpath %.o $(OBJ_PATH)
vpath %.c $(SRC_PATH)

default: libst $(OUT_EXE) $(OUT_OTS)

clean: libstclean
	-$(RM) $(OBJ_PATH)

libst:
	-$(MAKE) -C ./lib/st-1.9 OS="LINUX" BUILD=$(_ST_TYPE) STATIC_ONLY=yes EXTRA_CFLAGS=-fPIC EXAMPLES= DESC= HEADER=

libstclean:
	-$(MAKE) -C ./lib/st-1.9 clean

$(OUT_EXE): $(OBJ_EXE)
	$(CC) $(CFLAGS) $+ -L./lib/st-1.9/obj -lst -lxml2 -o $@

$(OUT_OTS): $(OBJ_OTS)
	$(CC) $(CFLAGS) $+ -L./lib/st-1.9/obj -lst -lxml2 -shared -o $@

$(OBJ_PATH)/%.o: %.c
	@if [ ! -d $(OBJ_PATH) ]; then $(MKDIR) $(OBJ_PATH); fi
	$(CC) $(CFLAGS) $(INC_PATH) -c $< -o $@

