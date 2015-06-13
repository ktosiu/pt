#ifndef INTERFACE_H
#define INTERFACE_H

#define TYPE_NONE       0x00000000
#define TYPE_RELOAD 0x00000001

#ifndef   _EXPORT
#define  _EXPORT
#endif

#ifndef _VERSION_1
    #define _VERSION_1
    #define   VERSION_1    1
#endif

#ifndef _VERSION_2
    #define _VERSION_2
    #define   VERSION_2    2
#endif

/*********************************************
                                  init_function
      ___________________|______________________
      |                                |                                     |
(children)                     (children)                        (children)
      |                                |                                     |
      |                                |                                     |
      |                         process_init                             |
      |                                |                                     |
      |                                |                                     |
      |                      while(yes or no)____                   |
      |                                |                  |                  |
      |                         process_run         |                  |
      |                                |                  |                  |
      |                                |__________|                  |
      |                                |                                     |
      |                      process_exit                               |
      |                                |                                     |
      |__________________|______________________|
                                       |
                             destroy_function
**********************************************/

typedef void (*p_status)(int);
typedef int (*p_printf)(const char *pszFmt, ...);
typedef const char* (* p_getres)();  
typedef const int (* p_getres_record)(const char*, char **, int*);
typedef const char* (* p_getres_field)(const char*, const int); 
typedef const int (* p_getres_type)(char **, int*);

enum { TYPE_CHAR = 1, TYPE_INT, TYPE_LONG, TYPE_FLOAT, TYPE_DOUBLE, TYPE_STRING };
#define KVP_NONE                0x00000000
#define KVP_COUNT_TPS           0x00000001
#define KVP_COUNT_AVG           0x00000010

typedef int (* p_kvp_open)(const char*, int,  int);
typedef int (* p_kvp_opt)(int, int,  ...);
typedef int (* p_kvp_close)(int);

typedef int (* p_connect_respool)(const char*);
typedef int (* p_close_respool)(const int);
typedef int (* p_sendto_respool)(const int,const char*,const char*);
typedef const char* (* p_getfromm_respool)(const int,const char*);
typedef int (* p_clean_respool)(const int);

struct proc_method_s
{
    int pID;                                                  /*children ID, start from 0*/
    int jID;                                                   /*job ID, start from 0*/  
    p_status _status;                                   /*method for changing status*/
    p_printf  _printf;                                      /*method for outputing testing result*/

    p_getres  _getIP;                                    /*method for getting resource of IP, need free memory*/
    p_getres  _getURL;                                 /*method for getting resource of URL, need free memory*/
    p_getres  _getMobileNumber;                  /*method for getting resource of MobileNumber, need free memory*/
    p_getres  _getUA;                                  /*method for getting resource of UA, need free memory*/

    p_kvp_open _openKVP;
    p_kvp_close _closeKVP;
    p_kvp_opt    _setKVP;                             /*method for setting the Value*/
    p_kvp_opt    _getKVP;                             /*method for getting the Value*/
    p_kvp_opt    _incKVP;                             /*method for operatng + */
    p_kvp_opt    _decKVP;                            /*method for operating -*/    

    p_connect_respool   _connectResPool;         
    p_close_respool     _closeResPool;
    p_sendto_respool    _sendtoResPool;        /*method for sending data to resource pool*/    
    p_getfromm_respool  _getfromResPool;    /*method for getting data to resource pool*/   
    p_clean_respool     _cleanResPool;           /*method for cleanning memory about resource pool*/
    
    p_getres_record  _getResByType;                  /*method for getting the whole recourd resource of type, need free memory*/
    p_getres_field   _getResFieldByType;             /*method for getting sub field resource of type, need free memory*/
    p_getres_type    _getResType;                      /*method for getting the whole resource type, need free memory*/
 };

typedef int   (*process_init)(struct proc_method_s *pMethod);        /*execute after child process start*/
typedef int   (*process_run)( void* param);                                  /*execute when the child process run*/
typedef void (*process_exit)(void);                                               /*execute before child process exit*/
                                     
struct proc_export_ {
        process_init _Init;   
        process_run _Run;
        process_exit _Exit;
};
typedef struct proc_export_ proc_export_t;
typedef int (*init_function)(const char *cfg, int size);
typedef int (*param_maker_function)(char** param, int* size);
typedef void (*destroy_function)(void);


/*export points*/
_EXPORT struct module_exports
{
    char* name;                                  /*name*/
    char* version;                               /*version*/
    char* mode;                                  /*template type*/

    int type;                                            /* which type of the module*/
    int stn;                                           /*count of the state */ 
    char **stn_str;                               /*meanings of every state*/
    init_function init_f;                           /* Initialization function */
    param_maker_function pm_f;           /*create parameters shared by all the testing instances*/
    destroy_function destroy_f;              /* function called when the module should be "destroyed", e.g: on exit */
    proc_export_t* proc_f;                   /* functions called when instantiate the testing instances*/
};

#endif

