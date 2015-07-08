#include "pt_include.h"

static int _arg_log_level = 2;
static int _arg_interactive_mode = 0;
static char _arg_usecase_path[256] = "pt.cfg";
static char _arg_config_path[256] = "pt.cfg";
static char _arg_running_path[256] = "pt.cfg";
static st_netfd_t _sig_pipe[2];  /* Signal pipe  */

void pt_cmd_show()
{
    pt_diam_dump();
    pt_m3ua_dump();
    pt_uc_dump();
}

void pt_cmd_run()
{
    if (pt_xml_load_exec(_arg_running_path) < 0) {
        fprintf(stderr, "load running parameter failed, path = %s!\n", _arg_running_path);
    }
}

static void pt_sig_catcher(int signo)
{
    int err, fd;

    err = errno;
    fd = st_netfd_fileno(_sig_pipe[1]);

    /* write() is async-safe */
    write(fd, &signo, sizeof(int));

    errno = err;
}

static void pt_sig_install(void)
{
    sigset_t mask;
    int p[2];

    /* Create signal pipe */
    pipe(p);
    _sig_pipe[0] = st_netfd_open(p[0]);
    _sig_pipe[1] = st_netfd_open(p[1]);

    /* Install signal handlers */
    signal(SIGTERM, pt_sig_catcher);  /* terminate */
    signal(SIGHUP,  pt_sig_catcher);  /* restart   */
    signal(SIGUSR1, pt_sig_catcher);  /* dump info */
    signal(SIGUSR2, pt_sig_catcher);  /* dump info */

    /* Unblock signals */
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGHUP);
    sigaddset(&mask, SIGUSR1);
    sigaddset(&mask, SIGUSR2);
    sigprocmask(SIG_UNBLOCK, &mask, NULL);
}

static void *pt_sig_process(void *arg)
{
    int signo;

    for (;;) {
        /* Read the next signal from the signal pipe */
        st_read(_sig_pipe[0], &signo, sizeof(int), ST_UTIME_NO_TIMEOUT);

        switch (signo) {
            case SIGHUP:
                break;
            case SIGTERM:
                break;
            case SIGUSR1:
                pt_cmd_show();
                break;
            case SIGUSR2:
                pt_cmd_run();
                break;
            default:
                ;
        }
    }

    return NULL;
}

void pt_shell()
{
    st_netfd_t fd_shell;
    char input[1024];
    int i;

    fd_shell = st_netfd_open(fileno(stdin));
    if (fd_shell == NULL) {
        printf("open stdin failed\n");
    }

    while (fd_shell) {
        printf(">>> ");
        fflush(stdout);
        st_read(fd_shell, input, sizeof(input), ST_UTIME_NO_TIMEOUT);
        if (strstr(input, "show"))
            pt_cmd_show();
        else if (strstr(input, "run"))
            pt_cmd_run();
        else
            printf("invalid cmd");
        printf("\n");
    }
}

static void pt_start_daemon(void)
{
    pid_t pid;

    /* Start forking */
    if ((pid = fork()) < 0) {
        fprintf(stderr, "fork failed\n");
        exit(1);
    }
    if (pid > 0)
        exit(0); /* parent */

    /* First child process */
    setsid(); /* become session leader */

    if ((pid = fork()) < 0){
        fprintf(stderr, "fork failed\n");
        exit(1);
    }
    if (pid > 0) /* first child */
        exit(0);

    umask(022);
}

static void pt_usage(const char *progname)
{
    fprintf(stderr, "Usage: %s [<options>]\n\n"
            "Possible options:\n\n"
            "\t-c <path>               Set config file path, default: pt.cfg.\n"
            "\t-u <path>               Set usecase file path, default: pt.cfg.\n"
            "\t-r <path>               Set running file path, default: pt.cfg.\n"
            "\t-l <log_level>          Set log level, 0-DEBUG 1-INFO 2-ERROR default: 2.\n"
            "\t-b <cpuid>              Bind CPU.\n"
            "\t-i                      Run in interactive mode.\n"
            ,
            progname);
    exit(1);
}

static void pt_parse_arguments(int argc, char *argv[])
{
    extern char *optarg;
    int opt;
    int cpuid;

    while ((opt = getopt(argc, argv, "l:c:u:r:b:i")) != EOF) {
        switch (opt) {
            case 'l':
                _arg_log_level = (int)strtol(optarg, NULL, 10);
                if (_arg_log_level >= PTLOG_INVALID)
                    _arg_log_level = PTLOG_ERROR;
                break;
            case 'c':
                strcpy(_arg_config_path, optarg);
                break;
            case 'u':
                strcpy(_arg_usecase_path, optarg);
                break;
            case 'r':
                strcpy(_arg_running_path, optarg);
                break;
            case 'b':
                cpuid = atoi(optarg);
                pt_setaffinity(0, cpuid);
                break;
            case 'i':
                _arg_interactive_mode = 1;
                break;
            default /*?*/:
                pt_usage(argv[0]);
                break;
        }
    }
}

int main(int argc, char **argv)
{
    pt_parse_arguments(argc, argv);

    if (!_arg_interactive_mode)
        pt_start_daemon();

    pt_st_thread_init();

    pt_log_set_level(_arg_log_level);
    if (pt_xml_load_cfg(_arg_config_path) < 0) {
        fprintf(stderr, "Can't load config: %s!\n", _arg_config_path);
        exit(1);
    }

    if (pt_xml_load_uc(_arg_usecase_path) < 0) {
        fprintf(stderr, "Can't load usecase: %s!\n", _arg_usecase_path);
        exit(1);
    }

    if (_arg_interactive_mode) {
        pt_shell();
    } else {
        pt_sig_install();
        pt_sig_process(NULL);
    }

	return 0;
}

