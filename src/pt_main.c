#include "pt_include.h"

static int arg_log_level = 2;
static int arg_interactive_mode = 0;
static char arg_usecase_path[256] = "pt.cfg";
static char arg_config_path[256] = "pt.cfg";
static char arg_running_path[256] = "pt.cfg";
static st_netfd_t sig_pipe[2];  /* Signal pipe  */

static void sig_catcher(int signo)
{
    int err, fd;

    err = errno;
    fd = st_netfd_fileno(sig_pipe[1]);

    /* write() is async-safe */
    write(fd, &signo, sizeof(int));

    errno = err;
}

static void sig_install(void)
{
    sigset_t mask;
    int p[2];

    /* Create signal pipe */
    pipe(p);
    sig_pipe[0] = st_netfd_open(p[0]);
    sig_pipe[1] = st_netfd_open(p[1]);

    /* Install signal handlers */
    signal(SIGTERM, sig_catcher);  /* terminate */
    signal(SIGHUP,  sig_catcher);  /* restart   */
    signal(SIGUSR1, sig_catcher);  /* dump info */
    signal(SIGUSR2, sig_catcher);  /* dump info */

    /* Unblock signals */
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGHUP);
    sigaddset(&mask, SIGUSR1);
    sigaddset(&mask, SIGUSR2);
    sigprocmask(SIG_UNBLOCK, &mask, NULL);
}

static void *sig_process(void *arg)
{
    int signo;

    for (;;) {
        /* Read the next signal from the signal pipe */
        st_read(sig_pipe[0], &signo, sizeof(int), ST_UTIME_NO_TIMEOUT);

        switch (signo) {
            case SIGHUP:
                break;
            case SIGTERM:
                break;
            case SIGUSR1:
                pt_diam_dump();
                pt_m3ua_dump();
                pt_uc_dump();
                break;
            case SIGUSR2:
                if (pt_xml_load_exec(arg_running_path) < 0) {
                    fprintf(stderr, "load running parameter failed, path = %s!\n", arg_running_path);
                }
                break;
            default:
                ;
        }
    }

    return NULL;
}

static void start_daemon(void)
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

static void usage(const char *progname)
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

static void parse_arguments(int argc, char *argv[])
{
    extern char *optarg;
    int opt;
    int cpuid;

    while ((opt = getopt(argc, argv, "l:c:u:r:b:i")) != EOF) {
        switch (opt) {
            case 'l':
                arg_log_level = (int)strtol(optarg, NULL, 10);
                if (arg_log_level >= PTLOG_INVALID)
                    arg_log_level = PTLOG_ERROR;
                break;
            case 'c':
                strcpy(arg_config_path, optarg);
                break;
            case 'u':
                strcpy(arg_usecase_path, optarg);
                break;
            case 'r':
                strcpy(arg_running_path, optarg);
                break;
            case 'b':
                cpuid = atoi(optarg);
                pt_setaffinity(0, cpuid);
                break;
            case 'i':
                arg_interactive_mode = 1;
                break;
            default /*?*/:
                usage(argv[0]);
                break;
        }
    }
}

int main(int argc, char **argv)
{
    parse_arguments(argc, argv);

    if (!arg_interactive_mode)
        start_daemon();

    pt_st_thread_init();

    pt_log_set_level(arg_log_level);
    if (pt_xml_load_cfg(arg_config_path) < 0) {
        fprintf(stderr, "Can't load config: %s!\n", arg_config_path);
        exit(1);
    }

    if (pt_xml_load_uc(arg_usecase_path) < 0) {
        fprintf(stderr, "Can't load usecase: %s!\n", arg_usecase_path);
        exit(1);
    }

    sig_install();
    sig_process(NULL);
	
	return 0;
}

