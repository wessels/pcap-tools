#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pcap.h>
#include <err.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <inttypes.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define DEF_TIME_FMT "%s"
#define DEF_COUNT_FMT "%09d.pcap"
#define START_OPT  1001
#define STOP_OPT   1002

static const char *kick_cmd = NULL;
static const char *ProgramName = "pcap-split";
static const char *gzext = ".gz";
static int opt_gzip = 0;
static int opt_verbose = 0;

/* Prototypes */
static void usage(const char *) __attribute__((noreturn));
static void help(void);
#ifdef __linux__
extern char *strptime(const char *s, const char *format, struct tm *tm);
extern int asprintf(char **strp, const char *fmt, ...);
#endif

int
main(int argc, char *argv[])
{
    pcap_t *in = NULL;
    pcap_dumper_t *out = NULL;
    char errbuf[PCAP_ERRBUF_SIZE + 1];
    struct pcap_pkthdr hdr;
    time_t this_bin;
    time_t last_bin = -1;
    time_t modulus = 0;
    uint64_t count = 0;
    uint64_t npkts = 0;
    const u_char *data;
    int ch;
    char *p;
    unsigned long ul;
    char *fmt = NULL;
    /* Track of starting and ending time */
    static time_t start_time = 0;
    static time_t stop_time = 0;
    char fname[128];
    char fifoname[128];
    char *pcapname = fname;

    while ((ch = getopt(argc, argv, "?hB:E:t:n:f:k:vz")) != -1)
    {
        switch (ch) {
            case 't':
                /* Validate that is a integer */
                ul = strtoul(optarg, &p, 0);
                if (*p != '\0')
                    usage("argument to -t must be an integer");
                modulus = (unsigned) ul;
                break;
	    case 'n':
		if (1 != sscanf(optarg, "%"PRIu64, &count))
		    usage("argument to -n must be an integer");
		break;
            case 'f':
                fmt = strdup(optarg);
                break;
            case 'k':
                kick_cmd = strdup(optarg);
                break;
            case '?':
            case 'h':
                help();
                exit(0);
                break;
            case 'B':
                {
                struct tm tm;
                memset(&tm, '\0', sizeof(tm));
                if (NULL == strptime(optarg, "%F %T", &tm))
                    usage("-B arg must have format YYYY-MM-DD HH:MM:SS");
                start_time = timegm(&tm);
                }
                break;
            case 'E':
                {
                struct tm tm;
                memset(&tm, '\0', sizeof(tm));
                if (NULL == strptime(optarg, "%F %T", &tm))
                    usage("-E arg must have format YYYY-MM-DD HH:MM:SS");
                stop_time = timegm(&tm);
                }
                break;
	    case 'v':
		opt_verbose = 1;
		break;
	    case 'z':
		opt_gzip = 1;
		break;
            default:
                usage("unrecognized command line option");
        }
    }

    if (0 == modulus && 0 == count) {
	help();
	exit(1);
    }

    if (start_time && stop_time && start_time > stop_time)
        usage("start time must be before stop time");

    /* If not format given, use the default */
    if (NULL == fmt)
        fmt = strdup(modulus ? DEF_TIME_FMT : DEF_COUNT_FMT);

    in = pcap_open_offline("-", errbuf);
    if (NULL == in) {
        fprintf(stderr, "stdin: %s", errbuf);
        exit(1);
    }
    while ((data = pcap_next(in, &hdr))) {
	if (modulus)
	    this_bin = hdr.ts.tv_sec - (hdr.ts.tv_sec % modulus);
	else
	    this_bin = (time_t) (npkts++ / count);
        /* Check if the packet is within the time window we are
         * interested
         */
        if (start_time && hdr.ts.tv_sec < start_time)
            continue;
        if (stop_time && hdr.ts.tv_sec >= stop_time)
            break;
        if (this_bin != last_bin) {
            if (out) {
                char *cmd = NULL;
                pcap_dump_close(out);
		if (opt_gzip) { int s; waitpid(-1, &s, 0); }
                if (kick_cmd != NULL) {
                    if (asprintf(&cmd, "%s %s &", kick_cmd, fname) < 0){
                        perror("asprintf");
                        cmd = NULL;
                    }
                    else {
                        system(cmd);
                        free(cmd);
                    }
                }
            }
	    if (modulus)
		strftime(fname, sizeof(fname)-sizeof(gzext), fmt, gmtime(&this_bin));
	    else
		snprintf(fname, sizeof(fname)-sizeof(gzext), fmt, (int) this_bin);
	    if (opt_gzip) {
		static int fifocount = 0;
		int gzfd = -1;
		strcat(fname, gzext);
		gzfd = open(fname, O_WRONLY|O_CREAT, 0666);
		if (gzfd < 0) {
			perror(fname);
			exit(1);
		}
		snprintf(fifoname, sizeof(fifoname), "/tmp/%s.fifo.%d.%d", ProgramName, (int) getpid(), fifocount++);
		if (mkfifo(fifoname, 0600) < 0) {
			perror(fifoname);
			exit(1);
		}
		if (0 == fork()) {
			/* child */
			int i;
			close(0);
			if (0 != open(fifoname, O_RDONLY)) {
				perror(fifoname);
				exit(1);
			}
			if (dup2(gzfd, 1) < 0) {
				perror("dup2");
				exit(1);
			}
			close(gzfd);
			for (i=3; i<20; i++)
				close(i);
			execlp("gzip", "gzip", "-9c", NULL);
		} else {
			close(gzfd);
			pcapname = fifoname;
		}
	    }
	    if (opt_verbose)
		fprintf(stderr, "writing %s\n", fname);
            out = pcap_dump_open(in, pcapname);
	    if (opt_gzip) {
		/*
		 * no race condition on unlink because open-for-write
		 * blocks until open-for-read happens first?
		 */
		unlink(fifoname);
	    }
            if (NULL == out) {
                perror(fname);
                exit(1);
            }
            last_bin = this_bin;
        }
        pcap_dump((void *)out, &hdr, data);
    }
    if (out) {
        char *cmd = NULL;
        pcap_dump_close(out);
	if (opt_gzip) { int s; waitpid(-1, &s, 0); }
        if (kick_cmd != NULL) {
            if (asprintf(&cmd, "%s %s &", kick_cmd, fname) < 0){
                perror("asprintf");
                cmd = NULL;
            }
            else {
                system(cmd);
                free(cmd);
            }
        }
    }
    exit(0);
}

static void
usage(const char *msg) {
    fprintf(stderr, "%s: usage error: %s\n", ProgramName, msg);
    fprintf(stderr, "\n");
    exit(1);
}

static void
help(void) {
    fprintf(stderr, "%s\n", ProgramName);
    fprintf(stderr,
        "\noptions:\n"
        "\t-? or -h  print these instructions and exit\n"
        "\t-B YYYY-MM-DD HH:MM:SS        select packets starting on that date\n"
        "\t-E YYYY-MM-DD HH:MM:SS        select packets until this time/date\n"
        "\t-t <interval>                 each <interval> seconds since\n"
        "\t                              the start time indicated by '-B'\n"
        "\t                              will close the old destination file\n"
        "\t                              and create a new one.\n"
        "\t-n <count>                    make new output file every <count> packets\n"
        "\t-f <format>                   receives a format accepted by\n"
        "\t                              strftime to name the files created.\n"
        "\t                              Default %%s (UNIX timestamp)\n"
        "\t-k <kick command>             After closing an old destination\n"
        "\t                              file, will execute this command with\n"
        "\t                              the file name as first parameter\n"
	"\t-v                            produce slightly more verbose output\n"
	"\t-z                            automatcially compress each pcap\n"
	"\t                              with gzip\n"
    );
}
