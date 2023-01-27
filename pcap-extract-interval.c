#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pcap.h>
#include <err.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <getopt.h>

static void
usage(void)
{
    fprintf(stderr, "usage: pcap-extract-interval [-x] begin end\n");
    fprintf(stderr, "\tbegin\tUnix timestamp\n");
    fprintf(stderr, "\tend\tUnix timestamp\n");
    fprintf(stderr, "\t-x\texit at first timestamp after end time\n");
    exit(1);
}

int
main(int argc, char *argv[])
{
    pcap_t *in = NULL;
    pcap_dumper_t *out = NULL;
    char errbuf[PCAP_ERRBUF_SIZE + 1];
    struct pcap_pkthdr hdr;
    const u_char *data;
    time_t beg;
    time_t end;
    int ch;
    int opt_exit = 0;

    while ((ch = getopt(argc, argv, "x")) != -1) {
        switch (ch) {
        case 'x':
            opt_exit = 1;
            break;
        case '?':
        case 'h':
	default:
            usage();
            break;
        }
    }


    if ((argc - optind) < 2) {
	usage();
    }
    beg = atoi(argv[optind]);
    end = atoi(argv[optind+1]);

    in = pcap_open_offline("-", errbuf);
    if (NULL == in) {
	fprintf(stderr, "stdin: %s", errbuf);
	exit(1);
    }
    out = pcap_dump_open(in, "-");
    if (NULL == out) {
	perror("stdout");
	exit(1);
    }
    while ((data = pcap_next(in, &hdr))) {
	if (hdr.ts.tv_sec < beg)
	    continue;
	if (hdr.ts.tv_sec >= end) {
	    if (opt_exit) {
		exit(0);
	    } else {
		continue;
	    }
	}
	pcap_dump((void *) out, &hdr, data);
    }
    pcap_close(in);
    pcap_dump_close(out);
    exit(0);
}
