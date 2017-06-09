#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <inttypes.h>
#include <pcap.h>
#include <err.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <getopt.h>

#include "pcap-tools.h"

const char *progname = 0;

/*
 * Sample every Nth packet
 */

void
usage(void)
{
    fprintf(stderr, "usage: %s -n rate < pcap-in > pcap-out\n", progname);
    exit(1);
}

int
main(int argc, char *argv[])
{
    pcap_t *in = NULL;
    pcap_dumper_t *out = NULL;
    struct pcap_pkthdr hdr;
    const u_char *data;
    int i;
    uint64_t samplerate = 0;
    uint64_t incount = 0;
    uint64_t outcount = 0;

    progname = argv[0];
    while ((i = getopt(argc, argv, "n:")) != -1) {
	switch (i) {
	case 'n':
	    samplerate = strtoul(optarg, 0, 10);
	    break;
	case '?':
	default:
	    usage();
	}
    }
    argc -= optind;
    argv += optind;

    in = my_pcap_open_offline("-");
    out = pcap_dump_open(in, "-");
    if (NULL == out) {
	perror("stdout");
	exit(1);
    }
    while ((data = pcap_next(in, &hdr))) {
	if (0 != (incount++ % samplerate))
	    continue;
	pcap_dump((void *) out, &hdr, data);
	outcount++;
    }
    my_pcap_close_offline(in);
    pcap_dump_close(out);
    fprintf(stderr, "%s: Read %" PRIu64 ", Wrote %" PRIu64 " packets\n", progname, incount, outcount);
    exit(0);
}
