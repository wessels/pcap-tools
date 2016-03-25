#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pcap.h>
#include <err.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <getopt.h>

#include "pcap-tools.h"

/*
 * Remove duplicated packets from a pcap file
 */

char *progname = NULL;
int is_bogus(struct pcap_pkthdr *thishdr, const u_char *thisdata);

void
usage(void)
{
	fprintf(stderr, "usage: %s pcapfiles ...\n", progname);
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
    int nbogus = 0;
    int dryrun = 0;

    progname = argv[0];
    while ((i = getopt(argc, argv, "n")) != -1) {
	switch (i) {
	case 'n':
	    dryrun = 1;
	    break;
	case '?':
	default:
	    usage();
	}
    }
    argc -= optind;
    argv += optind;


    if (argc < 1)
	usage();
    for (i = 0; i < argc; i++) {
	in = my_pcap_open_offline(argv[i]);
	while ((data = pcap_next(in, &hdr))) {
	    if (is_bogus(&hdr, data)) {
		nbogus++;
		if (dryrun)
		    warnx("found bogus packet of caplen=%d, len=%d, at %10lld.%06lld",
			hdr.caplen, hdr.len,
			(long long int) hdr.ts.tv_sec,
			(long long int) hdr.ts.tv_usec);
		else
		    continue;
	    }
	    if (!out) {
		out = pcap_dump_open(in, "-");
		if (NULL == out) {
		    perror("stdout");
		    exit(1);
		}
	    }
	    pcap_dump((void *)out, &hdr, data);
	}
	pcap_close(in);
    }
    if (out)
	pcap_dump_close(out);
    fprintf(stderr, "%s: Removed %d bad packets\n", progname, nbogus);
    exit(0);
}

int
is_bogus(struct pcap_pkthdr *thishdr, const u_char *thisdata)
{
    if (thishdr->caplen > 65535)
	return 1;
    if (thishdr->len > 65535)
	return 1;
    return 0;
}
