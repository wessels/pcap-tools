#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pcap.h>
#include <err.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <getopt.h>
#include <arpa/inet.h>

#include "pcap-tools.h"

char *progname = NULL;

int
needs_fixing(const struct pcap_pkthdr *hdr, const u_char * data)
{
    unsigned int family;
    if (hdr->caplen < 4)
	return 0;
    family = nptohl(data);
    if (10 == family)
	return 1;
    return 0;
}

void
fix(const u_char * data)
{
    unsigned int family = htonl(28);
    memcpy((void *) data, &family, sizeof(family));
}

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
    int nfixed = 0;
    int dryrun = 0;
    int dlt = 0;

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
	dlt = pcap_datalink(in);
	while ((data = pcap_next(in, &hdr))) {
	    if (DLT_LOOP == dlt && needs_fixing(&hdr, data)) {
		nfixed++;
		if (dryrun)
		    warnx("found bad packet of at %10lld.%06lld",
			(long long int) hdr.ts.tv_sec, (long long int) hdr.ts.tv_usec);
		else
		    fix(data);
	    }
	    if (!out) {
		out = pcap_dump_open(in, "-");
		if (NULL == out) {
		    perror("stdout");
		    exit(1);
		}
	    }
	    pcap_dump((void *) out, &hdr, data);
	}
	my_pcap_close_offline(in);
    }
    if (out)
	pcap_dump_close(out);
    fprintf(stderr, "%s: Fixed %d bad packets\n", progname, nfixed);
    exit(0);
}

int
is_bogus(struct pcap_pkthdr *thishdr, const u_char * thisdata)
{
    if (thishdr->caplen > 65535)
	return 1;
    if (thishdr->len > 65535)
	return 1;
    return 0;
}
