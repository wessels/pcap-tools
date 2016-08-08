#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pcap.h>
#include <err.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "pcap_layers.h"

#define XCMP(X,Y) (X<Y?-1:(X>Y?1:0))

int SORTSIZE = 256;
struct _pkt {
    struct pcap_pkthdr hdr;
    u_char *data;
};
int npkts = 0;
struct _pkt *packets;
struct timeval max_flushed = {0, 0};
int sort_err_fatal = 0;

int
my_ip4_handler(const struct ip *ip4, int len, void *userdata)
{
    memset(userdata, 0, 16);
    memcpy(userdata, &ip4->ip_src, 4);
    return 0;
}

int
my_ip6_handler(const struct ip6_hdr *ip6, int len, void *userdata)
{
    memcpy(userdata, &ip6->ip6_src, 16);
    return 0;
}


int
cmp_timeval(struct timeval a, struct timeval b)
{
    return (a.tv_sec == b.tv_sec)
    ? XCMP(a.tv_usec, b.tv_usec)
    : XCMP(a.tv_sec, b.tv_sec);
}

int
sorter(const void *A, const void *B)
{
    struct _pkt *a = (struct _pkt *)A;
    struct _pkt *b = (struct _pkt *)B;
    return cmp_timeval(a->hdr.ts, b->hdr.ts);
}

void
flush(pcap_dumper_t * out, int keep)
{
    int i;
    if (0 == npkts)
	return;
    qsort(packets, npkts, sizeof(struct _pkt), sorter);
    for (i = 0; i < (npkts - keep); i++) {
	pcap_dump((void *)out, &packets[i].hdr, packets[i].data);
	free(packets[i].data);
    }
    max_flushed = packets[i - 1].hdr.ts;
    if (keep)
	memmove(&packets[0], &packets[npkts - keep], keep * sizeof(struct _pkt));
    npkts = keep;
}

void
push(struct pcap_pkthdr *hdr, const u_char * data)
{
    assert(npkts < SORTSIZE);
    packets[npkts].hdr = *hdr;
    packets[npkts].data = malloc(hdr->caplen);
    if (0 == packets[npkts].data)
	err(1, "malloc");
    memcpy(packets[npkts].data, data, hdr->caplen);
    if (cmp_timeval(max_flushed, hdr->ts) > 0) {
	warnx("sortsize %d is not large enough "
	    "to fully sort this file.  "
	    "flushed=%10lld.%06lld, this=%10lld.%06lld",
	    SORTSIZE,
	    (long long int)max_flushed.tv_sec,
	    (long long int)max_flushed.tv_usec,
	    (long long int)hdr->ts.tv_sec,
	    (long long int)hdr->ts.tv_usec);
	if (sort_err_fatal)
	    exit(1);
    }
    npkts++;
}

void
usage(void)
{
    fprintf(stderr, "usage: pcap-reorder [-s] sortsize\n");
    fprintf(stderr, "\t-s\tinput is sorted by source IP\n");
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
    int ch;
    int sip_sorted = 0;
    u_char this_sip[16];
    u_char that_sip[16];

    while ((ch = getopt(argc, argv, "sx")) != -1) {
	switch (ch) {
	case 's':
	    sip_sorted = 1;
	    break;
	case 'x':
	    sort_err_fatal = 1;
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
    SORTSIZE = atoi(argv[0]);
    if (SORTSIZE < 2) {
	fprintf(stderr, "sortsize should be greater than 1\n");
	exit(1);
    }
    packets = calloc(SORTSIZE, sizeof(struct _pkt));
    if (0 == packets)
	err(1, "calloc");

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
    if (sip_sorted) {
	pcap_layers_init(pcap_datalink(in), 0);
	callback_ipv4 = my_ip4_handler;
	callback_ipv6 = my_ip6_handler;
    }
    while ((data = pcap_next(in, &hdr))) {
	push(&hdr, data);
	if (sip_sorted) {
	    handle_pcap(this_sip, &hdr, data);
	    if (memcmp(this_sip, that_sip, 16)) {
		flush(out, 0);
		memcpy(that_sip, this_sip, 16);
		max_flushed.tv_sec = max_flushed.tv_usec = 0;
	    }
	}
	if (SORTSIZE == npkts)
	    flush(out, npkts / 2);
    }
    pcap_close(in);
    flush(out, 0);
    pcap_dump_close(out);
    exit(0);
}
