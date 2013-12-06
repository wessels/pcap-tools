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

#define XCMP(X,Y) (X<Y?-1:(X>Y?1:0))

int SORTSIZE = 256;
struct _pkt {
    struct pcap_pkthdr hdr;
    u_char *data;
};
int npkts = 0;
struct _pkt *packets;
struct timeval max_flushed = {0,0};

int
cmp_timeval(struct timeval a, struct timeval b)
{
	return (a.tv_sec == b.tv_sec)
	  ? XCMP(a.tv_usec,b.tv_usec)
	  : XCMP(a.tv_sec,b.tv_sec);
}

int
sorter(const void *A, const void *B)
{
	struct _pkt *a = (struct _pkt *) A;
	struct _pkt *b = (struct _pkt *) B;
	return cmp_timeval(a->hdr.ts, b->hdr.ts);
}

void
flush(pcap_dumper_t *out, int keep)
{
	int i;
	if (0 == npkts)
		return;
	qsort(packets, npkts, sizeof(struct _pkt), sorter);
	for (i=0; i<(npkts-keep); i++) {
            pcap_dump((void *)out, &packets[i].hdr, packets[i].data);
	    free(packets[i].data);
	}
	max_flushed = packets[i-1].hdr.ts;
	if (keep)
	    memmove(&packets[0], &packets[npkts-keep], keep * sizeof(struct _pkt));
	npkts = keep;
}

void
push(struct pcap_pkthdr *hdr, const u_char *data)
{
	assert (npkts < SORTSIZE);
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
		(long long int) max_flushed.tv_sec,
		(long long int) max_flushed.tv_usec,
		(long long int) hdr->ts.tv_sec,
		(long long int) hdr->ts.tv_usec);
	}
	npkts++;
}

int
main(int argc, char *argv[])
{
    pcap_t *in = NULL;
    pcap_dumper_t *out = NULL;
    char errbuf[PCAP_ERRBUF_SIZE + 1];
    struct pcap_pkthdr hdr;
    const u_char *data;


    if (argc < 2) {
	fprintf(stderr, "usage: tcpdump-reorder sortsize\n");
	exit(1);
    }
    SORTSIZE = atoi(argv[1]);
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
    while ((data = pcap_next(in, &hdr))) {
	    push(&hdr, data);
	    if (SORTSIZE == npkts)
		flush(out, npkts/2);
    }
    pcap_close(in);
    flush(out, 0);
    pcap_dump_close(out);
    exit(0);
}

