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

int ARRAYSZ = 1<<20;
struct timeval *tvals = NULL;
int count;
int misordered = 0;

int
tv_cmp(struct timeval *a, struct timeval *b)
{
	return (a->tv_sec == b->tv_sec) ? XCMP(a->tv_usec,b->tv_usec) : XCMP(a->tv_sec,b->tv_sec);
}

void
flush(int keep)
{
	if (keep)
	    memmove(tvals, tvals+count-keep, keep * sizeof(*tvals));
	count = keep;
}

void
push(struct pcap_pkthdr *hdr, const u_char *data)
{
	assert (count < ARRAYSZ);
	*(tvals+count) = hdr->ts;
	count++;
	if (count < 2)
		return;
	if (0 > tv_cmp(tvals+count-1, tvals+count-2)) {
		printf("timestamp went from %10lld.%06ld to %10lld.%06ld\n",
			(long long int) (tvals+count-2)->tv_sec,
			(tvals+count-2)->tv_usec,
			(long long int) (tvals+count-1)->tv_sec,
			(tvals+count-1)->tv_usec);
		misordered++;
	}
}

int
main(int argc, char *argv[])
{
    pcap_t *in = NULL;
    char errbuf[PCAP_ERRBUF_SIZE + 1];
    struct pcap_pkthdr hdr;
    const u_char *data;


    if (argc < 2) {
	fprintf(stderr, "usage: pcap-reorder sortsize\n");
	exit(1);
    }
    ARRAYSZ = atoi(argv[1]);
    if (ARRAYSZ < 2) {
	fprintf(stderr, "sortsize should be greater than 1\n");
	exit(1);
    }
    tvals = calloc(ARRAYSZ, sizeof(*tvals));

    in = pcap_open_offline("-", errbuf);
    if (NULL == in) {
	fprintf(stderr, "stdin: %s", errbuf);
	exit(1);
    }
    while ((data = pcap_next(in, &hdr))) {
	    push(&hdr, data);
	    if (ARRAYSZ == count)
		flush(3*count/4);
    }
    pcap_close(in);
    exit(0 == misordered ? 0 : 1);
}

