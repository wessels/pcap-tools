#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pcap.h>
#include <err.h>
#include <string.h>
#include <time.h>
#include <errno.h>

int
main(int argc, char *argv[])
{
    pcap_t *in = NULL;
    pcap_dumper_t *out = NULL;
    char errbuf[PCAP_ERRBUF_SIZE + 1];
    struct pcap_pkthdr hdr;
    const u_char *data;
    char ttime[32];
    struct timeval adjust;
    long long int L1;
    long long int L2;


    if (argc < 2) {
	fprintf(stderr, "usage: pcap-adjust-timestamp adjust\n");
	exit(1);
    }

    snprintf(ttime, 32, "%8.6f", atof(argv[1]));
    if (2 != sscanf(ttime, "%lld.%lld", &L1, &L2)) {
	fprintf(stderr, "bad adjust time: %s\n", argv[1]);
	exit(1);
    }
    adjust.tv_sec = (time_t) L1;
    adjust.tv_usec = (time_t) L2;
    fprintf(stderr, "adjusting timestamps by %lld.%06lld sec\n",
	(long long int) adjust.tv_sec, (long long int) adjust.tv_usec);

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
	struct timeval result;
	timersub(&hdr.ts, &adjust, &result);
	hdr.ts = result;
	pcap_dump((void *) out, &hdr, data);
    }
    pcap_close(in);
    if (out)
	pcap_dump_close(out);
    exit(0);
}
