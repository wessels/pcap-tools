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
    time_t beg;
    time_t end;


    if (argc < 3) {
	fprintf(stderr, "usage: pcap-extract-interval begin end\n");
	exit(1);
    }
    beg = atoi(argv[1]);
    end = atoi(argv[2]);

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
	if (hdr.ts.tv_sec >= beg && hdr.ts.tv_sec <= end)
	    pcap_dump((void *)out, &hdr, data);
    }
    pcap_close(in);
    pcap_dump_close(out);
    exit(0);
}
