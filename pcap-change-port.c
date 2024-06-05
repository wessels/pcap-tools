/*
 * pcap-change-port
 *
 * Change UDP/TCP port of some packets.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pcap.h>
#include <err.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>

#include "pcap-tools.h"
#include "pcap_layers.h"

unsigned short oldport = 0;
unsigned short newport = 0;

int
my_udp_handler(struct udphdr *udp, int len, void *userdata)
{
    if (nptohs(&udp->uh_sport) == oldport)
	udp->uh_sport = ntohs(newport);
    if (nptohs(&udp->uh_dport) == oldport)
	udp->uh_dport = ntohs(newport);
    return 0;
}

int
my_tcp_handler(struct tcphdr *tcp, int len, void *userdata)
{
    if (nptohs(&tcp->th_sport) == oldport)
	tcp->th_sport = ntohs(newport);
    if (nptohs(&tcp->th_dport) == oldport)
	tcp->th_dport = ntohs(newport);
    return 0;
}

void
usage(void)
{
    fprintf(stderr, "usage: pcap-change-ip old-port new-port\n");
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

    if (argc < 3)
	usage();
    if ((oldport = strtoul(argv[1], 0, 10)) == 0) {
	fprintf(stderr, "bad old-port : %s\n", argv[1]);
	usage();
    }
    if ((newport = strtoul(argv[2], 0, 10)) == 0) {
	fprintf(stderr, "bad new-port : %s\n", argv[2]);
	usage();
    }

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
    pcap_layers_init(pcap_datalink(in), 0);
    callback_udp = (int (*)(const struct udphdr *, int,  void *)) my_udp_handler;
    callback_tcp = (int (*)(const struct tcphdr *, int,  void *)) my_tcp_handler;
    while ((data = pcap_next(in, &hdr))) {
	handle_pcap(NULL, &hdr, data);
	pcap_dump((void *) out, &hdr, data);
    }
    pcap_close(in);
    pcap_dump_close(out);
    exit(0);
}
