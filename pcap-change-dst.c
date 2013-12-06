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

#include "pcap_layers.h"

struct in_addr dst4;
struct in6_addr dst6;

/*
 * this will only be called if 'ip' is a complete IPv header
 */
int
my_ip4_handler(const struct ip *ip4, int len, void *userdata)
{
    memcpy((void*) &ip4->ip_dst, &dst4, sizeof(dst4));
    return 0;
}

int
my_ip6_handler(const struct ip6_hdr *ip6, int len, void *userdata)
{
    memcpy((void*) &ip6->ip6_dst, &dst6, sizeof(dst6));
    return 0;
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
	fprintf(stderr, "usage: tcpdump-change-dst dst-ipv4 dst-ipv6\n");
	exit(1);
    }
    if (inet_pton(AF_INET, argv[1], &dst4) != 1) {
	fprintf(stderr, "bad IPv4 address: %s\n", argv[1]);
	exit(1);
    }
    if (inet_pton(AF_INET6, argv[2], &dst6) != 1) {
	fprintf(stderr, "bad IPv6 address: %s\n", argv[2]);
	exit(1);
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
    callback_ipv4 = my_ip4_handler;
    callback_ipv6 = my_ip6_handler;
    while ((data = pcap_next(in, &hdr))) {
	    handle_pcap(NULL, &hdr, data);
	    pcap_dump((void *)out, &hdr, data);
    }
    pcap_close(in);
    pcap_dump_close(out);
    exit(0);
}

