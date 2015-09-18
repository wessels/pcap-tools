/*
 * pcap-change-ip
 *
 * If either src/dst IP falls within the given network, the IP will be
 * changed to a new value.
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

#include "pcap_layers.h"

struct in_addr old4;
struct in_addr mask4;
struct in_addr to4;
struct in6_addr old6;
struct in6_addr mask6;
struct in6_addr to6;

int
match4(struct in_addr check)
{
     if ((check.s_addr & mask4.s_addr) != old4.s_addr)
	return 0;
    return 1;
}

int
match6(struct in6_addr check)
{
    int k;
    for (k = 0; k < 16; k++)
	if ((check.s6_addr[k] & mask6.s6_addr[k]) != old6.s6_addr[k])
	    return 0;
    return 1;
}

/*
 * this will only be called if 'ip' is a complete IPv header
 */
int
my_ip4_handler(const struct ip *ip4, int len, void *userdata)
{
    if (match4(ip4->ip_src))
    	memcpy((void*) &ip4->ip_src, &to4, sizeof(to4));
    if (match4(ip4->ip_dst))
    	memcpy((void*) &ip4->ip_dst, &to4, sizeof(to4));
    return 0;
}

int
my_ip6_handler(const struct ip6_hdr *ip6, int len, void *userdata)
{
    if (match6(ip6->ip6_src))
    	memcpy((void*) &ip6->ip6_src, &to6, sizeof(to6));
    if (match6(ip6->ip6_dst))
    	memcpy((void*) &ip6->ip6_dst, &to6, sizeof(to6));
    return 0;
}

void
usage(void)
{
	fprintf(stderr, "usage: pcap-change-dst from-ip4/prefixlen new-ip4 from-ip6/prefixlen new-ip6\n");
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
    char *t;
    unsigned int ml;
    unsigned int k;


    if (argc < 5)
	usage();
    if (NULL == (t = strchr(argv[1], '/')))
	usage();
    *t = 0;
    if (inet_pton(AF_INET, argv[1], &old4) != 1) {
	fprintf(stderr, "bad IPv4 address: %s\n", argv[1]);
	usage();
    }
    ml = atoi(t+1);
    if (ml > 32) {
	fprintf(stderr, "IPv4 prefixlen (%u) out of range\n", ml);
	usage();
    }
    mask4.s_addr = htonl(~0 << (32-ml));
    if (inet_pton(AF_INET, argv[2], &to4) != 1) {
	fprintf(stderr, "bad IPv4 address: %s\n", argv[2]);
	usage();
    }
    if (NULL == (t = strchr(argv[3], '/')))
	usage();
    *t = 0;
    if (inet_pton(AF_INET6, argv[3], &old6) != 1) {
	fprintf(stderr, "bad IPv6 address: %s\n", argv[3]);
	exit(1);
    }
    ml = atoi(t+1);
    if (ml > 128) {
	fprintf(stderr, "IPv6 prefixlen (%u) out of range\n", ml);
	usage();
    }
    memset(&mask6, 0, sizeof(mask6));
    for (k = 0; k < 16; k++, ml -= 8) {
	if (ml >= 8) {
		mask6.s6_addr[k] = 0xff;
	} else {
		mask6.s6_addr[k] = 0xff << (8-ml);
		break;
	}
    }
    if (inet_pton(AF_INET6, argv[4], &to6) != 1) {
	fprintf(stderr, "bad IPv6 address: %s\n", argv[4]);
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

