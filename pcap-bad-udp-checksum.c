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

#include <pcap_layers.h>
#include <inx_addr_c.h>
#include "pcap-tools.h"

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86dd
#endif

const char *progname;
u_char out_data[65536];

struct state {
	inx_addr src;
	inx_addr dst;
        int proto;
	int frag;
	int cksum_bad;
};

unsigned short
in_cksum(unsigned short *ptr, int size, unsigned int sum)
{
    unsigned short oddbyte;
    unsigned short answer;
    while (size > 1) {
	sum += *ptr++;
	size -= 2;
    }
    if (size == 1) {
	oddbyte = 0;
	*((unsigned char *) &oddbyte) = *(unsigned char *) ptr;
	sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}

int
my_udp_handler(const struct udphdr *udp, int len, void *userdata)
{
    unsigned short pseudo[18];
    unsigned int ps = 0;
    struct state *s = userdata;
    unsigned int i;
    s->proto = 17;
    if (s->frag)
	return 0;
#ifdef __linux__
    if (0 == udp->check)
	return 0;
#else
    if (0 == udp->uh_sum)
	return 0;
#endif
    memset(&pseudo[0], 0, sizeof(pseudo));
    if (4 == inx_addr_version(&s->src)) {
        memcpy(&pseudo[0], &s->src._.in4, 4);
        memcpy(&pseudo[8], &s->dst._.in4, 4);
    } else if (6 == inx_addr_version(&s->src)) {
        memcpy(&pseudo[0], &s->src.in6, 16);
        memcpy(&pseudo[8], &s->dst.in6, 16);
    }
    pseudo[16] = htons(IPPROTO_UDP);
    pseudo[17] = htons((unsigned short) len);
    for (i = 0; i < sizeof(pseudo) / sizeof(unsigned short); i++)
	ps += pseudo[i];
    unsigned int calc_sum = in_cksum((unsigned short *) udp, len, ps);
    if (0 != calc_sum)
	s->cksum_bad = 1;
    return 0;
}

/*
 * this will only be called if 'ip' is a complete IPv header
 */
int
my_ip4_handler(const struct ip *ip4, int len, void *userdata)
{
    struct state *s = userdata;
    uint16_t ip_off = ntohs(ip4->ip_off);
    inx_addr_assign_v4(&s->src, &ip4->ip_src);
    inx_addr_assign_v4(&s->dst, &ip4->ip_dst);
    if ((ip_off & IP_MF) || 0 != (ip_off & IP_OFFMASK))
        s->frag = 1;
    return 0;
}

int
my_ip6_handler(const struct ip6_hdr *ip6, int len, void *userdata)
{
    struct state *s = userdata;
    inx_addr_assign_v6(&s->src, &ip6->ip6_src);
    inx_addr_assign_v6(&s->dst, &ip6->ip6_dst);
    return 0;
}

int
main(int argc, char *argv[])
{
    pcap_t *in = NULL;
    char errbuf[PCAP_ERRBUF_SIZE + 1];
    struct pcap_pkthdr hdr;
    const u_char *data;
    pcap_dumper_t *out = NULL;
    struct state S;

    memset(out_data, 0, sizeof(out_data));
    progname = argv[0];
    if (argc < 2) {
	fprintf(stderr, "usage: %s pcapfiles\n", progname);
	exit(1);
    }

    in = pcap_open_offline(argv[1], errbuf);
    if (NULL == in) {
	fprintf(stderr, "%s: %s", argv[1], errbuf);
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
    callback_udp = my_udp_handler;
    while ((data = pcap_next(in, &hdr))) {
	    memset(&S, 0, sizeof(S));
	    handle_pcap((u_char *)&S, &hdr, data);
	    if (17 == S.proto && 1 == S.cksum_bad)
		pcap_dump((void *)out, &hdr, data);
    }
    pcap_close(in);
    pcap_dump_close(out);
    exit(0);
}

