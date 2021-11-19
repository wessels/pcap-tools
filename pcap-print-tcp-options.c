#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <assert.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <inttypes.h>

#include <pcap.h>
#include "pcap_layers.h"

#ifdef __GLIBC__
#define __u6_addr __in6_u
#endif


struct inx_addr
{
    uint8_t family;
    union
    {
	struct in_addr in4;
	struct in6_addr in6;
    } u;
};

struct state
{
    struct inx_addr src;
    struct inx_addr dst;
};


static pcap_t *in = NULL;

int
my_tcp_handler(const struct tcphdr *tcp, int len, void *userdata)
{
    struct state *s = userdata;
    char sbuf[128];
    char dbuf[128];
    unsigned int doff;
    char sep = '\t';
    inet_ntop(s->src.family, &s->src.u, sbuf, sizeof(sbuf));
    inet_ntop(s->dst.family, &s->dst.u, dbuf, sizeof(dbuf));
    printf("%-30s %-30s %c%c%c%c%c%c", sbuf, dbuf,
#ifdef TH_FIN
	/* BSD */
	tcp->th_flags & TH_URG ? 'U' : '.',
	tcp->th_flags & TH_ACK ? 'A' : '.',
	tcp->th_flags & TH_PUSH ? 'P' : '.',
	tcp->th_flags & TH_RST ? 'R' : '.', tcp->th_flags & TH_SYN ? 'S' : '.', tcp->th_flags & TH_FIN ? 'F' : '.'
#else
	/* Linux */
	tcp->urg ? 'U' : '.',
	tcp->ack ? 'A' : '.', tcp->psh ? 'P' : '.', tcp->rst ? 'R' : '.', tcp->syn ? 'S' : '.', tcp->fin ? 'F' : '.'
#endif
	);
#ifdef TH_FIN
    /* BSD */
    doff = tcp->th_off << 2;
#else
    /* Linux */
    doff = tcp->doff << 2;
#endif
    if (doff > sizeof(*tcp)) {
	unsigned int hdrlen = doff - sizeof(*tcp);
	uint8_t *x = (uint8_t *) (tcp + 1);
	uint8_t optlen;
	while (hdrlen > 0) {
	    uint8_t opt = *x;
	    printf("%copt%u", sep, opt);
	    if (0 == opt || 1 == opt) {
		optlen = 1;
	    } else {
		if (hdrlen < 2)
		    break;
		optlen = *(x + 1);
		if (optlen < 2 || optlen > hdrlen)
		    break;
	    }
	    x += optlen;
	    hdrlen -= optlen;
	    sep = ',';
	}
    }
    printf("\n");
    return 0;
}


int
my_ip4_handler(const struct ip *ip4, int len, void *userdata)
{
    struct state *s = userdata;
    s->src.family = AF_INET;
    s->src.u.in4 = ip4->ip_src;
    s->dst.family = AF_INET;
    s->dst.u.in4 = ip4->ip_dst;
    return 0;
}

int
my_ip6_handler(const struct ip6_hdr *ip6, int len, void *userdata)
{
    struct state *s = userdata;
    s->src.family = AF_INET6;
    s->src.u.in6 = ip6->ip6_src;
    s->dst.family = AF_INET6;
    s->dst.u.in6 = ip6->ip6_dst;
    return 0;
}

int
main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE + 1];
    struct pcap_pkthdr hdr;
    const u_char *data;

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    in = pcap_open_offline("-", errbuf);
    if (NULL == in) {
	fprintf(stderr, "stdin: %s", errbuf);
	exit(1);
    }

    pcap_layers_init(pcap_datalink(in), 0);
    callback_ipv4 = my_ip4_handler;
    callback_ipv6 = my_ip6_handler;
    callback_tcp = my_tcp_handler;

    while ((data = pcap_next(in, &hdr))) {
	struct state s;
	memset(&s, 0, sizeof(s));
	handle_pcap((u_char *) & s, &hdr, data);

    }
    return 0;
}
