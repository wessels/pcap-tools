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

static pcap_t *in = NULL;


int
my_ip4_handler(const struct ip *ip4, int len, void *userdata)
{
    struct inx_addr *a = userdata;
    a->family = AF_INET;
    a->u.in4 = ip4->ip_src;
    return 0;
}

int
my_ip6_handler(const struct ip6_hdr *ip6, int len, void *userdata)
{
    struct inx_addr *a = userdata;
    a->family = AF_INET6;
    a->u.in6 = ip6->ip6_src;
    return 0;
}

int
is_rfc1918(struct inx_addr a)
{
    unsigned long clt_addr = ntohl(a.u.in4.s_addr);
    if (AF_INET != a.family)
	return 0;
    // 10/8
    if ((clt_addr & 0xff000000) == 0x0A000000)
	return 1;
    // 172.16/12
    if ((clt_addr & 0xfff00000) == 0xAC100000)
	return 1;
    // 192.168/16
    if ((clt_addr & 0xffff0000) == 0xC0A80000)
	return 1;

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

    while ((data = pcap_next(in, &hdr))) {
	char buf[128];
	struct inx_addr src;
	memset(&src, 0, sizeof(src));
	handle_pcap((u_char *) & src, &hdr, data);
	if (src.family == 0)
	    continue;
	inet_ntop(src.family, &src.u, buf, sizeof(buf));
	puts(buf);
    }
    return 0;
}
