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
#include <netinet/ip6.h>
#include <arpa/inet.h>

#include "pcap_layers.h"

struct _state {
	int from_gre;
	void *ip_start;
	int ip_len;
	void *gre_start;
	int gre_len;
};

/*
 * this will only be called if 'ip' is a complete IPv4 header
 */
int
my_ip4_handler(const struct ip *ip4, int len, void *userdata)
{
	struct _state *s = userdata;
	if (!s->from_gre) {
		s->ip_start = (void*) ip4;
		s->ip_len = len;
	} else {
		s->gre_start = (void*) ip4;
		s->gre_len = len;
	}
	return 0;
}

int
my_ip6_handler(const struct ip6_hdr *ip6, int len, void *userdata)
{
	struct _state *s = userdata;
	if (!s->from_gre) {
		s->ip_start = (void*) ip6;
		s->ip_len = len;
	} else {
		s->gre_start = (void*) ip6;
		s->gre_len = len;
	}
	return 0;
}

int
my_gre_handler(const unsigned char *pkt, int len, void *userdata)
{
	struct _state *s = userdata;
	s->from_gre = 1;
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
    struct _state s;


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
    callback_gre = my_gre_handler;
    while ((data = pcap_next(in, &hdr))) {
	    memset(&s, 0, sizeof(s));
	    handle_pcap((void*)&s, &hdr, data);
	    if (s.from_gre && s.ip_start && s.gre_start && s.ip_start < s.gre_start && s.ip_len && s.gre_len && s.ip_len > s.gre_len) {
		int chop = (s.gre_start - s.ip_start);
		hdr.caplen -= chop;
		hdr.len -= chop;
		memmove(s.ip_start, s.gre_start, s.gre_len);
	    	pcap_dump((void *)out, &hdr, data);
	    }
    }
    pcap_close(in);
    pcap_dump_close(out);
    exit(0);
}

