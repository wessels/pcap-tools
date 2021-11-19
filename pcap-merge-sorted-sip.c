#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pcap.h>
#include <err.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <inttypes.h>
#include <sys/signal.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "pcap-tools.h"
#include "pcap_layers.h"

struct _in
{
    pcap_t *pcap;
    struct pcap_pkthdr hdr;
    u_char data[65536];
    struct sockaddr_storage ss;
};

#define MAX_INPUTS 256
static struct _in inputs[MAX_INPUTS];
static unsigned int n_inputs = 0;
static uint64_t v4count = 0;
static uint64_t v6count = 0;


int
my_ip4_handler(const struct ip *ip4, int len, void *userdata)
{
    struct _in *in = userdata;
    struct sockaddr_in *s = (struct sockaddr_in *) &in->ss;
    s->sin_family = AF_INET;
    s->sin_addr = ip4->ip_src;
    v4count++;
    return 0;
}

int
my_ip6_handler(const struct ip6_hdr *ip6, int len, void *userdata)
{
    struct _in *in = userdata;
    struct sockaddr_in6 *s = (struct sockaddr_in6 *) &in->ss;
    s->sin6_family = AF_INET6;
    s->sin6_addr = ip6->ip6_src;
    v6count++;
    return 0;
}

pcap_dumper_t *
my_pcap_dump_open(pcap_t * other, const char *f)
{
    pcap_dumper_t *out;
    out = pcap_dump_open(other, f);
    if (NULL == out)
	errx(1, "%s", f);
    return out;
}

void
read_next_packet(struct _in *in)
{
    const u_char *data;
    data = pcap_next(in->pcap, &in->hdr);
    if (0 == data) {
	my_pcap_close_offline(in->pcap);
	in->pcap = 0;
	return;
    }
    memcpy(&in->data[0], data, in->hdr.caplen);
    handle_pcap((void *) in, &in->hdr, in->data);
}

struct _in *
compare(struct _in *this, struct _in *that)
{
    int r;
    assert(that);
    if (0 == this)
	return that;
    if (this->ss.ss_family < that->ss.ss_family)
	return this;
    if (this->ss.ss_family > that->ss.ss_family)
	return that;
    if (AF_INET == this->ss.ss_family) {
	struct sockaddr_in *sa_this = (struct sockaddr_in *) &this->ss;
	struct sockaddr_in *sa_that = (struct sockaddr_in *) &that->ss;
	r = memcmp(&sa_this->sin_addr, &sa_that->sin_addr, 4);
	if (r < 0)
	    return this;
	else if (r > 0)
	    return that;
    }
    if (AF_INET6 == this->ss.ss_family) {
	struct sockaddr_in6 *sa_this = (struct sockaddr_in6 *) &this->ss;
	struct sockaddr_in6 *sa_that = (struct sockaddr_in6 *) &that->ss;
	r = memcmp(&sa_this->sin6_addr, &sa_that->sin6_addr, 16);
	if (r < 0)
	    return this;
	else if (r > 0)
	    return that;
    }
    return this;
}

void
pcap_merge_sorted_sip(int argc, char *argv[], const char *outf)
{
    pcap_dumper_t *out = NULL;
    struct timeval start;
    struct timeval stop;
    struct timeval duration;
    unsigned int i;

    gettimeofday(&start, NULL);
    for (i = 0; i < argc; i++) {
	struct _in *in = &inputs[n_inputs++];
	memset(in, 0, sizeof(*in));
	in->pcap = my_pcap_open_offline(argv[i]);
	if (0 == i) {
	    pcap_layers_init(pcap_datalink(in->pcap), 0);
	    callback_ipv4 = my_ip4_handler;
	    callback_ipv6 = my_ip6_handler;
	} else if (pcap_datalink(inputs[0].pcap) != pcap_datalink(in->pcap)) {
	    errx(1, "All pcap input files must have same datalink type");
	}
	read_next_packet(in);
    }

    out = my_pcap_dump_open(inputs[0].pcap, outf);

    for (;;) {
	struct _in *best = 0;
	for (i = 0; i < n_inputs; i++) {
	    struct _in *in = &inputs[i];
	    if (0 == in->pcap)
		continue;
	    best = compare(best, in);
	}
	if (0 == best)
	    break;
	pcap_dump((u_char *) out, &best->hdr, best->data);
	read_next_packet(best);
    }

    pcap_dump_close(out);
    gettimeofday(&stop, NULL);
    timersub(&stop, &start, &duration);
    fprintf(stderr, "\nSorted %" PRIu64 " IPv4 and %" PRIu64 " IPv6 packets in %d.%d seconds\n",
	v4count, v6count, (int) duration.tv_sec, (int) duration.tv_usec / 100000);
}

int
main(int argc, char *argv[])
{
    if (argc < 2) {
	fprintf(stderr, "usage: pcap-merge-sorted-sip in1 in2 ... > out\n");
	exit(1);
    }
    argc--;
    argv++;
    pcap_merge_sorted_sip(argc, argv, "-");
    exit(0);
}
