#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pcap.h>
#include <err.h>
#include <string.h>
#include <time.h>

#include "pcap_layers.h"

struct _item {
	struct in_addr addr;
	pcap_dumper_t *out;
	struct _item *next;
};
struct _item *List;

void
read_list(const char *fn, pcap_t *in)
{
	FILE *fp = fopen(fn, "r");
	struct _item **tailp = &List;
	char buf[512];
	char ofn[768];
	if (NULL == fp) {
		perror(fn);
		exit(1);
	}
	while (NULL != fgets(buf, 512, fp)) {
		struct _item *i = calloc(1, sizeof(*i));
		strtok(buf, "\r\n");
		i->addr.s_addr = inet_addr(buf);
		snprintf(ofn, sizeof(ofn), "%s.pcap", buf);
	    	i->out = pcap_dump_open(in, ofn);
	        if (NULL == i->out) {
		    perror(ofn);
		    exit(1);
	        }
		*(tailp) = i;
		tailp = &i->next;
	}
}

struct _item *
search(const struct in_addr a)
{
	struct _item *i;
	for (i=List;i;i=i->next)
		if (i->addr.s_addr == a.s_addr)
			return i;
	return NULL;
}


int
my_ip4_handler(const struct ip *ip4, int len, void *userdata)
{
    struct in_addr *a= userdata;
    *a = ip4->ip_src;
    return 0;
}


int
main(int argc, char *argv[])
{
    pcap_t *in = NULL;
    char errbuf[PCAP_ERRBUF_SIZE + 1];
    struct pcap_pkthdr hdr;
    const u_char *data;
    struct _item *i;

    if (2 != argc) {
	fprintf(stderr, "usage: pcap-separate listfile\n");
	exit(1);
    }

    in = pcap_open_offline("-", errbuf);
    if (NULL == in) {
	fprintf(stderr, "stdin: %s", errbuf);
	exit(1);
    }
    read_list(argv[1], in);
    pcap_layers_init(pcap_datalink(in), 0);
    callback_ipv4 = my_ip4_handler;

    while ((data = pcap_next(in, &hdr))) {
	struct in_addr src;
	memset(&src, 0, sizeof(src));
	handle_pcap((u_char *) &src, &hdr, data);
	i = search(src);
	if (NULL == i)
		continue;
	pcap_dump((void *)i->out, &hdr, data);
    }
   
    for (i=List;i;i=i->next)
	pcap_dump_close(i->out);
    exit(0);
}
