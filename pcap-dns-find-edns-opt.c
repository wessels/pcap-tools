#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pcap.h>
#include <err.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <getopt.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>

#include <pcap_layers.h>
#include <inx_addr_c.h>
#include "pcap-tools.h"

#include <ldns/ldns.h>

const char *progname = 0;
unsigned int only_option_code = 0;
unsigned int verbose = 0;

int
my_dns_handler(const u_char *buf, int len, void *userdata)
{
    int *flag = userdata;
    ldns_pkt *pkt = 0;
    if (LDNS_STATUS_OK != ldns_wire2pkt(&pkt, buf, len))
        goto done;

    ldns_rdf *opt = ldns_pkt_edns_data(pkt);
    if (0 == opt)
	goto done;
    if (LDNS_RDF_TYPE_UNKNOWN != ldns_rdf_get_type(opt))
	goto done;
    unsigned short rdata_len = ldns_rdf_size(opt);
    unsigned char *rdata = ldns_rdf_data(opt);
    while (rdata_len >= 4) {
	unsigned short option_code = nptohs(rdata);
	unsigned short option_len = nptohs(rdata+2);
	if (verbose)
	    fprintf(stderr, "Found EDNS option %hu of %hu bytes\n", option_code, option_len);
        if (only_option_code == 0 || only_option_code == option_code)
	    *flag = 1;
        rdata_len -= 4;
	rdata += 4;
        if (option_len > rdata_len)
		goto done;
        rdata_len -= option_len;
	rdata += option_len;
    }

done:
    ldns_pkt_free(pkt);
    return 0;
}

int
main(int argc, char *argv[])
{
    pcap_t *in = NULL;
    struct pcap_pkthdr hdr;
    const u_char *data;
    pcap_dumper_t *out = NULL;
    int flag;

    progname = strdup(argv[0]);

    while ((flag = getopt(argc, argv, "o:v")) != -1) {
        switch(flag) {
	case 'o':
		only_option_code = strtoul(optarg, 0, 0);
		break;
	case 'v':
		verbose++;
		break;
	}
    }
    argc -= optind;
    argv += optind;

    in = my_pcap_open_offline("-");
    out = pcap_dump_open(in, "-");
    if (NULL == out)
	errx(1, "pcap_dump_open stdout");
    pcap_layers_init(pcap_datalink(in), 0);
    callback_l7 = my_dns_handler;
    while ((data = pcap_next(in, &hdr))) {
	    flag = 0;
	    handle_pcap((u_char *)&flag, &hdr, data);
	    if (flag)
		pcap_dump((void *)out, &hdr, data);
    }
    pcap_close(in);
    pcap_dump_close(out);
    exit(0);
}

