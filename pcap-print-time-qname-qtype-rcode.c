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
#include <ldns/ldns.h>

#include <pcap.h>
#include "pcap_layers.h"

#ifdef __GLIBC__
#define __u6_addr __in6_u
#endif


static pcap_t *in = NULL;
static struct pcap_pkthdr hdr;

int
my_dns_handler(const u_char *buf, int len, void *userdata)
{
    ldns_pkt *pkt = 0;
    ldns_rr_list *qd = 0;
    ldns_rr *q = 0;
    ldns_rdf *qn = 0;
    ldns_rr_type qt;
    char *qn_str = 0;
    if (LDNS_STATUS_OK != ldns_wire2pkt(&pkt, buf, len))
        goto done;
    if (1 != ldns_pkt_qr(pkt))
        goto done;
    qd = ldns_pkt_question(pkt);
    if (0 == qd)
        goto done;
    q = ldns_rr_list_rr(qd, 0);
    if (0 == q)
        goto done;
    qn = ldns_rr_owner(q);
    if (0 == qn)
        goto done;
    qn_str = ldns_rdf2str(qn);
    qt = ldns_rr_get_type(q);
    printf ("%10lu.%06lu %s %d %d\n",
        hdr.ts.tv_sec, hdr.ts.tv_usec,
        qn_str,
	qt,
        ldns_pkt_get_rcode(pkt));
done:
    ldns_pkt_free(pkt);
    LDNS_FREE(qn_str);
    return 0;
}


int
main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE + 1];
    const u_char *data;

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    in = pcap_open_offline("-", errbuf);
    if (NULL == in) {
	fprintf(stderr, "stdin: %s", errbuf);
	exit(1);
    }

    pcap_layers_init(pcap_datalink(in), 0);
    callback_l7 = my_dns_handler;

    while ((data = pcap_next(in, &hdr))) {
	handle_pcap(0, &hdr, data);
    }
    return 0;
}
