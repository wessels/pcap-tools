#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pcap.h>
#include <err.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>


#include "pcap-tools.h"

#ifdef __GLIBC__
#include <openssl/md5.h>
#define MD5Init MD5_Init
#define MD5Update MD5_Update
#define MD5Final MD5_Final
#else
#include <md5.h>
#endif

/*
 * Remove duplicated packets from a pcap file
 */

int is_dupe(struct pcap_pkthdr *thishdr, const u_char *thisdata);

int
main(int argc, char *argv[])
{
    pcap_t *in = NULL;
    pcap_dumper_t *out = NULL;
    struct pcap_pkthdr hdr;
    const u_char *data;
    int i;
    int ndupes = 0;

    if (argc < 2) {
	fprintf(stderr, "usage: pcap-remove-dupe pcapfiles ...");
	exit(1);
    }
    for (i = 1; i < argc; i++) {
	in = my_pcap_open_offline(argv[i]);
	while ((data = pcap_next(in, &hdr))) {
	    if (is_dupe(&hdr, data)) {
		ndupes++;
		continue;
	    }
	    if (!out) {
		out = pcap_dump_open(in, "-");
		if (NULL == out) {
		    perror("stdout");
		    exit(1);
		}
	    }
	    pcap_dump((void *)out, &hdr, data);
	}
	my_pcap_close_offline(in);
    }
    if (out)
	pcap_dump_close(out);
    fprintf(stderr, "Removed %d dupes\n", ndupes);
    exit(0);
}

int
is_dupe(struct pcap_pkthdr *thishdr, const u_char *thisdata)
{
    static struct pcap_pkthdr lasthdr;
    static char lastdata[4096];
    MD5_CTX md5;
    static unsigned int thisdigest[4];
    static unsigned int lastdigest[4];
    int rc = 0;
    /*
     * sigh, must compute MD5 for every packet
     */
    MD5Init(&md5);
    MD5Update(&md5, thisdata, thishdr->len);
    MD5Final((u_char*)thisdigest, &md5);
    if (thishdr->ts.tv_usec != lasthdr.ts.tv_usec)
	(void) 0;
    else if (thishdr->ts.tv_sec != lasthdr.ts.tv_sec)
	(void) 0;
    else if (thishdr->caplen != lasthdr.caplen)
	(void) 0;
    else if (thishdr->len != lasthdr.len)
	(void) 0;
    else {
	if (memcmp(thisdigest, lastdigest, 16) == 0)
	    rc = 1;
    }
    memcpy(lastdigest, thisdigest, 16);
    lasthdr = *thishdr;
    memcpy(lastdata, thisdata, thishdr->len);

    return rc;
}
