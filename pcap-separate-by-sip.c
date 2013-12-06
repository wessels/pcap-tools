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

#define LIMIT_OPEN_FD 8192
#define LIMIT_CLT_PKTS 2048
#define LIMIT_MAXRSS (256<<20)
#define LIMIT_PKTS_IN_MEM (2<<20)
#define QUAD_A(ip) ((ntohl(ip.u.in4.s_addr) >> 24) & 0xFF)
#define QUAD_B(ip) ((ntohl(ip.u.in4.s_addr) >> 16) & 0xFF)
#define QUAD_C(ip) ((ntohl(ip.u.in4.s_addr) >>  8) & 0xFF)
#define QUAD_D(ip) ((ntohl(ip.u.in4.s_addr)      ) & 0xFF)

#define MAX_FILTER_SZ 256*1024

#ifdef __GLIBC__
#define __u6_addr __in6_u
#endif


typedef struct _dlink_node dlink_node;
typedef struct _dlink_list dlink_list;

struct _dlink_node {
    void *data;
    dlink_node *prev;
    dlink_node *next;
};

struct _dlink_list {
    dlink_node *head;
    dlink_node *tail;
};

struct _packet {
    struct pcap_pkthdr hdr;
    void *data;
    struct _packet *next;
};

struct inx_addr {
	uint8_t family;
	union {
		struct in_addr in4;
		struct in6_addr in6;
	} u;
};

struct _client {
    struct inx_addr addr;
    struct _packet *pkthead;
    struct _packet **pkttail;
    int npackets;
    pcap_dumper_t *fd;
    struct _client *next;
    dlink_node lru;
};

static struct _client *Hash[256];
static struct _dlink_list *LRU;
static unsigned int nopen = 3;
static unsigned int nclts = 0;
static unsigned int npacketsmem = 0;
static pcap_t *in = NULL;
static int input_sorted = 0;	/* assume input already sorted by sip */
static int use_subdirs = 1;	/* write files into subdirs */

int
inx_addr_hash(struct inx_addr a)
{
	if (AF_INET == a.family)
		return QUAD_A(a);
	return 0;
}

int
inx_addr_equal(struct inx_addr a, struct inx_addr b)
{
	if (a.family != b.family)
		return 0;
	if (AF_INET == a.family)
		return a.u.in4.s_addr == b.u.in4.s_addr;
	return 0 == memcmp(&a.u.in6, &b.u.in6, 16);
}

void
dlinkAdd(void *data, dlink_node * m, dlink_list * list)
{
    m->data = data;
    m->prev = NULL;
    m->next = list->head;
    if (list->head)
	list->head->prev = m;
    list->head = m;
    if (list->tail == NULL)
	list->tail = m;
}

void
dlinkDelete(dlink_node * m, dlink_list * list)
{
    if (m->next)
	m->next->prev = m->prev;
    if (m->prev)
	m->prev->next = m->next;
    if (m == list->head)
	list->head = m->next;
    if (m == list->tail)
	list->tail = m->prev;
    m->next = m->prev = NULL;
}

void
hashDelete(struct _client *f)
{
    int i = inx_addr_hash(f->addr);
    struct _client **F;
    for (F = &Hash[i]; *F; F = &(*F)->next)
	if (f == *F) {
		*F = f->next;
		break;
	}
}

void
mksubdir(const char *path)
{
    char *t;
    for (t = (char *) path; *t; t++) {
	if ('/' == *t) {
		*t = '\0';
		if (mkdir(path, 0755) < 0 && EEXIST != errno) {
			perror(path);
			exit(1);
		}
		*t = '/';
	}
    }
}

const char *
output_fname(const struct _client *f) {
	unsigned int l = 0;
	static char fname[256];
    	static char aname[128];
	inet_ntop(f->addr.family, &f->addr.u, aname, sizeof(aname));
        if (use_subdirs && AF_INET == f->addr.family) {
		l += snprintf(&fname[l], sizeof(fname)-l, "%03d/", QUAD_A(f->addr));
		l += snprintf(&fname[l], sizeof(fname)-l, "%03d/", QUAD_B(f->addr));
	} else
        if (use_subdirs && AF_INET6 == f->addr.family) {
		l += snprintf(&fname[l], sizeof(fname)-l, "%04x/", f->addr.u.in6.__u6_addr.__u6_addr16[0]);
		l += snprintf(&fname[l], sizeof(fname)-l, "%04x/", f->addr.u.in6.__u6_addr.__u6_addr16[1]);
	}
	l += snprintf(&fname[l], sizeof(fname)-l, "%s", aname);
	if (!input_sorted)
		l += snprintf(&fname[l], sizeof(fname)-l, "/%lu.%06lu", 
                        (long unsigned int) f->pkthead->hdr.ts.tv_sec,
                        (long unsigned int) f->pkthead->hdr.ts.tv_usec);
	l += snprintf(&fname[l], sizeof(fname)-l, "%s", ".pcap");
	assert(l < sizeof(fname));
	return fname;
}


void
clt_pcap_open(struct _client *f)
{
    const char *file;
    if (NULL != f->fd)
	return;
    file = output_fname(f);
    if (input_sorted) {
	struct stat sb;
	if (0 == stat(file, &sb)) {
		fprintf(stderr, "%s already exist, perhaps input is not sorted?\n", file);
		exit(1);
	}
    }
    f->fd = pcap_dump_open(in, file);
    if (NULL == f->fd && errno == ENOENT) {
        mksubdir(file);
        f->fd = pcap_dump_open(in, file);
    }
    if (NULL == f->fd) {
        perror(file);
        exit(1);
    }
    nopen++;
}


void
clt_free_packets(struct _client *f)
{
    struct _packet *p;
    struct _packet *n;
    for (p = f->pkthead; p; p = n) {
	n = p->next;
	free(p->data);
	free(p);
    }
    npacketsmem -= f->npackets;
    f->npackets = 0;
    f->pkthead = NULL;
    f->pkttail = &f->pkthead;
}

void
clt_pcap_write(struct _client *f)
{
    struct _packet *p;
    if (0 == f->npackets)
	return;
    for (p = f->pkthead; p; p = p->next)
	pcap_dump((void *)f->fd, &p->hdr, p->data);
    clt_free_packets(f);
}

void
clt_pcap_close(struct _client *f)
{
    if (NULL == f->fd)
	return;
    pcap_dump_close(f->fd);
    nopen--;
    f->fd = NULL;
}

void
clt_free(struct _client *f)
{
    if (f->npackets)
	clt_free_packets(f);
    hashDelete(f);
    dlinkDelete(&f->lru, LRU);
    free(f);
    nclts--;
}

void
close_lru(void)
{
    int nc = 0;
    dlink_node *p = LRU->tail;
    fprintf(stderr, "Closing LRU...");
    while (nopen > (LIMIT_OPEN_FD / 2) && p) {
	struct _client *f = p->data;
	p = p->prev;
	if (NULL == f->fd)
		continue;
	clt_pcap_write(f);
	clt_pcap_close(f);
	/* clt_free(f); */
	nc++;
    }
    fprintf(stderr, "%d\n", nc);
}

void
flush(struct _client *f)
{
    if (nopen >= LIMIT_OPEN_FD)
	close_lru();
    clt_pcap_open(f);
    clt_pcap_write(f);
}

long
getmaxrss(void)
{
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    return ru.ru_maxrss;
}

void
flushall()
{
    int i;
    int n = 0;
    struct _client *f;
    struct _client *next;
    fprintf(stderr, "Flushing...\n");
    for (i = 0; i < 256; i++) {
	for (f = Hash[i]; f; f = next) {
	    next = f->next;
	    if (0 == f->npackets)
		continue;
	    if (f->fd == NULL)
		clt_pcap_open(f);
	    clt_pcap_write(f);
	    n++;
	    if (0 == (n % 1000))
		fprintf(stderr, "flushed %d clts, open fd: %d\n", n, nopen);
	    if (nopen >= LIMIT_OPEN_FD)
	        close_lru();
	}
    }
    fprintf(stderr, "flushed %d\n", n);
    fprintf(stderr, "open files: %d\n", nopen);
    fprintf(stderr, "max rss: %ld\n", getmaxrss());
}

void
stash2(struct _client *f, struct pcap_pkthdr *hdr, const unsigned char *data)
{
    struct _packet *p = calloc(1, sizeof(*p));
    assert(p);
    p->hdr = *hdr;
    p->data = malloc(hdr->caplen);
    assert(p->data);
    memcpy(p->data, data, hdr->caplen);
    *f->pkttail = p;
    f->pkttail = &p->next;
    f->npackets++;
    npacketsmem++;
#if 0
    if (f->npackets > LIMIT_CLT_PKTS)
	flush(f);
#endif
}

void
stash(struct inx_addr a, struct pcap_pkthdr *hdr, const unsigned char *data)
{
    struct _client **F;
    struct _client *f;
    int i = inx_addr_hash(a);
    for (F = &Hash[i]; (f = *F); F = &(*F)->next) {
	if (inx_addr_equal(f->addr, a))
	    break;
    }
    if (NULL == f) {
	nclts++;
	f = calloc(1, sizeof(*f));
	assert(f);
	f->addr = a;
	f->pkttail = &f->pkthead;
	f->next = Hash[i];
	Hash[i] = f;
    } else if (f != Hash[i]) {
	/* move to top */
	*F = f->next;
	f->next = Hash[i];
	Hash[i] = f;
    }
    stash2(f, hdr, data);
    dlinkDelete(&f->lru, LRU);
    dlinkAdd(f, &f->lru, LRU);
}

void
print_stats(struct timeval ts, uint64_t pkt_count)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    fprintf(stderr, "%ld.%03ld: at %ld, %12"PRIu64" pkts, %9d clts, %4d files\n",
	(long) now.tv_sec,
	(long) now.tv_usec / 1000,
	(long)ts.tv_sec,
	pkt_count,
	nclts,
	nopen);
}

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
    if ( ( clt_addr & 0xff000000) == 0x0A000000 )
        return 1;
    // 172.16/12
    if ( ( clt_addr & 0xfff00000) == 0xAC100000 )
        return 1;
    // 192.168/16
    if ( ( clt_addr & 0xffff0000) == 0xC0A80000 )
        return 1;

    return 0;
}


int
main(int argc, char *argv[])
{
    uint64_t pkt_count = 0;
    char errbuf[PCAP_ERRBUF_SIZE + 1];
    struct pcap_pkthdr hdr;
    const u_char *data;
    char *filterstr = NULL;
    char *filterfile = NULL;
    FILE *FP = NULL;
    char buf[80];
    char or_str[4] = "\0";
    char lc = 0;
    struct bpf_program fp;
    int ch;
    int skip_bogon = 0;

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    memset(Hash, '\0', sizeof(Hash));
    LRU = calloc(1, sizeof(LRU));
    assert(LRU);

    // Process command line
    while ((ch = getopt(argc, argv, "bf:ls")) != -1) {
        switch(ch) {
            case 'b':
                skip_bogon = 1;
                break;
            case 'f':
                filterfile = strdup(optarg);
                break;
            case 'l':
                use_subdirs = 0;
                break;
	    case 's':
		input_sorted = 1;
		break;
            default:
                fprintf(stderr, "usage: %s [-b] [-f addr_list_file]\n", argv[0]);
                exit(1);
                break;
        }
    }
    argc -= optind;
    argv += optind;

    if (NULL != filterfile) {
    // If a filter file was given, read it and prepare
    if ( (FP = fopen(filterfile, "r")) == NULL)
    {
        fprintf(stderr, "Can't read filter file %s, aborting\n",
        filterfile);
        exit(1);
    }
    filterstr = (char *)calloc(1, MAX_FILTER_SZ);
    while (fgets(buf, 80, FP))
    {
        if (strlen(filterstr) > MAX_FILTER_SZ - 12)
            continue;

        if (lc != 0)
            strcpy(or_str, "or");
        snprintf(filterstr, MAX_FILTER_SZ, "%s %s src net %s",
                    filterstr, or_str, buf);
        ++lc;
    }
    fclose(FP);

    // For debugging purporses, write the filter
    FILE *filter_fp = fopen("filter_pcap.dat", "w");
    if (NULL == filter_fp)
        fprintf(stderr, "Can't write filter, skipping\n");
    else {
        fprintf(filter_fp, "%s\n", filterstr);
        fclose(filter_fp);
    }
    }

    in = pcap_open_offline("-", errbuf);
    if (NULL == in) {
	fprintf(stderr, "stdin: %s", errbuf);
	exit(1);
    }

    // Set the filter
    if (NULL != filterstr) {
        memset(&fp, '\0', sizeof(fp));
        if (pcap_compile(in, &fp, filterstr, 1, 0) < 0) {
            fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(in));
            exit(1);
        }
        if (pcap_setfilter(in, &fp) < 0) {
            fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(in));
            exit(1);
        }
        fprintf(stderr, "Filter read and compiled!\n");
    }


    pcap_layers_init(pcap_datalink(in), 0);
    callback_ipv4 = my_ip4_handler;
    callback_ipv6 = my_ip6_handler;

    while ((data = pcap_next(in, &hdr))) {
	struct inx_addr src;
	memset(&src, 0, sizeof(src));
	handle_pcap((u_char *) & src, &hdr, data);
	if (src.family == 0)
	    continue;
    if (skip_bogon && is_rfc1918(src))
        continue;
	stash(src, &hdr, data);
	if (0 == (++pkt_count & 0x3FFF)) {
	    print_stats(hdr.ts, pkt_count);
	    if (npacketsmem > LIMIT_PKTS_IN_MEM) {
		flushall();
		close_lru();
	    }
	}
    }
    flushall();
    fprintf(stderr, "Max RSS  %ld KB \n", getmaxrss());
    return 0;
}
