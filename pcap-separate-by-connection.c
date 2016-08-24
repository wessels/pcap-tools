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
#include <pcap_layers.h>
#include "pcap-tools.h"

#define LIMIT_OPEN_FD 1024
#define LIMIT_MAXRSS (256<<20)
#define LIMIT_PKTS_IN_MEM (2<<20)
#define QUAD_A(ip) ((ntohl(ip.u.in4.s_addr) >> 24) & 0xFF)
#define QUAD_B(ip) ((ntohl(ip.u.in4.s_addr) >> 16) & 0xFF)
#define QUAD_C(ip) ((ntohl(ip.u.in4.s_addr) >>  8) & 0xFF)
#define QUAD_D(ip) ((ntohl(ip.u.in4.s_addr)      ) & 0xFF)

#ifdef __GLIBC__
#define __u6_addr __in6_u
#define th_sport source
#define th_dport dest
#endif

typedef struct _dlink_node dlink_node;
typedef struct _dlink_list dlink_list;
typedef struct _conn conn;
typedef struct _tuple tuple;
typedef struct _packet packet;
typedef struct _inx_addr inx_addr;

struct _dlink_node
{
    void *data;
    dlink_node *prev;
    dlink_node *next;
};

struct _dlink_list
{
    dlink_node *head;
    dlink_node *tail;
};

struct _packet
{
    struct pcap_pkthdr hdr;
    void *data;
    packet *next;
};

struct _inx_addr
{
    uint8_t family;
    union
    {
	struct in_addr in4;
	struct in6_addr in6;
    } u;
};

struct _tuple
{
    inx_addr sip;
    inx_addr dip;
    unsigned short sport;
    unsigned short dport;
};

struct _conn
{
    tuple tuple;
    packet *pkthead;
    packet **pkttail;
    int npackets;
    pcap_dumper_t *fd;
    conn *next;
    dlink_node lru;
};

#define HASH_SIZE 1037

static struct _conn *Hash[HASH_SIZE];
static struct _dlink_list *LRU;
static unsigned int nopen = 3;
static unsigned int nconn = 0;
static unsigned int npacketsmem = 0;
static pcap_t *in = NULL;
static int use_subdirs = 1;	/* write files into subdirs */
static uint64_t pkts_read = 0;
static uint64_t pkts_writ = 0;
static uint64_t pkts_stashed = 0;

unsigned int
inx_addr_hash(inx_addr a)
{
    if (AF_INET == a.family)
	return QUAD_B(a) + QUAD_C(a);
    return 0;
}

unsigned int
tuple_hash(tuple *t)
{
    return (inx_addr_hash(t->sip) + inx_addr_hash(t->dip) + t->sport + t->dport) % HASH_SIZE;
}

int
inx_addr_equal(inx_addr a, inx_addr b)
{
    if (a.family != b.family)
	return 0;
    if (AF_INET == a.family)
	return a.u.in4.s_addr == b.u.in4.s_addr;
    return 0 == memcmp(&a.u.in6, &b.u.in6, 16);
}

int
tuple_equal(tuple *a, tuple *b)
{
    if ((a->sport == b->sport) &&
	(a->dport == b->dport) &&
	inx_addr_equal(a->sip, b->sip) &&
	inx_addr_equal(a->dip, b->dip))
	return 1;
    if ((a->sport == b->dport) &&
	(a->dport == b->sport) &&
	inx_addr_equal(a->sip, b->dip) &&
	inx_addr_equal(a->dip, b->sip))
	return 1;
    return 0;
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
hashDelete(conn *f)
{
    unsigned int i = tuple_hash(&f->tuple);
    conn **F;
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
output_fname(const conn *f)
{
    static char fname[256];
    static char src_s[128];
    static char dst_s[128];
    inet_ntop(f->tuple.sip.family, &f->tuple.sip.u, src_s, sizeof(src_s));
    inet_ntop(f->tuple.dip.family, &f->tuple.dip.u, dst_s, sizeof(dst_s));
    snprintf(fname, sizeof(fname),
	"%s/%u/%s/%s:%u-%s:%u@%lu.%06lu.pcap",
	src_s,
	f->tuple.sport,
	dst_s,
	src_s,
	f->tuple.sport,
	dst_s,
	f->tuple.dport,
	f->pkthead->hdr.ts.tv_sec,
	(unsigned long) f->pkthead->hdr.ts.tv_usec);
    return fname;
}


void
conn_pcap_open(conn *f)
{
    const char *file;
    if (NULL != f->fd)
	return;
    file = output_fname(f);
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
conn_free_packets(conn *f)
{
    packet *p;
    packet *n;
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
conn_pcap_write(conn *f)
{
    packet *p;
    if (0 == f->npackets)
	return;
    for (p = f->pkthead; p; p = p->next) {
	pcap_dump((void *) f->fd, &p->hdr, p->data);
	pkts_writ++;
    }
    conn_free_packets(f);
}

void
conn_pcap_close(conn *f)
{
    if (NULL == f->fd)
	return;
    pcap_dump_close(f->fd);
    nopen--;
    f->fd = NULL;
}

void
conn_free(conn *f)
{
    if (f->npackets)
	conn_free_packets(f);
    hashDelete(f);
    dlinkDelete(&f->lru, LRU);
    free(f);
    nconn--;
}

void
close_lru(void)
{
    int nc = 0;
    dlink_node *p = LRU->tail;
    fprintf(stderr, "Closing LRU...");
    while (nopen > (LIMIT_OPEN_FD / 2) && p) {
	conn *f = p->data;
	p = p->prev;
	if (NULL == f->fd)
	    continue;
	conn_pcap_write(f);
	conn_pcap_close(f);
	conn_free(f);
	nc++;
    }
    fprintf(stderr, "%d\n", nc);
}

void
flush(conn *f)
{
    if (nopen >= LIMIT_OPEN_FD)
	close_lru();
    conn_pcap_open(f);
    conn_pcap_write(f);
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
    conn *f;
    conn *next;
    fprintf(stderr, "Flushing...\n");
    for (i = 0; i < HASH_SIZE; i++) {
	for (f = Hash[i]; f; f = next) {
	    next = f->next;
	    if (0 == f->npackets)
		continue;
	    if (f->fd == NULL)
		conn_pcap_open(f);
	    conn_pcap_write(f);
	    n++;
	    if (0 == (n % 1000))
		fprintf(stderr, "flushed %d conns, open fd: %d\n", n, nopen);
	    if (nopen >= LIMIT_OPEN_FD)
		close_lru();
	}
    }
    fprintf(stderr, "flushed %d\n", n);
    fprintf(stderr, "open files: %d\n", nopen);
    fprintf(stderr, "max rss: %ld\n", getmaxrss());
}

void
stash2(conn *f, struct pcap_pkthdr *hdr, const unsigned char *data)
{
    packet *p = calloc(1, sizeof(*p));
    assert(p);
    p->hdr = *hdr;
    p->data = malloc(hdr->caplen);
    assert(p->data);
    memcpy(p->data, data, hdr->caplen);
    *f->pkttail = p;
    f->pkttail = &p->next;
    f->npackets++;
    npacketsmem++;
}

void
stash(tuple *t, struct pcap_pkthdr *hdr, const unsigned char *data)
{
    conn **F;
    conn *f;
    int i = tuple_hash(t);
    for (F = &Hash[i]; (f = *F); F = &(*F)->next) {
	if (tuple_equal(&f->tuple, t))
	    break;
    }
    if (NULL == f) {
	nconn++;
	f = calloc(1, sizeof(*f));
	assert(f);
	f->tuple = *t;
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
print_stats(struct timeval ts)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    fprintf(stderr, "%ld.%03ld: at %ld, %12" PRIu64 " read, %12" PRIu64 " stashed, %12" PRIu64 " writ, %9d conns, %4d files\n",
	(long) now.tv_sec, (long) now.tv_usec / 1000, (long) ts.tv_sec, pkts_read, pkts_stashed, pkts_writ, nconn, nopen);
}

int
my_tcp_handler(const struct tcphdr *tcp, int len, void *userdata)
{
    tuple *t = userdata;
    t->sport = nptohs(&tcp->th_sport);
    t->dport = nptohs(&tcp->th_dport);
    return 0;
}

int
my_ip4_handler(const struct ip *ip4, int len, void *userdata)
{
    tuple *t = userdata;
    t->sip.family = AF_INET;
    t->sip.u.in4 = ip4->ip_src;
    t->dip.family = AF_INET;
    t->dip.u.in4 = ip4->ip_dst;
    return 0;
}

int
my_ip6_handler(const struct ip6_hdr *ip6, int len, void *userdata)
{
    tuple *t = userdata;
    t->sip.family = AF_INET6;
    t->sip.u.in6 = ip6->ip6_src;
    t->dip.family = AF_INET6;
    t->dip.u.in6 = ip6->ip6_dst;
    return 0;
}

int
main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE + 1];
    struct pcap_pkthdr hdr;
    const u_char *data;
    char *filterstr = NULL;
    struct bpf_program fp;
    int ch;

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    memset(Hash, '\0', sizeof(Hash));
    LRU = calloc(1, sizeof(LRU));
    assert(LRU);

    // Process command line
    while ((ch = getopt(argc, argv, "bf:ls")) != -1) {
	switch (ch) {
	case 'b':
	    filterstr = strdup(optarg);
	    break;
	case 'l':
	    use_subdirs = 0;
	    break;
	default:
	    fprintf(stderr, "usage: %s [-l] [-b bpfprogram]\n", argv[0]);
	    exit(1);
	    break;
	}
    }
    argc -= optind;
    argv += optind;

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
    callback_tcp = my_tcp_handler;
    callback_ipv4 = my_ip4_handler;
    callback_ipv6 = my_ip6_handler;

    while ((data = pcap_next(in, &hdr))) {
	tuple T;
	memset(&T, 0, sizeof(T));
	pkts_read++;
	handle_pcap((u_char *) & T, &hdr, data);
	if (T.sip.family == 0)
	    continue;
	if (0 == T.sport && 0 == T.dport)
	    continue;
	stash(&T, &hdr, data);
	if (0 == (++pkts_stashed & 0x3FFF)) {
	    print_stats(hdr.ts);
	    if (npacketsmem > LIMIT_PKTS_IN_MEM) {
		flushall();
	    }
	}
    }
    flushall();
    print_stats(hdr.ts);
    fprintf(stderr, "Max RSS  %ld KB \n", getmaxrss());
    return 0;
}
