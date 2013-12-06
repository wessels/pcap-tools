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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "pcap_layers.h"


#define N_SPLIT 256
#define MAX_LEVELS 16		/* 4 for IPv4, 16 for IPv6 */
static int theLevel = 0;

/*
 * the tmpdirs array holds temp dir names that should be 'rm -rf'd
 * if the program exits unexpectedly.  
*/
#define TMPDIRNAMESZ 128
static char tmpdirs[MAX_LEVELS][TMPDIRNAMESZ];

int
my_ip4_af_setter(const struct ip *ip4, int len, void *userdata)
{
    *((sa_family_t *) userdata) = AF_INET;
    return 0;
}

int
my_ip6_af_setter(const struct ip6_hdr *ip6, int len, void *userdata)
{
    *((sa_family_t *) userdata) = AF_INET6;
    return 0;
}

int
my_ip4_handler(const struct ip *ip4, int len, void *userdata)
{
    *((int *)userdata) = ntohl(ip4->ip_src.s_addr) >> (theLevel << 3) & 0xFF;
    return 0;
}

int
my_ip6_handler(const struct ip6_hdr *ip6, int len, void *userdata)
{
    *((int *)userdata) = ip6->ip6_src.s6_addr[15 - theLevel];
    return 0;
}

pcap_t *
my_pcap_open_offline(const char *f)
{
    char errbuf[PCAP_ERRBUF_SIZE + 1];
    pcap_t *in = pcap_open_offline(f, errbuf);
    if (NULL == in)
	errx(1, "[%d] %s(%d) %s: %s", getpid(), __FILE__,__LINE__,f, errbuf);
    return in;
}

void
cleanup(int sig)
{
    int i;
    char cmd[256];
    for (i=0; i<16; i++) {
	if ('\0' == tmpdirs[i][0])
		continue;
	snprintf(cmd, sizeof(cmd), "/bin/rm -r %s", tmpdirs[i]);
	system (cmd);
    }
    exit(1);
}

pcap_dumper_t *
my_pcap_dump_open(pcap_t * other, const char *f)
{
    pcap_dumper_t *out;
    out = pcap_dump_open(other, f);
    if (NULL == out)
	errx(1, f);
    return out;
}

void
pcap_sort(const char *inf, const char *outf, int level)
{
    pcap_t *in = NULL;
    pcap_dumper_t *pcap_out = NULL;
    pcap_dumper_t *out[N_SPLIT];
    struct pcap_pkthdr hdr;
    const u_char *data;
    int i;
    const char *dir;
    static char *twhiler = "-\\|/";
    static u_char tc = 0;

    memset(out, 0, sizeof(out));
    snprintf(tmpdirs[level], TMPDIRNAMESZ, "sort.%d.XXXXXXXXXXX", level);
    dir = mkdtemp(tmpdirs[level]);
    if (NULL == dir)
	errx(1, tmpdirs[level]);
    theLevel = level;
    /*fprintf(stderr, "Sorting '%s' at level %d\n", inf, theLevel);*/
    fprintf(stderr, "\r%c", twhiler[tc++ & 3]);
    in = my_pcap_open_offline(inf);
    pcap_layers_init(pcap_datalink(in), 0);
    callback_ipv4 = my_ip4_handler;
    callback_ipv6 = my_ip6_handler;
    while ((data = pcap_next(in, &hdr))) {
	int which = -1;
	handle_pcap((void *)&which, &hdr, data);
	assert(which != -1);
	if (NULL == out[which]) {
	    char tf[128];
	    snprintf(tf, 128, "%s/%d.%03d.tmp", dir, getpid(), which);
	    out[which] = my_pcap_dump_open(in, tf);
	}
	pcap_dump((void *)out[which], &hdr, data);
    }
    for (i = 0; i < N_SPLIT; i++)
	if (out[i])
	    pcap_dump_close(out[i]);

    /* fprintf(stderr, "Writing '%s' at level %d\n", outf, theLevel); */
    pcap_out = pcap_dump_open(in, outf);
    pcap_close(in);	/* close 'in; after using it to open 'out' */
    in = 0;
    for (i = 0; i < N_SPLIT; i++) {
	char tf[128];
	if (NULL == out[i])
	    continue;
	snprintf(tf, 128, "%s/%d.%03d.tmp", dir, getpid(), i);
	if (level > 0)
	    pcap_sort(tf, tf, level - 1);
	in = my_pcap_open_offline(tf);
	while ((data = pcap_next(in, &hdr)))
	    pcap_dump((void *)pcap_out, &hdr, data);
	pcap_close(in);
	if (0 != unlink(tf))
	    warn("unlink: %s", tf);
    }
    pcap_dump_close(pcap_out);
    if (0 != rmdir(dir))
	warn("rmdir: %s", dir);
    tmpdirs[level][0] = '\0';
}

pcap_dumper_t *
spawn(int level, pcap_t * other, int *rfd)
{
    pid_t kid;
    int p1[2];			/* parent -> child */
    int p2[2];			/* child -> parent */
    if (pipe(p1) < 0)
	errx(1, "pipe");
    if (pipe(p2) < 0)
	errx(1, "pipe");
    kid = fork();
    if (kid < 0)
	errx(1, "fork");
    if (0 == kid) {
	/* child */
	int i;
	if (dup2(p1[0], 0) < 0)	/* p->c pipe becomes c's stdin */
	    errx(1, "dup2");
	if (dup2(p2[1], 1) < 0)	/* c->p pipe becomes c's stdout */
	    errx(1, "dup2");
	stdin = fdopen(0, "r");	/* Because pcap uses stdio!! */
	stdout = fdopen(1, "w");
	for (i=3; i<10; i++)
	    close(i);
	pcap_sort("-", "-", level);
	exit(0);
    } else {
	/* parent */
	FILE *fp1 = fdopen(p1[1], "w");	/* p->c */
	pcap_dumper_t *out;
	if (NULL == fp1)
	    errx(1, "fdopen");
	out = pcap_dump_fopen(other, fp1);	/* writing p->c */
	if (NULL == out)
	    errx(1, "pcap_dump_fopen");
	close(p1[0]);
	close(p2[1]);
	*rfd = p2[0];
	return out;
    }
}

uint64_t
pcap_copy_fd_to_dump(int fd, pcap_dumper_t *out)
{
    uint64_t count = 0;
    char errbuf[PCAP_ERRBUF_SIZE + 1];
    FILE *fp = fdopen(fd, "r");
    pcap_t *in;
    struct pcap_pkthdr hdr;
    const u_char *data;

    if (NULL == fp)
	errx(1, "fdopen");
    in = pcap_fopen_offline(fp, errbuf);
    if (NULL == in)
	errx(1, errbuf);
    while ((data = pcap_next(in, &hdr))) {
	pcap_dump((u_char *) out, &hdr, data);
	count++;
    }
    pcap_close(in);
    return count;
}


void
pcap_sort_by_af_spawn(const char *inf, const char *outf)
{
    pcap_t *in = NULL;
    pcap_dumper_t *out = NULL;
    pcap_dumper_t *v4dump = NULL;
    pcap_dumper_t *v6dump = NULL;
    int v4rfd = -1;
    int v6rfd = -1;
    struct pcap_pkthdr hdr;
    const u_char *data;
    uint64_t v4sorted = 0;
    uint64_t v6sorted = 0;
    struct timeval start;
    struct timeval stop;
    struct timeval duration;

    gettimeofday(&start, NULL);
    in = my_pcap_open_offline(inf);
    v4dump = spawn(3, in, &v4rfd);
    v6dump = spawn(15, in, &v6rfd);

    pcap_layers_init(pcap_datalink(in), 0);
    callback_ipv4 = my_ip4_af_setter;
    callback_ipv6 = my_ip6_af_setter;
    while ((data = pcap_next(in, &hdr))) {
	sa_family_t fam = AF_UNSPEC;
	handle_pcap((void *)&fam, &hdr, data);
	switch (fam) {
	case AF_INET:
	    pcap_dump((u_char *) v4dump, &hdr, data);
	    break;
	case AF_INET6:
	    pcap_dump((u_char *) v6dump, &hdr, data);
	    break;
	default:
	    break;
	}
    }
    pcap_dump_close(v4dump);
    pcap_dump_close(v6dump);

    out = my_pcap_dump_open(in, outf);
    pcap_close(in);
    v6sorted = pcap_copy_fd_to_dump(v6rfd, out);
    v4sorted = pcap_copy_fd_to_dump(v4rfd, out);
    gettimeofday(&stop, NULL);
    timersub(&stop, &start, &duration);
    fprintf(stderr, "\nSorted %"PRIu64" IPv4 and %"PRIu64" IPv6 packets in %d.%d seconds\n",
	v4sorted, v6sorted,
	(int) duration.tv_sec, (int) duration.tv_usec / 100000);
    exit(0);
}

int
main(int argc, char *argv[])
{
    if (argc != 1) {
	fprintf(stderr, "usage: tcpdump-sort-by-sip < in > out\n");
	exit(1);
    }
    signal(SIGHUP, cleanup);
    signal(SIGINT, cleanup);
    signal(SIGQUIT, cleanup);
    signal(SIGBUS, cleanup);
    signal(SIGSEGV, cleanup);
    signal(SIGPIPE, cleanup);
    signal(SIGTERM, cleanup);
    memset(tmpdirs, '\0', sizeof(tmpdirs));
    pcap_sort_by_af_spawn("-", "-");
    exit(0);
}
