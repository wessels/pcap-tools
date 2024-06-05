#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <dirent.h>
#include <getopt.h>
#include <err.h>
#include <regex.h>
#include <assert.h>

#include "pcap-tools.h"

pcap_dumper_t *out = NULL;
const char *filterstr = 0;
int opt_mergecap = 0;
const char *progname = 0;
const char *mergecap_cmd = "|mergecap -w -";

typedef struct
{
    unsigned int size;
    unsigned int cnt;
    char **files;
} filelist;

int verbose = 0;

void
join(const char *pcapfile)
{
    pcap_t *in = NULL;
    struct pcap_pkthdr hdr;
    const u_char *data;
    if (verbose > 0)
	fprintf(stderr, "Joining %s\n", pcapfile);
    in = my_pcap_open_offline(pcapfile);
    if (filterstr) {
	struct bpf_program fp;
	memset(&fp, '\0', sizeof(fp));
	if (pcap_compile(in, &fp, filterstr, 1, 0) < 0) {
	    fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(in));
	    exit(1);
	}
	if (pcap_setfilter(in, &fp) < 0) {
	    fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(in));
	    exit(1);
	}
    }
    while ((data = pcap_next(in, &hdr))) {
	if (!out) {
	    out = pcap_dump_open(in, "-");
	    if (NULL == out) {
		perror("stdout");
		exit(1);
	    }
	}
	pcap_dump((void *) out, &hdr, data);
    }
    my_pcap_close_offline(in);
}

struct
{
    int nmatch;
    const char *pat;
    const char *fmt;
    regex_t *re;
} time_patterns[] = {
    {7, "([0-9]{4})([0-9]{2})([0-9]{2}).([0-9]{2}):([0-9]{2}):([0-9]{2})", "%Y%m%d.%H:%M:%S", 0},
    {7, "([0-9]{4})([0-9]{2})([0-9]{2})/([0-9]{2})([0-9]{2})([0-9]{2})", "%Y%m%d/%H%M%S", 0},
    {0, 0, 0, 0}
};

time_t
parse_timestamp(const char *s)
{
    regmatch_t pmatch[10];
    struct tm tm;
    unsigned int k;
    for (k = 0; time_patterns[k].pat; k++) {
	if (0 == time_patterns[k].re) {
	    time_patterns[k].re = calloc(1, sizeof(*time_patterns[k].re));
	    if (0 != regcomp(time_patterns[k].re, time_patterns[k].pat, REG_EXTENDED)) {
		fprintf(stderr, "regcomp '%s' failed\n", time_patterns[k].pat);
		exit(1);
	    }
	}
	if (0 != regexec(time_patterns[k].re, s, time_patterns[k].nmatch, pmatch, 0)) {
	    continue;
	}
	assert(pmatch[0].rm_so > -1);
	if (0 == strptime(s + pmatch[0].rm_so, time_patterns[k].fmt, &tm))
	    continue;
	return timegm(&tm);
    }
    fprintf(stderr, "no time patterns matched '%s'\n", s);
    return 0;
}

int
qsort_strcmp(const void *a, const void *b)
{
    return strcmp(*((char **) a), *((char **) b));
}

int
qsort_strptime(const void *a, const void *b)
{
    time_t time_a = parse_timestamp(*((char **) a));
    time_t time_b = parse_timestamp(*((char **) b));
    if (time_a < time_b)
	return -1;
    if (time_a > time_b)
	return 1;
    return -1;
}

void
usage(void)
{
    fprintf(stderr, "usage: pcap-join [options] pcapfiles ...\n");
    fprintf(stderr, "       pcap-join [options] directory\n");
    fprintf(stderr, "       pcap-join [options] (reads files from stdin)\n");
    fprintf(stderr, "options:\n");
    fprintf(stderr, "       -v           verbose\n");
    fprintf(stderr, "       -b filter    apply pcap filter\n");
    exit(1);
}

filelist *
filelist_init(void)
{
    filelist *fl;
    fl = calloc(1, sizeof(*fl));
    fl->size = 64;
    fl->cnt = 0;
    fl->files = calloc(fl->size, sizeof(char *));
    return fl;
}

void
filelist_add(filelist * fl, const char *file)
{
    if (fl->cnt == fl->size) {
	char **tmp = calloc(fl->size << 1, sizeof(char *));
	memcpy(tmp, fl->files, fl->size * sizeof(char *));
	free(fl->files);
	fl->files = tmp;
	fl->size <<= 1;
    }
    fl->files[fl->cnt++] = strdup(file);
}

int
main(int argc, char *argv[])
{
    int i;
    filelist *infiles = 0;
    if (strrchr(argv[0], '/'))
	progname = strdup(1 + strrchr(argv[0], '/'));
    else
	progname = strdup(argv[0]);
    while ((i = getopt(argc, argv, "b:c:hmv")) != -1) {
	switch (i) {
	case 'b':
	    filterstr = strdup(optarg);
	    break;
	case 'c':	/* used as comment, eg in ps output */
	    break;
	case '?':
	case 'h':
	default:
	    usage();
	    break;
	case 'm':
	    opt_mergecap = 1;
	    break;
	case 'v':
	    verbose++;
	    break;
	}
    }
    argc -= optind;
    argv += optind;

    infiles = filelist_init();

    if (0 == argc) {
	char buf[512];
	/* read file names from stdin */
	while (NULL != fgets(buf, 512, stdin)) {
	    strtok(buf, "\r\n");
	    filelist_add(infiles, buf);
	}
    } else
	for (i = 0; i < argc; i++) {
	    struct stat sb;
	    if (stat(argv[i], &sb) < 0)
		err(1, "%s", argv[i]);
	    if (S_ISDIR(sb.st_mode)) {
		DIR *d;
		struct dirent *e;
		/*
		 * read unsorted files
		 */
		d = opendir(argv[i]);
		if (NULL == d)
		    err(1, "%s", argv[i]);
		while (NULL != (e = readdir(d))) {
		    char path[512];
		    if (*e->d_name == '.')
			continue;
		    snprintf(path, sizeof(path), "%s/%s", argv[i], e->d_name);
		    filelist_add(infiles, path);
		}
		closedir(d);
		qsort(infiles->files, infiles->cnt, sizeof(char *), qsort_strcmp);

	    } else {
		filelist_add(infiles, argv[i]);
	    }
	}

    if (opt_mergecap) {
	size_t bufsize = 0;
	unsigned int j = 0;
	unsigned int k = 0;
	filelist *new = 0;
	new = filelist_init();
	qsort(infiles->files, infiles->cnt, sizeof(char *), qsort_strptime);
	while (j < infiles->cnt) {
	    char *buf = 0;
	    unsigned int i;
	    bufsize = strlen(mergecap_cmd);
	    while (k < infiles->cnt && parse_timestamp(infiles->files[j]) == parse_timestamp(infiles->files[k])) {
		bufsize += 1 + strlen(infiles->files[k]);
		k++;
	    }
	    bufsize += 1;	/* terminating null */
	    buf = calloc(bufsize, sizeof(char *));
	    strcat(buf, mergecap_cmd);
	    for (i = j; i < k; i++) {
		strcat(buf, " ");
		strcat(buf, infiles->files[i]);
	    }
	    assert(strlen(buf) == bufsize - 1);
	    filelist_add(new, buf);
	    j = k;
	    free(buf);
	    buf = 0;
	}
	for (i = 0; i < infiles->cnt; i++)
	    free(infiles->files[i]);
	free(infiles);
	infiles = new;
    }

    for (i = 0; i < infiles->cnt; i++) {
	join(infiles->files[i]);
	free(infiles->files[i]);
    }
    free(infiles);
    if (out)
	pcap_dump_close(out);
    exit(0);
}
