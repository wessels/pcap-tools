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

#include "pcap-tools.h"

pcap_dumper_t *out = NULL;
unsigned int fifocount = 0;
const char *filterstr = 0;
const char *progname = 0;
int verbose = 0;

void
join(const char *pcapfile)
{
    pcap_t *in = NULL;
    struct pcap_pkthdr hdr;
    const u_char *data;
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
	pcap_dump((void *)out, &hdr, data);
    }
    my_pcap_close_offline(in);
}

int
qsort_strcmp(const void *a, const void *b)
{
	return strcmp(*((char**)a), *((char**)b));
}

void
usage(void)
{
	fprintf(stderr, "usage: pcap-join pcapfiles ...\n       pcap-join directory\n       pcap-join\t(read files from stdin)\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
    int i;
    if (strrchr(argv[0], '/'))
	progname = strdup(1+strrchr(argv[0], '/'));
    else
	progname = strdup(argv[0]);
    while ((i = getopt(argc, argv, "b:hv")) != -1) {
        switch (i) {
            case 'b':
                filterstr = strdup(optarg);
                break;
            case '?':
            case 'h':
                default:
                usage();
            case 'v':
                verbose++;
		break;
        }
    }
    argc -= optind;
    argv += optind;

    if (0 == argc) {
	char buf[512];
	/* read file names from stdin */
	while (NULL != fgets(buf, 512, stdin)) {
		strtok(buf, "\r\n");
		if (verbose > 0)
			fprintf(stderr, "%s: %s\n", progname, buf);
		join(buf);
	}
    } else for (i = 0; i < argc; i++) {
	struct stat sb;
	if (stat(argv[i], &sb) < 0)
		err(1, "%s", argv[i]);
	if (S_ISDIR(sb.st_mode)) {
		DIR *d;
		unsigned int filecnt = 0;
		unsigned int k;
		struct dirent *e;
		char **paths;
		/*
		 * count files
		 */
		d = opendir(argv[i]);
		if (NULL == d)
			err(1, "%s", argv[i]);
		while (NULL != (e = readdir(d))) {
			if (*e->d_name == '.')
				continue;
			filecnt++;
		}
		closedir(d);
		/*
		 * read unsorted files
		 */
		paths = calloc(filecnt, sizeof(char *));
		filecnt = 0;
		d = opendir(argv[i]);
		if (NULL == d)
			err(1, "%s", argv[i]);
		while (NULL != (e = readdir(d))) {
			char path[512];
			if (*e->d_name == '.')
				continue;
			snprintf(path, sizeof(path), "%s/%s", argv[i], e->d_name);
			*(paths+(filecnt++)) = strdup(path);
		}
		closedir(d);
		qsort(paths, filecnt, sizeof(char *), qsort_strcmp);
		for (k = 0; k < filecnt; k++) {
			if (verbose > 0)
				fprintf(stderr, "Joining %s\n", *(paths+k));
			join(*(paths+k));
			free(*(paths+k));
		}
		free(paths);
	} else {
		join(argv[i]);
	}
    }
    if (out)
	pcap_dump_close(out);
    exit(0);
}
