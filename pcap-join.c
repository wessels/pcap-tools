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

pcap_dumper_t *out = NULL;
unsigned int fifocount = 0;
const char *filterstr = 0;

void
join(const char *pcapfile)
{
    pcap_t *in = NULL;
    char errbuf[PCAP_ERRBUF_SIZE + 1];
    struct pcap_pkthdr hdr;
    const u_char *data;
    char fifoname[256];
    int waitstatus;
    const char *readfile = pcapfile;
    fifoname[0] = '\0';
    if (0 == strcmp(pcapfile + strlen(pcapfile) - 3, ".gz")) {
	snprintf(fifoname, 256, "/tmp/fifo.%d.%u", getpid(), fifocount++);
	mkfifo(fifoname, 0600);
	if (0 == fork()) {
	    close(1);
	    open(fifoname, O_WRONLY);
	    execl("/usr/bin/gzip", "/usr/bin/gzip", "-dc", pcapfile, NULL);
	    perror("gzip");
	    abort();
	}
	readfile = fifoname;
    }
    in = pcap_open_offline(readfile, errbuf);
    if (fifoname[0])
	unlink(fifoname);
    if (NULL == in && fifoname[0]) {
	waitpid(-1, &waitstatus, 0);
	return;
    }
    if (NULL == in) {
	fprintf(stderr, "%s: %s", pcapfile, errbuf);
	exit(1);
    }
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
    pcap_close(in);
    waitpid(-1, &waitstatus, 0);
}

int
qsort_strcmp(const void *a, const void *b)
{
	return strcmp(*((char**)a), *((char**)b));
}

void
usage(void)
{
	fprintf(stderr, "usage: tcpdump-join pcapfiles ...\n       tcpdump-join directory\n       tcpdump-join\t(read files from stdin)\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
    int i;
    while ((i = getopt(argc, argv, "b:h")) != -1) {
        switch (i) {
            case 'b':
                filterstr = strdup(optarg);
                break;
            case '?':
            case 'h':
                default:
                usage();
        }
    }
    argc -= optind;
    argv += optind;

    if (0 == argc) {
	char buf[512];
	/* read file names from stdin */
	while (NULL != fgets(buf, 512, stdin)) {
		strtok(buf, "\r\n");
		join(buf);
	}
    } else for (i = 0; i < argc; i++) {
	struct stat sb;
	if (stat(argv[i], &sb) < 0)
		err(1, argv[i]);
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
			err(1, argv[i]);
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
			err(1, argv[i]);
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
