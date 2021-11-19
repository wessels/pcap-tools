#include <unistd.h>
#include <stdlib.h>
#include <err.h>
#include <pcap.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <assert.h>

pcap_t *
my_pcap_open_offline(const char *pcapfile)
{
    char errbuf[PCAP_ERRBUF_SIZE + 1];
    char fifoname[256];
    int waitstatus;
    const char *readfile = pcapfile;
    fifoname[0] = '\0';
    static unsigned int fifocount = 0;
    pcap_t *in;
    assert(pcapfile);
    if (pcapfile[0] == '|') {
	char **args = 0;
	unsigned int nargs = 0;
	unsigned int i = 0;
	/* count arguments */
	nargs++;		/* first arg */
	for (const char *s = pcapfile; *s; s++) {
	    if (*s == ' ')
		nargs++;
	}
	nargs++;		/* terminating null */
	args = calloc(nargs, sizeof(char *));
	args[0] = strtok((char *) pcapfile + 1, " ");
	for (unsigned int i = 1; i < nargs - 1; i++) {
	    args[i] = strtok(NULL, " ");
	    assert(args[i]);
	}
	snprintf(fifoname, 256, "/tmp/fifo.%d.%u", getpid(), fifocount++);
	mkfifo(fifoname, 0600);
	if (0 == fork()) {
	    close(1);
	    open(fifoname, O_WRONLY);
	    execvp(args[0], args);
	    perror(args[0]);
	    abort();
	}
	readfile = fifoname;
    } else if (0 == strcmp(pcapfile + strlen(pcapfile) - 3, ".gz")) {
	snprintf(fifoname, 256, "/tmp/fifo.%d.%u", getpid(), fifocount++);
	mkfifo(fifoname, 0600);
	if (0 == fork()) {
	    close(1);
	    open(fifoname, O_WRONLY);
	    execlp("gzip", "gzip", "-dc", pcapfile, NULL);
	    perror("gzip");
	    abort();
	}
	readfile = fifoname;
    } else if (0 == strcmp(pcapfile + strlen(pcapfile) - 4, ".bz2")) {
	snprintf(fifoname, 256, "/tmp/fifo.%d.%u", getpid(), fifocount++);
	mkfifo(fifoname, 0600);
	if (0 == fork()) {
	    close(1);
	    open(fifoname, O_WRONLY);
	    execlp("bzip2", "bzip2", "-dc", pcapfile, NULL);
	    perror("bzip2");
	    abort();
	}
	readfile = fifoname;
    } else if (0 == strcmp(pcapfile + strlen(pcapfile) - 3, ".xz")) {
	snprintf(fifoname, 256, "/tmp/fifo.%d.%u", getpid(), fifocount++);
	mkfifo(fifoname, 0600);
	if (0 == fork()) {
	    close(1);
	    open(fifoname, O_WRONLY);
	    execlp("xz", "xz", "-dc", pcapfile, NULL);
	    perror("xz");
	    abort();
	}
	readfile = fifoname;
    }
    in = pcap_open_offline(readfile, errbuf);
    if (fifoname[0])
	unlink(fifoname);
    if (NULL == in && fifoname[0]) {
	waitpid(-1, &waitstatus, 0);
	return 0;
    }
    if (NULL == in)
	errx(1, "[%d] %s(%d) %s: %s", getpid(), __FILE__, __LINE__, pcapfile, errbuf);
    return in;
}

void
my_pcap_close_offline(pcap_t * in)
{
    int waitstatus;
    pcap_close(in);
    waitpid(-1, &waitstatus, 0);
}
