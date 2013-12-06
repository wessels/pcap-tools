
PROGS= \
pcap-extract-interval \
pcap-subtract-timestamp \
pcap-join \
pcap-remove-dupe \
pcap-remove-bogus \
pcap-split \
pcap-change-dst \
pcap-decapsulate-gre \
pcap-find-misordered \
pcap-reorder \
pcap-fix-linux-af-inet6 \
pcap-strip-vlans \
pcap-print-sip \
pcap-print-sip-protocol \
pcap-separate-by-sip \
pcap-sort-by-sip \
pcap-separate \
pcap-to-dlt-loop \
pcap-to-dlt-raw \
pcap-to-dlt-en10mb

LIBPCAP=-lpcap

LIBPCAPLAYERS=-lpcap_layers

# BSD
#LIBMD5=-lmd
#INCDIRS=

# LINUX
LIBMD5=-lcrypto
INCDIRS=

CFLAGS = -Wall -g ${INCDIRS}

all: ${PROGS}


pcap-extract-interval: pcap-extract-interval.o
	${CC} -o $@ ${@}.o ${LIBPCAP}

pcap-subtract-timestamp: pcap-subtract-timestamp.o
	${CC} -o $@ ${@}.o ${LIBPCAP}

pcap-join: pcap-join.o
	${CC} -o $@ ${@}.o ${LIBPCAP}

pcap-remove-dupe: pcap-remove-dupe.o
	${CC} -o $@ ${@}.o ${LIBPCAP} ${LIBMD5}

pcap-remove-bogus: pcap-remove-bogus.o
	${CC} -o $@ ${@}.o ${LIBPCAP}

pcap-split: pcap-split.o
	${CC} -o $@ ${@}.o ${LIBPCAP}

pcap-change-dst: pcap-change-dst.o
	${CC} -o $@ ${@}.o ${LIBPCAP} ${LIBPCAPLAYERS}

pcap-decapsulate-gre: pcap-decapsulate-gre.o
	${CC} -o $@ ${@}.o ${LIBPCAP} ${LIBPCAPLAYERS}

pcap-find-misordered: pcap-find-misordered.o
	${CC} -o $@ ${@}.o ${LIBPCAP}

pcap-reorder: pcap-reorder.o
	${CC} -o $@ ${@}.o ${LIBPCAP}

pcap-fix-linux-af-inet6: pcap-fix-linux-af-inet6.o
	${CC} -o $@ ${@}.o ${LIBPCAP}

pcap-strip-vlans: pcap-strip-vlans.o
	${CC} -o $@ ${@}.o ${LIBPCAP}

pcap-print-sip: pcap-print-sip.o
	${CC} -o $@ ${@}.o ${LIBPCAP} ${LIBPCAPLAYERS}

pcap-print-sip-protocol: pcap-print-sip-protocol.o
	${CC} -o $@ ${@}.o ${LIBPCAP} ${LIBPCAPLAYERS}

pcap-separate-by-sip: pcap-separate-by-sip.o
	${CC} -o $@ ${@}.o ${LIBPCAP} ${LIBPCAPLAYERS}

pcap-sort-by-sip: pcap-sort-by-sip.o
	${CC} -o $@ ${@}.o ${LIBPCAP} ${LIBPCAPLAYERS}

pcap-separate: pcap-separate.o
	${CC} -o $@ ${@}.o ${LIBPCAP} ${LIBPCAPLAYERS}

pcap-to-dlt-loop: pcap-to-dlt-loop.o
	${CC} -o $@ ${@}.o ${LIBPCAP} ${LIBPCAPLAYERS}

pcap-to-dlt-raw: pcap-to-dlt-raw.o
	${CC} -o $@ ${@}.o ${LIBPCAP} ${LIBPCAPLAYERS}

pcap-to-dlt-en10mb: pcap-to-dlt-en10mb.o
	${CC} -o $@ ${@}.o ${LIBPCAP} ${LIBPCAPLAYERS}



clean:
	@for f in ${PROGS}; do \
		rm -fv $$f.o $$f ; \
	done

install:
	@for f in ${PROGS}; do \
		echo "install -C -m 755 $$f /usr/local/bin"; \
		install -C -m 755 $$f /usr/local/bin ; \
	done
