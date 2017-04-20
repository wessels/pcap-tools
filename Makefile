PREFIX=/usr/local
OBJS=\
pcap-tools.o

PROGS= \
pcap-extract-interval \
pcap-subtract-timestamp \
pcap-join \
pcap-remove-dupe \
pcap-remove-bogus \
pcap-split \
pcap-change-dst \
pcap-change-ip \
pcap-decapsulate-gre \
pcap-find-misordered \
pcap-reorder \
pcap-fix-linux-af-inet6 \
pcap-strip-vlans \
pcap-print-sip \
pcap-print-tcp-options \
pcap-print-sip-protocol \
pcap-print-time-qname-qtype-rcode \
pcap-separate-by-sip \
pcap-separate-by-connection \
pcap-sort-by-sip \
pcap-merge-sorted-sip \
pcap-separate \
pcap-to-dlt-loop \
pcap-to-dlt-raw \
pcap-to-dlt-en10mb \
pcap-bad-udp-checksum
#pcap-print-time-sip-len \

LIBPCAP=-lpcap

LIBPCAPLAYERS=-L${PREFIX}/lib -lpcap_layers

# BSD
#LIBMD5=-lmd
#INCDIRS=

# LINUX
LIBMD5=-lcrypto 
INCDIRS=-I${PREFIX}/include

CFLAGS = -Wall -g ${INCDIRS}

all: ${PROGS}

pcap-tools.o: pcap-tools.c pcap-tools.h
	${CC} -c -o $@ pcap-tools.c


pcap-extract-interval: pcap-extract-interval.o ${OBJS}
	${CC} -o $@ ${@}.o ${OBJS} ${LIBPCAP}

pcap-subtract-timestamp: pcap-subtract-timestamp.o ${OBJS}
	${CC} -o $@ ${@}.o ${OBJS} ${LIBPCAP}

pcap-join: pcap-join.o ${OBJS}
	${CC} -o $@ ${@}.o ${OBJS} ${LIBPCAP}

pcap-remove-dupe: pcap-remove-dupe.o ${OBJS}
	${CC} -o $@ ${@}.o ${OBJS} ${LIBPCAP} ${LIBMD5}

pcap-remove-bogus: pcap-remove-bogus.o ${OBJS}
	${CC} -o $@ ${@}.o ${OBJS} ${LIBPCAP}

pcap-split: pcap-split.o ${OBJS}
	${CC} -o $@ ${@}.o ${OBJS} ${LIBPCAP}

pcap-change-dst: pcap-change-dst.o ${OBJS}
	${CC} -o $@ ${@}.o ${OBJS} ${LIBPCAP} ${LIBPCAPLAYERS}

pcap-change-ip: pcap-change-ip.o ${OBJS}
	${CC} -o $@ ${@}.o ${OBJS} ${LIBPCAP} ${LIBPCAPLAYERS}

pcap-decapsulate-gre: pcap-decapsulate-gre.o ${OBJS}
	${CC} -o $@ ${@}.o ${OBJS} ${LIBPCAP} ${LIBPCAPLAYERS}

pcap-find-misordered: pcap-find-misordered.o ${OBJS}
	${CC} -o $@ ${@}.o ${OBJS} ${LIBPCAP}

pcap-reorder: pcap-reorder.o ${OBJS}
	${CC} -o $@ ${@}.o ${OBJS} ${LIBPCAP} ${LIBPCAPLAYERS}

pcap-fix-linux-af-inet6: pcap-fix-linux-af-inet6.o ${OBJS}
	${CC} -o $@ ${@}.o ${OBJS} ${LIBPCAP}

pcap-strip-vlans: pcap-strip-vlans.o ${OBJS}
	${CC} -o $@ ${@}.o ${OBJS} ${LIBPCAP}

pcap-print-sip: pcap-print-sip.o ${OBJS}
	${CC} -o $@ ${@}.o ${OBJS} ${LIBPCAP} ${LIBPCAPLAYERS}

pcap-print-tcp-options: pcap-print-tcp-options.o ${OBJS}
	${CC} -o $@ ${@}.o ${OBJS} ${LIBPCAP} ${LIBPCAPLAYERS}

pcap-print-sip-protocol: pcap-print-sip-protocol.o ${OBJS}
	${CC} -o $@ ${@}.o ${OBJS} ${LIBPCAP} ${LIBPCAPLAYERS}

pcap-separate-by-sip: pcap-separate-by-sip.o ${OBJS}
	${CC} -o $@ ${@}.o ${OBJS} ${LIBPCAP} ${LIBPCAPLAYERS}

pcap-separate-by-connection: pcap-separate-by-connection.o ${OBJS}
	${CC} -o $@ ${@}.o ${OBJS} ${LIBPCAP} ${LIBPCAPLAYERS}

pcap-sort-by-sip: pcap-sort-by-sip.o ${OBJS}
	${CC} -o $@ ${@}.o ${OBJS} ${LIBPCAP} ${LIBPCAPLAYERS}

pcap-separate: pcap-separate.o ${OBJS}
	${CC} -o $@ ${@}.o ${OBJS} ${LIBPCAP} ${LIBPCAPLAYERS}

pcap-to-dlt-loop: pcap-to-dlt-loop.o ${OBJS}
	${CC} -o $@ ${@}.o ${OBJS} ${LIBPCAP} ${LIBPCAPLAYERS}

pcap-to-dlt-raw: pcap-to-dlt-raw.o ${OBJS}
	${CC} -o $@ ${@}.o ${OBJS} ${LIBPCAP} ${LIBPCAPLAYERS}

pcap-to-dlt-en10mb: pcap-to-dlt-en10mb.o ${OBJS}
	${CC} -o $@ ${@}.o ${OBJS} ${LIBPCAP} ${LIBPCAPLAYERS}

pcap-merge-sorted-sip: pcap-merge-sorted-sip.o ${OBJS}
	${CC} -o $@ ${@}.o ${OBJS} ${LIBPCAP} ${LIBPCAPLAYERS}

#pcap-print-time-sip-len: pcap-print-time-sip-len.o
	#${CC} -o $@ ${@}.o ${LIBPCAP} ${LIBPCAPLAYERS}

pcap-print-time-qname-qtype-rcode: pcap-print-time-qname-qtype-rcode.o
	${CC} -o $@ ${@}.o ${LIBPCAP} ${LIBPCAPLAYERS} -lldns

pcap-bad-udp-checksum: pcap-bad-udp-checksum.o
	${CC} -o $@ ${@}.o ${LIBPCAP} ${LIBPCAPLAYERS} -linx_addr_c


clean:
	@for f in ${PROGS}; do \
		rm -fv $$f.o $$f ; \
	done
	rm -fv ${OBJS}

install:
	@for f in ${PROGS}; do \
		echo "install -C -m 755 $$f ${PREFIX}/bin"; \
		install -C -m 755 $$f ${PREFIX}/bin ; \
	done
