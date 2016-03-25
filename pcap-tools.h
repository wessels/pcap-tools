#ifndef PCAP_TOOLS_H
#define PCAP_TOOLS_H 1

/* Convert the network order 32 bit integer pointed to by p to host order.
 * p does not have to be aligned. */
#ifndef nptohl
#define nptohl(p) \
   ((((uint8_t*)(p))[0] << 24) | \
    (((uint8_t*)(p))[1] << 16) | \
    (((uint8_t*)(p))[2] << 8) | \
    ((uint8_t*)(p))[3])
#endif

/* Copy the host order 32 bit integer in x into the memory pointed to by p
 * in network order.  p does not have to be aligned. */
#ifndef htonpl
#define htonpl(p, x) \
    do { \
        ((uint8_t*)(p))[0] = (x & 0xFF000000) >> 24; \
        ((uint8_t*)(p))[1] = (x & 0x00FF0000) >> 16; \
        ((uint8_t*)(p))[2] = (x & 0x0000FF00) >> 8; \
        ((uint8_t*)(p))[3] = (x & 0x000000FF) >> 0; \
    } while (0)
#endif

/* Convert the network order 16 bit integer pointed to by p to host order.
 * p does not have to be aligned. */
#ifndef nptohs
#define nptohs(p) \
   ((((uint8_t*)(p))[0] << 8) | ((uint8_t*)(p))[1])
#endif

/* Copy the host order 16 bit integer in x into the memory pointed to by p
 * in network order.  p does not have to be aligned. */
#ifndef htonps
#define htonps(p, x) \
    do { \
        ((uint8_t*)(p))[0] = (x & 0xFF00) >> 8; \
        ((uint8_t*)(p))[1] = (x & 0x00FF) >> 0; \
    } while (0)
#endif

pcap_t * my_pcap_open_offline(const char *pcapfile);

#endif /* PCAP_TOOLS_H */
