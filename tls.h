#ifndef __TLS__H__
#define __TLS__H__

#define TLS_CIPHER 20
#define TLS_ALERT 21
#define TLS_HANDSHAKE 22
#define TLS_APP_DATA 23
#define TLS_HEARTBEAT 24
#define TLS_TLS1_2 25
#define TLS_ACK 26
#define TLS_RETURN 27

#include <pcap.h>
#include <stdbool.h>

void dechiffrage_tls(const u_char *packet, int size_of_lower_layer, const struct pcap_pkthdr *header, int verbose);

#endif
