#ifndef __HTTP1__H__
#define __HTTP1__H__

#include <pcap.h>
#include <stdbool.h>

void dechiffrage_http1(const u_char *packet, int size_of_lower_layer, const struct pcap_pkthdr *header, bool is_server, int verbose);

#endif
