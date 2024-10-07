#ifndef __POP__H__
#define __POP__H__

#include <pcap.h>
#include <stdbool.h>

void dechiffrage_pop(const u_char *packet, int size_of_lower_layer, const struct pcap_pkthdr *header, bool is_server, int verbose);

#endif
