#ifndef __ETHERNET__H__
#define __ETHERNET__H__

#include <net/ethernet.h>
#include <pcap.h>

void dechiffrage_ethernet(const u_char *packet, const struct pcap_pkthdr *header, int verbose);

#endif
