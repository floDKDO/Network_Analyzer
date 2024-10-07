#ifndef __ARP__H__
#define __ARP__H__

#include <netinet/if_ether.h>
#include <pcap.h>

void dechiffrage_arp(const u_char *packet, int size_of_lower_layer, int verbose);

#endif
