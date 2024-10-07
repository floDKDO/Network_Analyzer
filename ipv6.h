#ifndef __IPV6__H__
#define __IPV6__H__

#define ICMPV6_PROTOCOL 0x3A
#define TCP_PROTOCOL 0x06
#define UDP_PROTOCOL 0x11

#define ROUTING_EXTENSION 43
#define ROUTING_TYPE_0 0
#define ROUTING_TYPE_2 2
#define ROUTING_TYPE_4 4

#define FRAGMENT_EXTENSION 44
#define HOP_BY_HOP_EXTENSION 0
#define DESTINATION_EXTENSION 60

#include <netinet/ip6.h>
#include <stdbool.h>
#include <pcap.h>

void dechiffrage_ipv6(const u_char *packet, int size_of_lower_layer, const struct pcap_pkthdr *header, int verbose);
void dechiffrage_icmpv6(const u_char *packet, int size_of_lower_layer, const struct pcap_pkthdr *header, int verbose);

#endif
