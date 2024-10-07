#ifndef __IPV4__H__
#define __IPV4__H__

#define ICMP_PROTOCOL 0x01
#define TCP_PROTOCOL 0x06
#define UDP_PROTOCOL 0x11

#include <netinet/ip.h>
#include <stdbool.h>
#include <pcap.h>

void dechiffrage_ipv4(const u_char *packet, int size_of_lower_layer, const struct pcap_pkthdr *header, bool is_icmp, int verbose);
void dechiffrage_icmpv4(const u_char *packet, int size_of_lower_layer, const struct pcap_pkthdr *header, int verbose);

#endif
