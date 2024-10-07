#ifndef __UDP__H__
#define __UDP__H__

#define PORT_BOOTP_CLIENT 68
#define PORT_BOOTP_SERVEUR 67
#define PORT_DNS_UDP 53
#define PORT_TFTP 69

#include <netinet/udp.h>
#include <stdbool.h>
#include <pcap.h>

void dechiffrage_udp(const u_char *packet, int size_of_lower_layer, const struct pcap_pkthdr *header, bool is_icmp, int verbose);

#endif
