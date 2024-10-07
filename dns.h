#ifndef __DNS__H__
#define __DNS__H__

#define TYPE_A 1
#define TYPE_NS 2
#define TYPE_CNAME 5
#define TYPE_SOA 6
#define TYPE_PTR 12
#define TYPE_HINFO 13
#define TYPE_MX 15
#define TYPE_TXT 16
#define TYPE_AAAA 28
#define TYPE_OPT 41

#define CLASS_IN 1

#include <pcap.h>

void dechiffrage_dns(const u_char *packet, int size_of_lower_layer, const struct pcap_pkthdr *header, int verbose);

#endif
