#ifndef __FTP__H__
#define __FTP__H__

#include <pcap.h>

void dechiffrage_ftp(const u_char *packet, int size_of_lower_layer, const struct pcap_pkthdr *header, int verbose);

#endif
