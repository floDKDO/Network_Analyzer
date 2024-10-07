#ifndef __MON__BOOTP__H__
#define __MON__BOOTP__H__

#include "bootp.h"
#include <pcap.h>

struct option_tlv
{
	unsigned char type;
	unsigned char length;
};

void dechiffrage_bootp(const u_char *packet, int size_of_lower_layer, const struct pcap_pkthdr *header, int verbose);

#endif
