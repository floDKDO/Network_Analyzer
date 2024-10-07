#ifndef __TFTP__H__
#define __TFTP__H__

#define OP_RRQ 1
#define OP_WRQ 2
#define OP_DATA 3
#define OP_ACK 4
#define OP_ERR 5

#define ERR_NOT_DEF 0
#define ERR_FILE_NOT_FOUND 1
#define ERR_ACC_VIOLATION 2
#define ERR_DISK_FULL 3
#define ERR_ILLEGAL_OP 4
#define ERR_UNKNOWN_ID 5
#define ERR_FILE_EXISTS 6
#define ERR_NO_USER 7

#include <pcap.h>

void dechiffrage_tftp(const u_char *packet, int size_of_lower_layer, const struct pcap_pkthdr *header, int verbose);

#endif
