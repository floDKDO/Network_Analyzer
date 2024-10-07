#ifndef __TCP__H__
#define __TCP__H__

#define PORT_SMTP 25 
#define PORT_SMTP_CHIFFR_IMPL 465
#define PORT_SMTP_CHIFFR_EXPL 587
#define PORT_DNS_TCP 53
#define PORT_POP 110
#define PORT_POP_SSL 995
#define PORT_IMAP 143
#define PORT_IMAPS 993
#define PORT_FTP_DATA 20
#define PORT_FTP_CONN 21
#define PORT_TELNET 23
#define PORT_HTTP 80
#define PORT_HTTPS 443 

#include <netinet/tcp.h>
#include <stdbool.h>
#include <pcap.h>

struct option_tlv
{
	unsigned char type;
	unsigned char length;
};

void dechiffrage_tcp(const u_char *packet, int size_of_lower_layer, const struct pcap_pkthdr *header, bool is_icmp, int verbose);

#endif
