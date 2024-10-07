#ifndef __TELNET__H__
#define __TELNET__H__

#define SE_COMMAND 240
#define SB_COMMAND 250
#define WILL_COMMAND 251
#define WONT_COMMAND 252
#define DO_COMMAND 253
#define DONT_COMMAND 254
#define IAC_COMMAND 255

#define ECHO_SUBCOMM 1
#define SUPPRESS_SUBCOMM 3
#define TERM_TYPE_SUBCOMM 24
#define WIND_SIZE_SUBCOMM 31
#define TERM_SPEED_SUBCOMM 32
#define LINE_MODE_SUBCOMM 34
#define ENV_VAR_SUBCOMM 36
#define NEW_ENV_VAR_SUBCOMM 39

#include <pcap.h>

void dechiffrage_telnet(const u_char *packet, int size_of_lower_layer, const struct pcap_pkthdr *header, int verbose);

#endif
