#ifndef __HTTP2__H__
#define __HTTP2__H__

#define TYPE_DATA 0
#define TYPE_HEADERS 1
#define TYPE_PRIORITY 2
#define TYPE_RST_STREAM 3
#define TYPE_SETTINGS 4
#define TYPE_PUSH_PROMISE 5
#define TYPE_PING 6
#define TYPE_GOAWAY 7
#define TYPE_WINDOW_UPDATE 8
#define TYPE_CONTINUATION 9

#define NO_ERROR 0
#define PROTOCOL_ERROR 1
#define INTERNAL_ERROR 2
#define FLOW_CONTROL_ERROR 3
#define SETTINGS_TIMEOUT 4
#define STREAM_CLOSED 5
#define FRAME_SIZE_ERROR 6
#define REFUSED_STREAM 7
#define CANCEL 8
#define COMPRESSION_ERROR 9
#define CONNECT_ERROR 10
#define ENHANCE_YOUR_CALM 11
#define INADEQUATE_SECURITY 12
#define HTTP_1_1_REQUIRED 13

#define SETTINGS_HEADER_TABLE_SIZE 1
#define SETTINGS_ENABLE_PUSH 2
#define SETTINGS_MAX_CONCURRENT_STREAMS 3
#define SETTINGS_INITIAL_WINDOW_SIZE 4
#define SETTINGS_MAX_FRAME_SIZE 5
#define SETTINGS_MAX_HEADER_LIST_SIZE 6

#include <pcap.h>
#include <stdbool.h>

void dechiffrage_http2(const u_char *packet, int size_of_lower_layer, const struct pcap_pkthdr *header, bool is_server, int verbose);

#endif
