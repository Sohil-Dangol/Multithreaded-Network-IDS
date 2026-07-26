#ifndef CS241_SNIFF_H
#define CS241_SNIFF_H
#define NUM_THREADS 6

#include <pcap.h>

void sniff(char *interface, int verbose);
void dump(const unsigned char *data, int length);
void handle_sigint(int signo);
void pcap_callback(u_char *user,const struct pcap_pkthdr *header,const u_char *packet);

#endif
