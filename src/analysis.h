#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H

#define TOTAL_DOMAINS 2 
#define ARP_HEADER_SIZE 28
#define IP_HEADER_SIZE 20
#define TCP_HEADER_SIZE 20
#define WORD_SIZE 4
#define HOST_OFFSET 5

#include <pcap.h>

extern int uniqueIPs_count;
extern int synCount;
extern int arpCount;
extern int blackListedURLCount;
extern int googleCount;
extern int facebookCount;
extern int uniqueIP_capacity;

// --- Main analysis function ---
void analyse(struct pcap_pkthdr *header, const unsigned char *packet, int verbose);

// --- Packet analysis helpers ---
struct ether_header *getEth_header(const unsigned char *packet);
struct iphdr *getIP_header(struct ether_header *eth_header, const unsigned char *packet);
struct tcphdr *getTCP_header(struct iphdr *ip_header, const unsigned char *packet);

int getHeaderLength(struct ether_header *eth_header, struct iphdr *ip_header, struct tcphdr *tcp_header);
int getPayloadLength(int packetSize, int headerLength);
const unsigned char *getPayload(int headerLength, const unsigned char *packet);

void checkForSynATK(struct tcphdr *tcp_header, struct iphdr *ip_header);
void checkForArpATK(struct ether_header *eth_header,const unsigned char *packet,int packetSize);
void checkForBlacklistedURL(int headerLength, int packetSize, const unsigned char *packet,
                            struct tcphdr *tcp_header, uint32_t src_ip, uint32_t dest_ip);

int isUniqueIP(const struct iphdr *ip_header);
void print_IP(uint32_t ip);
void reSize();
char *getHostName(const unsigned char* payload);

#endif 
