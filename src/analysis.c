#include "analysis.h"

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdlib.h> 
#include <string.h>
#include <stdio.h>  
#include <pthread.h>



#define HTTP_PORT 80
#define TOTAL_DOMAINS 2  
#define ARP_HEADER_SIZE 28
#define IP_HEADER_SIZE 20
#define TCP_HEADER_SIZE 20
#define WORD_SIZE 4
#define HOST_OFFSET 5

pthread_mutex_t counter_mutex=PTHREAD_MUTEX_INITIALIZER;

char *blackListedURLs[TOTAL_DOMAINS] = {"www.google.co.uk", "www.facebook.com"};
char *domains[TOTAL_DOMAINS] = {"google","facebook"};

int uniqueIPs_count = 0;
int synCount = 0;
int arpCount = 0;
int blackListedURLCount = 0;
int googleCount = 0;
int facebookCount = 0;
int domainCounts[TOTAL_DOMAINS] = {0};
int uniqueIP_capacity = 100;

static uint32_t *uniqueIP_array = NULL;

void analyse(struct pcap_pkthdr *header,
             const unsigned char *packet,
             int verbose) {
  // TODO your part 2 code here
  //printf("analyse() running\n");
  int packetSize = header->caplen;
  if(packetSize < sizeof(struct ether_header)) {
    printf("Packet too small for Ethernet header\n");
    return;
  }
  struct ether_header * eth_header = getEth_header(packet);
  uint16_t ether_type = ntohs(eth_header->ether_type);

  checkForArpATK(eth_header,packet,packetSize);

  if (ether_type != ETHERTYPE_IP) {
    return; // ignore if doesnt have IP or ARP
  }

  if (packetSize < sizeof(struct ether_header) + sizeof(struct iphdr)) {
    return;
  }

  struct iphdr * ip_header = getIP_header(eth_header,packet);
  int ip_header_len = ip_header->ihl * WORD_SIZE;

  if (ip_header_len < IP_HEADER_SIZE) return;

  if (packetSize < sizeof(struct ether_header) + ip_header_len + sizeof(struct tcphdr)) {
      return;
  }

  struct tcphdr * tcp_header = getTCP_header(ip_header,packet);

  int tcp_header_len = tcp_header->th_off * WORD_SIZE;
  if (tcp_header_len < TCP_HEADER_SIZE) return;
  
  checkForSynATK(tcp_header, ip_header);
  
  int headerLength = getHeaderLength(eth_header,ip_header,tcp_header);
  if (packetSize <= headerLength) return; // No payload, cannot continue to check if packet has a blacklisted URL

  uint32_t src_IP = ntohl(ip_header->saddr);
  uint32_t dest_IP = ntohl(ip_header->daddr);

  checkForBlacklistedURL(headerLength,packetSize,packet,tcp_header,src_IP,dest_IP);

}
void checkForSynATK(struct tcphdr *tcp_header, struct iphdr *ip_header){
  //printf("SynAttack() running\n");
  if (tcp_header->th_flags & TH_SYN) {
    pthread_mutex_lock(&counter_mutex);
    synCount++;
    if(!uniqueIP_array){
      uniqueIP_array = malloc(uniqueIP_capacity * sizeof(uint32_t));
    }
    if (isUniqueIP(ip_header)) {  // checks if header contains a new IP address that has not been added to the collected list of IP addresses
      if (uniqueIPs_count >= uniqueIP_capacity) { // case the array is full, it is allocated more memory
        reSize();
      }
      uniqueIP_array[uniqueIPs_count++] = ntohl(ip_header->saddr);  // adds new IP address 
    }

    pthread_mutex_unlock(&counter_mutex);
  }
}

void checkForArpATK(struct ether_header *eth_header,const unsigned char *packet,int packetSize){
  //printf("ArpAttack() running\n");
 
  uint16_t ether_type = ntohs(eth_header->ether_type);

  // check if packet matches ARP packet criteria
  if (ether_type == ETHERTYPE_ARP){ 
    if (packetSize >= sizeof(struct ether_header) + ARP_HEADER_SIZE) { 
      struct ether_arp *arp_header = (struct ether_arp *)(packet + sizeof(struct ether_header));

      // check if ARP operation is a reply (op = 2) to prevent counting packet twice
      if (ntohs(arp_header->ea_hdr.ar_op) == ARPOP_REPLY) {
        pthread_mutex_lock(&counter_mutex);
        arpCount++;
        pthread_mutex_unlock(&counter_mutex);
      }
    }
  }
}

void checkForBlacklistedURL(int headerLength, int packetSize, const unsigned char *packet,struct tcphdr *tcp_header, uint32_t src_ip, uint32_t dest_ip){
  //printf("BlackListURLAttack() running\n");
  uint16_t dest_port = ntohs(tcp_header->th_dport);
  if (dest_port != HTTP_PORT) { // blacklist URL only when goes through HTTP Port
    return;
  }
  else{
    int payloadLength = getPayloadLength(packetSize,headerLength);

    if(payloadLength <= 0){ // invalid length check
      return;
    }
    const unsigned char *payload = getPayload(headerLength,packet);
    char *hostname = getHostName(payload);

    if(!hostname){
      return;
    }
    //iterate through each blacklisted domain to see if the given packet is from a blacklisted domain
    for(int i = 0 ; i < TOTAL_DOMAINS ; i++){ 
      if (strstr(hostname, blackListedURLs[i]) != NULL) { 
        //case that they are, updates counters and outputs the source and destination IP
        pthread_mutex_lock(&counter_mutex);
        blackListedURLCount++;
        domainCounts[i] += 1;
        pthread_mutex_unlock(&counter_mutex);
        printf("==============================\n");
        printf("Blacklisted URL violation detected\n");
        printf("Source IP address: "); print_IP(src_ip);
        printf("Destination IP address: "); print_IP(dest_ip);
        printf(" (%s)\n", domains[i]);
        printf("==============================\n");

        break;
      }
    }
    free(hostname);
  }
}

void reSize() {
  // used to resize dynamic IPs array when full
  int newCapacity = uniqueIP_capacity * 2;  // doubles the size of the array
  uint32_t *newArray = realloc(uniqueIP_array, newCapacity * sizeof(uint32_t));
  if (!newArray) {  // tests reallocation before assigning to the actual variable
    perror("realloc failed");
    exit(EXIT_FAILURE);
  }
  uniqueIP_array = newArray;
  uniqueIP_capacity = newCapacity;
}

int isUniqueIP(const struct iphdr *ip_header) {
    if (!uniqueIP_array || !ip_header || uniqueIPs_count < 0) return -1;

    uint32_t src = ntohl(ip_header->saddr); // network byte order

    for (int i = 0; i < uniqueIPs_count; i++) {
        if (uniqueIP_array[i] == src) {
            return 0; // found -> not unique
        }
    }
    return 1; // not found -> unique
}

// all getter functions

struct iphdr *getIP_header(struct ether_header * eth_header,const unsigned char *packet){

  struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ether_header));
  return ip_header;
}

struct ether_header *getEth_header(const unsigned char *packet){

  struct ether_header *eth_header = (struct ether_header *) packet;
  return eth_header;
}

struct tcphdr *getTCP_header(struct iphdr * ip_header, const unsigned char *packet){

  int ip_header_len = ip_header->ihl * WORD_SIZE;
  struct tcphdr *tcp_header = (struct tcphdr *)(packet + ETH_HLEN + ip_header_len);
  return tcp_header;
}

unsigned char getTCPFlags(struct tcphdr *tcp_header) {
    return tcp_header->th_flags; 
}
int getACKbit(unsigned char flags) { 
  return (flags & TH_ACK) != 0; // TH_ACK used as mask for extracting the ACK bit via bitwise AND
}
int getSYNbit(unsigned char flags){
  return (flags & TH_SYN) != 0; // TH_SYN used as mask for extracting the ACK bit via bitwise AND
}

const unsigned char *getPayload(int headerLength,const unsigned char *packet){
  unsigned char *payload = (unsigned char *)(packet + headerLength);
  return payload;
}

int getHeaderLength(struct ether_header *eth_header,struct iphdr *ip_header, struct tcphdr *tcp_header){
  int ip_header_len = ip_header->ihl * WORD_SIZE;
  int tcp_header_len = tcp_header->th_off * WORD_SIZE;
  int total_header_len = sizeof(struct ether_header) + ip_header_len + tcp_header_len;
  return total_header_len;
}
int getPayloadLength(int packetSize, int headerLength){
  return packetSize - headerLength;
}

char *getHostName(const unsigned char *payload){
  const unsigned char *host_start = (unsigned char *)strstr((char *)payload, "Host:");
  if (!host_start) return NULL;
  host_start += 5; // skip "Host:"
  while (*host_start == ' ' || *host_start == '\t')
        host_start++;

  size_t host_len = 0;
  const unsigned char *p = host_start;
  while (*p && *p != '\r' && *p != '\n'){ // loop used to compute needed memory to allocated for hostname, char* ends with \r or \n so parses until reaches either of the two
    host_len++;
    p++;
  } 

  char *hostname = malloc(host_len + 1); // +1 for '\0'

  if (!hostname){ // case host is empty
    return NULL;
  }

  // Copy bytes and null-terminate
  memcpy(hostname, host_start, host_len);
  hostname[host_len] = '\0';

  return hostname;
}

// function used to print the given IP address into the terminal 
void print_IP(uint32_t ip) {
  const int NUM_BYTES = 4;  // used for loop
  const int LAST_BYTE_INDEX = NUM_BYTES - 1;  // used to insert dots inbetween numbers

  uint8_t *bytes = (uint8_t *)&ip;  // castes the whole IP into an array of 8 bit numbers 
  for (int i = 0; i < NUM_BYTES; i++) { // prints one 8 bit number of the IP per iteration 
      printf("%u", bytes[i]);
      if (i < LAST_BYTE_INDEX) printf("."); // inserts dots between numbers
  }
}