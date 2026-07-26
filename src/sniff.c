#include "sniff.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <string.h>
#include <signal.h> 
#include <pthread.h>
#include "dispatch.h"
#include "queue.h"
#include "analysis.h"
#define NUM_THREADS 6

pthread_mutex_t queue_mutex=PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queue_cond=PTHREAD_COND_INITIALIZER;

pthread_t tid[NUM_THREADS];
struct queue *work_queue;
int loop = 1;

pcap_t *pcap_handle;

extern int synCount, uniqueIPs_count, arpCount, blackListedURLCount;
extern int domainCounts[TOTAL_DOMAINS];      
extern char *domains[TOTAL_DOMAINS];

// signal handler function
void handle_sigint(int signo){
  if (signo == SIGINT){
    // case that ctrl c is pressed -> signo = sigint (1)

    //prints packet report
    printf("received SIGINT\n");
    printf("Intrusion Detection Report: \n");
    printf("%d SYN packets detected from %d different IPs (syn attack) \n",synCount,uniqueIPs_count);
    printf("%d ARP responses (cache poisoning) \n", arpCount);
    printf("%d URL Blacklist violations: ", blackListedURLCount);
    printf(" (");
    
    for (int i = 0; i < TOTAL_DOMAINS; i++) { //loop used to print the counter for each blacklisted doman
      printf("%d %s", domainCounts[i],domains[i]);
      if (i < TOTAL_DOMAINS - 1) {
        printf(" and ");
      }
    }
    printf(")");

    loop = 0; // tell workers to exit
    pthread_mutex_lock(&queue_mutex);
    pthread_cond_broadcast(&queue_cond);  // wake all worker threads
    pthread_mutex_unlock(&queue_mutex);

    pcap_breakloop(pcap_handle);     // stop pcap_loop
  }
}

// Application main sniffing loop
void sniff(char *interface, int verbose) {
  
  char errbuf[PCAP_ERRBUF_SIZE];

  // Open the specified network interface for packet capture. pcap_open_live() returns the handle to be used for the packet
  // capturing session. check the man page of pcap_open_live()
  pcap_handle = pcap_open_live(interface, 4096, 1, 1000, errbuf);
  if (pcap_handle == NULL) {
    fprintf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
  } else {
    printf("SUCCESS! Opened %s for capture\n", interface);
  }
  
  
  //struct pcap_pkthdr header;
  //const unsigned char *packet;
  
  signal(SIGINT, handle_sigint);

  work_queue = create_queue();

  for (int i = 0; i < NUM_THREADS; i++) {
    pthread_create(&tid[i], NULL, worker_thread, NULL);
  }

  // Capture packet one packet everytime the loop runs using pcap_next(). This is inefficient.
  // A more efficient way to capture packets is to use use pcap_loop() instead of pcap_next().
  // See the man pages of both pcap_loop() and pcap_next().


  pcap_loop(pcap_handle, -1, pcap_callback, (u_char *)&verbose);

  for(int i=0;i<NUM_THREADS;i++){
		pthread_join(tid[i],NULL); //the main thread joins with the workers
	}
	destroy_queue(work_queue); // queue is deallocated
  
  
  /*while (1) {
    // Capture a  packet


    packet = pcap_next(pcap_handle, &header);
    if (packet == NULL) {
      // pcap_next can return null if no packet is seen within a timeout
      if (verbose) {
        printf("No packet received. %s\n", pcap_geterr(pcap_handle));
      }
    } else {
      // If verbose is set to 1, dump raw packet to terminal
      if (verbose) {
        dump(packet, header.len);
      }
      // Dispatch packet for processing
      dispatch(&header, packet, verbose);
    }
  }*/
  //printf("Intrusion Detection Report: \n");
  //printf("%d SYN packets detected from %d different IPs (syn attack) \n",synCount,uniqueIPs_count);
  //printf("%d ARP responses (cache poisoning) \n", arpCount);
  //printf("%d URL Blacklist violations (%d google and %d facebook) \n", blackListedURLCount,googleCount,facebookCount);
}


// Utility/Debugging method for dumping raw packet data
void dump(const unsigned char *data, int length) {
  unsigned int i;
  static unsigned long pcount = 0;
  // Decode Packet Header
  struct ether_header *eth_header = (struct ether_header *) data;
  printf("\n\n === PACKET %ld HEADER ===", pcount);
  printf("\nSource MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_shost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nDestination MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_dhost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nType: %hu\n", eth_header->ether_type);
  printf(" === PACKET %ld DATA == \n", pcount);
  // Decode Packet Data (Skipping over the header)
  int data_bytes = length - ETH_HLEN;
  const unsigned char *payload = data + ETH_HLEN;
  const static int output_sz = 20; // Output this many bytes at a time
  while (data_bytes > 0) {
    int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
    // Print data in raw hexadecimal form
    for (i = 0; i < output_sz; ++i) {
      if (i < output_bytes) {
        printf("%02x ", payload[i]);
      } else {
        printf ("   "); // Maintain padding for partial lines
      }
    }
    printf ("| ");
    // Print data in ascii form
    for (i = 0; i < output_bytes; ++i) {
      char byte = payload[i];
      if (byte > 31 && byte < 127) {
        // Byte is in printable ascii range
        printf("%c", byte);
      } else {
        printf(".");
      }
    }
    printf("\n");
    payload += output_bytes;
    data_bytes -= output_bytes;
  }
  pcount++;
}

void pcap_callback(u_char *user, const struct pcap_pkthdr *header, const u_char *packet){
  //printf("pcap_callback called!\n");
  int verbose = *(int *)user; 
  dispatch(header, packet, verbose);
}
