#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#define NUM_THREADS 6
#define MAX_PACKET_LENGTH 65535

#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

struct thread_args;

void *worker_thread(void *arg);
void dispatch(const struct pcap_pkthdr *header, 
              const unsigned char *packet,
              int verbose);
int validate_task(struct thread_args *task);
#endif
