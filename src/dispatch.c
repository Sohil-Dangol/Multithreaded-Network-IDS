#include "dispatch.h"

#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include "queue.h"

#define NUM_THREADS 6
#define MAX_PACKET_LENGTH 65535

#include "analysis.h"

// mutex lock required for the shared queue
extern pthread_mutex_t queue_mutex;

extern pthread_cond_t queue_cond;

extern pthread_t tid[NUM_THREADS];
extern struct queue *work_queue;
extern int loop;

struct thread_args{ //used to pass arguements to analyse
  struct pcap_pkthdr *header;
  unsigned char *packet;
  int verbose;
};


// Worker thread function
void *worker_thread(void *arg) {

  while (1) {
    pthread_mutex_lock(&queue_mutex);

    while (queue_isempty(work_queue) && loop) { // Wait until the queue has work or sniffer is shutting down
      pthread_cond_wait(&queue_cond, &queue_mutex);
    }

    if (!loop && queue_isempty(work_queue)) { // case of shutting down and queue empty, exit
      pthread_mutex_unlock(&queue_mutex);
      break;
    }

    // Pop a packet from the queue
    struct thread_args *task = dequeue(work_queue);
    pthread_mutex_unlock(&queue_mutex);

    //case of valid task
    if(validate_task(task)){
      struct pcap_pkthdr *header = task->header;
      unsigned char *packet = task->packet;
      int verbose = task->verbose;

      //call analyse to process packet 
      analyse(header,packet,verbose);

      //frees args once analyse() has finished executing for the current packet 
      free(header); 
      free(packet);
      free(task);
    }
    //printf("Worker processing packet\n");
  }

  
  return NULL;
}

void dispatch(const struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose) {
  // TODO: Your part 2 code here
  // This method should handle dispatching of work to threads. At present
  // it is a simple passthrough as this skeleton is single-threaded.
  //printf("dispatch called\n");
  struct thread_args *task = malloc(sizeof(struct thread_args));  // allocates memory to store task
  task->header = malloc(sizeof(struct pcap_pkthdr));  // Allocate memory for the packet header in the task (separate from original header)
  *(task->header) = *header; // deep copy
  task->packet = malloc(header->caplen); // Allocate memory for the packet payload (raw bytes) in the task
  memcpy((unsigned char *)task->packet, packet, header->caplen);  // Copy the actual packet data into the newly allocated memory
  task->verbose = verbose;

  // Add task to work queue
  pthread_mutex_lock(&queue_mutex);
  enqueue(work_queue, task);
  pthread_cond_signal(&queue_cond); // wake up a worker
  pthread_mutex_unlock(&queue_mutex);
}
// function used to make sure all args passes are valid and not null
int validate_task(struct thread_args *task) {
    //case no task
    if (!task) return 0;
    //case no header
    struct pcap_pkthdr *header = task->header;
    unsigned char *packet = task->packet;
    if (!header) {
        printf("ERROR: header is NULL\n");
        free(task);
        return 0;
    }
    //case no packet
    if (!packet) {
        printf("ERROR: packet is NULL\n");
        free(header);
        free(task);
        return 0;
    }

    int packetSize = header->caplen;
    if (packetSize == 0 || packetSize > MAX_PACKET_LENGTH) {
        printf("ERROR: caplen is invalid!\n");
        free(header);
        free(packet);
        free(task);
        return 0;
    }

    return 1; // valid
}