#include <stdio.h>
#include <stdlib.h>
#include "queue.h"

struct queue *create_queue(void){ //creates a queue and returns its pointer
  struct queue *q=(struct queue *)malloc(sizeof(struct queue));
  q->head=NULL;
  q->tail=NULL;
  return(q);
}

void destroy_queue(struct queue *q){  //destroys the queue and frees the memory
  while(!queue_isempty(q)){
    dequeue(q);
  }
  free(q);
}

int queue_isempty(struct queue *q){ // checks if queue is empty
  return(q->head==NULL);
}

void enqueue(struct queue *q, struct thread_args *task){ //enqueues a node with an item
  struct node *new_node=(struct node *)malloc(sizeof(struct node));
  new_node->task=task;
  new_node->next=NULL;
  if(queue_isempty(q)){
    q->head=new_node;
    q->tail=new_node;
  }
  else{
    q->tail->next=new_node;
    q->tail=new_node;
  }
}

struct thread_args *dequeue(struct queue *q){ //dequeues a the head node
  if(queue_isempty(q)){
    printf("Error: attempt to dequeue from an empty queue");
    return NULL;
  }
  else{
    struct node *head_node = q->head;       
    struct thread_args *task = head_node->task;
    head_node=q->head;
    q->head=q->head->next;
    if(q->head==NULL)
      q->tail=NULL;
    free(head_node);
    return task;
  }
}
