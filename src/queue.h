#ifndef QUEUE_H
#define QUEUE_H

#include <stdio.h>
#include <stdlib.h>

// Node structure
struct node {
    struct thread_args *task;
    struct node *next;
};

// Queue structure
struct queue {
    struct node *head;
    struct node *tail;
};

// Function prototypes
struct queue *create_queue(void);
void destroy_queue(struct queue *q);
int queue_isempty(struct queue *q);
void enqueue(struct queue *q, struct thread_args *task);
struct thread_args *dequeue(struct queue *q);
void printqueue(struct queue *q);

#endif // QUEUE_H
