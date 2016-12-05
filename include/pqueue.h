#define PREALLOC_ITEMS	1024


#define FL_VALID	0x1

struct pqueue {
	struct pqueue *next;
	unsigned char *data;
	unsigned int len;
	unsigned int flags;
};

typedef struct pqueue pqueue_t;

pqueue_t *alloc_pqueue(void);
void init_pqueue(void);
void add_queue(unsigned int,unsigned char *);
pqueue_t *handle_packet_storm(void);
void init_queue_reader(void);
void *pq_loop(void *);
int process_pq(pqueue_t *);
