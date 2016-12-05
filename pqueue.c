#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <pcap.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netinet/ip.h> 

#include <linux/if_ether.h>

#include "pal.h"
#include "pqueue.h"
#include "action.h"

pqueue_t *pq_p;
pthread_mutex_t qlock,cond_lock;
pthread_cond_t cond_v;
extern config_t conf;
int queue_ready;

pqueue_t *alloc_pqueue(void) {
	pqueue_t *pq;

	pq = (pqueue_t *) malloc(sizeof(pqueue_t));
	if (!pq) {
		syslog(LOG_ERR,"Can't allocate memory");
		exit(1);
	}

	pq->data = (unsigned char *) malloc(sizeof(char) * ETH_PACKET);
	if (!pq->data) {
		syslog(LOG_ERR,"Can't allocate memory");
		exit(1);
	}
	
	pq->len = 0;
	pq->next = NULL;
	pq->flags = 0;

	return pq;
}

void init_pqueue(void) {
	int i;
	pqueue_t *pq;

	pthread_mutex_init(&qlock,NULL);
	pthread_mutex_init(&cond_lock,NULL);
	pthread_cond_init(&cond_v,NULL);

	pq = pq_p = alloc_pqueue();
	for (i = 0; i < PREALLOC_ITEMS - 1; ++i) {
		pq->next = alloc_pqueue();
		pq = pq->next;
	}
	queue_ready = 0;
}

pqueue_t *handle_packet_storm(void) {
	/* Not implemented */
	return NULL;
}


void add_queue(unsigned int len, unsigned char *data) {
	pqueue_t *pq;

	pq = pq_p;
	pthread_mutex_lock(&qlock);
	for (pq = pq_p; pq; pq = pq->next) {
		if (pq->flags & FL_VALID) continue;
		break;
	}
	pthread_mutex_unlock(&qlock);

	if (!pq) pq = handle_packet_storm();
	if (pq == NULL) {
		syslog(LOG_WARNING,"Packet storm handling error, skipping packet");
		return;
	}

	/* No lock here, can be accessed only from this point */
	pq->len = len;
	memcpy(pq->data,data,len);
	pq->flags |= FL_VALID;
	
	pthread_mutex_lock(&cond_lock);
	queue_ready = 1;
	pthread_cond_signal(&cond_v);
	pthread_mutex_unlock(&cond_lock);
}

int process_pq(pqueue_t *pq) {
	struct ethhdr *eh;
	struct iphdr *iph;
	unsigned short proto;
	ipproto_drv_t *drv;
	int id;
	unsigned short off;
	
	eh = (struct ethhdr *) pq->data;
	proto = ntohs(eh->h_proto);
	if (proto != ETH_P_IP) return 1;

	iph = (struct iphdr *) ((unsigned long) eh + ETH_HDR_LEN);
	drv = get_proto(iph->protocol);
	if (!drv) return 0;	

	off = iph->ihl * 4;
	id = drv->probe((void *)((unsigned long) iph + off),ntohs(iph->tot_len) - off,iph->saddr,iph->daddr);
	if (id) {
		set_ips(iph->saddr,iph->daddr,id);
		action_finish(id);
	}
	
	return 1;
}

void *pq_loop(void *arg) {
	pqueue_t *pq;
	int i;

	while (1) {
		pthread_mutex_lock(&cond_lock);
		while (!queue_ready) 
			pthread_cond_wait(&cond_v,&cond_lock);
		pthread_mutex_unlock(&cond_lock);
		
		pthread_mutex_lock(&qlock);
		do {
			i = 0;
			for (pq = pq_p; pq; pq = pq->next) {
				if (pq->flags & FL_VALID) {
					pthread_mutex_unlock(&qlock);
					i += process_pq(pq);
					pthread_mutex_lock(&qlock);
					pq->flags &= ~FL_VALID;
				}
			}
		} while (i != 0);		
		pthread_mutex_unlock(&qlock);
		
		pthread_mutex_lock(&cond_lock);
		queue_ready = 0;
		pthread_mutex_unlock(&cond_lock);
	}
	return NULL;
}

void init_queue_reader(void) {
	pthread_t tid;
	pthread_attr_t attr;

	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr,conf.read_stack);
	pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
	if (pthread_create(&tid,&attr,pq_loop,NULL)) {
		syslog(LOG_ERR,"Failed to create read thread");
		exit(1);
	}
	pthread_attr_destroy(&attr);
}
