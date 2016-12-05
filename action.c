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
#include <time.h>

#include "pal.h"
#include "pqueue.h"
#include "rules.h"
#include "action.h"

pthread_mutex_t alock,acond_lock;
pthread_cond_t acond_v;
aqueue_t **aq;
int added;
extern config_t conf;

void init_action(void) {
	int i;
	
	aq = (aqueue_t **) malloc(sizeof(aqueue_t *) * conf.aqueue);
	if (!aq) {
		syslog(LOG_ERR,"No memory for aqueue");
		exit(1);
	}
	added = 0;
	for (i = 0; i < conf.aqueue; ++i) {
		aq[i] = (aqueue_t *) malloc(sizeof(aqueue_t));
		if (!aq[i]) {
			syslog(LOG_ERR,"No memory for aqueue");
			exit(1);
		}
		aq[i]->msg = NULL;
		aq[i]->status = STATUS_FREE;
		aq[i]->src_port = aq[i]->dst_port = 0;
		aq[i]->src_ip = aq[i]->dst_ip = 0;
		aq[i]->url = aq[i]->host = NULL;
	}
	init_action_thread();
}

void init_action_thread(void) {
	pthread_t tid;
        pthread_attr_t attr;

	pthread_mutex_init(&alock,NULL);
        pthread_mutex_init(&acond_lock,NULL);
        pthread_cond_init(&acond_v,NULL);

        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
        if (pthread_create(&tid,&attr,action_loop,NULL)) {
                syslog(LOG_ERR,"Failed to create action thread");
                exit(1);
        }
        pthread_attr_destroy(&attr);
}

void do_action(aqueue_t *aq) {
	char *msg;
	struct in_addr ia;
	char *src_ip,*dst_ip;
	int reql,hlen,b;
	char timeb[TIME_BUF];
	time_t tv;
	struct tm *tmp;


	reql = (aq->url) ? strlen(aq->url) : 0;
	if (reql > REQ_LEN) aq->url[REQ_LEN] = 0;
	hlen = (aq->host) ? strlen(aq->host) : 0;
	if (hlen > HOST_LEN) aq->url[HOST_LEN] = 0;
	
	msg = malloc(sizeof(char) * 4096 + reql + hlen);
	if (!msg) {
		syslog(LOG_WARNING,"Can't send due to memory alloc");
		return;
	}

	if (time(&tv) < 0) strncpy(timeb,"unknown",7);
	else {
		tmp = localtime(&tv);
		if (!tmp) strncpy(timeb,"unknown",7);
		else {
			b = strftime(timeb,TIME_BUF,"%a, %d %b %Y %H:%M:%S +0400",tmp);
			timeb[b] = 0;
		}		
	}

	ia.s_addr = aq->src_ip;
	src_ip = strdup(inet_ntoa(ia));
	ia.s_addr = aq->dst_ip;
	dst_ip = strdup(inet_ntoa(ia));

	if (!aq->host) aq->host = "no host";

	sprintf(msg,"From: %s\nTo: %s\nSubject: Alarm detected\n\n"\
		"PAL RESULTS:\n Description: %s\n Time: %s\n %s:%d -> %s:%d\n Host: %s\n Request: %s\n",
		conf.mail_from,
		conf.mail_to,
		aq->msg,
		timeb,
		src_ip,
		aq->src_port,
		dst_ip,
		aq->dst_port,
		aq->host,
		aq->url
	);

	free(src_ip), free(dst_ip);
	sendmail(msg);
	
	free(msg);
}


void sendmail(char *msg) {
	char buf[256];
	FILE *pipe;

	sprintf(buf,"%s -f%s\n",conf.sendmail,conf.mail_from);
	pipe = popen(buf,"w");
	if (!pipe) {
		syslog(LOG_WARNING,"Can't open %s\n",conf.sendmail);
		return;
	}

	fwrite(msg,sizeof(*msg),strlen(msg),pipe);
	pclose(pipe);
	syslog(LOG_INFO,"Alert message sent to %s\n",conf.mail_to);

}

void *action_loop(void *data) {
	int i,k;

	while (1) {
		pthread_mutex_lock(&acond_lock);
		while (!added)
			pthread_cond_wait(&acond_v,&acond_lock);
		pthread_mutex_unlock(&acond_lock);

		pthread_mutex_lock(&alock);
		do {
			i = 0;
			for (k = 0; k < conf.aqueue; ++k) {
				if (aq[k]->status == STATUS_READY) {
					pthread_mutex_unlock(&alock);
					do_action(aq[k]);
					pthread_mutex_lock(&alock);
					aq[k]->status = STATUS_FREE;
					++i;
				}
			}
		} while (i != 0);
		pthread_mutex_unlock(&alock);
	
		pthread_mutex_lock(&acond_lock);
		added = 0;
		pthread_mutex_unlock(&acond_lock);
	}
	return NULL;
}

void action_finish(int id) {
	pthread_mutex_lock(&alock);
	aq[id]->status = STATUS_READY;
	pthread_mutex_unlock(&alock);
	
	pthread_mutex_lock(&acond_lock);
        added = 1;
        pthread_cond_signal(&acond_v);
        pthread_mutex_unlock(&acond_lock);
}

void set_ips(unsigned int src,unsigned int dst,int id) {
	aq[id]->src_ip = src;
	aq[id]->dst_ip = dst;
}

void set_ports(unsigned short src,unsigned short dst,int id) {
	aq[id]->src_port = src;
	aq[id]->dst_port = dst;
}

void set_host_url(char *host,char *url,int id) {
	aq[id]->url = url;
	aq[id]->host = host;
}


int schedule_action(unsigned char *desc) {
	int id;

	pthread_mutex_lock(&alock);
	for (id = 1; id < conf.aqueue; ++id) {
		if (aq[id]->status == STATUS_FREE) {
			aq[id]->status = STATUS_NOTREADY;
			break;
		}
	}
	pthread_mutex_unlock(&alock);
	if (id == conf.aqueue) {
		syslog(LOG_ERR,"No free blocks for actions! Consider to increase action queue");
		exit(1);
	}
	aq[id]->msg = desc;
	return id;	
}

