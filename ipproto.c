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
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "pal.h"
#include "pqueue.h"
#include "action.h"

//HEHE
ipproto_drv_t *drvs[MAX_IPPROTO] = {
	NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL
};

int (*tcp_drvs[MAX_PORT])(void *,int, int *);

void ip_icmp_init(int num) {
	return;
}

int ip_icmp_probe(void *data,int len, unsigned int saddr, unsigned int daddr) {
	return 0;
}

void set_handler(int (*f)(void *,int, int *), unsigned short num) {
	if (tcp_drvs[num]) {
		syslog(LOG_ERR,"Error, two hanlers for port %d\n",num);
		exit(1);
	} 
	tcp_drvs[num] = f;
}

void ip_tcp_init(int num) {
	syslog(LOG_INFO,"TCP driver init");
	bzero(tcp_drvs,sizeof(void *) * MAX_PORT);
	set_handler(apache_probe,80);
	return;
}

int ip_tcp_probe(void *data,int len,unsigned int saddr,unsigned int daddr) {
	struct tcphdr *tcph;
	unsigned short port,off;
	int nlen,id;
	int last = 0;
	
	tcph = (struct tcphdr *) data;
	port = ntohs(tcph->dest);

	off = tcph->doff * 4;
	nlen = len - off;

	if (!nlen) return 0;

	if (tcp_drvs[port]) {
		id = tcp_drvs[port]((void *)((unsigned long) tcph + off),nlen,&last);
		
		set_ports(ntohs(tcph->source),port,id);
		return id;
	}
	return 0;
}

void ip_udp_init(int num) {
	return;
}

int ip_udp_probe(void *data, int len, unsigned int saddr, unsigned int daddr) {
	return 0;
}

ipproto_drv_t ip_tcp = {
	.name = "tcp",
	.num = IPPROTO_TCP,
	.init = ip_tcp_init,
	.probe = ip_tcp_probe
};

ipproto_drv_t ip_udp = {
	.name = "udp",
	.num = IPPROTO_UDP,
	.init = ip_udp_init,
	.probe = ip_udp_probe
};

ipproto_drv_t ip_icmp = {
	.name = "icmp",
	.num = IPPROTO_ICMP,
	.init = ip_icmp_init,
	.probe = ip_icmp_probe
};

ipproto_drv_t *static_drvs[] = {
	&ip_tcp,
	&ip_udp,
	&ip_icmp,
	NULL
};

void register_proto(char *name) {
	ipproto_drv_t *ip;
	int i;

	for (i = 0; (ip = static_drvs[i]); ++i) {
		if (name) {
			if (!strcmp(name,ip->name) && !drvs[i]) {
				drvs[i] = ip;
				ip->init(0);
			}
		} else {
			drvs[i] = ip;
			ip->init(0);
		}
	}
}

ipproto_drv_t *get_proto(int num) {
	register int i = 0;
	ipproto_drv_t *ip;

	for (; (ip = drvs[i]); ++i) 
		if (ip->num == num) return ip;
	
	
	return NULL;
}

