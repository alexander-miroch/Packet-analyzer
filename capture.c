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

#include "pal.h"
#include "pqueue.h"

pcap_t *fp;
extern config_t conf;
char errbuf[PCAP_ERRBUF_SIZE];

static void packet_handler(u_char *,const struct pcap_pkthdr *, const u_char *);

char *build_filter(void) {
	int i,port;
	char *p,*proto;
	char *filter,*sp_filter,*fmt;

	sp_filter = filter = (char *) malloc(1024 * (sizeof(char) * MAX_ENTRIES * 4));
	if (!filter) {
		syslog(LOG_ERR,"Can't allocate memory");
		exit(1);
	}
	*filter = 0;
	for (i = 0; conf.proto[i]; ++i) {
		p = conf.proto[i];
		if (strlen(p) > 16) {
			syslog(LOG_WARNING,"supplied parameter %s is too long, skipping",p);
			continue;
		}

		proto = strchr(p,':');
		if (!proto) {
			proto = p;
			port = 0;
		} else {
			*proto++ = 0;
			if (proto && *proto) port = atoi(proto);
			else {
				syslog(LOG_WARNING,"Syntax erro in command line, skipping");
				continue;
			}
			if (port < 1 || port > MAX_PORT) {
				syslog(LOG_WARNING,"Port %d doesn't exit, skipping",port);
				continue;
			}
			proto = p;
		}
		
		fmt = (port) ? FMT_WPORT : FMT_PROTO;
		if (*sp_filter) {
			memcpy(filter," or ",4);
			filter += 4;
		}
		sprintf(filter,fmt,proto,port);
		filter += strlen(filter);
		register_proto(proto);
	}
	if (!conf.proto[0]) {
		register_proto(NULL);
		free(filter);
		return NULL;
	}

	return sp_filter;
}

void prepare_pcap(void) {
	char *dev;
	char *filter;
	bpf_u_int32 net,mask;
	struct bpf_program bpf;
	
	if (!conf.interface) {
		dev = pcap_lookupdev(errbuf);
		if (!dev) {
			syslog(LOG_ERR,"Can't find network device %s",errbuf);
			exit(1);
		}
	} else dev = conf.interface;

	if (pcap_lookupnet(dev,&net,&mask,errbuf) < 0) {
		syslog(LOG_ERR,"Net lookup error %s",errbuf);
		exit(1);
	}

	syslog(LOG_INFO,"Ready to listen on %s",dev);
	fp = pcap_open_live(dev,ETH_PACKET,conf.promisc,ETH_MS,errbuf);
	if (!fp) {
		syslog(LOG_ERR,"Can't open pcap: %s",errbuf);
		exit(1);
	}

	pcap_setdirection(fp,PCAP_D_IN);
	filter = build_filter();
	if (filter) {
		syslog(LOG_INFO,"Will use filter %s",filter);
		if (pcap_compile(fp,&bpf,filter,1,mask) < 0) {
			syslog(LOG_ERR,"Filter compilation error");
			exit(1);
		}
		if (pcap_setfilter(fp,&bpf) < 0) {
			syslog(LOG_ERR,"Filter setting error");
			exit(1);
		}
	} 

	pcap_loop(fp,0,packet_handler,NULL);
}

static void packet_handler(u_char *dumb,const struct pcap_pkthdr *header, const u_char *data) {
	add_queue(header->len,(unsigned char *)data);
}
