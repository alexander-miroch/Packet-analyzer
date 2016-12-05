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
#include "rules.h"
#include "action.h"


extern rule_t **rules_body;
extern rule_t **rules_header;
extern rule_t **rules_url;

char inline *get_host(char *str) {
	char *host;

	if (!strncasecmp(str,"Host:",5)) {
		host = str + 5;
	} else host = NULL;
	skipsp(&host);
	return host;
}

int apache_probe(void *data, int len, int *last) {
	unsigned char *http,*str;
	char *host = NULL,*url;
	unsigned int clen = 0, accum = 0;
	int res = 0, hlen;
	int needtoret = 0;

	printf("come with %d->%s\n",len,(char *)data);

	http = (unsigned char *) data;
	http[len] = 0;

	if (!*rules_body && !*rules_header && !*rules_url) return 0;
	url = (char *) getstr(&http,&clen);
	accum = clen;

	if (*rules_url) res = check_rules(rules_url,(unsigned char *)url,clen);

//	printf("res=%d\n",res);		

	if (res) {
		str = getstr(&http,&clen);
			printf("nh0=%s\n",http);
		//host = get_host((char *)str);
		//set_host_url(host,url,res);
		needtoret = res;
//		return res;
	}
//	printf("u=%s\n",url);

//	if (*rules_header || *rules_body || needtoret) {
		while (1) {
			str = getstr(&http,&clen);
			printf("nh=%s\n",http);
			accum += clen;
			if (accum >= len) break;
//			if (!hcheck) {
			if (!host) host = get_host((char *)str);
			if (host && needtoret) {
//				printf("hf=%s\n",host);
				set_host_url(host,url,res);
				*last = 1;
				return needtoret;
			} 
			
			//	hcheck = 1;
	//		}
			if (!clen) break;
			if (needtoret) continue;
			if (*rules_header) {
				res = check_rules(rules_header,str,clen);
				if (res) {
					//set_host_url(host,url,res);
					//return res;
					needtoret = res;
				}
			}
		}
//	} else return 0;
	if (needtoret || !*rules_body) {
		set_host_url(NULL,url,needtoret);
		return needtoret;
	}

	hlen = strlen((char *) http);
	printf("h=%s (%d)\n",http,hlen);
	*last = check_last(http,hlen);

	res = check_rules(rules_body,http,hlen);
	if (res) {
		set_host_url(host,url,res);
		return res;
	}
	return 0;
}

int check_last(unsigned char *data, int len) {
	char c0,c1,c2,c3;

	c0 = data[len-1];
	c1 = data[len-2];
	c2 = data[len-3];
	c3 = data[len-4];

	printf("lastb=%x %x %x %x\n",c0,c1,c2,c3);
	return 1;

}

unsigned char *getstr(unsigned char **data,unsigned int *len) {
	unsigned char *ptr;
	unsigned int l = 0;

	ptr = *data;
	while (**data != '\n') {
		++(*data);
		++l;
	}
	**data = 0;
	if (*((*data)-1) == '\r') {
		*((*data)-1) = 0;
		--l;
	}
	++(*data), *len = l;
	return ptr;
}

