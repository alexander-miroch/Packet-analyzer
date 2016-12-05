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

extern config_t conf;
// s
conf_opts_t conf_opts[] = {
	{ .name = "http" , .handler = http_handler , .var = NULL },
	{ .name = "pidfile" , .handler = dummy , .var = &conf.pidfile },
	{ .name = "interface", .handler = dummy, .var = &conf.interface },
	{ .name = "daemon", .handler = dummy_int, .var = &conf.daemon },
	{ .name = "promisc", .handler = dummy_int, .var = &conf.promisc },
	{ .name = "action_queue", .handler = dummy_int, .var = &conf.aqueue },
	{ .name = "read_stack", .handler = dummy_int, .var = &conf.read_stack },
	{ .name = "mail_from", .handler = dummy, .var = &conf.mail_from },
	{ .name = "mail_to", .handler = dummy, .var = &conf.mail_to },
	{ .name = "sendmail", .handler = dummy, .var = &conf.sendmail },
	{ .name = "phash_size", .handler = dummy_int, .var = &conf.phash_size },
	{ NULL, NULL }
};

void inline skipsp(char **buf) {
	if (!*buf) return;
	while (**buf == '\t' || **buf == 0x20) (*buf)++;
}

void read_config(char *file) {
	FILE *f;
	char buf[256],*ptr;
	int i,rv;
	char *tp;
	

	f = fopen(file,"r");
	if (!f) {
		syslog(LOG_ERR,"Cant read config %s",file);
		exit(1);
	}

	while ((ptr = fgets(buf,256,f)) != NULL) {
		skipsp(&ptr);
		if (*ptr == '#' || *ptr == '\r' || *ptr == '\n') continue;
		tp = strchr(ptr,0x20);
		if (!tp) {
			tp = strchr(ptr,'\t');
			if (!tp) {
				syslog(LOG_ERR,"Parse error at %s\n",ptr);
				exit(1);
			}
		}
		*tp++ = 0;
		rv = -1;
		for (i = 0; conf_opts[i].name; ++i) {
			if (!strcmp(ptr,conf_opts[i].name)) {
				skipsp(&tp);
				rv = conf_opts[i].handler(tp,conf_opts[i].var);
			}
		}

		if (rv < 0) {
			syslog(LOG_ERR,"Error parsing option: %s\n",ptr);
			exit(1);
		}
	}
}

void chomp(char *str) {
	int len;
	
	len = strlen(str);
	if (str[len-1] == '\n') str[len-1] = 0;
	if (str[len-1] == '\r') str[len-1] = 0;
}

int dummy(char *rest, void *var) {
	chomp(rest);
	*(char **)var = strdup(rest);
	return 0;
}

int dummy_int(char *rest, void *var) {
	chomp(rest);
	*(int *)var = (int) atoi(rest);
	return 0;
}

int http_handler(char *rest, void *var) {
	char *p,*tp;
	rule_t *r;
	int type;

	
	r = alloc_rule();

	if (*rest != '"') {
		syslog(LOG_ERR,"Parse error in %s ",__FUNCTION__);
		return -1;
	}
	++rest;
	tp = strchr(rest,'"');
	if (!tp) {
		syslog(LOG_ERR,"Parse error in %s ",__FUNCTION__);
		return -1;
	}
	*tp++ = 0;
	r->description = (unsigned char *)strdup(rest);	

	skipsp(&tp);
	p = strchr(tp,0x20);
	if (!p) {
		syslog(LOG_ERR,"Parse error in %s ",__FUNCTION__);
		return -1;
	}
	*p++ = 0;

	if (!strcmp(tp,"pcre")) 
		r->type = TYPE_PCRE;
	else if (!strcmp(tp,"plain")) 
		r->type = TYPE_PLAIN;
	else {
		syslog(LOG_ERR,"Can't understand http type %s",tp);
		return -1;
	}

	skipsp(&p);
	tp = strchr(p,0x20);
	if (!tp) {
		syslog(LOG_ERR,"Parse error in %s ",__FUNCTION__);
		return -1;
	}
	*tp++ = 0;

	skipsp(&tp);
	if (!strcmp(p,"url")) type = MATCH_URL;
	else if (!strcmp(p,"body")) type = MATCH_BODY;
	else if (!strcmp(p,"header")) type = MATCH_HEADER;
	else {
		syslog(LOG_ERR,"Unknown match type: %s",p);
		return -1;
	}

	if (type == MATCH_HEADER) {
		p = strchr(tp,':');
		if (!p) {
			syslog(LOG_ERR,"Can't determine header name");
			return -1;
		}
		*p++ = 0;
		r->data = strdup(tp);
		r->source = strdup(p);
	} else {
		r->source = strdup(tp);
	}

	chomp(r->source);
	set_rule(r,type);
	return 0;
}
