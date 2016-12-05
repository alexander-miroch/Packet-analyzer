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
#include <pcre.h>

#include "pal.h"
#include "pqueue.h"
#include "rules.h"
#include "action.h"

rule_t **rules_body;
rule_t **rules_header;
rule_t **rules_url;

void init_rules(void) {
	rules_body = malloc(sizeof(rule_t));
	rules_header = malloc(sizeof(rule_t));
	rules_url = malloc(sizeof(rule_t));
	if (!rules_body || !rules_header || !rules_url) {
		syslog(LOG_ERR,"No memory for rules");
		exit(1);
	}
	*rules_body = *rules_header = *rules_url = NULL;
}

rule_t *alloc_rule(void) {
	rule_t *r;

	r = malloc(sizeof(rule_t));
	if (!r) {
		syslog(LOG_ERR,"No memory for rule alloc");
		exit(1);
	}

	r->next = NULL;
	r->compiled = NULL;
	r->is_reverse = 0;
	r->data = NULL;
	r->source = NULL;
	r->description = NULL;

	return r;
}

int check_rules(rule_t **base,unsigned char *str,unsigned int len) {
	rule_t *r;
	char *ptr;
	int rv,nlen;
	unsigned char *cmp;

	for (r = *base; r; r = r->next) {
		if (r->data) {
			ptr = strchr((char *) str,':');
			if (!ptr) continue;
			*ptr = 0;
			if (strcasecmp((char *) str,r->data)) {
				*ptr = ':';
				continue;
			}
			*ptr++ = ':';
			cmp = (unsigned char *) ptr;
			nlen = len - (cmp - str + 1);
		} else {
			cmp = str;
			nlen = len;
		}
		 
		skipsp((char **)&cmp);
		if (r->type == TYPE_PCRE) {
			rv = pcre_exec(r->compiled,NULL,(char *)cmp,nlen,0,PCRE_NOTEMPTY,NULL,0);
			if (rv == PCRE_ERROR_NOMATCH) continue;
			if (rv == 0) {
				return schedule_action(r->description);
			}
			syslog(LOG_WARNING,"Pcre match for %s returns error %d\n",r->source,rv);
		} else if (r->type == TYPE_PLAIN) {
			if (!strcmp((char *)cmp,r->source)) {
				return schedule_action(r->description);
			}
		} else continue;
	}
	return 0;
}

char *parse_regex(char *rx, int *opts) {
	char mark,*str,*tp;

	mark = *rx;
	str = rx + 1;
	tp = strrchr(rx,mark);
	if (!tp) {
		syslog(LOG_ERR,"Invalid regular expression %s",rx);
		exit(1);
	}
	*tp++ = 0;

	while (*tp) {
		switch (*tp) {
			case 'i':
				*opts |= PCRE_CASELESS;	
				break;
			default:
				syslog(LOG_WARNING,"Unsupported quantifier %c, skipped",*tp);
		}
		++tp;
	}

	return str;
}

int _rules_do_compile(rule_t **base) {
	rule_t *r;
	const char *errbuf;
	char *src;
	int eoff,opts;

	opts = PCRE_FIRSTLINE|PCRE_NO_AUTO_CAPTURE;
	for (r = *base; r; r = r->next) {
		if (r->type != TYPE_PCRE) continue;
		src = parse_regex(r->source,&opts);
		r->compiled = pcre_compile(src,opts,&errbuf,&eoff,NULL);
		if (!r->compiled) {
			syslog(LOG_ERR,"PCRE ERROR: %s",errbuf);
			exit(1);
		}
	}
	return 0;
}

void rules_compile(void) {
	_rules_do_compile(rules_body);
	_rules_do_compile(rules_url);
	_rules_do_compile(rules_header);
}

void set_rule(rule_t *nr,int type) {
	rule_t *r,**sr;

	switch (type) {
		case MATCH_URL:
			sr = rules_url;
			break;
		case MATCH_BODY:
			sr = rules_body;
			break;
		case MATCH_HEADER:
			sr = rules_header;
			break;
		default:
			syslog(LOG_ERR,"Invalid rule type");
			exit(1);
	}
	if (!*sr) {
		*sr = nr;
		return;
	}
	for (r = *sr; r->next; r = r->next) { ; }
	r->next = nr;
}

