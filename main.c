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
#include "pending.h"

struct option long_opts[] = {
	{ "help",0,0,'h' },
	{ "nodetach",0,0,'n' },
	{ "config",1,0,'c' },
	{ "proto",1,0,'p' },
};

config_t conf;


void usage(int out) {
	FILE *f;

	f = (out) ? stderr : stdout;
	fprintf(f,"Usage:\n"\
		  "\t"WEARE" [hn]\n");
	exit(out);
}

int main(int argc, char **argv) {
	int proto_idx = 0;
	char c;
	int oidx;

	init_conf(&conf);
	while ((c = getopt_long(argc,argv,"c:hi:np:",long_opts,&oidx)) != -1) {
		switch (c) {
			case 'p':
				if (proto_idx == MAX_ENTRIES) break;
				conf.proto[proto_idx] = strdup(optarg);
				++proto_idx;
			case 'n':
				conf.daemon = 0;
				break;
			case 'i':
				conf.interface = strdup(optarg);
				break;
			case 'c':
				conf.config_file = strdup(optarg);
				break;
			case 'h':
				usage(0);
			case '?':
			default:
				usage(1);

		}
	}


	openlog(WEARE,LOG_PID,conf.log_fac);
	syslog(LOG_INFO,WEARE" started");

	init_rules();
	read_config(conf.config_file);

	if (conf.daemon) create_daemon();

	init_action();	
	rules_compile();
	init_pqueue();
	init_queue_reader();
	prepare_pcap();

	return 0;
}

void create_daemon() {
	long fds;
	register int j;
	FILE *f;

	if (getppid() == 1) return;

	switch(fork()) {
		case 0:
			break;
                case -1:
			syslog(LOG_ERR,"Fork error,exitting...");
			exit(1);
		default:
			exit(0);
	}

	umask(UMASK);
	f = fopen(conf.pidfile,"w");
	if (!f) {
		syslog(LOG_ERR,"Cant't open pidfile %s",conf.pidfile);
		exit(1);
	}
	fprintf(f,"%d",getpid());
	fclose(f);

	setsid();
	if (chdir("/") < 0) {
		syslog(LOG_ERR,"Can't chdir to /");
		exit(1);
	}
	fds = sysconf(_SC_OPEN_MAX);
	for (j = 0; j<fds; ++j) close(j);

	j = open("/dev/null",O_RDWR);
	if (j>=0) {
		dup(j);
		dup(j);
	}

	signal(SIGCHLD,SIG_IGN);
	signal(SIGTSTP,SIG_IGN);
	signal(SIGTTIN,SIG_IGN);
	//signal(SIGINT,SIG_IGN);
	signal(SIGHUP,sig_h);
	signal(SIGTERM,sig_h);
}

void sig_h(int sig) {
        switch (sig) {
                case SIGHUP:
                        syslog(LOG_INFO,"sighup received");
                        break;
                case SIGTERM:
                        syslog(LOG_INFO,"sigterm received");
                        unlink(conf.pidfile);
                        exit(0);
                        break;
        }
}

void init_conf(config_t *conf) {
	int i;

	conf->pidfile = DEFAULT_PIDFILE;
	conf->config_file = DEFAULT_CONFIG;
	conf->log_fac = DEFAULT_FAC;
	conf->daemon = 1;
	conf->interface = NULL;
	conf->promisc = 0;
	conf->read_stack = DEFAULT_STACK;
	conf->proto = (char **) malloc(sizeof(char *) * MAX_ENTRIES);
	for (i = 0; i < MAX_ENTRIES; ++i)
		conf->proto[i] = NULL;
	conf->aqueue = ACTION_QUEUE;
	conf->mail_from = D_MAIL_FROM;
	conf->mail_to = D_MAIL_TO;
	conf->sendmail = D_SENDMAIL;
	conf->phash_size = D_PHASH_SIZE;
}

