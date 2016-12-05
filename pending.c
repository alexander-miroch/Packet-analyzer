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

extern config_t conf;
pending_t **pds;

void init_pendings(void) {
	int i = 0;

	pds = (pending_t **) malloc(sizeof(pending_t *) * conf.phash_size);
	if (!pds) {
		syslog(LOG_ERR,"Can't alloc phash");
		exit(1);
	}

	for (; i < conf.phash_size; ++i) 
		pds[i] = (pending_t *) 0;
}


static inline unsigned int phash(unsigned int saddr, unsigned short sport, unsigned int daddr, unsigned short dport) {
        unsigned int h = (saddr ^ sport) ^ (daddr ^ dport);

        h ^= h >> 16;
        h ^= h >> 8;
        return h;
}

static inline pending_t *get_pending(unsigned int hash) {
	return pds[hash & (conf.phash_size - 1)];
}

