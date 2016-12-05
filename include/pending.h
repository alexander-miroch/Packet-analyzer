#ifndef _PENDING_H
#define _PENDING_H

#define D_PHASH_SIZE	16384

typedef struct pending_s {
	int len;
	int continue_from;
	char *data;
	unsigned short sport,dport;
	unsigned int srcip,dstip;
} pending_t;


void init_pendings(void);

#endif
