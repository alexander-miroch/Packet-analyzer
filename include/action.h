#ifndef _ACTION_H
#define _ACTION_H

#define STATUS_FREE		0x0
#define STATUS_NOTREADY		0x1
#define STATUS_READY		0x2

#define ACTION_QUEUE		16

typedef struct action_queue_s {
	unsigned char *msg;
	char *url,*host;
	short status;
	unsigned short src_port,dst_port;
	unsigned int src_ip,dst_ip;
} aqueue_t;

void init_action(void);
void init_action_thread(void);
int schedule_action(unsigned char *);
void *action_loop(void *);
void do_action(aqueue_t *);
void set_host_url(char *,char *,int);
void set_ports(unsigned short,unsigned short,int);
void set_ips(unsigned int,unsigned int,int id);
void action_finish(int);
void sendmail(char *);

#define HOST_LEN	64
#define REQ_LEN		4096
#define TIME_BUF	256


#endif
