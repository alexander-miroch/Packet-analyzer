#ifndef _PAL_H
#define _PAL_H

#define WEARE	"pal"

#define DEFAULT_CONFIG "/etc/pal.conf"
#define DEFAULT_FAC	LOG_DAEMON
#define DEFAULT_PIDFILE	"/var/run/pal.pid"

#define DEFAULT_STACK 	16384		// 16k


#define D_MAIL_FROM	"sniffer@host.euroset.ru"
#define D_MAIL_TO	"admins@host.euroset.ru"
#define D_SENDMAIL	"/usr/sbin/sendmail -t -i"

#define UMASK 0002
typedef struct config_s {
	int log_fac;
	char *config_file;
	char *pidfile;
	int daemon;
	char *interface;
	int promisc;
	char **proto;
	unsigned int aqueue;
	unsigned int read_stack;
	char *mail_from,*mail_to;
	char *sendmail;
	unsigned int phash_size;
} config_t;

#define MAX_PORT	65535
#define MAX_IPPROTO	8

typedef struct ipproto_drv_s {
	char *name;
	unsigned int num;
	void (*init)(int);
	int (*probe)(void *,int, unsigned int, unsigned int);
} ipproto_drv_t;

void register_proto(char *);
ipproto_drv_t *get_proto(int);

void sig_h(int);
void usage(int);
void init_conf(config_t *);
void create_daemon(void);
void prepare_pcap(void);

char *build_filter(void);

#define MAX_ENTRIES	16

#define ETH_FRAME	1500
#define ETH_HDR_LEN	14
#define ETH_PACKET	(ETH_FRAME + ETH_HDR_LEN)
#define ETH_MS		20

#define FMT_WPORT	"(%s and port %d)"
#define FMT_PROTO	"(%s)"


void read_config(char *);
int apache_probe(void *,int, int *);

typedef struct conf_opts_s {
	char *name;
	int (*handler)(char *,void *);
	void *var;
} conf_opts_t;

int http_handler(char *,void *);
int dummy(char *,void *);
int dummy_int(char *,void *);
unsigned char *getstr(unsigned char **,unsigned int *);
void inline skipsp(char **);
char inline *get_host(char *);
void chomp(char *);
int check_last(unsigned char *,int);

#endif
