
#define TYPE_PLAIN	0x0
#define TYPE_PCRE	0x1

#define MATCH_URL	0x0
#define MATCH_HEADER	0x1
#define MATCH_BODY	0x2

typedef struct rule_s {
	char *source;
	void *compiled;
	int type;
	int is_reverse;
	char *data;
	unsigned char *description;
	struct rule_s *next;
} rule_t;

rule_t *alloc_rule(void);
void set_rule(rule_t *,int);
int check_rules(rule_t **,unsigned char *,unsigned int);
void init_rules(void);
int _rules_do_compile(rule_t **);
void rules_compile(void);
char *parse_regex(char *,int *);
