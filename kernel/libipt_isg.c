#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#define __EXPORTED_HEADERS__
#include <xtables.h>

#include <linux/netfilter_ipv4/ip_tables.h>

#define MAX_SERVICE_NAME_LEN 32

struct ipt_isg_info {
	char service_name[MAX_SERVICE_NAME_LEN];
};

static const struct option opts[] = {
	{ "service-name", 1, NULL, '1' },
	{ .name = NULL }
};

static void help(void) {
	printf(
"isg match options:\n"
"  --service-name VALUE		Match packets belonging to specified \"tagger\" type service\n");
}

static int parse(int c, char **argv, int invert, unsigned int *flags,
                 const void *entry, struct xt_entry_match **match) {
	struct ipt_isg_info *info = (struct ipt_isg_info *)(*match)->data;

	switch (c) {
		case '1':
			if (strlen(optarg) >= MAX_SERVICE_NAME_LEN) {
				xtables_error(PARAMETER_PROBLEM, "Service name must be shorter than %i characters", MAX_SERVICE_NAME_LEN);
			}
			strcpy((char *)info->service_name, optarg);
			*flags = 1;
			break;
		default:
			return 0;
	}
	return 1;
}

static void check(unsigned int flags) {
	if (!flags) {
		xtables_error(PARAMETER_PROBLEM, "You must specify --service-name");
	}
}

static void print(const void *ip, const struct xt_entry_match *match, int numeric) {
	struct ipt_isg_info *info = (struct ipt_isg_info *) match->data;

	info->service_name[MAX_SERVICE_NAME_LEN-1] = '\0';

	printf("ISG match service %s ", info->service_name);
}

static void save(const void *ip, const struct xt_entry_match *match) {
	struct ipt_isg_info *info = (struct ipt_isg_info *) match->data;

	info->service_name[MAX_SERVICE_NAME_LEN-1] = '\0';

	printf(" --service-name ");

	xtables_save_string((const char *)info->service_name);
}

static struct xtables_match mt_reg = {
	.name          = "isg",
	.version       = XTABLES_VERSION,
	.family        = NFPROTO_IPV4,
	.size          = XT_ALIGN(sizeof(struct ipt_isg_info)),
	.userspacesize = XT_ALIGN(sizeof(struct ipt_isg_info)),
	.help          = help,
	.parse         = parse,
	.final_check   = check,
	.print         = print,
	.save          = save,
	.extra_opts    = opts,
};


void _init(void) {
	xtables_register_match(&mt_reg);
}
