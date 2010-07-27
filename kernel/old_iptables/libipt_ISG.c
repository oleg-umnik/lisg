#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <getopt.h>
#include <iptables.h>
#include <linux/netfilter_ipv4/ip_tables.h>

struct ipt_ISG_info {
    u_int8_t flags;
};

static struct option opts[] = {
    { "session-init", 0, NULL, '1' },
    { "init-mode", 1, NULL, '2' },
    { .name = NULL }
};

static void help(void) {
    printf(
"ISG target options:\n"
" --session-init		This rule match can be session initiator\n"
" --init-mode <mode>		Session initialization mode:\n"
"				  src - use src IP-address as username\n"
"				  dst - use dst IP-address as username\n"
"				If --init-mode is not specified, `src' is assumed\n");
}

#define INIT_SESSION 0x01
#define INIT_BY_SRC  0x02
#define INIT_BY_DST  0x04

static int parse(int c, char **argv, int invert, unsigned int *flags,
		 const struct ipt_entry *entry,
		 struct ipt_entry_target **target) {

    struct ipt_ISG_info *isg = (struct ipt_ISG_info *)(*target)->data;

    switch (c) {
    case '1':
        if (*flags & INIT_SESSION) {
            exit_error(PARAMETER_PROBLEM, "Can't specify --session-init twice\n");
        }

	*flags |= INIT_SESSION;
	isg->flags |= INIT_SESSION;
	isg->flags |= INIT_BY_SRC;

        break;

    case '2':
        if (!(*flags & INIT_SESSION)) {
            exit_error(PARAMETER_PROBLEM, "--init-mode parameter must be used with --session-init option\n");
        }

	if (!strcmp(optarg, "src")) {
	    isg->flags |= INIT_BY_SRC;
	} else if (!strcmp(optarg, "dst")) {
	    isg->flags &= ~INIT_BY_SRC;
	    isg->flags |= INIT_BY_DST;
	} else {
	    exit_error(PARAMETER_PROBLEM, "Unknown session init mode '%s'\n", optarg);
	}

        break;

    default:
	return 0;
    }

    return 1;
}

static void save(const struct ipt_ip *ip, const struct ipt_entry_target *target) {
    struct ipt_ISG_info *isg = (struct ipt_ISG_info *)target->data;

    if (isg->flags & INIT_SESSION) {
	printf("--session-init ");

	if (isg->flags & INIT_BY_SRC) {
	    printf("--init-mode src");
	} else if (isg->flags & INIT_BY_DST) {
	    printf("--init-mode dst");
	}
    }
}

static void print(const struct ipt_ip *ip,
      const struct ipt_entry_target *target,
      int numeric) {

    struct ipt_ISG_info *isg = (struct ipt_ISG_info *)target->data;

    printf("ISG ");

    if (isg->flags & INIT_SESSION) {
        printf("initiator ");

	if (isg->flags & INIT_BY_SRC) {
	    printf("src mode");
	} else if (isg->flags & INIT_BY_DST) {
	    printf("dst mode");
	}
    }
}

static void check(unsigned int flags) {

}

static struct iptables_target isg_info = { 
    .name		= "ISG",
    .version		= IPTABLES_VERSION,
    .size		= IPT_ALIGN(sizeof(struct ipt_ISG_info)),
    .userspacesize	= IPT_ALIGN(sizeof(struct ipt_ISG_info)),
    .help		= &help,
    .parse		= &parse,
    .final_check	= &check,
    .print		= &print,
    .save		= &save,
    .extra_opts		= opts
};

void __attribute((constructor)) my_init(void) {
    register_target(&isg_info);
}