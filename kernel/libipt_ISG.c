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

static const struct option opts[] = {
    { "session-init", 0, NULL, '1' },
    { .name = NULL }
};

static void help(void) {
    printf(
"ISG target options:\n"
" --session-init	This rule match will be session initiator\n");
}

#define OPT_INIT 0x01

#if defined NEWSTYLE
    #define _EXIT_ERROR  xtables_error
    #define _SAVE_STRING xtables_save_string
#else
    #define _EXIT_ERROR  exit_error
    #define _SAVE_STRING save_string
#endif

static int parse(int c, char **argv, int invert, unsigned int *flags,
      const void *entry,
      struct xt_entry_target **target) {

    struct ipt_ISG_info *isg = (struct ipt_ISG_info *)(*target)->data;

    switch (c) {
    case '1':
        if (*flags & OPT_INIT) {
            _EXIT_ERROR(PARAMETER_PROBLEM, "Can't specify --session-init twice");
        }

	*flags |= OPT_INIT;
	isg->flags |= OPT_INIT;

        break;
    default:
	return 0;
    }

    return 1;
}

static void save(const void *ip, const struct xt_entry_target *target) {
    struct ipt_ISG_info *isg = (struct ipt_ISG_info *)target->data;

    if (isg->flags & OPT_INIT) {
	printf("--session-init ");
    }
}

static void print(const void *ip,
      const struct xt_entry_target *target,
      int numeric) {

    struct ipt_ISG_info *isg = (struct ipt_ISG_info *)target->data;

    printf("ISG ");

    if (isg->flags & OPT_INIT) {
        printf("initiator ");
    }
}

static void check(unsigned int flags) {

}

static struct xtables_target isg_info = { 
    .name		= "ISG",
    .version		= XTABLES_VERSION,
    .family		= PF_INET,
    .size		= XT_ALIGN(sizeof(struct ipt_ISG_info)),
    .userspacesize	= XT_ALIGN(sizeof(struct ipt_ISG_info)),
    .help		= help,
    .parse		= parse,
    .final_check	= check,
    .print		= print,
    .save		= save,
    .extra_opts		= opts
};

void _init(void) {
    xtables_register_target(&isg_info);
}
