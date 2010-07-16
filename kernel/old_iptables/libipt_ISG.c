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
    { .name = NULL }
};

static void help(void) {
    printf(
"ISG target options:\n"
" --session-init	This rule match will be session initiator\n");
}

#define OPT_INIT 0x01

static int parse(int c, char **argv, int invert, unsigned int *flags,
      const struct ipt_entry *entry,
      struct ipt_entry_target **target) {

    struct ipt_ISG_info *isg = (struct ipt_ISG_info *)(*target)->data;

    switch (c) {
    case '1':
        if (*flags & OPT_INIT) {
            exit_error(PARAMETER_PROBLEM, "Can't specify --session-init twice");
        }

	*flags |= OPT_INIT;
	isg->flags |= OPT_INIT;

        break;
    default:
	return 0;
    }

    return 1;
}

static void save(const struct ipt_ip *ip, const struct ipt_entry_target *target) {
    struct ipt_ISG_info *isg = (struct ipt_ISG_info *)target->data;

    if (isg->flags & OPT_INIT) {
	printf("--session-init ");
    }
}

static void print(const struct ipt_ip *ip,
      const struct ipt_entry_target *target,
      int numeric) {

    struct ipt_ISG_info *isg = (struct ipt_ISG_info *)target->data;

    printf("ISG ");

    if (isg->flags & OPT_INIT) {
        printf("initiator ");
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
