/* iptables module for the Linux ISG Access Control
 *
 * (C) 2009 by Oleg A. Arkhangelsky <sysoleg@yandex.ru>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#include "isg_main.h"
#include "build.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Oleg A. Arkhangelsky <sysoleg@yandex.ru>");
MODULE_DESCRIPTION("Xtables: Linux ISG Access Control");

static inline struct isg_session *isg_find_session(struct isg_in_event *);
static int isg_start_session(struct isg_session *);
static void isg_send_sessions_list(pid_t, struct isg_in_event *);
static int isg_free_session(struct isg_session *);
static int isg_clear_session(struct isg_in_event *);
static int isg_update_session(struct isg_in_event *);
static void isg_send_session_count(pid_t);
static void isg_send_event(u_int16_t, struct isg_session *, pid_t, int, int);
static void isg_send_event_type(pid_t, u_int32_t);
static int isg_add_service_desc(u_int8_t *, u_int8_t *);
static int isg_apply_service(struct isg_in_event *);
static void isg_session_timeout(unsigned long);
static void isg_sweep_service_desc_tc(void);
static void isg_send_services_list(pid_t, struct isg_in_event *);

static int approve_retry_interval = 60;
module_param(approve_retry_interval, int, 0600);
MODULE_PARM_DESC(approve_retry_interval, "Session approve retry interval (in seconds)");

static int nr_buckets = 8192;
module_param(nr_buckets, int, 0400);
MODULE_PARM_DESC(nr_buckets, "Number of buckets to store current sessions list");

int nehash_key_len = 20;
module_param(nehash_key_len, int, 0400);
MODULE_PARM_DESC(nehash_key_len, "Network hash key length (in bits)");

/* Don't touch parameters below (unless you know what you're doing) */

static unsigned int tg_action = XT_CONTINUE;
module_param(tg_action, uint, 0400);

static unsigned int session_check_interval = 10;
module_param(session_check_interval, uint, 0400);

static unsigned int pass_outgoing = 0;
module_param(pass_outgoing, bool, 0400);

static struct hlist_head *isg_hash = NULL;
static struct hlist_head isg_services;
static struct sock *sknl;

static unsigned long *port_bitmap = NULL;
static unsigned int jhash_rnd __read_mostly;

static pid_t isg_listener_pid = 0;
static unsigned int current_sess_cnt = 0;
static unsigned int unapproved_sess_cnt = 0;
static bool module_exiting = 0;

static DEFINE_MUTEX(event_mutex);
spinlock_t isg_lock = SPIN_LOCK_UNLOCKED;

struct sk_buff *sskb = NULL;

static void nl_receive_main(struct sk_buff *skb) {
    struct nlmsghdr *nlh = (struct nlmsghdr *) skb->data;
    struct isg_in_event *ev = (struct isg_in_event *) NLMSG_DATA(nlh);
    pid_t from_pid = ((struct nlmsghdr *)(skb->data))->nlmsg_pid;

    mutex_lock(&event_mutex);

    switch (ev->type) {
	int type;

	case EVENT_LISTENER_REG:
	    isg_listener_pid = from_pid;
	    printk(KERN_INFO "ipt_ISG: Listener daemon with pid %d registered\n", from_pid);
	    break;

	case EVENT_SESS_APPROVE:
	case EVENT_SESS_CHANGE:
	    if (isg_update_session(ev)) {
		type = EVENT_KERNEL_NACK;
	    } else {
		type = EVENT_KERNEL_ACK;
	    }
	    if (ev->type == EVENT_SESS_CHANGE) {
		isg_send_event_type(from_pid, type);
	    }
	    break;

	case EVENT_SERV_APPLY:
	    isg_apply_service(ev);
	    break;

	case EVENT_SESS_GETLIST:
	    isg_send_sessions_list(from_pid, ev);
	    break;

	case EVENT_SESS_GETCOUNT:
	    isg_send_session_count(from_pid);
	    break;

	case EVENT_SESS_CLEAR:
	    if (isg_clear_session(ev)) {
		type = EVENT_KERNEL_NACK;
	    } else {
		type = EVENT_KERNEL_ACK;
	    }
	    isg_send_event_type(from_pid, type);
	    break;

	case EVENT_NE_SWEEP_QUEUE:
	    nehash_sweep_queue();
	    isg_send_event_type(from_pid, EVENT_KERNEL_ACK);
	    break;

	case EVENT_NE_ADD_QUEUE:
	    nehash_add_to_queue(ev->ne.pfx, ev->ne.mask, ev->ne.tc_name);
	    isg_send_event_type(from_pid, EVENT_KERNEL_ACK);
	    break;

	case EVENT_NE_COMMIT:
	    nehash_commit_queue();
	    isg_send_event_type(from_pid, EVENT_KERNEL_ACK);
	    break;

	case EVENT_SDESC_ADD:
	    if (isg_add_service_desc(ev->sdesc.service_name, ev->sdesc.tc_name)) {
		type = EVENT_KERNEL_NACK;
	    } else {
		type = EVENT_KERNEL_ACK;
	    }
	    isg_send_event_type(from_pid, type);
	    break;

	case EVENT_SDESC_SWEEP_TC:
	    isg_sweep_service_desc_tc();
	    isg_send_event_type(from_pid, EVENT_KERNEL_ACK);
	    break;

	case EVENT_SERV_GETLIST:
	    isg_send_services_list(from_pid, ev);
	    break;

	default:
	    printk(KERN_ERR "ipt_ISG: Unknown event type %d\n", ev->type);
    }

    mutex_unlock(&event_mutex);
}

static void isg_send_skb(pid_t pid) {
    int err = netlink_unicast(sknl, sskb, pid, MSG_DONTWAIT);

    if (err < 0) {
	if (pid == isg_listener_pid) {
	    if (err == -ECONNREFUSED) {
		printk(KERN_ERR "ipt_ISG: Listener daemon (pid %d) disappeared\n", isg_listener_pid);
	        isg_listener_pid = 0;
	    } else {
		printk(KERN_ERR "ipt_ISG: Lost packet during sending data to listener (err=%d)\n", err);
	    }
	} else {
	    printk(KERN_ERR "ipt_ISG: Error (%d) while sending response to pid %d\n", err, pid);
	}
    }

    sskb = NULL;
}

static int isg_alloc_skb(unsigned int size) {
    sskb = alloc_skb(size, GFP_ATOMIC);

    if (!sskb) {
        printk(KERN_ERR "ipt_ISG: isg_alloc_skb() unable to alloc_skb\n");
        return 0;
    }

    return 1;
}

static void isg_send_event(u_int16_t type, struct isg_session *is, pid_t pid, int nl_type, int nl_flags) {
    struct isg_out_event *ev;

    struct nlmsghdr *nlh;
    void *nl_data;

    int data_size = sizeof(struct isg_out_event);
    int len = NLMSG_SPACE(data_size);

    struct timespec ts_now = ktime_to_timespec(ktime_get());

    if (is && is->info.flags & ISG_SERVICE_NO_ACCT) {
        return;
    }

    if (pid == 0) {
	if (isg_listener_pid) {
	    pid = isg_listener_pid;
	} else {
	    return;
	}
    }

    ev = kzalloc(sizeof(struct isg_out_event), GFP_ATOMIC);
    if (!ev) {
        printk(KERN_ERR "ipt_ISG: isg_send_event() event allocation failed\n");
        return;
    }

    ev->type = type;

    if (is) {
	ev->sinfo = is->info;
	ev->sstat = is->stat;

	if (is->start_ktime) {
	    ev->sstat.duration = ts_now.tv_sec - is->start_ktime;
	}

	if (is->parent_is) {
	    ev->parent_session_id = is->parent_is->info.id;
	}

	if (is->sdesc) {
	    memcpy(ev->service_name, is->sdesc->name, sizeof(is->sdesc->name));
	}
    }

    if (nl_flags & NLM_F_MULTI) {
	if (!sskb) {
	    if (!isg_alloc_skb(NLMSG_GOODSIZE))
		goto alloc_fail;
	} else {
	    if (len > skb_tailroom(sskb)) {
		isg_send_skb(pid);

		if (!isg_alloc_skb(NLMSG_GOODSIZE))
		    goto alloc_fail;
	    }
	}
    } else {
        if (!isg_alloc_skb(len))
    	    goto alloc_fail;
    }

    nlh = NLMSG_PUT(sskb, 0, 0, nl_type, data_size);

    if (nl_flags) {
	nlh->nlmsg_flags |= nl_flags;
    }

    nl_data = NLMSG_DATA(nlh);
    memcpy(nl_data, ev, data_size);

    NETLINK_CB(sskb).pid = 0;
    NETLINK_CB(sskb).dst_group = 0;

    if (nl_type == NLMSG_DONE) {
	isg_send_skb(pid);
    }

    kfree(ev);

    return;

alloc_fail:
    printk(KERN_ERR "ipt_ISG: SKB allocation failed\n");

nlmsg_failure:
    if (sskb) {
	kfree_skb(sskb);
    }

    kfree(ev);
}

static void isg_send_event_type(pid_t pid, u_int32_t type) {
    spin_lock_bh(&isg_lock);
    isg_send_event(type, NULL, pid, NLMSG_DONE, 0);
    spin_unlock_bh(&isg_lock);
}

static inline unsigned int get_isg_hash(u_int32_t val) {
    return jhash_1word(val, jhash_rnd) & (nr_buckets - 1);
}

static void isg_hash_insert(struct isg_session *is) {
    unsigned int h = get_isg_hash(is->info.ipaddr);
    hlist_add_head(&is->list, &isg_hash[h]);
}

static struct isg_service_desc *find_service_desc(u_int8_t *service_name) {
    struct isg_service_desc *sdesc;
    struct hlist_node *n;

    hlist_for_each_entry(sdesc, n, &isg_services, list) {
	if (!strcmp(sdesc->name, service_name)) {
	    return sdesc;
	}
    }

    return NULL;
}

static void isg_sweep_service_desc_tc(void) {
    struct isg_service_desc *sdesc;
    struct hlist_node *n;

    hlist_for_each_entry(sdesc, n, &isg_services, list) {
	memset(sdesc->tcs, 0, sizeof(sdesc->tcs));
    }
}

static int isg_add_service_desc(u_int8_t *service_name, u_int8_t *tc_name) {
    struct traffic_class *tc = NULL;
    struct traffic_class **tc_list;
    struct isg_service_desc *sdesc;
    int i;

    spin_lock_bh(&isg_lock);

    tc = nehash_find_class(tc_name);
    if (!tc) {
        printk(KERN_ERR "ipt_ISG: Unknown traffic class '%s' for service name '%s'\n", tc_name, service_name);
        goto err;
    }

    sdesc = find_service_desc(service_name);
    if (!sdesc) {
	sdesc = kzalloc(sizeof(struct isg_service_desc), GFP_ATOMIC);
	if (!sdesc) {
	    printk(KERN_ERR "ipt_ISG: service allocation failed\n");
	    goto err;
	}

	memcpy(sdesc->name, service_name, sizeof(sdesc->name));
	hlist_add_head(&sdesc->list, &isg_services);
    }

    tc_list = sdesc->tcs;

    for (i = 0; *tc_list && i < MAX_SD_CLASSES; i++) {
	tc_list++;
    }

    if (*tc_list) {
	printk(KERN_ERR "ipt_ISG: Can't add traffic class to service description\n");
	goto err;
    }

    *tc_list = tc;

    spin_unlock_bh(&isg_lock);
    return 0;

err:
    spin_unlock_bh(&isg_lock);
    return 1;
}

static int isg_apply_service(struct isg_in_event *ev) {
    struct isg_session *is, *nis;
    struct isg_service_desc *sdesc;

    spin_lock_bh(&isg_lock);

    sdesc = find_service_desc(ev->si.service_name);
    if (!sdesc) {
	printk(KERN_ERR "ipt_ISG: Unknown service name '%s'\n", ev->si.service_name);
	goto err;
    }

    is = isg_find_session(ev);
    if (is) {
	nis = kzalloc(sizeof(struct isg_session), GFP_ATOMIC);
	if (!nis) {
	    printk(KERN_ERR "ipt_ISG: service allocation failed\n");
	    goto err;
	}

	nis->sdesc = sdesc;
	nis->parent_is = is;
	nis->info = is->info;
	get_random_bytes(&(nis->info.id), sizeof(nis->info.id));

	hlist_add_head(&nis->srv_node, &is->srv_head);

	setup_timer(&nis->timer, isg_session_timeout, (unsigned long)nis);
	mod_timer(&nis->timer, jiffies + session_check_interval * HZ);

	ev->si.sinfo.id = nis->info.id;
	ev->si.sinfo.flags |= ISG_IS_SERVICE;

	spin_unlock_bh(&isg_lock);

	isg_update_session(ev);

	return 0;
    } else {
	printk(KERN_ERR "ipt_ISG: Unable to find parent session\n");
    }

err:
    spin_unlock_bh(&isg_lock);
    return 1;
}

static struct isg_session *isg_create_session(u_int32_t ipaddr, u_int8_t *src_mac) {
    struct isg_session *is;
    unsigned int port_number;
    struct timespec ts_now = ktime_to_timespec(ktime_get());

    is = kzalloc(sizeof(struct isg_session), GFP_ATOMIC);
    if (!is) {
	printk(KERN_ERR "ipt_ISG: session allocation failed\n");
	return NULL;
    }

    is->info.ipaddr = ipaddr;
    is->start_ktime = ts_now.tv_sec;

    port_number = find_next_zero_bit(port_bitmap, PORT_BITMAP_SIZE, 1);
    set_bit(port_number, port_bitmap);
    is->info.port_number = port_number;

    if (src_mac) {
	memcpy(is->info.macaddr, src_mac, ETH_ALEN);
    }

    get_random_bytes(&(is->info.id), sizeof(is->info.id));

    setup_timer(&is->timer, isg_session_timeout, (unsigned long)is);
    mod_timer(&is->timer, jiffies + approve_retry_interval * HZ);

    isg_hash_insert(is);

    isg_send_event(EVENT_SESS_CREATE, is, 0, NLMSG_DONE, 0);

    current_sess_cnt++;
    unapproved_sess_cnt++;

    return is;
}

static int isg_start_session(struct isg_session *is) {
    struct timespec ts_now = ktime_to_timespec(ktime_get());

    is->stat.in_packets  = 0;
    is->stat.out_packets = 0;
    is->stat.in_bytes    = 0;
    is->stat.out_bytes   = 0;
    is->stat.duration    = 0;

    is->in_last_seen = ktime_to_ns(ktime_get());
    is->start_ktime = is->last_export = ts_now.tv_sec;

    if (is->info.flags & ISG_IS_SERVICE) {
	is->info.flags |= ISG_SERVICE_ONLINE;
    }

    mod_timer(&is->timer, jiffies + session_check_interval * HZ);

    isg_send_event(EVENT_SESS_START, is, 0, NLMSG_DONE, 0);

    return 0;
}

static int isg_update_session(struct isg_in_event *ev) {
    struct isg_session *is;

    spin_lock_bh(&isg_lock);

    is = isg_find_session(ev);

    if (is) {
	is->info.in_rate = ev->si.sinfo.in_rate;
	is->info.in_burst = ev->si.sinfo.in_burst;

	is->info.out_rate = ev->si.sinfo.out_rate;
	is->info.out_burst = ev->si.sinfo.out_burst;

	if (ev->si.sinfo.nat_ipaddr) {
	    is->info.nat_ipaddr = ev->si.sinfo.nat_ipaddr;
	}

	if (ev->si.sinfo.export_interval) {
	    is->info.export_interval = ev->si.sinfo.export_interval;
	}

	if (ev->si.sinfo.idle_timeout) {
	    is->info.idle_timeout = ev->si.sinfo.idle_timeout;
	}

	if (ev->si.sinfo.max_duration) {
	    is->info.max_duration = ev->si.sinfo.max_duration;
	}

	if (ev->si.sinfo.flags) {
	    u_int16_t flags = ev->si.sinfo.flags & FLAGS_RW_MASK;

	    if (!ev->si.flags_op) {
		is->info.flags = flags;
	    } else if (ev->si.flags_op == FLAG_OP_SET) {
		is->info.flags |= flags;
	    } else if (ev->si.flags_op == FLAG_OP_UNSET) {
		is->info.flags &= ~flags;
	    }

	    if (IS_SERVICE_ONLINE(is) && !(is->info.flags & ISG_SERVICE_STATUS_ON)) {
		isg_free_session(is);
	    }
	}

	if (ev->type == EVENT_SERV_APPLY) {
	    is->info.flags |= ISG_IS_SERVICE;
	} else if (ev->type == EVENT_SESS_APPROVE) {
	    is->info.flags |= ISG_IS_APPROVED;
	    isg_start_session(is);
	    unapproved_sess_cnt--;
	}

	spin_unlock_bh(&isg_lock);
	return 0;
    }

    spin_unlock_bh(&isg_lock);
    return 1;
}

static void _isg_free_session(struct isg_session *is) {
    if (del_timer(&is->timer) || module_exiting) {
	/* Timer handler is not running currently */
	kfree(is);
    } else {
	/* Session will be freed by timer's handler */
	is->info.flags |= ISG_IS_DYING;
    }
}

static int isg_free_session(struct isg_session *is) {
    if (!IS_SERVICE(is)) {
	if (is->info.port_number) {
	    clear_bit(is->info.port_number, port_bitmap);
	}

	if (!(is->info.flags & ISG_IS_APPROVED)) {
	    unapproved_sess_cnt--;
	}
    }

    if (!hlist_empty(&is->srv_head)) { /* Freeing sub-sessions also */
	struct isg_session *isrv;
	struct hlist_node *n, *t;

	hlist_for_each_entry_safe(isrv, n, t, &is->srv_head, srv_node) {
	    if (IS_SERVICE_ONLINE(isrv)) {
		isg_send_event(EVENT_SESS_STOP, isrv, 0, NLMSG_DONE, 0);
	    }
	    hlist_del(&isrv->srv_node);
	    _isg_free_session(isrv);
	}
    }

    isg_send_event(EVENT_SESS_STOP, is, 0, NLMSG_DONE, 0);

    if (!IS_SERVICE(is)) {
	hlist_del(&is->list);
	_isg_free_session(is);
	current_sess_cnt--;
    } else {
	is->info.flags &= ~ISG_SERVICE_ONLINE;
	get_random_bytes(&(is->info.id), sizeof(is->info.id));
	is->start_ktime = 0;
	memset(&is->stat, 0, sizeof(is->stat));
    }

    return 0;
}

static int isg_clear_session(struct isg_in_event *ev) {
    struct isg_session *is;

    spin_lock_bh(&isg_lock);

    is = isg_find_session(ev);
    if (is) {
	isg_free_session(is);
	spin_unlock_bh(&isg_lock);
	return 0;
    }

    spin_unlock_bh(&isg_lock);

    return 1;
}

static inline struct isg_session *isg_lookup_session(u_int32_t ipaddr) {
    struct isg_session *is;
    struct hlist_node *n;
    unsigned int h = get_isg_hash(ipaddr);

    hlist_for_each_entry(is, n, &isg_hash[h], list) {
	if (is->info.ipaddr == ipaddr) {
            return is;
        }
    }

    return NULL;
}

static inline int isg_equal(struct isg_in_event *ev, struct isg_session *is) {
    if ((ev->si.sinfo.id && ev->si.sinfo.id == is->info.id) ||
	(is->info.port_number == ev->si.sinfo.port_number) ||
	(is->info.ipaddr == ev->si.sinfo.ipaddr)) {
	return 1;
    } else {
	return 0;
    }
}

static struct isg_session *isg_find_session(struct isg_in_event *ev) {
    unsigned int i;
    struct isg_session *is;
    struct hlist_node *n;

    for (i = 0; i < nr_buckets; i++) {
        hlist_for_each_entry(is, n, &isg_hash[i], list) {
	    if (ev->si.sinfo.flags & ISG_IS_SERVICE) {
		/* Searching for sub-session (service) */
		if (!hlist_empty(&is->srv_head)) {
		    struct isg_session *isrv;
		    struct hlist_node *t;

		    hlist_for_each_entry(isrv, t, &is->srv_head, srv_node) {
			if (isg_equal(ev, isrv)) {
			    return isrv;
			}
		    }
		}
	    } else {
		/* Searching for session (only heads) */
		if (isg_equal(ev, is)) {
		    return is;
		}
	    }
	}
    }
    return NULL;
}

static void isg_send_sessions_list(pid_t pid, struct isg_in_event *ev) {
    unsigned int i, exported_cnt = 0, t = 0;
    struct isg_session *is = NULL;
    struct hlist_node *n;

    spin_lock_bh(&isg_lock);

    if (current_sess_cnt == 0) {
	isg_send_event(EVENT_SESS_INFO, NULL, pid, NLMSG_DONE, 0);
        spin_unlock_bh(&isg_lock);
	return;
    }

    if (ev->si.sinfo.port_number || ev->si.sinfo.id) {
	is = isg_find_session(ev);
	isg_send_event(EVENT_SESS_INFO, is, pid, NLMSG_DONE, 0);
    } else {
	for (i = 0; i < nr_buckets; i++) {
    	    hlist_for_each_entry(is, n, &isg_hash[i], list) {
    		if (++exported_cnt == current_sess_cnt) {
    		    t = NLMSG_DONE;
    		}
    		isg_send_event(EVENT_SESS_INFO, is, pid, t, NLM_F_MULTI);
    	    }
	}
    }

    spin_unlock_bh(&isg_lock);
}

static void isg_send_session_count(pid_t pid) {
    struct isg_session *is = NULL;

    spin_lock_bh(&isg_lock);

    is = kzalloc(sizeof(struct isg_session), GFP_ATOMIC);
    if (!is) {
	printk(KERN_ERR "ipt_ISG: session allocation failed\n");
	spin_unlock_bh(&isg_lock);
        return;
    }

    is->info.ipaddr = current_sess_cnt;
    is->info.nat_ipaddr = unapproved_sess_cnt;

    isg_send_event(EVENT_SESS_COUNT, is, pid, NLMSG_DONE, 0);

    kfree(is);

    spin_unlock_bh(&isg_lock);
}

static void isg_send_services_list(pid_t pid, struct isg_in_event *ev) {
    struct isg_session *is, *isrv;
    struct hlist_node *n;
    unsigned int t = 0;

    spin_lock_bh(&isg_lock);

    is = isg_find_session(ev);

    if (is && !hlist_empty(&is->srv_head)) {
	hlist_for_each_entry(isrv, n, &is->srv_head, srv_node) {
	    if (n->next == NULL) {
		t = NLMSG_DONE;
	    }
	    isg_send_event(EVENT_SESS_INFO, isrv, pid, t, NLM_F_MULTI);
	}
    } else {
	/* Session not found or found, but has no services */
	isg_send_event(EVENT_SESS_INFO, NULL, pid, NLMSG_DONE, 0);
    }

    spin_unlock_bh(&isg_lock);
}

static void isg_update_tokens(struct isg_session *is, u_int64_t now, u_int8_t dir) {
    u_int64_t tokens;

    if (dir == ISG_DIR_IN) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
	tokens = div_s64(is->info.in_rate * (now - is->in_last_seen), NSEC_PER_SEC);
#else
	tokens = is->info.in_rate * (now - is->in_last_seen);
	tokens = do_div(tokens, NSEC_PER_SEC);
#endif
	if ((is->in_tokens + tokens) > is->info.in_burst) {
            is->in_tokens = is->info.in_burst;
        } else {
            is->in_tokens += tokens;
        }

	is->in_last_seen = now;
    } else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
	tokens = div_s64(is->info.out_rate * (now - is->out_last_seen), NSEC_PER_SEC);
#else
	tokens = is->info.out_rate * (now - is->out_last_seen);
	tokens = do_div(tokens, NSEC_PER_SEC);
#endif
	if ((is->out_tokens + tokens) > is->info.out_burst) {
            is->out_tokens = is->info.out_burst;
        } else {
            is->out_tokens += tokens;
        }

	is->out_last_seen = now;
    }
}

static void isg_session_timeout(unsigned long arg) {
    struct isg_session *is = (struct isg_session *) arg;
    struct timespec ts_now = ktime_to_timespec(ktime_get());

    if (module_exiting) {
	return;
    }

    spin_lock_bh(&isg_lock);

    if (is->info.flags & ISG_IS_DYING) {
	printk(KERN_DEBUG "ipt_ISG: ISG_IS_DYING is set, freeing (ignore this)\n");
	kfree(is);
	goto unlock;
    }

    if (!is->info.flags) { /* Unapproved session */
	isg_free_session(is);
	goto kfree;
    } else if (IS_SESSION_APPROVED(is) || IS_SERVICE_ONLINE(is)) {
	struct timespec ts_ls;
	struct isg_session *isrv;
	struct hlist_node *n;

	is->stat.duration = ts_now.tv_sec - is->start_ktime;

        if (!hlist_empty(&is->srv_head)) {
	    hlist_for_each_entry(isrv, n, &is->srv_head, srv_node) {
		is->in_last_seen = max(is->in_last_seen, isrv->in_last_seen);
		is->out_last_seen = max(is->out_last_seen, isrv->out_last_seen);
	    }
	}

	ts_ls = ns_to_timespec(is->in_last_seen);

	/* Check maximum session duration and idle timeout */
	if ((is->info.max_duration && is->stat.duration >= is->info.max_duration) ||
	    (is->info.idle_timeout && ts_now.tv_sec - ts_ls.tv_sec >= is->info.idle_timeout)) {
	    isg_free_session(is);
	    if (!IS_SERVICE(is)) {
	        goto kfree;
	    }
	/* Check last export time */
	} else if (is->info.export_interval && ts_now.tv_sec - is->last_export >= is->info.export_interval) {
	    is->last_export = ts_now.tv_sec;
	    isg_send_event(EVENT_SESS_UPDATE, is, 0, NLMSG_DONE, 0);
	}
    }

    mod_timer(&is->timer, jiffies + session_check_interval * HZ);

unlock:
    spin_unlock_bh(&isg_lock);
    return;

kfree:
    if (is->info.flags & ISG_IS_DYING) {
	kfree(is);
    }
    goto unlock;
}

static unsigned int
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
isg_tg(struct sk_buff **pskb,
	unsigned int hooknum,
	const struct net_device *in,
	const struct net_device *out,
	const void *targinfo,
	void *userinfo)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)
isg_tg(struct sk_buff **pskb,
	const struct net_device *in,
	const struct net_device *out,
	unsigned int hooknum,
	const void *targinfo,
	void *userinfo)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
isg_tg(struct sk_buff **pskb,
	const struct net_device *in,
	const struct net_device *out,
	unsigned int hooknum,
	const struct xt_target *target,
	const void *targinfo,
	void *userinfo)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
isg_tg(struct sk_buff **pskb,
	const struct net_device *in,
	const struct net_device *out,
	unsigned int hooknum,
	const struct xt_target *target,
	const void *targinfo)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
isg_tg(struct sk_buff *skb,
	const struct net_device *in,
	const struct net_device *out,
	unsigned int hooknum,
	const struct xt_target *target,
	const void *targinfo)
#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,28) */
isg_tg(struct sk_buff *skb,
	const struct xt_target_param *par)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
    const struct ipt_ISG_info *iinfo = targinfo;
#else
    const struct ipt_ISG_info *iinfo = par->targinfo;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
    struct sk_buff *skb = *pskb;
#endif

    struct iphdr _iph, *iph;
    struct isg_session *is, *isrv, *classic_is = NULL;
    struct nehash_entry *ne;
    struct traffic_class **tc_list;
    __be32 laddr, raddr;

    u_int32_t pkt_len, pkt_len_bits;
    u_int64_t now;

    iph = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);
    if (iph == NULL) {
	return NF_DROP;
    }

    pkt_len = ntohs(iph->tot_len);

    now = ktime_to_ns(ktime_get());

    pkt_len_bits = pkt_len << 3;

    spin_lock_bh(&isg_lock);

    if (iinfo->flags & ISG_DIR_IN) { /* Init direction */
	laddr = iph->saddr;
	raddr = iph->daddr;
    } else {
	laddr = iph->daddr;
	raddr = iph->saddr;
    }

    is = isg_lookup_session(laddr);

    if (is == NULL) {
	if (iinfo->flags & ISG_DIR_IN) {
	    u_int8_t *src_mac = NULL;

	    if (skb_mac_header(skb) >= skb->head && skb_mac_header(skb) + ETH_HLEN <= skb->data) {
		src_mac = eth_hdr(skb)->h_source;
	    }

	    isg_create_session(laddr, src_mac);
	} else if (pass_outgoing) {
	    goto ACCEPT;
	}
	goto DROP;
    }

    if (!(is->info.flags & ISG_IS_APPROVED)) {
        goto DROP;
    }

    if (!hlist_empty(&is->srv_head)) {
	/* This session is having sub-sessions, try to classify */
        struct hlist_node *n;

	ne = nehash_lookup(raddr);
	if (ne == NULL) {
	    goto DROP;
	}

	classic_is = is;

        hlist_for_each_entry(isrv, n, &is->srv_head, srv_node) { /* For each sub-session */
	    int i;

            if (!(isrv->info.flags & ISG_SERVICE_STATUS_ON)) {
		continue;
	    }

	    tc_list = isrv->sdesc->tcs;

	    for (i = 0; *tc_list && i < MAX_SD_CLASSES; i++, tc_list++) { /* For each service description's class */
		struct traffic_class *tc = *tc_list;
		if (ne->tc == tc) {
		    is = isrv;
		    goto found;
		}
	    }
        }
	/* This packet not belongs to session's services (or appropriate service's status is not on) */
        goto DROP;

found:
	if (!(is->info.flags & ISG_SERVICE_ONLINE)) {
	    isg_start_session(is);
	}
    }

    if (iinfo->flags & ISG_DIR_IN) {
	isg_update_tokens(is, now, ISG_DIR_IN);

	if (pkt_len_bits <= is->in_tokens || !is->info.in_rate) {
	    is->in_tokens -= pkt_len_bits;

	    is->stat.in_bytes += pkt_len;
	    is->stat.in_packets++;

	    if (classic_is) {
		classic_is->stat.in_bytes += pkt_len;
		classic_is->stat.in_packets++;
	    }

	    goto ACCEPT;
	} else {
	    goto DROP;
	}
    } else {
	isg_update_tokens(is, now, ISG_DIR_OUT);

	if (pkt_len_bits <= is->out_tokens || !is->info.out_rate) {
	    is->out_tokens -= pkt_len_bits;

	    is->stat.out_bytes += pkt_len;
	    is->stat.out_packets++;

	    if (classic_is) {
		classic_is->stat.out_bytes += pkt_len;
		classic_is->stat.out_packets++;
	    }

	    goto ACCEPT;
	} else {
	    goto DROP;
	}
    }

ACCEPT:
    spin_unlock_bh(&isg_lock);
    return tg_action;

DROP:
    spin_unlock_bh(&isg_lock);
    return NF_DROP;
}

static struct xt_target isg_tg_reg __read_mostly = {
    .name		= "ISG",
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,28)
    .family		= NFPROTO_IPV4,
#else
    .family		= AF_INET,
#endif
    .target		= isg_tg,
    .targetsize		= sizeof(struct ipt_ISG_info),
    .me			= THIS_MODULE,
};

static int __init isg_tg_init(void) {
    unsigned int i;
    int hsize = sizeof(struct hlist_head) * nr_buckets;

    get_random_bytes(&jhash_rnd, sizeof(jhash_rnd));

    isg_hash = vmalloc(hsize);
    if (isg_hash == NULL) {
	return -ENOMEM;
    }

    for (i = 0; i < nr_buckets; i++) {
        INIT_HLIST_HEAD(&isg_hash[i]);
    }

    INIT_HLIST_HEAD(&isg_services);

    port_bitmap = (unsigned long *)__get_free_pages(GFP_KERNEL, 1);
    if (port_bitmap == NULL) {
        return -ENOMEM;
    }

    memset(port_bitmap, 0, PAGE_SIZE << 1);

    if (nehash_init() < 0) {
	printk(KERN_ERR "ipt_ISG: Unable to initialize network hash table\n");
	return -ENOMEM;
    }

    sknl = netlink_kernel_create(&init_net, ISG_NETLINK_MAIN, 0, nl_receive_main, NULL, THIS_MODULE);
    if (sknl == NULL) {
	printk(KERN_ERR "ipt_ISG: Can't create ISG_NETLINK_MAIN socket\n");
	return -1;
    }

    printk(KERN_INFO "ipt_ISG: Loaded (built on %s)\n", _BUILD_DATE);

    return xt_register_target(&isg_tg_reg);
}

static void __exit isg_tg_exit(void) {
    unsigned int i;
    struct isg_session *is;
    struct isg_service_desc *sdesc;
    struct hlist_node *n, *t;

    module_exiting = 1;
    isg_listener_pid = 0;

    xt_unregister_target(&isg_tg_reg);

    if (sknl != NULL) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
	netlink_kernel_release(sknl);
#else
	sock_release(sknl->sk_socket);
#endif
    }

    spin_lock_bh(&isg_lock);

    for (i = 0; i < nr_buckets; i++) {
	hlist_for_each_entry_safe(is, n, t, &isg_hash[i], list) {
	    isg_free_session(is);
	}
    }

    hlist_for_each_entry_safe(sdesc, n, t, &isg_services, list) {
	hlist_del(&sdesc->list);
	kfree(sdesc);
    }

    spin_unlock_bh(&isg_lock);

    nehash_free_everything();

    vfree(isg_hash);

    free_pages((unsigned long)port_bitmap, 1);

    printk(KERN_INFO "ipt_ISG: Unloaded\n");
}

module_init(isg_tg_init);
module_exit(isg_tg_exit);
