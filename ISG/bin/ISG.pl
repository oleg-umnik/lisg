#!/usr/bin/perl -w

use strict;

use FindBin '$Bin';
use lib $Bin . "/../lib";

use ISG;

my $ev; my %rev;

my $PRINTF_TPL = "%-7s %-15s %-15s %-13s %-16s %-7s %-10s %-10s %-10s %-10s";

my %cfg = ISG::get_conf();

my $sk = prepare_netlink_socket();
if ($sk < 0) {
    print STDERR "Unable to open netlink socket: $!\n";
    exit(1);
}

if ((@ARGV == 2 && $ARGV[0] eq "clear") || (@ARGV == 4 && $ARGV[0] eq "change_rate")) {
    if ($ARGV[1] =~ /^Virtual([0-9]{1,})$/) {
	$ev->{'port_number'} = $1;
    } else {
	$ev->{'session_id'} = ISG::hex_session_id_to_llu($ARGV[1]);
    }

    $ev->{'type'} = ISG::EVENT_SESS_CLEAR;

    if ($ARGV[0] eq "change_rate") {
	$ev->{'type'} = ISG::EVENT_SESS_CHANGE;

	$ev->{'in_rate'}  = $ARGV[2] * 1000;
	$ev->{'out_rate'} = $ARGV[3] * 1000;

	$ev->{'in_burst'}  = $ev->{'in_rate'} * $cfg{burst_factor};
	$ev->{'out_burst'} = $ev->{'out_rate'} * $cfg{burst_factor};
    }

    if (isg_send_event($sk, $ev, \%rev) < 0) {
	print STDERR "$ARGV[0]: Unable to change session parameters ($!)\n";
    }

    if ($rev{'type'} != ISG::EVENT_KERNEL_ACK) {
	print STDERR "$ARGV[0]: Unable to find session\n";
    }

} elsif (@ARGV == 1 && $ARGV[0] eq "show_count") {
    $ev->{'type'} = ISG::EVENT_SESS_GETCOUNT;

    if (isg_send_event($sk, $ev, \%rev) < 0) {
        print STDERR "Unable to get sessions count info: $!\n";
        goto out;
    }

    my $act  = ISG::ntohl($rev{'ipaddr'});
    my $unap = ISG::ntohl($rev{'nat_ipaddr'});

    print "Approved sessions count:\t" . ($act - $unap) . "\n";
    print "Unapproved sessions count:\t" . $unap ."\n";

} elsif (!defined($ARGV[0])) {
    my $data;

    $ev->{'type'} = ISG::EVENT_SESS_GETLIST;

    if (isg_send_event($sk, $ev) < 0) {
	print STDERR "Unable to get sessions list: $!\n";
	goto out;
    }

    my $tot_msg_sz = ISG::NL_HDR_LEN + ISG::IN_EVENT_MSG_LEN;
    my $stop = 0;

    printf($PRINTF_TPL . "\n",
	    "Flags",
	    "User IP-address",
	    "NAT IP-address",
	    "Port number",
	    "Uniq. Identifier",
	    "Durat.",
	    "Octets-in",
	    "Octets-out",
	    "Rate-in",
	    "Rate-out");

    while (!$stop) {
	if (!(my $read_b = netlink_read($sk, \$data, 16384, 10))) {
	    print STDERR "Recv from kernel: $!\n";
	    last;
	} else {
	    if ($read_b < $tot_msg_sz) {
		print STDERR "Packet too small ($read_b bytes)\n";
		next;
	    }

	    if ($read_b % $tot_msg_sz) {
		print STDERR "Incorrect packet length ($read_b bytes)\n";
		next;
	    }

	    my $pkts_cnt = $read_b / $tot_msg_sz;

	    for (my $i = 0; $i < $pkts_cnt; $i++) {
		my $offset = $i * $tot_msg_sz;

		$ev = isg_parse_event(substr($data, $offset, $tot_msg_sz));

		if ($ev->{'type'} == ISG::EVENT_SESS_INFO) {
		    if ($ev->{'ipaddr'} != 0) {
			printf($PRINTF_TPL . "\n",
			    ($ev->{'flags'} & ISG::IS_APPROVED_SESSION) ? "Appr" : "NonAppr",
			    ISG::long2ip($ev->{'ipaddr'}),
			    ISG::long2ip($ev->{'nat_ipaddr'}),
			    "Virtual" . $ev->{'port_number'},
			    $ev->{'session_id'},
			    $ev->{'duration'},
			    $ev->{'in_bytes'},
			    $ev->{'out_bytes'},
			    $ev->{'in_rate'},
			    $ev->{'out_rate'},
			);
		    }

		    if ($ev->{'nlhdr_type'} == ISG::NLMSG_DONE) {
			$stop = 1;
			last;
		    }
		}
	    }
	}
    }

} else {
    print STDERR "Usage: $0 show_count | clear <Virtual# | Session-ID> | change_rate <Virtual# | Session-ID> <in_rate out_rate>\n";
}

out:
close($sk);
