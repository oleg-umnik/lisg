#!/usr/bin/perl -w

use strict;

use FindBin '$Bin';
use lib $Bin . "/../lib";

use ISG;

my $ev; my %rev;

my $PRINTF_TPL = "%-15s %-15s %-13s %-16s %-7s %-10s %-10s %-10s %-10s %-16s %-5s";

sub sprint_flags {
    my $ev = shift;
    my $ret = "";

    if (!$ev->{'flags'}) {
	$ret .= "X";
    } else {
	if (!($ev->{'flags'} & ISG::IS_SERVICE)) {
	    $ret .= $ev->{'flags'} & ISG::IS_APPROVED_SESSION ? "A" : "";
	} else {
	    $ret .= "S";
	    $ret .= $ev->{'flags'} & ISG::SERVICE_STATUS_ON ? "O" : "";
	    $ret .= $ev->{'flags'} & ISG::SERVICE_ONLINE    ? "U" : "";
	    $ret .= $ev->{'flags'} & ISG::SERVICE_NO_ACCT   ? "Z" : "";
	}
    }

    return $ret;
}

my $sk = prepare_netlink_socket();
if ($sk < 0) {
    print STDERR "Unable to open netlink socket: $!\n";
    exit(1);
}

if (defined($ARGV[0]) && defined($ARGV[1])) {
    if ($ARGV[1] =~ /^Virtual([0-9]{1,})$/) {
	$ev->{'port_number'} = $1;
    } else {
	$ev->{'session_id'} = ISG::hex_session_id_to_llu($ARGV[1]);
    }
}

if ((@ARGV == 2 && $ARGV[0] eq "clear") || (@ARGV == 4 && $ARGV[0] eq "change_rate")) {
    $ev->{'type'} = ISG::EVENT_SESS_CLEAR;

    if ($ARGV[0] eq "change_rate") {
	$ev->{'type'} = ISG::EVENT_SESS_CHANGE;

	$ev->{'in_rate'}  = $ARGV[2] * 1000;
	$ev->{'out_rate'} = $ARGV[3] * 1000;

	$ev->{'in_burst'}  = $ev->{'in_rate'} * 1.5;
	$ev->{'out_burst'} = $ev->{'out_rate'} * 1.5;
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

} elsif (!defined($ARGV[0]) || (@ARGV == 2 && $ARGV[0] eq "show_services")) {
    my $data;

    if (defined($ARGV[0]) && $ARGV[0] eq "show_services") {
	$ev->{'type'} = ISG::EVENT_SERV_GETLIST;
    } else {
	$ev->{'type'} = ISG::EVENT_SESS_GETLIST;
    }

    if (isg_send_event($sk, $ev) < 0) {
	print STDERR "Unable to get sessions list: $!\n";
	goto out;
    }

    my $tot_msg_sz = ISG::NL_HDR_LEN + ISG::IN_EVENT_MSG_LEN;
    my $stop = 0;

    printf($PRINTF_TPL . "\n",
	    "User IP-address",
	    "NAT IP-address",
	    "Port number",
	    "Uniq. Identifier",
	    "Durat.",
	    "Octets-in",
	    "Octets-out",
	    "Rate-in",
	    "Rate-out",
	    "Service name",
	    "Flags"
    );

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
			    ISG::long2ip($ev->{'ipaddr'}),
			    ISG::long2ip($ev->{'nat_ipaddr'}),
			    "Virtual" . $ev->{'port_number'},
			    $ev->{'session_id'},
			    $ev->{'duration'},
			    $ev->{'in_bytes'},
			    $ev->{'out_bytes'},
			    $ev->{'in_rate'},
			    $ev->{'out_rate'},
			    defined($ev->{'service_name'}) ? $ev->{'service_name'} : "Undefined",
			    sprint_flags($ev),
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
    goto invalid_usage;
}

out:
    close($sk);
    exit();

invalid_usage:
    print <<HELP;
Usage: $0 command

$0 command without any parameters will show all active sessions

Commands:
 show_count						Show session counters
 show_services <Virtual# | Session-ID>			Show services for specific session
 clear <Virtual# | Session-ID>				Clear specific session
 change_rate <Virtual# | Session-ID> <in_rate out_rate>	Change rate for specific session

Keys to flags:
 A	Session is approved
 X	Session is not approved
 S	This is a service (or a sub-session)
 O	Service status is on
 U	Service is online (RADIUS accounting is active)
 Z	Service accounting is disabled completely
HELP
