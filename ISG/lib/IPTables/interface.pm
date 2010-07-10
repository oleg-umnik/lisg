# IPTables::interface - Perl style wrapper interface for iptables command

package IPTables::interface;

use strict;
use warnings;
use Carp;

use IO::File;
use Fcntl ':flock';

our $fh;

BEGIN {
     use Exporter ();
     our ($VERSION, @ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS);

     # Package version
     $VERSION     = 0.01;

     @ISA         = qw(Exporter);
     @EXPORT      =
      qw(
      );
}

our %table_singleton_objects;

# Create a new iptables interface Object.
sub new
{
    my $tablename = shift;
    my $self      = {};

    # Extract object if it already exist.
    my $singleton = $table_singleton_objects{"$tablename"};
    if (defined $singleton) {
	return $singleton;
    }

    # Init / create a new object.
    # ---------------------------

    $fh = new IO::File();

    if (!$fh->open("/var/lock/iptables_lock", O_CREAT | O_WRONLY | O_TRUNC)) {
        croak("Can't create lock");
    }

    flock($fh, LOCK_EX);
    
    bless $self;

    $self->{'tablename'}                   = $tablename;
    $table_singleton_objects{"$tablename"} = $self;

    return $self;
}

sub unlock()
{
    my $self = shift;
    my $tablename = $self->{'tablename'};

    flock($fh, LOCK_UN);

    # Delete singleton hash/object instans here...
    delete $table_singleton_objects{"$tablename"};

    return 1;
}

##########################################
# IPTables: Chain operations
##########################################

# $success = is_chain($chain);
sub is_chain($)
{
    my $self   = shift;
    my $chain  = shift;

    my $success = 0;

    $self->iptables_exec("-nL $chain");

    if ($self->{'iptables_status'} == 1) {
	$success = 0;
    } elsif ($self->{'iptables_status'} == 0) {
	$success = 1;
    } else {
	warn "ERROR: is_chain: unexpected status\n";
    }

    # Change loglevel as failure is to be expected.
    return $success;
}


# This attempts to create the chain $chain.
#
# $success = create_chain($chain);
sub create_chain($)
{
    my $self   = shift;
    my $chain  = shift;

    my $success = $self->iptables_do_command("-N $chain");

    return $success;
}

# This attempts to delete the chain $chain.
#
#$success = delete_chain($chain);
sub delete_chain($)
{
    my $self   = shift;
    my $chain  = shift;

    my $success = $self->iptables_do_command("-X $chain");

    return $success;
}

# $success = rename_chain($oldchain, $newchain);
sub rename_chain($$)
{
    my $self     = shift;
    my $oldchain = shift;
    my $newchain = shift;

    my $success = $self->iptables_do_command("-E $oldchain $newchain");

    return $success;
}

# $num_of_refs = get_references($chain)
# Returns -1 on failure.
sub get_references($)
{
    my $self  = shift;
    my $chain = shift;

    my $num_of_refs = -1;

    $self->iptables_exec("-nL $chain");
    my @lns = split("\n", $self->{'iptables_res'});

    if (scalar(@lns) > 0 && $lns[0] =~ /^Chain .* \((\d{1,}) references\)/) {
	$num_of_refs = $1;
    }

    return $num_of_refs;
}


##########################################
# Rules/Entries affecting a full chain
##########################################

# Delete all rules in a chain
sub flush_entries($)
{
    my $self   = shift;
    my $chain  = shift;

    my $success = $self->iptables_do_command("-F $chain");

    return $success;
}

# Zero counter (on all rules) in a chain
sub zero_entries($)
{
    my $self   = shift;
    my $chain  = shift;

    my $success = $self->iptables_do_command("-Z $chain");

    return $success;
}


##########################################
# Listing related
##########################################

sub list_chains()
{
    my $self = shift;
    my @list_of_chainnames;

    $self->iptables_exec("-nL");
    my @lns = split("\n", $self->{'iptables_res'});

    foreach(@lns) {
	if (/Chain (.*) \(/) {
	    push(@list_of_chainnames, $1);
	}
    }

    return @list_of_chainnames;
}

# Given a $chain, list the rules src or dst IPs.
#  $type = {dst,src}
sub list_rules_IPs($$)
{
    my $self  = shift;
    my $type  = shift;
    my $chain = shift;

    my @list_of_IPs;

    my $rcnt = 0;
    my $elt  = 3; # default src IPs

    if ($type eq "dst") {
	$elt = 4;
    }

    $self->iptables_exec("-nL $chain");
    my @lns = split("\n", $self->{'iptables_res'});

    foreach(@lns) {
	if ($rcnt++ > 1) {
	    my @tmp = split(" ", $_);
	    push(@list_of_IPs, $tmp[$elt]);
	}
    }

    return @list_of_IPs;
}

sub iptables_exec()
{
    my $self = shift;
    my $commands = shift;

    my $table = $self->{'tablename'};

    my $full_command = "iptables -t $table $commands 2>&1";
    
    $self->{'iptables_res'} = `$full_command`;
    chomp($self->{'iptables_res'});

    $self->{'iptables_status'} = $? >> 8;
}

sub iptables_do_command()
{
    my $self = shift;

    my @input = @_;

    my $commands = join(" ", @input);

    $self->iptables_exec($commands);

    return $self->{'iptables_status'};
}


##########################################
# Rule operations through "do_command"
##########################################

# arguments($action, $chain, $rule, $target)
sub __command_rule($$$$$$)
{
    my $self        = shift;
    my $action      = shift;
    my $chain       = shift;
    my $rule        = shift || "";
    my $target      = shift;
    my $target_opts = shift || "";

    # Handle if the "target" is not specified
    my $target_cmd="";
    if (defined $target && $target ne "") {
	$target_cmd="-j $target";
    }
    else {
	$target = "";
    }

    my $success =
	$self->iptables_do_command("$action","$chain", $rule, $target_cmd, $target_opts);

    return $success;
}

sub append_rule($$$$)
{
    my $self   = shift;
    my $action = "--append";
    my ($chain, $rule, $target, $target_opts) = @_;
    my $success =
	$self->__command_rule($action, "$chain", $rule, $target, $target_opts);
    return $success;
}

sub insert_rule($$$$)
{
    my $self   = shift;
    my $action = "--insert";
    my ($chain, $rule, $target, $target_opts) = @_;
    my $success =
	$self->__command_rule($action, "$chain", $rule, $target, $target_opts);
    return $success;
}

sub delete_rule($$$$)
{
    my $self   = shift;
    my $action = "--delete";
    my ($chain, $rule, $target, $target_opts) = @_;
    my $success =
	$self->__command_rule($action, "$chain", $rule, $target, $target_opts);
    return $success;
}

1;
