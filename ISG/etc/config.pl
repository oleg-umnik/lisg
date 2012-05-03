#!/usr/bin/perl -w

### Detach from console after successful start
$cfg{daemonize} = 1;

### Log to syslog using this facility
$cfg{log_facility} = "local7";

### RADIUS-related settings

### You can specify as many as you want RADIUS servers. If server with lower index
### is not answering, server with next index will be tried (0, 1, 2, etc...).
$cfg{radius_auth}{0} = { server => "127.0.0.1:1812", timeout => 5, secret => "apple" };
$cfg{radius_acct}{0} = { server => "127.0.0.1:1813", timeout => 5, secret => "apple" };

#$cfg{nas_identifier} = "lISG"; ## By default equals to NAS IP-address

### CoA-related settings
#$cfg{coa_server} = "127.0.0.1";  ## Accept requests only from this IP (comment to accept from all)
$cfg{coa_secret} = "apple";	 ## Shared secret
$cfg{coa_port} = 3799;		 ## Local UDP port to listen for CoA requests

### Send Interim-Update to RADIUS server every session_alive_interval seconds
$cfg{session_alive_interval} = 60; ## Every minute (0 = don't send)

### Session inactivity default timeout (disconnect session after this time) (in seconds)
$cfg{session_idle_timeout} = 1800;

### Session default maximum duration (end session after this time) (in seconds)
$cfg{session_max_duration} = 86400;

### Enable static NAT using Framed-IP-Address attribute (comment to disable)
#$cfg{static_nat} = 1;

### Framed-IP-Address attribute values matching this regex will be ignored
$cfg{ignored_framed_ip} = "^192\.168\.|^255\.255\.255\.25(5|4)\$";

### Check traffic classification file MD5 sum every N seconds. If sum was changed re-read this file.
$cfg{tc_check_interval} = 300; ## Every 5 minutes

### Don't send RADIUS accounting for main session (even RADIUS Start and Stop)
#$cfg{no_accounting} = 1; ## Default is to send

####################### Services description #######################

### Begin ``TESTSERV'' service ###

## Format for download and upload rates: "rate;normal burst" (in bit/s)
## Use zero values (0;0) for no rate limit
$cfg{srv}{TESTSERV}{download_rate} = "512000;256000";
$cfg{srv}{TESTSERV}{upload_rate}   = "512000;256000";

## Traffic classes list for this service (as defined in tc.conf file)
$cfg{srv}{TESTSERV}{traffic_classes} = [ "OUR_LOCAL", "PEERING" ];

## Don't send RADIUS accounting for this service (default is to send)
#$cfg{srv}{TESTSERV}{no_accounting} = 1;

$cfg{srv}{TESTSERV}{alive_interval} = 120;   ## Equals to $cfg{session_alive_interval} if not defined
$cfg{srv}{TESTSERV}{idle_timeout}   = 600;   ## Equals to $cfg{session_idle_timeout} if not defined
$cfg{srv}{TESTSERV}{max_duration}   = 10000; ## Equals to $cfg{session_max_duration} if not defined

### End ``TESTSERV'' service ###

#################### End services description ######################

###
### It's better not to touch anything below this line
###
$cfg{debug} = 1;
$cfg{pid_file} = "/var/run/ISGd.pid";
$cfg{radius_dictionary} = $FindBin::RealBin . "/../etc/raddb/dictionary";
$cfg{tc_file} = $FindBin::RealBin . "/../etc/tc.conf"
