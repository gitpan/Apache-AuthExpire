package Apache::AuthExpire;
#file Apache/AuthExpire.pm
#
#	Author: J. J. Horner
#       Revisions:  Shannon Eric Peevey <speeves@erikin.com>
#	Version: 0.39 (07/29/2004)
#	Usage:  see documentation
#	Description:
#		Small mod_perl handler to provide Authentication phase 
#               time outs for sensitive areas, per realm.  Still has a 
#               few issues, but nothing too serious.
#

use strict;
use Carp;
use mod_perl;
require Exporter;
our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration use Apache::AuthExpire ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw() ] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

#---------------------------------------------------------------------------
#VERSION
our $VERSION = '0.39';

#---------------------------------------------------------------------------
# setting the constants to help identify which version of mod_perl
# is installed
use constant MP2 => ($mod_perl::VERSION >= 1.99);

#---------------------------------------------------------------------------
# test for the version of mod_perl, and use the appropriate libraries
BEGIN {
        if (MP2) {
                require Apache::Const;
                require Apache::Access;
                require Apache::Connection;
                require Apache::Log;
                require Apache::RequestRec;
                require Apache::RequestUtil; 
                require Apache::ServerUtil;
		require APR::Table;
                Apache::Const->import(-compile => 'HTTP_UNAUTHORIZED',
                                                  'OK','DECLINED');
        } else {
                require Apache::Constants;
		require Apache::Log;
                Apache::Constants->import('HTTP_UNAUTHORIZED','OK','DECLINED');
        }
}

#---------------------------------------------------------------------------
#---------------------------------------------------------------------------
sub handler {

    my $current_time = time();    # Time will be used here :)

    my $r = shift;
    my $log = $r->log;
    
    # check to see if this is the initial request, and pass
    # off to the next Handler, if it is not.
    return MP2 ? Apache::DECLINED : Apache::Constants::DECLINED 
        unless($r->is_initial_req);

    #grab debug value from config files.
    #Sends 'debug' level messages to error_log when set. 
    my $DEBUG;

    if (defined ($r->dir_config('TimeoutDebug'))) { 
        $DEBUG = $r->dir_config('TimeoutDebug'); 
        $log->notice("Debug value set to $DEBUG.");
    }
    
    my $default = $r->dir_config('DefaultLimit') || 60 ;
    my $limit = $r->dir_config('TimeLimit') || $default ;
    my $timeoutpurge = $r->dir_config('TimeoutPurge') || undef ;
    my $allowalternateauth = $r->dir_config('AllowAlternateAuth') || "";
    my $conftimes = $r->dir_config('TimeFileDir') || "logs/authexpire";
 
    my ($res, $sent_pw) = $r->get_basic_auth_pw;

    # Pass request to next Handler if not using Basic Authentication
    return $res 
        if($res !=  ((MP2) ? Apache::OK : Apache::Constants::OK));

    my $request_line = $r->the_request;

    # Grab TimeLimit from .htaccess file (if available)
    # or use DefaultLimit if TimeLimit not set or if
    # TimeLimit greater than default.  Can't have longer
    # time limits than max set by policy.

    # $DEBUG is set, print this to log file with
    # Default time limit
    $log->notice("Default Limit set to $default.") if ($DEBUG);

    if ($limit > $default) {
	$limit = $default;
	$log->notice("Time Limit for $request_line set to $limit") 
        	if ($DEBUG);
	}
	
    my $user = MP2 ? $r->user : $r->connection->user;
    my $realm = $r->auth_name();
    $realm =~ s/\s+/_/g;
    $realm =~ s/\//_/g;
    my $host = MP2 ? $r->connection->get_remote_host() : $r->get_remote_host();

    # Check for existence of X-Forwarded-For header, which specifies that the
    # request has been sent through a proxy.  We do this to grab the IP of the
    # original client, bypassing the problem created by all clients coming from
    # the same address.
    my $xforwardedfor = MP2 ? $r->headers_in->{'X-Forwarded-For'} : $r->header_in('X-Forwarded-For');
    if(defined($xforwardedfor))
    {
        $host = $xforwardedfor;
        $log->notice("Client: $xforwardedfor is being proxied in from $host") if ($DEBUG);
    }

    #Pre-check delete all timeout files older than N hours according
    # to TIMEOUT_PURGE value. ---bcw
    if (defined ($timeoutpurge))
    {
        $log->notice("TimeoutPurge value set to $timeoutpurge.") if ($DEBUG);
    }

    #The conftimes directory.
    my $time_file = "$conftimes/$realm-$host.$user";

    $time_file = (MP2) ? Apache::server_root_relative($r->pool,$time_file) : 
                         $r->server_root_relative($time_file);
    $log->notice("Time file set to $time_file") if ($DEBUG);

    #Do the $TimeoutPurge check here. ---bcw
    if($timeoutpurge && -e $time_file)
    {
        my $time = (stat($time_file))[9];
        if(60 * $timeoutpurge < $current_time - $time)
        {
            unlink($time_file);
            $log->notice("Time file deleted, as it has lived beyond its TimeoutPurge limit: $timeoutpurge.")
                if ($DEBUG);
        }
    }

    if (-e $time_file) {   # if timestamp file exists, check time difference
        my $last_time = (stat($time_file))[9] 
            || $log->warn("Unable to get last modtime from file: $!");

        # Determine time since last access
        my $time_delta = ($current_time - $last_time);
        if ($limit >  $time_delta) {
            # time delta = specified time limit
            open (TIME, ">$time_file") 
                || $log->warn("Can't update timestamp on $time_file: $!");
            close TIME;
	    if ($allowalternateauth eq 'yes'){
		    return MP2 ? Apache::DECLINED : Apache::Constants::DECLINED;
	    } else {
		    return MP2 ? Apache::OK : Apache::Constants::OK;
	    }
	    
        } else {  # time delta greater than TimeLimit
            $log->notice("Time since last access: $time_delta") if ($DEBUG);
            $r->note_basic_auth_failure;
            unlink($time_file) or $log->warn("Can't unlink file: $!");
            return  MP2 ? Apache::HTTP_UNAUTHORIZED : HTTP_UNAUTHORIZED;
        }

    } else {  
    # previous time delta greater than TimeLimit so file was unlinked
    # or first time checking into server.
        open (TIME, ">$time_file") || 
            $log->crit("Unable to create $time_file: $!\n");
        close TIME;
        if ($allowalternateauth eq 'yes'){
	    return MP2 ? Apache::DECLINED : Apache::Constants::DECLINED;
 	} else {
	    return MP2 ? Apache::OK : Apache::Constants::OK;
	}
    }
}

1;
__END__

=head1 NAME

Apache::AuthExpire - mod_perl handler to provide Authentication time limits on .htaccess protected pages.

=head1 SYNOPSIS

  In httpd.conf file:
	PerlAuthenHandler Apache::AuthExpire

  Optional httpd.conf file entry:
	PerlSetVar DefaultLimit <seconds>
        PerlSetVar TimeFileDir /location/of/timefilesdir
	PerlSetVar AllowAlternateAuth yes 
	PerlSetVar TimeoutDebug <0 || 1>
	
  Optional .htaccess entries: 
	PerlSetVar TimeLimit <seconds>

  Optional .htaccess or httpd.conf entries: 
        PerlSetVar TimeoutPurge <minutes> 

=head1 DESCRIPTION

This is a simple mod_perl handler for the Authentication phase which sets a 
time limit based on user inactivity. It provides timeouts for any file under 
the protection of a .htaccess file. This handler can be set anywhere an 
Authentication handler can be specified.

=head1 CONFIGURATION

=head2 PerlSetVar DefaultLimit <seconds>

Set the Default timeout limit for our session.  (time in seconds)  This is also used as the
'TimeLimit', if the 'TimeLimit' is not explicitly defined. Defaults to 60 seconds.  

=head2 PerlSetVar TimeFileDir /path

Set the timeout file directory to an alternate location. 
Default is <SERVERROOT>/logs/authexpire.

=head2 PerlSetVar AllowAlternateAuth 

Set to 'yes' to specify whether or not you would like to use a secondary 
authentication handler in conjunction with Apache::AuthExpire.  

=head2 PerlSetVar TimeoutDebug <0 || 1>

Set to 1, if you would like the module to write debugging information to the 
error_log.

=head2 PerlSetVar TimeLimit <seconds>

Explicitly set the timeout limit to a value other than the 'DefaultLimit'.  This value must
be less than the 'DefaultLimit', or else the module will revert to using the value of the
'DefaultLimit' instead. Defaults to value of the 'DefaultLimit'.

=head2 PerlSetVar TimeoutPurge <minutes>

This removes the time file if 'TimeoutPurge' has expired, and if the 'stale' time file still
exists.

=head1 INSTALLATION NOTES

This module uses the timestamps of files in the <SERVERROOT>/logs/authexpire directory
to monitor sessions.  Therefore, you need to manually create a 'authexpire' directory,
and your web server user (ie nobody), needs to have read/write access to this 
directory.

=head2 Caveats

  Does not work well with all browsers at this stage, please see
  mod_perl guide for more information.

  
=head1 EXPORT

None by default.


=head1 AUTHOR

J. J. Horner jjhorner@bellsouth.net 
Ported by Shannon Eric Peevey <speeves@erikin.com>

=head1 SEE ALSO

perl and mod_perl.

=head1 LOCATION

Can be found on CPAN.

=head1 CREDITS

plaid and merlyn from http://perlmonks.org/ for general help and debugging.

=cut


