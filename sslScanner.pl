#!/usr/bin/perl

##############################################################################
#                                                                            #
# Copyright 2010, Mike Cardwell, Contact info @ https://secure.grepular.com/ #
#                                                                            #
# This program is free software; you can redistribute it and/or modify       #
# it under the terms of the GNU General Public License as published by       #
# the Free Software Foundation; either version 2 of the License, or          #
# any later version.                                                         #
#                                                                            #
# This program is distributed in the hope that it will be useful,            #
# but WITHOUT ANY WARRANTY; without even the implied warranty of             #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the              #
# GNU General Public License for more details.                               #
#                                                                            #
# You should have received a copy of the GNU General Public License          #
# along with this program; if not, write to the Free Software                #
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA #
#                                                                            #
##############################################################################

our $VERSION = '0.2';

## Use some modules
  use strict;
  use warnings;
  use Crypt::OpenSSL::X509 qw( FORMAT_ASN1 );
  use Date::Parse;
  use Net::SSL::ExpireDate;

## Get the arguments
  my @arguments = @ARGV;

## Extract and parse options from the arguments
  my( $timeout, $expires_within, ) = ( 10, undef );
  {
     my @new_arguments = ();
     while( @arguments ){
        my $item = shift @arguments;
        if( $item =~ /^--help|-h$/ ){
           usage();
        } elsif( $item eq '--timeout' ){
           $timeout = shift @arguments;
           die "Invalid --timeout value\n" unless defined $timeout && $timeout =~ /^\d+$/;
        } elsif( $item eq '--expires-within' ){
           $expires_within = shift @arguments;
           die "Invalid --expires-within value\n" unless defined $expires_within && $expires_within =~ /^\d+$/;
        } else {
           push @new_arguments, $item;
        }
     }
     @arguments = @new_arguments;
  }

## Read the list from STDIN if there are no further arguments
  unless( @arguments ){
     while( <STDIN> ){
        chomp( my $arg = $_ );
        push @arguments, $arg;
     }
  }

## Global store for preventing duplicate checks
  my %done = ();

## Has header info been printed?
  my $header_printed = 0;

## Iterate over each remaining argument with the intention of "processing" it
  {
     my $net_netmask_required = 0; # Have we required Net::Netmask yet?

     my $res; # DNS Resolver
     while( @arguments ){
        my $arg = shift @arguments;

        ## Get the port
          my $port = 443; ( $arg, $port ) = ( $1, $2, ) if $arg =~ /^(.+):(\d+)$/;

        if( $arg =~ m#^\d{1,3}(\.\d{1,3}){3}$# ){
           ## IP
             process( $arg, $port );
        } elsif( $arg =~ m#^(\d{1,3}(?:\.\d{1,3}){3})/(\d+)$# ){
           ## IP/Net
             unless( $net_netmask_required ){
                eval 'use Net::Netmask'; die "You must install Net::Netmask to use network notation in your list\n" if $@;
                $net_netmask_required = 1;
             }

           process( $_, $port ) foreach Net::Netmask->new( $arg )->enumerate();          

        } elsif( $arg =~ m#^(?:[-a-z0-9]+\.)+(?:[-a-z0-9]{2,})$#i ){
           ## Hostname
             unless( defined $res ){
                eval 'use Net::DNS'; die "You must install Net::DNS to use hostnames rather than IPs in your list\n" if $@;
                $res = Net::DNS::Resolver->new;
             }

           my $query = $res->search( $arg );
           my @ips = $query ? map {$_->address} grep( $_->type eq 'A', $query->answer ) : ();
           warn "Failed on \"$arg\" - Error: Unable to resolve any IPs\n" unless @ips;

           process( $_, $port ) foreach @ips;
        } else {
           die "Bad argument: $arg\n";
        }
     }
  }

sub process {
   my( $ip, $port, ) = @_;

   ## Prevent duplicates
     return if exists $done{"$ip:$port"};
     $done{"$ip:$port"} = undef;

   ## Connect and retrieve the cert
     my $cert = eval {
        local $SIG{ALRM} = sub{die "Timed out\n"};
        alarm $timeout;
        Net::SSL::ExpireDate::_peer_certificate($ip, $port) or die "$!\n";
     };
     alarm 0;
     if( !defined($cert) ){
        my $error = $@; $error =~ s/[\r\n]+//gsm;
        $error =~ s# at .+? line \d+$##;
        $error = 'Does not look like an SSL port to me' if $error =~ /record type is not HANDSHAKE/;
        warn "Failed on \"$ip:$port\" - Error: $error\n";
        return;
     }

   ## Parse the certificate
    $cert = Crypt::OpenSSL::X509->new_from_string( $cert, FORMAT_ASN1 );
    die "FAIL\n" unless $cert;

   ## Retrieve the CN
     my( $cn ) = $cert->subject() =~ /^(?:.+? )?CN=([-\*\.a-zA-Z0-9]+)/; $cn = 'Unknown' unless defined $cn;

   ## Calculate how long the cert has left, given the expiry date
     my $days_left = int( ( str2time( $cert->notAfter() ) - time ) / 86400 );

   ## Don't display info unless it expires within x days of expiry
     return if $expires_within && $days_left > $expires_within;

   ## Send the table header
     unless( $header_printed ){
        printf("%15s  %5s  %9s  %s\n", 'IP Address', 'Port', 'Days Left', 'Common Name' );
        $header_printed = 1;
     }

   ## Output results
     printf("%15s  %5s  %9s  %s\n", $ip, $port, $days_left, $cn );
}

sub usage {
   print << "END_USAGE";
Usage:

1.) sslScanner.pl <Options> <Hosts>
2.) cat Hosts_List.txt | sslScanner.pl <Options>

Hosts:
  Any number of hosts can be scanned. They must each adhere to one of
  the following formats:

  x.x.x.x           : IP address
  x.x.x.x/cidr      : CIDR network. Requires Net::Netmask
  x.x.x.x:port      : IP address with port
  x.x.x.x/cidr:port : CIDR network and port. Requires Net::Netmask
  example.com       : Domain name
  example.com:port  : Domain name with port

  The port defaults to 443 (https) if not provided

Options:
  --help or -h          : Display this help information and exit
  --timeout secs        : Connection timeout. Default is 10
  --expires-within days : Only display info for those certs which
                          expire within x days, or that fail to lookup
END_USAGE
   exit 0;
}
