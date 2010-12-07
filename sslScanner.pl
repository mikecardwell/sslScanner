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

## Use some modules
  use strict;
  use warnings;
  use Crypt::OpenSSL::X509 qw( FORMAT_ASN1 );
  use Date::Parse;
  use Net::SSL::ExpireDate;

## Get the arguments
  my @arguments = @ARGV;

## Extract and parse options from the arguments
  my( $timeout, $expires_within, $ipv6, $ipv4 ) = ( 10, undef, undef, undef );
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
        } elsif( $item =~ /^--ipv([46])$/ ){
           if( !defined $ipv4 ){
              $ipv4 = 0; $ipv6 = 0;
           }
           $ipv4 = 1 if $1 == 4;
           $ipv6 = 1 if $1 == 6;
        } else {
           push @new_arguments, $item;
        }
     }
     @arguments = @new_arguments;
  }

## Default to supporting both IPv4 and IPv6
  if( !defined $ipv4 ){
      $ipv4 = 1;
      $ipv6 = 1;
  }

## Read the list from STDIN if there are no further arguments
  unless( @arguments ){
     while( <STDIN> ){
        chomp( my $arg = $_ );
        push @arguments, $arg;
     }
  }

## Check for IPv6 support
  if( $ipv6 ){
     eval 'use IO::Socket::INET6';
     die "Disable IPv6 with the --ipv4 option, or install IO::Socket::INET6\n" if $@;
     die "Upgrade to v1.08 or above of Net::SSL::ExpireDate, or disable IPv6 with the --ipv4 option\n" if $Net::SSL::ExpireDate::VERSION < 1.08;
  }

## Global store for preventing duplicate checks
  my %done = ();

## Has header info been printed?
  my $header_printed = 0;

## Iterate over each remaining argument with the intention of "processing" it
  {
     my $netaddr_ip_required = 0; # Have we required NetAddr::IP yet?

     my $res; # DNS Resolver
     while( @arguments ){
        my $arg = shift @arguments;

        ## Get the port
          my $port = 443; ( $arg, $port ) = ( $1, $2, ) if $arg =~ /^(.+):(\d+)$/;

        if( $arg =~ m#^\d{1,3}(\.\d{1,3}){3}$# ){
           ## IPv4
             process( $arg, $port );
        } elsif( $arg =~ m#^\[([a-f0-9:]+)\]$#i ){
           ## IPv6
             process( $1, $port );
        } elsif( $arg =~ m#^(\d{1,3}(?:\.\d{1,3}){3})/(\d+)$# || $arg =~ m#^\[([a-f0-9:]+)\]/(\d+)$#i ){
           ## IP/Net
             unless( $netaddr_ip_required ){
                eval 'use NetAddr::IP'; die "You must install NetAddr::IP to use network notation in your list\n" if $@;
                $netaddr_ip_required = 1;
             }

           my $net = NetAddr::IP->new( "$1/$2" );
           for( my $i = 0, my $n = $net->num(); $i < $n; ++$i ){
              my( $host ) = $net->nth($i) =~ /^(.+)\//;
              process( lc($host), $port );
           }

        } elsif( $arg =~ m#^(?:[-a-z0-9]+\.)+(?:[-a-z0-9]{2,})$#i ){
           ## Hostname
             unless( defined $res ){
                eval 'use Net::DNS'; die "You must install Net::DNS to use hostnames rather than IPs in your list\n" if $@;
                $res = Net::DNS::Resolver->new;
             }

           my @types = ();
           push @types, 'A'    if $ipv4;
           push @types, 'AAAA' if $ipv6;

           my $found_ips = 0;
           foreach my $type ( @types ){
              my $query = $res->query( $arg, $type );
              my @ips = $query ? map {$_->address} grep( $_->type eq $type, $query->answer ) : ();
              $found_ips += int(@ips);
              process( $_, $port ) foreach @ips;
           }
           warn "Failed on \"$arg\" - Error: Unable to resolve any IPs\n" unless $found_ips;
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
        printf("%".($ipv6?41:15)."s  %5s  %9s  %s\n", 'IP Address', 'Port', 'Days Left', 'Common Name' );
        $header_printed = 1;
     }

   ## Output results
     printf("%".($ipv6?39:15)."s  %5s  %9s  %s\n", $ip, $port, $days_left, $cn );
}

sub usage {
   print << "END_USAGE";
Usage:

1.) sslScanner <Options> <Hosts>
2.) cat Hosts_List.txt | sslScanner <Options>

Hosts:
  Any number of hosts can be scanned. They must each adhere to one of
  the following formats:

  x.x.x.x           : IP address
  x.x.x.x/cidr      : CIDR network. Requires NetAddr::IP
  x.x.x.x:port      : IP address with port
  x.x.x.x/cidr:port : CIDR network and port. Requires NetAddr::IP
  example.com       : Domain name
  example.com:port  : Domain name with port

  The port defaults to 443 (https) if not provided

IPv6/IPv4 notes:
  x.x.x.x in all of the above examples can be replaced with an IPv6 address,
  surrounded by square brackets. By default, we do both IPv6 and IPv4 checks.
  If you use either --ipv4 or --ipv6, then only IPv4 or IPv6 checks will take
  place.

Options:
  --help or -h          : Display this help information and exit
  --ipv6                : Enable IPv6 checks
  --ipv4                : Enable IPv4 checks
  --timeout secs        : Connection timeout. Default is 10
  --expires-within days : Only display info for those certs which
                          expire within x days, or that fail to lookup
END_USAGE
   exit 0;
}
