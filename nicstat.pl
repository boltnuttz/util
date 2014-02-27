#!/usr/bin/perl -w
#
# nicstat - print network traffic, Kbyte/s read and written.
#           Solaris 8+, Perl (Sun::Solaris::Kstat).
#
# "netstat -i" only gives a packet count, this program gives Kbytes.
#
# 30-Sep-2006, ver 1.00  (check for new versions, http://www.brendangregg.com)
#
# USAGE:    nicstat [-hsz] [-i int[,int...]] | [interval [count]]
#
#           -h              # help
#           -s              # print summary output
#           -z              # skip zero lines
#           -i int[,int...] # print these instances only
#   eg,
#           nicstat         # print summary since boot
#           nicstat 1       # print continually, every 1 second
#           nicstat 1 5     # print 5 times, every 1 second
#           nicstat -i hme0 # only examine hme0
#
# This prints out the KB/s transferred for all the network cards (NICs),
# including packet counts and average sizes. The first line is the summary
# data since boot.
#
# FIELDS:
#           Int         Interface
#           rKB/s       read Kbytes/s
#           wKB/s       write Kbytes/s
#           rPk/s       read Packets/s
#           wPk/s       write Packets/s
#           rAvs        read Average size, bytes
#           wAvs        write Average size, bytes
#           %Util       %Utilisation (r+w/ifspeed)
#           Sat         Saturation (defer, nocanput, norecvbuf, noxmtbuf)
#
# NOTES:
#
# - Some unusual network cards may not provide all the details to Kstat,
#   (or provide different symbols). Check for newer versions of this program,
#   and the @Network array in the code below.
# - Utilisation is based on bytes transferred divided by speed of the interface
#   (if the speed is known). It should be impossible to reach 100% as there
#   are overheads due to bus negotiation and timing.
# - Loopback interfaces may only provide packet counts (if anything), and so
#   bytes and %util will always be zero. Newer versions of Solaris (newer than
#   Solaris 10 6/06) may provide loopback byte stats.
# - Saturation is determined by counting read and write errors caused by the
#   interface running at saturation. This approach is not ideal, and the value
#   reported is often lower than it should be (eg, 0.0). Reading the rKB/s and
#   wKB/s fields may be more useful.
#
# SEE ALSO:
#           nicstat.c       # the C version, also on my website
#           kstat -n hme0 [interval [count]]       # or qfe0, ...
#           netstat -iI hme0 [interval [count]]
#           se netstat.se [interval]               # SE Toolkit
#           se nx.se [interval]                    # SE Toolkit
#
# COPYRIGHT: Copyright (c) 2006 Brendan Gregg.
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation; either version 2
#  of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software Foundation,
#  Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
#  (http://www.gnu.org/copyleft/gpl.html)
#
# Author: Brendan Gregg  [Sydney, Australia]
#
# 18-Jul-2004   Brendan Gregg   Created this.
# 07-Jan-2005       "      "    added saturation value.
# 07-Jan-2005       "      "    added summary style (from Peter Tribble).
# 23-Jan-2006       "      "    Tweaked style.
# 11-Aug-2006       "      "    Improved output neatness.
# 30-Sep-2006       "      "    Added loopback, tweaked output.

use strict;
use Getopt::Std;
#use Sun::Solaris::Kstat;
#my $Kstat = Sun::Solaris::Kstat->new();


#
#  Process command line args
#
usage() if defined $ARGV[0] and $ARGV[0] eq "--help";
getopts('hi:sz') or usage();
usage() if defined $main::opt_h;
my $STYLE  = defined $main::opt_s ? $main::opt_s : 0;
my $SKIPZERO  = defined $main::opt_z ? $main::opt_z : 0;

# process [interval [count]],
my ($interval, $loop_max);
if (defined $ARGV[0]) {
    $interval = $ARGV[0];
    $loop_max = defined $ARGV[1] ? $ARGV[1] : 2**32;
    usage() if $interval == 0;
}
else {
    $interval = 1;
    $loop_max = 1;
}

# check for -i,
my %NetworkOnly;             # network interfaces to print
my $NETWORKONLY = 0;         # match on network interfaces
if (defined $main::opt_i) {
    foreach my $net (split /,/, $main::opt_i) {
        $NetworkOnly{$net} = 1;
    }
    $NETWORKONLY = 1;
}

# globals,
my $loop = 0;                # current loop number
my $PAGESIZE = 20;           # max lines per header
my $line = $PAGESIZE;        # counter for lines printed
my %NetworkNames;            # Kstat network interfaces
my %NetworkData;             # network interface data
my %NetworkDataOld;          # network interface data
$main::opt_h = 0;
$| = 1;                      # autoflush



#
#  Main
#
while (1) {

    ### Print Header
    if ($line >= $PAGESIZE) {
        if ($STYLE == 0) {
            printf "%8s %7s %7s %7s %7s %7s %7s %7s %7s %6s\n",
                   "Time", "Int", "rKB/s", "wKB/s", "rPk/s", "wPk/s", "rAvs",
                   "wAvs", "%Util", "Sat";
        }
        elsif ($STYLE == 1) {
            printf "%8s %8s %14s %14s\n", "Time", "Int", "rKB/s", "wKB/s";
        }

        $line = 0;
    }

    ### Get new data
    my (@NetworkData) = fetch_net_data();

    foreach my $network_data (@NetworkData) {

        ### Extract values
        my ($int, $rbytes, $wbytes, $rpackets, $wpackets, $speed, $sat, $time)
            = split /:/, $network_data;

        ### Retrieve old values
        my ($old_rbytes, $old_wbytes, $old_rpackets, $old_wpackets, $old_sat,
            $old_time);
        if (defined $NetworkDataOld{$int}) {
            ($old_rbytes, $old_wbytes, $old_rpackets, $old_wpackets,
             $old_sat, $old_time) = split /:/, $NetworkDataOld{$int};
        }
        else {
            $old_rbytes = $old_wbytes = $old_rpackets = $old_wpackets
                = $old_sat = $old_time = 0;
        }

        #
        #  Calculate statistics
        #

        # delta time
        my $tdiff = $time - $old_time;

        # per second values
        my $rbps = ($rbytes - $old_rbytes) / $tdiff;
        my $wbps = ($wbytes - $old_wbytes) / $tdiff;
        my $rkps = $rbps / 1024;
        my $wkps = $wbps / 1024;
        my $rpps = ($rpackets - $old_rpackets) / $tdiff;
        my $wpps = ($wpackets - $old_wpackets) / $tdiff;
        my $ravs = $rpps > 0 ? $rbps / $rpps : 0;
        my $wavs = $wpps > 0 ? $wbps / $wpps : 0;

        # skip zero lines if asked
        next if $SKIPZERO and ($rbps + $wbps) == 0;

        # % utilisation
        my $util;
        if ($speed > 0) {
            # the following has a mysterious "800", it is 100
            # for the % conversion, and 8 for bytes2bits.
            $util = ($rbps + $wbps) * 800 / $speed;
            $util = 100 if $util > 100;
        }
        else {
            $util = 0;
        }

        # saturation per sec
        my $sats = ($sat - $old_sat) / $tdiff;

        #
        #  Print statistics
        #
        if ($rbps ne "") {
            my @Time = localtime();

            if ($STYLE == 0) {
                printf "%02d:%02d:%02d %7s ",
                       $Time[2], $Time[1], $Time[0], $int;
                print_neat($rkps);
                print_neat($wkps);
                print_neat($rpps);
                print_neat($wpps);
                print_neat($ravs);
                print_neat($wavs);
                printf "%7.2f %6.2f\n", $util, $sats;
            }
            elsif ($STYLE == 1) {
                printf "%02d:%02d:%02d %8s %14.3f %14.3f\n",
                       $Time[2], $Time[1], $Time[0], $int, $rkps, $wkps;
            }

            $line++;

            # for multiple interfaces, always print the header
            $line += $PAGESIZE if @NetworkData > 1;
        }

        ### Store old values
        $NetworkDataOld{$int}
            = "$rbytes:$wbytes:$rpackets:$wpackets:$sat:$time";
    }

    ### Check for end
    last if ++$loop == $loop_max;

    ### Interval
    sleep $interval;
}


# fetch - fetch Kstat data for the network interfaces.
#
# This uses the interfaces in %NetworkNames and returns useful Kstat data.
# The Kstat values used are rbytes64, obytes64, ipackets64, opackets64
# (or the 32 bit versions if the 64 bit values are not there).
#
sub fetch_net_data {
    my ($rbytes, $wbytes, $rpackets, $wpackets, $speed, $time);

     my @NetworkData = ();

    my $ifs_rawz = `ifconfig -a | grep : | grep -v lo0 `;
    my @ifs_raw = split /\n/, $ifs_rawz;

    #
    # run a kstat system call here and populate a hash
    #
    my %kstat = ();
    my $kstat_raw = "";

    foreach my $ifz (@ifs_raw)
    {
        my ($if, undef) = split /:/, $ifz;
        chop $if;
        $kstat_raw   .= `kstat -p \'${if}:\'`;
        my @kstat_lines = split /\n/, $kstat_raw;

        foreach my $line (@kstat_lines)
        {
            next if $line =~ /^$/;

            my ($raw_stat, $stat_value) = split /\s+/, $line;
            my (undef, undef, $if_name, $stat_name) = split /:/, $raw_stat;

            if ($if_name =~ /$if/)
            {
                $kstat{$if_name}{$stat_name} = $stat_value;
            }
        }

    }

    ### Loop over previously found network interfaces
    foreach my $name (keys %kstat) {

        if (defined $kstat{$name}{opackets}) {

            ### Fetch write bytes
            if (defined $kstat{$name}{obytes64}) {
                $rbytes = $kstat{$name}{rbytes64};
                $wbytes = $kstat{$name}{obytes64};
            }
            elsif (defined $kstat{$name}{obytes}) {
                $rbytes = $kstat{$name}{rbytes};
                $wbytes = $kstat{$name}{obytes};
            } else {
                $rbytes = $wbytes = 0;
            }

            ### Fetch read bytes
            if (defined $kstat{$name}{opackets64}) {
                $rpackets = $kstat{$name}{ipackets64};
                $wpackets = $kstat{$name}{opackets64};
            }
            else {
                $rpackets = $kstat{$name}{ipackets};
                $wpackets = $kstat{$name}{opackets};
            }

            ### Fetch interface speed
            if (defined $kstat{$name}{ifspeed}) {
                $speed = $kstat{$name}{ifspeed};
            }
            else {
                # if we can't fetch the speed, print the
                # %Util as 0.0 . To do this we,
                $speed = 2 ** 48;
            }

            ### Determine saturation value
            my $sat = 0;
            if (defined $kstat{$name}{nocanput} or defined $kstat{$name}{norcvbuf}) {
                $sat += defined $kstat{$name}{defer} ? $kstat{$name}{defer} : 0;
                $sat += defined $kstat{$name}{nocanput} ? $kstat{$name}{nocanput} : 0;
                $sat += defined $kstat{$name}{norcvbuf} ? $kstat{$name}{norcvbuf} : 0;
                $sat += defined $kstat{$name}{noxmtbuf} ? $kstat{$name}{noxmtbuf} : 0;
            }

            ### use the last snaptime value,
            $time = $kstat{$name}{snaptime};

            ### store data
            push @NetworkData, "$name:$rbytes:$wbytes:" .
             "$rpackets:$wpackets:$speed:$sat:$time";
        }
    }

    return @NetworkData;
}

# print_neat - print a float with decimal places if appropriate.
#
# This specifically keeps the width to 7 characters, if possible, plus
# a trailing space.
#
sub print_neat {
    my $num = shift;
    if ($num >= 100000) {
        printf "%7d ", $num;
    } elsif ($num >= 100) {
        printf "%7.1f ", $num;
    } else {
        printf "%7.2f ", $num;
    }
}

# usage - print usage and exit.
#
sub usage {
        print STDERR <<END;
USAGE: nicstat [-hsz] [-i int[,int...]] | [interval [count]]
   eg, nicstat               # print summary since boot
       nicstat 1             # print continually every 1 second
       nicstat 1 5           # print 5 times, every 1 second
       nicstat -s            # summary output
       nicstat -i hme0       # print hme0 only
END
        exit 1;
}
