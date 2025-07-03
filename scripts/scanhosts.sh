#!/usr/bin/env bash
########################################################################
# IndianZ Hosts Scanner                                                #
# Version 1.2 created 2014-08-19 18:00 (GMT+1)                         #
# https://www.indianz.ch/ - indianz<at>indianz<dot>ch                  #
########################################################################
# This program is free software: you can redistribute it and/or modify #
# it under the terms of the GNU General Public License as published by #
# the Free Software Foundation, either version 3 of the License, or    #
# (at your option) any later version. This program is distributed in   #
# the hope that it will be useful, but WITHOUT ANY WARRANTY; without   #
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A        #
# PARTICULAR PURPOSE. See the GNU General Public License for more      #
# details: http://www.gnu.org/licenses/                                #
########################################################################
# Description: This is a host scanner which will deliver a result      #
# directory with basic information gathering about protocols (tcp/ip), #
# ports (tcp/udp), services and vulnerabilities of a single host.      #
# Running time about 20-60 minutes, depending on responsiveness        #
# of target and network conditions. Have fun ;)                        # 
########################################################################
# Tools used: echo, ps, grep, which, tee, date, sleep, ifconfig, curl, #
# nmap, nessus, nessusd, nessus-update-plugins, wget, tar, chmod, kill,#
# mkdir, sed, mv, rm                                                   #
########################################################################
# Tested with Bash 4.2.x on Arch Linux 3.7.9-2-ARCH x86_64 GNU/Linux   #
########################################################################

# configuration to edit
VERSION=1.2
YOURUSER=username
NETINTFACE=eth0
NESSUSHOST=localhost
NESSUSUSER=user
NESSUSPASS=pass
NESSUSPORT=1241
OPENVASHOST=localhost
OPENVASUSER=user
OPENVASPASS=pass
OPENVASPORT=9391
LOG=scanhosts.txt

########################################################################
#           there should be no need to edit below this line            #
#              except to improve this script of course ;)              #
########################################################################

# check and set path to echo
ECHO=`which echo`

# usage help function
function Banner()
{
$ECHO
$ECHO "        _..__.          .__.._"
$ECHO "       .^-.._ '-(\__/)-' _..-^."
$ECHO "             '-.' oo '.-'"
$ECHO "                '-..-'"
$ECHO
$ECHO "     IndianZ Hosts Scanner" $VERSION 
$ECHO
}

# check root permissions
if [[ $EUID -ne 0 ]]; then
  Banner
  $ECHO
  $ECHO "[!] not root: please use sudo"
  $ECHO
  exit 1
fi

# check and set paths to tools
PS=`which ps`
GREP=`which grep`
TEE=`which tee`
DATE=`which date`
SLEEP=`which sleep`
PRINTF=`which printf`
IP=`which ip`
ROUTE=`which route`
CURL=`which curl`
TCPDUMP=`which tcpdump`
NMAP=`which nmap`
AMAP=`which amap`
NESSUS=`which nessus`
NESSUSSERVICE=`which nessus-service`
NESSUSSYNS=`which nessus-update-plugins`
KILL=`which kill`
MKDIR=`which mkdir`
WGET=`which wget`
SED=`which sed`
MV=`which mv`
RM=`which rm`
TAR=`which tar`
CHMOD=`which chmod`

# check if nessusd is running
$PS aux | $GREP -v grep | $GREP nessusd > /dev/nul
if [ $? -ne 0 ]
then
	Banner
	$ECHO
	$ECHO "[!] Nessusd is not running!"
	$ECHO
	$ECHO "[i] starting nessusd now." 
	$ECHO
	$NESSUSSERVICE -D
	$ECHO
	$ECHO "[i] updating nessus" 
	$ECHO
	$NESSUSSYNC
else
	$ECHO
	$ECHO "[i] Nessusd is running, cool!" 
	$ECHO
	$ECHO
	$ECHO "[i] updating nessus" 
	$ECHO
	$NESSUSSYNC
fi

# check if targets.txt is existing, exit if not
if [ -f targets.txt ]
then
    $ECHO
    $ECHO "[!] targets.txt found, cool!"
else
    Banner
	$ECHO
	$ECHO "[!] targets.txt is missing!"
	$ECHO
	$ECHO "[i] please create targets.txt, 1 IP per line" 
	$ECHO
	exit 1
fi

# define needed variables
PROTS=1,4,6,17,41
PORTSTCP=1,7,8,11,13,15,19,20,21,22,23,25,26,37,42,43,53,79,80,81,88,98,106,109,110,111,113,119,135,137,138,139,143,144,179,199,264,389,427,443,444,445,464,465,512,513,514,515,540,543,544,548,554,587,593,631,636,646,706,873,900,993,994,995,1025,1026,1027,1028,1029,1080,1110,1234,1241,1352,1433,1434,1494,1521,1526,1541,1701,1720,1723,1755,1900,1999,2000,2001,2049,2121,2301,2381,2401,2433,2638,2717,3128,3286,3269,3306,3372,3389,4110,4242,4321,4430,4444,4480,5000,5222,5432,5631,5632,5723,5724,5800,5900,6000,6001,6002,6103,6112,6588,6666,6667,7001,7002,7070,7100,8000,8001,8005,8008,8010,8080,8088,8100,8443,8531,8800,8843,8880,8888,8890,9090,9100,9391,9999,10000,10001,12001,32768,33333,49152,49153,49154,49155,49156,49157,65535
PORTSUDP=1,7,8,9,11,15,17,19,49,53,67,68,69,80,88,111,120,123,135,136,137,138,139,158,161-162,177,427,443,445,497,500,513,514,515,518,520,593,623,626,631,996-999,1022-1023,1025-1030,1194,1433,1434,1645,1646,1701,1718,1719,1812,1813,1900,2000,2048,2049,2222,2223,3283,3456,3703,4045,4444,4500,5000,5020,5060,5353,5632,9200,10000,17185,20031,30718,31337,32768,32769,32771,32815,33281,49152,49153,49154,49156,49181,49182,49185,49186,49188,49190,49191,49192,49193,49194,49200,49201,65024,65535

# backup of port lists
#PROTS=1,4,6,17,41
#PORTSTCP=1,7,8,11,13,15,19,20,21,22,23,25,26,37,42,43,53,79,80,81,88,98,106,109,110,111,113,119,135,137,138,139,143,144,179,199,264,389,427,443,444,445,464,465,512,513,514,515,540,543,544,548,554,587,593,631,636,646,706,873,900,993,994,995,1025,1026,1027,1028,1029,1080,1110,1234,1241,1352,1433,1434,1494,1521,1526,1541,1701,1720,1723,1755,1900,1999,2000,2001,2049,2121,2301,2381,2401,2433,2638,2717,3128,3286,3269,3306,3372,3389,4110,4242,4321,4430,4444,4480,5000,5222,5432,5631,5632,5723,5724,5800,5900,6000,6001,6002,6103,6112,6588,6666,6667,7001,7002,7070,7100,8000,8001,8005,8008,8010,8080,8088,8100,8443,8531,8800,8843,8880,8888,8890,9090,9100,9391,9999,10000,10001,12001,32768,33333,49152,49153,49154,49155,49156,49157,65535
#PORTSUDP=1,7,8,9,11,15,17,19,49,53,67,68,69,80,88,111,120,123,135,136,137,138,139,158,161-162,177,427,443,445,497,500,513,514,515,518,520,593,623,626,631,996-999,1022-1023,1025-1030,1194,1433,1434,1645,1646,1701,1718,1719,1812,1813,1900,2000,2048,2049,2222,2223,3283,3456,3703,4045,4444,4500,5000,5020,5060,5353,5632,9200,10000,17185,20031,30718,31337,32768,32769,32771,32815,33281,49152,49153,49154,49156,49181,49182,49185,49186,49188,49190,49191,49192,49193,49194,49200,49201,65024,65535

# log starting time
$ECHO "record time"
$DATE 2>&1
$ECHO

# show and record banner
Banner | $TEE -a $LOG

# log infos
$ECHO | $TEE -a $LOG
$ECHO "[i] record ip/route" | $TEE -a $LOG
$IP addr show $NETINTERFACE 2>&1 | $TEE -a $LOG
$ECHO | $TEE -a $LOG
$IP route list 2>&1 | $TEE -a $LOG
$ECHO | $TEE -a $LOG
$ECHO "[i] tester ip (public internet)" | $TEE -a $LOG
$CURL https://www.indianz.ch/ip.php 2>&1 | $TEE -a $LOG
$ECHO | $TEE -a $LOG

# start tcpdump
$ECHO "[i] starting tcpdump" | $TEE -a $LOG
$ECHO | $TEE -a $LOG
$TCPDUMP -i $NETINTFACE -n -s0 -w scanhosts_scanhosts.dump host $1 & dumppid=$!
$ECHO | $TEE -a $LOG
$SLEEP 3

# nmap: protocol scan 
$ECHO "[i] nmap protocols" | $TEE -a $LOG
$ECHO | $TEE -a $LOG
$NMAP -sO -T3 -P0 -e $NETINTFACE -oX scanhosts_nmap_protocols.xml -p $PROTS -n -vvv -iL targets.txt 2>&1 | $TEE -a $LOG
$ECHO | $TEE -a $LOG

# nmap: portscan tcp/udp redux
$ECHO "[i] nmap tcp/udp scan redux" | $TEE -a $LOG
$ECHO | $TEE -a $LOG
$NMAP -sSU -e $NETINTFACE -T3 -P0 -O --reason --open -n -vvv -oA scanhosts_nmap_redux -p T:$PORTSTCP,U:$PORTSUDP -iL targets.txt 2>&1 | $TEE -a $LOG
$ECHO | $TEE -a $LOG

# nmap: portscan tcp full
$ECHO "[i] nmap tcp scan full" | $TEE -a $LOG
$ECHO | $TEE -a $LOG
$NMAP -sSV -e $NETINTFACE -T3 -P0 -O -A --reason --open --script=safe -n -vvv -p- -oX scanhosts_nmap_scan_tcp_full.xml -iL targets.txt 2>&1 | $TEE -a $LOG
$ECHO | $TEE -a $LOG

# nmap: portscan udp top 100
$ECHO "[i] nmap udp scan top 100" | $TEE -a $LOG
$ECHO | $TEE -a $LOG
$NMAP -sUV -e $NETINTFACE -T3 -P0 -O --reason --open -n -vvv --top-ports 100 -oX scanhosts_nmap_scan_udp_reduced.xml -iL targets.txt 2>&1 | $TEE -a $LOG
$ECHO | $TEE -a $LOG

# amap: application mapping
$ECHO "[i] amap appmapping" | $TEE -a $LOG
$ECHO | $TEE -a $LOG
$AMAP -AbqH -C 1 -T 1 -c 1 -i scanhosts_nmap_redux.gnmap -o amap.out -m 2>&1 | $TEE -a $LOG
$ECHO | $TEE -a $LOG

# nessus: vulnerability scan
$ECHO "[i] nessus scan" | $TEE -a $LOG
$ECHO | $TEE -a $LOG
$PRINTF $1 > target.txt | $TEE -a $LOG
$NESSUS -V -T nbe -x -c nessus.config -q $NESSUSHOST $NESSUSPORT $NESSUSUSER $NESSUSPASS targets.txt scanhosts_nessus.nbe 2>&1 | $TEE -a $LOG
$ECHO | $TEE -a $LOG

# stop tcpdump
$ECHO "[i] stopping tcpdump" | $TEE -a $LOG
$ECHO | $TEE -a $LOG 
$KILL $dumppid 2>&1 | $TEE -a $LOG
$SLEEP 3
$SYNC

# log stopping time
$ECHO "[i] record time" | $TEE -a $LOG
$DATE 2>&1 | $TEE -a $LOG
STOPTIME=`$DATE` | $TEE -a $LOG
$ECHO | $TEE -a $LOG

# download nmap stylesheet
read -p "[?] download latest nmap.xsl from svn? (Yy/Nn) " answer
while true
do
  case $answer in
   [Yy]* ) $WGET http://nmap.org/svn/docs/nmap.xsl
           $ECHO "[i] downloading nmap.xsl"
           break;;

   [Nn]* ) $ECHO "[i] not downloading nmap.xsl"
           exit;;

   * )     $ECHO "[!] please enter either Yy or Nn"; break ;;
  esac
done

# cleaning and sorting results
$ECHO "[i] cleaning up"
$ECHO
$MKDIR scanhosts_`$DATE +%Y%m%d`
$SED -i 's/http:\/\/nmap.org\/svn\/docs\/nmap.xsl/nmap.xsl/g' *.xml
$SED -i 's/file:\/\/\/usr\/share\/nmap\/nmap.xsl/nmap.xsl/g' *.xml
$SED -i 's/file:\/\/\/usr\/bin\/..\/share\/nmap\/nmap.xsl/nmap.xsl/g' *.xml
$RM -f nmap*.*nmap
$MV scanhosts_nmap*.* scanhosts_`$DATE +%Y%m%d`/
$MV nmap.xsl scanhosts_`$DATE +%Y%m%d`/
$MV amap.out scanhosts_`$DATE +%Y%m%d`/
$MV targets.txt scanhosts_`$DATE +%Y%m%d`/
$RM -f nessus.config
$MV scanhosts_nessus* scanhosts_`$DATE +%Y%m%d`/
$TAR -cjf scanhosts_dump.tgz scanhosts.dump
$RM -f scanhosts.dump
$MV scanhosts_dump.tgz scanhosts_`$DATE +%Y%m%d`/

# set permissions
$ECHO
$ECHO "[i] setting permissions"
$CHOWN -R $YOURUSER:users scanhosts_`$DATE +%Y%m%d`/
$CHMOD -R 770 scanhosts_`$DATE +%Y%m%d`/

# print final message
Banner
$ECHO
$ECHO "[i] please find the results and the network dump in scanhosts_`$DATE +%Y%m%d`/ directory"
$ECHO "[i] and have a nice day ;)"
$ECHO

# exit correctly :p
exit 0