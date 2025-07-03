#!/usr/bin/env ruby
# coding: utf-8
########################################################################
# IndianZ TCP Port Checker                                             #
# Version 1.6 created 2014-08-29 15:00 (GMT+1)                         #
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
# Description: Automatisation of simple single tcp port checking,      #
# only needs ruby (socket, timeout, openssl, resolv) and linux file    #
# /etc/services. Output can be redirected to a txt-file ;)..           #
########################################################################
# Functionality:                                                       #
# - checks if service is found in /etc/services                        #
# - checks if port is open (portscan)                                  #
# - grabs the banner (if available)                                    #
# - checks ftp anonymous (port 21)                                     #
# - checks ftps anonymous and ssl info (port 990)                      #
# - enumerates some users smtp vrfy (port 25/587)                      #
#   (root, postmaster, administrator, abuse, info)                     #
# - checks for smtp relay (port 25/587)                                #
# - gets http methods (port 80)                                        #
# - get http (port 80)                                                 #
# - gets https methods and ssl info (port 443)                         #
# - get https (port 443)                                               #
# - finger root (port 79)                                              #
# - show security hints for 69 ports < 1024:                           #
#   0, 1, 7, 8, 9, 11, 13, 15, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, #
#   67, 68, 69, 70, 79, 80, 88, 98, 109, 110, 111, 113, 119, 135, 137, #
#   138, 139, 143, 173, 199, 222, 264, 389, 423, 443, 445, 464, 465,   #
#   512, 513, 514, 515, 540, 543, 544, 548, 554, 567, 587, 593, 631,   #
#   636, 666, 706, 777, 873, 989, 990, 993, 994, 995                   #
########################################################################
# Tested with Ruby 1.9.3 on Arch Linux 3.16.1-1-ARCH x86_64 GNU/Linux  #
########################################################################

# define version variable
@version = '1.6'

# define ruby requirements
require 'socket'
require 'timeout'
require 'openssl'
require 'resolv'

# define banner
def banner
  begin
  print("\n")
  print("  _..__.          .__.._\n")
  print(" .^-.._ '-(\\__/)-' _..-^.\n")
  print("       '-.' oo '.-'\n")
  print("          '-..-'\n")
  print("\n")
  print("IndianZ TCP Port Checker " + @version + "\n")
  print("\n")
  end
end

# check for root permissions
unless Process.uid == 0
banner()
print("Root permissions required for #{$0}!\n")
print("\n")
exit(1)
end

# check for command line arguments
unless ARGV.length == 2
banner()
print("Two Arguments required, usage: #{$0} host port\n\n")
print("\n")
exit(1)
end

# define needed variables
@host = Resolv.getaddress(ARGV[0])
@port = ARGV[1]
# freeze prevents modifications of object @ports (65 ports < 1024)
@ports = [ 0, 1, 7, 8, 9, 11, 13, 15, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 67, 68, 69, 70, 79, 80, 88, 98, 109, 110, 111, 113, 119, 135, 137, 138, 139, 143, 173, 199, 222, 264, 389, 423, 443, 445, 464, 465, 512, 513, 514, 515, 540, 543, 544, 548, 554, 567, 587, 593, 631, 636, 666, 706, 777, 873, 989, 990, 993, 994, 995 ].freeze

# show banner
banner()
print("\n")

# show start time
time = Time.new
puts time.strftime("Start %Y-%m-%d %H:%M:%S")

# define method portcheck (checks if port is registered service)
def portcheck
  begin
    a = nil
    print("\n")
    print("Port ", @port, " tcp is registered as...\n")
    a = IO.readlines('/etc/services')
    puts a.grep(/ #{@port}\/tcp/)
    print("\n")
  rescue => e
    puts e.message
  end
end

# define method portscan (scans if port is open)
def portscan
  begin
  print("Connecting to host ", @host, " port tcp ", @port, "...\n")
  timeout(5) do
  TCPSocket.open(@host, @port)
  end
  print("Port tcp ", @port, " on host ", @host, " is open ;)\n\n")
  rescue Timeout::Error
    print("Timeout on port tcp ", @port, "...\n\n")
      failed()
  rescue Errno::ECONNREFUSED
    print("Port tcp ", @port, " on host ", @host, " is closed...\n\n")
      failed()
  end
end

# define method bannergrab (grabs banner from port)
def bannergrab
  begin
    s = nil
    print("Checking banner on host ", @host, " port tcp ", @port, "...\n")
    timeout(5) do
    s = TCPSocket.open(@host, @port)
    print(s.recv(1024), "\n")
    end
    rescue Timeout::Error
      print("Timeout on port tcp ", @port, "...\n\n")
      failed()
    rescue Errno::ECONNREFUSED
      print("[!] Bannergrab failed...\n\n")
      failed()
  end
end

# define method ftp anon (checks anonymous logon over ftp)
def ftpanon
  begin
    s = nil
    print("Checking ftp on host ", @host, " port tcp ", @port, "...\n")
    timeout(5) do
    s = TCPSocket.open(@host, @port)
    print(s.recv(1024))
    print("USER anonymous\n")
    s.write("USER anonymous\r\n")
    print(s.recv(1024))
    print("PASS none@none.net root\n")
    s.write("PASS none@none.net\r\n")
    print(s.recv(1024))
    print("ls\n")
    s.write("ls\r\n")
    print(s.recv(1024), "\n")
    end
    rescue Timeout::Error
      print("Timeout on port tcp ", @port, "...\n\n")
      failed()
    rescue Errno::ECONNREFUSED
      print("Anonymous ftp failed...\n\n")
      failed()
  end
end

# define method ftps anon (checks anonymous logon over ftps)
def ftpsanon
  begin
    sock = nil
    ssl = nil
    print("Checking ftps on host ", @host, " port tcp ", @port, "...\n")
    timeout(5) do
    sock = TCPSocket.new(@host, @port)
    context = OpenSSL::SSL::SSLContext.new('SSLv23_client')
    ssl = OpenSSL::SSL::SSLSocket.new(sock, context)
    ssl.connect
    print(ssl.cipher, "\n")
    print(ssl.peer_cert, "\n")
    print(s.recv(1024))
    print("USER anonymous\n")
    s.write("USER anonymous\r\n")
    print(s.recv(1024))
    print("PASS none@none.net root\n")
    s.write("PASS none@none.net\r\n")
    print(s.recv(1024))
    print("ls\n")
    s.write("ls\r\n")
    print(s.recv(1024), "\n")
    end
    rescue Timeout::Error
      print("Timeout on port tcp ", @port, "...\n\n")
      failed()
    rescue Errno::ECONNREFUSED
      print("Anonymous ftps failed...\n\n")
      failed()
  end
end

# define method smtp relay (tries to relay over smtp)
def smtprelay
  begin
    s = nil
    print("Checking smtp on host ", @host, " port tcp ", @port, "...\n")
    timeout(5) do
    s = TCPSocket.open(@host, @port)
    print(s.recv(1024), "\n")
    print("mail from:none@none.net\n")
    s.write("mail from:none@none.net\r\n")
    print(s.recv(1024), "\n")
    print("rcpt to:none@none.net\n")
    s.write("rcpt to:none@none.net\r\n")
    print(s.recv(1024), "\n")
    print("data\n")
    s.write("data\r\n")
    print(s.recv(1024), "\n")
    print(".\n")
    s.write(".\r\n")
    print(s.recv(1024), "\n")
    end
    rescue Timeout::Error
      print("Timeout on port tcp ", @port, "...\n\n")
      failed()
    rescue Errno::ECONNREFUSED
      print("Smtp relay failed...\n\n")
      failed()
  end
end

# define method smtpvrfy (verifies some user names over smtp)
def smtpvrfy
  begin
    s = nil
    print("Checking smtp on host ", @host, " port tcp ", @port, "...\n")
    timeout(5) do
    s = TCPSocket.open(@host, @port)
    print(s.recv(1024), "\n")
    print("vrfy root\n")
    s.write("vrfy root\r\n")
    print(s.recv(1024), "\n")
    print("vrfy postmaster\n")
    s.write("vrfy postmaster\r\n")
    print(s.recv(1024), "\n")
    print("vrfy administrator\n")
    s.write("vrfy administrator\r\n")
    print(s.recv(1024), "\n")
    print("vrfy abuse\n")
    s.write("vrfy abuse\r\n")
    print(s.recv(1024), "\n")
    print("vrfy info\n")
    s.write("vrfy info\r\n")
    print(s.recv(1024), "\n")
    end
    rescue Timeout::Error
      print("Timeout on port tcp ", @port, "...\n\n")
      failed()
    rescue Errno::ECONNREFUSED
      print("Smtp vrfy failed...\n\n")
      failed()
  end
end

# define method httpopts (gets methods over http)
def httpopts
  begin
    s = nil
    print("Checking http methods on host ", @host, " port tcp ", @port, "...\n\n")
    timeout(5) do
    s = TCPSocket.open(@host, @port)
    print("OPTIONS * HTTP/1.0\n")
    s.write("OPTIONS * HTTP/1.0\n\n")
    print(s.read)
    print("\n")
    end
    rescue Timeout::Error
      print("Timeout on port tcp ", @port, "...\n\n")
      failed()
    rescue Errno::ECONNREFUSED
      print("Http methods failed...\n\n")
      failed()
  end
end

# define method httpget (get over http)
def httpget
  begin
    s = nil
    print("Getting http from host ", @host, " port tcp ", @port, "...\n\n")
    timeout(5) do
    s = TCPSocket.open(@host, @port)
    print("GET / HTTP/1.0\n")
    s.write("GET / HTTP/1.0\n\n")
    print(s.read)
    print("\n")
    end
    rescue Timeout::Error
      print("Timeout on port tcp ", @port, "...\n\n")
      failed()
    rescue Errno::ECONNREFUSED
      print("Http get failed...\n\n")
      failed()
  end
end

# define method httpsopts (gets methods over https)
def httpsopts
  begin
    sock = nil
    ssl = nil
    print("Checking https on host ", @host, " port tcp ", @port, "...\n\n")
    timeout(5) do
    sock = TCPSocket.new(@host, @port)
    context = OpenSSL::SSL::SSLContext.new('SSLv23_client')
    ssl = OpenSSL::SSL::SSLSocket.new(sock, context)
    ssl.connect
    print(ssl.cipher, "\n")
    print(ssl.peer_cert, "\n")
    print("OPTIONS * HTTP/1.0\n")
    ssl.write("OPTIONS * HTTP/1.0\n\n")
    print(ssl.read)
    print("\n")
    end
    rescue Timeout::Error
      print("Timeout on port tcp ", @port, "...\n\n")
      failed()
    rescue Errno::ECONNREFUSED
      print("Https methods failed...\n\n")
      failed()
  end
end

# define method httpsget (get over https)
def httpsget
  begin
    sock = nil
    ssl = nil
    print("Getting https from host ", @host, " port tcp ", @port, "...\n\n")
    timeout(5) do
    sock = TCPSocket.new(@host, @port)
    context = OpenSSL::SSL::SSLContext.new('SSLv23_client')
    ssl = OpenSSL::SSL::SSLSocket.new(sock, context)
    ssl.connect
    print(ssl.cipher, "\n")
    print(ssl.peer_cert, "\n")
    print("GET / HTTP/1.0\n")
    ssl.write("GET / HTTP/1.0\n\n")
    print(ssl.read)
    print("\n")
    end
    rescue Timeout::Error
      print("Timeout on port tcp ", @port, "...\n\n")
      failed()
    rescue Errno::ECONNREFUSED
      print("Https get failed...\n\n")
      failed()
  end
end

# define method finger
def finger
  begin
    sock = nil
    ssl = nil
    print("finger root on host ", @host, " port tcp ", @port, "...\n\n")
    timeout(5) do
    sock = TCPSocket.new(@host, @port)    
    print("finger root\n")
    sock.write("finger root\n\n")
    print(sock.read)
    print("\n")
    end
    rescue Timeout::Error
      print("Timeout on port tcp ", @port, "...\n\n")
      failed()
    rescue Errno::ECONNREFUSED
      print("Finger get failed...\n\n")
      failed()
  end
end

# define method failed (early exit on errors)
def failed
  begin
    time = Time.new
    puts time.strftime("Stop %Y-%m-%d %H:%M:%S")
    print("\n")
    print("Portchecker failed!\n\n")
    exit(1)
  end
end

# case condition for the supported ports ;)
case
  when @port == "0"
  portcheck()
  portscan()
  print("Security hints port tcp 0: RESERVED\n")
  print("unusual port, try to interact\n\n")
  when @port == "1"
  portcheck()
  portscan()
  print("Security hints port tcp 1: TCPMUX\n")
  print("unusual port, try to interact\n\n")
  when @port == "7"
  portcheck()
  portscan()
  print("Security hints port tcp 7: ECHO\n")
  print("echo can, in conjunction with chargen, generate DoS condition\n")
  print("do simple tcp/ip services really need to run?\n\n")
  when @port == "8"
  portcheck()
  portscan()
  print("Security hints port tcp 8: UNASSIGNED\n")
  print("unusual port, check for http access, try to interact\n\n")
  when @port == "9"
  portcheck()
  portscan()
  print("Security hints port tcp 9: DISCARD\n")
  print("do simple tcp/ip services really need to run?\n\n")
  when @port == "11"
  portcheck()
  portscan()
  print("Security hints port tcp 11: SYSTAT\n")
  print("try to enumerate user, host and network information\n\n")
  when @port == "13"
  portcheck()
  portscan()
  print("Security hints port tcp 13: DAYTIME\n")
  print("do simple tcp/ip services really need to run?\n\n")
  when @port == "15"
  portcheck()
  portscan()
  print("Security hints port tcp 15: NETSTAT\n")
  print("try to enumerate user, host and network information\n\n")
  when @port == "19"
  portcheck()
  portscan()
  print("Security hints port tcp 19: CHARGEN\n")
  print("chargen can, in conjunction with echo, generate DoS condition\n")
  print("do simple tcp/ip services really need to run?\n\n")
  when @port == "20"
  portcheck()
  portscan()
  print("Security hints port tcp 20: FTP-DATA\n")
  print("unusual port, spoof source port for firewall passing\n\n")
  when @port == "21"
  portcheck()
  portscan()
  ftpanon()
  print("Security hints port tcp 21: FTP\n")
  print("cleartext protocol, check auth, sniff password\n")
  print("check anonymous write access (if anonymous login successful)\n")
  print("may try to bruteforce, may try to fuzz daemon\n\n")
  when @port == "22"
  portcheck()
  portscan()
  bannergrab()
  print("Security hints port tcp 22: SSH\n")
  print("check ssh version and protocols (1.x)\n")
  print("may try to bruteforce with hydra\n\n")
  when @port == "23"
  portcheck()
  portscan()
  bannergrab()
  print("Security hints port tcp 23: TELNET\n")
  print("cleartext protocol, check auth, sniff password\n")
  print("may try to bruteforce with hydra\n\n")
  when @port == "25"
  portcheck()
  portscan()
  bannergrab()
  smtpvrfy()
  smtprelay()
  print("Security hints port tcp 25: SMTP\n")
  print("smtp vrfy/relay, spoof source port for firewall passing\n\n")
  when @port == "37"
  portcheck()
  portscan()
  print("Security hints port tcp 37: TIME\n")
  print("does time really need to run?\n\n")
  when @port == "42"
  portcheck()
  portscan()
  print("Security hints port tcp 42: NAME\n")
  print("try to use name\n\n")
  when @port == "43"
  portcheck()
  portscan()
  print("Security hints port tcp 43: WHOIS\n")
  print("try to use whois\n\n")
  when @port == "53"
  portcheck()
  portscan()
  print("Security hints port tcp 53: DNS\n")
  print("try to use dns, try full zone transfer (axfr)\n")
  print("spoof source port for firewall passing\n\n")
  when @port == "67"
  portcheck()
  portscan()
  print("Security hints port tcp 67: BOOTP\n")
  print("try to use bootp\n\n")
  when @port == "68"
  portcheck()
  portscan()
  print("Security hints port tcp 68: BOOTPC\n")
  print("try to use dhcp client\n\n")
    when @port == "69"
  portcheck()
  portscan()
  print("Security hints port tcp 69: TFTP\n")
  print("try to use tftp client\n\n")
  when @port == "70"
  portcheck()
  portscan()
  print("Security hints port tcp 70: GOPHER\n")
  print("try to use gopher (old http-alike)\n\n")
  when @port == "79"
  portcheck()
  portscan()
  finger()
  print("Security hints port tcp 79: FINGER\n")
  print("try to use finger to enumerate users\n\n")
  when @port == "80"
  portcheck()
  portscan()
  httpopts()
  httpget()
  print("Security hints port tcp 80: HTTP\n")
  print("check auth, robots.txt, dir trav, file incl, code exec\n")
  print("search injection points for xss and sql in forms/url\n")
  print("trace may allow for xst if xss possible\n")
  print("may try to bruteforce with hydra\n\n")
  when @port == "88"
  portcheck()
  portscan()
  print("Security hints port tcp 88: KERBEROS\n")
  print("try to use kerberos\n\n")
  when @port == "98"
  portcheck()
  portscan()
  print("Security hints port tcp 98: TACNEWS\n")
  print("malformed request may result in DoS condition\n\n")
  when @port == "109"
  portcheck()
  portscan()
  print("Security hints port tcp 109: POP2\n")
  print("try to enumerate users, may try to bruteforce with hydra\n\n")
  when @port == "110"
  portcheck()
  portscan()
  bannergrab()
  print("Security hints port tcp 110: POP3\n")
  print("try to enumerate users, may try to bruteforce with hydra\n\n")
  when @port == "111"
  portcheck()
  portscan()
  print("Security hints port tcp 111: RPC\n")
  print("try to use rpcinfo (linux/unix) or dcetest (windows)\n\n")
  when @port == "113"
  portcheck()
  portscan()
  print("Security hints port tcp 113: IDENT/AUTH\n")
  print("provides system/auth information for services\n\n")
  when @port == "119"
  portcheck()
  portscan()
  print("Security hints port tcp 119: NNTP\n")
  print("try to use nntp client\n\n")
  when @port == "135"
  portcheck()
  portscan()
  print("Security hints port tcp 135: MSRPC\n")
  print("try high range rpc ports, try to use epdump.exe\n\n")
  when @port == "137"
  portcheck()
  portscan()
  print("Security hints port tcp 137: NETBIOS-NS\n")
  print("check auth, try null session\n")
  print("try to use nbtscan/smbclient\n\n")
  when @port == "138"
  portcheck()
  portscan()
  print("Security hints port tcp 138: NETBIOS-DGN\n")
  print("check auth, try null session\n")
  print("try to use nbtscan/smbclient\n\n")
  when @port == "139"
  portcheck()
  portscan()
  print("Security hints port tcp 139: NETBIOS-SSN\n")
  print("check auth, try null session\n")
  print("try to use nbtscan/smbclient\n\n")
  when @port == "143"
  portcheck()
  portscan()
  print("Security hints port tcp 143: IMAP\n")
  print("try to enumerate users, may try to bruteforce with hydra\n\n")
  when @port == "173"
  portcheck()
  portscan()
  print("Security hints port tcp 173: BGP\n")
  print("try to speak bgp\n\n")
  when @port == "199"
  portcheck()
  portscan()
  print("Security hints port tcp 199: SMUX\n")
  print("linux snmp port, try to use snmpwalk\n\n")
  when @port == "222"
  portcheck()
  portscan()
  bannergrab()
  print("Security hints port tcp 222: RSH-SPX\n")
  print("unusual port, try to interact\n\n")
  when @port == "264"
  portcheck()
  portscan()
  print("Security hints port tcp 264: BGMP/CHECKPOINT TOPO\n")
  print("try to interact with bgmp or checkpoint\n\n")
  when @port == "389"
  portcheck()
  portscan()
  print("Security hints port tcp 389: LDAP\n")
  print("check auth, try to enumerate ldap\n\n")
  when @port == "423"
  portcheck()
  portscan()
  print("Security hints port tcp 423: BONJOUR\n")
  print("this is the apple bonjour port\n\n")
  when @port == "443"
  portcheck()
  portscan()
  httpsopts()
  httpsget()
  print("Security hints port tcp 443: HTTPS\n")
  print("check auth, robots.txt, dir trav, file incl, code exec\n")
  print("search injection points for xss and sql in forms/url\n")
  print("trace may allow for xst if xss possible\n")
  print("may try to bruteforce with hydra\n\n")
  when @port == "445"
  portcheck()
  portscan()
  print("Security hints port tcp 445: MS-DS\n")
  print("check auth, try null session\n")
  print("try to use nbtscan/smbclient\n\n")
  when @port == "464"
  portcheck()
  portscan()
  print("Security hints port tcp 464: KPASSWD\n")
  print("try to use kerberos (v5)\n\n")
  when @port == "465"
  portcheck()
  portscan()
  print("Security hints port tcp 465: URD/SMTPS\n")
  print("try url rendezvous directory (ssm), try to use smtps\n\n")
  when @port == "512"
  portcheck()
  portscan()
  print("Security hints port tcp 512: EXEC\n")
  print("try to use rexec\n\n")
  when @port == "513"
  portcheck()
  portscan()
  print("Security hints port tcp 513: LOGIN\n")
  print("try to use rlogin\n\n")
  when @port == "514"
  portcheck()
  portscan()
  print("Security hints port tcp 514: SHELL\n")
  print("cleartext protocol, check auth, sniff password\n")
  print("may try to bruteforce with hydra\n\n")
  when @port == "515"
  portcheck()
  portscan()
  print("Security hints port tcp 515: LPR\n")
  print("try to print with lpr\n\n")
  when @port == "540"
  portcheck()
  portscan()
  print("Security hints port tcp 540: UUCP\n")
  print("try to use unix to unix copy protocol\n\n")
  when @port == "543"
  portcheck()
  portscan()
  print("Security hints port tcp 543: KLOGIN\n")
  print("cleartext protocol, check auth, sniff password\n")
  print("may try to bruteforce with hydra\n\n")
  when @port == "544"
  portcheck()
  portscan()
  print("Security hints port tcp 544: KSHELL\n")
  print("cleartext protocol, check auth, sniff password\n")
  print("may try to bruteforce with hydra\n\n")
  when @port == "548"
  portcheck()
  portscan()
  print("Security hints port tcp 548: AFP\n")
  print("evil appleshare detected :o\n")
  when @port == "554"
  portcheck()
  portscan()
  print("Security hints port tcp 554: RTSP\n")
  print("try to use windows/quicktime media streaming\n\n")
  when @port == "567"
  portcheck()
  portscan()
  print("Security hints port tcp 567: DHCPv6\n")
  print("try to use dhcp (v6) client\n\n")
  when @port == "587"
  portcheck()
  portscan()
  smtpvrfy()
  smtprelay()
  print("Security hints port tcp 587: SUBMISSION\n")
  print("smtp vrfy/relay, spoof source port for firewall passing\n\n")
  when @port == "593"
  portcheck()
  portscan()
  print("Security hints port tcp 593: HTTP-RPC-EPMAP\n")
  print("try scanning high range rpc ports\n")
  print("try to use epdump.exe/dcetest (win) or rpcinfo (nix)\n\n")
  when @port == "631"
  portcheck()
  portscan()
  print("Security hints port tcp 631: IPP\n")
  print("connect with browser to this port, try to print with cups\n\n")
  when @port == "636"
  portcheck()
  portscan()
  print("Security hints port tcp 636: LDAPS\n")
  print("check auth, try to enumerate ldap\n\n")
  when @port == "666"
  portcheck()
  portscan()
  print("Security hints port tcp 666: MDQS/DOOM\n")
  print("unusual port, try to interact\n\n")
  when @port == "706"
  portcheck()
  portscan()
  print("Security hints port tcp 706: SILC\n")
  print("try to use secure internet live conferencing\n\n")
  when @port == "777"
  portcheck()
  portscan()
  print("Security hints port tcp 777: MULTILING-HTTP\n")
  print("check auth, robots.txt, dir trav, file incl, code exec\n")
  print("search injection points for xss and sql in forms/url\n")
  print("trace may allow for xst if xss possible\n")
  print("may try to bruteforce with hydra\n\n")
  when @port == "873"
  portcheck()
  portscan()
  print("Security hints port tcp 873: RSYNC\n")
  print("try to use rsync client\n\n")
  when @port == "989"
  portcheck()
  portscan()
  print("Security hints port tcp 989: FTPS-DATA\n")
  print("unusual port, spoof source port for firewall passing\n\n")
  when @port == "990"
  portcheck()
  portscan()
  ftpsanon()
  print("Security hints port tcp 990: FTPS\n")
  print("check auth, anonymous access and write access\n")
  print("may try to bruteforce with hydra, may try to fuzz\n\n")
  when @port == "993"
  portcheck()
  portscan()
  print("Security hints port tcp 993: IMAP4S\n")
  print("try to enumerate users, may try to bruteforce with hydra\n\n")
  portcheck()
  portscan()
  when @port == "994"
  portcheck()
  portscan()
  print("Security hints port tcp 994: IRCS\n")
  print("try to use irc client\n\n")
  when @port == "995"
  portcheck()
  portscan()
  print("Security hints port tcp 995: POP3S\n")
  print("try to enumerate users, may try to bruteforce with hydra\n\n")
  else
  print("only 69 common ports (tcp < 1024)\n")
  print("supported for security hints so far:\n")
  print("#{@ports}")
  print("\n\n")
  print("Anyway checking host ", @host, " on port tcp ", @port, "...\n")
  portcheck()
  portscan()
  bannergrab()
end

# show end time
time = Time.new
puts time.strftime("Stop %Y-%m-%d %H:%M:%S")
print("\n")

# exit correctly
exit(0)