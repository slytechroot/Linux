#/bin/bash/sh

#check for updates
sudo apt updates -y

#check for upgrades
sudo apt  upgrades -y

#start and persistent ssh
sudo systemctl enable ssh
sudo systemctl start ssh

#run as root to check for empty passwords
awk -F: '($2 == "") {print}' /etc/shadow

#Avoid Legacy Communication Methods
apt-get --purge remove xinetd nis tftpd tftpd-hpa telnetd rsh-server rsh-redone-server

#or for RPM based systems
yum erase xinetd ypserv tftp-server telnet-server rsh-server

#secure SSH /etc/ssh/sshd_config
PermitRootLogin no # disables root login
MaxAuthTries 3 # limits authentication attempts
PasswordAuthentication no # disables password authentication
PermitEmptyPasswords no # disables empty passwords
X11Forwarding no # disables GUI transmission
DebianBanner no # disbales verbose banner
AllowUsers *@XXX.X.XXX.0/24 # restrict users to an IP range

#restrict access to crontab. check who's got access
echo $(whoami) >> /etc/cron.d/cron.allow
# echo ALL >> /etc/cron.d/cron.deny

#Enforce PAM Modules
# CentOS/RHEL
echo 'password sufficient pam_unix.so use_authtok md5 shadow remember=5' 
/etc/pam.d/system-auth
# Ubuntu/Debian
echo 'password sufficient pam_unix.so use_authtok md5 shadow remember=5' 
/etc/pam.d/common-password

#Remove Unused Packages
yum list installed # CentOS/RHEL 
apt list --installed # Ubuntu/Debian

#Monitor Logs
/var/log/auth.log 		# logs authorization attempts
/var/log/daemon.log 	#logs background apps
/var/log/debug 			#logs debugging data
/var/log/kern.log 		#logs kernel data
/var/log/syslog 		#logs system data
/var/log/faillog 		#logs failed logins


	
	
	




