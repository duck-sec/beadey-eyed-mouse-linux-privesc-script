
echo "ICAgICAgICAgICAgLi0tLCAgICAgICAuLS0sCiAgICAgICAgICAgKCAoICBcLi0tLS4vICApICkKICAgICAgICAgICAgIi5fXy9vICAgb1xfXy4iCiAgICAgICAgICAgICAgIHs9ICBeICA9fQogICAgICAgICAgICAgICAgPiAgLSAgPAogX19fX19fX19fX18uIiJgLS0tLS0tLWAiIi5fX19fX19fX19fX18KLyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgXApcICAgICAgICAgIEJlYWRleSBFeWUgTW91c2UgICAgICAgICAgICAvCi8gICAgICAgICAgICBOb3cgU2Nhbm5pbmchICAgICAgICAgICAgIFwKXCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLyAgICAgICAgIF9fCi9pdWNucmVkbGlzdC5vcmcvc3BlY2llcy8yMTc3MC8yMjM2NjQxOVwgICAgIF8uLSIgIGAuClxfX19fX19fX19fX19fXyBfX19fX19fX19fIF9fX19fX19fX19fXy8gLi1+XiAgICAgICAgYH4tLSIKICAgICAgICAgICAgICBfX18pKCApKF9fXyAgICAgICAgYC0uX19fLiIKICAgICAgICAgICAgICgoKF9fKSAoX18pKSkK" | base64 -d 
echo -e "\e[00;93m=====================================================\e[00m"
echo -e "\n"





echo -e "\e[00;32mScan started at: \e[00m"; date 
 
echo -e "\e[00;32mRun as User: \e[00m"; whoami
echo -e "\n"




echo -e "\e[00;93m###-SYSTEM INFORMATION-###\e[00m" 
echo "ICAgICgpLSgpLi0tLS0uICAgICAgICAgIC4KICAgICBcIi9gIF9fXyAgO19fX19fX19fLi8KICAgICAgYCBeXiAgIF5eCg==" | base64 -d 
echo -e "\e[00;93m===========================\e[00m"
echo -e "\n"

#hostname
hostnamed=`hostname 2>/dev/null`
if [ "$hostnamed" ]; then
  echo -e "\e[00;92m[+] Hostname:\e[00m\n$hostnamed" 
  echo -e "\n"
fi

#architecture
arch=`uname -m 2>/dev/null`
if [ "$arch" ]; then
  echo -e "\e[00;92m[+] System Architecture:\e[00m\n$arch" 
  echo -e "\n"
fi

#list kern info
unameinfo=`uname -a 2>/dev/null`
if [ "$unameinfo" ]; then
  echo -e "\e[00;92m[+] Kernel information:\e[00m\n$unameinfo" 
fi  
procver=`cat /proc/version 2>/dev/null`
if [ "$procver" ]; then
  echo -e "\e[00m\n$procver" 
  echo -e "\n"
fi

#search all *-release files for version info
release=`cat /etc/*-release 2>/dev/null`
if [ "$release" ]; then
  echo -e "\e[00;92m[+] Release information:\e[00m\n$release"
  echo -e "\n"
fi


#check if this is a docker container
dockercontainer=` grep -i docker /proc/self/cgroup  2>/dev/null; find / -name "*dockerenv*" -exec ls -la {} \; 2>/dev/null`
if [ "$dockercontainer" ]; then
  echo -e "\e[00;92m[+] This system is a Docker Container:\e[00m" 
  echo -e "\e[00;93m[!] Container info:\e[00m\n$dockercontainer" 
  echo -e "\n"
fi

#check to see if we're a docker host
dockerhost=`docker --version 2>/dev/null; docker ps -a 2>/dev/null`
if [ "$dockerhost" ]; then
  echo -e "\e[00;92m[+] This system is a Docker Host:\e[00m" 
  echo -e "\e[00;93m[!] Found Containers:\e[00m\n$dockerhost" 
fi



echo -e "\n"
echo -e "\n"
echo -e "\e[00;93m#####-USEFUL TOOLS-#####\e[00m" 
echo "ICAgICgpLSgpLi0tLS0uICAgICAgICAgIC4KICAgICBcIi9gIF9fXyAgO19fX19fX19fLi8KICAgICAgYCBeXiAgIF5eCg==" | base64 -d 
echo -e "\e[00;93m===========================\e[00m"
echo -e "\n"

#do we have python(2)
python2=`which python 2>/dev/null`
if [ "$python2" ]; then
  echo -e "\e[00;92m[+] Python2 is installed:\e[00m\n$python2" 
  echo -e "\n"
fi

#do we have python(3)
python3=`which python3 2>/dev/null`
if [ "$python3" ]; then
  echo -e "\e[00;92m[+] Python3 is installed:\e[00m\n$python3" 
  echo -e "\n"
fi

#do we have perl
perl=`which perl 2>/dev/null`
if [ "$perl" ]; then
  echo -e "\e[00;92m[+] Perl is installed:\e[00m\n$perl" 
  echo -e "\n"
fi

#do we have ruby
ruby=`which ruby 2>/dev/null`
if [ "$ruby" ]; then
  echo -e "\e[00;92m[+] Ruby is installed:\e[00m\n$ruby" 
  echo -e "\n"
fi

#do we have gcc
gcc=`which gcc 2>/dev/null`
if [ "$gcc" ]; then
  echo -e "\e[00;92m[+] Ruby is installed:\e[00m\n$gcc" 
  echo -e "\n"
fi

#do we have tcpdump
tcpdump=`which tcpdump 2>/dev/null`
if [ "$tcpdump" ]; then
  echo -e "\e[00;92m[+] Ruby is installed:\e[00m\n$tcpdump" 
  echo -e "\n"
fi


echo -e "\n"
echo -e "\n"
echo -e "\e[00;93m#####-USERS + GROUPS-#####\e[00m" 
echo "ICAgICgpLSgpLi0tLS0uICAgICAgICAgIC4KICAgICBcIi9gIF9fXyAgO19fX19fX19fLi8KICAgICAgYCBeXiAgIF5eCg==" | base64 -d 
echo -e "\e[00;93m===========================\e[00m"
echo -e "\n"

#current user group
currusr=`id 2>/dev/null`
if [ "$currusr" ]; then
  echo -e "\e[00;92m[+] Current user/group info:\e[00m\n$currusr" 
  echo -e "\n"
fi

#current user env
currusr=`env 2>/dev/null`
if [ "$currusr" ]; then
  echo -e "\e[00;92m[+] Current environment info:\e[00m\n$currusr" 
  echo -e "\n"
fi

#current user path
currpath=`echo $PATH 2>/dev/null`
if [ "$currpath" ]; then
  echo -e "\e[00;92m[+] Current Path:\e[00m\n$currpath" 
  echo -e "\n"
fi

#all user accounts
allusers=`cut -d: -f1 /etc/passwd 2>/dev/null`
if [ "$allusers" ]; then
  echo -e "\e[00;92m[+] All user account(s):\e[00m\n$allusers"
  echo -e "\n"
fi


#all root accounts (uid 0)
superusers=`grep -v -E "^#" /etc/passwd 2>/dev/null| awk -F: '$3 == 0 { print $1}' 2>/dev/null`
if [ "$superusers" ]; then
  echo -e "\e[00;92m[+] Super user account(s):\e[00m\n$superusers"
  echo -e "\n"
fi

#last logged on user information
lastlogedonusrs=`lastlog 2>/dev/null |grep -v "Never" 2>/dev/null`
if [ "$lastlogedonusrs" ]; then
  echo -e "\e[00;92m[+] Users that have previously logged onto the system:\e[00m\n$lastlogedonusrs" 
  echo -e "\n" 
fi

#who else is logged on
loggedonusrs=`w 2>/dev/null`
if [ "$loggedonusrs" ]; then
  echo -e "\e[00;92m[+] Other users logged on:\e[00m\n$loggedonusrs" 
  echo -e "\n"
fi

#lists all id's and respective group(s)
grpinfo=`for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null`
if [ "$grpinfo" ]; then
  echo -e "\e[00;92m[+] Group memberships:\e[00m\n$grpinfo"
  echo -e "\n"
fi

#look for adm group 
adm_users=$(echo -e "$grpinfo" | grep "(adm)")
if [[ ! -z $adm_users ]];
  then
    echo -e "\e[00;92m[+] It looks like we have some admin users:\e[00m\n$adm_users"
    echo -e "\n"
fi

#contents of /etc/passwd
readpasswd=`cat /etc/passwd 2>/dev/null`
if [ "$readpasswd" ]; then
  echo -e "\e[00;92m[+] Contents of /etc/passwd:\e[00m\n$readpasswd" 
  echo -e "\n"
fi

#pull out vital sudoers info
sudoers=`grep "sudo" /etc/group 2>/dev/null`
if [ "$sudoers" ]; then
  echo -e "\e[00;92m[+] Sudoers Listed:\e[00m\n$sudoers"
  echo -e "\n"
fi

#pull out vital sudoers info
sudoers=`grep -v -e '^$' /etc/sudoers 2>/dev/null |grep -v "#" 2>/dev/null`
if [ "$sudoers" ]; then
  echo -e "\e[00;92m[+] Sudoers configuration:\e[00m$sudoers"
  echo -e "\n"
fi


#can we sudo without supplying a password
sudoperms=`echo '' | sudo -S -l -k 2>/dev/null`
if [ "$sudoperms" ]; then
  echo -e "\e[00;93m[!] We can sudo without supplying a password!\e[00m\n$sudoperms" 
  echo -e "\n"
fi





echo -e "\n"
echo -e "\n"
echo -e "\e[00;93m#####-FILES + PERMISSIONS-#####\e[00m" 
echo "ICAgICgpLSgpLi0tLS0uICAgICAgICAgIC4KICAgICBcIi9gIF9fXyAgO19fX19fX19fLi8KICAgICAgYCBeXiAgIF5eCg==" | base64 -d 
echo -e "\e[00;93m===========================\e[00m"
echo -e "\n"


#extract any user history files that are accessible
usrhist=`ls -la ~/.*_history 2>/dev/null`
if [ "$usrhist" ]; then
  echo -e "\e[00;92m[+] Current user's history files:\e[00m\n$usrhist" 
  echo -e "\n"
fi


#can we read roots *_history files - could be passwords stored etc.
roothist=`ls -la /root/.*_history 2>/dev/null`
if [ "$roothist" ]; then
  echo -e "\e[00;93m[+] Root's history files are accessible!\e[00m\n$roothist" 
  echo -e "\n"
fi


#all accessible .bash_history files in /home
checkbashhist=`find /home -name .bash_history -print -exec cat {} 2>/dev/null \;`
if [ "$checkbashhist" ]; then
  echo -e "\e[00;92m[+] Found .bash_history file(s): [if this is empty, history is probably pointed to /dev/null] \e[00m\n"
  echo -e "\n"
fi

#any .bak files that may be of interest
bakfiles=`find / -name *.bak -type f 2</dev/null`
if [ "$bakfiles" ]; then
  echo -e "\e[00;92m[+] Found some.bak file(s):\e[00m"
  for bak in `echo $bakfiles`; do ls -la $bak;done
  echo -e "\n"
fi

#is there any mail accessible
readmail=`ls -la /var/mail 2>/dev/null`
if [ "$readmail" ]; then
  echo -e "\e[00;92m[+] Any interesting mail in /var/mail:\e[00m\n$readmail" 
  echo -e "\n"
fi

#can we read roots mail
readmailroot=`head /var/mail/root 2>/dev/null`
if [ "$readmailroot" ]; then
  echo -e "\e[00;93m[+] We can read /var/mail/root! (snippet below)\e[00m\n$readmailroot" 
  echo -e "\n"
fi

#search for suid files
allsuid=`find / -perm -4000 -type f 2>/dev/null`
findsuid=`find $allsuid -perm -4000 -type f -exec ls -la {} 2>/dev/null \;`
if [ "$findsuid" ]; then
  echo -e "\e[00;92m[+] SUID files found:\e[00m\n$findsuid" 
  echo -e "\n"
fi


#search for sgid files
allsgid=`find / -perm -2000 -type f 2>/dev/null`
findsgid=`find $allsgid -perm -2000 -type f -exec ls -la {} 2>/dev/null \;`
if [ "$findsgid" ]; then
  echo -e "\e[00;92m[+] SGID files found:\e[00m\n$findsgid" 
  echo -e "\n"
fi

#search for writable files
writablefiles=`find . -writable 2>&1 | grep -v "Permission denied"`
if [ "$writablefiles" ]; then
  echo -e "\e[00;92m[+] All writable files by current user:\e[00m\n$findsgid" 
  echo -e "\n"
fi




echo -e "\n"
echo -e "\n"
echo -e "\e[00;93m#######-NETWORKING-#######\e[00m" 
echo "ICAgICgpLSgpLi0tLS0uICAgICAgICAgIC4KICAgICBcIi9gIF9fXyAgO19fX19fX19fLi8KICAgICAgYCBeXiAgIF5eCg==" | base64 -d 
echo -e "\e[00;93m===========================\e[00m"
echo -e "\n"


#network info, legacy using ifconfig
nicinfo=`/sbin/ifconfig -a 2>/dev/null`
if [ "$nicinfo" ]; then
  echo -e "\e[00;92m[+] Network and IP info:\e[00m\n$nicinfo" 
  echo -e "\n"
fi

#networking inf, using ip
nicinfoip=`/sbin/ip a 2>/dev/null`
if [ ! "$nicinfo" ] && [ "$nicinfoip" ]; then
  echo -e "\e[00;92m[+] Network and IP info:\e[00m\n$nicinfoip" 
  echo -e "\n"
fi

#check /etc/hosts
etchosts=`cat /etc/hosts 2>/dev/null`
if [ "$etchosts" ]; then
  echo -e "\e[00;92m[+] Entries from hosts file:\e[00m\n$etchosts" 
  echo -e "\n"
fi

#arp with legacy arp -a
arpinfo=`arp -a 2>/dev/null`
if [ "$arpinfo" ]; then
  echo -e "\e[00;92m[+] ARP history:\e[00m\n$arpinfo" 
  echo -e "\n"
fi

#arp with ip n
arpinfoip=`ip n 2>/dev/null`
if [ ! "$arpinfo" ] && [ "$arpinfoip" ]; then
  echo -e "\e[00;92m[+] ARP history:\e[00m\n$arpinfoip" 
  echo -e "\n"
fi

#dns settings
nsinfo=`grep "nameserver" /etc/resolv.conf 2>/dev/null`
if [ "$nsinfo" ]; then
  echo -e "\e[00;92m[+] Nameservers:\e[00m\n$nsinfo" 
  echo -e "\n"
fi

#same thing with resolvd
nsinfosysd=`systemd-resolve --status 2>/dev/null`
if [ "$nsinfosysd" ]; then
  echo -e "\e[00;92m[+] Nameservers:\e[00m\n$nsinfosysd" 
  echo -e "\n"
fi

#default route configuration
defroute=`route 2>/dev/null | grep default`
if [ "$defroute" ]; then
  echo -e "\e[00;92m[+] Default route:\e[00m\n$defroute" 
  echo -e "\n"
fi

#default route configuration
defrouteip=`ip r 2>/dev/null | grep default`
if [ ! "$defroute" ] && [ "$defrouteip" ]; then
  echo -e "\e[00;92m[+] Default route:\e[00m\n$defrouteip" 
  echo -e "\n"
fi

#TCP Listening Ports 
tcpservs=`netstat -ntpl 2>/dev/null`
if [ "$tcpservs" ]; then
  echo -e "\e[00;92m[+] Listening TCP:\e[00m\n$tcpservs" 
  echo -e "\n"
fi

tcpservsip=`ss -t -l -n 2>/dev/null`
if [ ! "$tcpservs" ] && [ "$tcpservsip" ]; then
  echo -e "\e[00;92m[+] Listening TCP:\e[00m\n$tcpservsip" 
  echo -e "\n"
fi

#UDP Listening Ports 
udpservs=`netstat -nupl 2>/dev/null`
if [ "$udpservs" ]; then
  echo -e "\e[00;92m[+] Listening UDP:\e[00m\n$udpservs" 
  echo -e "\n"
fi

udpservsip=`ss -u -l -n 2>/dev/null`
if [ ! "$udpservs" ] && [ "$udpservsip" ]; then
  echo -e "\e[00;92m[+] Listening UDP:\e[00m\n$udpservsip" 
  echo -e "\n"
fi


#list nfs shares/permisisons etc.
nfsexports=`ls -la /etc/exports 2>/dev/null; cat /etc/exports 2>/dev/null`
if [ "$nfsexports" ]; then
  echo -e "\e[00;92m[+] NFS config details: \e[00m\n$nfsexports" 
  echo -e "\n"
fi


fstab=`cat /etc/fstab 2>/dev/null`
  if [ "$fstab" ]; then
    echo -e "\e[00;92m[+] NFS displaying partitions and filesystems\e[00m"
    echo -e "$fstab"
    echo -e "\n"
  fi



echo -e "\n"
echo -e "\n"
echo -e "\e[00;93m#####-RUNNING PROCESSES-#####\e[00m" 
echo "ICAgICgpLSgpLi0tLS0uICAgICAgICAgIC4KICAgICBcIi9gIF9fXyAgO19fX19fX19fLi8KICAgICAgYCBeXiAgIF5eCg==" | base64 -d 
echo -e "\e[00;93m===========================\e[00m"
echo -e "\n"


#list all running processes
psaux=`ps -aux 2>/dev/null`
if [ "$psaux" ]; then
  echo -e "\e[00;92m[+] Runing Processes \e[00m\n$psaux" 
  echo -e "\n"
fi

#list all running processes as root 
psauxroot=`ps -ef | grep --color=auto root 2>/dev/null`
if [ "$psauxroot" ]; then
  echo -e "\e[00;91m[!] Runing Processes as ROOT: \e[00m\n$psauxroot" 
  echo -e "\n"
fi



echo -e "\n"
echo -e "\n"
echo -e "\e[00;93m#######-TASKS & CRON-#######\e[00m" 
echo "ICAgICgpLSgpLi0tLS0uICAgICAgICAgIC4KICAgICBcIi9gIF9fXyAgO19fX19fX19fLi8KICAgICAgYCBeXiAgIF5eCg==" | base64 -d 
echo -e "\e[00;93m===========================\e[00m"
echo -e "\n"




#are there any cron jobs configured
cronjobs=`ls -la /etc/cron* 2>/dev/null`
if [ "$cronjobs" ]; then
  echo -e "\e[00;92m[+] Cron jobs:\e[00m\n$cronjobs" 
  echo -e "\n"
fi

#can we manipulate these jobs in any way
cronjobwwperms=`find /etc/cron* -perm -0002 -type f -exec ls -la {} \; -exec cat {} 2>/dev/null \;`
if [ "$cronjobwwperms" ]; then
  echo -e "\e[00;33m[+] World-writable cron jobs and file contents:\e[00m\n$cronjobwwperms" 
  echo -e "\n"
fi

#contab contents
crontabvalue=`cat /etc/crontab 2>/dev/null`
if [ "$crontabvalue" ]; then
  echo -e "\e[00;92m[+] Crontab contents:\e[00m\n$crontabvalue" 
  echo -e "\n"
fi

crontabvar=`ls -la /var/spool/cron/crontabs 2>/dev/null`
if [ "$crontabvar" ]; then
  echo -e "\e[00;92m[+] Anything interesting in /var/spool/cron/crontabs:\e[00m\n$crontabvar" 
  echo -e "\n"
fi

anacronjobs=`ls -la /etc/anacrontab 2>/dev/null; cat /etc/anacrontab 2>/dev/null`
if [ "$anacronjobs" ]; then
  echo -e "\e[00;92m[+] Anacron jobs and associated file permissions:\e[00m\n$anacronjobs" 
  echo -e "\n"
fi

anacrontab=`ls -la /var/spool/anacron 2>/dev/null`
if [ "$anacrontab" ]; then
  echo -e "\e[00;92m[+] When were jobs last executed (/var/spool/anacron contents):\e[00m\n$anacrontab" 
  echo -e "\n"
fi

#pull out account names from /etc/passwd and see if any users have associated cronjobs (priv command)
cronother=`cut -d ":" -f 1 /etc/passwd | xargs -n1 crontab -l -u 2>/dev/null`
if [ "$cronother" ]; then
  echo -e "\e[00;92m[+] Jobs held by all users:\e[00m\n$cronother" 
  echo -e "\n"
fi

# list systemd timers
if [ "$thorough" = "1" ]; then
  # include inactive timers in thorough mode
  systemdtimers="$(systemctl list-timers --all 2>/dev/null)"
  info=""
else
  systemdtimers="$(systemctl list-timers 2>/dev/null |head -n -1 2>/dev/null)"
  # replace the info in the output with a hint towards thorough mode
  info="\e[2mEnable thorough tests to see inactive timers\e[00m"
fi
if [ "$systemdtimers" ]; then
  echo -e "\e[00;92m[+] Systemd timers:\e[00m\n$systemdtimers\n$info"
  echo -e "\n"
fi




echo -e "\n"
echo -e "\n"
echo -e "\e[00;93m#####-POSSIBLE CREDENTIALS-#####\e[00m" 
echo "ICAgICgpLSgpLi0tLS0uICAgICAgICAgIC4KICAgICBcIi9gIF9fXyAgO19fX19fX19fLi8KICAgICAgYCBeXiAgIF5eCg==" | base64 -d 
echo -e "\e[00;93m===========================\e[00m"
echo -e "\n"


#look for private keys
privatekeyfiles=`grep -rlw "PRIVATE KEY-----" /home/*/.ssh 2>/dev/null`
	if [ "$privatekeyfiles" ]; then
  		echo -e "\e[00;93m[+] Private SSH keys found!:\e[00m\n$privatekeyfiles"
  		echo -e "\n"
	fi






echo -e "\n"
echo -e "\n"
echo -e "\e[00;93m#######-EASY WINS!!!-#######\e[00m" 
echo "ICAgICgpLSgpLi0tLS0uICAgICAgICAgIC4KICAgICBcIi9gIF9fXyAgO19fX19fX19fLi8KICAgICAgYCBeXiAgIF5eCg==" | base64 -d 
echo -e "\e[00;93m===========================\e[00m"
echo -e "\n"


binarylist='ab$\|agetty$\|alpine$\|ansible-playbook$\|aoss$\|apt-get$\|apt$\|ar$\|aria2c$\|arj$\|arp$\|as$\|ascii-xfr$\|ascii85$\|ash$\|aspell$\|at$\|atobm$\|awk$\|aws$\|base32$\|base58$\|base64$\|basenc$\|basez$\|bash$\|batcat$\|bc$\|bconsole$\|bpftrace$\|bridge$\|bundle$\|bundler$\|busctl$\|busybox$\|byebug$\|bzip2$\|c89$\|c99$\|cabal$\|cancel$\|capsh$\|cat$\|cdist$\|certbot$\|check_by_ssh$\|check_cups$\|check_log$\|check_memory$\|check_raid$\|check_ssl_cert$\|check_statusfile$\|chmod$\|choom$\|chown$\|chroot$\|cmp$\|cobc$\|column$\|comm$\|composer$\|cowsay$\|cowthink$\|cp$\|cpan$\|cpio$\|cpulimit$\|crash$\|crontab$\|csh$\|csplit$\|csvtool$\|cupsfilter$\|curl$\|cut$\|dash$\|date$\|dd$\|debugfs$\|dialog$\|diff$\|dig$\|dmesg$\|dmidecode$\|dmsetup$\|dnf$\|docker$\|dosbox$\|dpkg$\|dvips$\|easy_install$\|eb$\|ed$\|efax$\|emacs$\|env$\|eqn$\|espeak$\|ex$\|exiftool$\|expand$\|expect$\|facter$\|file$\|find$\|finger$\|fish$\|flock$\|fmt$\|fold$\|fping$\|ftp$\|gawk$\|gcc$\|gcloud$\|gcore$\|gdb$\|gem$\|genie$\|genisoimage$\|ghc$\|ghci$\|gimp$\|ginsh$\|git$\|grc$\|grep$\|gtester$\|gzip$\|hd$\|head$\|hexdump$\|highlight$\|hping3$\|iconv$\|iftop$\|install$\|ionice$\|ip$\|irb$\|ispell$\|jjs$\|joe$\|join$\|journalctl$\|jq$\|jrunscript$\|jtag$\|knife$\|ksh$\|ksshell$\|ksu$\|kubectl$\|latex$\|latexmk$\|ld$\|ldconfig$\|less$\|lftp$\|ln$\|loginctl$\|logsave$\|look$\|lp$\|ltrace$\|lua$\|lualatex$\|luatex$\|lwp-download$\|lwp-request$\|mail$\|make$\|man$\|mawk$\|more$\|mosquitto$\|mount$\|msfconsole$\|msgattrib$\|msgcat$\|msgconv$\|msgfilter$\|msgmerge$\|msguniq$\|mtr$\|multitime$\|mv$\|mysql$\|nano$\|nasm$\|nawk$\|nc$\|neofetch$\|nft$\|nice$\|nl$\|nm$\|nmap$\|node$\|nohup$\|npm$\|nroff$\|nsenter$\|octave$\|od$\|openssl$\|openvpn$\|openvt$\|opkg$\|pandoc$\|paste$\|pax$\|pdb$\|pdflatex$\|pdftex$\|perf$\|perl$\|perlbug$\|pg$\|php$\|pic$\|pico$\|pidstat$\|pip$\|pkexec$\|pkg$\|posh$\|pr$\|pry$\|psftp$\|psql$\|ptx$\|puppet$\|python$\|rake$\|readelf$\|red$\|redcarpet$\|restic$\|rev$\|rlogin$\|rlwrap$\|rpm$\|rpmdb$\|rpmquery$\|rpmverify$\|rsync$\|rtorrent$\|ruby$\|run-mailcap$\|run-parts$\|rview$\|rvim$\|sash$\|scanmem$\|scp$\|screen$\|script$\|scrot$\|sed$\|service$\|setarch$\|setfacl$\|setlock$\|sftp$\|sg$\|shuf$\|slsh$\|smbclient$\|snap$\|socat$\|socket$\|soelim$\|softlimit$\|sort$\|split$\|sqlite3$\|ss$\|ssh-keygen$\|ssh-keyscan$\|ssh$\|sshpass$\|start-stop-daemon$\|stdbuf$\|strace$\|strings$\|su$\|sysctl$\|systemctl$\|systemd-resolve$\|tac$\|tail$\|tar$\|task$\|taskset$\|tasksh$\|tbl$\|tclsh$\|tcpdump$\|tee$\|telnet$\|tex$\|tftp$\|tic$\|time$\|timedatectl$\|timeout$\|tmate$\|tmux$\|top$\|torify$\|torsocks$\|troff$\|tshark$\|ul$\|unexpand$\|uniq$\|unshare$\|unzip$\|update-alternatives$\|uudecode$\|uuencode$\|valgrind$\|vi$\|view$\|vigr$\|vim$\|vimdiff$\|vipw$\|virsh$\|volatility$\|w3m$\|wall$\|watch$\|wc$\|wget$\|whiptail$\|whois$\|wireshark$\|wish$\|xargs$\|xdotool$\|xelatex$\|xetex$\|xmodmap$\|xmore$\|xpad$\|xxd$\|xz$\|yarn$\|yash$\|yelp$\|yum$\|zathura$\|zip$\|zsh$\|zsoelim$\|zypper$'
#check to see if we can write to /etc/passwd 
writepasswd='/etc/passwd'
if [[ -r $writepasswd && -w $writepasswd ]]; then
  echo -e "\e[00;91m[!] We can write to /etc/passwd!\e[00m\n$writepasswd" 
  echo -e "\n"
fi


#checks to see if the shadow file can be read
readshadow=`cat /etc/shadow 2>/dev/null`
if [ "$readshadow" ]; then
  echo -e "\e[00;91m[!] We can read the shadow file!\e[00m\n$readshadow" 
  echo -e "\n"
fi

#checks to see if /etc/master.passwd can be read - BSD 'shadow' variant
readmasterpasswd=`cat /etc/master.passwd 2>/dev/null`
if [ "$readmasterpasswd" ]; then
  echo -e "\e[00;91m[!] We can read the master.passwd file!\e[00m\n$readmasterpasswd" 
  echo -e "\n"
fi

#checks to see if any hashes are stored in /etc/passwd 
hashesinpasswd=`grep -v '^[^:]*:[x]' /etc/passwd 2>/dev/null`
if [ "$hashesinpasswd" ]; then
  echo -e "\e[00;91m[!] It looks like we have password hashes in /etc/passwd!\e[00m\n$hashesinpasswd" 
  echo -e "\n"
fi

#list of 'interesting' suid files
intsuid=`find $allsuid -perm -4000 -type f -exec ls -la {} \; 2>/dev/null | grep -w $binarylist 2>/dev/null`
if [ "$intsuid" ]; then
  echo -e "\e[00;91m[!] Possibly vulnerable SUID files with entry @ GTFObins:\e[00m\n$intsuid" 
  echo -e "\n"
fi

intsgid=`find $allsgid -perm -2000 -type f  -exec ls -la {} \; 2>/dev/null | grep -w $binarylist 2>/dev/null`
if [ "$intsgid" ]; then
  echo -e "\e[00;91m[!] Possibly vulnerable SGID files with entry @ GTFObins:\e[00m\n$intsgid" 
  echo -e "\n"
fi

vulnpacks=`apt list --installed | cut -d , -f 1 | cut -d / -f 1| grep -w $binarylist 2>/dev/null`
if [ "$vulnpacks" ]; then
  echo -e "\e[00;91m[!] Possibly vulnerable packages with entry @ GTFObins:\e[00m\n$vulnpacks" 
  echo -e "\n"
fi

#checks if we a member of the docker group
dockergrp=`id | grep -i docker 2>/dev/null`
if [ "$dockergrp" ]; then
  echo -e "\e[00;91m[!] We're a member of the (docker) group!\e[00m\n$dockergrp" 
  echo -e "\n"
fi



