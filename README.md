# Beady-eyed Mouse - Linux Privilege Escalation Script

This script is designed to assist in the detection of possible misconfigurations that may lead to privilege escalation on a Linux system. 
I use this as a "first view" script to gather basic system config information and detect "easy win" vulnerabilities - it is not intended to replace more comprehensive tools, such as LinPEAS.
It provides a quick overview of system information, user and group details, file permissions, network configurations, running processes, scheduled tasks, and potential security issues.

The Beady-eyed Mouse is a cute little mouse found in Columbia and Ecuador - with those beady eyes, if a mouse was going to be good at privilege esealation, it would be this one :)

## Usage

Run the script on a Linux system with the following command:

```bash
bash mouse.sh
```
# Features
- System Information: Displays details such as hostname, system architecture, kernel information, and release information.
- Useful Tools: Checks for the availability of essential tools such as Python, Perl, Ruby, GCC, and tcpdump.
- Users + Groups: Provides information about user accounts, group memberships, and sudo configuration.
- Files + Permissions: Examines file and directory permissions, searching for sensitive files and world-writable files.
- Networking: Reports network and IP information, DNS settings, and listening ports.
- Running Processes: Lists all running processes and identifies processes running with root privileges.
- Tasks & Cron: Displays cron jobs, systemd timers, and scheduled tasks.
- Possible Credentials: Searches for potential credentials, including private SSH keys.
- Easy Wins: Identifies common binaries and executables that may have security implications.

# Disclaimer
This code is provided for educational and ethical security testing purposes only. It should be used responsibly and only in environments where explicit authorization has been granted. Unauthorized or malicious use is strictly prohibited. By using this code, you agree to adhere to all applicable laws, regulations, and ethical standards applicable in your jurisdiction. The creators and contributors disclaim any liability for any damages or consequences arising from the misuse or unauthorized use of this code.

# Example Output

```

            .--,       .--,
           ( (  \.---./  ) )
            ".__/o   o\__."
               {=  ^  =}
                >  -  <
 ___________.""`-------`"".____________
/                                      \
\          Beadey Eye Mouse            /
/            Now Scanning!             \
\                                      /         __
/iucnredlist.org/species/21770/22366419\     _.-"  `.
\______________ __________ ____________/ .-~^        `~--"
              ___)( )(___        `-.___."
             (((__) (__)))
=====================================================


Scan started at: 
Sat Dec  2 13:40:23 UTC 2023
Run as User: 
logan


###-SYSTEM INFORMATION-###
    ()-().----.          .
     \"/` ___  ;________./
      ` ^^   ^^
===========================


[+] Hostname:
devvortex


[+] System Architecture:
x86_64


[+] Kernel information:
Linux devvortex 5.4.0-167-generic #184-Ubuntu SMP Tue Oct 31 09:21:49 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux

Linux version 5.4.0-167-generic (buildd@lcy02-amd64-010) (gcc version 9.4.0 (Ubuntu 9.4.0-1ubuntu1~20.04.2)) #184-Ubuntu SMP Tue Oct 31 09:21:49 UTC 2023


[+] Release information:
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=20.04
DISTRIB_CODENAME=focal
DISTRIB_DESCRIPTION="Ubuntu 20.04.6 LTS"
NAME="Ubuntu"
VERSION="20.04.6 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04.6 LTS"
VERSION_ID="20.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=focal
UBUNTU_CODENAME=focal






#####-USEFUL TOOLS-#####
    ()-().----.          .
     \"/` ___  ;________./
      ` ^^   ^^
===========================


[+] Python3 is installed:
/usr/bin/python3


[+] Perl is installed:
/usr/bin/perl


[+] Ruby is installed:
/usr/sbin/tcpdump






#####-USERS + GROUPS-#####
    ()-().----.          .
     \"/` ___  ;________./
      ` ^^   ^^
===========================


[+] Current user/group info:
uid=1000(logan) gid=1000(logan) groups=1000(logan)


[+] Current environment info:
SHELL=/bin/bash
LC_ADDRESS=C.UTF-8
LC_NAME=C.UTF-8
LC_MONETARY=C.UTF-8
PWD=/dev/shm
LOGNAME=logan
XDG_SESSION_TYPE=tty
MOTD_SHOWN=pam
HOME=/home/logan
LC_PAPER=C.UTF-8
LANG=C.UTF-8
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
SSH_CONNECTION=10.10.14.30 49666 10.129.51.59 22
LESSCLOSE=/usr/bin/lesspipe %s %s
XDG_SESSION_CLASS=user
LC_IDENTIFICATION=C.UTF-8
TERM=xterm-256color
LESSOPEN=| /usr/bin/lesspipe %s
USER=logan
SHLVL=2
LC_TELEPHONE=C.UTF-8
LC_MEASUREMENT=C.UTF-8
XDG_SESSION_ID=1
XDG_RUNTIME_DIR=/run/user/1000
SSH_CLIENT=10.10.14.30 49666 22
LC_TIME=C.UTF-8
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus
SSH_TTY=/dev/pts/0
LC_NUMERIC=C.UTF-8
OLDPWD=/home/logan
_=/usr/bin/env


[+] Current Path:
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin


[+] All user account(s):
root
daemon
bin
sys
sync
games
man
lp
mail
news
uucp
proxy
www-data
backup
list
irc
gnats
nobody
systemd-network
systemd-resolve
systemd-timesync
messagebus
syslog
_apt
tss
uuidd
tcpdump
landscape
pollinate
sshd
systemd-coredump
lxd
usbmux
fwupd-refresh
mysql
logan
_laurel


[+] Super user account(s):
root


[+] Users that have previously logged onto the system:
Username         Port     From             Latest
logan            pts/0    10.10.14.30      Sat Dec  2 13:38:44 +0000 2023


[+] Other users logged on:
 13:40:34 up 5 min,  1 user,  load average: 0.16, 0.09, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
logan    pts/0    10.10.14.30      13:38   18.00s  0.07s  0.00s bash mouse.sh


[+] Group memberships:
uid=0(root) gid=0(root) groups=0(root)
uid=1(daemon) gid=1(daemon) groups=1(daemon)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=5(games) gid=60(games) groups=60(games)
uid=6(man) gid=12(man) groups=12(man)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=9(news) gid=9(news) groups=9(news)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=100(systemd-network) gid=102(systemd-network) groups=102(systemd-network)
uid=101(systemd-resolve) gid=103(systemd-resolve) groups=103(systemd-resolve)
uid=102(systemd-timesync) gid=104(systemd-timesync) groups=104(systemd-timesync)
uid=103(messagebus) gid=106(messagebus) groups=106(messagebus)
uid=104(syslog) gid=110(syslog) groups=110(syslog),4(adm),5(tty)
uid=105(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=106(tss) gid=111(tss) groups=111(tss)
uid=107(uuidd) gid=112(uuidd) groups=112(uuidd)
uid=108(tcpdump) gid=113(tcpdump) groups=113(tcpdump)
uid=109(landscape) gid=115(landscape) groups=115(landscape)
uid=110(pollinate) gid=1(daemon) groups=1(daemon)
uid=111(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=999(systemd-coredump) gid=999(systemd-coredump) groups=999(systemd-coredump)
uid=998(lxd) gid=100(users) groups=100(users)
uid=112(usbmux) gid=46(plugdev) groups=46(plugdev)
uid=113(fwupd-refresh) gid=118(fwupd-refresh) groups=118(fwupd-refresh)
uid=114(mysql) gid=119(mysql) groups=119(mysql)
uid=1000(logan) gid=1000(logan) groups=1000(logan)
uid=997(_laurel) gid=997(_laurel) groups=997(_laurel)


[+] It looks like we have some admin users:
uid=104(syslog) gid=110(syslog) groups=110(syslog),4(adm),5(tty)


[+] Contents of /etc/passwd:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
fwupd-refresh:x:113:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
logan:x:1000:1000:,,,:/home/logan:/bin/bash
_laurel:x:997:997::/var/log/laurel:/bin/false


[+] Sudoers Listed:
sudo:x:27:


Sorry, try again.




#####-FILES + PERMISSIONS-#####
    ()-().----.          .
     \"/` ___  ;________./
      ` ^^   ^^
===========================


[+] Current user's history files:
lrwxrwxrwx 1 root root 9 Oct 26 14:58 /home/logan/.bash_history -> /dev/null


[+] Found .bash_history file(s): [if this is empty, history is probably pointed to /dev/null] 



[+] Any interesting mail in /var/mail:
total 8
drwxrwsr-x  2 root mail 4096 Jan 20  2021 .
drwxr-xr-x 13 root root 4096 Sep 12 17:36 ..


[+] SUID files found:
-rwsr-xr-- 1 root messagebus 51344 Oct 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 14488 Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 22840 Feb 21  2022 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 473576 Aug  4 22:02 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 55528 May 30  2023 /usr/bin/mount
-rwsr-xr-x 1 root root 166056 Apr  4  2023 /usr/bin/sudo
-rwsr-xr-x 1 root root 88464 Nov 29  2022 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 39144 May 30  2023 /usr/bin/umount
-rwsr-xr-x 1 root root 68208 Nov 29  2022 /usr/bin/passwd
-rwsr-xr-x 1 root root 39144 Mar  7  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root root 53040 Nov 29  2022 /usr/bin/chsh
-rwsr-sr-x 1 daemon daemon 55560 Nov 12  2018 /usr/bin/at
-rwsr-xr-x 1 root root 85064 Nov 29  2022 /usr/bin/chfn
-rwsr-xr-x 1 root root 44784 Nov 29  2022 /usr/bin/newgrp
-rwsr-xr-x 1 root root 67816 May 30  2023 /usr/bin/su


[+] SGID files found:
-rwxr-sr-x 1 root shadow 43168 Feb  2  2023 /usr/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 43160 Feb  2  2023 /usr/sbin/unix_chkpwd
-rwxr-sr-x 1 root utmp 14648 Sep 30  2019 /usr/lib/x86_64-linux-gnu/utempter/utempter
-rwxr-sr-x 1 root tty 35048 May 30  2023 /usr/bin/wall
-rwxr-sr-x 1 root ssh 350504 Aug  4 22:02 /usr/bin/ssh-agent
-rwxr-sr-x 1 root mail 14488 Aug 26  2019 /usr/bin/mlock
-rwxr-sr-x 1 root shadow 31312 Nov 29  2022 /usr/bin/expiry
-rwxr-sr-x 1 root tty 14488 Mar 30  2020 /usr/bin/bsd-write
-rwxr-sr-x 1 root shadow 84512 Nov 29  2022 /usr/bin/chage
-rwsr-sr-x 1 daemon daemon 55560 Nov 12  2018 /usr/bin/at
-rwxr-sr-x 1 root crontab 43720 Feb 13  2020 /usr/bin/crontab


[+] All writable files by current user:
-rwxr-sr-x 1 root shadow 43168 Feb  2  2023 /usr/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 43160 Feb  2  2023 /usr/sbin/unix_chkpwd
-rwxr-sr-x 1 root utmp 14648 Sep 30  2019 /usr/lib/x86_64-linux-gnu/utempter/utempter
-rwxr-sr-x 1 root tty 35048 May 30  2023 /usr/bin/wall
-rwxr-sr-x 1 root ssh 350504 Aug  4 22:02 /usr/bin/ssh-agent
-rwxr-sr-x 1 root mail 14488 Aug 26  2019 /usr/bin/mlock
-rwxr-sr-x 1 root shadow 31312 Nov 29  2022 /usr/bin/expiry
-rwxr-sr-x 1 root tty 14488 Mar 30  2020 /usr/bin/bsd-write
-rwxr-sr-x 1 root shadow 84512 Nov 29  2022 /usr/bin/chage
-rwsr-sr-x 1 daemon daemon 55560 Nov 12  2018 /usr/bin/at
-rwxr-sr-x 1 root crontab 43720 Feb 13  2020 /usr/bin/crontab






#######-NETWORKING-#######
    ()-().----.          .
     \"/` ___  ;________./
      ` ^^   ^^
===========================


[+] Network and IP info:
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.129.51.59  netmask 255.255.0.0  broadcast 10.129.255.255
        inet6 fe80::250:56ff:fe96:a4a1  prefixlen 64  scopeid 0x20<link>
        inet6 dead:beef::250:56ff:fe96:a4a1  prefixlen 64  scopeid 0x0<global>
        ether 00:50:56:96:a4:a1  txqueuelen 1000  (Ethernet)
        RX packets 611  bytes 77326 (77.3 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 434  bytes 62654 (62.6 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 544  bytes 41314 (41.3 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 544  bytes 41314 (41.3 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0


[+] Entries from hosts file:
127.0.0.1 localhost
127.0.1.1 devvortex

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters


[+] ARP history:
? (10.129.0.1) at 00:50:56:b9:f8:ec [ether] on eth0


[+] Nameservers:
nameserver 127.0.0.53


[+] Nameservers:
Global
       LLMNR setting: no                  
MulticastDNS setting: no                  
  DNSOverTLS setting: no                  
      DNSSEC setting: no                  
    DNSSEC supported: no                  
  Current DNS Server: 8.8.8.8             
         DNS Servers: 1.1.1.1             
                      8.8.8.8             
Fallback DNS Servers: 1.0.0.1             
          DNSSEC NTA: 10.in-addr.arpa     
                      16.172.in-addr.arpa 
                      168.192.in-addr.arpa
                      17.172.in-addr.arpa 
                      18.172.in-addr.arpa 
                      19.172.in-addr.arpa 
                      20.172.in-addr.arpa 
                      21.172.in-addr.arpa 
                      22.172.in-addr.arpa 
                      23.172.in-addr.arpa 
                      24.172.in-addr.arpa 
                      25.172.in-addr.arpa 
                      26.172.in-addr.arpa 
                      27.172.in-addr.arpa 
                      28.172.in-addr.arpa 
                      29.172.in-addr.arpa 
                      30.172.in-addr.arpa 
                      31.172.in-addr.arpa 
                      corp                
                      d.f.ip6.arpa        
                      home                
                      internal            
                      intranet            
                      lan                 
                      local               
                      private             
                      test                

Link 2 (eth0)
      Current Scopes: none
DefaultRoute setting: no  
       LLMNR setting: yes 
MulticastDNS setting: no  
  DNSOverTLS setting: no  
      DNSSEC setting: no  
    DNSSEC supported: no  


[+] Default route:
default         10.129.0.1      0.0.0.0         UG    0      0        0 eth0


[+] Listening TCP:
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   


[+] Listening UDP:
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -                   


[+] NFS displaying partitions and filesystems
# /etc/fstab: static file system information.
#
# Use 'blkid' to print the universally unique identifier for a
# device; this may be used with UUID= as a more robust way to name devices
# that works even if disks are added and removed. See fstab(5).
#
# <file system> <mount point>   <type>  <options>       <dump>  <pass>
# / was on /dev/sda2 during curtin installation
/dev/disk/by-uuid/0e6aec1f-7be8-49b9-8e43-d83828f4d864 / ext4 defaults 0 0
/dev/sda3       none    swap    sw      0       0






#####-RUNNING PROCESSES-#####
    ()-().----.          .
     \"/` ___  ;________./
      ` ^^   ^^
===========================


[+] Runing Processes 
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.5  0.2 167828 11424 ?        Ss   13:34   0:02 /sbin/init maybe-ubiquity
root           2  0.0  0.0      0     0 ?        S    13:34   0:00 [kthreadd]
root           3  0.0  0.0      0     0 ?        I<   13:34   0:00 [rcu_gp]
root           4  0.0  0.0      0     0 ?        I<   13:34   0:00 [rcu_par_gp]
root           6  0.0  0.0      0     0 ?        I<   13:34   0:00 [kworker/0:0H-kblockd]
root           7  0.0  0.0      0     0 ?        I    13:34   0:00 [kworker/u4:0-events_unbound]
root           8  0.0  0.0      0     0 ?        I<   13:34   0:00 [mm_percpu_wq]
root           9  0.0  0.0      0     0 ?        S    13:34   0:00 [ksoftirqd/0]
root          10  0.0  0.0      0     0 ?        I    13:34   0:00 [rcu_sched]
root          11  0.0  0.0      0     0 ?        S    13:34   0:00 [migration/0]
root          12  0.0  0.0      0     0 ?        S    13:34   0:00 [idle_inject/0]
root          14  0.0  0.0      0     0 ?        S    13:34   0:00 [cpuhp/0]
root          15  0.0  0.0      0     0 ?        S    13:34   0:00 [cpuhp/1]
root          16  0.0  0.0      0     0 ?        S    13:34   0:00 [idle_inject/1]
root          17  0.0  0.0      0     0 ?        S    13:34   0:00 [migration/1]
root          18  0.0  0.0      0     0 ?        S    13:34   0:00 [ksoftirqd/1]
root          20  0.0  0.0      0     0 ?        I<   13:34   0:00 [kworker/1:0H-kblockd]
root          21  0.0  0.0      0     0 ?        S    13:34   0:00 [kdevtmpfs]
root          22  0.0  0.0      0     0 ?        I<   13:34   0:00 [netns]
root          23  0.0  0.0      0     0 ?        S    13:34   0:00 [rcu_tasks_kthre]
root          24  0.0  0.0      0     0 ?        S    13:34   0:00 [kauditd]
root          25  0.0  0.0      0     0 ?        S    13:34   0:00 [khungtaskd]
root          26  0.0  0.0      0     0 ?        S    13:34   0:00 [oom_reaper]
root          27  0.0  0.0      0     0 ?        I<   13:34   0:00 [writeback]
root          28  0.0  0.0      0     0 ?        S    13:34   0:00 [kcompactd0]
root          29  0.0  0.0      0     0 ?        SN   13:34   0:00 [ksmd]
root          30  0.0  0.0      0     0 ?        SN   13:34   0:00 [khugepaged]
root          35  0.0  0.0      0     0 ?        I    13:34   0:00 [kworker/1:1-events]
root          77  0.0  0.0      0     0 ?        I<   13:34   0:00 [kintegrityd]
root          78  0.0  0.0      0     0 ?        I<   13:34   0:00 [kblockd]
root          79  0.0  0.0      0     0 ?        I<   13:34   0:00 [blkcg_punt_bio]
root          80  0.0  0.0      0     0 ?        I<   13:34   0:00 [tpm_dev_wq]
root          81  0.0  0.0      0     0 ?        I<   13:34   0:00 [ata_sff]
root          82  0.0  0.0      0     0 ?        I<   13:34   0:00 [md]
root          83  0.0  0.0      0     0 ?        I<   13:34   0:00 [edac-poller]
root          84  0.0  0.0      0     0 ?        I<   13:34   0:00 [devfreq_wq]
root          85  0.0  0.0      0     0 ?        S    13:34   0:00 [watchdogd]
root          88  0.0  0.0      0     0 ?        S    13:34   0:00 [kswapd0]
root          89  0.0  0.0      0     0 ?        S    13:34   0:00 [ecryptfs-kthrea]
root          91  0.0  0.0      0     0 ?        I<   13:34   0:00 [kthrotld]
root          92  0.0  0.0      0     0 ?        S    13:34   0:00 [irq/24-pciehp]
root          93  0.0  0.0      0     0 ?        S    13:34   0:00 [irq/25-pciehp]
root          94  0.0  0.0      0     0 ?        S    13:34   0:00 [irq/26-pciehp]
root          95  0.0  0.0      0     0 ?        S    13:34   0:00 [irq/27-pciehp]
root          96  0.0  0.0      0     0 ?        S    13:34   0:00 [irq/28-pciehp]
root          97  0.0  0.0      0     0 ?        S    13:34   0:00 [irq/29-pciehp]
root          98  0.0  0.0      0     0 ?        S    13:34   0:00 [irq/30-pciehp]
root          99  0.0  0.0      0     0 ?        S    13:34   0:00 [irq/31-pciehp]
root         100  0.0  0.0      0     0 ?        S    13:34   0:00 [irq/32-pciehp]
root         101  0.0  0.0      0     0 ?        S    13:34   0:00 [irq/33-pciehp]
root         102  0.0  0.0      0     0 ?        S    13:34   0:00 [irq/34-pciehp]
root         103  0.0  0.0      0     0 ?        S    13:34   0:00 [irq/35-pciehp]
root         104  0.0  0.0      0     0 ?        S    13:34   0:00 [irq/36-pciehp]
root         105  0.0  0.0      0     0 ?        S    13:34   0:00 [irq/37-pciehp]
root         106  0.0  0.0      0     0 ?        S    13:34   0:00 [irq/38-pciehp]
root         107  0.0  0.0      0     0 ?        S    13:34   0:00 [irq/39-pciehp]
root         108  0.0  0.0      0     0 ?        S    13:34   0:00 [irq/40-pciehp]
root         109  0.0  0.0      0     0 ?        S    13:34   0:00 [irq/41-pciehp]
root         110  0.0  0.0      0     0 ?        S    13:34   0:00 [irq/42-pciehp]
root         111  0.0  0.0      0     0 ?        S    13:34   0:00 [irq/43-pciehp]
root         112  0.0  0.0      0     0 ?        S    13:34   0:00 [irq/44-pciehp]
root         113  0.0  0.0      0     0 ?        S    13:34   0:00 [irq/45-pciehp]
root         114  0.0  0.0      0     0 ?        S    13:34   0:00 [irq/46-pciehp]
root         115  0.0  0.0      0     0 ?        S    13:34   0:00 [irq/47-pciehp]
root         116  0.0  0.0      0     0 ?        S    13:34   0:00 [irq/48-pciehp]
root         117  0.0  0.0      0     0 ?        S    13:34   0:00 [irq/49-pciehp]
root         118  0.0  0.0      0     0 ?        S    13:34   0:00 [irq/50-pciehp]
root         119  0.0  0.0      0     0 ?        S    13:34   0:00 [irq/51-pciehp]
root         120  0.0  0.0      0     0 ?        S    13:34   0:00 [irq/52-pciehp]
root         121  0.0  0.0      0     0 ?        S    13:34   0:00 [irq/53-pciehp]
root         122  0.0  0.0      0     0 ?        S    13:34   0:00 [irq/54-pciehp]
root         123  0.0  0.0      0     0 ?        S    13:34   0:00 [irq/55-pciehp]
root         124  0.0  0.0      0     0 ?        I<   13:34   0:00 [acpi_thermal_pm]
root         125  0.0  0.0      0     0 ?        S    13:34   0:00 [scsi_eh_0]
root         126  0.0  0.0      0     0 ?        I<   13:34   0:00 [scsi_tmf_0]
root         127  0.0  0.0      0     0 ?        S    13:34   0:00 [scsi_eh_1]
root         128  0.0  0.0      0     0 ?        I<   13:34   0:00 [scsi_tmf_1]
root         129  0.0  0.0      0     0 ?        I    13:34   0:00 [kworker/u4:2-events_unbound]
root         130  0.0  0.0      0     0 ?        I<   13:34   0:00 [vfio-irqfd-clea]
root         131  0.0  0.0      0     0 ?        I<   13:34   0:00 [ipv6_addrconf]
root         141  0.0  0.0      0     0 ?        I<   13:34   0:00 [kstrp]
root         144  0.0  0.0      0     0 ?        I<   13:34   0:00 [kworker/u5:0]
root         157  0.0  0.0      0     0 ?        I<   13:34   0:00 [charger_manager]
root         201  0.0  0.0      0     0 ?        I    13:34   0:00 [kworker/1:2-events]
root         203  0.0  0.0      0     0 ?        I<   13:34   0:00 [cryptd]
root         220  0.0  0.0      0     0 ?        I<   13:34   0:00 [mpt_poll_0]
root         238  0.0  0.0      0     0 ?        I<   13:34   0:00 [mpt/0]
root         239  0.0  0.0      0     0 ?        S    13:34   0:00 [irq/16-vmwgfx]
root         240  0.0  0.0      0     0 ?        I<   13:34   0:00 [ttm_swap]
root         241  0.0  0.0      0     0 ?        S    13:34   0:00 [scsi_eh_2]
root         242  0.0  0.0      0     0 ?        I<   13:34   0:00 [scsi_tmf_2]
root         243  0.1  0.0      0     0 ?        I<   13:34   0:00 [kworker/1:1H-kblockd]
root         250  0.1  0.0      0     0 ?        I<   13:34   0:00 [kworker/0:1H-kblockd]
root         273  0.0  0.0      0     0 ?        I<   13:34   0:00 [raid5wq]
root         324  0.0  0.0      0     0 ?        S    13:34   0:00 [jbd2/sda2-8]
root         325  0.0  0.0      0     0 ?        I<   13:34   0:00 [ext4-rsv-conver]
root         379  0.3  0.3  77756 15520 ?        S<s  13:34   0:01 /lib/systemd/systemd-journald
root         412  0.0  0.0      0     0 ?        I    13:34   0:00 [kworker/0:3-events]
root         416  0.1  0.1  22500  5940 ?        Ss   13:34   0:00 /lib/systemd/systemd-udevd
root         457  0.0  0.0      0     0 ?        I<   13:34   0:00 [nfit]
root         537  0.0  0.0      0     0 ?        I<   13:34   0:00 [kaluad]
root         538  0.0  0.0      0     0 ?        I<   13:34   0:00 [kmpath_rdacd]
root         539  0.0  0.0      0     0 ?        I<   13:34   0:00 [kmpathd]
root         540  0.0  0.0      0     0 ?        I<   13:34   0:00 [kmpath_handlerd]
root         541  0.0  0.4 214600 17948 ?        SLsl 13:34   0:00 /sbin/multipathd -d -s
systemd+     563  0.0  0.1  90884  6220 ?        Ssl  13:34   0:00 /lib/systemd/systemd-timesyncd
root         564  0.0  0.0  11356  1556 ?        S<sl 13:34   0:00 /sbin/auditd
root         596  0.0  0.2  47544 10628 ?        Ss   13:34   0:00 /usr/bin/VGAuthService
root         599  0.4  0.2 237804  8548 ?        Ssl  13:34   0:01 /usr/bin/vmtoolsd
root         613  0.0  0.1  99896  5852 ?        Ssl  13:34   0:00 /sbin/dhclient -1 -4 -v -i -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0
root         619  0.0  0.0      0     0 ?        S    13:34   0:00 [audit_prune_tre]
root         635  0.0  0.2 239300  9152 ?        Ssl  13:34   0:00 /usr/lib/accountsservice/accounts-daemon
message+     636  0.0  0.1   7388  4480 ?        Ss   13:34   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
root         650  0.0  0.0  81960  3720 ?        Ssl  13:34   0:00 /usr/sbin/irqbalance --foreground
root         654  0.0  0.2 236444  8888 ?        Ssl  13:34   0:00 /usr/lib/policykit-1/polkitd --no-debug
syslog       661  0.0  0.1 224344  5112 ?        Ssl  13:34   0:00 /usr/sbin/rsyslogd -n -iNONE
root         662  0.0  0.1  17348  7664 ?        Ss   13:34   0:00 /lib/systemd/systemd-logind
root         667  0.0  0.3 395504 13808 ?        Ssl  13:34   0:00 /usr/lib/udisks2/udisksd
root         724  0.0  0.3 245096 13324 ?        Ssl  13:34   0:00 /usr/sbin/ModemManager
root         727  0.0  0.0      0     0 ?        D    13:34   0:00 [kworker/0:4+events]
root         749  0.0  0.0      0     0 ?        I    13:35   0:00 [kworker/1:4-events]
systemd+     774  0.0  0.3  24708 12328 ?        Ss   13:35   0:00 /lib/systemd/systemd-resolved
root         841  0.0  0.0   6816  2812 ?        Ss   13:35   0:00 /usr/sbin/cron -f
root         842  0.0  0.7 220696 31720 ?        Ss   13:35   0:00 php-fpm: master process (/etc/php/7.4/fpm/php-fpm.conf)
daemon       860  0.0  0.0   3796  2280 ?        Ss   13:35   0:00 /usr/sbin/atd -f
root         863  0.0  0.1  12184  6788 ?        Ss   13:35   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
root         865  0.0  0.0  51204  1612 ?        Ss   13:35   0:00 nginx: master process /usr/sbin/nginx -g daemon on; master_process on;
www-data     866  0.0  0.1  51872  5164 ?        S    13:35   0:00 nginx: worker process
www-data     867  0.0  0.1  51872  5164 ?        S    13:35   0:00 nginx: worker process
root         886  0.0  0.0   5828  1784 tty1     Ss+  13:35   0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
www-data     887  0.0  0.2 221068 11128 ?        S    13:35   0:00 php-fpm: pool www
www-data     888  0.0  0.2 221068 11128 ?        S    13:35   0:00 php-fpm: pool www
mysql        892  1.3  9.9 1790732 398860 ?      Ssl  13:35   0:04 /usr/sbin/mysqld
root        1009  0.0  0.2  13968  8992 ?        Ss   13:38   0:00 sshd: logan [priv]
logan       1036  0.0  0.2  19040  9516 ?        Ss   13:38   0:00 /lib/systemd/systemd --user
logan       1039  0.0  0.0 169184  3260 ?        S    13:38   0:00 (sd-pam)
logan       1143  0.0  0.1  13968  5860 ?        S    13:38   0:00 sshd: logan@pts/0
logan       1144  0.0  0.1  10128  5528 pts/0    Ss   13:38   0:00 -bash
logan       1242  0.0  0.0   8748  3720 pts/0    S+   13:40   0:00 bash mouse.sh
root        1451  0.0  0.0  22500  3668 ?        S    13:40   0:00 /lib/systemd/systemd-udevd
root        1452  0.0  0.0      0     0 ?        I    13:40   0:00 [kworker/0:0]
logan       1465  0.0  0.0   8748  2080 pts/0    S+   13:40   0:00 bash mouse.sh
logan       1466  0.0  0.0  10808  3536 pts/0    R+   13:40   0:00 ps -aux


[!] Runing Processes as ROOT: 
root           1       0  0 13:34 ?        00:00:02 /sbin/init maybe-ubiquity
root           2       0  0 13:34 ?        00:00:00 [kthreadd]
root           3       2  0 13:34 ?        00:00:00 [rcu_gp]
root           4       2  0 13:34 ?        00:00:00 [rcu_par_gp]
root           6       2  0 13:34 ?        00:00:00 [kworker/0:0H-kblockd]
root           7       2  0 13:34 ?        00:00:00 [kworker/u4:0-events_unbound]
root           8       2  0 13:34 ?        00:00:00 [mm_percpu_wq]
root           9       2  0 13:34 ?        00:00:00 [ksoftirqd/0]
root          10       2  0 13:34 ?        00:00:00 [rcu_sched]
root          11       2  0 13:34 ?        00:00:00 [migration/0]
root          12       2  0 13:34 ?        00:00:00 [idle_inject/0]
root          14       2  0 13:34 ?        00:00:00 [cpuhp/0]
root          15       2  0 13:34 ?        00:00:00 [cpuhp/1]
root          16       2  0 13:34 ?        00:00:00 [idle_inject/1]
root          17       2  0 13:34 ?        00:00:00 [migration/1]
root          18       2  0 13:34 ?        00:00:00 [ksoftirqd/1]
root          20       2  0 13:34 ?        00:00:00 [kworker/1:0H-kblockd]
root          21       2  0 13:34 ?        00:00:00 [kdevtmpfs]
root          22       2  0 13:34 ?        00:00:00 [netns]
root          23       2  0 13:34 ?        00:00:00 [rcu_tasks_kthre]
root          24       2  0 13:34 ?        00:00:00 [kauditd]
root          25       2  0 13:34 ?        00:00:00 [khungtaskd]
root          26       2  0 13:34 ?        00:00:00 [oom_reaper]
root          27       2  0 13:34 ?        00:00:00 [writeback]
root          28       2  0 13:34 ?        00:00:00 [kcompactd0]
root          29       2  0 13:34 ?        00:00:00 [ksmd]
root          30       2  0 13:34 ?        00:00:00 [khugepaged]
root          35       2  0 13:34 ?        00:00:00 [kworker/1:1-events]
root          77       2  0 13:34 ?        00:00:00 [kintegrityd]
root          78       2  0 13:34 ?        00:00:00 [kblockd]
root          79       2  0 13:34 ?        00:00:00 [blkcg_punt_bio]
root          80       2  0 13:34 ?        00:00:00 [tpm_dev_wq]
root          81       2  0 13:34 ?        00:00:00 [ata_sff]
root          82       2  0 13:34 ?        00:00:00 [md]
root          83       2  0 13:34 ?        00:00:00 [edac-poller]
root          84       2  0 13:34 ?        00:00:00 [devfreq_wq]
root          85       2  0 13:34 ?        00:00:00 [watchdogd]
root          88       2  0 13:34 ?        00:00:00 [kswapd0]
root          89       2  0 13:34 ?        00:00:00 [ecryptfs-kthrea]
root          91       2  0 13:34 ?        00:00:00 [kthrotld]
root          92       2  0 13:34 ?        00:00:00 [irq/24-pciehp]
root          93       2  0 13:34 ?        00:00:00 [irq/25-pciehp]
root          94       2  0 13:34 ?        00:00:00 [irq/26-pciehp]
root          95       2  0 13:34 ?        00:00:00 [irq/27-pciehp]
root          96       2  0 13:34 ?        00:00:00 [irq/28-pciehp]
root          97       2  0 13:34 ?        00:00:00 [irq/29-pciehp]
root          98       2  0 13:34 ?        00:00:00 [irq/30-pciehp]
root          99       2  0 13:34 ?        00:00:00 [irq/31-pciehp]
root         100       2  0 13:34 ?        00:00:00 [irq/32-pciehp]
root         101       2  0 13:34 ?        00:00:00 [irq/33-pciehp]
root         102       2  0 13:34 ?        00:00:00 [irq/34-pciehp]
root         103       2  0 13:34 ?        00:00:00 [irq/35-pciehp]
root         104       2  0 13:34 ?        00:00:00 [irq/36-pciehp]
root         105       2  0 13:34 ?        00:00:00 [irq/37-pciehp]
root         106       2  0 13:34 ?        00:00:00 [irq/38-pciehp]
root         107       2  0 13:34 ?        00:00:00 [irq/39-pciehp]
root         108       2  0 13:34 ?        00:00:00 [irq/40-pciehp]
root         109       2  0 13:34 ?        00:00:00 [irq/41-pciehp]
root         110       2  0 13:34 ?        00:00:00 [irq/42-pciehp]
root         111       2  0 13:34 ?        00:00:00 [irq/43-pciehp]
root         112       2  0 13:34 ?        00:00:00 [irq/44-pciehp]
root         113       2  0 13:34 ?        00:00:00 [irq/45-pciehp]
root         114       2  0 13:34 ?        00:00:00 [irq/46-pciehp]
root         115       2  0 13:34 ?        00:00:00 [irq/47-pciehp]
root         116       2  0 13:34 ?        00:00:00 [irq/48-pciehp]
root         117       2  0 13:34 ?        00:00:00 [irq/49-pciehp]
root         118       2  0 13:34 ?        00:00:00 [irq/50-pciehp]
root         119       2  0 13:34 ?        00:00:00 [irq/51-pciehp]
root         120       2  0 13:34 ?        00:00:00 [irq/52-pciehp]
root         121       2  0 13:34 ?        00:00:00 [irq/53-pciehp]
root         122       2  0 13:34 ?        00:00:00 [irq/54-pciehp]
root         123       2  0 13:34 ?        00:00:00 [irq/55-pciehp]
root         124       2  0 13:34 ?        00:00:00 [acpi_thermal_pm]
root         125       2  0 13:34 ?        00:00:00 [scsi_eh_0]
root         126       2  0 13:34 ?        00:00:00 [scsi_tmf_0]
root         127       2  0 13:34 ?        00:00:00 [scsi_eh_1]
root         128       2  0 13:34 ?        00:00:00 [scsi_tmf_1]
root         129       2  0 13:34 ?        00:00:00 [kworker/u4:2-events_unbound]
root         130       2  0 13:34 ?        00:00:00 [vfio-irqfd-clea]
root         131       2  0 13:34 ?        00:00:00 [ipv6_addrconf]
root         141       2  0 13:34 ?        00:00:00 [kstrp]
root         144       2  0 13:34 ?        00:00:00 [kworker/u5:0]
root         157       2  0 13:34 ?        00:00:00 [charger_manager]
root         201       2  0 13:34 ?        00:00:00 [kworker/1:2-events]
root         203       2  0 13:34 ?        00:00:00 [cryptd]
root         220       2  0 13:34 ?        00:00:00 [mpt_poll_0]
root         238       2  0 13:34 ?        00:00:00 [mpt/0]
root         239       2  0 13:34 ?        00:00:00 [irq/16-vmwgfx]
root         240       2  0 13:34 ?        00:00:00 [ttm_swap]
root         241       2  0 13:34 ?        00:00:00 [scsi_eh_2]
root         242       2  0 13:34 ?        00:00:00 [scsi_tmf_2]
root         243       2  0 13:34 ?        00:00:00 [kworker/1:1H-kblockd]
root         250       2  0 13:34 ?        00:00:00 [kworker/0:1H-kblockd]
root         273       2  0 13:34 ?        00:00:00 [raid5wq]
root         324       2  0 13:34 ?        00:00:00 [jbd2/sda2-8]
root         325       2  0 13:34 ?        00:00:00 [ext4-rsv-conver]
root         379       1  0 13:34 ?        00:00:01 /lib/systemd/systemd-journald
root         412       2  0 13:34 ?        00:00:00 [kworker/0:3-events]
root         416       1  0 13:34 ?        00:00:00 /lib/systemd/systemd-udevd
root         457       2  0 13:34 ?        00:00:00 [nfit]
root         537       2  0 13:34 ?        00:00:00 [kaluad]
root         538       2  0 13:34 ?        00:00:00 [kmpath_rdacd]
root         539       2  0 13:34 ?        00:00:00 [kmpathd]
root         540       2  0 13:34 ?        00:00:00 [kmpath_handlerd]
root         541       1  0 13:34 ?        00:00:00 /sbin/multipathd -d -s
root         564       1  0 13:34 ?        00:00:00 /sbin/auditd
root         596       1  0 13:34 ?        00:00:00 /usr/bin/VGAuthService
root         599       1  0 13:34 ?        00:00:01 /usr/bin/vmtoolsd
root         613       1  0 13:34 ?        00:00:00 /sbin/dhclient -1 -4 -v -i -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0
root         619       2  0 13:34 ?        00:00:00 [audit_prune_tre]
root         635       1  0 13:34 ?        00:00:00 /usr/lib/accountsservice/accounts-daemon
root         650       1  0 13:34 ?        00:00:00 /usr/sbin/irqbalance --foreground
root         654       1  0 13:34 ?        00:00:00 /usr/lib/policykit-1/polkitd --no-debug
root         662       1  0 13:34 ?        00:00:00 /lib/systemd/systemd-logind
root         667       1  0 13:34 ?        00:00:00 /usr/lib/udisks2/udisksd
root         724       1  0 13:34 ?        00:00:00 /usr/sbin/ModemManager
root         727       2  0 13:34 ?        00:00:00 [kworker/0:4-events]
root         749       2  0 13:35 ?        00:00:00 [kworker/1:4-events]
root         841       1  0 13:35 ?        00:00:00 /usr/sbin/cron -f
root         842       1  0 13:35 ?        00:00:00 php-fpm: master process (/etc/php/7.4/fpm/php-fpm.conf)
root         863       1  0 13:35 ?        00:00:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
root         865       1  0 13:35 ?        00:00:00 nginx: master process /usr/sbin/nginx -g daemon on; master_process on;
root         886       1  0 13:35 tty1     00:00:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
root        1009     863  0 13:38 ?        00:00:00 sshd: logan [priv]
root        1451     416  0 13:40 ?        00:00:00 /lib/systemd/systemd-udevd
root        1452       2  0 13:40 ?        00:00:00 [kworker/0:0]
logan       1469    1467  0 13:40 pts/0    00:00:00 grep --color=auto root






#######-TASKS & CRON-#######
    ()-().----.          .
     \"/` ___  ;________./
      ` ^^   ^^
===========================


[+] Cron jobs:
-rw-r--r-- 1 root root 1042 Feb 13  2020 /etc/crontab

/etc/cron.d:
total 24
drwxr-xr-x   2 root root 4096 Oct 26 15:12 .
drwxr-xr-x 106 root root 4096 Nov 21 10:56 ..
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder
-rw-r--r--   1 root root  201 Feb 14  2020 e2scrub_all
-rw-r--r--   1 root root  712 Mar 27  2020 php
-rw-r--r--   1 root root  191 Apr 23  2020 popularity-contest

/etc/cron.daily:
total 48
drwxr-xr-x   2 root root 4096 Nov 21 10:55 .
drwxr-xr-x 106 root root 4096 Nov 21 10:56 ..
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder
-rwxr-xr-x   1 root root  376 Dec  4  2019 apport
-rwxr-xr-x   1 root root 1478 Apr  9  2020 apt-compat
-rwxr-xr-x   1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x   1 root root 1187 Sep  5  2019 dpkg
-rwxr-xr-x   1 root root  377 Jan 21  2019 logrotate
-rwxr-xr-x   1 root root 1123 Feb 25  2020 man-db
-rwxr-xr-x   1 root root 4574 Jul 18  2019 popularity-contest
-rwxr-xr-x   1 root root  214 Apr  2  2020 update-notifier-common

/etc/cron.hourly:
total 12
drwxr-xr-x   2 root root 4096 Oct 26 15:12 .
drwxr-xr-x 106 root root 4096 Nov 21 10:56 ..
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x   2 root root 4096 Oct 26 15:12 .
drwxr-xr-x 106 root root 4096 Nov 21 10:56 ..
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder

/etc/cron.weekly:
total 20
drwxr-xr-x   2 root root 4096 Oct 26 15:12 .
drwxr-xr-x 106 root root 4096 Nov 21 10:56 ..
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder
-rwxr-xr-x   1 root root  813 Feb 25  2020 man-db
-rwxr-xr-x   1 root root  403 Apr 25  2022 update-notifier-common


[+] Crontab contents:
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#


[+] Systemd timers:
NEXT                        LEFT           LAST                        PASSED               UNIT                         ACTIVATES                     
Sat 2023-12-02 13:49:52 UTC 8min left      n/a                         n/a                  systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
Sat 2023-12-02 13:53:44 UTC 12min left     Tue 2023-11-21 10:55:39 UTC 1 weeks 4 days ago   apt-daily-upgrade.timer      apt-daily-upgrade.service     
Sat 2023-12-02 14:09:00 UTC 28min left     Sat 2023-12-02 13:39:01 UTC 1min 58s ago         phpsessionclean.timer        phpsessionclean.service       
Sat 2023-12-02 15:52:24 UTC 2h 11min left  Tue 2023-10-03 08:32:00 UTC 1 months 29 days ago motd-news.timer              motd-news.service             
Sat 2023-12-02 22:28:21 UTC 8h left        Tue 2023-10-03 08:32:00 UTC 1 months 29 days ago apt-daily.timer              apt-daily.service             
Sat 2023-12-02 23:44:53 UTC 10h left       Thu 2023-10-26 16:09:17 UTC 1 months 6 days ago  fwupd-refresh.timer          fwupd-refresh.service         
Sun 2023-12-03 00:00:00 UTC 10h left       Sat 2023-12-02 13:34:59 UTC 6min ago             logrotate.timer              logrotate.service             
Sun 2023-12-03 00:00:00 UTC 10h left       Sat 2023-12-02 13:34:59 UTC 6min ago             man-db.timer                 man-db.service                
Sun 2023-12-03 03:10:59 UTC 13h left       Sat 2023-12-02 13:35:59 UTC 5min ago             e2scrub_all.timer            e2scrub_all.service           
Mon 2023-12-04 00:00:00 UTC 1 day 10h left Sat 2023-12-02 13:34:59 UTC 6min ago             fstrim.timer                 fstrim.service                

10 timers listed.
Enable thorough tests to see inactive timers






#####-POSSIBLE CREDENTIALS-#####
    ()-().----.          .
     \"/` ___  ;________./
      ` ^^   ^^
===========================






#######-EASY WINS!!!-#######
    ()-().----.          .
     \"/` ___  ;________./
      ` ^^   ^^
===========================


[!] Possibly vulnerable SUID files with entry @ GTFObins:
-rwsr-xr-x 1 root root 55528 May 30  2023 /usr/bin/mount
-rwsr-sr-x 1 daemon daemon 55560 Nov 12  2018 /usr/bin/at
-rwsr-xr-x 1 root root 67816 May 30  2023 /usr/bin/su


[!] Possibly vulnerable SGID files with entry @ GTFObins:
-rwxr-sr-x 1 root tty 35048 May 30  2023 /usr/bin/wall
-rwsr-sr-x 1 daemon daemon 55560 Nov 12  2018 /usr/bin/at
-rwxr-sr-x 1 root crontab 43720 Feb 13  2020 /usr/bin/crontab



WARNING: apt does not have a stable CLI interface. Use with caution in scripts.

[!] Possibly vulnerable packages with entry @ GTFObins:
apt
at
bash
bc
bzip2
cpio
curl
dash
dconf-service
dmidecode
dmsetup
dpkg
ed
file
ftp
gawk
git-man
git
grep
gzip
less
libcgi-fast-perl
libcgi-pm-perl
libencode-locale-perl
liberror-perl
libfcgi-perl
libhtml-parser-perl
libhtml-tagset-perl
libhtml-template-perl
libhttp-date-perl
libhttp-message-perl
libio-html-perl
liblocale-gettext-perl
liblwp-mediatypes-perl
libnginx-mod-mail
libtext-charwidth-perl
libtext-iconv-perl
libtext-wrapi18n-perl
libtimedate-perl
liburi-perl
libxmlsec1-openssl
logsave
ltrace
mawk
mount
nano
openssl
perl
php7.4-curl
php7.4-mysql
php7.4-sqlite3
php7.4-zip
python3-apt
python3-openssl
rsync
screen
sed
strace
tar
tcpdump
telnet
time
tmux
unzip
vim
wget
whiptail
xxd


```
