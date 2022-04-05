# Engineer-CTF

## Introduction

This is to introduce the multiple vulnerabilities in Engineers Online Portal 1.0 that could be chained together to reveal serious information, or even rce. Next, this box aims to tell why allowing mysql connection to remote host isn't a good idea. Finally, it takes a little buffer overflow skills to exploit a manually coded binary, and some basic knowledge of how CVE-2021-4034 works to escalate to root.

## Info for HTB

| hash | content |
| ---- | ------- |
| user.txt | 7d58250d6dec957ab2b8ded3fd925e85 |
| root.txt | 89d975f8ac623a6fdb0246bc01eefbf2 |

### Access

Passwords:

| User  | Password                            |
| ----- | ----------------------------------- |
| root | nocrackpleaseno! |
| cybercraze | nocrackpleaseno! |
| root(mysql) | youshallnotcrackthis |
| admin(engineer-portal admin) | youshallnotcrackthis |
| ralph(engineer-portal user) | ralphthelegend |
| tom(engineer-portal user) | tomandjerry |
| jez(engineer-portal user) | jezmusic |
| andres(engineer-portal user) | andresrevolutionary |

### Other

1. The online engineer portal is built using the original source code version 1.0. There's no deliberate manipulation of the source code to allow the further exploit done.
2. There's two ways to gain foothold, but the first way is the intended one (as the mysql user) while the second unintended way (as www-data) is unable to escalate to root. This is because the vulnerable binary "mysql-into-cybercraze-group" only works to include mysql user into cybercraze group, which is intended for further exploitation.
3. There's stored password in the binary "mysql-into-cybercraze-group", but it is made unreadable and hence using strings or downloading for local inspection will fail.
4. source code for mysql-into-cybercraze-group

            #include <stdio.h>
            #include <string.h>
            #include <stdlib.h>

            int main(void)
            {
            char buff[15];
            int pass = 0;

            printf("\n Enter the password : \n");
            gets(buff);

            if(strcmp(buff, "nocrackplzno!"))
            {
            printf ("\n Wrong Password \n");
            }
            else
            {
            printf ("\n Correct Password \n");
            pass = 1;
            }

            if(pass)
            {
            /* including mysql to cybercraze group */
            printf ("\n Including user mysql to cybercraze group \n");
            system ("echo 'nocrackpleaseno!' | sudo -S -k usermod -aG cybercraze mysql");
            }

            return 0;
            }
*notice the vulnerable function gets() to read password is used, which is vulnerable to buffer overflow

5. vulnerable /usr/bin/pkexec is moved to /opt/pkexec, where /opt is only readable and executable by user cybercraze

6. exploits refer to:

https://www.exploit-db.com/exploits/50452

https://www.idappcom.co.uk/post/engineers-online-portal-1-0-remote-code-execution

https://www.exploit-db.com/exploits/50453

https://github.com/berdav/CVE-2021-4034

## Writeup

1. Nmap Scan
            $nmap -sCV 192.168.0.186
            Starting Nmap 7.91 ( https://nmap.org ) at 2022-04-05 14:29 +08
            Nmap scan report for engineer.htb (192.168.0.186)
            Host is up (0.027s latency).
            Not shown: 997 closed ports
            PORT     STATE SERVICE VERSION
            22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
            | ssh-hostkey: 
            |   3072 e7:67:ab:72:53:be:d6:f3:7b:3d:c0:48:7f:31:34:fa (RSA)
            |   256 21:93:3c:26:89:14:9f:4a:7c:8c:bf:a1:b5:f6:5d:b3 (ECDSA)
            |_  256 d1:ed:71:b7:69:ef:64:12:e4:5a:99:cb:41:30:ae:f0 (ED25519)
            80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
            |_http-server-header: Apache/2.4.41 (Ubuntu)
            |_http-title: Onix Digital Marketing HTML5 Template
            3306/tcp open  mysql   MySQL 8.0.28-0ubuntu0.20.04.3
            | mysql-info: 
            |   Protocol: 10
            |   Version: 8.0.28-0ubuntu0.20.04.3
            |   Thread ID: 11
            |   Capabilities flags: 65535
            |   Some Capabilities: LongColumnFlag, SwitchToSSLAfterHandshake, Speaks41ProtocolOld, SupportsTransactions, IgnoreSigpipes, DontAllowDatabaseTableColumn, InteractiveClient, SupportsLoadDataLocal, Support41Auth, LongPassword, SupportsCompression, ConnectWithDatabase, IgnoreSpaceBeforeParenthesis, ODBCClient, Speaks41ProtocolNew, FoundRows, SupportsMultipleResults, SupportsAuthPlugins, SupportsMultipleStatments
            |   Status: Autocommit
            |   Salt: 3n!U1~"\x02\x08R:     ,fO\x11w\x05fs
            |_  Auth Plugin Name: caching_sha2_password
            | ssl-cert: Subject: commonName=MySQL_Server_8.0.28_Auto_Generated_Server_Certificate
            | Not valid before: 2022-04-03T08:32:53
            |_Not valid after:  2032-03-31T08:32:53
            Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

            Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
            Nmap done: 1 IP address (1 host up) scanned in 13.45 seconds

$gobuster vhost -u engineer.htb -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://engineer.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2022/04/05 14:33:56 Starting gobuster in VHOST enumeration mode
===============================================================
Found: webportal.engineer.htb (Status: 200) [Size: 9749]
                                                        
===============================================================
2022/04/05 14:34:01 Finished
===============================================================
