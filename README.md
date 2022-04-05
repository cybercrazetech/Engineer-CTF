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
2. There's two ways to gain foothold, but the first way is the intended one (as the mysql user) while the second unintended way (as www-data) is unable to escalate to root. This is because binary "mysql-into-cybercraze-group" only works to include mysql user into cybercraze group, which is intended for further exploitation.
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

6. exploits refer to:

https://www.exploit-db.com/exploits/50452
https://www.idappcom.co.uk/post/engineers-online-portal-1-0-remote-code-execution
https://www.exploit-db.com/exploits/50453
https://github.com/berdav/CVE-2021-4034

## Writeup

[Describe the steps to completing the box. Show all specific commands necessary so that someone could solve the box by copying and pasting from this writeup]
