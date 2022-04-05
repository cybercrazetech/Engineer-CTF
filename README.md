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
2. refer to:
https://www.exploit-db.com/exploits/50452


## Writeup

[Describe the steps to completing the box. Show all specific commands necessary so that someone could solve the box by copying and pasting from this writeup]
