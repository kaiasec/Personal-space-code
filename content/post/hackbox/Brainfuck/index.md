---
# Documentation: https://wowchemy.com/docs/managing-content/

title: "Brainfuck"
linktitle: "Brainfuck"
date: 2022-08-05T14:51:40+08:00
type: book
summary: ""
test: 
---


nmap

```bash
nmap -A -p- 10.10.10.17
```

```bash
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-05 02:47 EDT
Nmap scan report for 10.10.10.17
Host is up (0.091s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 94:d0:b3:34:e9:a5:37:c5:ac:b9:80:df:2a:54:a5:f0 (RSA)
|   256 6b:d5:dc:15:3a:66:7a:f4:19:91:5d:73:85:b2:4c:b2 (ECDSA)
|_  256 23:f5:a3:33:33:9d:76:d5:f2:ea:69:71:e3:4e:8e:02 (ED25519)
25/tcp  open  smtp     Postfix smtpd
|_smtp-commands: brainfuck, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN
110/tcp open  pop3     Dovecot pop3d
|_pop3-capabilities: SASL(PLAIN) USER RESP-CODES CAPA TOP PIPELINING UIDL AUTH-RESP-CODE
143/tcp open  imap     Dovecot imapd
|_imap-capabilities: IMAP4rev1 IDLE AUTH=PLAINA0001 LITERAL+ ID more Pre-login have post-login capabilities LOGIN-REFERRALS OK listed ENABLE SASL-IR
443/tcp open  ssl/http nginx 1.10.0 (Ubuntu)
| tls-alpn:
|_  http/1.1
| ssl-cert: Subject: commonName=brainfuck.htb/organizationName=Brainfuck Ltd./stateOrProvinceName=Attica/countryName=GR
| Subject Alternative Name: DNS:www.brainfuck.htb, DNS:sup3rs3cr3t.brainfuck.htb
| Not valid before: 2017-04-13T11:19:29
|_Not valid after:  2027-04-11T11:19:29
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.10.0 (Ubuntu)
| tls-nextprotoneg:
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.12 (92%), Linux 3.13 (92%), Linux 3.13 or 4.2 (92%), Linux 3.16 (92%), Linux 3.16 - 4.6 (92%), Linux 3.2 - 4.9 (92%), Linux 3.8 - 3.11 (92%), Linux 4.2 (92%), Linux 4.4 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host:  brainfuck; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT       ADDRESS
1   73.51 ms  10.10.16.1
2   143.86 ms 10.10.10.17

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 187.77 seconds

```
