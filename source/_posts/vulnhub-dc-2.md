---
title: VulnHub DC-2 靶场 Writeup
date: 2026-04-21 11:00:00
categories:
  - VulnHub靶场
tags:
  - VulnHub
  - WordPress
  - WPScan
  - rbash绕过
  - Sudo提权
  - Writeup

---

## 解题流程：
因为靶机和kali主机处于同一网段下，用nmap扫描一下

执行：nmap -sV 192.168.111.0/24

![](/img/posts/vulnhub-dc-2/vulnhub-dc-2-01.png)

找到了靶机的ip：192.168.111.134 

扫描所有端口看看，执行：nmap -A -p 1-65535 192.168.111.134

![](/img/posts/vulnhub-dc-2/vulnhub-dc-2-02.png)

开放了80和7744端口，直接访问80端口，跳转到了dc-2

![](/img/posts/vulnhub-dc-2/vulnhub-dc-2-03.png)

提示Unknown host:dc-2，解决方式攻击机（kali）的hosts文件中手动添加dc-2.

执行：sudo nano /etc/hosts

![](/img/posts/vulnhub-dc-2/vulnhub-dc-2-04.png)

保存后重新访问页面

![](/img/posts/vulnhub-dc-2/vulnhub-dc-2-05.png)

查看Flag

![](/img/posts/vulnhub-dc-2/vulnhub-dc-2-06.png)

你常用的密码列表可能不管用，所以，或许你需要发挥一下自己的特长。密码越多越好，但有时候你不可能每次都成功。用其中一个账号登录，即可查看下一道题。如果找不到，请用另一个账号登录。

需要我们找到一个登录页面。可以使用kali的dirb扫描目录

执行：dirb [http://dc-2](http://dc-2)

![](/img/posts/vulnhub-dc-2/vulnhub-dc-2-07.png)

访问扫描到的目录，自动跳转到了登录页面

![](/img/posts/vulnhub-dc-2/vulnhub-dc-2-08.png)

![](/img/posts/vulnhub-dc-2/vulnhub-dc-2-09.png)

很明显的这个网站是WordPress，可以使用WPScan扫描。

执行：wpscan --url [http://dc-2](http://dc-2) --enumerate u 可出用户名

![](/img/posts/vulnhub-dc-2/vulnhub-dc-2-10.png)

扫出了三个用户名：admin、jerry、tom，将其保存在users.txt，方便后续爆破

flag1中提到了 **cewl**：是一款由Ruby编写的智能爬虫工具，专为渗透测试设计。它通过抓取指定URL的网页内容，并根据爬取深度提取文本生成自定义字典，常用于密码爆破场景。

执行：cewl [http://dc-2](http://dc-2) -w passwords.txt 会将密码保存在passwords.txt中

爆破使用WPScan，执行：wpscan --url [http://dc-2](http://dc-2) -U users.txt -P passwords.txt

![](/img/posts/vulnhub-dc-2/vulnhub-dc-2-11.png)

成功了两个，登录测试一下

jerry/adipiscing：找到了Flag2

![](/img/posts/vulnhub-dc-2/vulnhub-dc-2-12.png)

![](/img/posts/vulnhub-dc-2/vulnhub-dc-2-13.png)

提示我们如股票WordPress这条路行不通，还有另一条路，在端口扫描的时候还有7744，部署的是ssh连接。因为Flag2是在jerry账号里找到了，tom里面什么也没有，推测可能是ssh的账号密码

执行：ssh tom@dc-2 -p 7744

密码：parturient

![](/img/posts/vulnhub-dc-2/vulnhub-dc-2-14.png)

成功连接

![](/img/posts/vulnhub-dc-2/vulnhub-dc-2-15.png)

不能用cat，用户在 rbash 环境下，系统只允许你执行极少数被限制在 ~/usr/bin 目录下的命令。ls 查看能用的命令

执行：ls /home/tom/usr/bin

![](/img/posts/vulnhub-dc-2/vulnhub-dc-2-16.png)

可以用vim编辑器查看文件

执行：vi flag3.txt

![](/img/posts/vulnhub-dc-2/vulnhub-dc-2-17.png)

flag3中提示"su"=swich user，要切换到jerry用户。

想要运行su，需要逃逸出rbash环境，经典方法使用，vi 的后门：vi 是一个文本编辑器，但它允许你在编辑时临时执行系统命令（:!command）或设置内部参数（:set shell）。

执行：vi

:set shell=/bin/sh

回车发现没有退出vi，继续

:shell

![](/img/posts/vulnhub-dc-2/vulnhub-dc-2-18.png)

由于指令是在/usr/bin下寻找，需要对该path重定向

执行：export PATH=$PATH:/bin，/bin下放着最重要的二进制指令

![](/img/posts/vulnhub-dc-2/vulnhub-dc-2-19.png)

执行：su jerry，输入密码，成功进入

![](/img/posts/vulnhub-dc-2/vulnhub-dc-2-20.png)

最后的提示是 **git **提权，Git提权通常发生在普通用户被赋予了通过 sudo 运行 git 的权限

执行：sudo -l 显示该用户能用root权限运行的不用输入密码的程序

![](/img/posts/vulnhub-dc-2/vulnhub-dc-2-21.png)

显然就是git提权，最常见方式git分页器：当运行 sudo git help 或某些需要长文本显示的 git 命令时，Git会调用 less 作为分页器。如果此时用户拥有以root权限运行 git 的sudo权限，可以在 less 中运行shell。

执行：sudo git help config

在less提示符下输入：!/bin/bash

![](/img/posts/vulnhub-dc-2/vulnhub-dc-2-22.png)

直接进入root shell，读取最后的flag。

## 知识点总结：
1.WordPress专项：wpscan的使用

2.社工字典生成工具：CeWL的使用

3.rbash机制绕过：vi/less等编辑器逃逸，export PATH/环境变量重构

4.用户切换：su命令

5.Sudo提权：git分页器提权。
