---
title: 搭建我的网络安全实验环境
date: 2026-10-10 13:00:00
categories:
  - 环境搭建
tags:
  - 实验环境
  - Kali
  - 靶场
---

学网安一定要动手，但 **绝不能拿真实网站练手**。这篇笔记记录我搭建「本地靶场」的过程：虚拟化平台、攻击机、靶场清单和网络规划。

<!-- more -->

## 一、总体结构

```
宿主机（Windows）
 ├── 虚拟化平台（VMware Workstation / VirtualBox）
 │    ├── 攻击机：Kali Linux
 │    ├── 靶机：DVWA / Pikachu / Vulhub 等
 │    └── 可选：Windows / 域环境虚拟机
 └── 网络：仅主机模式（Host-Only），与物理网隔离
```

**核心原则：靶场网络与真实网络隔离。** 用「仅主机模式」或独立的虚拟交换机，既保护自己不误伤内网，也避免靶场被打出去。

## 二、虚拟化平台选择

| 平台 | 特点 |
| ---- | ---- |
| VMware Workstation | 功能全、快照好用，个人学习用 Pro 或 Player |
| VirtualBox | 免费开源，轻量 |
| Hyper-V | Win10/11 自带，与 VMware 混用要注意冲突 |

建议：**内存至少 16G，给攻击机 2-4G、每台靶机 1-2G**。硬盘用动态分配即可，但一定要勤打 **快照**——把「刚装好」和「打完补丁」的状态存下来，随时回滚。

## 三、攻击机：Kali Linux

- 官方镜像：[kali.org](https://www.kali.org/get-kali/)
- 装好后第一件事：`sudo apt update && sudo apt full-upgrade -y`
- 常用工具集（只列名字，用法后面单独写笔记）：
  - 信息收集：nmap、whatweb、subfinder……
  - Web：sqlmap、burpsuite、ffuf
  - 抓包：wireshark、tcpdump

> 提示：Kali 里工具全，但不要「拿到工具就开扫」。先把原理学明白，工具只是效率放大器。

## 四、靶场清单（由浅入深）

| 靶场 | 特点 | 适合阶段 |
| ---- | ---- | -------- |
| **DVWA** | 经典入门，可调安全等级 | Web 入门 |
| **Pikachu** | 中文，漏洞类型全 | Web 入门 |
| **upload-labs** | 专注文件上传 | 上传专题 |
| **sqli-labs** | 专注 SQL 注入 | 注入专题 |
| **Vulhub** | Docker 一键起真实 CVE 环境 | 进阶复现 |
| **bWAPP** | 漏洞种类非常多 | 查漏补缺 |
| **VulnHub / Hack The Box** | 完整虚拟机，综合渗透 | 综合练习 |

Vulhub 特别推荐：`docker-compose up -d` 就能把带漏洞的环境跑起来，学完 `down` 掉，不留后患。

## 五、几点踩坑经验

1. **快照是生命线**：装好系统先拍快照，实验搞坏了 30 秒回滚；
2. **NAT vs Host-Only**：需要 `apt update` 的时候用 NAT 上网，纯实验用 Host-Only，做完再切回来；
3. **Docker 端口冲突**：Vulhub 起多个环境时注意映射端口不要重复；
4. **别在物理机装一堆安全工具**：环境乱了很难收拾，全部丢进虚拟机；
5. **记录实验**：命令、截图、结论随手记，这些就是以后博客的素材。

## 六、合规提醒

靶场只用来 **学习和研究**。扫描、攻击真实系统必须有书面授权，否则违法。技术本身无善恶，**用技术的人有边界**。

---

环境就绪，接下来开始 DVWA 的练习记录。
