---
title: 代理与隧道技术笔记：反向代理与 frp
date: 2026-10-10 16:30:00
categories:
  - 内网渗透
tags:
  - frp
  - 反向代理
  - 隧道技术
  - 内网穿透

---

## 反向代理：
我在公网，目标在内网，需要内网的机器走出来，才能连接

### frp（版本0.51.3）
frps（服务端，放在公网）和 frpc（客户端，放在内网）。

1.控制通道建立：内网的 frpc 启动，主动向公网的 frps 发起 TCP 连接（假设走 7000 端口）。这个连接建立后保持长连接断，称为“控制通道”。因为是内网主动向外访问，防火墙通常会放行。

2.端口绑定与监听：frps 收到连接后，根据配置文件，在公网服务器上额外开辟一个端口（例如 6000 端口），专门等待你的访问。

3.访客接入与隧道激活动作：



frpc配置：

```toml
[common]
# 1. 你的公网服务器（frps）的固定公网 IP
server_addr = x.x.x.x  
# 2. 与服务器通信的控制端口（必须与 frps.ini 中的 bind_port 一致）
server_port = 7000
# 3. 握手暗号/凭证（强烈建议配置，必须与 frps 端的 token 一致，否则会被人蹭隧道）
token = 12345678
# 4. 选填：连接池数量。实战中建议配置 2~5，可以显著降低第一次握手建立连接的延迟
pool_count = 3
# 5. 选填：建议开启 TLS 加密通信，防止流量特征被态势感知或防火墙拦截
tls_enable = true
```

方式一：ssh端口转发

```toml
[my_ssh_forward]            # 唯一代号，不能跟别人重复
type = tcp                  # 通信协议
local_ip = 127.0.0.1        # 如果是本机就写127.0.0.1，也可以写同内网其他机器的IP
local_port = 22             # 内网服务原本的端口

remote_port = 6001          # 关键：你希望在公网服务器上开放哪个端口来访问它
use_encryption = true       # 建议：传输数据加密
use_compression = true      # 建议：传输数据压缩（省公网流量带宽）
```

直接连接 公网IP:6001，等同于连接内网的 22 端口。

方法二：SOCKS5 全流量代理

```toml
[my_socks5_proxy]
type = tcp
remote_port = 6005          # 你在公网服务器上开放的 SOCKS5 端口

# 关键：不需要指定 local_ip，直接调用 frp 内置的 socks5 插件
plugin = socks5
plugin_user = r1d3r   # 建议：设置代理的账号（防别人爆破）
plugin_passwd = 12345678 # 建议：设置代理的密码
```

本地浏览器或 Proxifier 配置一个 SOCKS5 代理，指向 公网IP:6005，输入账号密码，即可畅行内网。

frps配置：

```toml
[common]
bind_addr = 0.0.0.0
# [配对点 A] 服务端监听端口
bind_port = 7000
# [配对点 B] 开启 KCP 协议的 UDP 端口，建议与 bind_port 一致
kcp_bind_port = 7000

# [配对点 C] 双方必须一致的认证暗号
token = 12345678

max_pool_count = 5
# 【注意】删除了 allow_ports，允许客户端映射任意公网端口
```
