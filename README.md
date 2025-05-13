写这个脚本，是因为感觉nmap的端口扫描太慢了，我自己本身需要大批量的IP 域名的端口探测，100W域名用时超出了我本身服务器的时间，所以就想要自己写一个工具

主要功能包括：

1. 高速扫描特性：

- 多线程并发扫描（默认100线程）
- 支持TCP全连接、SYN半开和UDP扫描
- 可自定义超时时间和端口范围

2. 扫描模式：

- TCP全连接扫描（默认）
- SYN隐蔽扫描（需要管理员权限）
- UDP扫描

3. 辅助功能：

- 主机存活检测（ICMP ping + ARP）
- 服务指纹识别
- 智能错误处理

使用方法示例：

1. 基础TCP扫描：python port_scanner.py 目标IP
2. UDP扫描：python port_scanner.py 目标IP -u
3. SYN扫描：python port_scanner.py 目标IP -s（需管理员）
4. 服务识别：python port_scanner.py 目标IP --service
5. 自定义端口：python port_scanner.py 目标IP -p 起始端口-结束端口

性能优势： 相比nmap，本扫描器在基础端口扫描场景下速度更快，尤其在大规模端口扫描时优势明显。

注意事项：

1. SYN扫描需要管理员/root权限
2. 服务识别功能可能被防火墙干扰
3. 请遵守当地网络安全法律法规
