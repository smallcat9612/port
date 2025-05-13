#!/usr/bin/env python3
import socket
import concurrent.futures
import time
import os
import struct
import select
import importlib.util
import glob
import json
from typing import List, Tuple, Optional, Dict, Any

# 常见端口服务名映射
DEFAULT_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

class ScriptManager:
    def __init__(self):
        self.scripts = []
        
    def load_scripts(self, script_dir="scripts"):
        if not os.path.exists(script_dir):
            return
            
        for script_path in glob.glob(f"{script_dir}/*.py"):
            try:
                spec = importlib.util.spec_from_file_location(
                    os.path.basename(script_path)[:-3], 
                    script_path
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                self.scripts.append(module)
            except Exception as e:
                print(f"加载脚本 {script_path} 失败: {e}")

    def run_scripts(self, target: str, port: int, service: str) -> Dict[str, Any]:
        results = {}
        for script in self.scripts:
            try:
                if hasattr(script, "run"):
                    result = script.run(target, port, service)
                    if result:
                        results[script.__name__] = result
            except Exception as e:
                print(f"执行脚本 {script.__name__} 失败: {e}")
        return results

class PortScanner:
    def __init__(self, target: str, timeout: float = 1.0, script_dir: str = None):
        self.target = target
        self.timeout = timeout
        self.open_ports = []
        self.script_manager = ScriptManager()
        if script_dir:
            self.script_manager.load_scripts(script_dir)

    def get_service_name(self, port: int, detected_service: str = None) -> str:
        """获取服务名，优先使用检测到的服务名"""
        if detected_service:
            return detected_service
        return DEFAULT_SERVICES.get(port, "未知")

    def host_discovery(self) -> bool:
        """检查主机是否存活"""
        try:
            if self._icmp_ping():
                return True
            if self._arp_ping():
                return True
            return False
        except Exception:
            return False
            
    def _icmp_ping(self) -> bool:
        """ICMP Ping实现"""
        try:
            icmp = socket.getprotobyname('icmp')
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
            sock.settimeout(self.timeout)
            
            header = struct.pack('bbHHh', 8, 0, 0, 0, 1)
            checksum = 0
            header = struct.pack('bbHHh', 8, 0, checksum, 0, 1)
            
            sock.sendto(header, (self.target, 0))
            
            start_time = time.time()
            while time.time() - start_time < self.timeout:
                ready = select.select([sock], [], [], self.timeout)
                if ready[0]:
                    packet = sock.recvfrom(1024)[0]
                    if packet:
                        return True
            return False
        except Exception:
            return False
            
    def _arp_ping(self) -> bool:
        """ARP Ping实现"""
        try:
            if os.name != 'posix':
                return False
                
            target_ip = socket.inet_aton(self.target)
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            sock.bind(('eth0', 0))
            
            arp_frame = [
                b'\xff\xff\xff\xff\xff\xff',
                b'\x00\x00\x00\x00\x00\x00',
                b'\x08\x06',
                b'\x00\x01\x08\x00\x06\x04\x00\x01',
                b'\x00\x00\x00\x00\x00\x00',
                socket.inet_aton('0.0.0.0'),
                b'\x00\x00\x00\x00\x00\x00',
                target_ip
            ]
            
            sock.send(b''.join(arp_frame))
            
            start_time = time.time()
            while time.time() - start_time < self.timeout:
                packet = sock.recvfrom(2048)[0]
                if packet[12:14] == b'\x08\x06':
                    if packet[20:22] == b'\x00\x02':
                        return True
            return False
        except Exception:
            return False

    def scan_port(self, port: int, scan_type: str = "tcp", detect_service: bool = False) -> Tuple[int, bool, Optional[str]]:
        if scan_type == "tcp":
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout)
                    result = s.connect_ex((self.target, port))
                    if result == 0:
                        service = None
                        if detect_service:
                            try:
                                s.send(b'\r\n\r\n')
                                service = s.recv(1024).decode('utf-8', errors='ignore').strip()
                            except:
                                pass
                        return (port, True, self.get_service_name(port, service))
            except Exception:
                pass
        elif scan_type == "syn":
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                s.settimeout(self.timeout)
                
                packet = self._craft_syn_packet(port)
                s.sendto(packet, (self.target, 0))
                
                while True:
                    response = s.recvfrom(1024)[0]
                    if response:
                        if (response[0] >> 4) == 4:
                            ip_header = response[:20]
                            src_port = (response[20] << 8) + response[21]
                            dst_port = (response[22] << 8) + response[23]
                            flags = response[33]
                            if dst_port == port and (flags & 0x12):
                                return (port, True, self.get_service_name(port, None))
            except socket.timeout:
                return (port, False, None)
            except PermissionError:
                print("错误: SYN扫描需要管理员权限")
                return (port, False, None)
            except Exception:
                pass
        elif scan_type == "udp":
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(self.timeout)
                    s.sendto(b'', (self.target, port))
                    s.recvfrom(1024)
                    return (port, True, self.get_service_name(port, None))
            except socket.timeout:
                return (port, None, None)
            except Exception:
                pass
        return (port, False, None)

    def _craft_syn_packet(self, port: int) -> bytes:
        """构造SYN包"""
        packet = bytearray()
        packet.extend(bytes([0]))
        packet.extend(bytes([0]))
        packet.extend(bytes([port >> 8]))
        packet.extend(bytes([port & 0xff]))
        packet.extend(bytes([0,0,0,0]))
        packet.extend(bytes([0,0,0,0]))
        packet.extend(bytes([0x50]))
        packet.extend(bytes([0x02]))
        packet.extend(bytes([0xff,0xff]))
        packet.extend(bytes([0,0]))
        packet.extend(bytes([0,0]))
        return bytes(packet)

    def scan_range(self, start_port: int, end_port: int, max_threads: int = 100, 
                  scan_type: str = "tcp", detect_service: bool = False) -> List[Tuple[int, str]]:
        open_ports_with_service = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = [executor.submit(self.scan_port, port, scan_type, detect_service) 
                      for port in range(start_port, end_port+1)]
            for future in concurrent.futures.as_completed(futures):
                port, is_open, service = future.result()
                if is_open:
                    open_ports_with_service.append((port, service))
        return sorted(open_ports_with_service, key=lambda x: x[0])

def export_html(report: dict, filename: str):
    """导出HTML报告"""
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>端口扫描报告 - {report['target']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px }}
        h1 {{ color: #333 }}
        .port {{ margin-bottom: 15px; padding: 10px; background: #f5f5f5 }}
        .script {{ margin-left: 20px; color: #666 }}
        .risk-high {{ color: red; font-weight: bold }}
        .risk-medium {{ color: orange }}
        .risk-low {{ color: green }}
    </style>
</head>
<body>
    <h1>端口扫描报告</h1>
    <p><strong>目标:</strong> {report['target']}</p>
    <p><strong>扫描时间:</strong> {report['timestamp']} (耗时: {report['scan_time']:.2f}秒)</p>
    
    <h2>开放端口</h2>"""

    for port_info in report['open_ports']:
        html += f"""
    <div class="port">
        <h3>端口: {port_info['port']}/tcp</h3>
        <p><strong>服务:</strong> {port_info['service'] or '未知'}</p>"""
        
        if port_info['scripts']:
            html += """
        <div class="scripts">
            <h4>脚本检测结果:</h4>"""
            for script, result in port_info['scripts'].items():
                html += f"""
            <div class="script">
                <h5>{script}</h5>"""
                for k, v in result.items():
                    if 'risk' in k.lower():
                        risk_class = f"risk-{v.lower().replace('严重','high').replace('高危','high').replace('中危','medium').replace('低危','low')}"
                        html += f"""
                <p><strong>{k}:</strong> <span class="{risk_class}">{v}</span></p>"""
                    else:
                        html += f"""
                <p><strong>{k}:</strong> {v}</p>"""
            html += """
        </div>"""
        html += """
    </div>"""

    html += """
</body>
</html>"""

    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html)

def export_json(report: dict, filename: str):
    """导出JSON报告"""
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

def export_txt(report: dict, filename: str):
    """导出文本报告"""
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(f"端口扫描报告\n")
        f.write(f"目标: {report['target']}\n")
        f.write(f"扫描时间: {report['timestamp']} (耗时: {report['scan_time']:.2f}秒)\n\n")
        f.write("开放端口:\n")
        
        for port_info in report['open_ports']:
            f.write(f"\n端口: {port_info['port']}/tcp\n")
            f.write(f"服务: {port_info['service'] or '未知'}\n")
            
            if port_info['scripts']:
                f.write("脚本检测结果:\n")
                for script, result in port_info['scripts'].items():
                    f.write(f"  [{script}]\n")
                    for k, v in result.items():
                        f.write(f"    {k}: {v}\n")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="高速端口扫描器")
    parser.add_argument("target", help="目标IP或主机名")
    parser.add_argument("-p", "--ports", help="端口范围 (例如 1-1000)", default="1-1024")
    parser.add_argument("-t", "--threads", help="最大线程数", type=int, default=100)
    parser.add_argument("--timeout", help="连接超时(秒)", type=float, default=1.0)
    parser.add_argument("-u", "--udp", help="UDP扫描模式", action="store_true")
    parser.add_argument("-s", "--syn", help="SYN扫描模式(需要管理员权限)", action="store_true")
    parser.add_argument("--service", help="启用服务识别", action="store_true")
    parser.add_argument("--script", help="启用脚本扫描", action="store_true")
    parser.add_argument("--script-dir", help="自定义脚本目录", default="scripts")
    parser.add_argument("-o", "--output", help="输出文件路径")
    parser.add_argument("--format", help="输出格式 (html/json/txt)", default="txt")
    parser.add_argument("--skip-ping", help="跳过主机存活检测", action="store_true")
    args = parser.parse_args()

    start_port, end_port = map(int, args.ports.split("-"))
    
    scanner = PortScanner(args.target, args.timeout, args.script_dir if args.script else None)
    
    if not args.skip_ping:
        print(f"检查主机 {args.target} 是否存活...")
        if not scanner.host_discovery():
            print(f"主机 {args.target} 似乎不可达")
            exit(1)
        print(f"主机 {args.target} 存活")
    
    start_time = time.time()
    scan_type = "udp" if args.udp else "syn" if args.syn else "tcp"
    open_ports = scanner.scan_range(start_port, end_port, args.threads, scan_type, args.service)
    elapsed = time.time() - start_time

    report = {
        "target": args.target,
        "scan_time": elapsed,
        "open_ports": [],
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    
    for port, service in open_ports:
        port_info = {
            "port": port,
            "service": service,
            "scripts": {}
        }
        if args.script:
            port_info["scripts"] = scanner.script_manager.run_scripts(args.target, port, service)
        report["open_ports"].append(port_info)

    print(f"扫描完成，耗时 {elapsed:.2f} 秒")
    print(f"目标 {args.target} 的开放端口:")
    for port_info in report["open_ports"]:
        print(f"  {port_info['port']}/tcp - {port_info['service']}")
        for script, result in port_info["scripts"].items():
            print(f"    [脚本 {script}]")
            for k, v in result.items():
                print(f"      {k}: {v}")

    if args.output:
        if args.format == "html":
            export_html(report, args.output)
        elif args.format == "json":
            export_json(report, args.output)
        else:
            export_txt(report, args.output)
        print(f"报告已保存到 {args.output} ({args.format}格式)")
