#!/usr/bin/env python3
import socket
import concurrent.futures
import time
import os
import struct
import select
import importlib.util
import glob
from typing import List, Tuple, Optional, Dict, Any

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
        
    def host_discovery(self) -> bool:
        """Check if host is alive using ICMP ping and ARP (for local networks)"""
        try:
            # Try ICMP ping first
            if self._icmp_ping():
                return True
                
            # If ICMP blocked, try ARP for local networks
            if self._arp_ping():
                return True
                
            return False
        except Exception:
            return False
            
    def _icmp_ping(self) -> bool:
        """Send ICMP echo request (ping) to target"""
        try:
            icmp = socket.getprotobyname('icmp')
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
            sock.settimeout(self.timeout)
            
            # ICMP header (type 8 = echo request)
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
        """Send ARP request for local network discovery"""
        try:
            if os.name != 'posix':
                return False  # ARP only works on Unix-like systems
                
            # Get target IP as bytes
            target_ip = socket.inet_aton(self.target)
            
            # Create raw socket
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            sock.bind(('eth0', 0))
            
            # Build ARP request
            arp_frame = [
                b'\xff\xff\xff\xff\xff\xff',  # Destination MAC (broadcast)
                b'\x00\x00\x00\x00\x00\x00',  # Source MAC (filled by kernel)
                b'\x08\x06',                   # EtherType (ARP)
                b'\x00\x01\x08\x00\x06\x04\x00\x01',  # ARP request
                b'\x00\x00\x00\x00\x00\x00',  # Sender MAC (filled by kernel)
                socket.inet_aton('0.0.0.0'),   # Sender IP
                b'\x00\x00\x00\x00\x00\x00',  # Target MAC
                target_ip                      # Target IP
            ]
            
            sock.send(b''.join(arp_frame))
            
            start_time = time.time()
            while time.time() - start_time < self.timeout:
                packet = sock.recvfrom(2048)[0]
                if packet[12:14] == b'\x08\x06':  # ARP packet
                    if packet[20:22] == b'\x00\x02':  # ARP reply
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
                        return (port, True, service)
            except Exception:
                pass
        elif scan_type == "syn":
            try:
                # Raw socket implementation for SYN scan
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                s.settimeout(self.timeout)
                
                # Craft SYN packet
                packet = self._craft_syn_packet(port)
                s.sendto(packet, (self.target, 0))
                
                # Check response
                while True:
                    response = s.recvfrom(1024)[0]
                    if response:
                        if (response[0] >> 4) == 4:  # IPv4
                            ip_header = response[:20]
                            src_port = (response[20] << 8) + response[21]
                            dst_port = (response[22] << 8) + response[23]
                            flags = response[33]
                            if dst_port == port and (flags & 0x12):  # SYN-ACK
                                return (port, True)
            except socket.timeout:
                return (port, False)
            except PermissionError:
                print("Error: SYN scan requires administrator privileges")
                return (port, False)
            except Exception:
                pass
        elif scan_type == "udp":
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(self.timeout)
                    s.sendto(b'', (self.target, port))
                    s.recvfrom(1024)
                    return (port, True)
            except socket.timeout:
                # UDP ports that don't respond might still be open
                return (port, None)
            except Exception:
                pass
        return (port, False)

    def scan_range(self, start_port: int, end_port: int, max_threads: int = 100, 
                  scan_type: str = "tcp", detect_service: bool = False) -> List[Tuple[int, Optional[str]]]:
        open_ports_with_service = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = [executor.submit(self.scan_port, port, scan_type, detect_service) 
                      for port in range(start_port, end_port+1)]
            for future in concurrent.futures.as_completed(futures):
                port, is_open, service = future.result()
                if is_open:
                    open_ports_with_service.append((port, service))
        return sorted(open_ports_with_service, key=lambda x: x[0])

    def _craft_syn_packet(self, port: int) -> bytes:
        # Simple SYN packet construction
        packet = bytearray()
        # TCP header
        packet.extend(bytes([0]))  # Source port (randomized in real implementation)
        packet.extend(bytes([0]))
        packet.extend(bytes([port >> 8]))  # Destination port
        packet.extend(bytes([port & 0xff]))
        packet.extend(bytes([0,0,0,0]))  # Sequence number
        packet.extend(bytes([0,0,0,0]))  # Acknowledgement number
        packet.extend(bytes([0x50]))     # Data offset
        packet.extend(bytes([0x02]))     # Flags (SYN)
        packet.extend(bytes([0xff,0xff])) # Window size
        packet.extend(bytes([0,0]))      # Checksum (would calculate properly in real impl)
        packet.extend(bytes([0,0]))      # Urgent pointer
        return bytes(packet)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Fast Port Scanner")
    parser.add_argument("--skip-ping", help="Skip host discovery", action="store_true")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("-p", "--ports", help="Port range (e.g. 1-1000)", default="1-1024")
    parser.add_argument("-t", "--threads", help="Max threads", type=int, default=100)
    parser.add_argument("--timeout", help="Connection timeout (seconds)", type=float, default=1.0)
    parser.add_argument("-u", "--udp", help="Scan UDP ports instead of TCP", action="store_true")
    parser.add_argument("-s", "--syn", help="Use SYN scan (requires admin)", action="store_true")
    parser.add_argument("--service", help="Detect services on open ports", action="store_true")
    parser.add_argument("--script", help="Enable script scanning", action="store_true")
    parser.add_argument("--script-dir", help="Custom script directory", default="scripts")
    args = parser.parse_args()

    start_port, end_port = map(int, args.ports.split("-"))
    
    scanner = PortScanner(args.target, args.timeout, args.script_dir if args.script else None)
    
    # Host discovery
    if not args.skip_ping:
        print(f"Checking if host {args.target} is alive...")
        if not scanner.host_discovery():
            print(f"Host {args.target} appears to be down")
            exit(1)
        print(f"Host {args.target} is alive")
    
    start_time = time.time()
    scan_type = "udp" if args.udp else "syn" if args.syn else "tcp"
    open_ports = scanner.scan_range(start_port, end_port, args.threads, scan_type, args.service)
    elapsed = time.time() - start_time

    print(f"Scan completed in {elapsed:.2f} seconds")
    print(f"Open ports on {args.target}:")
    for port, service in open_ports:
        if service:
            print(f"  {port}/tcp - {service[:100]}...")  # Truncate long banners
        else:
            print(f"  {port}/tcp")
            
        if args.script:
            script_results = scanner.script_manager.run_scripts(args.target, port, service)
            for script_name, result in script_results.items():
                print(f"    [脚本 {script_name}]")
                for k, v in result.items():
                    print(f"      {k}: {v}")
