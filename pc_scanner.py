'''
Date: 2025-05-06 09:21:40
LastEditors: LevinKai
LastEditTime: 2025-05-06 10:28:08
FilePath: \\script\\pc_scanner.py
'''
import sys
import os
import socket
import subprocess
import time
from smb.SMBConnection import SMBConnection
from concurrent.futures import ThreadPoolExecutor
from ipaddress import ip_network
import re

# 获取当前网段（仅限 macOS/Linux）
def get_ip_address():
    system = sys.platform
    
    print(f'HttpCaller get_ip_address {system}')
    
    try:
        if system == "win32":
            output = subprocess.check_output("ipconfig", encoding="gbk")
            adapter_priority = ["以太网适配器", "无线局域网适配器"]
            
            current_adapter = ""
            ip_list = {}
            
            for line in output.splitlines():
                line = line.strip()
                if any(name in line for name in adapter_priority):
                    current_adapter = line
                elif "IPv4 地址" in line:
                    ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                    if ip_match:
                        ip = ip_match.group(1)
                        ip_list[current_adapter] = ip
            
            for key in adapter_priority:
                for adapter, ip in ip_list.items():
                    if key in adapter:
                        return ip
        else:
            # Linux/macOS
            output = subprocess.check_output("ifconfig", encoding="utf-8")
            blocks = output.split("\n\n")
            
            ip_list = {}
            for block in blocks:
                if "inet " in block and "127.0.0.1" not in block:
                    iface = block.split(":")[0].strip()
                    ip_match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", block)
                    if ip_match:
                        ip_list[iface] = ip_match.group(1)
            
            for prefer_iface in ["eth0", "en0", "wlan0"]:
                if prefer_iface in ip_list:
                    return ip_list[prefer_iface]
            return next(iter(ip_list.values()), None)
    except Exception as e:
        print(f"[ERROR] 获取 IP 失败: {e}")
        return None
    
def get_local_subnet(ip=''):
    try:
        if not ip:
            # 使用 ipconfig 获取所有网卡信息
            result = subprocess.run(["ipconfig", "getifaddr", "en0"], stdout=subprocess.PIPE, text=True)
            ip = result.stdout.strip()

            # 如果 en0 没有IP，尝试 en1（可能是Wi-Fi）
            if not ip:
                result = subprocess.run(["ipconfig", "getifaddr", "en1"], stdout=subprocess.PIPE, text=True)
                ip = result.stdout.strip()

            if not ip or ip.startswith("127."):
                raise RuntimeError("未能获取有效的本地 IP 地址")

        subnet = ".".join(ip.split(".")[:3]) + ".0/24"
        return subnet

    except Exception as e:
        raise RuntimeError(f"获取本地子网失败: {e}")

# 检测 SMB 端口是否开放
def is_smb_open(ip):
    try:
        with socket.create_connection((ip, 445), timeout=1):
            return True
    except:
        return False

# 通过反向 DNS 获取主机名
def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None

# 匿名尝试 SMB 共享
def try_smb(ip, name=None):
    print(f'try_smb ip:{ip} name:{name} {time.ctime()}')

    try:
        conn = SMBConnection('', '', 'scanner', name or ip, use_ntlm_v2=True)
        conn.connect(ip, 445, timeout=3)
        shares = conn.listShares()
        result = [s.name for s in shares if not s.isSpecial and s.name not in ['NETLOGON', 'SYSVOL']]
        conn.close()
        return result
    except Exception as e:
        print(f"❌ SMB 连接失败 {ip}（{name or '无主机名'}）: {e}")
        return None

# 主扫描流程
def scan_network(subnet):
    print(f"📡 扫描子网: scan_network subnet:{subnet} {time.ctime()}")
    found = []
    
    def process(ip):
        if is_smb_open(ip):
            print(f"🔌 {ip} 开放 SMB")
            hostname = get_hostname(ip)
            print(f"🔍 主机名: {hostname or '未知'}")
            
            shares = None
            access_name = ip
            
            # 优先使用主机名连接 SMB
            if hostname:
                shares = try_smb(ip, hostname)
                if shares:
                    access_name = hostname
            
            # 如果主机名失败，再尝试 IP
            if not shares:
                shares = try_smb(ip)
            
            if shares:
                found.append((access_name, shares))

    with ThreadPoolExecutor(max_workers=50) as executor:
        executor.map(process, [str(ip) for ip in ip_network(subnet).hosts()])

    print("\n🎯 可访问共享:")
    for host, shares in found:
        for share in shares:
            print(f"✅ smb://{host}/{share}")

if __name__ == "__main__":
    ip = get_ip_address()
    subnet = get_local_subnet(ip) # type: ignore
    print(f'ip:{ip} subnet:{subnet}')
    scan_network(subnet)
