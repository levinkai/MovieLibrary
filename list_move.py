import socket
import subprocess
from ipaddress import ip_network, IPv4Address
from smb.SMBConnection import SMBConnection
from concurrent.futures import ThreadPoolExecutor
import fcntl
import struct
import platform
import os
import re

# 获取当前网段（仅限 macOS/Linux）
def get_local_subnet():
    try:
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
    try:
        conn = SMBConnection('', '', 'scanner', name or ip, use_ntlm_v2=True)
        conn.connect(ip, 445, timeout=3)
        shares = conn.listShares()
        result = [s.name for s in shares if not s.isSpecial and s.name not in ['NETLOGON', 'SYSVOL']]
        conn.close()
        return result
    except:
        return None

# 主扫描流程
def scan_network(subnet):
    print(f"📡 扫描子网: {subnet}")
    found = []

    def process(ip):
        if is_smb_open(ip):
            print(f"🔌 {ip} 开放 SMB")
            hostname = get_hostname(ip)
            print(f"🔍 主机名: {hostname or '未知'}")
            
            shares = try_smb(ip, hostname) or try_smb(ip)
            if shares:
                access_name = hostname if try_smb(ip, hostname) else ip
                found.append((access_name, shares))

    with ThreadPoolExecutor(max_workers=50) as executor:
        executor.map(process, [str(ip) for ip in ip_network(subnet).hosts()])

    print("\n🎯 可访问共享:")
    for host, shares in found:
        for share in shares:
            print(f"✅ smb://{host}/{share}")

if __name__ == "__main__":
    subnet = get_local_subnet()
    scan_network(subnet)
