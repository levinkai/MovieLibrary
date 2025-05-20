'''
Date: 2025-05-19 09:40:06
LastEditors: LevinKai
LastEditTime: 2025-05-20 15:38:41
FilePath: \\MovieLibrary\\smb_disk.py
'''
import os
import platform
import subprocess
from pathlib import Path
from typing import Optional
import string

sys_platform = platform.system().lower()
print(f'{sys_platform}')

def mount_smb_share(ip: str, share: str, username: str = "guest", password: Optional[str] = None) -> Optional[str]:
    """
    挂载 SMB 共享路径
    成功返回挂载的本地路径，失败返回 None。
    """
    print(f"[mount_smb_share] ip:{ip} share:{share} username:{username} password:{password}")
    
    if sys_platform == "linux":
        mount_base = Path("/mnt") / ip
        mount_path = mount_base / share

        # —— 1. 如果路径已存在且已挂载，直接返回 ——
        if mount_path.exists():
            # 检查是否已挂载
            with open("/proc/mounts") as f:
                for line in f:
                    cols = line.split()
                    if cols[1] == str(mount_path) and cols[0].startswith(f"//{ip}/{share}"):
                        print(f"[mount_smb_share] 已挂载: {mount_path}")
                        return str(mount_path)

        # 确保本地挂载点存在
        mount_path.mkdir(parents=True, exist_ok=True)

        cred_option = f",username={username}"
        if password:
            cred_option += f",password={password}"
        else:
            cred_option += ",guest"

        cmd = [
            "sudo", "mount", "-t", "cifs",
            f"//{ip}/{share}", str(mount_path),
            "-o", f"uid={os.getuid()},gid={os.getgid()},rw{cred_option}" # type: ignore
        ]

    elif sys_platform == "darwin":
        mount_name = f"{ip.replace('.', '_')}_{share}"
        mount_path = Path("/Volumes") / mount_name

        if mount_path.exists():
            print(f"[mount_smb_share] 已挂载: {mount_path}")
            return str(mount_path)

        smb_url = f"//{username}@{ip}/{share}"
        if password:
            smb_url = f"//{username}:{password}@{ip}/{share}"

        mount_path.mkdir(parents=True, exist_ok=True)
        # cmd = [
        #     "mkdir", "-p", str(mount_path)
        # ]
        # subprocess.run(cmd, check=True)
        
        cmd = [
            "mount_smbfs",
            smb_url,
            str(mount_path)
        ]
    elif sys_platform == "windows":
        #net use Z: \\192.168.1.141\pi /user:guest /persistent:no
        # —— 2. 先扫描已有网络驱动器 —— 
        # 并且检查是否已有网络映射到相同 smb_path
        smb_path = f"\\\\{ip}\\{share}"
        existing = {}
        cmd = 'wmic logicaldisk where drivetype=4 get name,providername'
        wmic = subprocess.check_output(cmd,text=True, shell=True,timeout=5)
        print(f'{cmd}:\n{wmic}')
        for line in wmic.splitlines()[1:]:
            parts = line.strip().split()
            if len(parts) == 2:
                drive, provider = parts
                existing[drive.upper()] = provider

        print(f"existing: {existing}")
        if existing:
            for drive, provider in existing.items():
                if provider.lower() == smb_path.lower():
                    print(f"[mount_smb_share] 发现已映射盘符 {drive} -> {provider}")
                    return drive + "\\"
        else:
            print("[mount_smb_share] 没有已映射的网络驱动器")
            
        # 获取所有已用盘符（固定盘 & 网络盘都跳过）
        used = set()
        cmd = 'wmic logicaldisk get Name,DriveType'
        all_disks = subprocess.check_output(cmd,text=True, shell=True,timeout=5)
        print(f'{cmd}:\n{all_disks}')
        for line in all_disks.splitlines()[1:]:
            parts = line.strip().split()
            if len(parts) == 2:
                dtype, drive = parts
                # DriveType: 3 = 本地固定磁盘, 4 = 网络连接, 2 = 可移动
                print(f"drive: {drive} DriveType: {dtype}")
                print(f'{'本地磁盘' if dtype == '3' else '网络盘' if dtype == '4' else '可移动磁盘'}: {drive}')
                used.add(drive[0].upper())
                
        print(f'used:{used}')
        
        # 从 D-Z 依次查找可用盘符
        available = None
        for letter in string.ascii_uppercase[3:]:  # 跳过 A,B,C
            if letter not in used:
                available = letter + ":"
                break

        if not available:
            print("[mount_smb_share] 没有可用盘符")
            return None
        
        print(f"[mount_smb_share] 可用盘符: {available}")
        cmd = ["net", "use", available, smb_path, f"/user:{username}", "/persistent:no"]
        if password:
            cmd.insert(-1, password)  # 在 /persistent:no 之前加密码

        mount_path = Path(available) if '\\' in available else Path(available + "\\")
    else:
        raise NotImplementedError(f"Unsupported platform: {sys_platform}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True,timeout=5)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip())
        if not mount_path.exists():
            raise RuntimeError("挂载目录不存在")
        return str(mount_path)
    except Exception as e:
        print(f"[mount_smb_share] username:{username} password:{password} ip:{ip} share:{share} 挂载失败: {e}")
        return None

def unmount_smb_share(path: str) -> bool:
    """
    卸载挂载路径
    成功返回 True，失败返回 False。
    """
    print(f"[unmount_smb_share] path:{path}")

    if not Path(path).exists():
        return True  # 认为已卸载

    if sys_platform == "linux":
        cmd = ["sudo", "umount", path]
    elif sys_platform == "darwin":
        cmd = ["umount", path]
    elif sys_platform == "windows":
        # net use Z: /delete
        try:
            # path 可能是 Z:\ 或 Z:
            drive = path[0].upper() + ":"
            cmd = ["net", "use", drive, "/delete", "/y"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                raise RuntimeError(result.stderr.strip())
            return True
        except Exception as e:
            print(f"[unmount_smb_share] Windows 卸载失败: {e}")
            return False
    else:
        raise NotImplementedError(f"Unsupported platform: {sys_platform}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip())
        return True
    except Exception as e:
        print(f"[unmount_smb_share] 卸载失败: {e}")
        return False
    
if __name__ == "__main__":
    path = mount_smb_share("192.168.1.141", "pi")
    if path and os.path.exists(path):
        print(f"挂载成功: {path}")
        # do something...
        unmount_smb_share(path)
    else:
        print("挂载失败")