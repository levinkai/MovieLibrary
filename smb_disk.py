'''
Date: 2025-05-19 09:40:06
LastEditors: LevinKai
LastEditTime: 2025-05-19 14:15:18
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
    print(f"[mount_smb_share] ip;{ip} share:{share} username:{username} password:{password}")
    
    if sys_platform == "linux":
        mount_base = Path("/mnt") / ip
        mount_path = mount_base / share
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
            return str(mount_path)

        smb_url = f"//{username}@{ip}/{share}"
        if password:
            smb_url = f"//{username}:{password}@{ip}/{share}"

        cmd = [
            "mount_smbfs",
            smb_url,
            str(mount_path)
        ]
    elif sys_platform == "windows":
        #net use Z: \\192.168.1.141\pi /user:guest /persistent:no
        # 获取已用盘符
        used = set()
        output = subprocess.check_output("wmic logicaldisk get name", shell=True, text=True)
        for line in output.splitlines():
            line = line.strip()
            if line and ":" in line:
                used.add(line[0].upper())

        # 从 C-Z 依次查找可用盘符
        available = None
        for letter in string.ascii_uppercase[2:]:  # Skip A,B (软驱)
            if letter not in used:
                available = letter + ":"
                break

        if not available:
            print("[mount_smb_share] 没有可用盘符")
            return None

        smb_path = f"\\\\{ip}\\{share}"
        cmd = ["net", "use", available, smb_path, "/user:" + username]
        if password:
            cmd.append(password)
        cmd.append("/persistent:no")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True,timeout=5)
            if result.returncode != 0:
                raise RuntimeError(result.stderr.strip())
            return available + "\\"
        except Exception as e:
            print(f"[mount_smb_share] Windows 挂载失败: {e}")
            return None
    else:
        raise NotImplementedError(f"Unsupported platform: {sys_platform}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip())
        if not mount_path.exists():
            raise RuntimeError("挂载目录不存在")
        return str(mount_path)
    except Exception as e:
        print(f"[mount_smb_share] 挂载失败: {e}")
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
    if path:
        print(f"挂载成功: {path}")
        # do something...
        unmount_smb_share(path)
    else:
        print("挂载失败")