'''
Date: 2025-05-19 09:40:06
LastEditors: LevinKai
LastEditTime: 2025-05-25 16:33:47
FilePath: \\Work\\MovieLibrary\\smb_disk.py
'''
import os
import platform
import subprocess
from pathlib import Path
from typing import Optional
import string
import re

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

        # —— 1. 如果路径已存在且已挂载（且挂载源为目标ip/共享），直接返回 ——
        if mount_path.exists():
            with open("/proc/mounts") as f:
                for line in f:
                    cols = line.split()
                    if cols[1] == str(mount_path) and cols[0].startswith(f"//{ip}/{share}"):
                        print(f"[mount_smb_share] 已挂载: {mount_path}")
                        return str(mount_path)
            # 路径存在但未挂载或挂错源，继续往下走

        # 确保本地挂载点存在
        cmd = f'sudo mkdir -p {mount_path}'
        try:
            result = subprocess.run(args=cmd, capture_output=True, text=True, check=True, shell=True)
            print(f'result:{result.stdout.strip()}')
        except Exception as e:
            print(f"[mount_smb_share] 创建挂载目录失败: {e}")
            return None
        
        # 构造挂载选项
        cred_option = ""
        if username and username.strip():
            cred_option += f",username={username}"
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
        # 检查/Volumes下是否有同名share且指向指定ip
        base_mount_dir = Path("/Volumes")
        candidate_mounts = []
        for p in base_mount_dir.iterdir():
            if p.name.startswith(share):
                # 检查该挂载点是否指向目标ip
                try:
                    # 查询mount信息
                    mount_info = subprocess.check_output(['mount'], text=True)
                    for line in mount_info.splitlines():
                        if str(p) in line and f"//{username}@" in line and ip in line and f"/{share}" in line:
                            print(f"[mount_smb_share] 已挂载且指向目标ip: {p}")
                            return str(p)
                except Exception as e:
                    print(f"[mount_smb_share] 查询挂载信息失败: {e}")
                candidate_mounts.append(p)  # 若不是目标ip，后续新挂载

        smb_url = f"smb://{username}@{ip}/{share}"
        if password:
            smb_url = f"smb://{username}:{password}@{ip}/{share}"

        try:
            # 使用 AppleScript 让 Finder 执行挂载
            script = f'''
            tell application "Finder"
                try
                    mount volume "{smb_url}"
                on error errMsg
                    return "Error: " & errMsg
                end try
            end tell
            '''
            result = subprocess.run(["osascript", "-e", script], capture_output=True, text=True)
            output = result.stdout.strip()
            if "Error" in output:
                raise RuntimeError(output)
            
            # 等待一会儿让系统完成挂载
            import time
            for _ in range(10):
                for p in base_mount_dir.iterdir():
                    if p.name.startswith(share):
                        try:
                            mount_info = subprocess.check_output(['mount'], text=True)
                            for line in mount_info.splitlines():
                                if str(p) in line and f"//{username}@" in line and ip in line and f"/{share}" in line:
                                    return str(p)
                        except Exception:
                            continue
                time.sleep(0.5)
            raise RuntimeError("挂载后找不到路径")
        except Exception as e:
            print(f"[mount_smb_share] macOS 挂载失败: {e}")
            return None

    elif sys_platform == "windows":
        smb_path = f"\\\\{ip}\\{share}"
        existing = {}
        # 查找所有已映射的网络驱动器，且指向目标ip/共享
        try:
            cmd = 'wmic logicaldisk where drivetype=4 get name,providername'
            wmic = subprocess.check_output(cmd, text=True, shell=True, timeout=5)
            print(f'{cmd}:\n{wmic}')
            for line in wmic.splitlines()[1:]:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) == 2:
                    drive, provider = parts
                    existing[drive.upper()] = provider

            print(f"existing: {existing}")
            for drive, provider in existing.items():
                if provider.lower() == smb_path.lower():
                    print(f"[mount_smb_share] 发现已映射盘符 {drive} -> {provider}")
                    return drive + "\\"
        except Exception as e:
            print(f"[mount_smb_share] 查询网络驱动器失败: {e}")

        # 获取所有已用盘符（固定盘 & 网络盘都跳过）
        used = set()
        try:
            cmd = 'wmic logicaldisk get Name,DriveType'
            all_disks = subprocess.check_output(cmd, text=True, shell=True, timeout=5)
            print(f'{cmd}:\n{all_disks}')
            for line in all_disks.splitlines()[1:]:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) == 2:
                    dtype, drive = parts
                    used.add(drive[0].upper())
            print(f'used:{used}')
        except Exception as e:
            print(f"[mount_smb_share] 查询盘符失败: {e}")

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
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip())
        if not mount_path.exists():
            raise RuntimeError("挂载目录不存在")
        return str(mount_path)
    except Exception as e:
        print(f"[mount_smb_share] username:{username} password:{password} ip:{ip} share:{share} 挂载失败: {e}")
        return None

def unmount_smb_share(path: str, ip ='') -> bool:
    r"""
    卸载 SMB 挂载路径
    - 支持 Windows/Linux/macOS
    - Windows 可传入 Z: 或 \\host\share
    - 新增ip参数：若传入ip，则只有路径对应挂载点的ip是目标ip时才执行卸载
    """
    sys_platform = platform.system().lower()
    print(f"[unmount_smb_share] path: {path} ip: {ip}")

    # 非 Windows 系统直接判断路径是否存在
    if sys_platform == "linux":
        if not Path(path).exists():
            return True
        # 检查目标路径挂载源是否为指定ip
        if ip:
            found = False
            with open("/proc/mounts") as f:
                for line in f:
                    cols = line.split()
                    if cols[1] == str(path) and f"//{ip}/" in cols[0]:
                        found = True
                        break
            if not found:
                print(f"[unmount_smb_share] 路径未挂载或不属于目标ip，跳过卸载")
                return True

        cmd = ["sudo", "umount", path]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                raise RuntimeError(result.stderr.strip())
            return True
        except Exception as e:
            print(f"[unmount_smb_share] 卸载失败: {e}")
            return False
    elif sys_platform == "darwin":
        if not Path(path).exists():
            return True
        # 检查目标路径挂载源是否为指定ip
        if ip:
            try:
                mount_info = subprocess.check_output(['mount'], text=True)
                match = False
                for line in mount_info.splitlines():
                    if str(path) in line and ip in line:
                        match = True
                        break
                if not match:
                    print(f"[unmount_smb_share] 路径未挂载或不属于目标ip，跳过卸载")
                    return True
            except Exception as e:
                print(f"[unmount_smb_share] 查询挂载信息失败: {e}")
                return True
        try:
            # 使用 AppleScript 让 Finder 卸载卷
            script = f'''
            tell application "Finder"
                try
                    eject POSIX file "{path}"
                on error errMsg
                    return "Error: " & errMsg
                end try
            end tell
            '''
            result = subprocess.run(["osascript", "-e", script], capture_output=True, text=True)
            output = result.stdout.strip()
            if "Error" in output:
                raise RuntimeError(output)
            return True
        except Exception as e:
            print(f"[unmount_smb_share] macOS 卸载失败: {e}")
            return False

    elif sys_platform == "windows":
        def is_permanent_mapping(drive_letter: str) -> bool:
            try:
                key = rf"HKCU\Network\{drive_letter.upper()}"
                result = subprocess.run(["reg", "query", key], capture_output=True, text=True)
                return result.returncode == 0
            except Exception as e:
                print(f"[is_permanent_mapping] 判断失败: {e}")
                return False

        path = path.strip()
        # Case 1: 是一个合法盘符 Z: 或 Z:\ 开头
        if re.fullmatch(r"[A-Z]:\\?", path.upper()):
            drive = path[0].upper() + ":"
            print(f"[unmount_smb_share] 识别为盘符: {drive}")
            # 检查是否已映射该驱动器，且映射目标为ip
            try:
                output = subprocess.check_output(["net", "use"], text=True)
                related_line = None
                for line in output.splitlines():
                    if line.strip().startswith(drive):
                        related_line = line
                        break
                need_unmount = True
                if ip and related_line:
                    # 检查映射目标
                    parts = re.split(r"\s{2,}", related_line.strip())
                    if len(parts) >= 2 and ip not in parts[1]:
                        print(f"[unmount_smb_share] 路径不属于目标ip，跳过卸载")
                        return True
                if related_line:
                    cmd = ["net", "use", drive, "/delete", "/y"]
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    if result.returncode != 0:
                        raise RuntimeError(result.stderr.strip())
                    print(f"[unmount_smb_share] 盘符 {drive} 卸载成功")
                    return True
                else:
                    print(f"[unmount_smb_share] 盘符 {drive} 未映射，跳过卸载")
                    return True
            except Exception as e:
                print(f"[unmount_smb_share] 查询或卸载失败: {e}")
                return False

        # Case 2: 是一个 SMB 路径 \\host\share
        elif path.startswith("\\\\"):
            print(f"[unmount_smb_share] 识别为 SMB 路径: {path}")
            try:
                # 查询所有 net use 映射
                output = subprocess.check_output(["net", "use"], text=True)
                # 示例行：Z:          \\192.168.1.141\pi     Microsoft Windows Network
                for line in output.splitlines():
                    line = line.strip()
                    if not line or not "\\" in line:
                        continue
                    parts = re.split(r"\s{2,}", line)
                    if len(parts) >= 3:
                        status, local, remote = parts[:3]
                        permanent = is_permanent_mapping(local)
                        if ip and ip not in remote:
                            continue
                        if (remote.lower() == path.lower()) and (not permanent):
                            print(f"[unmount_smb_share] 匹配: {local} -> {remote}，卸载中...")
                            subprocess.run(["net", "use", local, "/delete", "/y"],
                                        capture_output=True, text=True)
                return True
            except Exception as e:
                print(f"[unmount_smb_share] SMB 路径卸载失败: {e}")
                return False
        else:
            print(f"[unmount_smb_share] 无法识别路径类型：{path}")
            return False

    else:
        raise NotImplementedError(f"Unsupported platform: {sys_platform}")

if __name__ == "__main__":
    path = mount_smb_share("192.168.1.141", "pi")
    if path and os.path.exists(path):
        print(f"挂载成功: {path}")
        # do something...
        unmount_smb_share(r'\\192.168.1.141\pi')
        unmount_smb_share(path)
    else:
        print("挂载失败")