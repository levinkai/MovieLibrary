'''
Date: 2025-05-06 09:21:40
LastEditors: LevinKai
LastEditTime: 2025-05-14 17:59:09
FilePath: \\MovieLibrary\\pc_scanner.py
'''
import sys
import os

platform = sys.platform
print(platform)
import os
# 获取当前文件所在目录的上一级路径
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
print(f'parent_dir:{parent_dir}')
if parent_dir:
    sys.path.insert(0, parent_dir)
    
import socket
import subprocess
import time
from smb.SMBConnection import SMBConnection
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_network
import re

from functools import partial
from PySide6.QtWidgets import * # type: ignore
from PySide6.QtGui import * # type: ignore
from PySide6.QtCore import * # type: ignore

import logging
import my_log#上级目录中的包

from queue import Queue, Empty
import requests
import json

from ui_search_share import Ui_SearchWindow

LOG_TAG = '[SCANNER] '
log_file = os.path.basename(__file__)
logger = logging.getLogger(log_file)

# 获取当前网段（仅限 macOS/Linux）
def get_ip_address():
    system = sys.platform
    
    print(f'ScanCaller get_ip_address {system}')
    
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
        err = str(e)
        print(f"❌ SMB 连接失败 {ip}（{name or '无主机名'}）: err")
        return err

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

class SignalEmitter(QObject):
    resultReady = Signal(object)
    
class ScanCaller(QRunnable):
    def __init__(self, emitter: SignalEmitter):
        super().__init__()
        print(f'{time.ctime()} ScanCaller __init__')
        
        self.emitter = emitter
        self.task_queue = Queue()
        self.running = True
        self._result = {}
        
    def set_emitter(self,emitter: SignalEmitter):
        print(f'{time.ctime()} ScanCaller set_emitter same:{self.emitter is emitter}')
        
        self.emitter = emitter
    
    def stop(self):
        print(f'{time.ctime()} scan')
        self.running = False
        self.task_queue.put(None)  # 唤醒阻塞线程退出
    
    def scan(self):
        print(f'{time.ctime()} ScanCaller scan')
        self.task_queue.put(('scan', None))
    
    def get(self, url, timeout=3, **kwargs):
        print(f'{time.ctime()} ScanCaller get url:{url} timeout:{timeout}')
        
        self.task_queue.put(('get', (url, timeout, kwargs)))
    
    def post(self, url, timeout=3, data=None, json=None, **kwargs):
        print(f'{time.ctime()} ScanCaller post url:{url} timeout:{timeout} data:{data} json:{json}')
        
        self.task_queue.put(('post', (url, timeout, data, json, kwargs)))
    
    def run(self):
        print("ScanCaller thread running")
        while self.running:
            try:
                task = self.task_queue.get(timeout=1)
                if task is None:
                    break
                
                task_type, args = task
                print(f'{time.ctime()} task:{task_type} ----------->')
                
                if task_type == 'scan':
                    result = self._scan_network()
                elif task_type == 'get':
                    url, timeout, kwargs = args
                    result = self._safe_request('get', url, timeout, **kwargs)
                elif task_type == 'post':
                    url, timeout, data, json_data, kwargs = args
                    result = self._safe_request('post', url, timeout, data=data, json=json_data, **kwargs)
                else:
                    result = f"{time.ctime()} Unknown task type: {task_type}"
                    continue
                
                print(f'{time.ctime()} task:{task_type} -----------> result:{result}')
                
                self._result[task_type] = result
                
                if self.emitter:
                    self.emitter.resultReady.emit(self._result)
                else:
                    print(f'{time.ctime()} no emitter!!!')
                    
            except Empty:
                continue
        #finally:
        print("ScanCaller thread exiting")
        
    def scan_lan_port(self, base_ip="192.168.1", port=12345, timeout=1):
        print(f'{time.ctime()} scan_lan_port base_ip:{base_ip} port:{port} timeout:{timeout}')
        """扫描局域网内哪个 IP 的指定端口是开放的"""
        system = sys.platform
        
        for i in range(2, 255):
            if not self.running:
                print(f'{time.ctime()} scan_lan_port stop!!!')
                break
            
            ip = f"{base_ip}.{i}"
            if system == "Windows":
                # 使用 PowerShell 的 Test-NetConnection
                cmd = ["powershell", "-Command", f"Test-NetConnection -ComputerName {ip} -Port {port}"]
            else:
                # 使用 nc 命令（需要确保安装了 netcat）
                cmd = ["nc", "-z", "-w", str(timeout), ip, str(port)]
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+1)
                output = result.stdout.lower()
                if system == "Windows":
                    if "tcp test succeeded" in output:
                        print(f"[+] Found open port {port} on {ip}")
                        return ip
                else:
                    if result.returncode == 0:
                        print(f"[+] Found open port {port} on {ip}")
                        return ip
            except subprocess.TimeoutExpired:
                pass
            except Exception as e:
                print(f"Error scanning {ip}:{port} => {e}")
        
        return None
    
    def _scan_single_ip(self, ip):
        """扫描单个 IP 地址，检查是否开放 SMB 以及共享信息"""
        try:
            if is_smb_open(ip):
                print(f"🔌 {ip} 开放 SMB")
                hostname = get_hostname(ip)
                print(f"🔍 主机名: {hostname or '未知'}")
                
                data = {
                    'ip': ip,
                    'name': hostname,
                    'shares': ''
                }
                
                shares = try_smb(ip)
                data['shares'] = shares
                
                return data if shares else None
        except Exception as e:
            print(f'{time.ctime()} fail:{e}')
            if data:
                data['error'] = e
        return None
    
    def _scan_network(self):
        """使用多线程对局域网内所有 IP 地址进行扫描"""
        local_ip = get_ip_address()
        results = {}
        print(f'{time.ctime()} _scan_network {local_ip}')

        if local_ip:
            ip_prefix = ".".join(local_ip.split(".")[:3])
            ip_list = [f"{ip_prefix}.{i}" for i in range(1, 255)]

            # 使用线程池进行并发扫描
            max_workers = min(32, (os.cpu_count() or 1) * 5)
            with ThreadPoolExecutor(max_workers) as executor:
                future_to_ip = {executor.submit(self._scan_single_ip, ip): ip for ip in ip_list}
                
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        data = future.result()
                        if data:
                            results[ip] = data
                    except Exception as e:
                        print(f"{time.ctime()} 扫描 {ip} 时出错: {e}")
            
            print("\n🎯 可访问共享:")
            for host, data in results.items():
                shares = data['shares']
                if isinstance(shares,list):
                    smbshares = []
                    for share in shares:
                        if 'win32' == platform:
                            pth = f"\\\\{host}\\{share}"
                        else:
                            pth = f'smb://{host}/{share}'
                            
                        smbshares.append(pth)
                        print(f"✅ {pth}")
                    # data['shares'] = smbshares
                else:
                    print(f'{shares}')
        return results
    
    def _safe_request(self, method, url, timeout=3, **kwargs):
        print(f'{time.ctime()} ScanCaller _safe_request method:{method} url:{url} timeout:{timeout} kwargs:{kwargs}')
        try:
            r = getattr(requests, method)(url, timeout=timeout, **kwargs)
            print(f'{time.ctime()} code:{r.status_code}')
            
            return r.json() if r.status_code == 200 else f"Error: {r.status_code}"
        except Exception as e:
            print(f"{time.ctime()} _safe_request Exception: {e}")
            
            return ''

DEFAULT_FILE_NAME = "result.json"
def load_results(file_path=DEFAULT_FILE_NAME):
    """
    加载测试结果文件，如果不存在则创建一个空的测试结果文件。
    :param file_path: 测试结果文件路径
    :return: 测试结果字典
    """
    if not os.path.exists(file_path):
        # 文件不存在，创建一个空文件
        try:
            with open(file_path, 'w') as file:
                json.dump([], file, indent=4)
        except Exception as e:
            logger.error(f"{LOG_TAG} load_results creat file fail!{e}")
        return {}
    else:
        # 读取文件内容
        try:
            with open(file_path, 'r') as file:
                return json.load(file)
        except Exception as e:
            logger.error(f"{LOG_TAG} load_results fail!{e} clear it!")
            with open(file_path, 'w') as file:
                json.dump([], file, indent=4)
            return {}
        
def save_results(test_results, file_path=DEFAULT_FILE_NAME):
    """
    保存测试结果到文件中。
    :param test_results: 测试结果列表
    :param file_path: 测试结果文件路径
    """
    try:
        with open(file_path, 'w') as file:
            json.dump(test_results, file, indent=4)
    except Exception as e:
        logger.error(f"{LOG_TAG} save_results fail!{e}")
        
def show_auto_close_message(
    title: str,
    text: str,
    timeout_ms: int = 3000,
    window: QWidget | None = None,
    icon=QMessageBox.Information, # type: ignore
    buttons=QMessageBox.Ok # type: ignore
):
    """
    显示一个超时自动关闭的消息框
    
    :param title: 窗口标题
    :param text: 消息内容
    :param timeout_ms: 自动关闭超时（毫秒）
    :param window: 父窗口（可选，设为None则作为独立窗口）
    :param icon: 图标类型（如 QMessageBox.Critical）
    :param buttons: 按钮类型（如 QMessageBox.Ok | QMessageBox.Cancel）
    """
    msg_box = QMessageBox(window if window else None)  # 设置父窗口或独立窗口
    msg_box.setIcon(icon)
    msg_box.setWindowTitle(title)
    msg_box.setText(text)
    msg_box.setStandardButtons(buttons)

    # 设置超时自动关闭
    QTimer.singleShot(timeout_ms, msg_box.close)

    # 根据父窗口决定模态行为
    if window:
        msg_box.setModal(True)  # 模态阻塞父窗口
    else:
        msg_box.setWindowModality(Qt.ApplicationModal)  # 独立应用模态 # type: ignore

    msg_box.exec()
    
class SearchWindow(QMainWindow):
    def __init__(self):
        super(SearchWindow, self).__init__()
        self.ui = Ui_SearchWindow()
        self.ui.setupUi(self)
        self.ui.statusbar.showMessage('初始化...')
        local_ip = get_ip_address()
        ip_prefix = '' if local_ip is None else ".".join(local_ip.split(".")[:3])
        
        print(f'ip:{local_ip} ip_prefix:{ip_prefix}')
        
        # Initialize treeView
        self.ui.treeWidget_sharelist.setHeaderLabels(["IP/Share", "Status"])
        self.ui.treeWidget_sharelist.setContextMenuPolicy(Qt.CustomContextMenu) # type: ignore
        self.ui.treeWidget_sharelist.customContextMenuRequested.connect(self.show_context_menu)
        self.ui.treeWidget_sharelist.itemDoubleClicked.connect(self.on_item_double_clicked)
        
        self.signal_emitter = SignalEmitter()
        self.scan_caller = ScanCaller(self.signal_emitter)
        QThreadPool.globalInstance().start(self.scan_caller)
        
        self.ui.lineEdit_ip.setText(f'{local_ip}')
        self.ui.lineEdit_subnet.setText(f'{ip_prefix}')
        self.ui.pushButton_search.clicked.connect(partial(self.scan_shares))
        if local_ip:
            self.ui.statusbar.showMessage('初始化成功')
        else:
            self.ui.statusbar.showMessage('初始化失败')
        
        self.share_map = load_results()
        
        if self.share_map:
            self.on_scan_complete(self.share_map)
            
    def showEvent(self, event):
        print(f"{self.windowTitle()} showEvent")
        super().showEvent(event)
        
        self.ui.treeWidget_sharelist.clearSelection()
        
    def hideEvent(self, event):
        print(f"{self.windowTitle()} hideEvent")
        super().hideEvent(event)
        
    def closeEvent(self, event):
        print(LOG_TAG+f"{self.windowTitle()} closeEvent!!!")
        if self.scan_caller:
            self.scan_caller.stop()
        
        save_results(self.share_map)
        
        event.accept()#self.manager.show_window(WINDOW_TITLE.START)
        QCoreApplication.quit()
        
    def scan_shares(self):
        self.scan_caller.emitter.resultReady.connect(self.on_scan_complete)
        self.scan_caller.scan()
        self.ui.statusbar.showMessage(f'{time.ctime()} 扫描开始...')
        
    def on_scan_complete(self, result):
        print("on_scan_complete [Scan Result]:", len(result) if result else result)
        self.ui.treeWidget_sharelist.clear()  # Clear existing tree items
        
        try:
            if isinstance(result,dict):
                if 'scan' in result:
                    self.scan_caller.emitter.resultReady.disconnect(self.on_scan_complete)
                    self.ui.statusbar.showMessage(f'{time.ctime()} 扫描结束')
                    result = result.get('scan')
                    logger.info(f'{LOG_TAG} scan result')
                else:
                    logger.info(f'{LOG_TAG} init result')
        except Exception as e:
            logger.error(f'{LOG_TAG} on_scan_complete fail! {e}')
            
        if result:
            if isinstance(result,dict):
                self.share_map = result
                for ip, data in result.items(): 
                    self.add_to_tree(ip, data)
                    
    def get_top_level_parent(self,item):
        """获取最顶层的父项（如果 item 本身就是顶层，则返回自身）"""
        while item.parent() is not None:  # 只要还有父项，就继续向上查找
            item = item.parent()
        return item
    
    def add_to_tree(self, ip, data):
        # Check if the IP node already exists
        root = self.ui.treeWidget_sharelist
        existing_ip_item = None
        for i in range(root.topLevelItemCount()):
            item = root.topLevelItem(i)
            if item.text(0) == ip: # type: ignore
                existing_ip_item = item
                break
        
        # If the IP node exists, use it; otherwise, create a new one
        if existing_ip_item is None:
            # Create a new IP item
            ip_item = QTreeWidgetItem(self.ui.treeWidget_sharelist)
            ip_item.setText(0, ip)
            ip_item.setCheckState(0, Qt.Unchecked)  # type: ignore # Add checkbox
        else:
            ip_item = existing_ip_item
            # Add data to the IP node
            if isinstance(data, list):
                existing_shares = set()
                # Collect existing shares under this IP
                for i in range(ip_item.childCount()):
                    existing_shares.add(ip_item.child(i).text(0))
                # Add only the new shares
                for item in data:
                    if item not in existing_shares:
                        share_item = QTreeWidgetItem(ip_item)
                        share_item.setText(0, item)
                return share_item
        
        ip_item.setText(1, data.get('name', 'Unknown'))
        
        shares = data.get('shares')
        if isinstance(shares,ConnectionResetError):
            shares = f'{shares}'
        if isinstance(shares, str):
            # If shares is a string, mark it as an error
            share_item = QTreeWidgetItem(ip_item)
            share_item.setText(0, shares)
            share_item.setBackground(0, Qt.red) # type: ignore
        elif isinstance(shares, list):
            # If shares is a list, add each one as a child
            for share in shares:
                share_item = QTreeWidgetItem(ip_item)
                share_item.setText(0, share)
            return ip_item
        
    def show_context_menu(self, position):
        # Show right-click menu
        item = self.ui.treeWidget_sharelist.itemAt(position)
        if item:
            menu = QMenu()
            connect_action = menu.addAction("连接")
            delete_action = menu.addAction("删除")
            action = menu.exec_(self.ui.treeWidget_sharelist.viewport().mapToGlobal(position))
            if action == connect_action:
                self.connect_share(item)
            elif action == delete_action:
                self.delete_item(item)
    
    def connect_share(self, item):
        """
        Establish an SMB connection and refresh the tree structure for the share.
        Recursively list all files and directories under the share.
        """
        topitem = self.get_top_level_parent(item)
        ip = topitem.text(0)
        share = item.text(0) if item.parent() else None
        username = '' if not self.share_map else self.share_map[ip].get('username', '')
        password = '' if not self.share_map else self.share_map[ip].get('password', '')
        
        logger.info(f'{LOG_TAG} Connecting to IP: {ip}, Username: {username}, Share: {share}')
        
        if not username:  # Prompt for credentials if not provided
            username, ok = QInputDialog.getText(self, "输入用户名", f"连接到 {ip} 的用户名：")
            if ok:
                password, ok = QInputDialog.getText(self, "输入密码", f"连接到 {ip} 的密码：") # , QLineEdit.Password type: ignore
                if not ip in self.share_map:
                    self.share_map[ip] = {}
                self.share_map[ip]['username'] = username
                self.share_map[ip]['password'] = password
        
        try:
            # Establish SMB connection
            conn = SMBConnection(username, password, "my_pc", ip, use_ntlm_v2=True, is_direct_tcp=True)
            if conn.connect(ip, 445):
                logger.info(f"{LOG_TAG} Connected to {ip} via port 445")
                show_auto_close_message(title="成功", text=f"连接到 {ip} 成功", window=self)
                item.setBackground(0, Qt.green)
                
                # Clear existing children and refresh the tree structure
                self.remove_all_children(item)
                shares = conn.listShares()
                shares = [s.name for s in shares if not s.isSpecial and s.name not in ['NETLOGON', 'SYSVOL']]
                for share in shares:
                    if share:
                        item = QTreeWidgetItem(topitem)
                        item.setText(0, share)
                        if 'win32' == platform:
                            path = rf"\\{ip}\{share}"
                            if os.path.exists(path):
                                video_exts = {'.rm', '.rmvb', '.mkv', '.mp3', '.wmv'}
                                video_files = []
                                dir_list = []
                                file_list = []
                                for root, dirs, files in os.walk(path):
                                    # 1. 必须原地修改dirs以控制递归
                                    dir_list[:] = [d for d in dirs if not d.startswith(('.', '\\', '$'))]
                                    file_list[:] = [f for f in files if not f.startswith(('.', '\\', '$'))]
                                    break
                                
                                for d in dir_list:
                                    if d.startswith(('.', '\\', '$')):
                                        continue
                                    sub_item = QTreeWidgetItem(item)
                                    sub_item.setText(0, d)
                                    sub_item.setCheckState(0, Qt.Unchecked)  # type: ignore # Add checkbox for directories
                                    sub_item.setBackground(0, Qt.NoBrush)  # type: ignore # Reset background color
                                    
                                    full_path = os.path.join(root, d)
                                    print(full_path)
                                        
                                # 过滤文件并匹配扩展名
                                for f in file_list:
                                    if f.startswith(('.', '\\', '$')):
                                        continue
                                    
                                    sub_item = QTreeWidgetItem(item)
                                    sub_item.setText(0, f)
                                    
                                    full_path = os.path.join(root, f)
                                    print(full_path)
                                    
                                    if os.path.splitext(f)[1].lower() in video_exts:
                                        video_files.append(full_path)
                        
                        else:
                            self.list_files_recursive(conn, item, share, "/")
                    else:
                        logger.info(f"{LOG_TAG} {ip} has no shares!")
                        show_auto_close_message(title="提示", text=f"{ip} has no shares!", window=self)
                
            elif conn.connect(ip, 139):
                logger.info(f"{LOG_TAG} Connected to {ip} via port 139")
                show_auto_close_message(title="成功", text=f"连接到 {ip} 成功 (端口 139)", window=self)
            else:
                raise Exception("无法连接到 SMB 服务")

        except Exception as e:
            logger.error(f"{LOG_TAG} Failed to connect to {ip}: {e}")
            show_auto_close_message(title="错误", text=f"连接失败: {e}", window=self, icon=QMessageBox.Critical) # type: ignore
            item.setBackground(0, Qt.red) # type: ignore
    
    def list_files_recursive(self, conn, parent_item, share, current_path):
        """
        Recursively list files and directories in a shared path and populate QTreeWidgetItem.
        :param conn: SMBConnection object
        :param parent_item: QTreeWidgetItem parent node
        :param share: SMB share name
        :param current_path: Current directory path in the share
        """
        try:
            # Strip leading and trailing slashes for consistency
            current_path = current_path.strip("\\").strip("/")
            logger.info(f'{LOG_TAG} list_files_recursive try conn.listPath({share}, {current_path})')

            # Fetch the list of files and directories in the current path
            files = conn.listPath(share, current_path if current_path else "/")
            
            for file in files:
                logger.info(f'{LOG_TAG} {file.filename}|{"文件夹" if file.isDirectory else "文件"}')
                
                # Skip special entries and hidden directories
                if file.filename.startswith(('.', '\\', '$')):
                    continue
                
                # Create a tree item for the file or directory
                file_item = QTreeWidgetItem(parent_item)
                file_item.setText(0, file.filename)
                file_item.setText(1, "文件夹" if file.isDirectory else "文件")
                
                if file.isDirectory:
                    file_item.setCheckState(0, Qt.Unchecked)  # type: ignore # Add checkbox for directories
                    file_item.setBackground(0, Qt.NoBrush)  # type: ignore # Reset background color
                    
                    # Build the next path for the recursive call
                    next_path = f"{current_path}/{file.filename}" if current_path else file.filename
                    logger.info(f'{LOG_TAG} next share:{share} path:{next_path}')
                    
                    # Recursively list the contents of the directory
                    self.list_files_recursive(conn, file_item, share, next_path)
        
        except Exception as e:
            logger.error(f"Failed to list path {current_path} in share {share}: {e}")
            show_auto_close_message(title="错误", text=f"Failed to list path {current_path} in share {share}: {e}", window=self, icon=QMessageBox.Critical)  # type: ignore
    
    def delete_item(self, item):
        # Remove the selected item from the tree
        parent = item.parent()
        logger.warning(f'{LOG_TAG} delete_item {item.text(0)}')
        if parent:
            parent.removeChild(item)
        else:
            index = self.ui.treeWidget_sharelist.indexOfTopLevelItem(item)
            self.ui.treeWidget_sharelist.takeTopLevelItem(index)
    
    def remove_all_children(self,parent_item):
        """删除 parent_item 的所有子节点"""
        logger.warning(f'{LOG_TAG} remove_all_children {parent_item.text(0)}')
        
        children = parent_item.takeChildren()  # 移除所有子节点并返回列表
        if children:
            for child in children:  # 彻底删除子节点（防止内存泄漏）
                del child
    
    def remove_children_one_by_one(self,parent_item):
        """逐个删除 parent_item 的子节点"""
        logger.warning(f'{LOG_TAG} remove_children_one_by_one {parent_item.text(0)}')
        
        for i in reversed(range(parent_item.childCount())):  # 从后往前删
            child = parent_item.child(i)
            parent_item.removeChild(child)  # 从父节点移除
            del child  # 彻底删除
    
    def on_item_double_clicked(self, item, column):
        # Double-click to connect
        if item.parent():
            self.connect_share(item)
            
if __name__ == "__main__":
    current_time = time.strftime("%Y-%m-%d-%H-%M-%S")
    # log_file = f"{log_file}-{current_time}" 
    my_log.initLogging(log_file=log_file,message=f'{LOG_TAG}================================ {current_time} [START] {log_file} ================================')
    
    app = QApplication(sys.argv)
    window = SearchWindow()
    window.show()
    
    sys.exit(app.exec())

