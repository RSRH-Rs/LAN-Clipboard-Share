import socket
import threading
import pyperclip
import time
import hashlib

# 配置
BROADCAST_PORT = 37123    # 广播端口
SYNC_PORT = 37124         # 数据同步端口
BROADCAST_INTERVAL = 3    # 广播间隔（秒）
SYNC_INTERVAL = 0.5       # 剪贴板检查间隔

class AutoClipShare:
    def __init__(self):
        self.peer_address = None
        self.last_hash = ""
        self.all_device = set()
        self.running = True
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.udp_socket.settimeout(0.5)
        # 绑定到所有网卡的 BROADCAST_PORT
        self.udp_socket.bind(('', BROADCAST_PORT))

    def broadcast_service(self):
        """持续发送设备存在广播"""
        while self.running:
            try:
                self.udp_socket.sendto(b'CLIP_SHARE_HELLO', 
                    ('<broadcast>', BROADCAST_PORT))
            except Exception as e:
                print(f"广播错误: {e}")
            time.sleep(BROADCAST_INTERVAL)

    def discovery_service(self):
        """监听设备广播"""
        while self.running:
            try:
                data, addr = self.udp_socket.recvfrom(1024)
                if data == b'CLIP_SHARE_HELLO' and addr[0] != self.get_self_ip():
                    if addr[0] not in self.all_device:
                        self.all_device.add(addr[0])
                        print(f"🔍 发现新设备: {addr[0]}")
                    
                    if not self.peer_address:
                        self.peer_address = addr[0]
                        threading.Thread(
                            target=self.sync_service,
                            daemon=True
                        ).start()
            except socket.timeout:
                continue

    def sync_service(self):
        """与设备建立同步连接"""
        print(f"🔄 正在与 {self.peer_address} 建立连接...")
        
        # 启动TCP服务端
        server = threading.Thread(target=self.tcp_server, daemon=True)
        server.start()
        
        # 启动剪贴板监控
        self.monitor_clipboard()

    def tcp_server(self):
        """TCP数据接收服务"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('0.0.0.0', SYNC_PORT))
            s.listen(1)
            while self.running:
                conn, addr = s.accept()
                if addr[0] == self.peer_address:
                    self.handle_connection(conn)

    def handle_connection(self, conn):
        """处理TCP连接数据"""
        with conn:
            data = conn.recv(10*1024*1024)  # 最大10MB
            if data:
                content = data.decode('utf-8')
                current_hash = self.get_hash(content)
                if current_hash != self.last_hash:
                    pyperclip.copy(content)
                    self.last_hash = current_hash
                    print(f"📥 收到远程剪贴板更新")

    def monitor_clipboard(self):
        """监控本地剪贴板变化"""
        while self.running and self.peer_address:
            current = pyperclip.paste()
            current_hash = self.get_hash(current)
            
            if current and current_hash != self.last_hash:
                self.send_update(current)
                self.last_hash = current_hash
                print(f"📤 已发送剪贴板更新")
            
            time.sleep(SYNC_INTERVAL)

    def send_update(self, content):
        """发送更新到对端"""
        try:
            with socket.socket() as s:
                s.settimeout(2)
                s.connect((self.peer_address, SYNC_PORT))
                s.sendall(content.encode('utf-8'))
        except Exception as e:
            print(f"发送失败: {e}")

    def get_self_ip(self):
        """获取本机局域网IP"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            return s.getsockname()[0]
        except:
            return '127.0.0.1'

    def get_hash(self, text):
        """生成内容哈希"""
        return hashlib.md5(text.encode('utf-8')).hexdigest()

    def start(self):
        print("🚀 零配置剪贴板共享已启动")
        print(f"本机IP: {self.get_self_ip()}")
        
        # 启动广播服务
        threading.Thread(target=self.broadcast_service, daemon=True).start()
        # 启动发现服务
        threading.Thread(target=self.discovery_service, daemon=True).start()
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.running = False
            print("\n👋 已停止")

if __name__ == "__main__":
    AutoClipShare().start()

