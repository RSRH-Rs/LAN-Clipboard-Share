import socket
import threading
import pyperclip
import time
import platform
import io
import struct
import json
import hmac
import hashlib
import os
from typing import Optional, Tuple, Literal
from PIL import Image
from utils import get_self_ip, get_hash, payload_signature
from config import *


# 类型码
TYPE_TEXT = 1
TYPE_IMAGE = 2


def recv_exact(conn: socket.socket, n: int) -> Optional[bytes]:
    """从TCP读取恰好 n 字节；失败/断开返回 None"""
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def build_packet(payload_type: int, payload: bytes) -> bytes:
    """
    帧格式：
    0..3   : magic "CLP1"
    4      : ver (1 byte)
    5      : type (1 byte)
    6..9   : length (uint32, big-endian)
    10..41 : hmac (32 bytes, 若无PSK则全0)
    42..   : payload
    """
    header = bytearray()
    header += PROTO_MAGIC
    header += struct.pack("!B", PROTO_VER)
    header += struct.pack("!B", payload_type)
    header += struct.pack("!I", len(payload))

    sig = b"\x00" * 32

    header += sig
    return bytes(header) + payload


def parse_packet(conn: socket.socket) -> Optional[Tuple[int, bytes]]:
    """读取并解析一帧，返回 (type, payload)；失败返回 None"""
    header = recv_exact(conn, 42)
    if header is None or header[:4] != PROTO_MAGIC:
        return None

    ver = header[4]
    if ver != PROTO_VER:
        return None

    payload_type = header[5]
    length = struct.unpack("!I", header[6:10])[0]
    sig = header[10:42]

    payload = recv_exact(conn, length)
    if payload is None:
        return None

    return payload_type, payload


# Windows 图片剪贴板读写
def win_get_clipboard_image() -> Optional[Image.Image]:
    if platform.system() != "Windows":
        return None
    try:
        import win32clipboard
        import win32con

        win32clipboard.OpenClipboard()
        try:
            if win32clipboard.IsClipboardFormatAvailable(win32con.CF_DIB):
                dib = win32clipboard.GetClipboardData(win32con.CF_DIB)
                # BMP 头（14字节）
                if isinstance(dib, bytes):
                    bmp_header = (
                        b"BM"
                        + struct.pack("<I", len(dib) + 14)
                        + b"\x00\x00\x00\x00"
                        + struct.pack("<I", 14)
                    )
                    bmp_bytes = bmp_header + dib
                    return Image.open(io.BytesIO(bmp_bytes))
        finally:
            win32clipboard.CloseClipboard()
    except Exception:
        return None
    return None


def win_set_clipboard_image(img: Image.Image):
    import win32clipboard

    output = io.BytesIO()
    img.convert("RGB").save(output, format="BMP")
    data = output.getvalue()[14:]  # 去掉BMP文件头
    output.close()
    try:
        win32clipboard.OpenClipboard()
        win32clipboard.EmptyClipboard()
        win32clipboard.SetClipboardData(win32clipboard.CF_DIB, data)
    finally:
        win32clipboard.CloseClipboard()


class AutoClipShare:
    def __init__(self):
        self.platform = platform.system()
        self.self_ip = get_self_ip()
        self.hostname = socket.gethostname()

        # 设备列表ip
        self.peers = {}
        self.peers_lock = threading.Lock()

        self.running = True
        self.last_sig = ""  # 最近一次已处理内容的哈希签名
        self._print_banner()

        # UDP 广播 socket
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.udp.settimeout(0.5)
        self.udp.bind(("", BROADCAST_PORT))

    # 日志
    def _print_banner(self):
        print("剪贴板共享已启动")
        print(f"设备名: {socket.gethostname()} - 本机IP: {self.self_ip}")
        print("同网段任意主机都能推送")

    # 发现/广播
    def broadcast_service(self):
        payload = {
            "magic": HELLO_MAGIC,
            "ver": 1,
            "name": self.hostname,
            "port": SYNC_PORT,
            "ip": self.self_ip,
        }
        while self.running:
            try:
                self.udp.sendto(
                    json.dumps(payload).encode("utf-8"), ("<broadcast>", BROADCAST_PORT)
                )
            except Exception as e:
                print(f"广播错误: {e}")
            time.sleep(BROADCAST_INTERVAL)

    def discovery_service(self):
        while self.running:
            try:
                data, addr = self.udp.recvfrom(2048)
                ip = addr[0]
                if ip == self.self_ip:
                    continue
                try:
                    msg = json.loads(data.decode("utf-8"))
                except Exception:
                    continue
                if msg.get("magic") != HELLO_MAGIC or "port" not in msg:
                    continue

                with self.peers_lock:
                    first_seen = ip not in self.peers
                    self.peers[ip] = time.time()

                if first_seen:
                    print(f"发现设备: {msg.get('name','?')} @ {ip}:{msg['port']}")
            except socket.timeout:
                # 清理超时未见的设备
                now = time.time()
                with self.peers_lock:
                    dead = [
                        ip
                        for ip, ts in self.peers.items()
                        if now - ts > 3 * BROADCAST_INTERVAL + 2
                    ]
                    for d in dead:
                        print(f"设备离线: {d}")
                        self.peers.pop(d, None)
                continue
            except Exception as e:
                print(f"发现服务错误: {e}")

    # TCP 服务端
    def tcp_server(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", SYNC_PORT))
        srv.listen(8)
        print(f"同步服务监听 {SYNC_PORT}")
        while self.running:
            try:
                conn, addr = srv.accept()
                threading.Thread(
                    target=self.handle_connection, args=(conn, addr), daemon=True
                ).start()
            except Exception:
                continue

    def handle_connection(self, conn: socket.socket, addr):
        ip, _ = addr
        with conn:
            pkt = parse_packet(conn)
            if not pkt:
                return
            payload_type, payload = pkt
            try:
                if payload_type == TYPE_TEXT:
                    self._handle_text(payload)
                elif payload_type == TYPE_IMAGE:
                    self._handle_image(payload)
            except Exception as e:
                print(f"处理来自 {ip} 的数据失败: {e}")

    # 剪贴板访问
    def get_clipboard_content(self) -> Optional[Tuple[Literal["TEXT", "IMAGE"], bytes]]:
        """
        优先尝试图片 否则文本。
        返回 ("IMAGE", png_bytes) 或 ("TEXT", utf-8 bytes)
        """
        # 尝试图片
        if self.platform == "Windows":
            try:
                img = win_get_clipboard_image()
                if img:
                    b = io.BytesIO()
                    img.save(b, format="PNG")
                    return ("IMAGE", b.getvalue())
            except Exception:
                pass

        # 文本
        try:
            text = pyperclip.paste()
            if isinstance(text, str) and text.strip():
                return ("TEXT", text.encode("utf-8"))
        except Exception:
            pass

        return None

    def set_clipboard_text(self, content: bytes):
        try:
            text = content.decode("utf-8")
            pyperclip.copy(text)
        except Exception as e:
            print(f"设置文本剪贴板失败: {e}")

    def set_clipboard_image(self, png_bytes: bytes):
        try:
            img = Image.open(io.BytesIO(png_bytes))
        except Exception as e:
            print(f"解析图片失败: {e}")
            return

        if self.platform == "Windows":
            try:
                win_set_clipboard_image(img)
            except Exception as e:
                print(f"设置图片剪贴板失败(Windows): {e}")
        else:
            # 非Windows（macOS）
            print("非Windows平台暂未实现图片写入剪贴板")

    # 收到内容后的处理
    def _handle_text(self, payload: bytes):
        sig = payload_signature("TEXT", payload)
        if sig == self.last_sig:
            return
        self.set_clipboard_text(payload)
        self.last_sig = sig
        print("收到文本更新")

    def _handle_image(self, payload: bytes):
        sig = payload_signature("IMAGE", payload)
        if sig == self.last_sig:
            return
        self.set_clipboard_image(payload)
        self.last_sig = sig
        print("收到图片更新")

    # 本地监控并分发
    def monitor_clipboard(self):
        while self.running:
            item = self.get_clipboard_content()
            if item:
                kind, data = item  # kind: "IMAGE" / "TEXT"
                sig = payload_signature(kind, data)
                if sig != self.last_sig:
                    self._broadcast_update(kind, data)
                    self.last_sig = sig
                    print("已发送图片更新" if kind == "IMAGE" else "已发送文本更新")
            time.sleep(SYNC_INTERVAL)

    def _broadcast_update(self, kind: Literal["TEXT", "IMAGE"], data: bytes):
        payload_type = TYPE_TEXT if kind == "TEXT" else TYPE_IMAGE
        pkt = build_packet(payload_type, data)

        with self.peers_lock:
            targets = list(self.peers.keys())

        for ip in targets:
            try:
                with socket.create_connection((ip, SYNC_PORT), timeout=1.8) as s:
                    s.sendall(pkt)
            except Exception:
                # 连接失败
                pass

    # 启动
    def start(self):
        threading.Thread(target=self.broadcast_service, daemon=True).start()
        threading.Thread(target=self.discovery_service, daemon=True).start()
        threading.Thread(target=self.tcp_server, daemon=True).start()
        try:
            self.monitor_clipboard()
        except KeyboardInterrupt:
            self.running = False
            print("\n已停止")


if __name__ == "__main__":
    AutoClipShare().start()
