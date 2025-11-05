import socket
import hashlib
from PIL import Image


def get_self_ip() -> str:
    """获取本机局域网IP"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except:
        return "127.0.0.1"


def get_hash(data: bytes) -> str:
    """生成哈希内容"""
    return hashlib.sha256(data).hexdigest()


def payload_signature(kind: str, data: bytes) -> str:
    import hashlib, io

    if kind == "IMAGE":
        try:
            img = Image.open(io.BytesIO(data)).convert("RGBA")
            w, h = img.size
            raw = img.tobytes()  # 像素
            return hashlib.sha256(
                b"IMG" + w.to_bytes(4, "big") + h.to_bytes(4, "big") + raw
            ).hexdigest()
        except Exception:
            # 退回对字节本身哈希
            return hashlib.sha256(b"IMG" + data).hexdigest()
    else:  # TEXT
        return hashlib.sha256(b"TXT" + data).hexdigest()
