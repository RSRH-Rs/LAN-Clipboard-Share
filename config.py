# 配置
BROADCAST_PORT = 37123  # UDP 广播端口
SYNC_PORT = 37124  # TCP 同步端口
BROADCAST_INTERVAL = 3.0  # 广播间隔（秒）
SYNC_INTERVAL = 0.35  # 剪贴板检查间隔（秒）
HELLO_MAGIC = "CLIPSHARE_"  # 发现用魔术字 *标记
PROTO_MAGIC = b"CLP_"  # 传输协议魔术字
PROTO_VER = 1  # 协议版本
