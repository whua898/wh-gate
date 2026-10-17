#!/usr/bin/env python3
"""
ProtonVPN 免费节点订阅生成
==========================
输入:
  1) 明文目录: 环境变量 PROTON_CONF_DIR 下的 *.conf (本地手工验证用)
  2) 否则解密仓库 proton/proton_configs.enc (Fernet, 密钥 PROTON_ENC_KEY)
输出 (PUBLIC_DIR 或 out-local/):
  proton-<SUB>.yaml       mihomo / Clash Party 完整配置 (直接导入)
  proton-sb-<SUB>.json    sing-box 完整配置 (v2rayN「导入 sing-box 配置」)
  proton-v2ray-<SUB>.txt  base64 的 wireguard:// URI 列表 (v2rayN 订阅分组)
退出码:
  0 = 正常完成 (含「未配置密钥时跳过」, 允许 0 节点以外的部分解析失败)
  1 = 硬性失败 (解密失败 / 解析出 0 节点, 绝不允许「假成功」)
"""

import base64
import configparser
import io
import json
import os
import re
import sys
import tempfile
import zipfile
from urllib.parse import quote

from vpngate import log, die, _env, COUNTRY_ZH, REPO_DIR

# 保证日志在任何控制台编码下都能输出 (Windows GBK 控制台不会崩)
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# 配置 (均可用环境变量覆盖, 便于本地测试)
# ---------------------------------------------------------------------------
ENC_PATH = os.path.join(REPO_DIR, "proton", "proton_configs.enc")
ENC_KEY = _env("PROTON_ENC_KEY", "")
CONF_DIR = _env("PROTON_CONF_DIR", "")
PUBLIC_DIR = os.environ.get("PUBLIC_DIR", os.path.join(REPO_DIR, "public"))
LOCAL_DIR = os.path.join(REPO_DIR, "out-local")
SUB_NAME = _env("PROTON_SUB_NAME", "")
PUBLISH = os.environ.get("PUBLISH_PROTON", "").strip().lower() in ("1", "true", "yes")
PROTON_REFRESH = os.environ.get("PROTON_REFRESH", "每天").strip() or "每天"
MTU_DEFAULT = 1280


def _decrypt_confs_to_tmp():
    """用 PROTON_ENC_KEY 解密 proton_configs.enc -> 临时目录 (返回目录路径)。"""
    if not os.path.exists(ENC_PATH):
        return None
    from cryptography.fernet import Fernet, InvalidToken  # 懒加载: 明文目录/跳过模式无需 cryptography
    try:
        raw = Fernet(ENC_KEY.encode("ascii")).decrypt(open(ENC_PATH, "rb").read())
    except (InvalidToken, ValueError):
        die("PROTON_ENC_KEY 无法解密 proton_configs.enc (密钥错 / 文件损坏)")
    except Exception as exc:
        die(f"解密 proton_configs.enc 异常: {type(exc).__name__}: {exc}")
    tmp = tempfile.mkdtemp(prefix="proton_confs_")
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        zf.extractall(tmp)
    return tmp


def _country_code_from_name(filename):
    """从 wg 文件名提取 ISO 国家码 (如 wg-us-101... -> US), 失败返回 '??'。"""
    for m in re.findall(r"[A-Z]{2}", os.path.basename(filename).upper()):
        if m in COUNTRY_ZH:
            return m
    return "??"


def parse_confs(conf_dir):
    """解析目录下 *.conf -> nodes 列表 (按 server 去重, 国家+服务器稳定排序)。"""
    nodes, seen = [], set()
    paths = []
    for root, _dn, fns in os.walk(conf_dir):
        for fn in sorted(fns):
            if fn.lower().endswith(".conf"):
                paths.append(os.path.join(root, fn))
    paths.sort()
    for path in paths:
        fn = os.path.basename(path)
        try:
            cp = configparser.ConfigParser()
            cp.read(path, encoding="utf-8")
            priv = cp.get("Interface", "PrivateKey").strip()
            addr = cp.get("Interface", "Address")
            pub = cp.get("Peer", "PublicKey").strip()
            endpoint = cp.get("Peer", "Endpoint").strip()
            mtu = cp.get("Interface", "MTU", fallback=str(MTU_DEFAULT)).strip() or str(MTU_DEFAULT)
        except Exception as exc:
            log("PARSE", f"跳过 {fn}: 解析失败 ({exc})")
            continue
        if ":" not in endpoint:
            log("PARSE", f"跳过 {fn}: Endpoint 无端口 ({endpoint})")
            continue
        host, port = endpoint.rsplit(":", 1)
        if not port.isdigit():
            log("PARSE", f"跳过 {fn}: 端口非法 ({endpoint})")
            continue
        ip4, ip6 = "", ""
        for a in addr.split(","):
            a = a.strip().split("/")[0]
            if ":" in a:
                ip6 = ip6 or a
            elif "." in a:
                ip4 = ip4 or a
        key = (host.lower(), port, pub)
        if key in seen:
            continue
        seen.add(key)
        code = _country_code_from_name(fn)
        nodes.append({
            "file": fn, "code": code, "server": host, "port": int(port),
            "ip": ip4, "ipv6": ip6, "private_key": priv, "public_key": pub,
            "mtu": int(mtu) if mtu.isdigit() else MTU_DEFAULT,
        })
    nodes.sort(key=lambda n: (n["code"], n["server"]))
    counters = {}
    for n in nodes:
        counters[n["code"]] = counters.get(n["code"], 0) + 1
        n["name"] = f"Proton-{n['code']}-{counters[n['code']]:02d}"
        n["country_zh"] = COUNTRY_ZH.get(n["code"], n["code"])
    return nodes

# ---------------------------------------------------------------------------
# 产物 1: mihomo / Clash Party 完整 YAML (手写, 不引入 pyyaml 依赖)
# ---------------------------------------------------------------------------
def build_mihomo_yaml(nodes):
    L = [
        "# ProtonVPN 免费节点 (mihomo / Clash Party: 直接作为配置文件导入)",
        f"# 自动生成: 节点 {len(nodes)} 个, {PROTON_REFRESH}更新 (url-test 自动测速选优)",
        "# 订阅 URL 含随机文件名, 请勿公开分享",
        "mixed-port: 7890",
        "allow-lan: true",
        "mode: rule",
        "log-level: info",
        "dns:",
        "  enable: true",
        "  ipv6: false",
        "  nameserver:",
        "    - 10.2.0.1",
        "    - 223.5.5.5",
        "  fallback:",
        "    - 8.8.8.8",
        "proxies:",
    ]
    for n in nodes:
        L.append(f"  - name: \"{n['name']}\"")
        L.append("    type: wireguard")
        L.append(f"    server: {n['server']}")
        L.append(f"    port: {n['port']}")
        L.append(f"    ip: {n['ip'] or '10.2.0.2'}")
        if n["ipv6"]:
            L.append(f"    ipv6: {n['ipv6']}")
        L.append(f"    private-key: {n['private_key']}")
        L.append(f"    public-key: {n['public_key']}")
        L.append("    reserved: [0, 0, 0]")
        L.append("    mtu: {0}".format(n['mtu']))
        L.append("    udp: true")
    # groups

    groups = {}
    for n in nodes:
        groups.setdefault(n["code"], []).append(n["name"])
    names = [n["name"] for n in nodes]
    L.append("proxy-groups:")
    L.append("  - name: \"MANUAL\"")
    L.append("    type: select")
    L.append("    proxies:")
    L.append("      - \"AUTO\"")
    for nm in names:
        L.append(f"      - \"{nm}\"")
    L.append("  - name: \"AUTO\"")
    L.append("    type: url-test")
    L.append("    proxies:")
    for nm in names:
        L.append(f"      - \"{nm}\"")
    L.append("    url: http://www.gstatic.com/generate_204")
    L.append("    interval: 300")
    for code in sorted(groups):
        L.append(f"  - name: \"{COUNTRY_ZH.get(code, code)}\"")
        L.append("    type: select")
        L.append("    proxies:")
        for nm in groups[code]:
            L.append(f"      - \"{nm}\"")
    L += ["rules:", "  - GEOIP,CN,DIRECT", "  - MATCH,MANUAL"]
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------------------
# 产物 2: sing-box 完整 JSON (v2rayN「导入 sing-box 配置」)
# ---------------------------------------------------------------------------
def build_singbox(nodes):
    tags = [n["name"] for n in nodes]
    outbounds = []
    for n in nodes:
        local = []
        if n["ip"]:
            local.append(f"{n['ip']}/32")
        if n["ipv6"]:
            local.append(f"{n['ipv6']}/128")
        outbounds.append({
            "type": "wireguard", "tag": n["name"],
            "server": n["server"], "server_port": n["port"],
            "local_address": local or ["10.2.0.2/32"],
            "private_key": n["private_key"], "peer_public_key": n["public_key"],
            "mtu": n["mtu"],
        })
    return {
        "log": {"level": "info"},
        "dns": {"servers": [{"tag": "proton", "address": "10.2.0.1"},
                            {"tag": "public", "address": "223.5.5.5"}]},
        "inbounds": [{"type": "mixed", "tag": "mixed-in",
                      "listen": "127.0.0.1", "listen_port": 10808}],
        "outbounds": outbounds + [
            {"type": "selector", "tag": "MANUAL", "outbounds": ["AUTO"] + tags},
            {"type": "urltest", "tag": "AUTO", "outbounds": tags,
             "url": "http://www.gstatic.com/generate_204", "interval": "5m"},
        ],
        "route": {"rules": [{"geoip": "cn", "outbound": "direct"}],
                  "final": "MANUAL", "auto_detect_interface": True},
    }

# ---------------------------------------------------------------------------
# 产物 3: wireguard:// URI 列表 (v2rayN / NekoBox 订阅文本)
# ---------------------------------------------------------------------------
def build_wireguard_uris(nodes):
    lines = []
    for n in nodes:
        addr = ",".join(([f"{n['ip']}/32"] if n["ip"] else [])
                        + ([f"{n['ipv6']}/128"] if n["ipv6"] else [])) or "10.2.0.2/32"
        lines.append(
            f"wireguard://{n['private_key']}@{n['server']}:{n['port']}"
            f"?publickey={n['public_key']}"
            f"&address={quote(addr, safe='')}"
            f"&mtu={n['mtu']}"
            f"#{quote(n['name'], safe='')}"
        )
    return "\n".join(lines) + "\n"

def write_outputs(nodes):
    """发布门控: PUBLISH_PROTON=1 + PROTON_SUB_NAME 才进 public/。"""
    if PUBLISH and SUB_NAME:
        out_dir, suffix = PUBLIC_DIR, SUB_NAME
        log("SUB", "发布模式: 写入 public/ (随机文件名, 不索引)")
    else:
        if not SUB_NAME:
            log("SUB", "跳过发布: 未配置 PROTON_SUB_NAME")
        else:
            log("SUB", "跳过发布: 未设置 PUBLISH_PROTON=1")
        out_dir, suffix = LOCAL_DIR, "local"
        log("SUB", "只写本地 out-local/ (gitignore, 不入库不发布)")
    os.makedirs(out_dir, exist_ok=True)
    written = []
    y = os.path.join(out_dir, f"proton-{suffix}.yaml")
    with open(y, "w", encoding="utf-8") as f:
        f.write(build_mihomo_yaml(nodes))
    written.append(y)
    s = os.path.join(out_dir, f"proton-sb-{suffix}.json")
    with open(s, "w", encoding="utf-8") as f:
        json.dump(build_singbox(nodes), f, ensure_ascii=False, indent=1)
    written.append(s)
    t = os.path.join(out_dir, f"proton-v2ray-{suffix}.txt")
    with open(t, "w", encoding="utf-8") as f:
        f.write(base64.b64encode(build_wireguard_uris(nodes).encode("utf-8")).decode("ascii"))
    written.append(t)
    return written


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    conf_dir = CONF_DIR if (CONF_DIR and os.path.isdir(CONF_DIR)) else None
    if conf_dir is None:
        tmp = _decrypt_confs_to_tmp()
        if tmp is None:
            # 未启用 Proton 订阅 (无 Secrets、无密文): 优雅跳过, 不影响 check.yml 主流程
            log("PROTON", "跳过: 未配置 PROTON_CONF_DIR 且无 proton/proton_configs.enc")
            return
        conf_dir = tmp
        log("PROTON", "输入: proton_configs.enc (已解密到临时目录)")
    else:
        log("PROTON", f"输入: 明文目录 {conf_dir}")
    nodes = parse_confs(conf_dir)
    if not nodes:
        die("解析出 0 个 WireGuard 节点 (不生成空结果, 本次运行判定失败)")
    log("PROTON", f"可用节点: {len(nodes)}")
    log("PROTON", f"国家: {', '.join(sorted({n['code'] for n in nodes}))}")
    for p in write_outputs(nodes):
        log("WEBSITE", f"生成 {os.path.relpath(p, REPO_DIR)}")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        die(f"程序异常: {type(exc).__name__}: {exc}")
